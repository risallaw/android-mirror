package dev.local.androidmirror.core

import dev.local.androidmirror.service.peerText
import org.json.JSONArray
import org.json.JSONException
import java.io.Closeable

/** A Mac that paired with this phone (see `nativeListPaired`). */
data class PairedMac(val clientId: String, val clientName: String, val pairedAtMs: Long) {
    /** The Mac's name, or its id when it sent none, safe to show (both came from the Mac; see [peerText]). */
    val displayName: String get() = peerText(clientName.ifBlank { clientId }).orEmpty()

    /** When it paired, or null if the store has no plausible date for it (0 = none recorded). */
    val pairedAt: Long? get() = pairedAtMs.takeIf { it >= EARLIEST_PAIRED_AT_MS }

    private companion object {
        /** 2020-01-01: anything earlier is a missing or bogus date, not one worth showing as 1970. */
        const val EARLIEST_PAIRED_AT_MS = 1_577_836_800_000L
    }
}

/**
 * The paired list from its JSON (`[{"clientId":…,"clientName":…,"pairedAtMs":…}]`), or null if it
 * could not be read (null or malformed: an unreadable store must not look like an empty one).
 */
internal fun parsePaired(json: String?): List<PairedMac>? {
    if (json == null) return null
    return try {
        val arr = JSONArray(json)
        List(arr.length()) { i ->
            val o = arr.getJSONObject(i)
            val id = o.getString("clientId")
            // Not optString: Android's turns a JSON null into "null".
            val name = (o.opt("clientName") as? String).orEmpty()
            PairedMac(id, name, o.optLong("pairedAtMs", 0L))
        }
    } catch (_: JSONException) {
        null
    }
}

/**
 * Owner of one Rust core instance (TCP server + H.264 encoder). Methods become no-ops once
 * closed. Only [start] and [close] lock (so a handle is created once and destroyed once): the
 * other calls need no lock, because a handle is a key into the native side's handle table, so a
 * call racing [close] finds it gone and returns its fallback instead of touching freed memory.
 * Locking them would only queue the main thread's calls (port, pin, setDisplay) behind a slow
 * one on another thread, such as a revoke waiting for its file sync. [close] blocks, normally
 * for under a second (BYE, thread joins, codec release; longer if the codec wedges), and
 * upcalls [CoreCallbacks.onSurfaceGone], so call it off the main thread and never while holding
 * the projection lock.
 */
class NativeCore(private val callbacks: CoreCallbacks) : Closeable {
    @Volatile
    private var handle = 0L

    /** Start the server; false if the core could not start (see logcat tag MirrorCore). */
    @Synchronized
    fun start(configJson: String): Boolean {
        if (handle == 0L) handle = nativeCreate(configJson, callbacks)
        return handle != 0L
    }

    fun port(): Int = if (handle == 0L) 0 else nativeGetPort(handle)

    fun setDisplay(width: Int, height: Int, rotation: Int, dpi: Int) {
        if (handle != 0L) nativeSetDisplay(handle, width, height, rotation, dpi)
    }

    fun setScreenState(on: Boolean) {
        if (handle != 0L) nativeSetScreenState(handle, on)
    }

    fun networkChanged() {
        if (handle != 0L) nativeNetworkChanged(handle)
    }

    /** The system ended the projection: the client gets BYE `projection_revoked`. Call before [close]. */
    fun projectionRevoked() {
        if (handle != 0L) nativeProjectionRevoked(handle)
    }

    /** Current pairing PIN, "" if none. */
    fun pin(): String = if (handle == 0L) "" else nativeGetPin(handle)

    /** Tell the core whether the Accessibility service is on, so it forwards control input. */
    fun setControlAvailable(available: Boolean) {
        if (handle != 0L) nativeSetControlAvailable(handle, available)
    }

    /** Macs paired with this phone, oldest first as stored; null if the core is closed or the store unreadable. */
    fun listPaired(): List<PairedMac>? = if (handle == 0L) null else parsePaired(nativeListPaired(handle))

    /** Forget a paired Mac (it is disconnected if connected). True if it existed. */
    fun revoke(clientId: String): Boolean = handle != 0L && nativeRevoke(handle, clientId)

    /**
     * Replace the pairing PIN and end any PIN lockout; the new PIN, or null if closed. It does
     * not call [CoreCallbacks.onPinChanged]. Quick: it takes the same short lock as [pin].
     */
    fun newPin(): NewPin? {
        if (handle == 0L) return null
        val pin = nativeNewPin(handle) ?: return null
        // Read after the reset: the count only grows, so this is at least that reset's count and
        // every failure counted before it carries a smaller one (see CoreCallbacks.onPairingFailed).
        val resets = nativePinResets(handle)
        return if (resets < 0) null else NewPin(pin, resets)
    }

    /** A "New PIN" result: the PIN and the core's "New PIN" count once it was applied. No PIN in [toString]. */
    class NewPin(val pin: String, val resets: Long) {
        override fun toString() = "NewPin(resets=$resets)"
    }

    override fun close() {
        // Zero the handle under the lock (later calls become no-ops), then
        // destroy outside it so a slow shutdown does not block other callers.
        val h = synchronized(this) { handle.also { handle = 0L } }
        if (h != 0L) nativeDestroy(h)
    }

    companion object {
        init {
            System.loadLibrary("mirror_core")
        }

        @JvmStatic
        external fun nativeVersion(): String

        @JvmStatic
        external fun nativeCreate(configJson: String, callbacks: CoreCallbacks): Long

        @JvmStatic
        external fun nativeGetPort(handle: Long): Int

        @JvmStatic
        external fun nativeSetDisplay(handle: Long, width: Int, height: Int, rotation: Int, dpi: Int)

        @JvmStatic
        external fun nativeSetScreenState(handle: Long, on: Boolean)

        @JvmStatic
        external fun nativeNetworkChanged(handle: Long)

        @JvmStatic
        external fun nativeProjectionRevoked(handle: Long)

        @JvmStatic
        external fun nativeGetPin(handle: Long): String

        @JvmStatic
        external fun nativeSetControlAvailable(handle: Long, available: Boolean)

        /** The list's JSON; null when the core is closed or the store cannot be read. */
        @JvmStatic
        external fun nativeListPaired(handle: Long): String?

        @JvmStatic
        external fun nativeRevoke(handle: Long, clientId: String): Boolean

        @JvmStatic
        external fun nativeDestroy(handle: Long)

        /** New PIN, lockout cleared; null if the handle is closed. */
        @JvmStatic
        external fun nativeNewPin(handle: Long): String?

        /** How many times "New PIN" has run (only grows); -1 if the handle is closed. */
        @JvmStatic
        external fun nativePinResets(handle: Long): Long

        // Handle-free: read / edit the pairing store in filesDir while no core runs. Never call
        // them while a core is alive (it would write its cached pairings back): go through
        // [Pairings], which serializes them with core start and close.

        /** The list's JSON; null (or, from older cores, "[]") when the store cannot be read. */
        @JvmStatic
        external fun nativeListPairedIn(filesDir: String): String?

        @JvmStatic
        external fun nativeRevokeIn(filesDir: String, clientId: String): Boolean

        internal fun listPairedIn(filesDir: String): List<PairedMac>? = parsePaired(nativeListPairedIn(filesDir))
    }
}
