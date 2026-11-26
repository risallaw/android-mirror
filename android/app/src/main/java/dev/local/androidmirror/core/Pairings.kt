package dev.local.androidmirror.core

import android.os.Handler
import android.os.Looper
import android.util.Log
import java.io.File
import java.util.concurrent.Executors

/**
 * Paired Macs, listed and removed whether or not mirroring runs. While a core runs, its
 * handle-based calls are used (a revoked Mac that is connected is disconnected); otherwise the
 * store file is read / edited directly. [MirrorService][dev.local.androidmirror.service.MirrorService]
 * starts and closes its core through [start] / [close] so the two never overlap (see [StoreGuard]).
 */
object Pairings {
    private const val TAG = "Pairings"
    private val guard = StoreGuard<NativeCore>()
    private val io = Executors.newSingleThreadExecutor { r -> Thread(r, "pairings") }
    private val main = Handler(Looper.getMainLooper())

    /** Start [core]; until [close] returns it owns the store. */
    fun start(core: NativeCore, configJson: String): Boolean = guard.start(core) { core.start(configJson) }

    /** Close [core] (blocking; not on the main thread) and release the store. */
    fun close(core: NativeCore) = guard.close(core) { core.close() }

    /**
     * Load the list on a background thread; [done] runs on the main thread with it, or null if
     * the store could not be read. Every load and removal runs on one thread in call order, so
     * results arrive in that order too: the last one is the newest.
     */
    fun refresh(filesDir: File, done: (List<PairedMac>?) -> Unit) {
        io.execute {
            val list = list(filesDir)
            main.post { done(list) }
        }
    }

    /** Forget [clientId], then reload the list; [done] (removed?, list) runs on the main thread. */
    fun remove(filesDir: File, clientId: String, done: (Boolean, List<PairedMac>?) -> Unit) {
        io.execute {
            val removed = native(false) {
                guard.use(idle = { NativeCore.nativeRevokeIn(filesDir.absolutePath, clientId) }, running = { it.revoke(clientId) })
            }
            val list = list(filesDir)
            main.post { done(removed, list) }
        }
    }

    private fun list(filesDir: File): List<PairedMac>? = native(null) {
        guard.use(idle = { NativeCore.listPairedIn(filesDir.absolutePath) }, running = { it.listPaired() })
    }

    /** A core library that is missing leaves the list unreadable instead of crashing. */
    private inline fun <T> native(fallback: T, block: () -> T): T = try {
        block()
    } catch (e: LinkageError) {
        Log.w(TAG, "native pairing call unavailable: $e")
        fallback
    }
}

/**
 * Whether a [Pairings.remove] really forgot [clientId]. Both are needed: a running core drops the
 * Mac from memory before saving, so a failed save returns false while the reloaded list no longer
 * shows it (it would come back, key and all, after Stop); and a false revoke can't be told apart
 * from "already gone", which is rare enough (the Mac was on screen) to report as a failure too.
 */
internal fun removeSucceeded(removed: Boolean, clientId: String, list: List<PairedMac>?): Boolean =
    removed && list?.any { it.clientId == clientId } != true
