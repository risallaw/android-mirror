package dev.local.androidmirror.service

import android.os.Handler
import android.os.Looper
import dev.local.androidmirror.core.CoreCallbacks
import dev.local.androidmirror.core.PairedMac

/** What the mirroring session is doing, as shown by the UI and notification. */
enum class Phase { IDLE, STARTING, WAITING, CONNECTING, STREAMING, STOPPING, ERROR }

data class MirrorStatus(
    val phase: Phase = Phase.IDLE,
    /** LAN IPv4 of the phone, null when not on Wi-Fi/LAN. */
    val ip: String? = null,
    val port: Int = 0,
    /** The connected Mac's name as it sent it (see [peerText]); null if none or blank. */
    val clientName: String? = null,
    /** e.g. "864×1920 · 60 fps". */
    val streamInfo: String? = null,
    val error: String? = null,
    /** Current pairing PIN ("" if none). Shown while waiting for a Mac. */
    val pin: String = "",
    /** Paired Macs; null until loaded, or when the store could not be read ([pairedUnreadable]). */
    val paired: List<PairedMac>? = null,
    val pairedUnreadable: Boolean = false,
    /** Last pairing problem to show next to the PIN, e.g. "Wrong PIN from … — 3 tries left". */
    val pairingMessage: String? = null,
    /** The core's "New PIN" count [pairingMessage] was counted under (see [pairingFailureApplies]). */
    val pairingMessageResets: Long = 0,
    /** The core's "New PIN" count after the last New PIN applied (see [withNewPin]). */
    val pinResets: Long = 0,
    /** A "New PIN" request is in flight. */
    val newPinPending: Boolean = false,
) {
    val address: String? get() = if (ip != null && port > 0) "$ip:$port" else null
    /** The PIN is only useful while no Mac is connected. */
    val showPin: Boolean get() = phase == Phase.WAITING && pin.isNotEmpty()
    /** A session is up or coming up; not while it is [Phase.STOPPING]. */
    val running: Boolean
        get() = phase == Phase.STARTING || phase == Phase.WAITING || phase == Phase.CONNECTING || phase == Phase.STREAMING

    /**
     * Only what [Notifications.build] shows, so a PIN, pairing-message or paired-list change
     * does not re-post an identical notification (each is an IPC and counts toward the
     * system's per-app notification rate limit).
     */
    fun notificationFields(): MirrorStatus =
        MirrorStatus(phase = phase, ip = ip, port = port, clientName = clientName, streamInfo = streamInfo)

    /** Without the PIN: a status may end up in a log or crash report. */
    override fun toString(): String =
        "MirrorStatus(phase=$phase, ip=$ip, port=$port, clientName=$clientName, streamInfo=$streamInfo, " +
            "error=$error, pin=${if (pin.isEmpty()) "none" else "<redacted>"}, paired=${paired?.size}, " +
            "pairedUnreadable=$pairedUnreadable, pairingMessage=$pairingMessage, pairingMessageResets=$pairingMessageResets, " +
            "pinResets=$pinResets, newPinPending=$newPinPending)"

    /** With the paired list loaded by [dev.local.androidmirror.core.Pairings] (null: unreadable). */
    fun withPaired(list: List<PairedMac>?): MirrorStatus =
        copy(paired = list, pairedUnreadable = list == null)
}

/**
 * The status after a client state change ([CoreCallbacks.onClientState]) and the session it now
 * tracks (0: none). Only the tracked (latest) session moves the status on: a replaced client's
 * late STREAMING or DISCONNECTED must not override the new one.
 */
internal fun applyClientState(s: MirrorStatus, tracked: Long, state: Int, sessionId: Long, name: String?): Pair<MirrorStatus, Long> {
    val label = peerText(name)?.takeIf { it.isNotBlank() }
    return when {
        state == CoreCallbacks.STATE_CONNECTING ->
            s.copy(phase = Phase.CONNECTING, clientName = label, streamInfo = null, error = null) to sessionId
        sessionId != tracked -> s to tracked
        state == CoreCallbacks.STATE_STREAMING -> s.copy(phase = Phase.STREAMING, clientName = label) to tracked
        state == CoreCallbacks.STATE_DISCONNECTED ->
            s.copy(phase = Phase.WAITING, clientName = null, streamInfo = null) to 0L
        else -> s to tracked
    }
}

/**
 * The status once the core is up at [ip]:[port] with [pin]. Events the core reported before this
 * (a Mac connecting in its first milliseconds, a wrong PIN) are kept: only a session still
 * STARTING becomes WAITING.
 */
internal fun coreReady(s: MirrorStatus, ip: String?, port: Int, pin: String): MirrorStatus =
    s.copy(phase = if (s.phase == Phase.STARTING) Phase.WAITING else s.phase, ip = ip, port = port, pin = pin)

/** The status from Stop until the shutdown finishes: no PIN, address or client any more. */
internal fun stoppingStatus(s: MirrorStatus): MirrorStatus =
    MirrorStatus(phase = Phase.STOPPING, paired = s.paired, pairedUnreadable = s.pairedUnreadable)

/**
 * The status after a "New PIN" that left the core's count at [resets]: the core rotated the PIN
 * and cleared any lockout, so a wrong-PIN or lockout message counted before it (a smaller count)
 * no longer holds. One counted at [resets] is kept: it is a failure against the new PIN, and wiping
 * it would hide a real lockout. A null [pin] (the core closed meanwhile) changes only the pending flag.
 */
internal fun withNewPin(s: MirrorStatus, pin: String?, resets: Long): MirrorStatus = when {
    pin == null -> s.copy(newPinPending = false)
    s.pairingMessageResets < resets ->
        s.copy(pin = pin, pinResets = maxOf(s.pinResets, resets), pairingMessage = null, newPinPending = false)
    else -> s.copy(pin = pin, pinResets = maxOf(s.pinResets, resets), newPinPending = false)
}

/** Whether a "New PIN" asked of [startedCore] in session [startedGen] still belongs to the session on screen. */
internal fun newPinResultApplies(startedGen: Int, gen: Int, live: Boolean, startedCore: Any, core: Any?): Boolean =
    startedGen == gen && live && startedCore === core

/**
 * The PIN to show once "New PIN" returned [returned] (null: failed), or null to show none. It is
 * read again from the core ([livePin]): the server may have rotated it once more (a lockout)
 * before this result reached the main thread, and its `onPinChanged` may have been applied first.
 */
internal fun newPinToShow(applies: Boolean, returned: String?, livePin: () -> String): String? =
    if (applies && returned != null) livePin() else null

/**
 * Whether a wrong-PIN / lockout report counted under the core's "New PIN" count [resets] still
 * holds: not if a New PIN already applied ([pinResets], see [withNewPin]) came after it, as that
 * cleared it. The server reports outside its lock, so a report from before a New PIN can reach the
 * main thread after it. One counted at [pinResets] or later is against the current PIN and is kept.
 */
internal fun pairingFailureApplies(live: Boolean, resets: Long, pinResets: Long): Boolean =
    live && resets >= pinResets

/** A lockout of [ms] as (hours, minutes, seconds) to show, rounded up: seconds only under a minute. */
internal fun lockoutParts(ms: Long): Triple<Long, Long, Long> {
    val secs = (maxOf(ms, 0L) + 999) / 1000
    if (secs < 60) return Triple(0, 0, secs)
    val mins = (secs + 59) / 60
    return Triple(mins / 60, mins % 60, 0)
}

/**
 * Text a peer chose (a Mac's name, an address), made safe to log and show: control and
 * bidi-formatting characters escaped (no forged log lines, no reordered UI text) as `\uXXXX`, or
 * `\u{XXXXX}` above U+FFFF (so a digit after it cannot be read as part of it), at most [max]
 * characters plus "…" when cut.
 */
fun peerText(s: String?, max: Int = 64): String? {
    if (s == null) return null
    val out = StringBuilder()
    var i = 0
    while (i < s.length) {
        val cp = s.codePointAt(i)
        val n = Character.charCount(cp)
        // A lone surrogate is malformed text: escaped like a control character.
        val piece = if (Character.isISOControl(cp) || Character.getType(cp) == Character.FORMAT.toInt() ||
            Character.getType(cp) == Character.SURROGATE.toInt()
        ) {
            if (cp > 0xFFFF) "\\u{%x}".format(cp) else "\\u%04x".format(cp)
        } else {
            String(Character.toChars(cp))
        }
        // Cut before a piece that does not fit whole: never between a pair's halves or in an escape.
        if (out.length + piece.length > max) break
        out.append(piece)
        i += n
    }
    return if (i < s.length) out.append('…').toString() else out.toString()
}

/**
 * Process-wide session state written by [MirrorService] (and, for the paired list while idle,
 * the UI) and shown by the UI.
 * Listeners are invoked on the main thread.
 */
object MirrorState {
    private val main = Handler(Looper.getMainLooper())
    private val listeners = mutableSetOf<(MirrorStatus) -> Unit>()

    @Volatile
    var current = MirrorStatus()
        private set

    /** Apply [change] on the main thread and notify listeners if it changed something. */
    fun update(change: (MirrorStatus) -> MirrorStatus) {
        if (Looper.myLooper() != Looper.getMainLooper()) {
            main.post { update(change) }
            return
        }
        val next = change(current)
        if (next == current) return
        current = next
        listeners.toList().forEach { it(next) }
    }

    /** Main thread only. The listener is called immediately with the current state. */
    fun observe(listener: (MirrorStatus) -> Unit) {
        listeners += listener
        listener(current)
    }

    fun remove(listener: (MirrorStatus) -> Unit) {
        listeners -= listener
    }
}

/** "123456" -> "123 456" for reading aloud and at a glance. */
fun groupPin(pin: String): String =
    if (pin.length == 6) "${pin.substring(0, 3)} ${pin.substring(3)}" else pin
