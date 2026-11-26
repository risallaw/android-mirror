package dev.local.androidmirror.control

import android.content.ClipData
import android.os.PersistableBundle

/**
 * Lends the clipboard to pastes and gives it back afterwards. Back-to-back pastes share one
 * restore: the user's clip is saved before the first paste and put back (or the clipboard is
 * cleared) [delayMs] after the last one. A per-paste restore would clear the clipboard under a
 * slower asynchronous paste (WebView) and, when the previous clip is readable, leave our own
 * typed text on the clipboard. All calls on one thread.
 */
internal class ClipboardLease<C : Any>(
    /** The current clip, or null if there is none or it cannot be read. */
    private val read: () -> C?,
    /** Set the clip (null clears the clipboard); false if that failed. */
    private val write: (C?) -> Boolean,
    private val schedule: (Runnable, Long) -> Unit,
    private val cancel: (Runnable) -> Unit,
    private val delayMs: Long,
) {
    private var saved: C? = null
    private var lent = false

    /** Whether a clip of ours reached the clipboard during this lease (else there is nothing to undo). */
    private var changed = false

    private val restore = Runnable {
        val s = saved
        saved = null
        lent = false
        // An unreadable user clip is saved as null, so "restoring" it clears the clipboard: only
        // do that when our text is on it, never after a write of ours that failed.
        if (changed) write(s)
        changed = false
    }

    /**
     * Put [clip] on the clipboard, run [paste], and schedule the restore. False, without
     * pasting, if [clip] could not be set (the paste would insert whatever was there).
     */
    fun paste(clip: C, paste: () -> Boolean): Boolean {
        if (lent) cancel(restore) else saved = read()
        lent = true
        val wrote = write(clip)
        if (wrote) changed = true
        val ok = wrote && paste()
        schedule(restore, if (ok) delayMs else 0L)
        return ok
    }

    /** Restore now if a restore is pending (the thread that would run it is going away). */
    fun flush() {
        if (!lent) return
        cancel(restore)
        restore.run()
    }
}

/**
 * A plain-text clip marked sensitive, so the Android 13+ clipboard preview and keyboards'
 * clipboard history do not show or keep it (typed text may be a password). The extra's literal
 * key is what `ClipDescription.EXTRA_IS_SENSITIVE` holds on 33+ and what keyboards honour on
 * older releases.
 */
internal fun sensitiveTextClip(text: String): ClipData = ClipData.newPlainText("", text).apply {
    description.extras = PersistableBundle().apply { putBoolean(EXTRA_IS_SENSITIVE, true) }
}

internal const val EXTRA_IS_SENSITIVE = "android.content.extra.IS_SENSITIVE"
