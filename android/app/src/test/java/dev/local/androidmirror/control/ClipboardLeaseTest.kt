package dev.local.androidmirror.control

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Test

class ClipboardLeaseTest {
    /** A clipboard plus a fake main-thread clock. */
    private class Fixture(var clip: String?, var writable: Boolean = true) {
        var now = 0L
        val tasks = mutableListOf<Pair<Long, Runnable>>()
        val lease = ClipboardLease(
            read = { clip },
            write = { c -> if (writable) clip = c; writable },
            schedule = { r, d -> tasks += (now + d) to r },
            cancel = { r -> tasks.removeAll { it.second === r } },
            delayMs = 500,
        )

        fun advance(ms: Long) {
            now += ms
            tasks.filter { it.first <= now }.sortedBy { it.first }.forEach { t ->
                tasks.remove(t)
                t.second.run()
            }
        }
    }

    @Test
    fun singlePasteRestoresTheUsersClip() {
        val f = Fixture("user")
        var seen: String? = null
        f.lease.paste("a") { seen = f.clip; true }
        assertEquals("a", seen)
        f.advance(500)
        assertEquals("user", f.clip)
    }

    @Test
    fun backToBackPastesRestoreTheUsersClipNotOurText() {
        val f = Fixture("user")
        f.lease.paste("a") { true }
        f.advance(100)
        f.lease.paste("b") { true }
        f.advance(1000)
        assertEquals("user", f.clip)
    }

    @Test
    fun anEarlierRestoreDoesNotPullTheClipFromUnderALaterPaste() {
        val f = Fixture(null) // background apps usually cannot read the clipboard
        f.lease.paste("a") { true }
        f.advance(400)
        f.lease.paste("b") { true }
        f.advance(200) // 600 ms after the first paste, 200 ms after the second
        assertEquals("b", f.clip)
        // Then cleared: the user's clip could not be read, and typed text (maybe a password) must
        // not stay behind. That loss is why TextInjector pastes only as a last resort and tells
        // the user when it did (ControlBridge.clipboardUsed).
        f.advance(300)
        assertNull(f.clip)
    }

    @Test
    fun failedWriteDoesNotPaste() {
        val f = Fixture("user", writable = false)
        var pasted = false
        assertFalse(f.lease.paste("a") { pasted = true; true })
        assertFalse(pasted)
        f.advance(0)
        assertEquals("user", f.clip)
    }

    @Test
    fun aFailedWriteLeavesAnUnreadableClipAlone() {
        // From Android 10 the user's clip cannot be read (saved as null). If our write fails, the
        // user's clip is still there; "restoring" null would clear it.
        val f = Fixture("user")
        var writes = 0
        val lease = ClipboardLease<String>(
            read = { null },
            write = { c -> writes++; if (writes == 1) false else { f.clip = c; true } },
            schedule = { r, d -> f.tasks += (f.now + d) to r },
            cancel = { r -> f.tasks.removeAll { it.second === r } },
            delayMs = 500,
        )
        assertFalse(lease.paste("a") { true })
        f.advance(500)
        assertEquals("user", f.clip)
        assertEquals(1, writes)
    }

    @Test
    fun failedPasteRestoresImmediately() {
        val f = Fixture("user")
        assertFalse(f.lease.paste("a") { false })
        f.advance(0)
        assertEquals("user", f.clip)
    }
}

class ClipboardLeaseFlushTest {
    @Test
    fun flushRestoresNowAndCancelsTheScheduledRestore() {
        var clip: String? = "user"
        val tasks = mutableListOf<Runnable>()
        val lease = ClipboardLease(
            read = { clip },
            write = { c -> clip = c; true },
            schedule = { r, _ -> tasks += r },
            cancel = { r -> tasks.remove(r) },
            delayMs = 500,
        )
        lease.paste("typed") { true }
        lease.flush() // the service is going away: its thread will not run the restore later
        assertEquals("user", clip)
        assertEquals(0, tasks.size)
        lease.flush() // idempotent: nothing lent
        assertEquals("user", clip)
    }
}
