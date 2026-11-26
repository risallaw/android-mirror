package dev.local.androidmirror.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

class StoreGuardTest {
    private val guard = StoreGuard<String>()
    private fun who() = guard.use(idle = { "file" }, running = { "core:$it" })

    @Test
    fun editsGoThroughTheRunningCoreAndToTheFileOtherwise() {
        assertEquals("file", who())
        assertTrue(guard.start("a") { true })
        assertEquals("core:a", who())
        guard.close("a") {}
        assertEquals("file", who())
    }

    @Test
    fun aCoreThatFailedToStartDoesNotOwnTheStore() {
        assertFalse(guard.start("a") { false })
        assertEquals("file", who())
    }

    @Test
    fun theCoreOwnsTheStoreUntilItIsClosed() {
        guard.start("a") { true }
        // A revoke while the core shuts down must not write the file under it (it would write its
        // cached pairings back), nor hit its zeroed handle and silently do nothing.
        var during: String? = null
        guard.close("a") { during = runOnOtherThread { who() } ?: "blocked" }
        assertEquals("blocked", during)
        assertEquals("file", who())
    }

    @Test
    fun aCoreCannotStartWhileAFileEditRuns() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val edit = thread { guard.use(idle = { entered.countDown(); release.await() }, running = {}) }
        assertTrue(entered.await(5, TimeUnit.SECONDS))
        var started = false
        val starter = thread { guard.start("a") { started = true; true } }
        starter.join(200)
        assertFalse("core started while the store file was being edited", started)
        release.countDown()
        starter.join(5000)
        edit.join(5000)
        assertTrue(started)
    }

    /** [block]'s result if it finishes on another thread within 200 ms, else null. */
    private fun <T> runOnOtherThread(block: () -> T): T? {
        var result: T? = null
        val t = thread { result = block() }
        t.join(200)
        return if (t.isAlive) null else result
    }
}
