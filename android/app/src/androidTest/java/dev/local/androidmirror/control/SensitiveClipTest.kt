package dev.local.androidmirror.control

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** Runs on a device: ClipData and PersistableBundle are framework classes. */
class SensitiveClipTest {
    @Test
    fun typedTextClipIsMarkedSensitive() {
        val clip = sensitiveTextClip("hunter2")
        assertEquals("hunter2", clip.getItemAt(0).text.toString())
        assertTrue(clip.description.extras?.getBoolean(EXTRA_IS_SENSITIVE) == true)
    }

    @Test
    fun extraKeyMatchesThePlatformConstant() {
        if (android.os.Build.VERSION.SDK_INT >= 33) {
            assertEquals(android.content.ClipDescription.EXTRA_IS_SENSITIVE, EXTRA_IS_SENSITIVE)
        }
    }
}
