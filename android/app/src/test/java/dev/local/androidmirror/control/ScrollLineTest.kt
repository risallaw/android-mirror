package dev.local.androidmirror.control

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class ScrollLineTest {
    private val slop = 21f // 8 dp at 420 dpi

    @Test
    fun dragShorterThanTheTouchSlopIsNotASwipe() {
        // A 150 ms swipe of a few pixels lands as a tap on whatever is under the cursor.
        assertNull(scrollLine(500f, 1000f, 0f, 5f, 1080, 2400, slop))
        assertNull(scrollLine(500f, 1000f, 14f, 14f, 1080, 2400, slop)) // ~19.8 px diagonal
        assertNull(scrollLine(500f, 1000f, 0f, 21f, 1080, 2400, slop))
    }

    @Test
    fun dragPastTheSlopIsASwipe() {
        assertArrayEquals(floatArrayOf(500f, 1000f, 500f, 880f), scrollLine(500f, 1000f, 0f, -120f, 1080, 2400, slop), 0f)
    }

    @Test
    fun clampingAtTheEdgeCanMakeItTooShort() {
        // Finger would leave the screen after 10 px: too short once clamped.
        assertNull(scrollLine(500f, 2389f, 0f, 120f, 1080, 2400, slop))
        assertArrayEquals(floatArrayOf(0f, 1000f, 1079f, 1000f), scrollLine(-50f, 1000f, 5000f, 0f, 1080, 2400, slop), 0f)
    }

    @Test
    fun clampToleratesAnEmptyScreen() {
        assertEquals(0f, clampTo(10f, 0), 0f)
        assertEquals(1079f, clampTo(5000f, 1080), 0f)
    }
}
