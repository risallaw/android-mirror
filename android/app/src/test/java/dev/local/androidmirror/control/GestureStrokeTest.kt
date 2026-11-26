package dev.local.androidmirror.control

import android.view.KeyEvent
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class GestureStrokeTest {
    private fun stroke(kind: Int, xs: FloatArray, ys: FloatArray = xs, ms: Long = 0) = gestureStroke(kind, xs, ys, ms, 1080, 2400)

    @Test fun aTapUsesTheFirstPointAndTheDefaultDuration() {
        val s = stroke(1, floatArrayOf(10f, 20f))!!
        assertArrayEquals(floatArrayOf(10f), s.xs, 0f)
        assertEquals(TAP_MS, s.durationMs)
        assertEquals(30L, stroke(1, floatArrayOf(10f), ms = 30)!!.durationMs)
    }

    @Test fun aLongPressDefaultsToItsOwnDuration() {
        assertEquals(LONG_PRESS_MS, stroke(2, floatArrayOf(1f), ms = -5)!!.durationMs)
        assertEquals(1, stroke(2, floatArrayOf(1f, 2f))!!.xs.size)
    }

    @Test fun aPathKeepsItsPointsAndDurationClamped() {
        val s = stroke(3, floatArrayOf(1f, 2f, 3f), ms = 0)!!
        assertEquals(3, s.xs.size)
        assertEquals(1L, s.durationMs)
        assertEquals(MAX_GESTURE_MS, stroke(3, floatArrayOf(1f), ms = Long.MAX_VALUE)!!.durationMs)
        assertEquals(MAX_GESTURE_MS, stroke(1, floatArrayOf(1f), ms = 60_000)!!.durationMs)
    }

    @Test fun pointsAreCappedAndClampedToTheScreen() {
        val many = FloatArray(1000) { it.toFloat() }
        assertEquals(MAX_GESTURE_POINTS, stroke(3, many)!!.xs.size)
        val s = gestureStroke(3, floatArrayOf(-5f, 5000f), floatArrayOf(9000f, -1f), 100, 1080, 2400)!!
        assertArrayEquals(floatArrayOf(0f, 1079f), s.xs, 0f)
        assertArrayEquals(floatArrayOf(2399f, 0f), s.ys, 0f)
    }

    @Test fun mismatchedArraysUseTheShorter() = assertEquals(1, stroke(3, floatArrayOf(1f, 2f), floatArrayOf(1f))!!.xs.size)

    @Test fun nothingForAnUnknownKindOrNoPoints() {
        assertNull(stroke(0, floatArrayOf(1f)))
        assertNull(stroke(4, floatArrayOf(1f)))
        assertNull(stroke(1, floatArrayOf()))
    }
}

class ImeKeyCodeTest {
    @Test fun everyMacKeyHasItsAndroidCode() {
        val expected = mapOf(
            1 to KeyEvent.KEYCODE_DEL, 2 to KeyEvent.KEYCODE_ENTER, 3 to KeyEvent.KEYCODE_DPAD_LEFT,
            4 to KeyEvent.KEYCODE_DPAD_RIGHT, 5 to KeyEvent.KEYCODE_DPAD_UP, 6 to KeyEvent.KEYCODE_DPAD_DOWN,
            7 to KeyEvent.KEYCODE_FORWARD_DEL, 8 to KeyEvent.KEYCODE_TAB,
        )
        for ((key, code) in expected) assertEquals("key $key", code, imeKeyCode(key))
    }

    @Test fun unknownKeysHaveNone() {
        assertNull(imeKeyCode(0))
        assertNull(imeKeyCode(9))
        assertNull(imeKeyCode(-1))
    }
}
