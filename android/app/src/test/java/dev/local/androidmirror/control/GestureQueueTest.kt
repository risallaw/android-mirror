package dev.local.androidmirror.control

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class GestureQueueTest {
    /** Records dispatches; strokes end only when the test says so. A fake main-thread clock. */
    private class Fixture(var accept: Boolean = true, val slop: Float = 5f) {
        val started = mutableListOf<Stroke>()
        val ends = mutableListOf<() -> Unit>()
        val tasks = mutableListOf<Pair<Long, Runnable>>()
        var now = 0L
        val q = GestureQueue(
            dispatch = { s, end ->
                if (accept) {
                    started += s
                    ends += end
                }
                accept
            },
            // A scroll becomes a stroke when it moves further than the slop.
            toStroke = { s -> if (kotlin.math.hypot(s.dx, s.dy) > slop) Stroke(floatArrayOf(s.x, s.x + s.dx), floatArrayOf(s.y, s.y + s.dy), 100, 120) else null },
            schedule = { r, ms -> tasks += (now + ms) to r },
            cancel = { r -> tasks.removeAll { it.second === r } },
            watchdogMs = 2_000,
            maxQueue = 4,
        )

        fun advance(ms: Long) {
            now += ms
            tasks.filter { it.first <= now }.sortedBy { it.first }.forEach { t ->
                tasks.remove(t)
                t.second.run()
            }
        }

        fun dy(i: Int) = started[i].ys[1] - started[i].ys[0]
    }

    private fun tap(x: Float = 1f) = Stroke(floatArrayOf(x), floatArrayOf(1f), 50)

    @Test
    fun strokesRunOneAtATime() {
        val f = Fixture()
        f.q.stroke(tap(1f))
        f.q.stroke(tap(2f))
        assertEquals(1, f.started.size)
        f.ends[0]()
        assertEquals(2, f.started.size)
        assertEquals(2f, f.started[1].xs[0])
    }

    @Test
    fun aFinishedStrokeCancelsItsWatchdog() {
        val f = Fixture()
        f.q.stroke(tap())
        assertEquals(1, f.tasks.size)
        assertEquals(50L + 2_000, f.tasks[0].first) // duration + watchdog
        f.ends[0]()
        assertTrue("watchdog left pending", f.tasks.isEmpty())
    }

    @Test
    fun theWatchdogCoversTheHoldToo() {
        val f = Fixture()
        f.q.scroll(10f, 10f, 0f, 50f)
        assertEquals(100L + 120 + 2_000, f.tasks.single().first)
    }

    @Test
    fun aLostEndReportDoesNotWedgeTheQueue() {
        val f = Fixture()
        f.q.stroke(tap(1f))
        f.q.stroke(tap(2f))
        f.advance(2_049)
        assertEquals(1, f.started.size)
        f.advance(1)
        assertEquals(2, f.started.size)
        f.ends[0]() // the late report of the first stroke must not end the second
        f.q.stroke(tap(3f))
        assertEquals(2, f.started.size)
    }

    @Test
    fun queuedScrollsAtOnePointAreCoalesced() {
        val f = Fixture()
        f.q.stroke(tap())
        repeat(3) { f.q.scroll(10f, 10f, 0f, 20f) }
        f.ends[0]()
        assertEquals(2, f.started.size)
        assertEquals(60f, f.dy(1))
    }

    @Test
    fun aScrollShorterThanTheSlopIsHeldAndAddedToTheNext() {
        val f = Fixture()
        f.q.scroll(10f, 10f, 0f, 3f) // would be a tap
        assertEquals(0, f.started.size)
        f.q.scroll(10f, 10f, 0f, 3f)
        assertEquals(6f, f.dy(0))
    }

    @Test
    fun aHeldScrollElsewhereIsDropped() {
        val f = Fixture()
        f.q.scroll(10f, 10f, 0f, 3f)
        f.q.scroll(99f, 10f, 0f, 6f)
        assertEquals(6f, f.dy(0))
    }

    @Test
    fun aRefusedDispatchMovesOn() {
        val f = Fixture(accept = false)
        f.q.stroke(tap(1f))
        f.accept = true
        f.q.stroke(tap(2f))
        assertEquals(2f, f.started.single().xs[0])
    }

    @Test
    fun theOldestIsDroppedWhenTheQueueIsFull() {
        val f = Fixture()
        f.q.stroke(tap(0f)) // in flight
        (1..5).forEach { f.q.stroke(tap(it.toFloat())) }
        repeat(5) { f.ends.last()() }
        assertEquals(listOf(0f, 2f, 3f, 4f, 5f), f.started.map { it.xs[0] })
    }

    @Test
    fun clearForgetsTheStrokeInFlightAndItsWatchdog() {
        val f = Fixture()
        f.q.stroke(tap(1f))
        f.q.stroke(tap(2f))
        f.q.clear()
        assertTrue(f.tasks.isEmpty())
        f.ends[0]() // late report
        assertEquals(1, f.started.size)
        f.q.stroke(tap(3f))
        assertEquals(3f, f.started.last().xs[0])
    }
}
