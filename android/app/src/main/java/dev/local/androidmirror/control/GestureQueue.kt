package dev.local.androidmirror.control

/**
 * One finger stroke through ([xs], [ys]) (screen pixels) over [durationMs], then, if [holdMs] > 0,
 * held still at its end for that long before lifting, so it ends with no velocity.
 */
internal class Stroke(val xs: FloatArray, val ys: FloatArray, val durationMs: Long, val holdMs: Long = 0)

/** A scroll at ([x], [y]) by the finger-drag ([dx], [dy]). */
internal class Scroll(val x: Float, val y: Float, var dx: Float, var dy: Float)

/**
 * Runs strokes one at a time: the next one starts only after the previous one ended
 * (overlapping dispatches cancel each other). Queued scrolls at the same point are coalesced so a
 * fast trackpad does not build a backlog, and a scroll too short to dispatch ([toStroke] gives
 * null: it would be taken for a tap) is held back and added to the next one at the same point.
 * A watchdog ends a stroke whose end is never reported. All calls on one thread.
 */
internal class GestureQueue(
    /** Start [Stroke]; call the callback once when it ended (completed or cancelled). False if refused. */
    private val dispatch: (Stroke, () -> Unit) -> Boolean,
    private val toStroke: (Scroll) -> Stroke?,
    private val schedule: (Runnable, Long) -> Unit,
    private val cancel: (Runnable) -> Unit,
    private val watchdogMs: Long = WATCHDOG_MS,
    private val maxQueue: Int = MAX_QUEUE,
) {
    private val queue = ArrayDeque<Any>()
    private var inFlight = false
    private var held: Scroll? = null

    /** Invalidates the end report of a finished or cleared stroke. */
    private var token = 0
    private var watchdog: Runnable? = null

    fun stroke(s: Stroke) = enqueue(s)

    fun scroll(x: Float, y: Float, dx: Float, dy: Float) {
        val last = queue.lastOrNull()
        if (last is Scroll && last.x == x && last.y == y) {
            last.dx += dx
            last.dy += dy
            return
        }
        val h = held
        held = null
        if (h != null && h.x == x && h.y == y) enqueue(Scroll(x, y, h.dx + dx, h.dy + dy)) else enqueue(Scroll(x, y, dx, dy))
    }

    /** Drop everything queued; a stroke in flight is forgotten. */
    fun clear() {
        queue.clear()
        held = null
        inFlight = false
        token++
        stopWatchdog()
    }

    private fun enqueue(item: Any) {
        if (queue.size >= maxQueue) queue.removeFirst()
        queue.addLast(item)
        pump()
    }

    private fun pump() {
        while (!inFlight) {
            val stroke = when (val item = queue.removeFirstOrNull() ?: return) {
                is Stroke -> item
                is Scroll -> toStroke(item) ?: run {
                    held = item
                    null
                }
                else -> null
            } ?: continue
            inFlight = true
            val my = ++token
            if (!dispatch(stroke) { ended(my) }) {
                inFlight = false
                continue
            }
            // Never wedge the queue if the system loses the end report.
            if (my == token && inFlight) {
                val w = Runnable { ended(my) }
                watchdog = w
                schedule(w, stroke.durationMs + stroke.holdMs + watchdogMs)
            }
        }
    }

    private fun ended(my: Int) {
        if (my != token || !inFlight) return
        inFlight = false
        stopWatchdog()
        pump()
    }

    private fun stopWatchdog() {
        watchdog?.let(cancel)
        watchdog = null
    }

    companion object {
        const val WATCHDOG_MS = 2_000L
        const val MAX_QUEUE = 32
    }
}
