package dev.local.androidmirror.control

import android.accessibilityservice.AccessibilityService
import android.accessibilityservice.GestureDescription
import android.graphics.Path
import android.graphics.Rect
import android.hardware.display.DisplayManager
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.util.DisplayMetrics
import android.util.Log
import android.view.Display
import android.view.ViewConfiguration
import android.view.WindowManager
import kotlin.math.hypot

/**
 * Injects the Mac's touch gestures and scrolls, one at a time on the main thread (see
 * [GestureQueue]).
 */
class GestureInjector(private val service: AccessibilityService) {
    private val main = Handler(Looper.getMainLooper())
    private val touchSlop by lazy { ViewConfiguration.get(service).scaledTouchSlop.toFloat() }

    private val queue = GestureQueue(
        dispatch = ::dispatch,
        toStroke = ::swipe,
        schedule = { r, ms -> main.postDelayed(r, ms) },
        cancel = main::removeCallbacks,
    )

    /** kind: 1 tap, 2 long press, 3 path (see `CoreCallbacks.onGesture`). */
    fun gesture(kind: Int, xs: FloatArray, ys: FloatArray, durationMs: Long) {
        if (minOf(xs.size, ys.size) == 0) return
        val b = screen()
        gestureStroke(kind, xs, ys, durationMs, b.width(), b.height())?.let(queue::stroke)
    }

    /** Scroll = a short swipe by the finger-drag ([dx], [dy]), clamped to the screen (see [scrollLine]). */
    fun scroll(x: Float, y: Float, dx: Float, dy: Float) = queue.scroll(x, y, dx, dy)

    /** Drop everything queued (the service is going away). */
    fun clear() = queue.clear()

    /**
     * The swipe ends held still for [HOLD_MS]: lifted while moving, the target would fling on top
     * of the Mac's own scroll momentum (which arrives as further scrolls) and overshoot.
     */
    private fun swipe(s: Scroll): Stroke? {
        val b = screen()
        val line = scrollLine(s.x, s.y, s.dx, s.dy, b.width(), b.height(), touchSlop) ?: return null
        return Stroke(floatArrayOf(line[0], line[2]), floatArrayOf(line[1], line[3]), SCROLL_MS, HOLD_MS)
    }

    private fun dispatch(stroke: Stroke, ended: () -> Unit): Boolean {
        val path = Path().apply {
            moveTo(stroke.xs[0], stroke.ys[0])
            for (i in 1 until stroke.xs.size) lineTo(stroke.xs[i], stroke.ys[i])
        }
        val hold = stroke.holdMs > 0
        val first = GestureDescription.StrokeDescription(path, 0, stroke.durationMs, hold)
        return send(first) { completed ->
            if (!completed || !hold) {
                ended()
                return@send
            }
            val end = Path().apply { moveTo(stroke.xs.last(), stroke.ys.last()) }
            if (!send(first.continueStroke(end, 0, stroke.holdMs, false)) { ended() }) ended()
        }
    }

    /** Dispatch one stroke; [done] (completed?) runs on the main thread. False if refused. */
    private fun send(stroke: GestureDescription.StrokeDescription, done: (Boolean) -> Unit): Boolean {
        val callback = object : AccessibilityService.GestureResultCallback() {
            override fun onCompleted(gestureDescription: GestureDescription?) = done(true)
            override fun onCancelled(gestureDescription: GestureDescription?) = done(false)
        }
        return try {
            service.dispatchGesture(GestureDescription.Builder().addStroke(stroke).build(), callback, main)
        } catch (e: RuntimeException) {
            Log.w(TAG, "dispatchGesture failed", e)
            false
        }
    }

    /** Real display size in pixels (gestures use screen coordinates). */
    @Suppress("DEPRECATION")
    private fun screen(): Rect {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            return service.getSystemService(WindowManager::class.java).maximumWindowMetrics.bounds
        }
        val dm = service.getSystemService(DisplayManager::class.java)
        val display = dm.getDisplay(Display.DEFAULT_DISPLAY)
        val m = DisplayMetrics()
        display.getRealMetrics(m)
        return Rect(0, 0, m.widthPixels, m.heightPixels)
    }

    private companion object {
        const val TAG = "GestureInjector"
        const val SCROLL_MS = 100L

        /** Longer than the 100 ms window the platform's VelocityTracker estimates a fling from. */
        const val HOLD_MS = 120L
    }
}

internal const val TAP_MS = 50L
internal const val LONG_PRESS_MS = 650L
internal const val MAX_GESTURE_MS = 10_000L
internal const val MAX_GESTURE_POINTS = 256

/**
 * The stroke for a gesture of [kind] (1 tap, 2 long press, 3 path) on a [width]x[height] screen:
 * a tap or long press uses the first point and its default duration when none (<= 0) is given; a
 * path keeps up to [MAX_GESTURE_POINTS]. Points are clamped to the screen and the duration to
 * 1..[MAX_GESTURE_MS]. Null for no points or an unknown kind.
 */
internal fun gestureStroke(kind: Int, xs: FloatArray, ys: FloatArray, durationMs: Long, width: Int, height: Int): Stroke? {
    val n = minOf(xs.size, ys.size, MAX_GESTURE_POINTS)
    if (n == 0) return null
    val (points, duration) = when (kind) {
        1 -> 1 to if (durationMs > 0) durationMs else TAP_MS
        2 -> 1 to if (durationMs > 0) durationMs else LONG_PRESS_MS
        3 -> n to durationMs
        else -> return null
    }
    val px = FloatArray(points) { clampTo(xs[it], width) }
    val py = FloatArray(points) { clampTo(ys[it], height) }
    return Stroke(px, py, duration.coerceIn(1, MAX_GESTURE_MS))
}

/** [v] clamped to 0..size-1 (0 for an empty size). */
internal fun clampTo(v: Float, size: Int): Float = v.coerceIn(0f, maxOf(size - 1, 0).toFloat())

/**
 * The swipe for a scroll at ([x], [y]) by ([dx], [dy]) on a [width]x[height] screen, as
 * `[x0, y0, x1, y1]`, or null when, after clamping to the screen, it would not move further
 * than [slop]: the target would take such a short swipe as a tap.
 */
internal fun scrollLine(x: Float, y: Float, dx: Float, dy: Float, width: Int, height: Int, slop: Float): FloatArray? {
    val x0 = clampTo(x, width)
    val y0 = clampTo(y, height)
    val x1 = clampTo(x + dx, width)
    val y1 = clampTo(y + dy, height)
    if (hypot(x1 - x0, y1 - y0) <= maxOf(slop, 1f)) return null
    return floatArrayOf(x0, y0, x1, y1)
}
