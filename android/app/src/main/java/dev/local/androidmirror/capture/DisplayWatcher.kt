package dev.local.androidmirror.capture

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.graphics.Point
import android.hardware.display.DisplayManager
import android.os.Handler
import android.os.Looper
import android.util.DisplayMetrics
import android.view.Display
import androidx.core.content.ContextCompat

/** Size of the default display in its current orientation. */
data class DisplaySnapshot(val width: Int, val height: Int, val rotation: Int, val dpi: Int) {
    companion object {
        fun query(context: Context): DisplaySnapshot {
            val dm = context.getSystemService(DisplayManager::class.java)
            val display = dm.getDisplay(Display.DEFAULT_DISPLAY)
            // getRealSize/getRealMetrics are deprecated in favour of WindowMetrics, which
            // needs a visual (Activity) context; a foreground service has none.
            val size = Point()
            val metrics = DisplayMetrics()
            @Suppress("DEPRECATION")
            display.getRealSize(size)
            @Suppress("DEPRECATION")
            display.getRealMetrics(metrics)
            return DisplaySnapshot(size.x, size.y, display.rotation, metrics.densityDpi)
        }
    }
}

/**
 * Watches the default display (rotation, resolution changes and, on API 34+,
 * captured-content resizes forwarded by the projection callback) with a 150 ms
 * debounce, plus screen on/off broadcasts. Callbacks run on the main thread.
 */
class DisplayWatcher(
    private val context: Context,
    private val onDisplay: (DisplaySnapshot) -> Unit,
    private val onScreen: (Boolean) -> Unit,
) {
    private val handler = Handler(Looper.getMainLooper())
    private val displayManager = context.getSystemService(DisplayManager::class.java)
    private var last: DisplaySnapshot? = null
    private var started = false

    private val check = Runnable {
        val now = DisplaySnapshot.query(context)
        if (now != last) {
            last = now
            onDisplay(now)
        }
    }

    private val displayListener = object : DisplayManager.DisplayListener {
        override fun onDisplayAdded(displayId: Int) = Unit
        override fun onDisplayRemoved(displayId: Int) = Unit
        override fun onDisplayChanged(displayId: Int) {
            if (displayId == Display.DEFAULT_DISPLAY) schedule()
        }
    }

    private val screenReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            when (intent.action) {
                Intent.ACTION_SCREEN_ON -> onScreen(true)
                Intent.ACTION_SCREEN_OFF -> onScreen(false)
            }
        }
    }

    /** Start watching; [initial] is the snapshot the session was created with. */
    fun start(initial: DisplaySnapshot) {
        if (started) return
        started = true
        last = initial
        displayManager.registerDisplayListener(displayListener, handler)
        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_SCREEN_ON)
            addAction(Intent.ACTION_SCREEN_OFF)
        }
        ContextCompat.registerReceiver(context, screenReceiver, filter, ContextCompat.RECEIVER_NOT_EXPORTED)
    }

    /** Re-check after 150 ms of quiet (called for display and captured-content changes). */
    fun schedule() {
        if (!started) return
        handler.removeCallbacks(check)
        handler.postDelayed(check, DEBOUNCE_MS)
    }

    fun stop() {
        if (!started) return
        started = false
        handler.removeCallbacks(check)
        displayManager.unregisterDisplayListener(displayListener)
        runCatching { context.unregisterReceiver(screenReceiver) }
    }

    private companion object {
        const val DEBOUNCE_MS = 150L
    }
}
