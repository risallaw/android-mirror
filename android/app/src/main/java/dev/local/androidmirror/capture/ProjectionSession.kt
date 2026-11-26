package dev.local.androidmirror.capture

import android.hardware.display.DisplayManager
import android.hardware.display.VirtualDisplay
import android.media.projection.MediaProjection
import android.os.Handler
import android.util.Log
import android.view.Surface

/**
 * The single VirtualDisplay of one MediaProjection. It is created exactly once
 * with a null surface (Android 14+ forbids a second createVirtualDisplay per
 * projection); the Rust encoder attaches and detaches its input surface through
 * [onSurfaceReady]/[onSurfaceGone], called on Rust threads. All VirtualDisplay
 * access is under [lock]; nothing calls into native code while holding it.
 */
class ProjectionSession(private val projection: MediaProjection) {
    private val lock = Any()
    private var virtualDisplay: VirtualDisplay? = null
    private var surface: Surface? = null
    private var width = 0
    private var height = 0
    private var dpi = 160
    private var released = false

    /** Create the VirtualDisplay (once). */
    fun create(initial: DisplaySnapshot, handler: Handler) = synchronized(lock) {
        check(virtualDisplay == null && !released) { "VirtualDisplay already created" }
        width = initial.width
        height = initial.height
        dpi = initial.dpi
        virtualDisplay = projection.createVirtualDisplay(
            "AndroidMirror",
            initial.width,
            initial.height,
            initial.dpi,
            DisplayManager.VIRTUAL_DISPLAY_FLAG_AUTO_MIRROR,
            null,
            null,
            handler,
        )
    }

    /** Apply a new screen density now; the size stays until the encoder attaches its surface. */
    fun setDensity(newDpi: Int) = synchronized(lock) {
        if (newDpi == dpi) return@synchronized
        dpi = newDpi
        if (!released) virtualDisplay?.resize(width, height, dpi)
    }

    fun onSurfaceReady(newSurface: Surface, width: Int, height: Int) = synchronized(lock) {
        val vd = virtualDisplay
        if (vd == null || released) {
            newSurface.release()
            return@synchronized
        }
        vd.resize(width, height, dpi)
        this.width = width
        this.height = height
        vd.surface = newSurface
        surface?.takeIf { it !== newSurface }?.release()
        surface = newSurface
        Log.i(TAG, "encoder surface attached ${width}x$height @${dpi}dpi")
    }

    /**
     * Detach and re-attach the current surface: the display then composites a
     * fresh frame even when nothing on screen changed. The gap lets the display
     * apply the detach first (back-to-back calls collapse into no change). Throws
     * without a display or surface (the core then restarts the codec, which attaches
     * a new one). Called on the encoder thread.
     */
    fun refreshSurface() {
        val s = synchronized(lock) {
            val vd = virtualDisplay ?: throw IllegalStateException("no VirtualDisplay")
            val s = surface ?: throw IllegalStateException("no encoder surface")
            vd.surface = null
            s
        }
        Thread.sleep(REFRESH_GAP_MS)
        synchronized(lock) {
            // Unless the surface was replaced or released meanwhile.
            if (surface === s) virtualDisplay?.surface = s
        }
        Log.d(TAG, "encoder surface re-attached")
    }

    fun onSurfaceGone() = synchronized(lock) {
        virtualDisplay?.surface = null
        surface?.release()
        surface = null
        Log.i(TAG, "encoder surface detached")
    }

    /** Release the VirtualDisplay; safe to call more than once. */
    fun release() = synchronized(lock) {
        released = true
        virtualDisplay?.release()
        virtualDisplay = null
        surface?.release()
        surface = null
    }

    private companion object {
        const val TAG = "ProjectionSession"
        const val REFRESH_GAP_MS = 50L
    }
}
