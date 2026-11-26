package dev.local.androidmirror.control

import android.content.Context
import android.os.Handler
import android.os.Looper
import android.util.Log
import androidx.core.content.edit
import dev.local.androidmirror.core.NativeCore
import java.util.concurrent.Executors

/**
 * Process-wide link between the Rust core's control callbacks (Rust threads), the
 * Accessibility service (main thread) and availability reporting back to the core.
 * Gestures and global actions are posted to the main thread; text and keys go to the
 * [TextInjector]'s own thread (its calls can block for seconds).
 */
object ControlBridge {
    private const val TAG = "ControlBridge"
    private val main = Handler(Looper.getMainLooper())

    // Main-thread state; `service` is also read by Rust threads for text input.
    @Volatile
    private var service: MirrorAccessibilityService? = null
    private var core: NativeCore? = null
    private val listeners = mutableSetOf<(Boolean) -> Unit>()

    private const val PREFS = "notes"
    private const val KEY_CLIPBOARD_USED = "clipboard_used"
    private val io = Executors.newSingleThreadExecutor { r -> Thread(r, "notes") }

    /**
     * True once typing from the Mac fell back to the clipboard (it may have been cleared), until
     * the user has seen the note ([acknowledgeNotes]). Kept across restarts of the app: the user
     * may only look after the session. Main thread.
     */
    var clipboardUsed = false
        private set

    /** True once typing from the Mac was not delivered, until the note was seen. Main thread. */
    var inputDropped = false
        private set

    /** True while the Accessibility service is enabled and bound. Main thread. */
    val isAvailable: Boolean get() = service != null

    /** Main thread. Called immediately with the current value. */
    fun observe(listener: (Boolean) -> Unit) {
        listeners += listener
        listener(isAvailable)
    }

    fun remove(listener: (Boolean) -> Unit) {
        listeners -= listener
    }

    /** Main thread. Binds the running core and tells it the current availability. */
    fun attachCore(c: NativeCore) {
        core = c
        c.setControlAvailable(isAvailable)
    }

    /** Main thread. Call before the core is closed. */
    fun detachCore() {
        core = null
    }

    internal fun serviceConnected(s: MirrorAccessibilityService) {
        service = s
        publish()
    }

    internal fun serviceDisconnected(s: MirrorAccessibilityService) {
        if (service !== s) return
        service = null
        publish()
    }

    private fun publish() {
        val available = isAvailable
        core?.setControlAvailable(available)
        listeners.toList().forEach { it(available) }
    }

    /** Main thread. Loads a clipboard note left by an earlier run of the app (off the main thread). */
    fun loadNotes(context: Context) {
        val app = context.applicationContext
        io.execute {
            if (prefs(app).getBoolean(KEY_CLIPBOARD_USED, false)) main.post { setClipboardUsed(null) }
        }
    }

    /** Main thread. The user has seen the notes: clear them. */
    fun acknowledgeNotes(context: Context) {
        if (!clipboardUsed && !inputDropped) return
        val app = context.applicationContext
        val hadClipboardNote = clipboardUsed
        clipboardUsed = false
        inputDropped = false
        if (hadClipboardNote) io.execute { prefs(app).edit { remove(KEY_CLIPBOARD_USED) } }
        publish()
    }

    private fun prefs(context: Context) = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    /** Main thread; [persist] is the context to save it with, or null if loaded from there. */
    private fun setClipboardUsed(persist: Context?) {
        if (clipboardUsed) return
        clipboardUsed = true
        if (persist != null) io.execute { prefs(persist).edit { putBoolean(KEY_CLIPBOARD_USED, true) } }
        publish()
    }

    // ---- Core callbacks: any thread in, main thread out. ----

    private inline fun withService(crossinline block: (MirrorAccessibilityService) -> Unit) {
        main.post {
            val s = service
            if (s == null) Log.d(TAG, "control input dropped: service not connected") else block(s)
        }
    }

    fun onGesture(kind: Int, xs: FloatArray, ys: FloatArray, durationMs: Long) =
        withService { it.gestures.gesture(kind, xs, ys, durationMs) }

    fun onScroll(x: Float, y: Float, dx: Float, dy: Float) =
        withService { it.gestures.scroll(x, y, dx, dy) }

    fun onGlobalAction(action: Int) = withService { it.globalActions.perform(action) }

    fun onText(text: String) = service?.text?.enqueueText(text) ?: dropped()

    fun onKey(key: Int) = service?.text?.enqueueKey(key) ?: dropped()

    private fun dropped() {
        Log.d(TAG, "control input dropped: service not connected")
    }

    /** Any thread. */
    internal fun reportClipboardUsed(context: Context) {
        val app = context.applicationContext
        main.post { setClipboardUsed(app) }
    }

    /** Any thread. */
    internal fun reportInputDropped() {
        main.post {
            if (!inputDropped) {
                inputDropped = true
                publish()
            }
        }
    }
}
