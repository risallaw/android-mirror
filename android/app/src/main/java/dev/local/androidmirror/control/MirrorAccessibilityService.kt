package dev.local.androidmirror.control

import android.accessibilityservice.AccessibilityService
import android.accessibilityservice.InputMethod
import android.content.Intent
import android.os.Build
import android.util.Log
import android.view.accessibility.AccessibilityEvent
import android.view.inputmethod.EditorInfo
import androidx.annotation.RequiresApi

/**
 * Lets a paired Mac control this phone: it injects gestures, global actions and text on request
 * (see [ControlBridge]). To type, it reads the focused field's text and edits it ([TextInjector]);
 * it reads nothing else on screen. It handles no accessibility events, except text changes while
 * it is editing a password field it filled ([watchTextChanges]). It is "connected" while the user
 * has it enabled in Accessibility settings.
 */
class MirrorAccessibilityService : AccessibilityService() {
    lateinit var gestures: GestureInjector
        private set
    lateinit var globalActions: GlobalActions
        private set
    lateinit var text: TextInjector
        private set

    /**
     * The input connection of the focused editor (API 33+), published from the main thread, where
     * the framework updates it, for the text thread (the framework's own field is not volatile).
     */
    @Volatile
    private var connection: Any? = null

    override fun onServiceConnected() {
        super.onServiceConnected()
        gestures = GestureInjector(this)
        globalActions = GlobalActions(this)
        text = TextInjector(this)
        ControlBridge.serviceConnected(this)
    }

    @RequiresApi(Build.VERSION_CODES.TIRAMISU)
    override fun onCreateInputMethod(): InputMethod = object : InputMethod(this) {
        override fun onStartInput(attribute: EditorInfo, restarting: Boolean) {
            super.onStartInput(attribute, restarting)
            connection = currentInputConnection
        }

        override fun onFinishInput() {
            connection = null
            super.onFinishInput()
        }
    }

    /** Any thread. */
    @RequiresApi(Build.VERSION_CODES.TIRAMISU)
    fun inputConnection(): InputMethod.AccessibilityInputConnection? =
        connection as? InputMethod.AccessibilityInputConnection

    override fun onUnbind(intent: Intent?): Boolean {
        release()
        return super.onUnbind(intent)
    }

    override fun onDestroy() {
        release()
        super.onDestroy()
    }

    private fun release() {
        if (::gestures.isInitialized) gestures.clear()
        ControlBridge.serviceDisconnected(this)
        if (::text.isInitialized) text.close()
    }

    /**
     * Subscribe to text-change events (any thread); true if the subscription is now as asked. The
     * config subscribes to none: [onAccessibilityEvent] needs them only while [TextInjector] knows
     * the text of a password field it filled (its content is masked). Unsubscribed, they do not
     * reach [onAccessibilityEvent]; the system may still send them to this process to keep its
     * node cache current.
     */
    fun watchTextChanges(on: Boolean): Boolean = synchronized(this) {
        runCatching {
            val info = serviceInfo ?: return false // not connected (any more)
            val types = if (on) AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED else 0
            if (info.eventTypes != types) {
                info.eventTypes = types
                serviceInfo = info
            }
        }.onFailure { Log.w(TAG, "event subscription change failed: $it") }.isSuccess
    }

    /** Text changes of password fields only (see [watchTextChanges]); the event's text is not read. */
    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        if (event == null || event.eventType != AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED || !event.isPassword) return
        if (::text.isInitialized) text.onPasswordTextChanged(event.fromIndex, event.removedCount, event.addedCount)
    }

    override fun onInterrupt() = Unit

    private companion object {
        const val TAG = "MirrorA11y"
    }
}
