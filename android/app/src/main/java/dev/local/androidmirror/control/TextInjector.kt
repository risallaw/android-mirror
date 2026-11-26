package dev.local.androidmirror.control

import android.accessibilityservice.InputMethod
import android.content.ClipboardManager
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.HandlerThread
import android.os.SystemClock
import android.util.Log
import android.view.KeyCharacterMap
import android.view.KeyEvent
import android.view.accessibility.AccessibilityNodeInfo
import androidx.annotation.RequiresApi

/**
 * Types text and keys into the focused field.
 *
 * API 33+: through the service's input-method connection (needs `flagInputMethodEditor`,
 * set in res/xml-v33). Otherwise, or when no live connection is active: edit the focused
 * node (ACTION_SET_TEXT spliced at the selection; see [passwordBase] for password fields),
 * falling back, last, to clipboard + ACTION_PASTE (which can cost the user's clip, see [paste]).
 *
 * Every one of these is a blocking cross-process call that can stall for seconds when the target
 * app is stuck, so they run on a thread of their own, in arrival order, never on the main thread
 * (which runs the service lifecycle, the notification's Stop and gestures). [close] when the
 * service goes away.
 */
class TextInjector(private val service: MirrorAccessibilityService) {
    private val thread = HandlerThread("mirror-text").apply { start() }
    private val handler = Handler(thread.looper)
    private val queue = InputQueue(MAX_PENDING_OPS, MAX_PENDING_CHARS)

    @Volatile
    private var closed = false

    /** Set on the first drop, cleared by the next drain: one log line per backlog. */
    @Volatile
    private var dropping = false

    // Text thread state.
    private val warned = mutableSetOf<String>()

    /** Text-change events are subscribed to only while this knows a password field's text. */
    private val password = PasswordMemory<AccessibilityNodeInfo>(onForget = { service.watchTextChanges(false) })

    /** Any thread. */
    fun enqueueText(text: String) {
        if (text.isNotEmpty()) enqueue(InputQueue.Op.Text(text))
    }

    /** Any thread. Key codes mirror `CoreCallbacks.onKey`. */
    fun enqueueKey(key: Int) = enqueue(InputQueue.Op.Key(key))

    /** Main thread: a password field's text changed (see [PasswordMemory.onTextChanged]). */
    fun onPasswordTextChanged(fromIndex: Int, removed: Int, added: Int) {
        if (!closed) handler.post { password.onTextChanged(fromIndex, removed, added) }
    }

    private fun enqueue(op: InputQueue.Op) {
        if (closed) return
        when (val offer = queue.offer(op)) {
            InputQueue.Offer.DRAIN -> handler.post(drain)
            InputQueue.Offer.QUEUED -> Unit
            InputQueue.Offer.DROPPED, InputQueue.Offer.DROPPED_AFTER_LOSS -> if (!dropping) {
                dropping = true
                Log.w(
                    TAG,
                    if (offer == InputQueue.Offer.DROPPED) "text input dropped: the focused app is not keeping up"
                    else "text input dropped: earlier input reached no field",
                )
                ControlBridge.reportInputDropped()
            }
        }
    }

    private val drain = Runnable {
        dropping = false
        while (true) {
            val op = queue.poll() ?: break
            try {
                when (op) {
                    is InputQueue.Op.Text -> type(op.text)
                    is InputQueue.Op.Key -> key(op.key)
                }
            } catch (e: RuntimeException) {
                // A dying target app; keep draining (an escaping exception would kill the process).
                Log.w(TAG, "text input failed: $e")
            }
        }
    }

    /** Drop pending input, put a lent clip back and stop the thread. Idempotent. */
    fun close() {
        if (closed) return
        closed = true
        queue.clear()
        // A paste the target handles asynchronously (WebView) may still be reading the lent clip:
        // restoring now would paste the user's clip instead, so wait the usual restore delay.
        handler.postDelayed({
            clipboard.flush()
            password.forget()
            thread.quit()
        }, CLIP_RESTORE_DELAY_MS)
    }

    private fun type(text: String) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU && commitViaIme(text)) return
        val node = focusedInput()
        if (node == null) {
            undelivered("no focused input for text")
            return
        }
        // Every node-path access carries the whole field text over binder; past this size the
        // next access would stall for seconds and fail, so stop here with a reported drop.
        if (!fitsNodeField(shownText(node)?.length ?: 0, text.length)) {
            undelivered("field too large for the node path")
            return
        }
        if (!spliceNode(node, text, backspace = 0, delete = 0)) paste(node, text)
    }

    private fun key(key: Int) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU && keyViaIme(key)) return
        val node = focusedInput()
        if (node == null) {
            if (keyEditsText(key)) undelivered("no focused input for key $key")
            else Log.d(TAG, "no focused input for key $key")
            return
        }
        when (key) {
            1, 7 ->
                if (!spliceNode(node, "", backspace = if (key == 1) 1 else 0, delete = if (key == 7) 1 else 0)) {
                    logOnce("Backspace/Delete unsupported here without an IME connection (password field we did not fill, or a very large field)")
                }
            2 -> enter(node)
            3 -> move(node, AccessibilityNodeInfo.MOVEMENT_GRANULARITY_CHARACTER, forward = false)
            4 -> move(node, AccessibilityNodeInfo.MOVEMENT_GRANULARITY_CHARACTER, forward = true)
            5 -> move(node, AccessibilityNodeInfo.MOVEMENT_GRANULARITY_LINE, forward = false)
            6 -> move(node, AccessibilityNodeInfo.MOVEMENT_GRANULARITY_LINE, forward = true)
            // Tab has no node-level equivalent without an IME connection.
            else -> Log.d(TAG, "key $key unsupported on this path")
        }
    }

    // ---- API 33+ input connection ----

    /**
     * The input connection, if it still reaches the editor. After the app restarts input on the
     * focused field (seen with a search field's clear button on API 35) the connection can go
     * dead: commitText is void and drops the text silently, while a synchronous read returns
     * null. The read is also an ordering barrier: the editor's app re-posts IME key events to
     * the end of its main queue, while commitText applies as soon as it arrives, so Backspace
     * then a quickly typed letter came out as letter-then-Backspace. The read returns only
     * after the earlier key events are queued ahead of what we send next.
     */
    @RequiresApi(Build.VERSION_CODES.TIRAMISU)
    private fun liveConnection(): InputMethod.AccessibilityInputConnection? {
        val ic = service.inputConnection() ?: return null
        return ic.takeIf { it.getSurroundingText(0, 0, 0) != null }
    }

    @RequiresApi(Build.VERSION_CODES.TIRAMISU)
    private fun commitViaIme(text: String): Boolean {
        val ic = liveConnection() ?: return false
        ic.commitText(text, 1, null)
        password.forget() // the field may be one we filled; we no longer know its content
        return true
    }

    @RequiresApi(Build.VERSION_CODES.TIRAMISU)
    private fun keyViaIme(key: Int): Boolean {
        val code = imeKeyCode(key) ?: return true // unknown: swallow
        val ic = liveConnection() ?: return false
        // As InputMethodService.sendDownUpKeyEvents does: real event times (editors and key
        // listeners compare them) and the soft-keyboard flags of an IME-generated key.
        val flags = KeyEvent.FLAG_SOFT_KEYBOARD or KeyEvent.FLAG_KEEP_TOUCH_MODE
        val down = SystemClock.uptimeMillis()
        ic.sendKeyEvent(KeyEvent(down, down, KeyEvent.ACTION_DOWN, code, 0, 0, KeyCharacterMap.VIRTUAL_KEYBOARD, 0, flags))
        ic.sendKeyEvent(
            KeyEvent(down, SystemClock.uptimeMillis(), KeyEvent.ACTION_UP, code, 0, 0, KeyCharacterMap.VIRTUAL_KEYBOARD, 0, flags),
        )
        password.forget() // Backspace/Delete may have edited a field we filled
        return true
    }

    // ---- Node-based path (API 29+) ----

    private fun focusedInput(): AccessibilityNodeInfo? =
        service.rootInActiveWindow?.findFocus(AccessibilityNodeInfo.FOCUS_INPUT)
            // refresh() bypasses the accessibility cache, whose text lags edits by the event
            // timeout: splicing on stale text would drop characters typed in quick succession.
            ?.takeIf { it.refresh() && it.isEditable }

    /**
     * Replace the selection / delete around the caret via ACTION_SET_TEXT. False if that is not
     * possible: the action failed, or a password field's content cannot be known ([passwordBase]).
     */
    private fun spliceNode(node: AccessibilityNodeInfo, insert: String, backspace: Int, delete: Int): Boolean {
        val shown = shownText(node)
        val start = node.textSelectionStart
        val end = node.textSelectionEnd
        // A password field's text is masked: never splice into the mask characters.
        val current = if (!node.isPassword) shown.orEmpty() else {
            password.base(node, shown?.length, start, end) ?: return false
        }
        if (!fitsSetText(current.length, insert.length)) return false // too big for SET_TEXT: paste
        val result = splice(current, start, end, insert, backspace, delete)
            ?: return true // nothing to delete
        val args = Bundle().apply {
            putCharSequence(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE, result.text)
        }
        // Subscribed before SET_TEXT: its echo event must not be missed (PasswordMemory matches them).
        val watching = node.isPassword && service.watchTextChanges(true)
        if (!node.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, args)) {
            if (node.isPassword && !password.holdsText) service.watchTextChanges(false)
            return false
        }
        if (node.isPassword) password.remember(node, result.text, current.length, watching)
        val sel = Bundle().apply {
            putInt(AccessibilityNodeInfo.ACTION_ARGUMENT_SELECTION_START_INT, result.caret)
            putInt(AccessibilityNodeInfo.ACTION_ARGUMENT_SELECTION_END_INT, result.caret)
        }
        node.performAction(AccessibilityNodeInfo.ACTION_SET_SELECTION, sel)
        return true
    }

    /** The field's text; "" while it shows its hint (reported as its text), null if not reported. */
    private fun shownText(node: AccessibilityNodeInfo): String? =
        if (node.isShowingHintText) "" else node.text?.toString()

    /**
     * Insert at the cursor through the clipboard; [clipboard] puts the user's clip back afterwards.
     * From Android 10 an unfocused app cannot read the clip, so "back" is usually "cleared": the
     * last resort, and the app UI says it happened.
     */
    private fun paste(node: AccessibilityNodeInfo, text: String) {
        ControlBridge.reportClipboardUsed(service)
        if (!clipboard.paste(sensitiveTextClip(text)) { node.performAction(AccessibilityNodeInfo.ACTION_PASTE) }) {
            Log.d(TAG, "paste failed")
        }
    }

    /** Text-thread: input that reached no field is a drop (reported; a following Enter is refused). */
    private fun undelivered(why: String) {
        Log.d(TAG, why)
        queue.noteDrop()
        ControlBridge.reportInputDropped()
    }

    /** Each message once per service connection. */
    private fun logOnce(msg: String) {
        if (warned.add(msg)) Log.w(TAG, msg)
    }

    private fun enter(node: AccessibilityNodeInfo) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R &&
            node.performAction(AccessibilityNodeInfo.AccessibilityAction.ACTION_IME_ENTER.id)
        ) {
            return
        }
        if (node.isMultiLine) {
            spliceNode(node, "\n", backspace = 0, delete = 0)
        } else {
            // API 29 has no ACTION_IME_ENTER, and no IME connection: Enter cannot submit here.
            logOnce("Enter unsupported in a single-line field without an IME connection (API < 30)")
        }
    }

    private fun move(node: AccessibilityNodeInfo, granularity: Int, forward: Boolean) {
        val args = Bundle().apply {
            putInt(AccessibilityNodeInfo.ACTION_ARGUMENT_MOVEMENT_GRANULARITY_INT, granularity)
            putBoolean(AccessibilityNodeInfo.ACTION_ARGUMENT_EXTEND_SELECTION_BOOLEAN, false)
        }
        node.performAction(
            if (forward) AccessibilityNodeInfo.ACTION_NEXT_AT_MOVEMENT_GRANULARITY
            else AccessibilityNodeInfo.ACTION_PREVIOUS_AT_MOVEMENT_GRANULARITY,
            args,
        )
    }

    private val clipboardManager by lazy { service.getSystemService(ClipboardManager::class.java) }

    // ACTION_PASTE can be handled asynchronously (WebView); give the target time to read the clip.
    private val clipboard = ClipboardLease(
        read = { runCatching { clipboardManager?.primaryClip }.getOrNull() },
        write = { clip ->
            val cm = clipboardManager
            try {
                if (cm != null) {
                    if (clip != null) cm.setPrimaryClip(clip) else cm.clearPrimaryClip()
                }
                cm != null
            } catch (e: RuntimeException) {
                Log.d(TAG, "clipboard write failed: $e")
                false
            }
        },
        schedule = { r, delay -> handler.postDelayed(r, delay) },
        cancel = handler::removeCallbacks,
        delayMs = CLIP_RESTORE_DELAY_MS,
    )
    private companion object {
        const val TAG = "TextInjector"
        const val CLIP_RESTORE_DELAY_MS = 500L

        // A stuck target can hold each call for seconds; beyond this, input is dropped. The char
        // budget holds a whole Mac paste (up to 16 TEXT messages of 64 KiB, merged per message).
        const val MAX_PENDING_OPS = 256
        const val MAX_PENDING_CHARS = InputQueue.MAX_CHARS
    }
}

/**
 * Whether a key (codes of `CoreCallbacks.onKey`) changes text, so that with no focused field it
 * leaves a hole in what the user typed: Backspace and Delete. Arrows and Tab only move, and Enter
 * with no field is the usual second press after a submit closed it; nothing is lost.
 */
internal fun keyEditsText(key: Int): Boolean = key == 1 || key == 7

/** The Android key code for a key of `CoreCallbacks.onKey`, or null for an unknown one. */
internal fun imeKeyCode(key: Int): Int? = when (key) {
    1 -> KeyEvent.KEYCODE_DEL
    2 -> KeyEvent.KEYCODE_ENTER
    3 -> KeyEvent.KEYCODE_DPAD_LEFT
    4 -> KeyEvent.KEYCODE_DPAD_RIGHT
    5 -> KeyEvent.KEYCODE_DPAD_UP
    6 -> KeyEvent.KEYCODE_DPAD_DOWN
    7 -> KeyEvent.KEYCODE_FORWARD_DEL
    8 -> KeyEvent.KEYCODE_TAB
    else -> null
}
