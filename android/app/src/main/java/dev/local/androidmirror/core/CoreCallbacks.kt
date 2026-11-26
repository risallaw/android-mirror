package dev.local.androidmirror.core

import android.view.Surface

/**
 * Upcalls from the Rust core (`android/core/src/callbacks.rs`). Every method is
 * called on a Rust thread (encoder, session or the thread running
 * `nativeDestroy`), never on the main thread. Implementations must be quick, must
 * not call back into [NativeCore] synchronously, and post UI work to the main
 * thread. Method names and signatures are resolved by JNI; keep them in sync.
 */
interface CoreCallbacks {
    /** The encoder's input surface: resize the VirtualDisplay to [width]x[height] and render into it. */
    fun onSurfaceReady(surface: Surface, width: Int, height: Int)

    /** Detach and release the surface; the codec is released after this returns. */
    fun onSurfaceGone()

    /**
     * Re-attach the current surface so the VirtualDisplay composites a fresh frame
     * (the screen is static and a keyframe was requested). Throw if that is not
     * possible; the core then restarts the encoder instead.
     */
    fun onSurfaceRefresh()

    /**
     * Client lifecycle; [state] is one of the `STATE_*` constants. [reason] is the disconnect
     * reason code of android/core/src/events.rs (logged only). [name] and [peer] come from the
     * network: escape them before logging or showing (see `peerText`).
     */
    fun onClientState(state: Int, sessionId: Long, name: String?, peer: String?, reason: Int)

    /** The encoder that is now running (after each start/reconfigure). */
    fun onStreamInfo(width: Int, height: Int, fps: Int, encoder: String)

    /** Non-fatal error worth showing. */
    fun onError(message: String)

    /**
     * The pairing PIN changed (after a pairing, or after too many wrong tries). The first PIN is
     * not reported here: read [NativeCore.pin] after [NativeCore.start]. [pin] is reported outside
     * the server's lock, so it can be older than a "New PIN" applied meanwhile: show
     * [NativeCore.pin] (read under the lock) rather than [pin].
     */
    fun onPinChanged(pin: String)

    /** A Mac paired successfully; the PIN has been rotated. */
    fun onPaired(clientId: String, clientName: String)

    /**
     * A PIN attempt from [peer] failed. [attemptsLeft] tries remain before a new PIN is
     * issued; [lockedForMs] > 0 means PIN attempts are locked out for that long. [resets] is the
     * "New PIN" count it was counted under: smaller than [NativeCore.NewPin.resets] of a New
     * PIN already applied predates it (that New PIN cleared it).
     */
    fun onPairingFailed(peer: String, attemptsLeft: Int, lockedForMs: Long, resets: Long)

    /**
     * A touch gesture in display pixels. [kind] 1 = tap, 2 = long press, 3 = path through
     * ([xs], [ys]). [durationMs] is the path duration; 0 for tap/long press means "use the default".
     */
    fun onGesture(kind: Int, xs: FloatArray, ys: FloatArray, durationMs: Long)

    /** Scroll at ([x], [y]) by finger-drag ([dx], [dy]) in display pixels (positive dy = finger moves down). */
    fun onScroll(x: Float, y: Float, dx: Float, dy: Float)

    /** A `GLOBAL_*` action: 1 back, 2 home, 3 recents, 4 notifications, 5 quick settings, 6 lock, 7 volume up, 8 volume down. */
    fun onGlobalAction(action: Int)

    /** Text typed on the Mac, to insert at the focused field's cursor. */
    fun onText(text: String)

    /** A key: 1 backspace, 2 enter, 3 left, 4 right, 5 up, 6 down, 7 delete-forward, 8 tab. */
    fun onKey(key: Int)

    /** Live touch: [phase] 0 down, 1 move, 2 up, 3 cancel. Currently ignored (gestures are sent whole). */
    fun onTouchLive(phase: Int, x: Float, y: Float)

    companion object {
        // Mirrors android/core/src/events.rs.
        const val STATE_CONNECTING = 0
        const val STATE_STREAMING = 1
        const val STATE_DISCONNECTED = 2
    }
}
