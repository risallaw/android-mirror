//! Rust → Kotlin upcalls on the `CoreCallbacks` object (PLAN §4 JNI rules).
//!
//! - The `JavaVM` comes from `JNI_OnLoad` ([`JAVA_VM`]); native threads
//!   attach permanently on their first upcall and are detached by `jni` when
//!   they exit.
//! - Only the callback object's `GlobalRef` is used from native threads; the
//!   method IDs are resolved once, on the Kotlin thread calling `nativeCreate`
//!   (no class lookups from native threads).
//! - Every upcall runs in its own local frame (attached native threads never
//!   pop frames otherwise) and clears any pending Java exception afterwards.
//! - Callers never hold a Rust mutex while calling these.

use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use jni::objects::{GlobalRef, JMethodID, JObject, JValue};
use jni::signature::{Primitive, ReturnType};
use jni::sys::jvalue;
use jni::{JNIEnv, JavaVM};
use mirror_protocol::{GestureKind, GlobalAction, Key, TouchPhase};
use mirror_sender::{
    log_str, ClientInfo, ClientState, ControlSink, HostError, HostEvents, PairedClient, PixelPoint,
};
use ndk::native_window::NativeWindow;

use crate::control::{gesture_args, global_action_code, key_code, scroll_args, touch_phase_code};
use crate::events::{pairing_failed_args, peer_string, pin_resets_arg, state_codes};

/// JNI descriptors of the `CoreCallbacks` methods (must match the Kotlin interface).
mod sig {
    pub const ON_SURFACE_READY: &str = "(Landroid/view/Surface;II)V";
    pub const ON_SURFACE_GONE: &str = "()V";
    pub const ON_SURFACE_REFRESH: &str = "()V";
    pub const ON_CLIENT_STATE: &str = "(IJLjava/lang/String;Ljava/lang/String;I)V";
    pub const ON_STREAM_INFO: &str = "(IIILjava/lang/String;)V";
    pub const ON_ERROR: &str = "(Ljava/lang/String;)V";
    pub const ON_PIN_CHANGED: &str = "(Ljava/lang/String;)V";
    pub const ON_PAIRED: &str = "(Ljava/lang/String;Ljava/lang/String;)V";
    pub const ON_PAIRING_FAILED: &str = "(Ljava/lang/String;IJJ)V";
    pub const ON_GESTURE: &str = "(I[F[FJ)V";
    pub const ON_SCROLL: &str = "(FFFF)V";
    pub const ON_GLOBAL_ACTION: &str = "(I)V";
    pub const ON_TEXT: &str = "(Ljava/lang/String;)V";
    pub const ON_KEY: &str = "(I)V";
    pub const ON_TOUCH_LIVE: &str = "(IFF)V";
}

/// Set once in `JNI_OnLoad`.
pub static JAVA_VM: OnceLock<JavaVM> = OnceLock::new();

/// The Kotlin `CoreCallbacks` instance and its cached method IDs.
pub struct Callbacks {
    target: GlobalRef,
    on_surface_ready: JMethodID,
    on_surface_gone: JMethodID,
    on_surface_refresh: JMethodID,
    on_client_state: JMethodID,
    on_stream_info: JMethodID,
    on_error: JMethodID,
    on_pin_changed: JMethodID,
    on_paired: JMethodID,
    on_pairing_failed: JMethodID,
    on_gesture: JMethodID,
    on_scroll: JMethodID,
    on_global_action: JMethodID,
    on_text: JMethodID,
    on_key: JMethodID,
    on_touch_live: JMethodID,
}

impl Callbacks {
    /// Resolve method IDs on the calling (Kotlin) thread.
    pub fn new(env: &mut JNIEnv, cb: &JObject) -> jni::errors::Result<Self> {
        let class = env.get_object_class(cb)?;
        let mut mid = |name: &str, sig: &str| env.get_method_id(&class, name, sig);
        let on_surface_ready = mid("onSurfaceReady", sig::ON_SURFACE_READY)?;
        let on_surface_gone = mid("onSurfaceGone", sig::ON_SURFACE_GONE)?;
        let on_surface_refresh = mid("onSurfaceRefresh", sig::ON_SURFACE_REFRESH)?;
        let on_client_state = mid("onClientState", sig::ON_CLIENT_STATE)?;
        let on_stream_info = mid("onStreamInfo", sig::ON_STREAM_INFO)?;
        let on_error = mid("onError", sig::ON_ERROR)?;
        let on_pin_changed = mid("onPinChanged", sig::ON_PIN_CHANGED)?;
        let on_paired = mid("onPaired", sig::ON_PAIRED)?;
        let on_pairing_failed = mid("onPairingFailed", sig::ON_PAIRING_FAILED)?;
        let on_gesture = mid("onGesture", sig::ON_GESTURE)?;
        let on_scroll = mid("onScroll", sig::ON_SCROLL)?;
        let on_global_action = mid("onGlobalAction", sig::ON_GLOBAL_ACTION)?;
        let on_text = mid("onText", sig::ON_TEXT)?;
        let on_key = mid("onKey", sig::ON_KEY)?;
        let on_touch_live = mid("onTouchLive", sig::ON_TOUCH_LIVE)?;
        let target = env.new_global_ref(cb)?;
        env.delete_local_ref(class)?;
        Ok(Callbacks {
            target,
            on_surface_ready,
            on_surface_gone,
            on_surface_refresh,
            on_client_state,
            on_stream_info,
            on_error,
            on_pin_changed,
            on_paired,
            on_pairing_failed,
            on_gesture,
            on_scroll,
            on_global_action,
            on_text,
            on_key,
            on_touch_live,
        })
    }

    /// Run `f` on an attached env inside a local frame; log (describe) and
    /// clear any Java exception it leaves pending.
    fn upcall(
        &self,
        what: &str,
        f: impl FnOnce(&mut JNIEnv, &JObject) -> jni::errors::Result<()>,
    ) -> Result<(), String> {
        self.upcall_with(what, true, f)
    }

    /// [`Self::upcall`]; `describe: false` clears a pending exception
    /// without printing its stack trace (for documented, expected throws).
    fn upcall_with(
        &self,
        what: &str,
        describe: bool,
        f: impl FnOnce(&mut JNIEnv, &JObject) -> jni::errors::Result<()>,
    ) -> Result<(), String> {
        let vm = JAVA_VM.get().ok_or("JavaVM not initialised")?;
        let mut env = vm
            .attach_current_thread_permanently()
            .map_err(|e| format!("{what}: attach failed: {e}"))?;
        let r = env.with_local_frame(16, |env| f(env, self.target.as_obj()));
        if env.exception_check().unwrap_or(false) {
            if describe {
                let _ = env.exception_describe();
            }
            let _ = env.exception_clear();
            return Err(format!("{what}: Kotlin threw"));
        }
        r.map_err(|e| format!("{what}: {e}"))
    }

    fn call_void(
        env: &mut JNIEnv,
        obj: &JObject,
        mid: JMethodID,
        args: &[jvalue],
    ) -> jni::errors::Result<()> {
        // SAFETY: `mid` was resolved on this object's class with a signature
        // matching `args` and a void return.
        unsafe {
            env.call_method_unchecked(obj, mid, ReturnType::Primitive(Primitive::Void), args)?;
        }
        Ok(())
    }

    /// `onSurfaceReady(surface, width, height)`: Kotlin resizes the
    /// VirtualDisplay and points it at the encoder's input surface.
    pub fn surface_ready(
        &self,
        window: &NativeWindow,
        width: u32,
        height: u32,
    ) -> Result<(), String> {
        let mid = self.on_surface_ready;
        self.upcall("onSurfaceReady", |env, obj| {
            // SAFETY: `env` is a valid attached JNIEnv; the returned local ref
            // is owned by the current local frame.
            let raw = unsafe { window.to_surface(env.get_raw()) };
            if raw.is_null() {
                return Err(jni::errors::Error::NullPtr("ANativeWindow_toSurface"));
            }
            // SAFETY: non-null local reference just created above.
            let surface = unsafe { JObject::from_raw(raw) };
            Self::call_void(
                env,
                obj,
                mid,
                &[
                    JValue::Object(&surface).as_jni(),
                    JValue::Int(width as i32).as_jni(),
                    JValue::Int(height as i32).as_jni(),
                ],
            )
        })
    }

    /// `onSurfaceGone()`: returns once Kotlin has detached the surface.
    pub fn surface_gone(&self) -> Result<(), String> {
        let mid = self.on_surface_gone;
        self.upcall("onSurfaceGone", |env, obj| {
            Self::call_void(env, obj, mid, &[])
        })
    }

    /// `onSurfaceRefresh()`: Kotlin re-attaches the current surface to the
    /// VirtualDisplay so it composites a fresh frame (static screen). Kotlin
    /// throws when it cannot (documented), so that is not described.
    pub fn surface_refresh(&self) -> Result<(), String> {
        let mid = self.on_surface_refresh;
        self.upcall_with("onSurfaceRefresh", false, |env, obj| {
            Self::call_void(env, obj, mid, &[])
        })
    }

    pub fn client_state(&self, state: ClientState, client: &ClientInfo) {
        let (code, reason) = state_codes(state);
        let mid = self.on_client_state;
        let r = self.upcall("onClientState", |env, obj| {
            let name = env.new_string(&client.name)?;
            let peer = env.new_string(peer_string(&client.peer))?;
            Self::call_void(
                env,
                obj,
                mid,
                &[
                    JValue::Int(code).as_jni(),
                    JValue::Long(client.session_id as i64).as_jni(),
                    JValue::Object(&name).as_jni(),
                    JValue::Object(&peer).as_jni(),
                    JValue::Int(reason).as_jni(),
                ],
            )
        });
        if let Err(e) = r {
            log::warn!("{e}");
        }
    }

    pub fn stream_info(&self, width: u32, height: u32, fps: u32, encoder: &str) {
        let mid = self.on_stream_info;
        let r = self.upcall("onStreamInfo", |env, obj| {
            let enc = env.new_string(encoder)?;
            Self::call_void(
                env,
                obj,
                mid,
                &[
                    JValue::Int(width as i32).as_jni(),
                    JValue::Int(height as i32).as_jni(),
                    JValue::Int(fps as i32).as_jni(),
                    JValue::Object(&enc).as_jni(),
                ],
            )
        });
        if let Err(e) = r {
            log::warn!("{e}");
        }
    }

    pub fn error(&self, message: &str) {
        let mid = self.on_error;
        let r = self.upcall("onError", |env, obj| {
            let msg = env.new_string(message)?;
            Self::call_void(env, obj, mid, &[JValue::Object(&msg).as_jni()])
        });
        if let Err(e) = r {
            log::warn!("{e}");
        }
    }

    /// Run a fire-and-forget upcall; failures are logged.
    fn notify(&self, what: &str, f: impl FnOnce(&mut JNIEnv, &JObject) -> jni::errors::Result<()>) {
        if let Err(e) = self.upcall(what, f) {
            log::warn!("{e}");
        }
    }

    /// Upcall with only primitive arguments.
    fn notify_prims(&self, what: &str, mid: JMethodID, args: &[jvalue]) {
        self.notify(what, |env, obj| Self::call_void(env, obj, mid, args));
    }

    pub fn pin_changed(&self, pin: &str) {
        let mid = self.on_pin_changed;
        self.notify("onPinChanged", |env, obj| {
            let pin = env.new_string(pin)?;
            Self::call_void(env, obj, mid, &[JValue::Object(&pin).as_jni()])
        });
    }

    pub fn paired(&self, client_id: &str, client_name: &str) {
        let mid = self.on_paired;
        self.notify("onPaired", |env, obj| {
            let id = env.new_string(client_id)?;
            let name = env.new_string(client_name)?;
            Self::call_void(
                env,
                obj,
                mid,
                &[JValue::Object(&id).as_jni(), JValue::Object(&name).as_jni()],
            )
        });
    }

    pub fn pairing_failed(
        &self,
        peer: &SocketAddr,
        attempts_left: u32,
        locked_for: Option<Duration>,
        resets: u64,
    ) {
        let (attempts, locked_ms) = pairing_failed_args(attempts_left, locked_for);
        let resets = pin_resets_arg(resets);
        let mid = self.on_pairing_failed;
        self.notify("onPairingFailed", |env, obj| {
            let peer = env.new_string(peer_string(peer))?;
            Self::call_void(
                env,
                obj,
                mid,
                &[
                    JValue::Object(&peer).as_jni(),
                    JValue::Int(attempts).as_jni(),
                    JValue::Long(locked_ms).as_jni(),
                    JValue::Long(resets).as_jni(),
                ],
            )
        });
    }

    pub fn gesture(&self, kind: GestureKind, points: &[PixelPoint]) {
        let Some(a) = gesture_args(kind, points) else {
            log::debug!("gesture {kind:?} with {} points ignored", points.len());
            return;
        };
        let mid = self.on_gesture;
        self.notify("onGesture", |env, obj| {
            // At most 255 points (u8 count on the wire); the cast cannot truncate
            // for anything the server delivers, and `try_from` guards the rest.
            let len = i32::try_from(a.xs.len()).map_err(|_| {
                jni::errors::Error::JniCall(jni::errors::JniError::InvalidArguments)
            })?;
            let xs = env.new_float_array(len)?;
            env.set_float_array_region(&xs, 0, &a.xs)?;
            let ys = env.new_float_array(len)?;
            env.set_float_array_region(&ys, 0, &a.ys)?;
            Self::call_void(
                env,
                obj,
                mid,
                &[
                    JValue::Int(a.kind).as_jni(),
                    JValue::Object(&xs).as_jni(),
                    JValue::Object(&ys).as_jni(),
                    JValue::Long(a.duration_ms).as_jni(),
                ],
            )
        });
    }

    pub fn scroll(&self, x: u32, y: u32, dx: i32, dy: i32) {
        let [x, y, dx, dy] = scroll_args(x, y, dx, dy);
        self.notify_prims(
            "onScroll",
            self.on_scroll,
            &[
                JValue::Float(x).as_jni(),
                JValue::Float(y).as_jni(),
                JValue::Float(dx).as_jni(),
                JValue::Float(dy).as_jni(),
            ],
        );
    }

    pub fn global_action(&self, action: GlobalAction) {
        self.notify_prims(
            "onGlobalAction",
            self.on_global_action,
            &[JValue::Int(global_action_code(action)).as_jni()],
        );
    }

    /// Typed text may be a password. `new_string` copies it into a JVM
    /// String, which cannot be wiped (immutable, moved and freed by the GC
    /// on its own schedule): an accepted limitation of handing text to
    /// Android's input APIs, which take Strings anyway. Rust's copies are
    /// wiped by the caller.
    pub fn text(&self, text: &str) {
        let mid = self.on_text;
        self.notify("onText", |env, obj| {
            let t = env.new_string(text)?;
            Self::call_void(env, obj, mid, &[JValue::Object(&t).as_jni()])
        });
    }

    pub fn key(&self, key: Key) {
        self.notify_prims("onKey", self.on_key, &[JValue::Int(key_code(key)).as_jni()]);
    }

    pub fn touch_live(&self, phase: TouchPhase, x: u32, y: u32) {
        self.notify_prims(
            "onTouchLive",
            self.on_touch_live,
            &[
                JValue::Int(touch_phase_code(phase)).as_jni(),
                JValue::Float(x as f32).as_jni(),
                JValue::Float(y as f32).as_jni(),
            ],
        );
    }
}

/// [`HostEvents`] forwarded to Kotlin (called on mirror-sender threads,
/// never under a mirror-sender lock that Kotlin could wait on).
pub struct Events(pub Arc<Callbacks>);

impl HostEvents for Events {
    fn client_state(&self, state: ClientState, client: &ClientInfo) {
        log::info!(
            "client {:?} ({}): {state:?}",
            log_str(&client.name),
            peer_string(&client.peer)
        );
        self.0.client_state(state, client);
    }

    fn error(&self, err: &HostError) {
        log::warn!("host error: {err}");
        self.0.error(&err.to_string());
    }

    fn pin_changed(&self, pin: &str) {
        log::info!("pairing PIN changed");
        self.0.pin_changed(pin);
    }

    fn paired(&self, client: &PairedClient) {
        log::info!(
            "paired with {:?} ({:?})",
            log_str(&client.client_name),
            log_str(&client.client_id)
        );
        self.0.paired(&client.client_id, &client.client_name);
    }

    // `resets` lets Kotlin drop a failure that a "New PIN" it already applied
    // cleared (the server's own check cannot cover a reset racing this upcall).
    fn pairing_failed_at(
        &self,
        peer: SocketAddr,
        attempts_left: u32,
        locked_for: Option<Duration>,
        resets: u64,
    ) {
        // mirror-sender already logs every failure and refusal at WARN.
        log::debug!(
            "pairing failed from {}: {attempts_left} attempts left, locked for {locked_for:?} (resets {resets})",
            peer_string(&peer)
        );
        self.0
            .pairing_failed(&peer, attempts_left, locked_for, resets);
    }
}

/// [`ControlSink`] forwarded to Kotlin (called on the session reader thread;
/// Kotlin posts the work to the main thread and returns at once).
pub struct Control(pub Arc<Callbacks>);

impl ControlSink for Control {
    fn gesture(&self, kind: GestureKind, points: &[PixelPoint]) {
        self.0.gesture(kind, points);
    }

    fn touch_live(&self, phase: TouchPhase, x: u32, y: u32) {
        self.0.touch_live(phase, x, y);
    }

    fn scroll(&self, x: u32, y: u32, dx: i32, dy: i32) {
        self.0.scroll(x, y, dx, dy);
    }

    fn global_action(&self, action: GlobalAction) {
        self.0.global_action(action);
    }

    fn text(&self, text: &str) {
        self.0.text(text);
    }

    fn key(&self, key: Key) {
        self.0.key(key);
    }
}
