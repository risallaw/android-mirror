//! JNI exports for `dev.local.androidmirror.core.NativeCore` (PLAN §4).
//!
//! Every export runs inside [`guarded`] so no panic unwinds into the JVM.
//! A handle is a key into [`CORES`] (see [`crate::handles`]), so a destroyed
//! or bogus handle is an error, never a dangling pointer, whatever the
//! caller's locking.

use std::ffi::c_void;
use std::sync::Arc;

use jni::objects::{JClass, JObject, JString};
use jni::sys::{jboolean, jint, jlong, jstring, JNI_FALSE, JNI_TRUE, JNI_VERSION_1_6};
use jni::{JNIEnv, JavaVM};

use crate::callbacks::{Callbacks, JAVA_VM};
use crate::config::HostConfig;
use crate::core::Core;
use crate::display::DisplayInfo;
use crate::events::{paired_json, pin_resets_arg};
use crate::guarded;
use crate::handles::Handles;
use zeroize::Zeroizing;

/// Every live core, keyed by the handle Kotlin holds.
static CORES: Handles<Core> = Handles::new();

fn throw(env: &mut JNIEnv, message: &str) {
    if !env.exception_check().unwrap_or(false) {
        let _ = env.throw_new("java/lang/RuntimeException", message);
    }
}

/// Run an export body; log errors and panics and return `fallback` for them.
fn run<T>(name: &str, fallback: T, f: impl FnOnce() -> Result<T, String>) -> T {
    match guarded(f) {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            log::error!("{name}: {e}");
            fallback
        }
        Err(p) => {
            log::error!("panic in {name}: {p}");
            fallback
        }
    }
}

/// Borrow the core behind a live handle.
fn with_core<T>(handle: jlong, f: impl FnOnce(&Core) -> T) -> Result<T, String> {
    if handle == 0 {
        return Err("null handle".into());
    }
    let core = CORES
        .get(handle)
        .ok_or_else(|| format!("unknown or destroyed handle {handle}"))?;
    Ok(f(&core))
}

/// A Java string for `s`, or null if even that fails (an exception is then
/// pending, e.g. OutOfMemoryError, and Kotlin sees it). Never panics.
fn java_string(env: &mut JNIEnv, s: &str) -> jstring {
    match guarded(|| env.new_string(s).map(|j| j.into_raw())) {
        Ok(Ok(raw)) => raw,
        Ok(Err(e)) => {
            log::error!("new_string: {e}");
            std::ptr::null_mut()
        }
        Err(p) => {
            log::error!("panic in new_string: {p}");
            std::ptr::null_mut()
        }
    }
}

/// Read a Java string argument; null and conversion failures are errors.
fn rust_string(env: &mut JNIEnv, s: &JString, what: &str) -> Result<String, String> {
    if s.is_null() {
        return Err(format!("{what} must not be null"));
    }
    let r = env
        .get_string(s)
        .map(String::from)
        .map_err(|e| format!("{what}: {e}"));
    if r.is_err() && env.exception_check().unwrap_or(false) {
        let _ = env.exception_clear();
    }
    r
}

#[no_mangle]
pub extern "system" fn JNI_OnLoad(vm: *mut jni::sys::JavaVM, _reserved: *mut c_void) -> jint {
    let _ = guarded(|| {
        crate::logger::init();
        // SAFETY: the VM pointer passed to JNI_OnLoad is valid for the process.
        match unsafe { JavaVM::from_raw(vm) } {
            Ok(vm) => {
                let _ = JAVA_VM.set(vm);
            }
            Err(e) => log::error!("JNI_OnLoad: bad JavaVM: {e}"),
        }
        log::info!("{} loaded", crate::version_string());
    });
    JNI_VERSION_1_6
}

#[no_mangle]
pub extern "system" fn Java_dev_local_androidmirror_core_NativeCore_nativeVersion(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    let result = guarded(|| {
        env.new_string(crate::version_string())
            .map(|s| s.into_raw())
    });
    match result {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            throw(&mut env, &format!("nativeVersion failed: {e}"));
            std::ptr::null_mut()
        }
        Err(msg) => {
            throw(&mut env, &format!("panic in nativeVersion: {msg}"));
            std::ptr::null_mut()
        }
    }
}

/// Start the listener. Returns the handle, or 0 on failure (logged; no
/// exception is left pending).
#[no_mangle]
pub extern "system" fn Java_dev_local_androidmirror_core_NativeCore_nativeCreate<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    config_json: JString<'l>,
    callbacks: JObject<'l>,
) -> jlong {
    run("nativeCreate", 0, || {
        let json = rust_string(&mut env, &config_json, "configJson")?;
        let cfg = HostConfig::parse(&json)?;
        if callbacks.is_null() {
            return Err("callbacks must not be null".into());
        }
        let cb = match Callbacks::new(&mut env, &callbacks) {
            Ok(cb) => cb,
            Err(e) => {
                // A missing callback method leaves NoSuchMethodError pending;
                // describe (log) and clear it so this returns 0 as documented
                // instead of throwing into Kotlin.
                if env.exception_check().unwrap_or(false) {
                    let _ = env.exception_describe();
                    let _ = env.exception_clear();
                }
                return Err(format!("callbacks: {e}"));
            }
        };
        let core = Core::create(&cfg, Arc::new(cb))?;
        Ok(CORES.insert(core))
    })
}

#[no_mangle]
pub extern "system" fn Java_dev_local_androidmirror_core_NativeCore_nativeGetPort(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jint {
    run("nativeGetPort", 0, || {
        with_core(handle, |c| c.port() as jint)
    })
}

#[no_mangle]
pub extern "system" fn Java_dev_local_androidmirror_core_NativeCore_nativeSetDisplay(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
    width: jint,
    height: jint,
    rotation: jint,
    dpi: jint,
) {
    run("nativeSetDisplay", (), || {
        let d = DisplayInfo::from_raw(width, height, rotation, dpi)
            .ok_or_else(|| format!("invalid display {width}x{height} r{rotation} dpi {dpi}"))?;
        with_core(handle, |c| c.set_display(d))
    })
}

#[no_mangle]
pub extern "system" fn Java_dev_local_androidmirror_core_NativeCore_nativeSetScreenState(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
    on: jboolean,
) {
    run("nativeSetScreenState", (), || {
        with_core(handle, |c| c.set_screen_state(on != 0))
    })
}

#[no_mangle]
pub extern "system" fn Java_dev_local_androidmirror_core_NativeCore_nativeNetworkChanged(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    run("nativeNetworkChanged", (), || {
        with_core(handle, |c| c.network_changed())
    })
}

/// The projection was revoked by the system; call right before `nativeDestroy`
/// so the client gets BYE `projection_revoked` instead of `stopped_by_user`.
#[no_mangle]
pub extern "system" fn Java_dev_local_androidmirror_core_NativeCore_nativeProjectionRevoked(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    run("nativeProjectionRevoked", (), || {
        with_core(handle, |c| c.projection_revoked())
    })
}

/// `nativeGetPin(handle): String` — the current pairing PIN, "" for a
/// closed or unknown handle.
#[no_mangle]
pub extern "system" fn Java_dev_local_androidmirror_core_NativeCore_nativeGetPin(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jstring {
    let pin = run("nativeGetPin", Zeroizing::default(), || {
        with_core(handle, |c| c.pin())
    });
    let s = java_string(&mut env, &pin);
    drop(pin); // wiped now; only the Java copy remains
    s
}

/// `nativeNewPin(handle): String?` — "New PIN" on the phone: rotate the PIN
/// and clear the PIN lockout and its escalation. Returns the new PIN (no
/// `onPinChanged` upcall for it), or null for a closed or unknown handle.
/// Call it off the main thread (it takes the server's pairing lock).
#[no_mangle]
pub extern "system" fn Java_dev_local_androidmirror_core_NativeCore_nativeNewPin(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jstring {
    let pin = run("nativeNewPin", None, || {
        with_core(handle, |c| c.new_pin()).map(Some)
    });
    match pin {
        Some(pin) => {
            let s = java_string(&mut env, &pin);
            drop(pin); // wiped now; only the Java copy remains
            s
        }
        None => std::ptr::null_mut(),
    }
}

/// `nativePinResets(handle): Long` — how many times "New PIN" has run, or -1
/// for a closed or unknown handle. Kotlin reads it right after
/// `nativeNewPin`, on the same thread, and drops an `onPairingFailed` whose
/// `resets` is below it. Safe though not atomic with the reset: the count
/// only grows, so the value read is at least that reset's count, and any
/// failure counted before the reset carries a smaller one. A larger value
/// (a later "New PIN" in between) only means that reset also cleared it.
#[no_mangle]
pub extern "system" fn Java_dev_local_androidmirror_core_NativeCore_nativePinResets(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jlong {
    run("nativePinResets", -1, || {
        with_core(handle, |c| pin_resets_arg(c.pin_resets()))
    })
}

/// `nativeSetControlAvailable(handle, available)` — the Accessibility service
/// is (not) running; control input is forwarded only while it is.
#[no_mangle]
pub extern "system" fn Java_dev_local_androidmirror_core_NativeCore_nativeSetControlAvailable(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
    available: jboolean,
) {
    run("nativeSetControlAvailable", (), || {
        with_core(handle, |c| c.set_control_available(available != 0))
    })
}

/// `nativeListPaired(handle): String?` — JSON array
/// `[{"clientId":"…","clientName":"…","pairedAtMs":123}]`. Null (logged) if
/// the pairing store could not be loaded or the handle is closed or
/// unknown, so the UI says it couldn't read the list instead of showing none.
#[no_mangle]
pub extern "system" fn Java_dev_local_androidmirror_core_NativeCore_nativeListPaired(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jstring {
    let json = run("nativeListPaired", None, || {
        let list =
            with_core(handle, |c| c.list_paired())?.map_err(|e| format!("pairing store: {e}"))?;
        Ok(Some(paired_json(&list)))
    });
    match json {
        Some(json) => java_string(&mut env, &json),
        None => std::ptr::null_mut(),
    }
}

/// `nativeRevoke(handle, clientId): Boolean` — forget a paired client
/// (disconnecting it if connected). True if it existed.
#[no_mangle]
pub extern "system" fn Java_dev_local_androidmirror_core_NativeCore_nativeRevoke<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    handle: jlong,
    client_id: JString<'l>,
) -> jboolean {
    let revoked = run("nativeRevoke", false, || {
        let id = rust_string(&mut env, &client_id, "clientId")?;
        with_core(handle, |c| c.revoke(&id))
    });
    if revoked {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

/// `nativeListPairedIn(filesDir): String` — like `nativeListPaired`, read
/// from `<filesDir>/pairings.json` while mirroring is not running. Null on
/// any failure (logged: unreadable, corrupt or newer store), so the UI says
/// it couldn't read the list instead of showing none.
#[no_mangle]
pub extern "system" fn Java_dev_local_androidmirror_core_NativeCore_nativeListPairedIn<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    files_dir: JString<'l>,
) -> jstring {
    let json = run("nativeListPairedIn", None, || {
        let dir = rust_string(&mut env, &files_dir, "filesDir")?;
        // Store errors are already logged where they happen.
        Ok(crate::store::list_json_in(&dir).ok())
    });
    match json {
        Some(json) => java_string(&mut env, &json),
        None => std::ptr::null_mut(),
    }
}

/// `nativeRevokeIn(filesDir, clientId): Boolean` — forget a paired client in
/// `<filesDir>/pairings.json` while mirroring is not running (so a lost Mac
/// can be revoked before the listener starts). True only if it was paired
/// and the removal was persisted. Must not race a running core.
#[no_mangle]
pub extern "system" fn Java_dev_local_androidmirror_core_NativeCore_nativeRevokeIn<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    files_dir: JString<'l>,
    client_id: JString<'l>,
) -> jboolean {
    let revoked = run("nativeRevokeIn", false, || {
        let dir = rust_string(&mut env, &files_dir, "filesDir")?;
        let id = rust_string(&mut env, &client_id, "clientId")?;
        // Store errors are already logged where they happen.
        Ok(crate::store::revoke_in(&dir, &id).unwrap_or(false))
    });
    if revoked {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

/// BYE to the client, join every thread, release the codec, drop the global
/// refs and invalidate the handle. Normally well under a second: the BYE
/// linger (500 ms) plus the codec release (accept is blocking on Android and
/// woken at once). Worst case it also waits for what the session threads
/// are doing: an encoder start or stop in flight (each bounded by the
/// encoder's 10 s `COMMAND_TIMEOUT`, so up to about 20 s) and their Kotlin
/// upcalls (`onClientState`, `onSurfaceGone`, which run on those threads
/// and take as long as Kotlin does); a wedged codec release is not bounded.
/// Call it off the main thread and without holding the projection lock or
/// any lock those upcalls take. 0 is a no-op; an unknown or destroyed
/// handle a logged one.
#[no_mangle]
pub extern "system" fn Java_dev_local_androidmirror_core_NativeCore_nativeDestroy(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    run("nativeDestroy", (), || {
        if handle == 0 {
            return Ok(());
        }
        let core = CORES
            .remove(handle)
            .ok_or_else(|| format!("unknown or destroyed handle {handle}"))?;
        // A call still in flight holds its own `Arc`; it finds a stopped core.
        core.shutdown();
        drop(core);
        log::info!("core destroyed");
        Ok(())
    })
}
