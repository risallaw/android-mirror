//! mirror-android-core: Rust core of the Android sender, loaded as `libmirror_core.so`.
//!
//! Host-testable logic lives in `config`, `control`, `display`, `events`,
//! `format`, `handles`, `recovery` and `store`; the JNI/NDK parts (`jni_api`,
//! `callbacks`, `encoder`, `core`, `logger`) build only for Android.
//!
//! Nothing is public except the JNI exports: the modules are private so the
//! dead-code lint sees every unused item on the Android target (the clippy
//! gate). On the host the Android-only callers are missing, hence the allow.
#![cfg_attr(not(target_os = "android"), allow(dead_code))]

mod config;
mod control;
mod display;
mod events;
mod format;
mod handles;
mod recovery;
mod store;

#[cfg(target_os = "android")]
mod callbacks;
#[cfg(target_os = "android")]
mod core;
#[cfg(target_os = "android")]
mod encoder;
#[cfg(target_os = "android")]
mod jni_api;
#[cfg(target_os = "android")]
mod logger;

/// Human-readable build identifier, e.g. `mirror-core 0.1.0 (rustc 1.97.0 ...)`.
fn version_string() -> String {
    format!(
        "mirror-core {} ({})",
        env!("CARGO_PKG_VERSION"),
        env!("MIRROR_RUSTC_VERSION")
    )
}

/// Runs `f`, turning a panic into its message so no unwind crosses the FFI boundary.
fn guarded<T>(f: impl FnOnce() -> T) -> Result<T, String> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).map_err(|payload| {
        payload
            .downcast_ref::<&str>()
            .map(|s| s.to_string())
            .or_else(|| payload.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "unknown panic".into())
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn version_string_has_prefix() {
        assert!(super::version_string().starts_with("mirror-core 0.1.0 (rustc"));
    }

    #[test]
    fn guarded_returns_value() {
        assert_eq!(super::guarded(|| 7), Ok(7));
    }

    #[test]
    fn guarded_catches_str_and_string_panics() {
        assert_eq!(
            super::guarded(|| -> u8 { panic!("boom") }),
            Err("boom".into())
        );
        let n = 3;
        assert_eq!(
            super::guarded(|| -> u8 { panic!("boom {n}") }),
            Err("boom 3".into())
        );
    }
}
