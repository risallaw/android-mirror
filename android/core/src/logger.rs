//! `log` facade → logcat (tag `MirrorCore`), without extra crates.

use std::ffi::{c_char, c_int, CString};

use log::{Level, LevelFilter, Log, Metadata, Record};

#[link(name = "log")]
extern "C" {
    fn __android_log_write(prio: c_int, tag: *const c_char, text: *const c_char) -> c_int;
}

struct Logcat;

static LOGGER: Logcat = Logcat;

impl Log for Logcat {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= log::max_level()
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        // ANDROID_LOG_DEBUG=3 … ERROR=6.
        let prio = match record.level() {
            Level::Error => 6,
            Level::Warn => 5,
            Level::Info => 4,
            Level::Debug => 3,
            Level::Trace => 2,
        };
        let msg = format!("[{}] {}", record.target(), record.args()).replace('\0', " ");
        if let Ok(text) = CString::new(msg) {
            // SAFETY: both pointers are valid NUL-terminated strings for the call.
            unsafe {
                __android_log_write(prio, c"MirrorCore".as_ptr(), text.as_ptr());
            }
        }
    }

    fn flush(&self) {}
}

/// Install the logger once (later calls are no-ops).
pub fn init() {
    if log::set_logger(&LOGGER).is_ok() {
        log::set_max_level(if cfg!(debug_assertions) {
            LevelFilter::Debug
        } else {
            LevelFilter::Info
        });
    }
}
