//! Logging helpers for what a peer controls: rate limiting for lines it can
//! trigger at will, truncation for strings it chooses.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::server::lock;

/// Default interval between two throttled lines of one kind.
pub(crate) const LOG_INTERVAL: Duration = Duration::from_secs(5);

/// At most one event per `interval`, counting the ones suppressed.
#[derive(Debug)]
pub(crate) struct Throttle {
    interval: Duration,
    last: Option<Instant>,
    suppressed: u64,
}

impl Throttle {
    pub(crate) const fn new(interval: Duration) -> Self {
        Throttle {
            interval,
            last: None,
            suppressed: 0,
        }
    }

    /// `Some(n)` if an event may be reported at `now`, `n` being the number
    /// suppressed since the last one; `None` (and counted) otherwise.
    pub(crate) fn allow(&mut self, now: Instant) -> Option<u64> {
        if self
            .last
            .is_some_and(|t| now.saturating_duration_since(t) < self.interval)
        {
            self.suppressed += 1;
            return None;
        }
        self.last = Some(now);
        Some(std::mem::take(&mut self.suppressed))
    }
}

/// Log `msg()` at `level` unless `t` suppresses it; the next line that gets
/// through says how many were suppressed.
pub(crate) fn log_throttled(t: &Mutex<Throttle>, level: log::Level, msg: impl FnOnce() -> String) {
    if !log::log_enabled!(level) {
        return;
    }
    let Some(n) = lock(t).allow(Instant::now()) else {
        return;
    };
    let msg = msg();
    if n == 0 {
        log::log!(level, "{msg}");
    } else {
        log::log!(level, "{msg} ({n} similar lines suppressed)");
    }
}

/// Longest peer-chosen string (client name or id) put in a log line.
const LOG_STR_MAX: usize = 64;

/// `s` cut to 64 characters (marked with `…`), for logging a peer-chosen
/// string (a client name or id) with `{:?}`, which also escapes line breaks
/// and control characters so the string cannot forge log lines. Exported as
/// [`log_str`](crate::log_str).
pub fn short(s: &str) -> std::borrow::Cow<'_, str> {
    match s.char_indices().nth(LOG_STR_MAX) {
        None => s.into(),
        Some((i, _)) => format!("{}…", &s[..i]).into(),
    }
}

/// Test-only `log` backend that keeps every record, so tests can count the
/// lines a flood produces. Installed once per test binary; tests filter the
/// records by a marker unique to them (tests run in parallel).
#[cfg(test)]
pub(crate) mod capture {
    use std::sync::{Mutex, Once};

    static RECORDS: Mutex<Vec<(log::Level, String)>> = Mutex::new(Vec::new());

    struct Capture;

    impl log::Log for Capture {
        fn enabled(&self, _: &log::Metadata) -> bool {
            true
        }
        fn log(&self, r: &log::Record) {
            crate::server::lock(&RECORDS).push((r.level(), r.args().to_string()));
        }
        fn flush(&self) {}
    }

    pub(crate) fn install() {
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            log::set_logger(&Capture).expect("no other logger in unit tests");
            log::set_max_level(log::LevelFilter::Trace);
        });
    }

    /// Records at `level` whose text contains every one of `needles`.
    pub(crate) fn count(level: log::Level, needles: &[&str]) -> usize {
        crate::server::lock(&RECORDS)
            .iter()
            .filter(|(l, m)| *l == level && needles.iter().all(|n| m.contains(n)))
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_truncates_long_strings_on_a_char_boundary() {
        assert_eq!(short("mac"), "mac");
        let exact = "é".repeat(LOG_STR_MAX);
        assert_eq!(short(&exact), exact);
        let long = "é".repeat(LOG_STR_MAX + 1);
        assert_eq!(short(&long), format!("{exact}…"));
        // Logged with `{:?}`: no raw line break or control character.
        let forged = format!("{:?}", short("mac\nE MirrorCore: fake\r\u{1b}[31m"));
        assert!(!forged.contains(['\n', '\r', '\u{1b}']), "{forged}");
    }

    #[test]
    fn one_per_interval_with_a_suppressed_count() {
        let mut t = Throttle::new(Duration::from_secs(5));
        let t0 = Instant::now();
        assert_eq!(t.allow(t0), Some(0));
        assert_eq!(t.allow(t0 + Duration::from_secs(1)), None);
        assert_eq!(t.allow(t0 + Duration::from_millis(4_999)), None);
        assert_eq!(t.allow(t0 + Duration::from_secs(5)), Some(2));
        assert_eq!(t.allow(t0 + Duration::from_secs(11)), Some(0));
    }
}
