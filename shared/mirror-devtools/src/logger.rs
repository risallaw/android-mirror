//! Minimal stderr logger (no env_logger dependency).

use log::{Level, LevelFilter, Log, Metadata, Record};
use std::time::{SystemTime, UNIX_EPOCH};

struct StderrLogger;

impl Log for StderrLogger {
    fn enabled(&self, m: &Metadata) -> bool {
        m.level() <= log::max_level()
    }
    fn log(&self, r: &Record) {
        if !self.enabled(r.metadata()) {
            return;
        }
        let t = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let lvl = match r.level() {
            Level::Error => "ERROR",
            Level::Warn => "WARN ",
            Level::Info => "INFO ",
            Level::Debug => "DEBUG",
            Level::Trace => "TRACE",
        };
        eprintln!(
            "{}.{:03} {lvl} {}",
            (t / 1000) % 100_000,
            t % 1000,
            r.args()
        );
    }
    fn flush(&self) {}
}

/// The log level for the value of `MIRROR_LOG`/`RUST_LOG` (`None`: unset):
/// `error|warn|info|debug|trace|off` (any case), default `info`. `Err` names
/// an invalid value.
pub fn parse_level(value: Option<&str>) -> Result<LevelFilter, String> {
    match value {
        None => Ok(LevelFilter::Info),
        Some(s) => s
            .trim()
            .parse::<LevelFilter>()
            .map_err(|_| format!("invalid log level {s:?} (use error|warn|info|debug|trace|off)")),
    }
}

/// Install the stderr logger. Level from `MIRROR_LOG` or `RUST_LOG`
/// (see [`parse_level`]); an invalid value is reported and `info` used.
/// Safe to call twice.
pub fn init_logger() {
    static LOGGER: StderrLogger = StderrLogger;
    let value = std::env::var("MIRROR_LOG")
        .or_else(|_| std::env::var("RUST_LOG"))
        .ok();
    let level = parse_level(value.as_deref()).unwrap_or_else(|e| {
        eprintln!("warning: {e}; using info");
        LevelFilter::Info
    });
    if log::set_logger(&LOGGER).is_ok() {
        log::set_max_level(level);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levels() {
        assert_eq!(parse_level(None), Ok(LevelFilter::Info));
        assert_eq!(parse_level(Some("DEBUG")), Ok(LevelFilter::Debug));
        assert_eq!(parse_level(Some("off")), Ok(LevelFilter::Off));
        assert!(parse_level(Some("verbose"))
            .unwrap_err()
            .contains("verbose"));
        assert!(parse_level(Some("")).is_err());
    }
}
