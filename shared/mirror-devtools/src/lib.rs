//! mirror-devtools: helpers and binaries for exercising the sender/receiver
//! cores on a desktop without a phone.
//!
//! - [`H264Stream`]: an Annex-B `.h264` file split into access units
//!   ([`split_access_units`]) with SPS/PPS and dimensions ([`parse_sps`]).
//! - [`FileSource`]: a [`mirror_sender::VideoSource`] that replays an
//!   [`H264Stream`] at a fixed frame rate (used by the `fakeserver` bin).
//! - [`init_logger`]: a tiny stderr logger for the bins.
//!
//! Binaries: `fakeserver` (serve a file over the mirror protocol) and
//! `rawclient` (receive and write raw Annex-B to stdout, e.g. for ffplay).

mod logger;
mod source;
mod splitter;
mod sps;

pub use logger::{init_logger, parse_level};
pub use source::{FakeOptions, FileSource};
pub use splitter::{split_access_units, AccessUnit, H264Stream, StreamError};
pub use sps::{parse_sps, SpsError, SpsInfo};

/// `s` safe to print on a terminal: control characters (escape sequences,
/// newlines that would forge log lines) and bidirectional-override
/// characters are replaced with `\u{FFFD}`. For strings a peer chose
/// (device or client names, error texts).
pub fn printable(s: &str) -> String {
    s.chars()
        .map(|c| {
            let bidi = matches!(c, '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}');
            if c.is_control() || bidi {
                '\u{FFFD}'
            } else {
                c
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn printable_neutralises_terminal_controls() {
        assert_eq!(super::printable("Pixel 8 é"), "Pixel 8 é");
        assert_eq!(
            super::printable("a\x1b[2Jb\nc\u{202E}d\u{7f}"),
            "a\u{FFFD}[2Jb\u{FFFD}c\u{FFFD}d\u{FFFD}"
        );
    }
}
