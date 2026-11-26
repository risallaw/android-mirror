use thiserror::Error;

/// Longest [`ProtocolError::Malformed`] `reason`, in characters (plus `…`
/// when cut).
pub(crate) const MAX_REASON_CHARS: usize = 160;

/// Errors produced while decoding protocol data.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    /// The 4-byte connection preamble was not `AMR1`.
    #[error("bad magic: expected \"AMR1\", got {0:02x?}")]
    BadMagic([u8; 4]),

    /// A frame header announced a payload larger than the allowed maximum.
    #[error("payload too large: {len} bytes (max {max})")]
    PayloadTooLarge { len: u32, max: u32 },

    /// A known message type had a payload that could not be parsed.
    /// The offending frame has been consumed; the stream is still in sync.
    #[error("malformed payload for message type 0x{ty:02x}: {reason}")]
    Malformed { ty: u8, reason: String },

    /// A record announced a ciphertext length above this direction's limit.
    #[error("record length {len} too large (max {max})")]
    RecordTooLarge { len: u32, max: u32 },

    /// A record announced a ciphertext length below header + tag, which no
    /// valid record can have.
    #[error("record length {len} too short (min {min})")]
    RecordTooShort { len: u32, min: u32 },

    /// A record failed authentication (wrong key, tampered bytes, reordered
    /// or replayed record). The connection must close; no BYE can be trusted.
    #[error("record failed authentication")]
    BadRecord,

    /// A record decrypted fine but its plaintext was not exactly one frame.
    #[error("record plaintext is not exactly one frame")]
    BadRecordPlaintext,

    /// The 64-bit record sequence number is exhausted (nonce reuse guard).
    #[error("record sequence number exhausted")]
    SeqExhausted,

    /// The decoder hit a fatal error earlier and will not produce more messages.
    #[error("decoder is in a failed state after a previous fatal error")]
    Poisoned,
}

impl ProtocolError {
    /// True when the stream can no longer be decoded and the connection should close.
    pub fn is_fatal(&self) -> bool {
        !matches!(self, ProtocolError::Malformed { .. })
    }

    /// `reason` may quote peer-controlled text (serde errors echo the
    /// offending value), and it ends up in logs: escape control characters
    /// and cap it at [`MAX_REASON_CHARS`] so a hostile peer cannot inject log
    /// lines or make each error carry 64 KiB.
    pub(crate) fn malformed(ty: u8, reason: impl AsRef<str>) -> Self {
        let mut out = String::new();
        // Quotes and backslashes stay readable; control, bidi and other
        // non-printable characters are written as escapes.
        let mut chars = reason.as_ref().chars().flat_map(|c| {
            let keep = matches!(c, '"' | '\'' | '\\');
            let one = keep.then_some(c).into_iter();
            let esc = (!keep).then(|| c.escape_debug()).into_iter().flatten();
            one.chain(esc)
        });
        out.extend(chars.by_ref().take(MAX_REASON_CHARS));
        if chars.next().is_some() {
            out.push('…');
        }
        ProtocolError::Malformed { ty, reason: out }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reason(e: ProtocolError) -> String {
        match e {
            ProtocolError::Malformed { reason, .. } => reason,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn malformed_reason_escapes_raw_control_characters() {
        let r = reason(ProtocolError::malformed(
            1,
            "unknown variant `a\nb\r\u{1b}[31m\u{202e}`, \"q\" \\",
        ));
        assert_eq!(
            r,
            "unknown variant `a\\nb\\r\\u{1b}[31m\\u{202e}`, \"q\" \\"
        );
    }

    #[test]
    fn malformed_reason_is_capped() {
        let r = reason(ProtocolError::malformed(1, "é".repeat(10_000)));
        assert_eq!(r.chars().count(), MAX_REASON_CHARS + 1);
        assert!(r.ends_with("é…"));
        let exact = "é".repeat(MAX_REASON_CHARS);
        assert_eq!(reason(ProtocolError::malformed(1, &exact)), exact);
    }
}
