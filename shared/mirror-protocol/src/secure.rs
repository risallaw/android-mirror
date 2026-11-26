//! Record layer ("secure channel"): every frame after AUTH_RESULT `ok`.
//!
//! ```text
//! record    = u32_be len || ciphertext          len = ciphertext length incl. the 16-byte tag
//! plaintext = exactly one frame (16-byte header + payload)
//! nonce     = 4 zero bytes || u64_be seq        seq = 0, 1, 2, ... per direction
//! aad       = the 4 length bytes
//! AEAD      = ChaCha20-Poly1305
//! ```
//!
//! [`Sealer`] turns frames into records; [`Opener`] is the incremental,
//! sans-IO counterpart of [`Decoder`](crate::Decoder): push received bytes,
//! drain decrypted [`Message`]s. Every error except
//! [`ProtocolError::Malformed`] is fatal (the opener poisons itself) and the
//! connection must close without a BYE (it could not be authenticated).
//!
//! The sequence number makes every nonce unique per key (each direction has
//! its own key), and because the receiver tracks the same counter, a
//! dropped, replayed or reordered record fails authentication.

use std::fmt;

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce as AeadNonce, Tag};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::codec::encode_into_reserving;
use crate::error::ProtocolError;
use crate::messages::Message;
use crate::wire::{ty, Header, HEADER_LEN, MAX_JSON_PAYLOAD, MAX_PAYLOAD};

/// Poly1305 tag length.
pub const TAG_LEN: usize = 16;
/// Record length prefix size.
pub const LEN_PREFIX: usize = 4;

/// A 32-byte direction key. Zeroized on drop; `Debug` is redacted.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey(pub(crate) [u8; 32]);

impl SecretKey {
    pub fn from_bytes(b: [u8; 32]) -> Self {
        SecretKey(b)
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey(<redacted>)")
    }
}

fn nonce(seq: u64) -> AeadNonce {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&seq.to_be_bytes());
    n.into()
}

/// Smallest valid record `len`: a bare frame header plus the tag.
const MIN_RECORD_LEN: u32 = (HEADER_LEN + TAG_LEN) as u32;

/// Largest record `len` for a direction whose frames carry at most `max_payload`.
fn max_record_len(max_payload: u32) -> u32 {
    // max_payload is clamped to MAX_PAYLOAD, so this cannot overflow.
    HEADER_LEN as u32 + max_payload + TAG_LEN as u32
}

/// Encrypts outgoing frames. One per connection direction.
pub struct Sealer {
    // ChaCha20Poly1305 zeroizes its key on drop.
    aead: ChaCha20Poly1305,
    seq: u64,
    max_payload: u32,
}

impl fmt::Debug for Sealer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sealer")
            .field("seq", &self.seq)
            .field("max_payload", &self.max_payload)
            .finish_non_exhaustive()
    }
}

impl Sealer {
    /// `max_payload`: the peer's receive limit for this direction (the
    /// sealer refuses larger frames instead of sending a record the peer
    /// would reject). Clamped to [`MAX_PAYLOAD`].
    pub fn new(key: &SecretKey, max_payload: u32) -> Self {
        Sealer {
            aead: ChaCha20Poly1305::new(Key::from_slice(&key.0)),
            seq: 0,
            max_payload: max_payload.min(MAX_PAYLOAD),
        }
    }

    /// Encode `msg` and append it to `out` as one record. The frame is
    /// encoded straight into `out` (room for the tag reserved up front) and
    /// encrypted in place: no extra copy of a video payload.
    ///
    /// Errors (nothing is appended): payload over the limit,
    /// [`ProtocolError::SeqExhausted`].
    pub fn seal_message(&mut self, msg: &Message, out: &mut Vec<u8>) -> Result<(), ProtocolError> {
        let start = out.len();
        out.extend_from_slice(&[0; LEN_PREFIX]);
        encode_into_reserving(msg, out, TAG_LEN);
        self.seal_tail(out, start)
    }

    /// Append one record carrying `frame` (an encoded header + payload, as
    /// produced by [`encode`](crate::encode)) to `out`.
    ///
    /// Errors (nothing is appended): `frame` is not exactly one frame
    /// ([`ProtocolError::BadRecordPlaintext`]), payload over the limit,
    /// [`ProtocolError::SeqExhausted`].
    pub fn seal_frame(&mut self, frame: &[u8], out: &mut Vec<u8>) -> Result<(), ProtocolError> {
        let start = out.len();
        out.reserve(LEN_PREFIX + frame.len() + TAG_LEN);
        out.extend_from_slice(&[0; LEN_PREFIX]);
        out.extend_from_slice(frame);
        self.seal_tail(out, start)
    }

    /// `out[start..]` = 4 placeholder bytes + one plaintext frame. Encrypt it
    /// in place, fill in the length and append the tag. On error, truncate
    /// `out` back to `start`.
    fn seal_tail(&mut self, out: &mut Vec<u8>, start: usize) -> Result<(), ProtocolError> {
        let r = self.try_seal_tail(out, start);
        if r.is_err() {
            out.truncate(start);
        }
        r
    }

    fn try_seal_tail(&mut self, out: &mut Vec<u8>, start: usize) -> Result<(), ProtocolError> {
        let pt = &out[start + LEN_PREFIX..];
        check_one_frame(pt, self.max_payload)?;
        if self.seq == u64::MAX {
            return Err(ProtocolError::SeqExhausted);
        }
        // Fits: payload <= max_payload <= MAX_PAYLOAD.
        let len = (pt.len() + TAG_LEN) as u32;
        let len_bytes = len.to_be_bytes();
        out[start..start + LEN_PREFIX].copy_from_slice(&len_bytes);
        let tag = self
            .aead
            .encrypt_in_place_detached(&nonce(self.seq), &len_bytes, &mut out[start + LEN_PREFIX..])
            .map_err(|_| ProtocolError::BadRecord)?;
        out.extend_from_slice(&tag);
        self.seq += 1;
        Ok(())
    }
}

/// The plaintext must be one whole frame: header + exactly `length` payload
/// bytes, within the direction's limit and the JSON cap for JSON types.
fn check_one_frame(pt: &[u8], max_payload: u32) -> Result<Header, ProtocolError> {
    let Some(hb) = pt.first_chunk::<HEADER_LEN>() else {
        return Err(ProtocolError::BadRecordPlaintext);
    };
    let h = Header::decode(hb);
    if h.length as usize != pt.len() - HEADER_LEN {
        return Err(ProtocolError::BadRecordPlaintext);
    }
    let max = if ty::is_json(h.ty) {
        max_payload.min(MAX_JSON_PAYLOAD)
    } else {
        max_payload
    };
    if h.length > max {
        return Err(ProtocolError::PayloadTooLarge { len: h.length, max });
    }
    Ok(h)
}

/// Incremental record decoder: [`push`](Opener::push) received bytes, then
/// call [`next`](Opener::next) until it returns `Ok(None)`.
pub struct Opener {
    // ChaCha20Poly1305 zeroizes its key on drop.
    aead: ChaCha20Poly1305,
    seq: u64,
    max_payload: u32,
    buf: Vec<u8>,
    /// Read offset into `buf`; compacted lazily.
    pos: usize,
    failed: bool,
}

impl fmt::Debug for Opener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Opener")
            .field("seq", &self.seq)
            .field("max_payload", &self.max_payload)
            .field("buffered", &self.buffered())
            .field("failed", &self.failed)
            .finish_non_exhaustive()
    }
}

impl Opener {
    /// `max_payload`: the largest frame payload accepted in this direction
    /// ([`MAX_PAYLOAD`] phone -> receiver,
    /// [`MAX_CLIENT_PAYLOAD`](crate::wire::MAX_CLIENT_PAYLOAD) receiver ->
    /// phone). Records longer than `16 + max_payload + 16` are rejected from
    /// the 4 length bytes alone. Clamped to [`MAX_PAYLOAD`].
    pub fn new(key: &SecretKey, max_payload: u32) -> Self {
        Opener {
            aead: ChaCha20Poly1305::new(Key::from_slice(&key.0)),
            seq: 0,
            max_payload: max_payload.min(MAX_PAYLOAD),
            buf: Vec::new(),
            pos: 0,
            failed: false,
        }
    }

    /// Append received bytes (e.g. what the plaintext
    /// [`Decoder`](crate::Decoder) still held, see
    /// [`Decoder::take_buffered`](crate::Decoder::take_buffered), then
    /// socket reads). Everything pushed stays buffered until
    /// [`next`](Opener::next) consumes it, so drain after each push.
    pub fn push(&mut self, data: &[u8]) {
        if self.failed {
            return;
        }
        if self.pos > 0 && self.pos == self.buf.len() {
            self.buf.clear();
            self.pos = 0;
        } else if self.pos > 64 * 1024 && self.pos * 2 > self.buf.len() {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
        self.buf.extend_from_slice(data);
    }

    /// Bytes buffered but not yet consumed.
    pub fn buffered(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// Decrypt and decode the next complete record, if any.
    ///
    /// Fatal errors poison the opener (every later call returns
    /// [`ProtocolError::Poisoned`]); [`ProtocolError::Malformed`] (an
    /// authentic frame of a known type with an unparsable payload) consumes
    /// only that record.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<Option<Message>, ProtocolError> {
        if self.failed {
            return Err(ProtocolError::Poisoned);
        }
        let avail = &self.buf[self.pos..];
        let Some(lb) = avail.first_chunk::<LEN_PREFIX>() else {
            return Ok(None);
        };
        let len_bytes = *lb;
        let len = u32::from_be_bytes(len_bytes);
        // Check the length before waiting for (or buffering towards) the body:
        // never trust it for an allocation.
        let max = max_record_len(self.max_payload);
        if len > max {
            return Err(self.fail(ProtocolError::RecordTooLarge { len, max }));
        }
        if len < MIN_RECORD_LEN {
            return Err(self.fail(ProtocolError::RecordTooShort {
                len,
                min: MIN_RECORD_LEN,
            }));
        }
        let total = LEN_PREFIX + len as usize;
        if avail.len() < total {
            return Ok(None);
        }
        if self.seq == u64::MAX {
            return Err(self.fail(ProtocolError::SeqExhausted));
        }
        let ct_start = self.pos + LEN_PREFIX;
        let tag_start = self.pos + total - TAG_LEN;
        let tag = *Tag::from_slice(&self.buf[tag_start..self.pos + total]);
        let ok = self
            .aead
            .decrypt_in_place_detached(
                &nonce(self.seq),
                &len_bytes,
                &mut self.buf[ct_start..tag_start],
                &tag,
            )
            .is_ok();
        if !ok {
            return Err(self.fail(ProtocolError::BadRecord));
        }
        self.seq += 1;
        let pt = &self.buf[ct_start..tag_start];
        let h = match check_one_frame(pt, self.max_payload) {
            Ok(h) => h,
            Err(e) => return Err(self.fail(e)),
        };
        let res = Message::decode_frame(&h, &pt[HEADER_LEN..]);
        // The message owns its copy now; wipe the decrypted bytes so the
        // buffer never holds old plaintext (typed TEXT can be a password).
        // Costs under 1% of the decryption.
        self.buf[ct_start..tag_start].zeroize();
        self.pos += total;
        res.map(Some)
    }

    fn fail(&mut self, e: ProtocolError) -> ProtocolError {
        self.failed = true;
        // May hold a decrypted record that was not one valid frame.
        self.buf.zeroize();
        self.buf = Vec::new();
        self.pos = 0;
        e
    }
}

#[cfg(test)]
mod tests {
    /// chacha20 0.9 picks NEON only under this cfg (see .cargo/config.toml);
    /// a build that loses it silently runs the ~30% slower portable code.
    /// Checked on the aarch64 targets that config sets it for.
    #[test]
    #[cfg(all(
        target_arch = "aarch64",
        any(
            target_os = "macos",
            target_os = "android",
            all(target_os = "linux", target_env = "gnu")
        )
    ))]
    #[allow(clippy::assertions_on_constants)] // the constant IS the build flag under test
    fn aarch64_builds_use_the_neon_chacha20_backend() {
        assert!(cfg!(chacha20_force_neon), "set --cfg chacha20_force_neon");
    }

    use super::*;

    fn key() -> SecretKey {
        SecretKey::from_bytes([3; 32])
    }

    #[test]
    fn length_prefix_alone_does_not_preallocate() {
        let mut o = Opener::new(&key(), MAX_PAYLOAD);
        o.push(&max_record_len(MAX_PAYLOAD).to_be_bytes());
        assert_eq!(o.next(), Ok(None));
        assert!(o.buf.capacity() < 1024, "capacity {}", o.buf.capacity());
    }

    #[test]
    fn sequence_exhaustion_is_refused_not_wrapped() {
        let mut s = Sealer::new(&key(), MAX_PAYLOAD);
        let mut out = Vec::new();
        s.seq = u64::MAX - 1;
        s.seal_message(&Message::RequestKeyframe, &mut out).unwrap();
        let sealed = out.len();
        assert_eq!(
            s.seal_message(&Message::RequestKeyframe, &mut out),
            Err(ProtocolError::SeqExhausted)
        );
        assert_eq!(out.len(), sealed, "nothing appended on error");

        let mut o = Opener::new(&key(), MAX_PAYLOAD);
        o.seq = u64::MAX - 1;
        o.push(&out);
        o.push(&out); // a second record; seq would be u64::MAX
        assert_eq!(o.next(), Ok(Some(Message::RequestKeyframe)));
        assert_eq!(o.next(), Err(ProtocolError::SeqExhausted));
        assert_eq!(o.next(), Err(ProtocolError::Poisoned));
    }

    fn contains(hay: &[u8], needle: &[u8]) -> bool {
        hay.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn consumed_plaintext_is_wiped_from_the_buffer() {
        let secret = "hunter2-correct-horse";
        let mut s = Sealer::new(&key(), MAX_PAYLOAD);
        let mut wire = Vec::new();
        s.seal_message(&Message::Text(secret.into()), &mut wire)
            .unwrap();
        // A malformed (non-UTF-8) TEXT is consumed too: wiped as well.
        let mut bad = Header {
            ty: ty::TEXT,
            flags: 0,
            length: 8,
            pts_us: 0,
        }
        .encode()
        .to_vec();
        bad.extend_from_slice(b"\xffsecret!");
        s.seal_frame(&bad, &mut wire).unwrap();
        let mut o = Opener::new(&key(), MAX_PAYLOAD);
        o.push(&wire);
        assert_eq!(o.next(), Ok(Some(Message::Text(secret.into()))));
        assert!(!o.next().unwrap_err().is_fatal());
        assert_eq!(o.next(), Ok(None));
        assert!(!contains(&o.buf, secret.as_bytes()));
        assert!(!contains(&o.buf, b"secret!"));
    }

    #[test]
    fn debug_is_redacted() {
        let k = key();
        let s = format!("{k:?} {:?} {:?}", Sealer::new(&k, 1), Opener::new(&k, 1));
        assert!(!s.contains("3, 3"), "{s}");
    }
}
