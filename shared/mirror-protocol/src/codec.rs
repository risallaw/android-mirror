//! Sans-IO framing: [`encode`] a message, feed received bytes into a [`Decoder`].

use crate::error::ProtocolError;
use crate::messages::Message;
use crate::wire::{ty, Header, HEADER_LEN, MAGIC, MAX_JSON_PAYLOAD, MAX_PAYLOAD};

/// Encode a message as header + payload. Does not include the magic preamble
/// (send [`MAGIC`] once at connection start).
///
/// Payloads larger than [`MAX_PAYLOAD`] are a caller bug; the peer will
/// reject them. Debug builds assert.
pub fn encode(msg: &Message) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(msg, &mut out);
    out
}

/// Encode a message and append it to `out`.
pub fn encode_into(msg: &Message, out: &mut Vec<u8>) {
    encode_into_reserving(msg, out, 0);
}

/// [`encode_into`], also reserving `extra` bytes after the frame (the record
/// tag) so appending them later does not reallocate and copy the frame.
pub(crate) fn encode_into_reserving(msg: &Message, out: &mut Vec<u8>, extra: usize) {
    let payload = msg.payload();
    debug_assert!(
        payload.len() <= MAX_PAYLOAD as usize,
        "payload exceeds MAX_PAYLOAD"
    );
    let h = Header {
        ty: msg.ty(),
        flags: msg.flags(),
        // Saturate rather than wrap: a header claiming u32::MAX is rejected
        // by every peer (and by the Sealer's one-frame check), while a
        // wrapped length would desynchronise the stream.
        length: u32::try_from(payload.len()).unwrap_or(u32::MAX),
        pts_us: msg.pts_us(),
    };
    out.reserve(HEADER_LEN + payload.len() + extra);
    out.extend_from_slice(&h.encode());
    out.extend_from_slice(&payload);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Magic,
    Frames,
    Failed,
}

/// Incremental decoder. Push arbitrary chunks of received bytes with
/// [`push`](Decoder::push), then drain messages with [`next`](Decoder::next)
/// until it returns `Ok(None)`.
///
/// Fatal errors (bad magic, oversize length) poison the decoder: every later
/// call returns [`ProtocolError::Poisoned`]. A [`ProtocolError::Malformed`]
/// error consumes only the offending frame; decoding can continue.
#[derive(Debug)]
pub struct Decoder {
    buf: Vec<u8>,
    /// Read offset into `buf`; compacted lazily.
    pos: usize,
    state: State,
    max_payload: u32,
}

impl Default for Decoder {
    fn default() -> Self {
        Decoder::new(true)
    }
}

impl Decoder {
    /// `expect_magic`: require the 4-byte `AMR1` preamble before the first frame.
    pub fn new(expect_magic: bool) -> Self {
        Decoder {
            buf: Vec::new(),
            pos: 0,
            state: if expect_magic {
                State::Magic
            } else {
                State::Frames
            },
            max_payload: MAX_PAYLOAD,
        }
    }

    /// Lower the maximum accepted payload length (default [`MAX_PAYLOAD`]).
    /// Values above [`MAX_PAYLOAD`] are clamped to it: the protocol never
    /// allows more, and a larger limit could overflow `usize` on 32-bit targets.
    pub fn with_max_payload(mut self, max: u32) -> Self {
        self.max_payload = max.min(MAX_PAYLOAD);
        self
    }

    /// Append received bytes. Everything pushed stays buffered until
    /// [`next`](Decoder::next) consumes it, so drain after each push.
    pub fn push(&mut self, data: &[u8]) {
        if self.state == State::Failed {
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

    /// Remove and return the bytes buffered but not yet decoded. Use it when
    /// the plaintext handshake ends: whatever the peer already sent after its
    /// last plaintext frame is the start of the record stream, so push it
    /// into the [`Opener`](crate::secure::Opener) before further reads.
    pub fn take_buffered(&mut self) -> Vec<u8> {
        let rest = self.buf.split_off(self.pos);
        self.buf.clear();
        self.pos = 0;
        rest
    }

    /// True once the magic preamble has been seen (or was not expected).
    pub fn magic_seen(&self) -> bool {
        self.state == State::Frames
    }

    /// Decode the next complete message, if any.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<Option<Message>, ProtocolError> {
        loop {
            let avail = &self.buf[self.pos..];
            match self.state {
                State::Failed => return Err(ProtocolError::Poisoned),
                State::Magic => {
                    // Check the bytes we have so far so garbage fails fast.
                    let n = avail.len().min(4);
                    if avail[..n] != MAGIC[..n] {
                        let mut got = [0u8; 4];
                        got[..n].copy_from_slice(&avail[..n]);
                        return Err(self.fail(ProtocolError::BadMagic(got)));
                    }
                    if n < 4 {
                        return Ok(None);
                    }
                    self.pos += 4;
                    self.state = State::Frames;
                }
                State::Frames => {
                    if avail.len() < HEADER_LEN {
                        return Ok(None);
                    }
                    let hb: &[u8; HEADER_LEN] = avail[..HEADER_LEN].try_into().unwrap();
                    let h = Header::decode(hb);
                    let max = if ty::is_json(h.ty) {
                        self.max_payload.min(MAX_JSON_PAYLOAD)
                    } else {
                        self.max_payload
                    };
                    if h.length > max {
                        return Err(
                            self.fail(ProtocolError::PayloadTooLarge { len: h.length, max })
                        );
                    }
                    let total = HEADER_LEN + h.length as usize;
                    // No up-front reserve for the body: a peer could make us
                    // allocate MAX_PAYLOAD with a 16-byte header alone.
                    if avail.len() < total {
                        return Ok(None);
                    }
                    let res = Message::decode_frame(&h, &avail[HEADER_LEN..total]);
                    self.pos += total;
                    return res.map(Some);
                }
            }
        }
    }

    fn fail(&mut self, e: ProtocolError) -> ProtocolError {
        self.state = State::Failed;
        self.buf = Vec::new();
        self.pos = 0;
        e
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_alone_does_not_preallocate_body() {
        let h = Header {
            ty: ty::VIDEO_FRAME,
            flags: 0,
            length: MAX_PAYLOAD,
            pts_us: 0,
        };
        let mut d = Decoder::new(false);
        d.push(&h.encode());
        assert_eq!(d.next(), Ok(None));
        assert!(d.buf.capacity() < 1024, "capacity {}", d.buf.capacity());
    }
}
