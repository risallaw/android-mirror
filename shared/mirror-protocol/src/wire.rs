//! Wire constants and the fixed 16-byte frame header.

/// Connection preamble each side sends first: `"AMR1"`.
pub const MAGIC: [u8; 4] = *b"AMR1";
/// Protocol version carried in the HELLO messages (`proto`).
pub const PROTO_VERSION: u32 = 2;
/// Default TCP port of the phone-side server.
pub const DEFAULT_PORT: u16 = 47800;
/// DNS-SD service type.
pub const SERVICE_TYPE: &str = "_androidmirror._tcp";
/// Maximum accepted payload length (8 MiB).
pub const MAX_PAYLOAD: u32 = 8 * 1024 * 1024;
/// Maximum accepted payload length for JSON message types (64 KiB). These
/// are small control messages, mostly exchanged before authentication, so a
/// tighter limit keeps a hostile peer from making us buffer and parse 8 MiB.
pub const MAX_JSON_PAYLOAD: u32 = 64 * 1024;
/// Maximum payload of any receiver -> phone frame (64 KiB, every type,
/// TEXT included). The phone enforces it on the plaintext handshake decoder
/// and on its record [`Opener`](crate::secure::Opener).
pub const MAX_CLIENT_PAYLOAD: u32 = 64 * 1024;
/// Size of the frame header in bytes.
pub const HEADER_LEN: usize = 16;

/// Message type codes.
pub mod ty {
    // Phone -> receiver
    pub const SERVER_HELLO: u8 = 0x01;
    pub const AUTH_RESULT: u8 = 0x02;
    pub const VIDEO_CONFIG: u8 = 0x03;
    pub const VIDEO_FRAME: u8 = 0x04;
    pub const STATUS: u8 = 0x05;
    pub const PONG: u8 = 0x06;
    pub const SERVER_BYE: u8 = 0x07;
    /// Reserved (Phase 3).
    pub const AUDIO_CONFIG: u8 = 0x08;
    /// Reserved (Phase 3).
    pub const AUDIO_FRAME: u8 = 0x09;
    /// PIN pairing: SPAKE2 message B + server confirmation.
    pub const PAKE_REPLY: u8 = 0x0A;

    // Receiver -> phone
    pub const CLIENT_HELLO: u8 = 0x10;
    pub const AUTH: u8 = 0x11;
    pub const START: u8 = 0x12;
    pub const REQUEST_KEYFRAME: u8 = 0x13;
    pub const PING: u8 = 0x14;
    pub const CLIENT_BYE: u8 = 0x15;
    /// PIN pairing: client confirmation.
    pub const AUTH_CONFIRM: u8 = 0x16;
    pub const TOUCH_GESTURE: u8 = 0x20;
    pub const GLOBAL_ACTION: u8 = 0x21;
    pub const TEXT: u8 = 0x22;
    pub const KEY: u8 = 0x23;
    pub const SCROLL: u8 = 0x24;
    pub const TOUCH_LIVE: u8 = 0x25;

    /// True for the types whose payload is JSON.
    pub fn is_json(t: u8) -> bool {
        matches!(
            t,
            SERVER_HELLO
                | AUTH_RESULT
                | STATUS
                | SERVER_BYE
                | CLIENT_HELLO
                | AUTH
                | START
                | CLIENT_BYE
                | PAKE_REPLY
                | AUTH_CONFIRM
        )
    }
}

/// Header flag bits.
pub mod flags {
    pub const KEYFRAME: u8 = 1 << 0;
    pub const CONFIG: u8 = 1 << 1;
    pub const DISCONTINUITY: u8 = 1 << 2;
}

/// The 16-byte big-endian frame header.
///
/// | off | size | field |
/// |---|---|---|
/// | 0 | u8 | type |
/// | 1 | u8 | flags |
/// | 2 | u16 | reserved (0) |
/// | 4 | u32 | length |
/// | 8 | u64 | pts_us |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Header {
    pub ty: u8,
    pub flags: u8,
    pub length: u32,
    pub pts_us: u64,
}

impl Header {
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut b = [0u8; HEADER_LEN];
        b[0] = self.ty;
        b[1] = self.flags;
        // b[2..4] reserved = 0
        b[4..8].copy_from_slice(&self.length.to_be_bytes());
        b[8..16].copy_from_slice(&self.pts_us.to_be_bytes());
        b
    }

    /// Parse a header. The reserved field is ignored (forward compatibility).
    pub fn decode(b: &[u8; HEADER_LEN]) -> Header {
        Header {
            ty: b[0],
            flags: b[1],
            length: u32::from_be_bytes([b[4], b[5], b[6], b[7]]),
            pts_us: u64::from_be_bytes([b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]]),
        }
    }
}
