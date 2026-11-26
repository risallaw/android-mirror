//! Typed protocol messages and their payload (de)serialisation.

use std::borrow::Cow;

use serde::{Deserialize, Serialize};

use crate::error::ProtocolError;
use crate::wire::{flags, ty, Header};

// ---------------------------------------------------------------------------
// JSON payloads
// ---------------------------------------------------------------------------

/// Authentication modes advertised in SERVER_HELLO and chosen in AUTH.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthMode {
    /// SPAKE2 PIN pairing (AUTH carries `pake`; PAKE_REPLY / AUTH_CONFIRM follow).
    Pin,
    /// HMAC proof keyed by a stored 32-byte pairing key.
    Token,
    /// No authentication (devtools/tests only; still encrypted, control is refused).
    #[serde(rename = "none")]
    NoAuth,
    /// Any mode this version does not know.
    #[serde(other)]
    Unknown,
}

impl AuthMode {
    /// The wire string, also bound into the handshake transcript.
    /// `None` for [`AuthMode::Unknown`], which can never be negotiated.
    pub fn as_str(self) -> Option<&'static str> {
        match self {
            AuthMode::Pin => Some("pin"),
            AuthMode::Token => Some("token"),
            AuthMode::NoAuth => Some("none"),
            AuthMode::Unknown => None,
        }
    }
}

/// Why the phone refused authentication (AUTH_RESULT `reason`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthReason {
    /// Token mode, but the phone holds no key for this `clientId` (never
    /// paired, or revoked). The client should forget its key and re-pair.
    UnknownClient,
    /// The proof / PAKE message did not verify.
    BadProof,
    /// Too many wrong PINs; `retryAfterMs` says when to try again.
    LockedOut,
    /// The requested mode is not offered (e.g. `none` without `allow_no_auth`).
    ModeUnsupported,
    /// Any reason this version does not know.
    #[serde(other)]
    Unknown,
}

/// 0x01 SERVER_HELLO (phone -> receiver).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerHello {
    /// Lenient: see [`ClientHello::proto`].
    #[serde(default, deserialize_with = "lenient_proto")]
    pub proto: u32,
    pub device_name: String,
    pub device_id: String,
    pub model: String,
    pub sdk_int: u32,
    #[serde(default)]
    pub codecs: Vec<String>,
    /// Capability strings, e.g. `"control"`, later `"enc"`.
    #[serde(default)]
    pub caps: Vec<String>,
    #[serde(default)]
    pub auth_modes: Vec<AuthMode>,
    /// Server nonce, lowercase hex (32 random bytes -> 64 chars).
    pub nonce_s: String,
    /// Server ephemeral X25519 public key, lowercase hex (64 chars).
    /// Defaults to empty so a v1 peer still decodes and gets `proto_mismatch`.
    #[serde(default)]
    pub kx: String,
}

/// 0x02 AUTH_RESULT (phone -> receiver).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct AuthResult {
    pub ok: bool,
    /// Token-mode server proof, lowercase hex. Present when `ok` and mode was
    /// `token` (in `pin` mode the server proved itself in PAKE_REPLY).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_proof: Option<String>,
    /// Failure reason when `!ok`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<AuthReason>,
    /// With `locked_out`: milliseconds until PIN attempts are accepted again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
}

/// 0x0A PAKE_REPLY (phone -> receiver), PIN mode only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PakeReply {
    /// SPAKE2 message B, lowercase hex.
    pub pake: String,
    /// `serverConfirm`, lowercase hex (32 bytes).
    pub server_proof: String,
}

/// 0x16 AUTH_CONFIRM (receiver -> phone), PIN mode only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthConfirm {
    /// `clientConfirm`, lowercase hex (32 bytes).
    pub proof: String,
}

/// STATUS states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StatusState {
    /// Reserved: defined by the protocol, never sent by the phone.
    Streaming,
    ScreenOff,
    ScreenOn,
    Reconfiguring,
    ControlAvailable,
    ControlUnavailable,
    #[serde(other)]
    Unknown,
}

/// 0x05 STATUS (phone -> receiver).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Status {
    pub state: StatusState,
}

/// BYE reasons (both directions).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ByeReason {
    StoppedByUser,
    ProjectionRevoked,
    Replaced,
    AuthFailed,
    ProtoMismatch,
    #[serde(other)]
    Unknown,
}

/// 0x07 / 0x15 BYE.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bye {
    pub reason: ByeReason,
}

/// 0x10 CLIENT_HELLO (receiver -> phone).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientHello {
    /// Protocol version. Lenient: a missing value, or one that is not a
    /// `u32` (a future peer's `"3.0"`, `-1`, `2^40`), decodes as 0, so the
    /// peer gets `proto_mismatch` instead of a decode error.
    #[serde(default, deserialize_with = "lenient_proto")]
    pub proto: u32,
    pub client_name: String,
    pub client_id: String,
    /// Client nonce, lowercase hex (32 random bytes -> 64 chars).
    pub nonce_c: String,
    /// Client ephemeral X25519 public key, lowercase hex (64 chars).
    /// Defaults to empty so a v1 peer still decodes and gets `proto_mismatch`.
    #[serde(default)]
    pub kx: String,
}

/// 0x11 AUTH (receiver -> phone).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Auth {
    pub mode: AuthMode,
    /// Token-mode client proof, lowercase hex. Empty for `pin` and `none`.
    #[serde(default)]
    pub proof: String,
    /// PIN mode: SPAKE2 message A, lowercase hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pake: Option<String>,
}

/// 0x12 START (receiver -> phone). All fields optional; an empty payload
/// decodes as `Start::default()` (sender defaults).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Start {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_long_edge: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_fps: Option<u32>,
    /// Bits per second.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bitrate: Option<u32>,
}

// ---------------------------------------------------------------------------
// Binary payloads
// ---------------------------------------------------------------------------

/// 0x03 VIDEO_CONFIG. Encoded with the CONFIG flag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VideoConfig {
    /// Encoded (video frame) width in pixels.
    pub width: u16,
    pub height: u16,
    /// Physical display size the normalised coordinates map onto.
    pub display_width: u16,
    pub display_height: u16,
    /// Display rotation in quarter turns (Android `Surface.ROTATION_*`, 0..=3).
    pub rotation: u8,
    /// SPS + PPS in Annex-B form (with start codes).
    pub sps_pps: Vec<u8>,
}

/// 0x04 VIDEO_FRAME: one Annex-B access unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VideoFrame {
    pub pts_us: u64,
    /// Header flags (`flags::KEYFRAME`, `flags::DISCONTINUITY`).
    pub flags: u8,
    pub data: Vec<u8>,
}

impl VideoFrame {
    pub fn is_keyframe(&self) -> bool {
        self.flags & flags::KEYFRAME != 0
    }
    pub fn is_discontinuity(&self) -> bool {
        self.flags & flags::DISCONTINUITY != 0
    }
}

macro_rules! u8_enum {
    ($(#[$m:meta])* $name:ident { $($(#[$vm:meta])* $v:ident = $n:literal),* $(,)? }) => {
        $(#[$m])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum $name {
            $($(#[$vm])* $v,)*
            /// A value this version does not know (kept for forward compatibility).
            Other(u8),
        }
        impl $name {
            pub fn to_u8(self) -> u8 {
                match self { $($name::$v => $n,)* $name::Other(x) => x }
            }
            pub fn from_u8(x: u8) -> Self {
                match x { $($n => $name::$v,)* other => $name::Other(other) }
            }
        }
        impl From<u8> for $name { fn from(x: u8) -> Self { Self::from_u8(x) } }
        impl From<$name> for u8 { fn from(x: $name) -> u8 { x.to_u8() } }
    };
}

u8_enum!(
    /// TOUCH_GESTURE kind.
    GestureKind { Tap = 1, LongPress = 2, Path = 3 }
);

u8_enum!(
    /// 0x21 GLOBAL_ACTION.
    GlobalAction {
        Back = 1, Home = 2, Recents = 3, Notifications = 4, QuickSettings = 5,
        Lock = 6, VolumeUp = 7, VolumeDown = 8,
    }
);

u8_enum!(
    /// 0x23 KEY.
    Key {
        Backspace = 1, Enter = 2, Left = 3, Right = 4, Up = 5, Down = 6,
        DeleteForward = 7, Tab = 8,
    }
);

u8_enum!(
    /// TOUCH_LIVE phase.
    TouchPhase { Down = 0, Move = 1, Up = 2, Cancel = 3 }
);

/// One point of a TOUCH_GESTURE. `x`,`y` normalised 0..=65535 over the video
/// frame; `dt_ms` is the time since the previous point (0 for the first).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GesturePoint {
    pub x: u16,
    pub y: u16,
    pub dt_ms: u16,
}

/// Maximum points in one TOUCH_GESTURE (`count` is a u8).
pub const MAX_GESTURE_POINTS: usize = 255;

/// 0x20 TOUCH_GESTURE. At most [`MAX_GESTURE_POINTS`] points are encoded;
/// extra points are dropped by the encoder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TouchGesture {
    pub kind: GestureKind,
    pub points: Vec<GesturePoint>,
}

/// 0x24 SCROLL: a finger drag of (`dx`, `dy`) starting at (`x`, `y`).
///
/// `x`,`y` are normalised like every coordinate (0..=65535 over the video
/// frame). `dx`,`dy` are the finger-drag distance in the same normalised
/// units (65535 = the full video width / height), signed; positive `dy` =
/// the finger moves down (content scrolls up), positive `dx` = right. The
/// sender maps them to display pixels exactly like coordinates, keeping sign.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Scroll {
    pub x: u16,
    pub y: u16,
    pub dx: i16,
    pub dy: i16,
}

/// 0x25 TOUCH_LIVE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TouchLive {
    pub phase: TouchPhase,
    pub x: u16,
    pub y: u16,
}

// ---------------------------------------------------------------------------
// Message
// ---------------------------------------------------------------------------

/// Every protocol message. Direction is implied by the variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    // Phone -> receiver
    ServerHello(ServerHello),
    AuthResult(AuthResult),
    VideoConfig(VideoConfig),
    VideoFrame(VideoFrame),
    Status(Status),
    Pong([u8; 8]),
    ServerBye(Bye),
    PakeReply(PakeReply),
    // Receiver -> phone
    ClientHello(ClientHello),
    Auth(Auth),
    Start(Start),
    RequestKeyframe,
    Ping([u8; 8]),
    ClientBye(Bye),
    AuthConfirm(AuthConfirm),
    TouchGesture(TouchGesture),
    GlobalAction(GlobalAction),
    Text(String),
    Key(Key),
    Scroll(Scroll),
    TouchLive(TouchLive),
    /// A type this version does not understand (including reserved audio
    /// types). Re-encodes byte-for-byte except `pts_us`, which is 0.
    Unknown {
        ty: u8,
        flags: u8,
        payload: Vec<u8>,
    },
}

/// Any JSON value: a `u32` number as itself, anything else as 0 (never a
/// valid version).
fn lenient_proto<'de, D: serde::Deserializer<'de>>(d: D) -> Result<u32, D::Error> {
    let v = serde_json::Value::deserialize(d)?;
    Ok(v.as_u64().and_then(|n| u32::try_from(n).ok()).unwrap_or(0))
}

fn json<T: Serialize>(v: &T) -> Vec<u8> {
    // Serialising these plain structs cannot fail.
    serde_json::to_vec(v).expect("JSON serialisation of protocol struct")
}

fn from_json<'a, T: Deserialize<'a>>(t: u8, p: &'a [u8]) -> Result<T, ProtocolError> {
    serde_json::from_slice(p).map_err(|e| ProtocolError::malformed(t, e.to_string()))
}

fn need(t: u8, p: &[u8], n: usize) -> Result<(), ProtocolError> {
    if p.len() < n {
        Err(ProtocolError::malformed(
            t,
            format!("payload {} bytes, need at least {n}", p.len()),
        ))
    } else {
        Ok(())
    }
}

fn be16(p: &[u8], o: usize) -> u16 {
    u16::from_be_bytes([p[o], p[o + 1]])
}

fn opaque8(t: u8, p: &[u8]) -> Result<[u8; 8], ProtocolError> {
    p.try_into()
        .map_err(|_| ProtocolError::malformed(t, format!("expected 8 bytes, got {}", p.len())))
}

impl Message {
    /// Wire type code.
    pub fn ty(&self) -> u8 {
        match self {
            Message::ServerHello(_) => ty::SERVER_HELLO,
            Message::AuthResult(_) => ty::AUTH_RESULT,
            Message::VideoConfig(_) => ty::VIDEO_CONFIG,
            Message::VideoFrame(_) => ty::VIDEO_FRAME,
            Message::Status(_) => ty::STATUS,
            Message::Pong(_) => ty::PONG,
            Message::ServerBye(_) => ty::SERVER_BYE,
            Message::PakeReply(_) => ty::PAKE_REPLY,
            Message::ClientHello(_) => ty::CLIENT_HELLO,
            Message::Auth(_) => ty::AUTH,
            Message::Start(_) => ty::START,
            Message::RequestKeyframe => ty::REQUEST_KEYFRAME,
            Message::Ping(_) => ty::PING,
            Message::ClientBye(_) => ty::CLIENT_BYE,
            Message::AuthConfirm(_) => ty::AUTH_CONFIRM,
            Message::TouchGesture(_) => ty::TOUCH_GESTURE,
            Message::GlobalAction(_) => ty::GLOBAL_ACTION,
            Message::Text(_) => ty::TEXT,
            Message::Key(_) => ty::KEY,
            Message::Scroll(_) => ty::SCROLL,
            Message::TouchLive(_) => ty::TOUCH_LIVE,
            Message::Unknown { ty, .. } => *ty,
        }
    }

    /// Header flags this message is sent with.
    pub fn flags(&self) -> u8 {
        match self {
            Message::VideoConfig(_) => flags::CONFIG,
            Message::VideoFrame(f) => f.flags,
            Message::Unknown { flags, .. } => *flags,
            _ => 0,
        }
    }

    /// Header `pts_us` (non-zero only for VIDEO_FRAME).
    pub fn pts_us(&self) -> u64 {
        match self {
            Message::VideoFrame(f) => f.pts_us,
            _ => 0,
        }
    }

    /// Serialise the payload (without header).
    pub fn encode_payload(&self) -> Vec<u8> {
        self.payload().into_owned()
    }

    /// The payload, borrowed where it is already stored as bytes so that
    /// encoding a video frame does not copy it twice.
    pub(crate) fn payload(&self) -> Cow<'_, [u8]> {
        Cow::Owned(match self {
            Message::VideoFrame(f) => return Cow::Borrowed(&f.data),
            Message::Text(s) => return Cow::Borrowed(s.as_bytes()),
            Message::Unknown { payload, .. } => return Cow::Borrowed(payload),
            Message::ServerHello(m) => json(m),
            Message::AuthResult(m) => json(m),
            Message::Status(m) => json(m),
            Message::ServerBye(m) | Message::ClientBye(m) => json(m),
            Message::ClientHello(m) => json(m),
            Message::Auth(m) => json(m),
            Message::Start(m) => json(m),
            Message::PakeReply(m) => json(m),
            Message::AuthConfirm(m) => json(m),
            Message::VideoConfig(c) => {
                let mut v = Vec::with_capacity(12 + c.sps_pps.len());
                v.extend_from_slice(&c.width.to_be_bytes());
                v.extend_from_slice(&c.height.to_be_bytes());
                v.extend_from_slice(&c.display_width.to_be_bytes());
                v.extend_from_slice(&c.display_height.to_be_bytes());
                v.push(c.rotation);
                v.extend_from_slice(&[0, 0, 0]);
                v.extend_from_slice(&c.sps_pps);
                v
            }
            Message::Pong(b) | Message::Ping(b) => b.to_vec(),
            Message::RequestKeyframe => Vec::new(),
            Message::TouchGesture(g) => {
                let n = g.points.len().min(MAX_GESTURE_POINTS);
                let mut v = Vec::with_capacity(4 + 6 * n);
                v.push(g.kind.to_u8());
                v.push(n as u8);
                v.extend_from_slice(&[0, 0]);
                for p in &g.points[..n] {
                    v.extend_from_slice(&p.x.to_be_bytes());
                    v.extend_from_slice(&p.y.to_be_bytes());
                    v.extend_from_slice(&p.dt_ms.to_be_bytes());
                }
                v
            }
            Message::GlobalAction(a) => vec![a.to_u8()],
            Message::Key(k) => vec![k.to_u8()],
            Message::Scroll(s) => {
                let mut v = Vec::with_capacity(8);
                v.extend_from_slice(&s.x.to_be_bytes());
                v.extend_from_slice(&s.y.to_be_bytes());
                v.extend_from_slice(&s.dx.to_be_bytes());
                v.extend_from_slice(&s.dy.to_be_bytes());
                v
            }
            Message::TouchLive(t) => {
                let mut v = Vec::with_capacity(6);
                v.push(t.phase.to_u8());
                v.push(0);
                v.extend_from_slice(&t.x.to_be_bytes());
                v.extend_from_slice(&t.y.to_be_bytes());
                v
            }
        })
    }

    /// Build a message from a parsed header and its full payload.
    ///
    /// Fixed-layout binary payloads may carry trailing bytes (ignored, for
    /// forward compatibility); PING/PONG must be exactly 8 bytes.
    pub fn decode_frame(h: &Header, p: &[u8]) -> Result<Message, ProtocolError> {
        let t = h.ty;
        Ok(match t {
            ty::SERVER_HELLO => Message::ServerHello(from_json(t, p)?),
            ty::AUTH_RESULT => Message::AuthResult(from_json(t, p)?),
            ty::STATUS => Message::Status(from_json(t, p)?),
            ty::SERVER_BYE => Message::ServerBye(from_json(t, p)?),
            ty::CLIENT_HELLO => Message::ClientHello(from_json(t, p)?),
            ty::AUTH => Message::Auth(from_json(t, p)?),
            ty::START => {
                if p.iter().all(u8::is_ascii_whitespace) {
                    Message::Start(Start::default())
                } else {
                    Message::Start(from_json(t, p)?)
                }
            }
            ty::CLIENT_BYE => Message::ClientBye(from_json(t, p)?),
            ty::PAKE_REPLY => Message::PakeReply(from_json(t, p)?),
            ty::AUTH_CONFIRM => Message::AuthConfirm(from_json(t, p)?),
            ty::VIDEO_CONFIG => {
                need(t, p, 12)?;
                Message::VideoConfig(VideoConfig {
                    width: be16(p, 0),
                    height: be16(p, 2),
                    display_width: be16(p, 4),
                    display_height: be16(p, 6),
                    rotation: p[8],
                    sps_pps: p[12..].to_vec(),
                })
            }
            ty::VIDEO_FRAME => Message::VideoFrame(VideoFrame {
                pts_us: h.pts_us,
                flags: h.flags,
                data: p.to_vec(),
            }),
            ty::PONG => Message::Pong(opaque8(t, p)?),
            ty::PING => Message::Ping(opaque8(t, p)?),
            ty::REQUEST_KEYFRAME => Message::RequestKeyframe,
            ty::TOUCH_GESTURE => {
                need(t, p, 4)?;
                let n = p[1] as usize;
                need(t, p, 4 + 6 * n)?;
                let points = (0..n)
                    .map(|i| {
                        let o = 4 + 6 * i;
                        GesturePoint {
                            x: be16(p, o),
                            y: be16(p, o + 2),
                            dt_ms: be16(p, o + 4),
                        }
                    })
                    .collect();
                Message::TouchGesture(TouchGesture {
                    kind: GestureKind::from_u8(p[0]),
                    points,
                })
            }
            ty::GLOBAL_ACTION => {
                need(t, p, 1)?;
                Message::GlobalAction(GlobalAction::from_u8(p[0]))
            }
            ty::TEXT => Message::Text(String::from_utf8(p.to_vec()).map_err(|e| {
                // Typed text may be a password: wipe the rejected copy too.
                let msg = e.to_string();
                zeroize::Zeroize::zeroize(&mut e.into_bytes());
                ProtocolError::malformed(t, msg)
            })?),
            ty::KEY => {
                need(t, p, 1)?;
                Message::Key(Key::from_u8(p[0]))
            }
            ty::SCROLL => {
                need(t, p, 8)?;
                Message::Scroll(Scroll {
                    x: be16(p, 0),
                    y: be16(p, 2),
                    dx: be16(p, 4) as i16,
                    dy: be16(p, 6) as i16,
                })
            }
            ty::TOUCH_LIVE => {
                need(t, p, 6)?;
                Message::TouchLive(TouchLive {
                    phase: TouchPhase::from_u8(p[0]),
                    x: be16(p, 2),
                    y: be16(p, 4),
                })
            }
            _ => Message::Unknown {
                ty: t,
                flags: h.flags,
                payload: p.to_vec(),
            },
        })
    }
}
