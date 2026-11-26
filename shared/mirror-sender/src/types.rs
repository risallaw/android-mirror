//! Public types and the host-facing traits ([`VideoSource`], [`ControlSink`],
//! [`HostEvents`]).

use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;

use mirror_protocol::geometry::DEFAULT_MAX_LONG_EDGE;
use mirror_protocol::{AuthMode, GestureKind, GlobalAction, Key, Start, TouchPhase};

use crate::pairing::PairedClient;
use crate::sink::FrameSink;

/// Boxed error type returned by host implementations.
pub type SourceError = Box<dyn std::error::Error + Send + Sync + 'static>;

// ---------------------------------------------------------------------------
// Stream parameters
// ---------------------------------------------------------------------------

/// Default cap on the encoded long edge, pixels.
pub const DEFAULT_LONG_EDGE: u32 = DEFAULT_MAX_LONG_EDGE;
/// Frame-rate cap used when START omits `maxFps` (a cap, not a target: the
/// source may produce fewer frames, e.g. on a static screen). START may ask
/// for any value; it is clamped to [`FPS_RANGE`].
pub const DEFAULT_MAX_FPS: u32 = 60;
/// Accepted frame-rate range for START (values outside are clamped).
pub const FPS_RANGE: (u32, u32) = (1, 120);
/// Accepted bitrate range for START, bits per second (PLAN §4: 2–20 Mbps).
pub const BITRATE_RANGE: (u32, u32) = (2_000_000, 20_000_000);
/// Smallest accepted non-zero `maxLongEdge`; smaller requests are raised to
/// it. Below this, rounding both edges to whole macroblocks squashes the
/// picture and hardware encoders reject the size (a 20:9 phone encodes at
/// 144×320 here).
pub const MIN_LONG_EDGE: u32 = 320;

/// Encoder parameters for one client connection, derived from START.
///
/// Every field is already validated/clamped; a [`VideoSource`] can use them
/// as-is (it may still lower them, e.g. on a configure-ladder fallback).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamParams {
    /// Cap on the encoded long edge in pixels; `0` = no cap (native size).
    /// Default [`DEFAULT_LONG_EDGE`] (1920). Non-zero values are at least
    /// [`MIN_LONG_EDGE`]. Feed into `mirror_protocol::geometry::encode_size`.
    pub max_long_edge: u32,
    /// Maximum frame rate, clamped to [`FPS_RANGE`]. Default 60.
    pub max_fps: u32,
    /// Target bitrate in bits per second, clamped to [`BITRATE_RANGE`].
    /// Default: 8 Mbps when the long edge cap is > 1280 (or uncapped),
    /// 4 Mbps otherwise (PLAN §4).
    pub bitrate: u32,
}

impl Default for StreamParams {
    fn default() -> Self {
        StreamParams::from_start(&Start::default())
    }
}

impl StreamParams {
    /// Default bitrate for a long-edge cap (PLAN §4).
    pub fn default_bitrate(max_long_edge: u32) -> u32 {
        if max_long_edge == 0 || max_long_edge > 1280 {
            8_000_000
        } else {
            4_000_000
        }
    }

    /// Apply defaults and clamps to a START message.
    pub fn from_start(s: &Start) -> Self {
        let max_long_edge = match s.max_long_edge.unwrap_or(DEFAULT_LONG_EDGE) {
            0 => 0,
            v => v.max(MIN_LONG_EDGE),
        };
        let max_fps = s
            .max_fps
            .unwrap_or(DEFAULT_MAX_FPS)
            .clamp(FPS_RANGE.0, FPS_RANGE.1);
        let bitrate = s
            .bitrate
            .unwrap_or_else(|| Self::default_bitrate(max_long_edge))
            .clamp(BITRATE_RANGE.0, BITRATE_RANGE.1);
        StreamParams {
            max_long_edge,
            max_fps,
            bitrate,
        }
    }
}

// ---------------------------------------------------------------------------
// Video
// ---------------------------------------------------------------------------

/// One encoded H.264 access unit produced by a [`VideoSource`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedFrame {
    /// Presentation timestamp, microseconds (any monotonic origin).
    pub pts_us: u64,
    /// True for IDR access units.
    pub keyframe: bool,
    /// Annex-B access unit (start codes included).
    pub data: Vec<u8>,
}

/// Produces encoded video for one client connection at a time.
///
/// Lifetime: the server calls [`start`](VideoSource::start) when an
/// authenticated client sends START and [`stop`](VideoSource::stop) when that
/// client goes away (or before starting for a newer client). Calls to
/// `start`/`stop` are serialised by the server; if `start` returns an error,
/// `stop` is still called once so a partial start can be cleaned up.
///
/// After `start`, the source pushes into the given [`FrameSink`] from its own
/// thread: first a `VideoConfig` (SPS+PPS), then an IDR frame, then frames.
/// On a geometry change it pushes a new config followed by an IDR.
///
/// Threading rules for implementors:
/// - All methods take `&self`; use interior synchronisation.
/// - [`request_keyframe`](VideoSource::request_keyframe) may be called from
///   any thread, **including from inside a `FrameSink` call made by the
///   source's own thread** (backpressure resync). It must not block and must
///   not call back into the sink.
/// - [`stop`](VideoSource::stop) should stop pushing and release the encoder
///   before returning. Pushes into a sink after its session ended are ignored,
///   so a late push is harmless.
pub trait VideoSource: Send + Sync {
    fn start(&self, params: StreamParams, sink: FrameSink) -> Result<(), SourceError>;
    fn request_keyframe(&self);
    fn stop(&self);
}

// ---------------------------------------------------------------------------
// Control
// ---------------------------------------------------------------------------

/// One gesture point mapped to display pixels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PixelPoint {
    pub x: u32,
    pub y: u32,
    /// Delay since the previous point, ms (0 for the first).
    pub dt_ms: u16,
}

/// Receives input from the receiver (Phase 2). Coordinates are already
/// mapped from the normalised wire range to display pixels using the
/// `displayWidth`/`displayHeight` of the latest VIDEO_CONFIG.
///
/// Called on the session's reader thread; implementations should hand work
/// off quickly and must not call [`Server::stop`](crate::Server::stop).
/// Only called for sessions authenticated with `pin`/`token`, and only
/// while the host has said control is available
/// ([`Server::set_control_available`](crate::Server::set_control_available)).
/// All methods default to no-ops.
pub trait ControlSink: Send + Sync {
    fn gesture(&self, _kind: GestureKind, _points: &[PixelPoint]) {}
    fn touch_live(&self, _phase: TouchPhase, _x: u32, _y: u32) {}
    /// Swipe from (`x`, `y`) by (`dx`, `dy`), all in display pixels; `dx`,
    /// `dy` are the signed finger-drag distance (positive `dy` = finger
    /// moves down).
    fn scroll(&self, _x: u32, _y: u32, _dx: i32, _dy: i32) {}
    fn global_action(&self, _action: GlobalAction) {}
    fn text(&self, _text: &str) {}
    fn key(&self, _key: Key) {}
}

/// A [`ControlSink`] that ignores everything.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoControl;
impl ControlSink for NoControl {}

// ---------------------------------------------------------------------------
// Host events
// ---------------------------------------------------------------------------

/// The authenticated client a state change refers to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientInfo {
    /// Server-assigned connection id (unique per `Server`).
    pub session_id: u64,
    pub peer: SocketAddr,
    /// `clientName` from CLIENT_HELLO.
    pub name: String,
    /// `clientId` from CLIENT_HELLO.
    pub id: String,
    /// How the session authenticated: `Pin` (paired just now), `Token`
    /// (previously paired) or `NoAuth` (only with `allow_no_auth`; never
    /// gets control).
    pub auth: AuthMode,
}

/// Why a client session ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisconnectReason {
    /// The client sent BYE.
    ClientBye,
    /// A newer authenticated client took over.
    Replaced,
    /// Nothing received for the liveness timeout.
    Timeout,
    /// The peer closed the connection or a socket error occurred.
    Closed,
    /// The peer sent something the protocol does not allow.
    ProtocolError,
    /// [`Server::disconnect`](crate::Server::disconnect) or
    /// [`Server::stop`](crate::Server::stop).
    Server,
    /// The video source failed to start, or ended the session through
    /// [`FrameSink::fail`].
    SourceFailed,
}

/// Client lifecycle as reported to [`HostEvents`]. Only authenticated
/// clients are reported; connections that fail the handshake are only logged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientState {
    /// Authenticated; waiting for START.
    Connecting,
    /// START received and the video source started.
    Streaming,
    /// The session ended.
    Disconnected(DisconnectReason),
}

/// Non-fatal problems the host may want to surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostError {
    /// `VideoSource::start` failed; the client was disconnected.
    SourceStart(String),
    /// `accept()` failed (e.g. out of file descriptors); the server keeps
    /// trying.
    Accept(String),
    /// A session thread could not be spawned; the connection was dropped.
    Spawn(String),
    /// A pairing change (new pairing, revoke) could not be written to the
    /// pairing store; it holds in memory until the server stops.
    PairingStore(String),
}

impl fmt::Display for HostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HostError::SourceStart(e) => write!(f, "video source failed to start: {e}"),
            HostError::Accept(e) => write!(f, "accept failed: {e}"),
            HostError::Spawn(e) => write!(f, "could not spawn session thread: {e}"),
            HostError::PairingStore(e) => write!(f, "pairing store not saved: {e}"),
        }
    }
}

impl std::error::Error for HostError {}

/// Notifications to the host app (UI, notification, Wi-Fi lock).
///
/// Called from server threads (accept/session); must not block for long and
/// must not call [`Server::stop`](crate::Server::stop) (it joins the calling
/// thread). Default impls do nothing.
pub trait HostEvents: Send + Sync {
    fn client_state(&self, _state: ClientState, _client: &ClientInfo) {}
    fn error(&self, _err: &HostError) {}
    /// The PIN changed (after a pairing or a lockout); show the new one.
    /// The initial PIN is [`Server::pin`](crate::Server::pin). The upcall
    /// can race the host's own [`Server::new_pin`](crate::Server::new_pin)
    /// (the server skips it when it sees the race, but cannot close it), so
    /// a host should show [`Server::pin`](crate::Server::pin) when it
    /// applies the change rather than trust `pin` blindly.
    fn pin_changed(&self, _pin: &str) {}
    /// A receiver paired with the PIN (its key is stored).
    fn paired(&self, _client: &PairedClient) {}
    /// A PIN attempt from `peer` failed (wrong PIN or abandoned), or was
    /// refused during a lockout. `locked_for` is `Some` while PIN
    /// attempts are refused.
    fn pairing_failed(
        &self,
        _peer: SocketAddr,
        _attempts_left: u32,
        _locked_for: Option<Duration>,
    ) {
    }
    /// [`pairing_failed`](Self::pairing_failed) with the "New PIN" count
    /// ([`Server::pin_resets`](crate::Server::pin_resets)) the failure was
    /// counted under. The server drops a failure that predates a "New PIN"
    /// it can see, but the reset can still land between that check and this
    /// upcall: a host that applies "New PIN" results should drop a failure
    /// whose `resets` is below the count it last applied. The default
    /// forwards to `pairing_failed`.
    fn pairing_failed_at(
        &self,
        peer: SocketAddr,
        attempts_left: u32,
        locked_for: Option<Duration>,
        _resets: u64,
    ) {
        self.pairing_failed(peer, attempts_left, locked_for);
    }
}

/// A [`HostEvents`] that ignores everything.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoEvents;
impl HostEvents for NoEvents {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn params_defaults() {
        let p = StreamParams::default();
        assert_eq!(
            p,
            StreamParams {
                max_long_edge: 1920,
                max_fps: 60,
                bitrate: 8_000_000
            }
        );
    }

    #[test]
    fn params_clamps() {
        let p = StreamParams::from_start(&Start {
            max_long_edge: Some(1280),
            max_fps: Some(0),
            bitrate: None,
        });
        assert_eq!(
            (p.max_long_edge, p.max_fps, p.bitrate),
            (1280, 1, 4_000_000)
        );
        let p = StreamParams::from_start(&Start {
            max_long_edge: Some(3),
            max_fps: Some(1000),
            bitrate: Some(u32::MAX),
        });
        assert_eq!(
            (p.max_long_edge, p.max_fps, p.bitrate),
            (MIN_LONG_EDGE, 120, 20_000_000)
        );
        let p = StreamParams::from_start(&Start {
            max_long_edge: Some(319),
            max_fps: None,
            bitrate: None,
        });
        assert_eq!((p.max_long_edge, p.bitrate), (320, 4_000_000));
        let p = StreamParams::from_start(&Start {
            max_long_edge: Some(0),
            max_fps: None,
            bitrate: Some(1),
        });
        assert_eq!((p.max_long_edge, p.max_fps, p.bitrate), (0, 60, 2_000_000));
    }
}
