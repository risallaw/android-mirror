//! Receiver-side network client (PLAN.md §5, PROTOCOL.md "Session sequence").
//!
//! [`Client::connect`] performs the whole v2 handshake synchronously on the
//! caller's thread (magic → CLIENT_HELLO → SERVER_HELLO → AUTH → [PAKE_REPLY →
//! AUTH_CONFIRM →] AUTH_RESULT → START) and, on success, spawns two threads:
//!
//! - **reader**: blocking reads with a short timeout tick, feeds the record
//!   [`Opener`], turns messages into [`ClientEvent`]s and enforces liveness
//!   (no bytes for [`Timeouts::liveness`] → disconnect).
//! - **writer**: drains a small bounded command queue, seals each message
//!   with the [`Sealer`] and sends a PING every [`Timeouts::ping_interval`].
//!   The PING payload is the send time (µs since the client's epoch,
//!   big-endian), so the PONG echo yields the RTT. Only an echo of one of
//!   the last few PINGs counts, once, so a phone cannot report a made-up
//!   RTT.
//!
//! Whichever side detects the end first records a [`DisconnectReason`],
//! emits exactly one [`ClientEvent::Disconnected`], and shuts the socket down
//! so the other thread wakes. Events go out on a bounded crossbeam channel;
//! when it is full the reader blocks (TCP backpressure to the phone) but
//! still notices [`Client::close`].
//!
//! # Credentials
//!
//! Chosen after SERVER_HELLO, in this order (spec §3):
//!
//! 1. `pin` — [`ClientConfig::pin`] is set and the phone offers `pin`
//!    (pairing; on success the new key replaces any stored one and
//!    [`ClientEvent::Paired`] follows `Connected`). An explicit PIN wins
//!    over a stored key so the user can re-pair after the phone refused
//!    that key (which is kept, see [`DisconnectReason::PairingRemoved`]);
//! 2. `token` — a pairing key is stored in [`ClientConfig::store`] for the
//!    phone's `deviceId` and the phone offers `token`;
//! 3. `none` — only with [`ClientConfig::allow_no_auth`] (devtools/tests)
//!    and only if offered;
//! 4. otherwise no AUTH is sent: the connection is closed with
//!    [`DisconnectReason::NeedsPin`] (the phone offers `pin`; ask the user and
//!    connect again with the PIN) or [`DisconnectReason::AuthUnsupported`].
//!
//! **Who persists pairings:** the client, through the shared
//! [`Store`] in its config. That is the only place that
//! knows the key at the right moment, and the reconnect supervisor's next
//! attempt must already find it there. The UI only ever sees device ids and
//! names (never key material) and calls
//! [`Store::remove_pairing`](crate::store::Store::remove_pairing) for
//! "Forget device".
//!
//! Every auth outcome ([`DisconnectReason::is_auth_outcome`]) is final for
//! the reconnect supervisor.

use std::fmt;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crossbeam_channel::{bounded, select, Receiver, Sender, TrySendError};
use mirror_protocol::auth::PIN_DIGITS;
use mirror_protocol::handshake::{
    ClientCredential, ClientHandshake, ClientStep, Established, HandshakeError,
};
use mirror_protocol::secure::{Opener, Sealer};
use mirror_protocol::wire::HEADER_LEN;
use mirror_protocol::{
    encode, AuthMode, AuthReason, Bye, ByeReason, Decoder, Message, ProtocolError, ServerHello,
    Start, StatusState, VideoConfig, VideoFrame, MAGIC, MAX_CLIENT_PAYLOAD, PROTO_VERSION,
};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use zeroize::Zeroizing;

use crate::store::{now_ms, PairedDevice, Store};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Timeouts and intervals. Defaults follow PLAN.md §6; tests shrink them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timeouts {
    /// TCP connect.
    pub connect: Duration,
    /// Whole handshake, from TCP connected to AUTH_RESULT received.
    pub handshake: Duration,
    /// PING period.
    pub ping_interval: Duration,
    /// Disconnect after this long without receiving any byte. Also bounds a
    /// single blocked socket write.
    pub liveness: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Timeouts {
            connect: Duration::from_secs(3),
            handshake: Duration::from_secs(5),
            ping_interval: Duration::from_secs(2),
            liveness: Duration::from_secs(6),
        }
    }
}

/// Everything [`Client::connect`] needs besides the address. `Debug` never
/// shows the PIN.
#[derive(Clone)]
pub struct ClientConfig {
    /// Human-readable receiver name shown on the phone (`clientName`).
    pub client_name: String,
    /// Stable receiver id (`clientId`); the phone keys pairings by it.
    pub client_id: String,
    /// Pairing keys by `deviceId`: read for `token` auth, written (replacing
    /// any old key) when a PIN pairing succeeds. Never deleted by the client:
    /// a refusal is unauthenticated, so a rejected key is kept (see
    /// [`DisconnectReason::PairingRemoved`]). Defaults to an empty in-memory
    /// store.
    pub store: Store,
    /// The 6-digit PIN shown on the phone, for this connect (pairing). When
    /// set and the phone offers `pin`, it wins over a stored key (re-pairing).
    /// The supervisor sends it at most once (dropped once an AUTH carried it,
    /// or after any successful handshake). Wiped on drop, like every copy.
    pub pin: Option<Zeroizing<String>>,
    /// Permit auth mode `none` (unauthenticated but still encrypted; the
    /// phone refuses control). Devtools/tests only; `false` by default.
    pub allow_no_auth: bool,
    /// START parameters; every field optional (`None` = sender default).
    pub start: Start,
    pub timeouts: Timeouts,
    /// Capacity of the event channel (frames block the reader when full).
    pub event_capacity: usize,
    /// Capacity of the outgoing command queue ([`Client::send`]).
    pub send_capacity: usize,
}

impl fmt::Debug for ClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientConfig")
            .field("client_name", &self.client_name)
            .field("client_id", &self.client_id)
            .field("store", &self.store)
            .field("pin", &self.pin.as_ref().map(|_| "<redacted>"))
            .field("allow_no_auth", &self.allow_no_auth)
            .field("start", &self.start)
            .field("timeouts", &self.timeouts)
            .field("event_capacity", &self.event_capacity)
            .field("send_capacity", &self.send_capacity)
            .finish()
    }
}

impl ClientConfig {
    pub fn new(client_name: impl Into<String>, client_id: impl Into<String>) -> Self {
        ClientConfig {
            client_name: client_name.into(),
            client_id: client_id.into(),
            store: Store::default(),
            pin: None,
            allow_no_auth: false,
            start: Start::default(),
            timeouts: Timeouts::default(),
            // Frames can be MAX_PAYLOAD (8 MiB) each, so this bounds queued
            // memory (128 MiB worst case) and receiver-side lag (~270 ms at
            // 60 fps, in line with the sender's 250 ms backpressure budget,
            // PLAN.md §6): beyond it TCP backpressure lets the sender resync.
            event_capacity: 16,
            send_capacity: 32,
        }
    }
}

/// Longest `clientName` the phone keeps, in UTF-8 bytes.
pub const MAX_CLIENT_NAME_BYTES: usize = 256;

/// `name` cut to [`MAX_CLIENT_NAME_BYTES`] on a character boundary: the
/// phone truncates a longer one anyway, and a computer name can be anything.
fn fit_client_name(name: &str) -> &str {
    &name[..name.floor_char_boundary(MAX_CLIENT_NAME_BYTES)]
}

/// True for a well-formed pairing PIN (exactly 6 ASCII digits). The client
/// refuses anything else locally ([`DisconnectReason::WrongPin`]) rather
/// than burn one of the phone's limited attempts on it.
pub fn is_valid_pin(pin: &str) -> bool {
    pin.len() == PIN_DIGITS && pin.bytes().all(|b| b.is_ascii_digit())
}

// ---------------------------------------------------------------------------
// Events and reasons
// ---------------------------------------------------------------------------

/// Which deadline expired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeoutKind {
    Connect,
    Handshake,
    /// No bytes received for [`Timeouts::liveness`].
    Liveness,
}

/// Why a connection ended (or never got going). Also the error type of
/// [`Client::connect`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisconnectReason {
    /// [`Client::close`] (or drop) on this side.
    Closed,
    /// The server sent BYE.
    Bye(ByeReason),
    /// The peer closed the TCP connection without BYE.
    ConnectionClosed,
    Timeout(TimeoutKind),
    /// Socket error (connect refused, reset, write failure, ...).
    Io {
        kind: io::ErrorKind,
        message: String,
    },
    /// Undecodable stream (bad magic, oversize frame, a record that fails
    /// authentication) or a message that is not allowed at this point of the
    /// session. Retryable: a fresh connection starts a fresh channel.
    Protocol(String),
    /// The server speaks another protocol version.
    ProtoMismatch {
        ours: u32,
        theirs: u32,
    },

    // --- Auth outcomes: final, never retried by the supervisor. ---
    /// No stored key for this phone and no PIN supplied: no AUTH was sent.
    /// Ask the user for the PIN shown on the phone and connect again with
    /// [`ClientConfig::pin`].
    NeedsPin {
        device_id: String,
        device_name: String,
    },
    /// The PIN was wrong (the phone's confirmation did not verify, or the
    /// phone refused ours), or it was not 6 digits. Each wrong PIN counts
    /// toward the phone's lockout.
    WrongPin,
    /// Too many wrong PINs; the phone accepts PIN attempts again after
    /// `retry_after`.
    LockedOut {
        retry_after: Duration,
    },
    /// The phone no longer accepts our stored key (it was revoked on the
    /// phone, or the phone lost its pairings); pairing again with a PIN is
    /// required. The key is kept (the refusal is unauthenticated, so it
    /// must not be able to unpair us); a successful PIN pairing replaces it.
    PairingRemoved {
        device_id: String,
    },
    /// Token mode: the phone could not prove it holds our pairing key. It is
    /// not the phone we paired with (or someone is in the middle). The key
    /// is kept: an impostor must not be able to unpair us.
    IdentityChanged {
        device_id: String,
    },
    /// The phone offers no auth mode this client may use (e.g. only `none`
    /// while [`ClientConfig::allow_no_auth`] is off).
    AuthUnsupported {
        offered: Vec<AuthMode>,
    },
    /// Any other refusal (AUTH_RESULT `ok:false` with `mode_unsupported` /
    /// an unknown reason, or BYE `auth_failed` during the handshake).
    AuthFailed {
        reason: Option<AuthReason>,
    },
}

impl DisconnectReason {
    fn io(e: &io::Error) -> Self {
        DisconnectReason::Io {
            kind: e.kind(),
            message: e.to_string(),
        }
    }

    /// True for the results of authentication (pairing required, wrong PIN,
    /// lockout, rejected key, ...). These are final: retrying cannot fix them
    /// and PIN failures count toward the phone's lockout.
    pub fn is_auth_outcome(&self) -> bool {
        use DisconnectReason::*;
        matches!(
            self,
            NeedsPin { .. }
                | WrongPin
                | LockedOut { .. }
                | PairingRemoved { .. }
                | IdentityChanged { .. }
                | AuthUnsupported { .. }
                | AuthFailed { .. }
        )
    }
}

impl fmt::Display for DisconnectReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use DisconnectReason::*;
        match self {
            Closed => write!(f, "closed locally"),
            Bye(r) => write!(f, "server said goodbye: {r:?}"),
            ConnectionClosed => write!(f, "connection closed by the phone"),
            Timeout(TimeoutKind::Connect) => write!(f, "connect timed out"),
            Timeout(TimeoutKind::Handshake) => write!(f, "handshake timed out"),
            Timeout(TimeoutKind::Liveness) => write!(f, "phone stopped responding"),
            Io { message, .. } => write!(f, "network error: {message}"),
            Protocol(m) => write!(f, "protocol error: {m}"),
            ProtoMismatch { ours, theirs } => write!(
                f,
                "protocol version mismatch: receiver speaks v{ours}, phone v{theirs}"
            ),
            NeedsPin { device_name, .. } => {
                write!(f, "pairing required: enter the PIN shown on {device_name}")
            }
            WrongPin => write!(f, "wrong PIN"),
            LockedOut { retry_after } => write!(
                f,
                "too many wrong PINs; try again in {} s",
                retry_after.as_millis().div_ceil(1000)
            ),
            PairingRemoved { .. } => {
                write!(f, "the phone no longer knows this receiver; pair again")
            }
            IdentityChanged { .. } => write!(
                f,
                "device identity changed: the phone could not prove it is the paired device"
            ),
            AuthUnsupported { offered } => {
                write!(f, "phone offers no usable auth mode (offers {offered:?})")
            }
            AuthFailed { reason: Some(r) } => write!(f, "authentication failed: {r:?}"),
            AuthFailed { reason: None } => write!(f, "authentication failed"),
        }
    }
}

impl std::error::Error for DisconnectReason {}

/// Everything the client (and the reconnect supervisor) reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientEvent {
    /// Handshake complete; always the first event of a connection.
    Connected {
        addr: SocketAddr,
        server: ServerHello,
        /// How this session authenticated. Control needs `Pin`/`Token`.
        auth: AuthMode,
    },
    /// PIN pairing succeeded; right after `Connected`. The key is in the
    /// [`ClientConfig::store`] for this run either way.
    Paired {
        device_id: String,
        device_name: String,
        /// `Some(why)` when the key could not be saved to disk: the next app
        /// start will need the PIN again. Show it to the user.
        save_error: Option<String>,
    },
    VideoConfig(VideoConfig),
    VideoFrame(VideoFrame),
    /// Every STATUS. `ControlAvailable` / `ControlUnavailable` also update
    /// [`Client::control_available`].
    Status(StatusState),
    /// Round-trip time from the latest PONG.
    Rtt(Duration),
    /// The connection ended; exactly once per connection, always last.
    Disconnected(DisconnectReason),
    /// Supervisor only: waiting `delay` before reconnect attempt `attempt`
    /// (1-based).
    Reconnecting {
        attempt: u32,
        delay: Duration,
    },
    /// Supervisor only: the reconnect budget ran out. Final event.
    GaveUp {
        attempts: u32,
        last: DisconnectReason,
    },
    /// Supervisor only: stopped without (further) retrying, because the
    /// reason is not retryable (e.g. any auth outcome) or the supervisor was
    /// closed. Final event.
    Stopped(DisconnectReason),
}

/// Why a message was not queued.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendError {
    /// The outgoing queue is full (the link is congested); try again later.
    QueueFull,
    /// The connection has ended (or is being re-established).
    Disconnected,
    /// `send_control`: the session is unauthenticated (`none`) or the phone
    /// has not said `control_available` (Accessibility service off).
    ControlUnavailable,
    /// `send_control`: not an input message.
    NotControl,
    /// The payload exceeds the receiver→phone limit (64 KiB).
    TooLarge,
}

impl fmt::Display for SendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SendError::QueueFull => write!(f, "send queue full"),
            SendError::Disconnected => write!(f, "not connected"),
            SendError::ControlUnavailable => write!(f, "remote control is not available"),
            SendError::NotControl => write!(f, "not a control message"),
            SendError::TooLarge => write!(f, "message too large"),
        }
    }
}

impl std::error::Error for SendError {}

/// True for the receiver→phone input messages (TOUCH_GESTURE .. TOUCH_LIVE).
pub fn is_control_message(msg: &Message) -> bool {
    matches!(
        msg,
        Message::TouchGesture(_)
            | Message::GlobalAction(_)
            | Message::Text(_)
            | Message::Key(_)
            | Message::Scroll(_)
            | Message::TouchLive(_)
    )
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// State shared by the client handle and its two threads.
struct Shared {
    events: Sender<ClientEvent>,
    /// Socket handle used only for `shutdown` (wakes blocked reads/writes).
    stream: TcpStream,
    /// Local close requested: suppresses error reasons, unblocks event sends.
    closing: AtomicBool,
    /// Same as `closing`, but owned by whoever created the client (the
    /// supervisor sets it to stop): it can be raised before this client's
    /// handle is reachable, e.g. while `start` blocks emitting `Connected`.
    cancel: Arc<AtomicBool>,
    finished: AtomicBool,
    /// Carries the final reason to whoever waits (the supervisor).
    done: Sender<DisconnectReason>,
    /// Tells the writer to stop; `Some` = send this BYE first.
    stop: Sender<Option<ByeReason>>,
    epoch: Instant,
    /// Latest RTT in µs; `u64::MAX` = none yet.
    rtt_us: AtomicU64,
    /// Recently sent PING stamps (writer records, reader matches PONGs).
    pings: Mutex<PingLog>,
    /// Held while emitting, so no event can follow `Disconnected` (a reader
    /// emit racing the writer's `finish`).
    emit_lock: Mutex<()>,
    /// How this session authenticated.
    auth: AuthMode,
    /// Latest STATUS control_available (true) / control_unavailable (false).
    control: AtomicBool,
}

impl Shared {
    /// Deliver an event, blocking while the channel is full unless a local
    /// close is in progress. Returns false if the event was dropped, which
    /// includes every event once the connection has finished.
    fn emit(&self, ev: ClientEvent) -> bool {
        let _order = lock(&self.emit_lock);
        !self.is_finished() && self.send_event(ev)
    }

    fn send_event(&self, mut ev: ClientEvent) -> bool {
        loop {
            match self.events.send_timeout(ev, Duration::from_millis(50)) {
                Ok(()) => return true,
                Err(crossbeam_channel::SendTimeoutError::Timeout(e)) => {
                    if self.is_closing() {
                        return false;
                    }
                    ev = e;
                }
                Err(crossbeam_channel::SendTimeoutError::Disconnected(_)) => return false,
            }
        }
    }

    /// End the connection once: record the reason, wake both threads, emit
    /// [`ClientEvent::Disconnected`].
    fn finish(&self, reason: DisconnectReason) {
        if self.finished.swap(true, Ordering::AcqRel) {
            return;
        }
        let reason = if self.is_closing() {
            DisconnectReason::Closed
        } else {
            reason
        };
        let _ = self.stop.try_send(None);
        let _ = self.stream.shutdown(Shutdown::Both);
        // Emit before signalling `done`: the supervisor closes this client as
        // soon as `done` fires, and that close would make a still-blocked
        // emit (full channel, slow consumer) drop `Disconnected`. Under the
        // emit lock: an in-flight emit lands before it, none after.
        {
            let _order = lock(&self.emit_lock);
            self.send_event(ClientEvent::Disconnected(reason.clone()));
        }
        let _ = self.done.try_send(reason);
    }

    fn is_finished(&self) -> bool {
        self.finished.load(Ordering::Acquire)
    }

    fn is_closing(&self) -> bool {
        self.closing.load(Ordering::Acquire) || self.cancel.load(Ordering::Acquire)
    }

    fn now_us(&self) -> u64 {
        u64::try_from(self.epoch.elapsed().as_micros()).unwrap_or(u64::MAX)
    }

    fn control_available(&self) -> bool {
        // Never offer control on an unauthenticated session, whatever the
        // phone says (it refuses it too; this is defence in depth).
        matches!(self.auth, AuthMode::Pin | AuthMode::Token)
            && self.control.load(Ordering::Acquire)
            && !self.is_finished()
    }
}

/// A poisoned lock only means another thread panicked holding it; the
/// guarded data (`()` / plain stamps) is still valid.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// The last few PING stamps sent. A PONG counts only if it echoes one of
/// them, and each only once. Several are kept so an RTT above the PING
/// interval is still measured.
#[derive(Debug, Default)]
struct PingLog {
    sent: [Option<u64>; 4],
    next: usize,
}

impl PingLog {
    fn record(&mut self, stamp: u64) {
        self.sent[self.next] = Some(stamp);
        self.next = (self.next + 1) % self.sent.len();
    }

    /// True (once) if `stamp` is an outstanding PING.
    fn take(&mut self, stamp: u64) -> bool {
        self.sent
            .iter_mut()
            .find(|s| **s == Some(stamp))
            .map(|s| *s = None)
            .is_some()
    }
}

/// Cheap, cloneable send side of a session (used by the supervisor so the
/// UI can send while the supervisor thread owns the [`Client`]).
#[derive(Clone)]
pub(crate) struct Handle {
    shared: Arc<Shared>,
    /// Encoded frames (header + payload); the writer seals them.
    queue: Sender<Vec<u8>>,
}

impl Handle {
    pub(crate) fn send(&self, msg: Message) -> Result<(), SendError> {
        if self.shared.is_finished() {
            return Err(SendError::Disconnected);
        }
        // Encoded once, here: the size check needs the length, and the
        // writer seals these bytes as they are. Checked here so the caller
        // learns about it; the writer's sealer would refuse it anyway.
        let frame = encode(&msg);
        if frame.len() - HEADER_LEN > MAX_CLIENT_PAYLOAD as usize {
            return Err(SendError::TooLarge);
        }
        self.queue.try_send(frame).map_err(|e| match e {
            TrySendError::Full(_) => SendError::QueueFull,
            TrySendError::Disconnected(_) => SendError::Disconnected,
        })
    }

    pub(crate) fn send_control(&self, msg: Message) -> Result<(), SendError> {
        if !is_control_message(&msg) {
            return Err(SendError::NotControl);
        }
        if self.shared.is_finished() {
            return Err(SendError::Disconnected);
        }
        if !self.shared.control_available() {
            return Err(SendError::ControlUnavailable);
        }
        self.send(msg)
    }

    pub(crate) fn control_available(&self) -> bool {
        self.shared.control_available()
    }

    pub(crate) fn rtt(&self) -> Option<Duration> {
        match self.shared.rtt_us.load(Ordering::Relaxed) {
            u64::MAX => None,
            us => Some(Duration::from_micros(us)),
        }
    }

    pub(crate) fn is_finished(&self) -> bool {
        self.shared.is_finished()
    }
}

/// Thread inputs between handshake and [`Client::start`].
struct Pending {
    read_half: TcpStream,
    write_half: TcpStream,
    opener: Opener,
    sealer: Sealer,
    queue: Receiver<Vec<u8>>,
    stop: Receiver<Option<ByeReason>>,
    timeouts: Timeouts,
    /// After a PIN pairing: emitted as [`ClientEvent::Paired`].
    paired: Option<Pairing>,
}

/// A connected, authenticated session. Dropping it closes it (BYE + join).
pub struct Client {
    handle: Handle,
    events: Receiver<ClientEvent>,
    done: Receiver<DisconnectReason>,
    server: ServerHello,
    addr: SocketAddr,
    pending: Option<Pending>,
    reader: Option<JoinHandle<()>>,
    writer: Option<JoinHandle<()>>,
    /// Disconnects when the writer thread exits (see [`Client::close`]).
    writer_exited: Option<Receiver<()>>,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("addr", &self.addr)
            .field("device_id", &self.server.device_id)
            .field("auth", &self.handle.shared.auth)
            .field("finished", &self.handle.is_finished())
            .finish()
    }
}

impl Client {
    /// Connect, handshake and start streaming. Blocks for at most
    /// `timeouts.connect + timeouts.handshake`. On success the first event on
    /// [`events`](Self::events) is [`ClientEvent::Connected`].
    pub fn connect(addr: SocketAddr, config: ClientConfig) -> Result<Client, DisconnectReason> {
        let (tx, rx) = bounded(config.event_capacity.max(1));
        let cancel = Arc::new(AtomicBool::new(false));
        let mut client = Self::establish(addr, config, tx, rx, cancel, &mut false)?;
        client.start()?;
        Ok(client)
    }

    /// Connect and handshake into an existing event channel, without
    /// emitting events or spawning threads yet (see [`start`](Self::start)).
    /// The supervisor uses this so one channel spans many connections and
    /// its send handle is in place before `Connected` is observable.
    ///
    /// Raising `cancel` aborts the handshake (with [`DisconnectReason::Closed`]
    /// within 50 ms) and acts like [`close`](Self::close) for event
    /// delivery; the TCP connect itself is not interruptible.
    ///
    /// `pin_sent` is set once an AUTH carrying [`ClientConfig::pin`] may
    /// have reached the phone (whatever the outcome), so the caller never
    /// replays that PIN.
    pub(crate) fn establish(
        addr: SocketAddr,
        config: ClientConfig,
        tx: Sender<ClientEvent>,
        rx: Receiver<ClientEvent>,
        cancel: Arc<AtomicBool>,
        pin_sent: &mut bool,
    ) -> Result<Client, DisconnectReason> {
        let t = config.timeouts;
        let mut stream = open_socket(addr, t.connect)?;
        let hs = handshake(&mut stream, &config, &cancel, pin_sent)?;

        // Streaming phase: reads tick so liveness and close are noticed;
        // writes are bounded so a dead link cannot wedge the writer.
        let tick = (t.liveness / 10).clamp(Duration::from_millis(5), Duration::from_millis(250));
        let io_err = |e: io::Error| DisconnectReason::io(&e);
        stream.set_read_timeout(Some(tick)).map_err(io_err)?;
        stream
            .set_write_timeout(Some(t.liveness.max(Duration::from_millis(1))))
            .map_err(io_err)?;
        let read_half = stream.try_clone().map_err(io_err)?;
        let write_half = stream.try_clone().map_err(io_err)?;

        let (done_tx, done_rx) = bounded(1);
        let (stop_tx, stop_rx) = bounded(1);
        let (queue_tx, queue_rx) = bounded(config.send_capacity.max(1));
        let shared = Arc::new(Shared {
            events: tx,
            stream,
            closing: AtomicBool::new(false),
            cancel,
            finished: AtomicBool::new(false),
            done: done_tx,
            stop: stop_tx,
            epoch: Instant::now(),
            rtt_us: AtomicU64::new(u64::MAX),
            pings: Mutex::default(),
            emit_lock: Mutex::new(()),
            auth: hs.auth,
            control: AtomicBool::new(false),
        });
        Ok(Client {
            handle: Handle {
                shared,
                queue: queue_tx,
            },
            events: rx,
            done: done_rx,
            server: hs.server,
            addr,
            pending: Some(Pending {
                read_half,
                write_half,
                opener: hs.opener,
                sealer: hs.sealer,
                queue: queue_rx,
                stop: stop_rx,
                timeouts: t,
                paired: hs.paired,
            }),
            reader: None,
            writer: None,
            writer_exited: None,
        })
    }

    /// Emit [`ClientEvent::Connected`] (and [`ClientEvent::Paired`] after a
    /// PIN pairing) and spawn the reader and writer. No-op after the first
    /// call.
    pub(crate) fn start(&mut self) -> Result<(), DisconnectReason> {
        let Some(p) = self.pending.take() else {
            return Ok(());
        };
        let shared = &self.handle.shared;
        shared.emit(ClientEvent::Connected {
            addr: self.addr,
            server: self.server.clone(),
            auth: shared.auth,
        });
        if let Some(Pairing {
            device_name,
            save_error,
        }) = p.paired
        {
            shared.emit(ClientEvent::Paired {
                device_id: self.server.device_id.clone(),
                device_name,
                save_error,
            });
        }
        let t = p.timeouts;
        let reader = {
            let shared = Arc::clone(shared);
            let (stream, opener) = (p.read_half, p.opener);
            thread::Builder::new()
                .name("mirror-client-rx".into())
                .spawn(move || reader_loop(&shared, stream, opener, t.liveness))
        };
        let (exit_tx, exit_rx) = bounded::<()>(0);
        self.writer_exited = Some(exit_rx);
        let writer = {
            let shared = Arc::clone(shared);
            let (stream, sealer, queue, stop) = (p.write_half, p.sealer, p.queue, p.stop);
            thread::Builder::new()
                .name("mirror-client-tx".into())
                .spawn(move || {
                    let _exit = exit_tx;
                    writer_loop(&shared, stream, sealer, queue, stop, t.ping_interval)
                })
        };
        // Keep whatever spawned so close() joins it; fail if either did not.
        let err = reader
            .as_ref()
            .err()
            .or(writer.as_ref().err())
            .map(DisconnectReason::io);
        self.reader = reader.ok();
        self.writer = writer.ok();
        match err {
            None => Ok(()),
            Some(reason) => {
                self.handle.shared.finish(reason.clone());
                self.close();
                Err(reason)
            }
        }
    }

    pub(crate) fn handle(&self) -> Handle {
        self.handle.clone()
    }

    /// The event stream. Cloning the receiver is cheap; all clones share it.
    pub fn events(&self) -> Receiver<ClientEvent> {
        self.events.clone()
    }

    /// SERVER_HELLO of this session.
    pub fn server(&self) -> &ServerHello {
        &self.server
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// How this session authenticated.
    pub fn auth_mode(&self) -> AuthMode {
        self.handle.shared.auth
    }

    /// Latest measured round-trip time, if any PONG arrived yet.
    pub fn rtt(&self) -> Option<Duration> {
        self.handle.rtt()
    }

    /// True once the connection has ended (for any reason).
    pub fn is_disconnected(&self) -> bool {
        self.handle.is_finished()
    }

    /// True while the session is authenticated (`pin`/`token`), up, and the
    /// phone's latest STATUS was `control_available`.
    pub fn control_available(&self) -> bool {
        self.handle.control_available()
    }

    /// Receives the final [`DisconnectReason`] once (in addition to the
    /// `Disconnected` event). Used by the supervisor to wait in `select!`.
    pub(crate) fn done(&self) -> &Receiver<DisconnectReason> {
        &self.done
    }

    /// Ask the phone for an IDR frame.
    pub fn request_keyframe(&self) -> Result<(), SendError> {
        self.send(Message::RequestKeyframe)
    }

    /// Queue any receiver→phone message. Never blocks; fails with
    /// [`SendError::QueueFull`] when congested. Input should go through
    /// [`send_control`](Self::send_control).
    pub fn send(&self, msg: Message) -> Result<(), SendError> {
        self.handle.send(msg)
    }

    /// Queue an input message (TOUCH_GESTURE, SCROLL, GLOBAL_ACTION, TEXT,
    /// KEY, TOUCH_LIVE). Never blocks. Refused with
    /// [`SendError::ControlUnavailable`] unless
    /// [`control_available`](Self::control_available).
    pub fn send_control(&self, msg: Message) -> Result<(), SendError> {
        self.handle.send_control(msg)
    }

    /// Send BYE `stopped_by_user` (if still connected), close the socket and
    /// join both threads. Idempotent; also runs on drop. Emits
    /// `Disconnected(Closed)` unless the connection had already ended.
    /// Takes at most about [`BYE_GRACE`] even when the phone stopped reading
    /// (the BYE is then abandoned).
    pub fn close(&mut self) {
        let shared = &self.handle.shared;
        if self.pending.take().is_some() {
            // Never started: no events were emitted; just hang up.
            shared.finished.store(true, Ordering::Release);
            let _ = shared.stream.shutdown(Shutdown::Both);
            return;
        }
        if self.reader.is_none() && self.writer.is_none() {
            return;
        }
        shared.closing.store(true, Ordering::Release);
        if !shared.is_finished() {
            let _ = shared.stop.try_send(Some(ByeReason::StoppedByUser));
        }
        // Let the writer send the BYE, but not for long: blocked on a full
        // send buffer it would hold us for up to `liveness`. Shutting the
        // socket down (in `finish`) wakes it.
        if let Some(exited) = self.writer_exited.take() {
            let _ = exited.recv_timeout(BYE_GRACE);
        }
        shared.finish(DisconnectReason::Closed);
        if let Some(w) = self.writer.take() {
            let _ = w.join();
        }
        if let Some(r) = self.reader.take() {
            let _ = r.join();
        }
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        self.close();
    }
}

// ---------------------------------------------------------------------------
// Connect + handshake
// ---------------------------------------------------------------------------

fn open_socket(addr: SocketAddr, timeout: Duration) -> Result<TcpStream, DisconnectReason> {
    let io_err = |e: io::Error| DisconnectReason::io(&e);
    let sock = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))
        .map_err(io_err)?;
    sock.set_tcp_nodelay(true).map_err(io_err)?;
    sock.set_keepalive(true).map_err(io_err)?;
    match sock.connect_timeout(&SockAddr::from(addr), timeout.max(Duration::from_millis(1))) {
        Ok(()) => Ok(sock.into()),
        Err(e) if is_timeout(&e) => Err(DisconnectReason::Timeout(TimeoutKind::Connect)),
        Err(e) => Err(io_err(e)),
    }
}

fn is_timeout(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

fn protocol_err(e: ProtocolError) -> DisconnectReason {
    DisconnectReason::Protocol(e.to_string())
}

/// How long [`Client::close`] waits for the BYE to be written.
pub const BYE_GRACE: Duration = Duration::from_millis(500);

/// How often a blocked handshake read checks for cancellation.
const CANCEL_TICK: Duration = Duration::from_millis(50);

/// Used when a `locked_out` refusal carries no `retryAfterMs` (the phone's
/// lockout is 30 s).
const DEFAULT_LOCKOUT: Duration = Duration::from_secs(30);

/// Upper bound for a reported lockout. `retryAfterMs` comes from an
/// unauthenticated AUTH_RESULT: an absurd value (up to `u64::MAX` ms) must
/// not reach `Instant + retry_after` arithmetic, which panics on overflow.
/// The phone's own lockout tops out at 1 h.
pub const MAX_LOCKOUT: Duration = Duration::from_secs(24 * 60 * 60);

/// Blocking plaintext handshake I/O against one overall deadline.
struct Transport<'a> {
    stream: &'a mut TcpStream,
    dec: Decoder,
    deadline: Instant,
    cancel: &'a AtomicBool,
    /// A frame that arrived together with the magic preamble.
    early: Option<Message>,
}

impl Transport<'_> {
    fn write(&mut self, bytes: &[u8]) -> Result<(), DisconnectReason> {
        // Never send AUTH/START once cancelled: a late AUTH would make the
        // phone evict whatever receiver connected to it in the meantime.
        if self.cancel.load(Ordering::Acquire) {
            return Err(DisconnectReason::Closed);
        }
        // Each write gets only what is left of the handshake budget.
        let left = self.deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(DisconnectReason::Timeout(TimeoutKind::Handshake));
        }
        self.stream
            .set_write_timeout(Some(left))
            .map_err(|e| DisconnectReason::io(&e))?;
        self.stream.write_all(bytes).map_err(|e| {
            if is_timeout(&e) {
                DisconnectReason::Timeout(TimeoutKind::Handshake)
            } else {
                DisconnectReason::io(&e)
            }
        })
    }

    fn send(&mut self, msg: &Message) -> Result<(), DisconnectReason> {
        self.write(&encode(msg))
    }

    /// Read once (bounded by the deadline) into the decoder.
    fn fill(&mut self) -> Result<(), DisconnectReason> {
        let mut buf = [0u8; 8192];
        loop {
            let left = self.deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(DisconnectReason::Timeout(TimeoutKind::Handshake));
            }
            self.stream
                .set_read_timeout(Some(left.min(CANCEL_TICK)))
                .map_err(|e| DisconnectReason::io(&e))?;
            match self.stream.read(&mut buf) {
                Ok(0) => return Err(DisconnectReason::ConnectionClosed),
                Ok(n) => {
                    self.dec.push(&buf[..n]);
                    return Ok(());
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) if is_timeout(&e) => {
                    if self.cancel.load(Ordering::Acquire) {
                        return Err(DisconnectReason::Closed);
                    }
                }
                Err(e) => return Err(DisconnectReason::io(&e)),
            }
        }
    }

    fn read_magic(&mut self) -> Result<(), DisconnectReason> {
        while !self.dec.magic_seen() {
            match self.dec.next().map_err(protocol_err)? {
                Some(m) => self.early = Some(m),
                None if self.dec.magic_seen() => {}
                None => self.fill()?,
            }
        }
        Ok(())
    }

    /// Next handshake-relevant message. Skips unknown types and harmless
    /// strays; a server BYE ends the handshake with its reason.
    ///
    /// Reads exactly up to the frame it returns: after the final
    /// AUTH_RESULT, whatever is still buffered is the start of the record
    /// stream and must not be parsed as plaintext.
    fn next(&mut self) -> Result<Message, DisconnectReason> {
        loop {
            let msg = match self.early.take() {
                Some(m) => m,
                None => match self.dec.next().map_err(protocol_err)? {
                    Some(m) => m,
                    None => {
                        self.fill()?;
                        continue;
                    }
                },
            };
            match msg {
                Message::Unknown { .. } | Message::Pong(_) | Message::Status(_) => {}
                Message::ServerBye(Bye {
                    reason: ByeReason::AuthFailed,
                }) => return Err(DisconnectReason::AuthFailed { reason: None }),
                Message::ServerBye(b) => return Err(DisconnectReason::Bye(b.reason)),
                m => return Ok(m),
            }
        }
    }
}

fn unexpected(what: &str, got: &Message) -> DisconnectReason {
    DisconnectReason::Protocol(format!(
        "expected {what}, got message type 0x{:02x}",
        got.ty()
    ))
}

/// A finished handshake: the secure channel plus what the UI needs.
struct Handshaken {
    server: ServerHello,
    auth: AuthMode,
    sealer: Sealer,
    opener: Opener,
    /// Set when this handshake paired by PIN.
    paired: Option<Pairing>,
}

/// A PIN pairing made during the handshake.
struct Pairing {
    device_name: String,
    /// Why the new key did not reach the disk, if it did not.
    save_error: Option<String>,
}

/// Pick the credential (module docs, "Credentials"). `Err` closes the
/// connection without sending AUTH.
fn choose_credential(
    config: &ClientConfig,
    server: &ServerHello,
) -> Result<ClientCredential, DisconnectReason> {
    let offers = |m: AuthMode| server.auth_modes.contains(&m);
    // An explicitly supplied PIN wins: the user is re-pairing (e.g. after
    // the phone refused our key, which we keep; see `auth_failure`).
    if offers(AuthMode::Pin) {
        if let Some(pin) = &config.pin {
            if !is_valid_pin(pin) {
                return Err(DisconnectReason::WrongPin);
            }
            // The protocol crate wipes the credential's copy on drop.
            return Ok(ClientCredential::Pin(String::clone(pin)));
        }
    }
    if offers(AuthMode::Token) {
        if let Some(key) = config.store.pairing_key(&server.device_id) {
            return Ok(ClientCredential::Token(key));
        }
    }
    // `none` only when the caller opted in: otherwise a fake phone could
    // simply offer `none` and we would stream to it unauthenticated.
    if config.allow_no_auth && offers(AuthMode::NoAuth) {
        return Ok(ClientCredential::NoAuth);
    }
    if offers(AuthMode::Pin) {
        return Err(DisconnectReason::NeedsPin {
            device_id: server.device_id.clone(),
            device_name: server.device_name.clone(),
        });
    }
    Err(DisconnectReason::AuthUnsupported {
        offered: server.auth_modes.clone(),
    })
}

/// Map a failed auth step to the user-facing outcome. Never touches the
/// stored key (refusals are unauthenticated).
fn auth_failure(e: HandshakeError, mode: AuthMode, server: &ServerHello) -> DisconnectReason {
    let device_id = server.device_id.clone();
    match e {
        HandshakeError::Rejected {
            reason: AuthReason::LockedOut,
            retry_after_ms,
        } => DisconnectReason::LockedOut {
            retry_after: retry_after_ms
                .map_or(DEFAULT_LOCKOUT, Duration::from_millis)
                .min(MAX_LOCKOUT),
        },
        HandshakeError::Rejected {
            reason: AuthReason::UnknownClient | AuthReason::BadProof,
            ..
        } if mode == AuthMode::Token => {
            // The phone no longer accepts this key (revoked / reinstalled),
            // so the UI asks for a PIN. The key is deliberately kept: this
            // AUTH_RESULT is unauthenticated plaintext, and deleting the key
            // on its say-so would let anyone at the phone's address unpair
            // us (same policy as `IdentityChanged`). A successful PIN
            // pairing replaces it (`put_pairing` replaces by deviceId).
            DisconnectReason::PairingRemoved { device_id }
        }
        HandshakeError::Rejected {
            reason: AuthReason::BadProof,
            ..
        } if mode == AuthMode::Pin => DisconnectReason::WrongPin,
        HandshakeError::Rejected { reason, .. } => DisconnectReason::AuthFailed {
            reason: Some(reason),
        },
        // The key is deliberately kept: anyone can claim this deviceId, and
        // deleting the key on their say-so would let them unpair us.
        HandshakeError::ServerProofMismatch => DisconnectReason::IdentityChanged { device_id },
        HandshakeError::WrongPin => DisconnectReason::WrongPin,
        HandshakeError::ProtoMismatch(theirs) => DisconnectReason::ProtoMismatch {
            ours: PROTO_VERSION,
            theirs,
        },
        HandshakeError::ModeNotOffered(_) => DisconnectReason::AuthUnsupported {
            offered: server.auth_modes.clone(),
        },
        HandshakeError::Rng(m) => DisconnectReason::Io {
            kind: io::ErrorKind::Other,
            message: format!("no system randomness: {m}"),
        },
        e @ (HandshakeError::BadField(_)
        | HandshakeError::WeakKeyExchange
        | HandshakeError::Unexpected(_)) => DisconnectReason::Protocol(e.to_string()),
    }
}

fn handshake(
    stream: &mut TcpStream,
    config: &ClientConfig,
    cancel: &AtomicBool,
    pin_sent: &mut bool,
) -> Result<Handshaken, DisconnectReason> {
    let limit = config.timeouts.handshake.max(Duration::from_millis(1));
    let mut io = Transport {
        stream,
        dec: Decoder::new(true),
        deadline: Instant::now() + limit,
        cancel,
        early: None,
    };

    io.write(&MAGIC)?;
    io.read_magic()?;

    let (hs, hello) = ClientHandshake::new(fit_client_name(&config.client_name), &config.client_id)
        .map_err(|e| {
            DisconnectReason::Io {
                // Only the OS RNG can fail here.
                kind: io::ErrorKind::Other,
                message: e.to_string(),
            }
        })?;
    io.send(&Message::ClientHello(hello))?;

    let server = match io.next()? {
        Message::ServerHello(h) => h,
        other => return Err(unexpected("SERVER_HELLO", &other)),
    };
    if server.proto != PROTO_VERSION {
        let _ = io.send(&Message::ClientBye(Bye {
            reason: ByeReason::ProtoMismatch,
        }));
        return Err(DisconnectReason::ProtoMismatch {
            ours: PROTO_VERSION,
            theirs: server.proto,
        });
    }

    let credential = choose_credential(config, &server)?;
    let mode = credential.mode();
    let fail = |e| auth_failure(e, mode, &server);
    let (auth, mut wait) = hs.authenticate(&server, credential).map_err(fail)?;
    // Set before writing: even a failed write may have delivered the AUTH.
    *pin_sent |= mode == AuthMode::Pin;
    io.send(&auth)?;

    // Feed the server's replies until authenticated: PAKE_REPLY (pin; we
    // answer AUTH_CONFIRM) and AUTH_RESULT. Every proof check happens in
    // `on_message` before we trust or reveal anything.
    let established: Established = loop {
        let msg = io.next()?;
        match wait.on_message(&msg).map_err(fail)? {
            ClientStep::Send(reply, next) => {
                io.send(&reply)?;
                wait = next;
            }
            ClientStep::Done(est) => break est,
        }
    };

    // Persist a new pairing before anything else can go wrong: the phone
    // has already stored its side, and a reconnect must find our key.
    let paired = established.pairing_key.as_ref().map(|key| {
        let device = PairedDevice {
            device_id: server.device_id.clone(),
            device_name: server.device_name.clone(),
            key: key.clone(),
            paired_at_ms: now_ms(),
        };
        // On failure the key is still kept in memory for this run; only the
        // disk copy is missing, which the UI must tell the user.
        let save_error = config.store.put_pairing(device).err().map(|e| {
            eprintln!("settings: could not save the new pairing: {e}");
            e.to_string()
        });
        Pairing {
            device_name: server.device_name.clone(),
            save_error,
        }
    });

    // From here on every frame is a record. Bytes already read past
    // AUTH_RESULT belong to the record stream.
    let (mut sealer, mut opener) = established.keys.client_channel();
    debug_assert!(io.early.is_none());
    opener.push(&io.dec.take_buffered());

    let mut start = Vec::with_capacity(64);
    sealer
        .seal_message(&Message::Start(config.start), &mut start)
        .map_err(protocol_err)?;
    io.write(&start)?;

    Ok(Handshaken {
        server,
        auth: established.mode,
        sealer,
        opener,
        paired,
    })
}

// ---------------------------------------------------------------------------
// Threads
// ---------------------------------------------------------------------------

fn reader_loop(shared: &Shared, mut stream: TcpStream, mut opener: Opener, liveness: Duration) {
    let mut buf = vec![0u8; 64 * 1024];
    // Liveness counts only time spent waiting on the socket since the last
    // byte, not time spent blocked handing events to a slow consumer (after
    // such a stall the phone gets a full `liveness` to be heard again).
    let mut idle = Duration::ZERO;
    loop {
        loop {
            match opener.next() {
                Ok(None) => break,
                Ok(Some(m)) => {
                    if let Some(reason) = dispatch(shared, m) {
                        shared.finish(reason);
                        return;
                    }
                }
                // An authentic record of a known type with an unparsable
                // payload: consumed, the channel is still in sync; skip it.
                Err(e) if !e.is_fatal() => {}
                // A record that fails authentication / is oversize: the
                // stream cannot be trusted any more (and no BYE could be).
                // Retryable: a new connection gets a new channel.
                Err(e) => {
                    shared.finish(protocol_err(e));
                    return;
                }
            }
            if shared.is_finished() {
                return;
            }
        }
        if shared.is_finished() {
            return;
        }
        let waiting = Instant::now();
        match stream.read(&mut buf) {
            Ok(0) => {
                shared.finish(DisconnectReason::ConnectionClosed);
                return;
            }
            Ok(n) => {
                opener.push(&buf[..n]);
                idle = Duration::ZERO;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => idle += waiting.elapsed(),
            Err(e) if is_timeout(&e) => {
                idle += waiting.elapsed();
                if idle >= liveness {
                    shared.finish(DisconnectReason::Timeout(TimeoutKind::Liveness));
                    return;
                }
            }
            Err(e) => {
                shared.finish(DisconnectReason::io(&e));
                return;
            }
        }
    }
}

/// Turn one received message into events. `Some` ends the connection.
fn dispatch(shared: &Shared, msg: Message) -> Option<DisconnectReason> {
    match msg {
        Message::VideoConfig(c) => {
            shared.emit(ClientEvent::VideoConfig(c));
        }
        Message::VideoFrame(f) => {
            shared.emit(ClientEvent::VideoFrame(f));
        }
        Message::Status(s) => {
            match s.state {
                StatusState::ControlAvailable => shared.control.store(true, Ordering::Release),
                StatusState::ControlUnavailable => shared.control.store(false, Ordering::Release),
                _ => {}
            }
            shared.emit(ClientEvent::Status(s.state));
        }
        Message::Pong(p) => {
            // Payload is our own send timestamp: only an outstanding PING's
            // stamp counts (unsolicited, repeated or made-up ones are ignored).
            let sent = u64::from_be_bytes(p);
            if !lock(&shared.pings).take(sent) {
                return None;
            }
            if let Some(rtt) = shared.now_us().checked_sub(sent) {
                shared
                    .rtt_us
                    .store(rtt.min(u64::MAX - 1), Ordering::Relaxed);
                shared.emit(ClientEvent::Rtt(Duration::from_micros(rtt)));
            }
        }
        Message::ServerBye(b) => return Some(DisconnectReason::Bye(b.reason)),
        // Late handshake replies, unknown/reserved types (audio) and
        // receiver->phone types a confused server might echo: ignored.
        _ => {}
    }
    None
}

fn writer_loop(
    shared: &Shared,
    mut stream: TcpStream,
    mut sealer: Sealer,
    queue: Receiver<Vec<u8>>,
    stop: Receiver<Option<ByeReason>>,
    ping_interval: Duration,
) {
    let ping_interval = ping_interval.max(Duration::from_millis(1));
    let mut next_ping = Instant::now() + ping_interval;
    let mut buf = Vec::with_capacity(256);
    loop {
        let now = Instant::now();
        buf.clear();
        let sealed = if now >= next_ping {
            // Checked first so a busy queue cannot starve liveness pings.
            next_ping = now + ping_interval;
            let stamp = shared.now_us();
            lock(&shared.pings).record(stamp);
            sealer.seal_message(&Message::Ping(stamp.to_be_bytes()), &mut buf)
        } else {
            select! {
                recv(stop) -> s => {
                    if let Ok(Some(reason)) = s {
                        buf.clear();
                        if sealer.seal_message(&Message::ClientBye(Bye { reason }), &mut buf).is_ok() {
                            let _ = stream.write_all(&buf);
                            let _ = stream.flush();
                        }
                    }
                    return;
                }
                recv(queue) -> m => match m {
                    Ok(frame) => sealer.seal_frame(&frame, &mut buf),
                    Err(_) => return,
                },
                default(next_ping - now) => continue,
            }
        };
        // Sizes were checked when queued, so the only failure left is
        // sequence exhaustion: the channel cannot continue.
        if let Err(e) = sealed {
            shared.finish(protocol_err(e));
            return;
        }
        if let Err(e) = stream.write_all(&buf) {
            shared.finish(if is_timeout(&e) {
                DisconnectReason::Timeout(TimeoutKind::Liveness)
            } else {
                DisconnectReason::io(&e)
            });
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `Shared` over a loopback socket, plus its event receiver.
    fn shared() -> (Shared, Receiver<ClientEvent>) {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let stream = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (events, rx) = bounded(16);
        let (done, _) = bounded(1);
        let (stop, _) = bounded(1);
        let s = Shared {
            events,
            stream,
            closing: AtomicBool::new(false),
            cancel: Arc::new(AtomicBool::new(false)),
            finished: AtomicBool::new(false),
            done,
            stop,
            epoch: Instant::now(),
            rtt_us: AtomicU64::new(u64::MAX),
            pings: Mutex::default(),
            emit_lock: Mutex::new(()),
            auth: AuthMode::NoAuth,
            control: AtomicBool::new(false),
        };
        (s, rx)
    }

    #[test]
    fn a_long_client_name_is_cut_on_a_char_boundary() {
        assert_eq!(fit_client_name("Mac"), "Mac");
        let exact = "a".repeat(MAX_CLIENT_NAME_BYTES);
        assert_eq!(fit_client_name(&exact), exact);
        // 255 ASCII bytes, then a 3-byte character that would cross 256.
        let long = format!("{}€€", "a".repeat(MAX_CLIENT_NAME_BYTES - 1));
        let cut = fit_client_name(&long);
        assert_eq!(cut, "a".repeat(MAX_CLIENT_NAME_BYTES - 1));
        assert!(cut.len() <= MAX_CLIENT_NAME_BYTES);
    }

    #[test]
    fn nothing_is_emitted_after_disconnected() {
        let (s, rx) = shared();
        assert!(s.emit(ClientEvent::Status(StatusState::Streaming)));
        s.finish(DisconnectReason::ConnectionClosed);
        // A reader that was mid-dispatch when the writer finished.
        assert!(!s.emit(ClientEvent::Status(StatusState::Streaming)));
        let got: Vec<_> = rx.try_iter().collect();
        assert_eq!(
            got,
            vec![
                ClientEvent::Status(StatusState::Streaming),
                ClientEvent::Disconnected(DisconnectReason::ConnectionClosed),
            ]
        );
    }

    #[test]
    fn only_an_outstanding_ping_yields_an_rtt_and_only_once() {
        let (s, rx) = shared();
        let pong = |t: u64| Message::Pong(t.to_be_bytes());
        // Unsolicited (made-up) stamps: no RTT.
        assert_eq!(dispatch(&s, pong(0)), None);
        assert_eq!(dispatch(&s, pong(3)), None);
        assert!(rx.try_recv().is_err());
        assert_eq!(s.rtt_us.load(Ordering::Relaxed), u64::MAX);
        // A real one counts once; older outstanding ones still count.
        let mut log = lock(&s.pings);
        log.record(1);
        log.record(2);
        drop(log);
        std::thread::sleep(Duration::from_millis(1)); // now_us > the stamps
        assert_eq!(dispatch(&s, pong(2)), None);
        assert!(matches!(rx.try_recv(), Ok(ClientEvent::Rtt(_))));
        assert_eq!(dispatch(&s, pong(2)), None);
        assert!(rx.try_recv().is_err(), "a repeated echo is ignored");
        assert_eq!(dispatch(&s, pong(1)), None);
        assert!(matches!(rx.try_recv(), Ok(ClientEvent::Rtt(_))));
    }

    #[test]
    fn ping_log_forgets_the_oldest() {
        let mut log = PingLog::default();
        for t in 1..=5 {
            log.record(t);
        }
        assert!(!log.take(1), "overwritten by the fifth");
        assert!(log.take(2) && log.take(5));
        assert!(!log.take(5));
    }

    #[test]
    fn pin_format() {
        assert!(is_valid_pin("000000"));
        assert!(is_valid_pin("123456"));
        for bad in ["", "12345", "1234567", "12345a", "١٢٣٤٥٦", " 12345"] {
            assert!(!is_valid_pin(bad), "{bad:?}");
        }
    }

    #[test]
    fn handshake_writes_get_only_the_time_left() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut stream = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let cancel = AtomicBool::new(false);
        let mut io = Transport {
            stream: &mut stream,
            dec: Decoder::new(true),
            deadline: Instant::now() + Duration::from_secs(5),
            cancel: &cancel,
            early: None,
        };
        io.write(b"x").unwrap();
        let t = io
            .stream
            .write_timeout()
            .unwrap()
            .expect("write timeout set");
        assert!(t <= Duration::from_secs(5) && !t.is_zero(), "{t:?}");
        // Out of budget: nothing more is written.
        io.deadline = Instant::now();
        assert_eq!(
            io.write(b"y"),
            Err(DisconnectReason::Timeout(TimeoutKind::Handshake))
        );
    }

    #[test]
    fn config_debug_hides_the_pin() {
        let mut c = ClientConfig::new("r", "c");
        c.pin = Some(Zeroizing::new("482913".into()));
        let s = format!("{c:?}");
        assert!(!s.contains("482913"), "{s}");
        assert!(s.contains("redacted"), "{s}");
    }

    #[test]
    fn auth_outcomes_are_classified() {
        use DisconnectReason::*;
        for r in [
            NeedsPin {
                device_id: "d".into(),
                device_name: "n".into(),
            },
            WrongPin,
            LockedOut {
                retry_after: Duration::from_secs(1),
            },
            PairingRemoved {
                device_id: "d".into(),
            },
            IdentityChanged {
                device_id: "d".into(),
            },
            AuthUnsupported { offered: vec![] },
            AuthFailed { reason: None },
        ] {
            assert!(r.is_auth_outcome(), "{r:?}");
            assert!(!r.to_string().is_empty());
        }
        for r in [Closed, ConnectionClosed, Protocol("x".into())] {
            assert!(!r.is_auth_outcome(), "{r:?}");
        }
    }
}
