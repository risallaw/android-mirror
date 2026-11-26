//! [`Server`]: listener, accept loop, single-client policy, source ownership.

use std::io;
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use mirror_protocol::auth::PairingKey;
use mirror_protocol::{ByeReason, Message, Status, StatusState, VideoConfig};
use zeroize::Zeroizing;

use crate::config::ServerConfig;
use crate::net;
use crate::pairing::{
    now_ms, PairedClient, PairingStore, PinAdmission, PinFailure, PinState, StoreWriter,
};
use crate::pending::PendingSet;
use crate::session::{self, mode_allows_control, SessionHandle};
use crate::sink::FrameSink;
use crate::throttle::{log_throttled, short, Throttle, LOG_INTERVAL};
use crate::types::{
    ClientInfo, ControlSink, DisconnectReason, HostError, HostEvents, SourceError, StreamParams,
    VideoSource,
};

/// Lock ignoring poisoning: a panicking host callback must not wedge the
/// server (the protected data stays consistent; every critical section here
/// is short and panic-free).
pub(crate) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// One accepted connection (handshake or session) and its thread.
struct Conn {
    id: u64,
    /// Clone used to force-close the socket from `stop()`.
    stream: TcpStream,
    thread: JoinHandle<()>,
}

/// State shared by the accept thread, session threads and sinks.
pub(crate) struct Shared {
    pub(crate) cfg: ServerConfig,
    source: Arc<dyn VideoSource>,
    pub(crate) events: Arc<dyn HostEvents>,
    pub(crate) control: Arc<dyn ControlSink>,
    pub(crate) stopping: AtomicBool,
    /// The authenticated client (newest wins).
    active: Mutex<Option<Arc<SessionHandle>>>,
    /// Session id the source is running for; 0 = stopped.
    owner: AtomicU64,
    /// Serialises `VideoSource::start`/`stop`.
    source_lock: Mutex<()>,
    /// Latest VIDEO_CONFIG from the source, used to map control input
    /// coordinates (never re-sent to a client). `Arc`: read on every control
    /// message, so readers clone a pointer, not the SPS/PPS.
    pub(crate) last_config: Mutex<Option<Arc<VideoConfig>>>,
    /// Phone screen is off (last sticky STATUS was `screen_off`). Written
    /// under the `active` lock so a client activated concurrently with
    /// [`Server::send_status`] sees either the replay or the live STATUS.
    screen_off: AtomicBool,
    /// The host's control capability (Accessibility service enabled).
    /// Written under the `active` lock, like `screen_off`.
    control_available: AtomicBool,
    /// PIN and pairing store. Never held while calling the host, nor while
    /// the store is written to disk (`store_writer`).
    auth: Mutex<AuthState>,
    store_writer: StoreWriter,
    /// Throttle log lines any LAN host can trigger at will. Failed
    /// handshakes have one throttle for Info and above and one for Debug,
    /// so debug lines never suppress an info one.
    pub(crate) handshake_log: Mutex<Throttle>,
    pub(crate) handshake_debug_log: Mutex<Throttle>,
    /// "rejecting non-LAN peer" and pending-handshake evictions: separate,
    /// so a flood of one cannot hide the other.
    non_lan_log: Mutex<Throttle>,
    eviction_log: Mutex<Throttle>,
    /// Connections still in the handshake (admission/eviction policy).
    pending: Mutex<PendingSet>,
    conns: Mutex<Vec<Conn>>,
    next_id: AtomicU64,
}

impl Shared {
    fn new(
        cfg: ServerConfig,
        source: Arc<dyn VideoSource>,
        events: Arc<dyn HostEvents>,
        control: Arc<dyn ControlSink>,
    ) -> Self {
        let auth = AuthState {
            pin: PinState::new(cfg.fixed_pin.as_deref()),
            store: PairingStore::open(cfg.pairing_store.clone()),
        };
        Shared {
            control_available: AtomicBool::new(false),
            auth: Mutex::new(auth),
            store_writer: StoreWriter::default(),
            handshake_log: Mutex::new(Throttle::new(LOG_INTERVAL)),
            handshake_debug_log: Mutex::new(Throttle::new(LOG_INTERVAL)),
            non_lan_log: Mutex::new(Throttle::new(LOG_INTERVAL)),
            eviction_log: Mutex::new(Throttle::new(LOG_INTERVAL)),
            pending: Mutex::new(PendingSet::new(
                cfg.max_pending_handshakes,
                cfg.max_pending_handshakes_per_ip,
            )),
            cfg,
            source,
            events,
            control,
            stopping: AtomicBool::new(false),
            active: Mutex::new(None),
            owner: AtomicU64::new(0),
            source_lock: Mutex::new(()),
            last_config: Mutex::new(None),
            screen_off: AtomicBool::new(false),
            conns: Mutex::new(Vec::new()),
            next_id: AtomicU64::new(1),
        }
    }

    pub(crate) fn source_owner(&self) -> u64 {
        self.owner.load(Ordering::SeqCst)
    }

    /// Make `h` the active client; the previous one gets BYE `replaced`.
    /// `key`: the pairing key `h` authenticated with (`pin`/`token`).
    /// Right after AUTH_RESULT a new client is told whether it may control
    /// the phone (STATUS `control_available`/`control_unavailable`), then a
    /// sticky STATUS it missed (`screen_off`).
    pub(crate) fn activate(&self, h: &Arc<SessionHandle>, key: Option<&PairingKey>) -> Activation {
        let mut a = lock(&self.active);
        if self.stopping.load(Ordering::SeqCst) {
            return Activation::Stopping;
        }
        // Checked under the `active` lock: `revoke` removes the key before
        // it looks at the active session, so a session whose pairing was
        // revoked after its key lookup is refused here instead of first
        // replacing (kicking) the legitimate active client. The key itself
        // is compared, not just the presence of a pairing: a revoke followed
        // at once by a new pairing of the same `clientId` must still refuse
        // the session that used the revoked key.
        if mode_allows_control(h.info.auth)
            && !key.is_some_and(|k| self.pairing_key(&h.info.id).as_ref() == Some(k))
        {
            return Activation::Revoked;
        }
        if let Some(old) = a.replace(h.clone()) {
            log::info!(
                "client {:?} ({}) replaced by {:?} ({})",
                short(&old.info.name),
                old.info.peer,
                short(&h.info.name),
                h.info.peer
            );
            old.finish(ByeReason::Replaced, DisconnectReason::Replaced);
        }
        let control = self.control_available.load(Ordering::SeqCst);
        h.push_control(control_status(control && mode_allows_control(h.info.auth)));
        if self.screen_off.load(Ordering::SeqCst) {
            h.push_control(Message::Status(Status {
                state: StatusState::ScreenOff,
            }));
        }
        Activation::Active
    }

    pub(crate) fn deactivate(&self, id: u64) {
        let mut a = lock(&self.active);
        if a.as_ref().is_some_and(|h| h.id == id) {
            *a = None;
        }
    }

    /// (Re)start the source for session `id`, stopping it first if it runs
    /// for another session. `Ok(false)`: `id` is no longer the active client
    /// (replaced or server stopping), nothing was started.
    pub(crate) fn start_source(
        &self,
        id: u64,
        params: StreamParams,
        sink: FrameSink,
    ) -> Result<bool, SourceError> {
        let _g = lock(&self.source_lock);
        // Checked under `source_lock`: a replaced session whose START waited
        // here must not take the source away from its successor.
        if self.stopping.load(Ordering::SeqCst)
            || !lock(&self.active).as_ref().is_some_and(|h| h.id == id)
        {
            return Ok(false);
        }
        if self.owner.swap(0, Ordering::SeqCst) != 0 {
            self.source.stop();
        }
        // The previous session's config must not map this session's input
        // (its geometry may differ); the source pushes a new one.
        *lock(&self.last_config) = None;
        // Owner is set before start so the sink is live for pushes made
        // from inside `start`.
        self.owner.store(id, Ordering::SeqCst);
        log::info!("starting video source for session {id}: {params:?}");
        if let Err(e) = self.source.start(params, sink) {
            self.owner.store(0, Ordering::SeqCst);
            // Let the source clean up a partial start.
            self.source.stop();
            return Err(e);
        }
        Ok(true)
    }

    /// Stop the source if it runs for session `id` (`None` = whoever).
    pub(crate) fn stop_source(&self, id: Option<u64>) {
        let _g = lock(&self.source_lock);
        let cur = self.owner.load(Ordering::SeqCst);
        if cur != 0 && id.is_none_or(|id| id == cur) {
            self.owner.store(0, Ordering::SeqCst);
            log::info!("stopping video source (session {cur})");
            self.source.stop();
        }
    }

    pub(crate) fn request_keyframe(&self, id: u64) {
        if self.source_owner() == id {
            self.source.request_keyframe();
        }
    }

    pub(crate) fn control_available(&self) -> bool {
        self.control_available.load(Ordering::SeqCst)
    }

    /// The stored pairing key for `client_id` (token mode).
    pub(crate) fn pairing_key(&self, client_id: &str) -> Option<PairingKey> {
        lock(&self.auth).store.key(client_id)
    }

    /// AUTH `pin` arrived from `peer`: count the attempt (see
    /// [`PinState::admit`]) or refuse with the time until a retry may
    /// succeed (remaining lockout, or the handshake timeout when every
    /// allowed attempt is in flight).
    pub(crate) fn admit_pin_attempt(
        self: &Arc<Self>,
        peer: SocketAddr,
    ) -> Result<PinAttempt, Duration> {
        let (admission, resets) = {
            let mut a = lock(&self.auth);
            let admission = a.pin.admit(Instant::now(), self.cfg.handshake_timeout);
            (admission, a.pin.resets())
        };
        match admission {
            PinAdmission::Attempt { pin, gen } => Ok(PinAttempt {
                shared: self.clone(),
                peer,
                pin,
                gen,
                resets,
                resolved: false,
            }),
            PinAdmission::Refused {
                retry_after,
                notify,
            } => {
                self.report_refusal(peer, retry_after, notify, resets);
                Err(retry_after)
            }
        }
    }

    /// Report a refused PIN attempt (if `notify`), `resets` being the "New
    /// PIN" count when it was refused: like a failure, a refusal from a
    /// lockout that "New PIN" has since cleared is not reported.
    fn report_refusal(&self, peer: SocketAddr, retry_after: Duration, notify: bool, resets: u64) {
        if !notify {
            log::debug!("PIN attempt from {peer} refused for {retry_after:?}");
            return;
        }
        log::warn!("PIN attempt from {peer} refused for {retry_after:?}");
        let refused = PinFailure {
            attempts_left: 0,
            locked_for: Some(retry_after),
            rotated: false,
        };
        self.report_pin_failure(peer, refused, resets);
    }

    /// Write a pairing-store change (outside the `auth` lock); a failure
    /// is reported to the host. False if it was not persisted.
    fn save_store(&self, save: crate::pairing::Save) -> bool {
        match self.store_writer.write(save) {
            Ok(()) => true,
            Err(e) => {
                self.events.error(&HostError::PairingStore(e));
                false
            }
        }
    }
}

/// Outcome of [`Shared::activate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Activation {
    /// `h` is now the active client.
    Active,
    /// The server is stopping; nothing changed.
    Stopping,
    /// `h` authenticated with a pairing key that has since been revoked;
    /// nothing changed (the active client keeps its session).
    Revoked,
}

/// Host-visible pairing state, under one lock.
struct AuthState {
    pin: PinState,
    store: PairingStore,
}

fn control_status(available: bool) -> Message {
    Message::Status(Status {
        state: if available {
            StatusState::ControlAvailable
        } else {
            StatusState::ControlUnavailable
        },
    })
}

/// One counted PIN attempt. Dropping it without
/// [`succeeded`](PinAttempt::succeeded) (wrong PIN, timeout, disconnect,
/// any error) records a failure, so every way out of the handshake after
/// AUTH `pin` burns the attempt; only a server stop, or a "New PIN" since it
/// was admitted (random PIN: it can no longer succeed), does not.
pub(crate) struct PinAttempt {
    shared: Arc<Shared>,
    peer: SocketAddr,
    /// The PIN this attempt is checked against.
    pin: Zeroizing<String>,
    /// Its [`PinState`] generation.
    gen: u64,
    /// The "New PIN" count when it was admitted.
    resets: u64,
    resolved: bool,
}

impl PinAttempt {
    pub(crate) fn pin(&self) -> &str {
        &self.pin
    }

    /// The PIN exchange succeeded: if the PIN it used is still the current
    /// one, store the key (replacing any previous one for this client),
    /// reset the failure count, rotate the PIN and return true. False (and
    /// counted as a failure) if the PIN rotated while the attempt was in
    /// flight: a rotated PIN must not pair anyone any more.
    pub(crate) fn succeeded(mut self, client_id: &str, client_name: &str, key: PairingKey) -> bool {
        let sh = self.shared.clone();
        let client = PairedClient {
            client_id: client_id.to_owned(),
            client_name: client_name.to_owned(),
            paired_at_ms: now_ms(),
        };
        let (save, new_gen) = {
            let mut a = lock(&sh.auth);
            if !a.pin.is_current(self.gen) {
                drop(a);
                log::info!("PIN from {} was correct but has rotated since", self.peer);
                return false; // dropped unresolved: a failure
            }
            self.resolved = true;
            let save = a
                .store
                .put_unsaved(client_id, client_name, key, client.paired_at_ms);
            a.pin.succeeded();
            (save, a.pin.gen())
        };
        sh.save_store(save);
        log::info!(
            "paired {:?} ({:?}) from {}",
            short(client_name),
            short(client_id),
            self.peer
        );
        sh.events.paired(&client);
        if new_gen != self.gen {
            sh.report_pin_rotation(new_gen);
        }
        true
    }
}

impl Drop for PinAttempt {
    fn drop(&mut self) {
        let sh = &self.shared;
        // A handshake cut short by `Server::stop` is no failed guess (and
        // the PIN state goes away with the server).
        if self.resolved || sh.stopping.load(Ordering::SeqCst) {
            return;
        }
        let (failure, new_gen, resets) = {
            let mut a = lock(&sh.auth);
            // Admitted before "New PIN": that cleared the count it was in,
            // so it neither takes one of the fresh attempts (nor, with all
            // of them in flight, starts a lockout) nor is reported. Not so
            // with a fixed PIN: "New PIN" keeps it, so this was a real
            // guess at the PIN in use and must count (else every reset
            // would grant free guesses).
            if a.pin.resets() != self.resets && !a.pin.is_fixed() {
                drop(a);
                log::debug!("PIN attempt from {} predates a new PIN", self.peer);
                return;
            }
            let failure = if a.pin.resets() == self.resets {
                a.pin.failed(Instant::now())
            } else {
                a.pin.failed_after_reset(Instant::now())
            };
            (failure, a.pin.gen(), a.pin.resets())
        };
        log::warn!(
            "PIN attempt from {} failed; {} left{}",
            self.peer,
            failure.attempts_left,
            match (failure.rotated, failure.locked_for) {
                (true, _) => "; locked out, new PIN",
                (false, Some(_)) => "; locked out",
                (false, None) => "",
            }
        );
        sh.report_pin_failure(self.peer, failure, resets);
        if failure.rotated && new_gen != self.gen {
            sh.report_pin_rotation(new_gen);
        }
    }
}

impl Shared {
    /// Report the PIN rotation to generation `gen` through
    /// [`HostEvents::pin_changed`], unless the PIN changed again since: a
    /// later rotation reports itself and "New PIN" hands its PIN to the
    /// host directly, so a late upcall would put a dead PIN on screen. The
    /// PIN is re-read here (not carried from the rotation) for the same
    /// reason. This narrows the race with "New PIN" (the host must still
    /// re-read [`Server::pin`] when it applies the upcall).
    fn report_pin_rotation(&self, gen: u64) {
        let pin = {
            let a = lock(&self.auth);
            if !a.pin.is_current(gen) {
                return;
            }
            Zeroizing::new(a.pin.pin().to_owned())
        };
        self.events.pin_changed(&pin);
    }

    /// Report a failed PIN attempt, `resets` being the "New PIN" count when
    /// it was counted. Dropped if "New PIN" ran since: it cleared the count
    /// and the lockout this failure reports, so the host would show a stale
    /// lockout or attempt count.
    fn report_pin_failure(&self, peer: SocketAddr, failure: PinFailure, resets: u64) {
        if lock(&self.auth).pin.resets() != resets {
            log::debug!("PIN failure from {peer} predates a new PIN; not reported");
            return;
        }
        self.events
            .pairing_failed_at(peer, failure.attempts_left, failure.locked_for, resets);
    }
}

/// Removes the connection from the pending-handshake set when the
/// handshake ends.
pub(crate) struct PendingGuard {
    shared: Arc<Shared>,
    id: u64,
}

impl PendingGuard {
    /// The handshake succeeded. False if the connection was evicted to make
    /// room for a newer one (its socket is being closed; do not activate).
    pub(crate) fn complete(self) -> bool {
        lock(&self.shared.pending).remove(self.id)
    }
}

impl Drop for PendingGuard {
    fn drop(&mut self) {
        lock(&self.shared.pending).remove(self.id);
    }
}

/// The phone-side mirror server.
///
/// [`Server::start`] binds the port and spawns the accept thread; each
/// connection gets a session thread (handshake, then reader) and, once
/// authenticated, a writer thread. [`Server::stop`] (also run on drop) sends
/// BYE `stopped_by_user` to the client, closes every socket and joins every
/// thread. `Server` is `Send + Sync`.
pub struct Server {
    shared: Arc<Shared>,
    local_addr: SocketAddr,
    accept: Mutex<Option<JoinHandle<()>>>,
}

impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server")
            .field("local_addr", &self.local_addr)
            .finish_non_exhaustive()
    }
}

impl Server {
    /// Bind and start accepting. See [`ServerConfig`] for port fallback.
    pub fn start(
        config: ServerConfig,
        source: Arc<dyn VideoSource>,
        events: Arc<dyn HostEvents>,
        control: Arc<dyn ControlSink>,
    ) -> io::Result<Server> {
        let config = config.sanitized();
        let listener = net::bind_listener(config.bind_addr, config.port)?;
        let blocking = net::set_accept_timeout(&listener, ACCEPT_WAKE_FALLBACK);
        if !blocking {
            listener.set_nonblocking(true)?;
        }
        let local_addr = listener.local_addr()?;
        log::info!("mirror server listening on {local_addr}");
        let shared = Arc::new(Shared::new(config, source, events, control));
        let sh = shared.clone();
        let accept = thread::Builder::new()
            .name("mirror-accept".into())
            .spawn(move || accept_loop(sh, listener, blocking))?;
        Ok(Server {
            shared,
            local_addr,
            accept: Mutex::new(Some(accept)),
        })
    }

    /// The bound port (advertise this via NSD).
    pub fn port(&self) -> u16 {
        self.local_addr.port()
    }

    /// The bound address.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// The current authenticated client, if any.
    pub fn client(&self) -> Option<ClientInfo> {
        lock(&self.shared.active).as_ref().map(|h| h.info.clone())
    }

    /// Send STATUS to the current client. False if there is none.
    ///
    /// `ScreenOff`/`ScreenOn` are sticky: while the last of them was
    /// `ScreenOff`, every newly authenticated client also gets STATUS
    /// `screen_off` right after AUTH_RESULT. Other states are transient.
    pub fn send_status(&self, state: StatusState) -> bool {
        let a = lock(&self.shared.active);
        match state {
            StatusState::ScreenOff => self.shared.screen_off.store(true, Ordering::SeqCst),
            StatusState::ScreenOn => self.shared.screen_off.store(false, Ordering::SeqCst),
            _ => {}
        }
        a.as_ref()
            .is_some_and(|h| h.push_control(Message::Status(Status { state })))
    }

    /// The current pairing PIN (6 digits), wiped when dropped. Rotations by
    /// the server (after a pairing or a lockout) are reported through
    /// [`HostEvents::pin_changed`].
    pub fn pin(&self) -> Zeroizing<String> {
        Zeroizing::new(lock(&self.shared.auth).pin.pin().to_owned())
    }

    /// "New PIN" on the phone: rotate the PIN (attempts in flight on the
    /// old one then fail) and clear the PIN lockout, the failure count and
    /// the lockout escalation. Returns the new PIN; it is *not* also reported
    /// through [`HostEvents::pin_changed`]. With a
    /// [`fixed_pin`](ServerConfig::fixed_pin) the PIN is kept and only the
    /// lockout is cleared.
    pub fn new_pin(&self) -> Zeroizing<String> {
        let mut a = lock(&self.shared.auth);
        a.pin.reset();
        log::info!("new PIN requested by the host; PIN lockout cleared");
        Zeroizing::new(a.pin.pin().to_owned())
    }

    /// How many times [`new_pin`](Self::new_pin) has run; it only grows.
    /// Read right after `new_pin` it is at least that reset's count, so a
    /// failure reported through [`HostEvents::pairing_failed_at`] with a
    /// smaller count predates that reset.
    pub fn pin_resets(&self) -> u64 {
        lock(&self.shared.auth).pin.resets()
    }

    /// Tell the server whether the host can inject input (Accessibility
    /// service enabled). On a change the current client is sent STATUS
    /// `control_available`/`control_unavailable` at once; new clients get
    /// it right after AUTH_RESULT. Control messages are dropped while it is
    /// `false` (the initial value) and always for sessions with auth `none`.
    pub fn set_control_available(&self, available: bool) {
        let a = lock(&self.shared.active);
        let was = self
            .shared
            .control_available
            .swap(available, Ordering::SeqCst);
        if was == available {
            return;
        }
        log::info!(
            "control {}",
            if available {
                "available"
            } else {
                "unavailable"
            }
        );
        if let Some(h) = a.as_ref().filter(|h| mode_allows_control(h.info.auth)) {
            h.push_control(control_status(available));
        }
    }

    /// Paired receivers, oldest first. Empty if the pairing store could not
    /// be loaded; see [`try_list_paired`](Self::try_list_paired).
    pub fn list_paired(&self) -> Vec<PairedClient> {
        lock(&self.shared.auth).store.list()
    }

    /// Like [`list_paired`](Self::list_paired), but `Err` (the load error)
    /// if the pairing store file exists and could not be loaded at start: the
    /// empty in-memory list then does not say that nothing is paired.
    pub fn try_list_paired(&self) -> Result<Vec<PairedClient>, String> {
        let a = lock(&self.shared.auth);
        match a.store.load_error() {
            Some(e) => Err(e.to_owned()),
            None => Ok(a.store.list()),
        }
    }

    /// Forget the pairing for `client_id`; its next `token` AUTH gets
    /// `unknown_client`. If that client is connected, it gets BYE
    /// `auth_failed` and is disconnected. False if it was not paired, or if
    /// the removal could not be written to the pairing store (reported via
    /// [`HostEvents::error`]): it is then forgotten only until the server
    /// stops, and the key would be valid again after a restart.
    pub fn revoke(&self, client_id: &str) -> bool {
        // Remove first: a handshake that already looked the key up checks
        // again under the `active` lock (see `Shared::activate`).
        let save = lock(&self.shared.auth).store.remove_unsaved(client_id);
        let removed = save.is_some_and(|s| self.shared.save_store(s));
        let active = lock(&self.shared.active).clone();
        if let Some(h) = active.filter(|h| h.info.id == client_id) {
            log::info!(
                "revoked client {:?} is connected; disconnecting",
                short(client_id)
            );
            h.finish(ByeReason::AuthFailed, DisconnectReason::Server);
        }
        if removed {
            log::info!("revoked pairing for {:?}", short(client_id));
        }
        removed
    }

    /// Send BYE `reason` to the current client and close its session (e.g.
    /// `ProjectionRevoked`). A BYE tells the receiver the session ended on
    /// purpose, so it does not reconnect; see [`Server::drop_client`] for
    /// that. False if there is no client.
    pub fn disconnect(&self, reason: ByeReason) -> bool {
        let a = lock(&self.shared.active).clone();
        a.is_some_and(|h| h.finish(reason, DisconnectReason::Server))
    }

    /// Close the current client's connection without a BYE, so the receiver
    /// sees a lost connection and reconnects (e.g. after the phone's network
    /// changed). The session ends with [`DisconnectReason::Server`]. False if
    /// there is no client or it is already ending.
    pub fn drop_client(&self) -> bool {
        let Some(h) = lock(&self.shared.active).clone() else {
            return false;
        };
        if !h.abort(DisconnectReason::Server) {
            return false;
        }
        for c in lock(&self.shared.conns).iter().filter(|c| c.id == h.id) {
            let _ = c.stream.shutdown(Shutdown::Both);
        }
        true
    }

    /// Stop the server: BYE `stopped_by_user` to the client, close all
    /// sockets, stop the video source and join every thread. Idempotent;
    /// also called on drop.
    ///
    /// Blocks for about `bye_linger`, plus the accept thread's wake-up
    /// (immediate where `accept` blocks, as on Linux and Android; up to
    /// `accept_poll_interval` where the listener is polled), plus any host
    /// code the joined threads are running: a `VideoSource::start` or
    /// `stop` in flight (a session ending also stops the source) and the
    /// final `HostEvents` callbacks. The server cannot bound those; the host
    /// must. Must not be called from a `HostEvents`, `ControlSink` or
    /// `VideoSource` callback.
    pub fn stop(&self) {
        let Some(accept) = lock(&self.accept).take() else {
            return;
        };
        let sh = &self.shared;
        sh.stopping.store(true, Ordering::SeqCst);
        // Wake the accept thread blocked in `accept` (else it notices within
        // ACCEPT_WAKE_FALLBACK).
        net::wake_listener(self.local_addr);
        if accept.join().is_err() {
            log::error!("accept thread panicked");
        }
        let active = lock(&sh.active).take();
        if let Some(a) = &active {
            a.finish(ByeReason::StoppedByUser, DisconnectReason::Server);
        }
        let conns = std::mem::take(&mut *lock(&sh.conns));
        let active_id = active.as_ref().map(|a| a.id);
        for c in &conns {
            if Some(c.id) != active_id {
                let _ = c.stream.shutdown(Shutdown::Both);
            }
        }
        // Give the active session a moment to deliver its BYE.
        let deadline = Instant::now() + sh.cfg.bye_linger;
        while Instant::now() < deadline && conns.iter().any(|c| !c.thread.is_finished()) {
            thread::sleep(Duration::from_millis(5));
        }
        for c in &conns {
            let _ = c.stream.shutdown(Shutdown::Both);
        }
        for c in conns {
            if c.thread.join().is_err() {
                log::error!("session thread {} panicked", c.id);
            }
        }
        sh.stop_source(None);
        log::info!("mirror server on {} stopped", self.local_addr);
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Longest a blocking `accept` waits before re-checking for a stop, should
/// the wake-up connection from `stop()` not arrive.
const ACCEPT_WAKE_FALLBACK: Duration = Duration::from_secs(1);

/// `blocking`: the listener blocks in `accept` (bounded by
/// [`ACCEPT_WAKE_FALLBACK`]); otherwise it is non-blocking and polled every
/// `accept_poll_interval`.
fn accept_loop(shared: Arc<Shared>, listener: TcpListener, blocking: bool) {
    let poll = shared.cfg.accept_poll_interval;
    let mut error_reported = false;
    // A persistent error (e.g. out of file descriptors) repeats every poll.
    let accept_log = Mutex::new(Throttle::new(LOG_INTERVAL));
    while !shared.stopping.load(Ordering::SeqCst) {
        match listener.accept() {
            // Possibly the wake-up connection from `stop()`.
            Ok(_) if shared.stopping.load(Ordering::SeqCst) => break,
            Ok((stream, peer)) => {
                error_reported = false;
                on_accept(&shared, stream, peer);
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                if !blocking {
                    thread::sleep(poll);
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => {
                log_throttled(&accept_log, log::Level::Warn, || {
                    format!("accept failed: {e}")
                });
                if !error_reported {
                    error_reported = true;
                    shared.events.error(&HostError::Accept(e.to_string()));
                }
                thread::sleep(poll);
            }
        }
        reap(&shared);
    }
}

/// Join finished connection threads.
fn reap(shared: &Shared) {
    let finished: Vec<Conn> = lock(&shared.conns)
        .extract_if(.., |c| c.thread.is_finished())
        .collect();
    for c in finished {
        if c.thread.join().is_err() {
            log::error!("session thread {} panicked", c.id);
        }
    }
}

fn on_accept(shared: &Arc<Shared>, stream: TcpStream, peer: SocketAddr) {
    let cfg = &shared.cfg;
    if !net::is_allowed_peer(peer.ip(), cfg.allow_loopback) {
        log_throttled(&shared.non_lan_log, log::Level::Warn, || {
            format!("rejecting non-LAN peer {peer}")
        });
        return;
    }
    net::configure_stream(&stream, cfg.send_buffer_size);
    let clone = match stream.try_clone() {
        Ok(c) => c,
        Err(e) => {
            log::warn!("try_clone failed for {peer}: {e}");
            return;
        }
    };
    let id = shared.next_id.fetch_add(1, Ordering::SeqCst);
    let victim = lock(&shared.pending).admit(id, peer.ip());
    let guard = PendingGuard {
        shared: shared.clone(),
        id,
    };
    if let Some(v) = victim {
        // Removed from the pending set under its lock, so the victim's
        // `PendingGuard::complete` fails even if its AUTH races this.
        log_throttled(&shared.eviction_log, log::Level::Warn, || {
            format!("too many pending handshakes; closing session {v} for {peer}")
        });
        for c in lock(&shared.conns).iter().filter(|c| c.id == v) {
            let _ = c.stream.shutdown(Shutdown::Both);
        }
    }
    let sh = shared.clone();
    log::debug!("accepted {peer} as session {id}");
    match thread::Builder::new()
        .name(format!("mirror-session-{id}"))
        .spawn(move || session::run(sh, stream, peer, id, guard))
    {
        Ok(thread) => lock(&shared.conns).push(Conn {
            id,
            stream: clone,
            thread,
        }),
        Err(e) => {
            log::error!("spawn session thread: {e}");
            shared.events.error(&HostError::Spawn(e.to_string()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::queue::QueueLimits;
    use crate::types::{NoControl, NoEvents};
    use std::sync::atomic::AtomicUsize;
    use std::sync::Weak;

    #[derive(Default)]
    struct Starts(AtomicUsize);
    impl VideoSource for Starts {
        fn start(&self, _p: StreamParams, _sink: FrameSink) -> Result<(), SourceError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        fn request_keyframe(&self) {}
        fn stop(&self) {}
    }

    fn handle(id: u64) -> Arc<SessionHandle> {
        handle_as(id, "", mirror_protocol::AuthMode::NoAuth)
    }

    fn handle_as(id: u64, client_id: &str, auth: mirror_protocol::AuthMode) -> Arc<SessionHandle> {
        let info = ClientInfo {
            session_id: id,
            peer: "127.0.0.1:1".parse().unwrap(),
            name: format!("c{id}"),
            id: client_id.into(),
            auth,
        };
        let limits = QueueLimits {
            max_age: Duration::from_millis(250),
            max_frames: 8,
            max_bytes: 1 << 20,
            keyframe_retry: Duration::from_secs(1),
        };
        Arc::new(SessionHandle::new(id, info, limits))
    }

    #[test]
    fn replaced_session_cannot_take_the_source() {
        let src = Arc::new(Starts::default());
        let sh = Shared::new(
            ServerConfig::new("d", "i", "m", 35),
            src.clone(),
            Arc::new(NoEvents),
            Arc::new(NoControl),
        );
        let sink = |id| FrameSink::new(id, Weak::new(), Weak::new());
        let (b, c) = (handle(2), handle(3));
        assert_eq!(sh.activate(&b, None), Activation::Active);
        // C replaces B and starts streaming; B's START was already waiting.
        assert_eq!(sh.activate(&c, None), Activation::Active);
        assert!(sh
            .start_source(3, StreamParams::default(), sink(3))
            .unwrap());
        assert!(!sh
            .start_source(2, StreamParams::default(), sink(2))
            .unwrap());
        assert_eq!(sh.source_owner(), 3);
        assert_eq!(src.0.load(Ordering::SeqCst), 1);
    }

    /// A token session whose key was revoked between its key lookup and its
    /// activation must not replace (kick) the legitimate active client.
    #[test]
    fn revoked_session_cannot_replace_the_active_client() {
        use mirror_protocol::AuthMode;
        let sh = Shared::new(
            ServerConfig::new("d", "i", "m", 35),
            Arc::new(Starts::default()),
            Arc::new(NoEvents),
            Arc::new(NoControl),
        );
        lock(&sh.auth)
            .store
            .put("legit", "L", PairingKey::from_bytes([1; 32]), 1)
            .unwrap();
        let legit = handle_as(1, "legit", AuthMode::Token);
        let k1 = PairingKey::from_bytes([1; 32]);
        assert_eq!(sh.activate(&legit, Some(&k1)), Activation::Active);
        // "gone" passed its key lookup, then was revoked.
        let gone = handle_as(2, "gone", AuthMode::Pin);
        assert_eq!(sh.activate(&gone, Some(&k1)), Activation::Revoked);
        assert_eq!(lock(&sh.active).as_ref().map(|h| h.id), Some(1));
        assert!(!legit.is_closed(), "the active client was not kicked");
        // `none` sessions have no pairing to check.
        assert_eq!(
            sh.activate(&handle_as(3, "x", AuthMode::NoAuth), None),
            Activation::Active
        );
    }

    fn shared() -> Arc<Shared> {
        Arc::new(Shared::new(
            ServerConfig::new("d", "i", "m", 35),
            Arc::new(Starts::default()),
            Arc::new(NoEvents),
            Arc::new(NoControl),
        ))
    }

    /// Revoked, then paired again at once (same `clientId`, new key): the
    /// session that used the revoked key is still refused.
    #[test]
    fn session_with_a_replaced_key_is_refused() {
        use mirror_protocol::AuthMode;
        let sh = shared();
        let old = PairingKey::from_bytes([1; 32]);
        let new = PairingKey::from_bytes([2; 32]);
        let _ = lock(&sh.auth).store.put_unsaved("mac", "M", new.clone(), 1);
        let stale = handle_as(1, "mac", AuthMode::Token);
        assert_eq!(sh.activate(&stale, Some(&old)), Activation::Revoked);
        assert_eq!(sh.activate(&stale, None), Activation::Revoked);
        assert_eq!(sh.activate(&stale, Some(&new)), Activation::Active);
    }

    #[test]
    fn no_activation_while_stopping() {
        let sh = shared();
        sh.stopping.store(true, Ordering::SeqCst);
        assert_eq!(sh.activate(&handle(1), None), Activation::Stopping);
        assert!(lock(&sh.active).is_none());
    }

    /// A newer session's input is never mapped with the previous session's
    /// config.
    #[test]
    fn starting_the_source_forgets_the_old_config() {
        let sh = shared();
        *lock(&sh.last_config) = Some(Arc::new(VideoConfig {
            width: 1,
            height: 1,
            display_width: 1,
            display_height: 1,
            rotation: 0,
            sps_pps: Vec::new(),
        }));
        let h = handle(1);
        sh.activate(&h, None);
        let sink = FrameSink::new(1, Weak::new(), Weak::new());
        assert!(sh.start_source(1, StreamParams::default(), sink).unwrap());
        assert!(lock(&sh.last_config).is_none());
    }

    /// A LAN host in a connect loop evicts its own pending handshakes on
    /// every connection; the warning about it must be rate-limited, not one
    /// logcat line per connection.
    #[test]
    fn pending_eviction_warnings_are_throttled() {
        crate::throttle::capture::install();
        let mut cfg = ServerConfig::new("d", "i", "m", 35);
        cfg.max_pending_handshakes_per_ip = 1;
        let sh = Arc::new(Shared::new(
            cfg,
            Arc::new(Starts::default()),
            Arc::new(NoEvents),
            Arc::new(NoControl),
        ));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        // A peer address no other test uses, so only this test's lines count.
        let peer: SocketAddr = "10.77.0.1:4000".parse().unwrap();
        let mut clients = Vec::new();
        // A rejected non-LAN peer just before does not hide the warning.
        clients.push(TcpStream::connect(addr).unwrap());
        on_accept(
            &sh,
            listener.accept().unwrap().0,
            "8.8.4.4:1".parse().unwrap(),
        );
        for _ in 0..20 {
            clients.push(TcpStream::connect(addr).unwrap());
            let (stream, _) = listener.accept().unwrap();
            on_accept(&sh, stream, peer);
        }
        let warns = crate::throttle::capture::count(
            log::Level::Warn,
            &["too many pending handshakes", "10.77.0.1"],
        );
        assert_eq!(warns, 1, "19 evictions, one warning per interval");
        sh.stopping.store(true, Ordering::SeqCst);
        for c in std::mem::take(&mut *lock(&sh.conns)) {
            let _ = c.stream.shutdown(Shutdown::Both);
            c.thread.join().unwrap();
        }
    }

    /// `on_accept` a loopback connection as if it came from `peer`; returns
    /// the client end.
    fn accept_as(sh: &Arc<Shared>, l: &TcpListener, peer: &str) -> TcpStream {
        let c = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (stream, _) = l.accept().unwrap();
        on_accept(sh, stream, peer.parse().unwrap());
        c
    }

    /// Wait for every connection thread of `sh` to end.
    fn join_conns(sh: &Shared) {
        for c in std::mem::take(&mut *lock(&sh.conns)) {
            c.thread.join().unwrap();
        }
    }

    /// Unknown frames during the handshake are counted and logged once,
    /// not one line each, and that line is throttled across handshakes.
    #[test]
    fn unknown_handshake_frames_are_logged_once() {
        use mirror_protocol::{encode, MAGIC};
        crate::throttle::capture::install();
        let sh = shared();
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut out = MAGIC.to_vec();
        for _ in 0..50 {
            out.extend(encode(&Message::Unknown {
                ty: 0x7f,
                flags: 0,
                payload: vec![1, 2, 3],
            }));
        }
        for port in 1..=3 {
            let mut c = accept_as(&sh, &l, &format!("10.77.0.3:{port}"));
            std::io::Write::write_all(&mut c, &out).unwrap();
            c.shutdown(Shutdown::Write).unwrap();
            join_conns(&sh);
        }
        let lines = crate::throttle::capture::count(log::Level::Debug, &["10.77.0.3", "skipp"]);
        assert_eq!(lines, 1);
        assert_eq!(
            crate::throttle::capture::count(log::Level::Debug, &["10.77.0.3", "skipped 50 "]),
            1
        );
    }

    /// A debug-level handshake failure (garbage) does not suppress the next
    /// info-level one.
    #[test]
    fn debug_handshake_failures_do_not_suppress_info_ones() {
        crate::throttle::capture::install();
        let sh = shared();
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut c = accept_as(&sh, &l, "10.77.0.4:1");
        std::io::Write::write_all(&mut c, b"XXXX").unwrap(); // bad magic
        join_conns(&sh);
        drop(c);
        drop(accept_as(&sh, &l, "10.77.0.4:2")); // closed during handshake
        join_conns(&sh);
        let info = |lvl| crate::throttle::capture::count(lvl, &["10.77.0.4", "handshake failed"]);
        assert_eq!(info(log::Level::Debug), 1);
        assert_eq!(info(log::Level::Info), 1);
    }

    /// Pairing events, recorded; `on_paired` runs inside `paired` (a
    /// deterministic window between a rotation and its upcall).
    #[derive(Default)]
    struct PinEvents {
        log: Mutex<Vec<String>>,
        on_paired: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    }
    impl HostEvents for PinEvents {
        fn pin_changed(&self, pin: &str) {
            lock(&self.log).push(format!("pin {pin}"));
        }
        fn paired(&self, _c: &PairedClient) {
            lock(&self.log).push("paired".into());
            if let Some(f) = lock(&self.on_paired).take() {
                f();
            }
        }
        fn pairing_failed(&self, _p: SocketAddr, left: u32, locked: Option<Duration>) {
            lock(&self.log).push(format!("failed {left} {locked:?}"));
        }
    }

    fn pin_shared() -> (Arc<Shared>, Arc<PinEvents>) {
        let ev = Arc::new(PinEvents::default());
        let sh = Arc::new(Shared::new(
            ServerConfig::new("d", "i", "m", 35),
            Arc::new(Starts::default()),
            ev.clone(),
            Arc::new(NoControl),
        ));
        (sh, ev)
    }

    /// "New PIN" between a pairing's rotation and its `pin_changed` upcall:
    /// the stale upcall is skipped (it would put a dead PIN on screen).
    #[test]
    fn new_pin_during_pairing_skips_the_stale_pin_changed() {
        let (sh, ev) = pin_shared();
        let weak = Arc::downgrade(&sh);
        *lock(&ev.on_paired) = Some(Box::new(move || {
            lock(&weak.upgrade().unwrap().auth).pin.reset(); // Server::new_pin
        }));
        let a = sh.admit_pin_attempt("10.0.0.1:1".parse().unwrap()).unwrap();
        assert!(a.succeeded("c", "C", PairingKey::from_bytes([1; 32])));
        assert_eq!(*lock(&ev.log), ["paired"]);
        // Without "New PIN" in between, the rotation is reported.
        let a = sh.admit_pin_attempt("10.0.0.1:1".parse().unwrap()).unwrap();
        assert!(a.succeeded("c", "C", PairingKey::from_bytes([1; 32])));
        let pin = lock(&sh.auth).pin.pin().to_owned();
        assert_eq!(*lock(&ev.log), ["paired", "paired", &format!("pin {pin}")]);
    }

    /// A PIN failure counted before "New PIN" is not reported after it: the
    /// lockout it reports was cleared.
    #[test]
    fn pin_failure_predating_a_new_pin_is_not_reported() {
        let (sh, ev) = pin_shared();
        let peer = "10.0.0.1:1".parse().unwrap();
        let locked = PinFailure {
            attempts_left: 0,
            locked_for: Some(Duration::from_secs(30)),
            rotated: true,
        };
        let resets = lock(&sh.auth).pin.resets();
        lock(&sh.auth).pin.reset();
        sh.report_pin_failure(peer, locked, resets);
        assert!(lock(&ev.log).is_empty());
        sh.report_pin_failure(peer, locked, resets + 1);
        assert_eq!(*lock(&ev.log), ["failed 0 Some(30s)"]);
        // Same for the rotation that came with it.
        let gen = lock(&sh.auth).pin.gen();
        lock(&sh.auth).pin.reset();
        sh.report_pin_rotation(gen);
        assert_eq!(lock(&ev.log).len(), 1);
    }

    /// `pairing_failed_at` carries the "New PIN" count the failure was
    /// counted under (the host's last guard against a reset racing the
    /// upcall); a host that overrides only `pairing_failed` still gets it.
    #[test]
    fn pin_failure_carries_its_reset_count() {
        #[derive(Default)]
        struct AtEvents(Mutex<Vec<(u32, u64)>>);
        impl HostEvents for AtEvents {
            fn pairing_failed_at(
                &self,
                _p: SocketAddr,
                left: u32,
                _l: Option<Duration>,
                resets: u64,
            ) {
                lock(&self.0).push((left, resets));
            }
        }
        let ev = Arc::new(AtEvents::default());
        let sh = Arc::new(Shared::new(
            ServerConfig::new("d", "i", "m", 35),
            Arc::new(Starts::default()),
            ev.clone(),
            Arc::new(NoControl),
        ));
        let peer = "10.0.0.1:1".parse().unwrap();
        lock(&sh.auth).pin.reset();
        lock(&sh.auth).pin.reset();
        drop(sh.admit_pin_attempt(peer).unwrap());
        let left = crate::pairing::MAX_PIN_FAILURES - 1;
        assert_eq!(*lock(&ev.0), [(left, 2)]);
        // The default forwards to `pairing_failed`.
        let (sh, ev) = pin_shared();
        drop(sh.admit_pin_attempt(peer).unwrap());
        assert_eq!(*lock(&ev.log), [format!("failed {left} None")]);
    }

    /// A real PIN attempt admitted before "New PIN" and failing after it is
    /// neither reported nor counted: with the fresh attempts all in flight
    /// it would otherwise start a lockout.
    #[test]
    fn pin_attempt_predating_a_new_pin_is_not_counted_or_reported() {
        let (sh, ev) = pin_shared();
        let peer = "10.0.0.1:1".parse().unwrap();
        let stale = sh.admit_pin_attempt(peer).unwrap();
        lock(&sh.auth).pin.reset(); // Server::new_pin
        let fresh: Vec<_> = (0..crate::pairing::MAX_PIN_FAILURES)
            .map(|_| sh.admit_pin_attempt(peer).unwrap())
            .collect();
        drop(stale);
        let log = lock(&ev.log).clone();
        assert!(log.is_empty(), "{log:?}");
        // A fresh one still counts (and, all five being in flight, locks out).
        drop(fresh);
        assert_eq!(lock(&ev.log)[0], "failed 0 Some(30s)");
    }

    /// With a fixed PIN, "New PIN" keeps the PIN, so an attempt admitted
    /// before it was a real guess: it is counted and reported.
    #[test]
    fn a_stale_attempt_on_a_fixed_pin_still_counts() {
        let ev = Arc::new(PinEvents::default());
        let mut cfg = ServerConfig::new("d", "i", "m", 35);
        cfg.fixed_pin = Some("123456".into());
        let sh = Arc::new(Shared::new(
            cfg,
            Arc::new(Starts::default()),
            ev.clone(),
            Arc::new(NoControl),
        ));
        let peer = "10.0.0.1:1".parse().unwrap();
        let stale = sh.admit_pin_attempt(peer).unwrap();
        lock(&sh.auth).pin.reset(); // Server::new_pin
        drop(stale);
        // One guard: formatting the message must not lock `log` again.
        let log = lock(&ev.log).clone();
        assert_eq!(log.len(), 1, "{log:?}");
        let want = format!("failed {} None", crate::pairing::MAX_PIN_FAILURES - 1);
        assert!(log[0].starts_with(&want), "{log:?}");
    }

    /// A refusal during a lockout that "New PIN" has since cleared is not
    /// reported (the host would show a stale lockout).
    #[test]
    fn refusal_predating_a_new_pin_is_not_reported() {
        let (sh, ev) = pin_shared();
        let peer = "10.0.0.1:1".parse().unwrap();
        for _ in 0..crate::pairing::MAX_PIN_FAILURES {
            drop(sh.admit_pin_attempt(peer).unwrap());
        }
        assert!(sh.admit_pin_attempt(peer).is_err(), "locked out");
        let n = lock(&ev.log).len();
        assert!(
            lock(&ev.log)[n - 1].starts_with("failed 0 Some("),
            "refusal reported"
        );
        let resets = lock(&sh.auth).pin.resets();
        lock(&sh.auth).pin.reset();
        let d = Duration::from_secs(30);
        sh.report_refusal(peer, d, true, resets);
        assert_eq!(lock(&ev.log).len(), n);
        sh.report_refusal(peer, d, true, resets + 1);
        assert_eq!(lock(&ev.log).len(), n + 1);
    }

    /// A handshake evicted by a newer one cannot complete; its guard (and a
    /// completed one) leaves the pending set.
    #[test]
    fn evicted_pending_guard_cannot_complete() {
        let mut cfg = ServerConfig::new("d", "i", "m", 35);
        cfg.max_pending_handshakes = 1;
        let sh = Arc::new(Shared::new(
            cfg,
            Arc::new(Starts::default()),
            Arc::new(NoEvents),
            Arc::new(NoControl),
        ));
        let ip = "10.0.0.1".parse().unwrap();
        let guard = |id, evicts| {
            assert_eq!(lock(&sh.pending).admit(id, ip), evicts);
            PendingGuard {
                shared: sh.clone(),
                id,
            }
        };
        let first = guard(1, None);
        let second = guard(2, Some(1));
        assert!(!first.complete());
        assert!(second.complete());
        drop(guard(3, None));
        assert_eq!(
            lock(&sh.pending).admit(4, ip),
            None,
            "the dropped guard left"
        );
    }
}
