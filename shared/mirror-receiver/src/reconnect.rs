//! Reconnect supervisor (PLAN.md §5): keeps a [`Client`] alive across
//! network hiccups with backoff 0.5, 1, 2, 4, 5, 5, … s for at most 30 s.
//!
//! # What is retried
//!
//! Only failures that a later attempt can plausibly fix: the TCP connection
//! dropping ([`DisconnectReason::ConnectionClosed`]), timeouts (connect,
//! handshake, liveness), socket errors (refused while the phone service
//! restarts, reset on a Wi-Fi change) and stream corruption
//! ([`DisconnectReason::Protocol`]).
//!
//! **No server BYE is retried.** A BYE is a deliberate end by the phone:
//!
//! | BYE reason | Why not reconnect |
//! |---|---|
//! | `stopped_by_user` | The phone user stopped sharing; reconnecting would fight them. |
//! | `projection_revoked` | Screen capture ended (lock screen, "Stop sharing" chip); needs consent on the phone. |
//! | `replaced` | Another receiver took over; retrying would make two receivers evict each other in a loop. |
//! | `auth_failed` | Same credentials fail again, and failures count toward the phone's PIN lockout. |
//! | `proto_mismatch` | Permanent until one side is updated. |
//! | unknown | A reason from a newer phone; treated as deliberate. |
//!
//! Also final: local close, protocol-version mismatch and every **auth
//! outcome** ([`DisconnectReason::is_auth_outcome`]: pairing required, wrong
//! PIN, lockout, rejected or unverifiable key, no usable auth mode). A wrong
//! PIN would only burn more of the phone's attempts, and the others need the
//! user. A fresh [`Supervisor::start`] with a PIN is a new attempt.
//!
//! A record that fails authentication (tampering, a broken middlebox) ends
//! the connection as [`DisconnectReason::Protocol`] and *is* retried: the
//! next connection starts a fresh secure channel.
//!
//! # The PIN
//!
//! [`ClientConfig::pin`] is sent at most once: it is dropped as soon as an
//! attempt has sent it in an AUTH, whatever the outcome. After a pairing the
//! stored key is used, and a stale PIN (the phone rotates it after every
//! pairing) must never be replayed. That also covers an attempt that fails
//! retryably after the AUTH went out (e.g. the link drops before
//! AUTH_RESULT): the phone may already have paired and rotated its PIN, so
//! a replay would only burn a lockout attempt; the next attempt uses a key
//! if one was stored, else ends with
//! [`DisconnectReason::NeedsPin`].
//!
//! The 30 s budget runs from the moment the connection was lost (connect
//! time of failed attempts included). A failure of the very first connect is
//! final unless [`ReconnectPolicy::retry_initial`] is set, so a wrong IP
//! fails fast.
//!
//! # When the budget resets
//!
//! A completed handshake alone does not end an outage: a phone that accepts
//! the handshake and then drops at once (e.g. its encoder cannot start)
//! would otherwise be redialled every 0.5 s forever. Only a session that
//! stayed up for at least [`ReconnectPolicy::stable_after`] (10 s by
//! default; see [`ReconnectPolicy::session_was_stable`]) resets the budget
//! and the attempt counter. After a shorter session the outage simply
//! continues: its start time and attempt count carry forward (the short
//! session's uptime counts toward the budget), so `GaveUp` still arrives
//! within the budget. Uptime is used rather than "VIDEO_CONFIG seen"
//! because it needs no hook into the client and also covers a phone that
//! sends a config and then dies.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crossbeam_channel::{bounded, select, Receiver, Sender};
use mirror_protocol::Message;

use crate::client::{Client, ClientConfig, ClientEvent, DisconnectReason, Handle, SendError};

/// Backoff schedule and budget.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconnectPolicy {
    /// Delay before attempt 1, 2, …; the last entry repeats.
    pub delays: Vec<Duration>,
    /// Give up once the next delay would end later than this after the
    /// connection was lost.
    pub budget: Duration,
    /// Also retry when the very first connect fails.
    pub retry_initial: bool,
    /// A session that stayed up at least this long ends the outage (resets
    /// the budget and attempt counter); a shorter one does not.
    pub stable_after: Duration,
}

impl Default for ReconnectPolicy {
    fn default() -> Self {
        ReconnectPolicy {
            delays: [500, 1000, 2000, 4000, 5000]
                .into_iter()
                .map(Duration::from_millis)
                .collect(),
            budget: Duration::from_secs(30),
            retry_initial: false,
            stable_after: Duration::from_secs(10),
        }
    }
}

impl ReconnectPolicy {
    /// Delay before reconnect attempt `attempt` (1-based; 0 is treated as 1)
    /// when `elapsed` has passed since the connection was lost, or `None` to
    /// give up. Pure.
    pub fn next_delay(&self, attempt: u32, elapsed: Duration) -> Option<Duration> {
        let last = self.delays.len().checked_sub(1)?;
        let i = (attempt.max(1) as usize - 1).min(last);
        let d = self.delays[i];
        (elapsed.checked_add(d)? <= self.budget).then_some(d)
    }

    /// True when a session that was up for `uptime` was useful enough to end
    /// the outage (reset budget and attempts). Pure.
    pub fn session_was_stable(&self, uptime: Duration) -> bool {
        uptime >= self.stable_after
    }

    /// The full sequence of delays, assuming attempts themselves take no
    /// time (an upper bound on the number of attempts). Pure.
    pub fn schedule(&self) -> Vec<Duration> {
        let mut out = Vec::new();
        let mut elapsed = Duration::ZERO;
        while let Some(d) = self.next_delay(out.len() as u32 + 1, elapsed) {
            if d.is_zero() && out.len() > 1024 {
                break; // all-zero schedule: bound the list
            }
            out.push(d);
            elapsed += d;
        }
        out
    }
}

/// True when the supervisor should try again after `reason` (see the
/// module docs for the table).
pub fn is_retryable(reason: &DisconnectReason) -> bool {
    use DisconnectReason::*;
    match reason {
        ConnectionClosed | Timeout(_) | Io { .. } | Protocol(_) => true,
        Closed | Bye(_) | ProtoMismatch { .. } => false,
        r => {
            debug_assert!(r.is_auth_outcome(), "{r:?}");
            false
        }
    }
}

struct Shared {
    events: Sender<ClientEvent>,
    /// Also each client's cancel flag, so stopping unblocks a handshake or
    /// a client blocked on a full event channel.
    stopping: Arc<AtomicBool>,
    /// Send side of the live session; the supervisor thread owns the Client.
    current: Mutex<Option<Handle>>,
}

impl Shared {
    fn slot(&self) -> MutexGuard<'_, Option<Handle>> {
        // A panic while holding the lock cannot leave the Option invalid.
        self.current.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn stopping(&self) -> bool {
        self.stopping.load(Ordering::Acquire)
    }

    /// Blocking send that gives up once stopping and the channel is full.
    fn emit(&self, mut ev: ClientEvent) {
        loop {
            match self.events.send_timeout(ev, Duration::from_millis(50)) {
                Ok(()) => return,
                Err(crossbeam_channel::SendTimeoutError::Timeout(e)) if !self.stopping() => ev = e,
                Err(_) => return,
            }
        }
    }
}

/// Cloneable send side of a [`Supervisor`]: usable from any thread (e.g.
/// the UI thread while the decode thread owns the supervisor). Never blocks.
#[derive(Clone)]
pub struct SessionLink {
    shared: Arc<Shared>,
}

impl std::fmt::Debug for SessionLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionLink")
            .field("connected", &self.is_connected())
            .finish()
    }
}

impl SessionLink {
    /// True while a session is up.
    pub fn is_connected(&self) -> bool {
        self.shared
            .slot()
            .as_ref()
            .is_some_and(|c| !c.is_finished())
    }

    /// True while the current session is authenticated (`pin`/`token`) and
    /// the phone's latest STATUS was `control_available`.
    pub fn control_available(&self) -> bool {
        self.shared
            .slot()
            .as_ref()
            .is_some_and(Handle::control_available)
    }

    /// Latest RTT of the current session.
    pub fn rtt(&self) -> Option<Duration> {
        self.shared.slot().as_ref().and_then(Handle::rtt)
    }

    /// Queue a message on the current session ([`SendError::Disconnected`]
    /// while reconnecting).
    pub fn send(&self, msg: Message) -> Result<(), SendError> {
        match self.shared.slot().as_ref() {
            Some(c) => c.send(msg),
            None => Err(SendError::Disconnected),
        }
    }

    /// Queue an input message; refused unless
    /// [`control_available`](Self::control_available) (see
    /// [`Client::send_control`]).
    pub fn send_control(&self, msg: Message) -> Result<(), SendError> {
        match self.shared.slot().as_ref() {
            Some(c) => c.send_control(msg),
            None if crate::client::is_control_message(&msg) => Err(SendError::Disconnected),
            None => Err(SendError::NotControl),
        }
    }
}

/// Keeps one session alive. All events (the clients' plus
/// [`ClientEvent::Reconnecting`], [`ClientEvent::GaveUp`] and
/// [`ClientEvent::Stopped`]) arrive on one channel; `GaveUp`/`Stopped` is
/// always the last event.
pub struct Supervisor {
    shared: Arc<Shared>,
    events: Receiver<ClientEvent>,
    stop: Sender<()>,
    thread: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for Supervisor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Supervisor")
            .field("running", &self.thread.is_some())
            .finish()
    }
}

impl Supervisor {
    /// Start connecting in the background. Never blocks.
    pub fn start(addr: SocketAddr, config: ClientConfig, policy: ReconnectPolicy) -> Supervisor {
        let (tx, rx) = bounded(config.event_capacity.max(1));
        let (stop_tx, stop_rx) = bounded(1);
        let shared = Arc::new(Shared {
            events: tx.clone(),
            stopping: Arc::new(AtomicBool::new(false)),
            current: Mutex::new(None),
        });
        let thread = {
            let shared = Arc::clone(&shared);
            let rx = rx.clone();
            thread::Builder::new()
                .name("mirror-reconnect".into())
                .spawn(move || run(&shared, addr, config, policy, tx, rx, stop_rx))
        };
        let thread = match thread {
            Ok(t) => Some(t),
            Err(e) => {
                shared.emit(ClientEvent::Stopped(DisconnectReason::Io {
                    kind: e.kind(),
                    message: format!("cannot spawn supervisor thread: {e}"),
                }));
                None
            }
        };
        Supervisor {
            shared,
            events: rx,
            stop: stop_tx,
            thread,
        }
    }

    pub fn events(&self) -> Receiver<ClientEvent> {
        self.events.clone()
    }

    /// A cloneable handle for sending from other threads.
    pub fn link(&self) -> SessionLink {
        SessionLink {
            shared: Arc::clone(&self.shared),
        }
    }

    /// True while a session is up.
    pub fn is_connected(&self) -> bool {
        self.link().is_connected()
    }

    /// See [`SessionLink::control_available`].
    pub fn control_available(&self) -> bool {
        self.link().control_available()
    }

    /// Latest RTT of the current session.
    pub fn rtt(&self) -> Option<Duration> {
        self.link().rtt()
    }

    pub fn request_keyframe(&self) -> Result<(), SendError> {
        self.send(Message::RequestKeyframe)
    }

    /// Queue a message on the current session ([`SendError::Disconnected`]
    /// while reconnecting).
    pub fn send(&self, msg: Message) -> Result<(), SendError> {
        self.link().send(msg)
    }

    /// See [`SessionLink::send_control`].
    pub fn send_control(&self, msg: Message) -> Result<(), SendError> {
        self.link().send_control(msg)
    }

    /// Close the current session (BYE), stop retrying and join the
    /// supervisor thread. Idempotent; also runs on drop. An in-flight
    /// handshake is abandoned within 50 ms, but an in-flight TCP connect is
    /// waited for (at most [`Timeouts::connect`](crate::client::Timeouts)),
    /// as is a BYE blocked on a full send buffer (at most
    /// [`BYE_GRACE`](crate::client::BYE_GRACE)).
    pub fn close(&mut self) {
        let Some(thread) = self.thread.take() else {
            return;
        };
        self.shared.stopping.store(true, Ordering::Release);
        let _ = self.stop.try_send(());
        let _ = thread.join();
    }
}

impl Drop for Supervisor {
    fn drop(&mut self) {
        self.close();
    }
}

/// Bookkeeping for one outage (from connection loss to reconnect or give-up).
struct Outage {
    since: Instant,
    attempts: u32,
    last: DisconnectReason,
}

fn run(
    shared: &Shared,
    addr: SocketAddr,
    mut config: ClientConfig,
    policy: ReconnectPolicy,
    tx: Sender<ClientEvent>,
    rx: Receiver<ClientEvent>,
    stop: Receiver<()>,
) {
    let mut first = true;
    let mut outage: Option<Outage> = None;
    loop {
        if shared.stopping() {
            shared.emit(ClientEvent::Stopped(DisconnectReason::Closed));
            return;
        }
        let cancel = Arc::clone(&shared.stopping);
        let mut pin_sent = false;
        let attempt = Client::establish(
            addr,
            config.clone(),
            tx.clone(),
            rx.clone(),
            cancel,
            &mut pin_sent,
        );
        if pin_sent {
            config.pin = None; // never replay a PIN (module docs, "The PIN")
        }
        match attempt {
            Ok(mut client) => {
                first = false;
                // Authenticated otherwise (token/none): the PIN is not
                // needed any more either.
                config.pin = None;
                if shared.stopping() {
                    drop(client); // never started: just hangs up
                    shared.emit(ClientEvent::Stopped(DisconnectReason::Closed));
                    return;
                }
                // Publish the send handle before `Connected` is observable.
                *shared.slot() = Some(client.handle());
                let up_since = Instant::now();
                let started = client.start();
                let reason = match started {
                    Err(r) => r,
                    Ok(()) => select! {
                        recv(client.done()) -> r => r.unwrap_or(DisconnectReason::Closed),
                        recv(stop) -> _ => DisconnectReason::Closed,
                    },
                };
                *shared.slot() = None;
                drop(client); // BYE if still up (close), join threads
                if shared.stopping() || !is_retryable(&reason) {
                    let reason = if shared.stopping() {
                        DisconnectReason::Closed
                    } else {
                        reason
                    };
                    shared.emit(ClientEvent::Stopped(reason));
                    return;
                }
                match outage.as_mut() {
                    // Short session: the outage goes on (budget + attempts).
                    Some(o) if !policy.session_was_stable(up_since.elapsed()) => o.last = reason,
                    _ => {
                        outage = Some(Outage {
                            since: Instant::now(),
                            attempts: 0,
                            last: reason,
                        })
                    }
                }
            }
            Err(reason) => {
                if shared.stopping() {
                    shared.emit(ClientEvent::Stopped(DisconnectReason::Closed));
                    return;
                }
                if (first && !policy.retry_initial) || !is_retryable(&reason) {
                    shared.emit(ClientEvent::Stopped(reason));
                    return;
                }
                first = false;
                match outage.as_mut() {
                    Some(o) => o.last = reason,
                    None => {
                        outage = Some(Outage {
                            since: Instant::now(),
                            attempts: 0,
                            last: reason,
                        })
                    }
                }
            }
        }

        let Some(o) = outage.as_mut() else {
            continue; // unreachable: every non-returning path sets it
        };
        let attempt = o.attempts.saturating_add(1);
        let Some(delay) = policy.next_delay(attempt, o.since.elapsed()) else {
            shared.emit(ClientEvent::GaveUp {
                attempts: o.attempts,
                last: o.last.clone(),
            });
            return;
        };
        o.attempts = attempt;
        shared.emit(ClientEvent::Reconnecting { attempt, delay });
        select! {
            recv(stop) -> _ => {
                shared.emit(ClientEvent::Stopped(DisconnectReason::Closed));
                return;
            }
            default(delay) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::TimeoutKind;
    use mirror_protocol::ByeReason;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn default_delays_follow_plan() {
        let p = ReconnectPolicy::default();
        let got: Vec<_> = (1..=7).map(|a| p.next_delay(a, Duration::ZERO)).collect();
        let want: Vec<_> = [500, 1000, 2000, 4000, 5000, 5000, 5000]
            .map(|m| Some(ms(m)))
            .to_vec();
        assert_eq!(got, want);
        assert_eq!(p.next_delay(0, Duration::ZERO), Some(ms(500)));
    }

    #[test]
    fn default_schedule_fits_30s_budget() {
        let s = ReconnectPolicy::default().schedule();
        assert_eq!(
            s,
            [500, 1000, 2000, 4000, 5000, 5000, 5000, 5000]
                .map(ms)
                .to_vec()
        );
        let total: Duration = s.iter().sum();
        assert!(total <= Duration::from_secs(30), "{total:?}");
    }

    #[test]
    fn gives_up_when_delay_would_exceed_budget() {
        let p = ReconnectPolicy::default();
        assert_eq!(p.next_delay(5, Duration::from_secs(25)), Some(ms(5000)));
        assert_eq!(p.next_delay(5, ms(25_001)), None);
        assert_eq!(p.next_delay(1, Duration::from_secs(30)), None);
        assert_eq!(p.next_delay(1, Duration::MAX), None, "no overflow");
    }

    #[test]
    fn empty_and_zero_schedules_are_bounded() {
        let empty = ReconnectPolicy {
            delays: vec![],
            ..Default::default()
        };
        assert_eq!(empty.next_delay(1, Duration::ZERO), None);
        assert!(empty.schedule().is_empty());
        let zero = ReconnectPolicy {
            delays: vec![Duration::ZERO],
            ..Default::default()
        };
        assert!(zero.schedule().len() <= 1026);
    }

    #[test]
    fn only_a_stable_session_ends_the_outage() {
        let p = ReconnectPolicy::default();
        assert_eq!(p.stable_after, Duration::from_secs(10));
        assert!(!p.session_was_stable(Duration::ZERO));
        assert!(!p.session_was_stable(ms(9_999)));
        assert!(p.session_was_stable(Duration::from_secs(10)));
        assert!(p.session_was_stable(Duration::MAX));
    }

    #[test]
    fn retry_classification() {
        use DisconnectReason::*;
        for r in [
            ConnectionClosed,
            Timeout(TimeoutKind::Liveness),
            Timeout(TimeoutKind::Connect),
            Protocol("x".into()),
            Io {
                kind: std::io::ErrorKind::ConnectionRefused,
                message: String::new(),
            },
        ] {
            assert!(is_retryable(&r), "{r:?} should retry");
        }
        for r in [
            Closed,
            Bye(ByeReason::StoppedByUser),
            Bye(ByeReason::ProjectionRevoked),
            Bye(ByeReason::Replaced),
            Bye(ByeReason::AuthFailed),
            Bye(ByeReason::ProtoMismatch),
            Bye(ByeReason::Unknown),
            ProtoMismatch { ours: 1, theirs: 2 },
            AuthFailed { reason: None },
            NeedsPin {
                device_id: "d".into(),
                device_name: "n".into(),
            },
            WrongPin,
            LockedOut {
                retry_after: Duration::from_secs(30),
            },
            PairingRemoved {
                device_id: "d".into(),
            },
            IdentityChanged {
                device_id: "d".into(),
            },
            AuthUnsupported { offered: vec![] },
        ] {
            assert!(!is_retryable(&r), "{r:?} should not retry");
        }
    }
}
