//! One client connection: handshake, reader loop, writer thread, teardown.
//!
//! The handshake runs in plaintext frames (spec §3). From AUTH_RESULT
//! `ok:true` on, every frame in both directions is an encrypted record
//! (spec §5): the reader opens them with an [`Opener`], the writer thread
//! seals them with a [`Sealer`]. A record-layer error closes the connection
//! without a BYE (it could not be authenticated anyway).

use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use mirror_protocol::auth::PairingKey;
use mirror_protocol::handshake::{Established, HandshakeError, ServerHandshake, ServerStep};
use mirror_protocol::secure::{Opener, Sealer};
use mirror_protocol::wire::ty;
use mirror_protocol::{
    encode, AuthMode, AuthReason, Bye, ByeReason, ClientHello, Decoder, Message, ProtocolError,
    ServerHello, MAGIC, MAX_CLIENT_PAYLOAD, PROTO_VERSION,
};
use zeroize::Zeroize;

use crate::control::{dispatch_control, is_control};
use crate::queue::{QueueLimits, SendQueue};
use crate::server::{lock, Activation, PendingGuard, PinAttempt, Shared};
use crate::sink::FrameSink;
use crate::throttle::{log_throttled, short, Throttle};
use crate::types::{ClientInfo, ClientState, DisconnectReason, HostError, StreamParams};

/// Longest we keep reading after sending a handshake-failure BYE, so the
/// peer receives it instead of a reset.
const FAIL_LINGER: Duration = Duration::from_millis(500);

/// Minimum interval between "control dropped" log lines per session.
const DROP_LOG_INTERVAL: Duration = Duration::from_secs(10);

/// Minimum interval between client REQUEST_KEYFRAMEs passed on to the
/// source, so a client cannot flood the encoder with requests. See
/// [`KeyframeGate`].
const CLIENT_KEYFRAME_INTERVAL: Duration = Duration::from_millis(250);

/// How far past the liveness timeout the reader may notice a silent peer,
/// so it can reuse its socket read timeout (see `read_loop`).
const IDLE_SLACK: Duration = Duration::from_millis(10);

/// Writer buffer capacity kept between records (larger frames reallocate).
const KEEP_WRITE_BUF: usize = 1 << 20;

/// The writer seals messages that are already queued into one buffer, up
/// to this many bytes, and writes them with one syscall (TCP_NODELAY would
/// otherwise send each small record in its own segment). See [`seal_batch`].
const MAX_WRITE_BATCH: usize = 256 * 1024;

/// Longest `clientId` accepted in CLIENT_HELLO, and the length `clientName`
/// is cut to for storage and display, in bytes. Both are stored in the
/// pairing store and shown in the phone's UI.
const MAX_CLIENT_FIELD: usize = 256;

/// Only sessions that proved knowledge of the PIN or a pairing key may
/// control the phone; `none` (devtools) never may.
pub(crate) fn mode_allows_control(mode: AuthMode) -> bool {
    matches!(mode, AuthMode::Pin | AuthMode::Token)
}

/// The authenticated session as seen by other threads.
pub(crate) struct SessionHandle {
    pub(crate) id: u64,
    pub(crate) info: ClientInfo,
    pub(crate) queue: Mutex<SendQueue>,
    pub(crate) cv: Condvar,
    /// Reason set by whoever ended the session from outside (replaced,
    /// server); reported instead of what the reader observed.
    end_reason: Mutex<Option<DisconnectReason>>,
    /// The reader loop has returned (signalled on `reader_cv`).
    reader_done: Mutex<bool>,
    reader_cv: Condvar,
}

impl SessionHandle {
    pub(crate) fn new(id: u64, info: ClientInfo, limits: QueueLimits) -> Self {
        SessionHandle {
            id,
            info,
            queue: Mutex::new(SendQueue::new(limits)),
            cv: Condvar::new(),
            end_reason: Mutex::new(None),
            reader_done: Mutex::new(false),
            reader_cv: Condvar::new(),
        }
    }

    fn set_reader_done(&self) {
        *lock(&self.reader_done) = true;
        self.reader_cv.notify_all();
    }

    /// Wait until the reader loop returned, at most `timeout`. True if it did.
    fn wait_reader_done(&self, timeout: Duration) -> bool {
        let g = lock(&self.reader_done);
        let (g, _) = self
            .reader_cv
            .wait_timeout_while(g, timeout, |done| !*done)
            .unwrap_or_else(|e| e.into_inner());
        *g
    }

    /// Queue a control message for the writer. False if the session is closing.
    pub(crate) fn push_control(&self, m: Message) -> bool {
        let ok = lock(&self.queue).push_control(m);
        self.cv.notify_one();
        ok
    }

    /// End the session from outside: BYE `bye` is the last message, then the
    /// writer half-closes the socket. False if it was already ending.
    pub(crate) fn finish(&self, bye: ByeReason, reason: DisconnectReason) -> bool {
        let mut q = lock(&self.queue);
        let queued = q.push_final(Message::ServerBye(Bye { reason: bye }));
        if queued {
            // Set while the queue is locked: teardown closes the queue and
            // then reads this, so a queued BYE always comes with its reason.
            lock(&self.end_reason).get_or_insert(reason);
        }
        drop(q);
        self.cv.notify_one();
        queued
    }

    /// End the session from outside without a final message: closes the
    /// queue (so no BYE can follow) and records `reason`. The caller then
    /// shuts the socket down. False if it was already ending.
    pub(crate) fn abort(&self, reason: DisconnectReason) -> bool {
        let mut q = lock(&self.queue);
        if q.is_closed() {
            return false;
        }
        q.close();
        lock(&self.end_reason).get_or_insert(reason);
        drop(q);
        self.cv.notify_one();
        true
    }

    fn close(&self) {
        lock(&self.queue).close();
        self.cv.notify_one();
    }

    pub(crate) fn is_closed(&self) -> bool {
        lock(&self.queue).is_closed()
    }
}

enum RecvError {
    /// Deadline / idle timeout passed.
    Timeout,
    /// Peer closed or socket error.
    Closed,
    /// Fatal decode or record error (bad magic, oversize, record failed
    /// authentication, ...).
    Protocol(ProtocolError),
    /// Non-fatal: one frame could not be parsed and was skipped.
    Malformed(ProtocolError),
}

enum Wait {
    /// Absolute deadline (handshake).
    Until(Instant),
    /// Read timeout, re-armed by every received byte. The caller decides
    /// whether it means the peer is gone (see [`Reader::last_rx`]).
    Idle(Duration),
}

/// Reading half: socket + plaintext decoder, then the record opener.
struct Reader {
    stream: TcpStream,
    dec: Decoder,
    /// Set once authenticated; from then on every byte goes here.
    opener: Option<Opener>,
    buf: Box<[u8]>,
    timeout: Option<Duration>,
    /// When bytes last arrived (liveness).
    last_rx: Instant,
}

impl Reader {
    fn new(stream: TcpStream) -> Self {
        Reader {
            stream,
            // Nothing legitimate from a receiver exceeds 64 KiB (TEXT included).
            dec: Decoder::new(true).with_max_payload(MAX_CLIENT_PAYLOAD),
            opener: None,
            buf: vec![0u8; 16 * 1024].into_boxed_slice(),
            timeout: None,
            last_rx: Instant::now(),
        }
    }

    /// Switch to records. Bytes the decoder already buffered past the
    /// client's last plaintext frame are the start of the record stream.
    fn start_records(&mut self, mut opener: Opener) {
        opener.push(&self.dec.take_buffered());
        self.opener = Some(opener);
    }

    fn set_timeout(&mut self, t: Duration) -> io::Result<()> {
        let t = t.max(Duration::from_millis(1));
        if self.timeout != Some(t) {
            self.stream.set_read_timeout(Some(t))?;
            self.timeout = Some(t);
        }
        Ok(())
    }

    fn recv(&mut self, wait: &Wait) -> Result<Message, RecvError> {
        loop {
            let next = match &mut self.opener {
                Some(o) => o.next(),
                None => self.dec.next(),
            };
            match next {
                Ok(Some(m)) => return Ok(m),
                Ok(None) => {}
                Err(e) if e.is_fatal() => return Err(RecvError::Protocol(e)),
                Err(e) => return Err(RecvError::Malformed(e)),
            }
            let t = match *wait {
                Wait::Until(d) => {
                    let left = d.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        return Err(RecvError::Timeout);
                    }
                    left
                }
                Wait::Idle(t) => t,
            };
            if self.set_timeout(t).is_err() {
                return Err(RecvError::Closed);
            }
            match self.stream.read(&mut self.buf) {
                Ok(0) => return Err(RecvError::Closed),
                Ok(n) => {
                    self.last_rx = Instant::now();
                    match &mut self.opener {
                        Some(o) => o.push(&self.buf[..n]),
                        None => self.dec.push(&self.buf[..n]),
                    }
                }
                Err(e) if is_timeout(&e) => {
                    if matches!(wait, Wait::Idle(_)) {
                        return Err(RecvError::Timeout);
                    }
                    // Until: loop re-checks the deadline.
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => return Err(RecvError::Closed),
            }
        }
    }

    /// Half-close and discard input until EOF or `linger`, so data we just
    /// wrote is not destroyed by a reset on close.
    fn linger_close(&mut self, linger: Duration) {
        let _ = self.stream.flush();
        let _ = self.stream.shutdown(Shutdown::Write);
        let deadline = Instant::now() + linger;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() || self.set_timeout(left).is_err() {
                break;
            }
            match self.stream.read(&mut self.buf) {
                Ok(0) => break,
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => break,
            }
        }
        let _ = self.stream.shutdown(Shutdown::Both);
    }
}

fn is_timeout(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

/// Handshake failure: why, whether a BYE was sent (then linger), and the
/// level to log it at.
struct HsFail {
    what: String,
    sent_bye: bool,
    level: log::Level,
}

impl HsFail {
    fn quiet(what: impl Into<String>) -> Self {
        HsFail {
            what: what.into(),
            sent_bye: false,
            level: log::Level::Info,
        }
    }

    /// Garbage from an unauthenticated peer: only worth a debug line.
    fn garbage(what: impl Into<String>) -> Self {
        HsFail {
            level: log::Level::Debug,
            ..HsFail::quiet(what)
        }
    }
}

/// A completed handshake.
struct Authenticated {
    hello: ClientHello,
    session: Established,
    /// The pairing key the client proved (`pin`: the new one, `token`: the
    /// stored one); `None` for `none`.
    key: Option<PairingKey>,
}

/// Plaintext handshake I/O, bounded by one deadline.
struct Hs<'a> {
    sh: &'a Shared,
    r: &'a mut Reader,
    wait: Wait,
    peer: SocketAddr,
    /// Frames of unknown type skipped; logged once when the handshake ends
    /// (a peer controls how many it sends).
    skipped: u64,
}

impl Drop for Hs<'_> {
    fn drop(&mut self) {
        if self.skipped > 0 {
            let (peer, n) = (self.peer, self.skipped);
            log_throttled(&self.sh.handshake_debug_log, log::Level::Debug, || {
                format!("handshake with {peer}: skipped {n} frame(s) of unknown type")
            });
        }
    }
}

impl Hs<'_> {
    fn next(&mut self) -> Result<Message, HsFail> {
        loop {
            match self.r.recv(&self.wait) {
                Ok(Message::Unknown { .. }) => self.skipped += 1,
                Ok(m) => return Ok(m),
                Err(RecvError::Timeout) => return Err(HsFail::quiet("handshake timeout")),
                Err(RecvError::Closed) => return Err(HsFail::quiet("closed during handshake")),
                Err(RecvError::Protocol(e) | RecvError::Malformed(e)) => {
                    return Err(HsFail::garbage(format!("protocol error: {e}")))
                }
            }
        }
    }

    fn send(&mut self, m: &Message) -> Result<(), HsFail> {
        self.r
            .stream
            .write_all(&encode(m))
            .map_err(|e| HsFail::quiet(format!("write: {e}")))
    }

    /// Send a (plaintext) BYE; the caller then lingers and closes.
    fn bye(&mut self, reason: ByeReason, what: String) -> HsFail {
        let _ = self.send(&Message::ServerBye(Bye { reason }));
        HsFail {
            what,
            sent_bye: true,
            level: log::Level::Info,
        }
    }
}

/// Cut `s` to at most `max` bytes, on a character boundary.
fn truncate_utf8(s: &mut String, max: usize) {
    let end = s.floor_char_boundary(max);
    s.truncate(end);
}

fn reject(reason: AuthReason, retry_after: Option<Duration>) -> ServerStep {
    let ms = retry_after.map(|d| d.as_millis().max(1) as u64);
    ServerStep::Reject {
        reply: ServerHandshake::rejection(reason, ms),
        reason,
    }
}

/// `"AMR1"` → CLIENT_HELLO → SERVER_HELLO → AUTH → (PAKE_REPLY → AUTH_CONFIRM)
/// → AUTH_RESULT. On success AUTH_RESULT `ok:true` has been sent and the
/// caller switches to records.
fn handshake(sh: &Arc<Shared>, r: &mut Reader, peer: SocketAddr) -> Result<Authenticated, HsFail> {
    let cfg = &sh.cfg;
    r.stream
        .set_write_timeout(Some(cfg.handshake_timeout))
        .and_then(|_| r.stream.write_all(&MAGIC))
        .map_err(|e| HsFail::quiet(format!("write: {e}")))?;
    let mut io = Hs {
        sh,
        r,
        wait: Wait::Until(Instant::now() + cfg.handshake_timeout),
        peer,
        skipped: 0,
    };

    let mut hello = match io.next()? {
        Message::ClientHello(h) => h,
        other => {
            return Err(HsFail::quiet(format!(
                "expected CLIENT_HELLO, got type 0x{:02x}",
                other.ty()
            )))
        }
    };
    let mut auth_modes = vec![AuthMode::Token, AuthMode::Pin];
    if cfg.allow_no_auth {
        auth_modes.push(AuthMode::NoAuth);
    }
    let template = ServerHello {
        proto: PROTO_VERSION,
        device_name: cfg.device_name.clone(),
        device_id: cfg.device_id.clone(),
        model: cfg.model.clone(),
        sdk_int: cfg.sdk_int,
        codecs: vec!["h264".into()],
        caps: Vec::new(),
        auth_modes,
        nonce_s: String::new(), // filled in with kx by ServerHandshake::new
        kx: String::new(),
    };
    let (hs, server_hello) = match ServerHandshake::new(&hello, template) {
        Ok(x) => x,
        Err(HandshakeError::ProtoMismatch(v)) => {
            return Err(io.bye(
                ByeReason::ProtoMismatch,
                format!("protocol {v} not supported"),
            ))
        }
        Err(e) => return Err(HsFail::garbage(format!("bad CLIENT_HELLO: {e}"))),
    };
    // Checked after the version (a v1 hello still gets its BYE). The id is
    // persisted and names the pairing: it must be non-empty and bounded.
    if hello.client_id.is_empty() || hello.client_id.len() > MAX_CLIENT_FIELD {
        return Err(HsFail::garbage(format!(
            "CLIENT_HELLO clientId empty or over {MAX_CLIENT_FIELD} bytes ({})",
            hello.client_id.len()
        )));
    }
    // The name is only displayed and stored: cut it rather than refuse (a
    // Mac's ComputerName may be long). The transcript already bound the
    // name as sent (`ServerHandshake::new` copied it).
    truncate_utf8(&mut hello.client_name, MAX_CLIENT_FIELD);
    io.send(&Message::ServerHello(server_hello))?;

    let auth = match io.next()? {
        Message::Auth(a) => a,
        other => {
            return Err(HsFail::quiet(format!(
                "expected AUTH, got type 0x{:02x}",
                other.ty()
            )))
        }
    };
    // Kept alive until the end of the handshake: dropping it unresolved
    // (wrong PIN, timeout, disconnect) counts the attempt as failed.
    let mut attempt: Option<PinAttempt> = None;
    let mut token_key: Option<PairingKey> = None;
    let step = match auth.mode {
        AuthMode::Token => match sh.pairing_key(hs.client_id()) {
            Some(pk) => {
                let step = hs.accept_token(&auth, &pk);
                token_key = Some(pk);
                step
            }
            // Never paired, or revoked: the client should forget its key.
            None => reject(AuthReason::UnknownClient, None),
        },
        AuthMode::Pin => match sh.admit_pin_attempt(peer) {
            Err(retry_after) => reject(AuthReason::LockedOut, Some(retry_after)),
            Ok(a) => {
                let step = hs.start_pin(&auth, a.pin());
                attempt = Some(a);
                match step {
                    ServerStep::Continue { reply, wait } => {
                        io.send(&reply)?;
                        match io.next()? {
                            Message::AuthConfirm(c) => wait.on_confirm(&c),
                            other => {
                                return Err(HsFail::quiet(format!(
                                    "expected AUTH_CONFIRM, got type 0x{:02x}",
                                    other.ty()
                                )))
                            }
                        }
                    }
                    other => other,
                }
            }
        },
        // `none` only when the config allows it (devtools/tests): the
        // session is encrypted but unauthenticated and never gets control.
        AuthMode::NoAuth if cfg.allow_no_auth => hs.accept_none(),
        _ => reject(AuthReason::ModeUnsupported, None),
    };
    // PIN pairing: store the key before AUTH_RESULT goes out, so the
    // receiver can reconnect with `token` as soon as it sees ok:true.
    let step = match (step, attempt.take()) {
        (ServerStep::Accept { reply, session }, Some(a)) => {
            let current = session
                .pairing_key
                .clone()
                .is_some_and(|pk| a.succeeded(&hello.client_id, &hello.client_name, pk));
            if current {
                ServerStep::Accept { reply, session }
            } else {
                // The PIN rotated while in flight (failure already counted).
                reject(AuthReason::BadProof, None)
            }
        }
        (step, a) => {
            drop(a); // count a failed PIN attempt (and log it) before replying
            step
        }
    };
    match step {
        ServerStep::Accept { reply, session } => {
            io.send(&reply)?;
            let key = token_key.or_else(|| session.pairing_key.clone());
            Ok(Authenticated {
                hello,
                session,
                key,
            })
        }
        ServerStep::Reject { reply, reason } => {
            let _ = io.send(&reply);
            let mut fail = io.bye(
                ByeReason::AuthFailed,
                format!("auth {:?} refused: {reason:?}", auth.mode),
            );
            if auth.mode == AuthMode::Pin && reason == AuthReason::BadProof {
                // The failed attempt was already logged with its count.
                fail.level = log::Level::Debug;
            }
            Err(fail)
        }
        ServerStep::Continue { .. } => Err(HsFail::quiet("unexpected handshake continuation")),
    }
}

/// Connection thread body.
pub(crate) fn run(
    sh: Arc<Shared>,
    stream: TcpStream,
    peer: SocketAddr,
    id: u64,
    pending: PendingGuard,
) {
    let mut r = Reader::new(stream);
    let Authenticated {
        hello,
        session,
        key,
    } = match handshake(&sh, &mut r, peer) {
        Ok(x) => x,
        Err(f) => {
            // One throttle per level class, so a flood of debug-level
            // garbage cannot suppress an info line.
            let throttle = if f.level <= log::Level::Info {
                &sh.handshake_log
            } else {
                &sh.handshake_debug_log
            };
            log_throttled(throttle, f.level, || {
                format!("session {id} ({peer}) handshake failed: {}", f.what)
            });
            if f.sent_bye {
                r.linger_close(FAIL_LINGER.min(sh.cfg.handshake_timeout));
            } else {
                let _ = r.stream.shutdown(Shutdown::Both);
            }
            return;
        }
    };
    let mode = session.mode;
    let (sealer, opener) = session.keys.server_channel();
    drop(session);
    r.start_records(opener);
    if !pending.complete() {
        log::info!("session {id} ({peer}): evicted by a newer pending handshake");
        let _ = r.stream.shutdown(Shutdown::Both);
        return;
    }

    let cfg = &sh.cfg;
    let info = ClientInfo {
        session_id: id,
        peer,
        name: hello.client_name,
        id: hello.client_id,
        auth: mode,
    };
    log::info!(
        "session {id}: client {:?} ({}) authenticated with {mode:?}",
        short(&info.name),
        peer
    );
    let handle = Arc::new(SessionHandle::new(
        id,
        info.clone(),
        QueueLimits {
            max_age: cfg.max_queue_age,
            max_frames: cfg.max_queued_frames,
            max_bytes: cfg.max_queued_bytes,
            keyframe_retry: cfg.keyframe_retry,
        },
    ));

    let writer_stream = match r.stream.try_clone() {
        Ok(s) => s,
        Err(e) => {
            log::warn!("session {id}: try_clone: {e}");
            let _ = r.stream.shutdown(Shutdown::Both);
            return;
        }
    };
    let _ = writer_stream.set_write_timeout(Some(cfg.liveness_timeout));
    match sh.activate(&handle, key.as_ref()) {
        Activation::Active => {}
        Activation::Stopping => {
            log::info!("session {id}: server stopping");
            let _ = r.stream.shutdown(Shutdown::Both);
            return;
        }
        Activation::Revoked => {
            // A revoke ran between the key lookup and activation. The
            // session was never active (the current client keeps its
            // session), so the host hears nothing about it: a Connecting
            // here would make the host treat it as the new active client.
            // It only gets its BYE, written inline (the queue holds nothing
            // else), then the socket lingers so the BYE is not reset away.
            log::info!("session {id}: pairing revoked during the handshake");
            handle.finish(ByeReason::AuthFailed, DisconnectReason::Server);
            writer_loop(&handle, writer_stream, sealer);
            r.linger_close(FAIL_LINGER);
            return;
        }
    }
    let wh = handle.clone();
    let writer = match thread::Builder::new()
        .name(format!("mirror-writer-{id}"))
        .spawn(move || {
            if let Some(stream) = writer_loop(&wh, writer_stream, sealer) {
                // A final BYE went out: give the peer FAIL_LINGER to read
                // it and close, then wake the reader (which may sit in a
                // read for up to the liveness timeout) by closing the
                // socket. A replaced session thus ends in about FAIL_LINGER.
                if !wh.wait_reader_done(FAIL_LINGER) {
                    let _ = stream.shutdown(Shutdown::Both);
                }
            }
        }) {
        Ok(w) => w,
        Err(e) => {
            log::error!("session {id}: spawn writer: {e}");
            sh.events.error(&HostError::Spawn(e.to_string()));
            sh.deactivate(id);
            let _ = r.stream.shutdown(Shutdown::Both);
            return;
        }
    };
    sh.events.client_state(ClientState::Connecting, &info);

    let reason = read_loop(&sh, &handle, &mut r);

    // Teardown.
    handle.set_reader_done();
    sh.deactivate(id);
    handle.close();
    let external = lock(&handle.end_reason).take();
    if external.is_none() {
        // Our own reason (peer closed, timeout, BYE, error): close now so a
        // writer blocked on a stalled peer returns immediately.
        let _ = r.stream.shutdown(Shutdown::Both);
    }
    if writer.join().is_err() {
        log::error!("session {id}: writer thread panicked");
    }
    if external.is_some() {
        // The writer has sent the final BYE and half-closed; give the peer a
        // moment to read it before the socket is torn down.
        r.linger_close(FAIL_LINGER);
    }
    let _ = r.stream.shutdown(Shutdown::Both);
    let reason = external.unwrap_or(reason);
    sh.stop_source(Some(id));
    let dropped = lock(&handle.queue).dropped_frames();
    log::info!("session {id} ({peer}) ended: {reason:?}; {dropped} frames dropped by backpressure");
    sh.events
        .client_state(ClientState::Disconnected(reason), &info);
}

/// Rate-limited "control dropped" logging.
struct DropLog(Throttle);

impl DropLog {
    fn dropped(&mut self, id: u64, why: &str) {
        if let Some(n) = self.0.allow(Instant::now()) {
            log::info!("session {id}: control input dropped ({why}; {n} more since last report)");
        }
    }
}

/// Rate limit for client REQUEST_KEYFRAMEs: at most one is passed on to
/// the source per [`CLIENT_KEYFRAME_INTERVAL`]. A request inside the
/// interval is deferred to its end, not dropped: the receiver repeats an
/// unanswered request only after 1 s (backing off to 8 s), and the IDR
/// answering its previous request may itself have failed to decode, so a
/// dropped request would freeze the picture for that long. Requests within
/// one interval coalesce into one.
#[derive(Default)]
struct KeyframeGate {
    last: Option<Instant>,
    pending: bool,
}

impl KeyframeGate {
    /// A request arrived. True if it is to be passed on now.
    fn request(&mut self, now: Instant) -> bool {
        self.pending = true;
        self.poll(now)
    }

    /// True if a deferred request is due now (it is then passed on).
    fn poll(&mut self, now: Instant) -> bool {
        if !self.pending || self.due_in(now).is_some_and(|d| !d.is_zero()) {
            return false;
        }
        self.pending = false;
        self.last = Some(now);
        true
    }

    /// Time until the pending request may be passed on; `None` if none is.
    fn due_in(&self, now: Instant) -> Option<Duration> {
        self.pending.then(|| {
            self.last.map_or(Duration::ZERO, |t| {
                CLIENT_KEYFRAME_INTERVAL.saturating_sub(now.saturating_duration_since(t))
            })
        })
    }
}

fn read_loop(sh: &Arc<Shared>, handle: &Arc<SessionHandle>, r: &mut Reader) -> DisconnectReason {
    let id = handle.id;
    let mode_ok = mode_allows_control(handle.info.auth);
    let liveness = sh.cfg.liveness_timeout;
    let mut started = false;
    let mut drop_log = DropLog(Throttle::new(DROP_LOG_INTERVAL));
    let mut keyframe_gate = KeyframeGate::default();
    loop {
        let now = Instant::now();
        if keyframe_gate.poll(now) {
            sh.request_keyframe(id);
        }
        // Wake for a deferred keyframe request; otherwise wait out the
        // liveness timeout, counted from the last received byte. Right
        // after a byte arrived that is the full timeout: rounding it up to
        // exactly `liveness` keeps the socket timeout unchanged from read to
        // read (no setsockopt per message) for at most IDLE_SLACK late.
        let idle_left = liveness.saturating_sub(now.saturating_duration_since(r.last_rx));
        let t = match keyframe_gate.due_in(now) {
            Some(d) => d.min(idle_left),
            None if idle_left + IDLE_SLACK >= liveness => liveness,
            None => idle_left,
        };
        let msg = match r.recv(&Wait::Idle(t)) {
            Ok(m) => m,
            Err(RecvError::Malformed(e)) => {
                if !started && matches!(e, ProtocolError::Malformed { ty: ty::START, .. }) {
                    // Skipping it would leave the client waiting for video
                    // forever: end the session with a final BYE instead.
                    log::info!("session {id}: malformed START: {e}");
                    handle.finish(ByeReason::Unknown, DisconnectReason::ProtocolError);
                    return DisconnectReason::ProtocolError;
                }
                log::debug!("session {id}: skipping malformed frame: {e}");
                continue;
            }
            Err(RecvError::Timeout) if r.last_rx.elapsed() < liveness => continue,
            Err(RecvError::Timeout) => return DisconnectReason::Timeout,
            Err(RecvError::Closed) => return DisconnectReason::Closed,
            Err(RecvError::Protocol(e)) => {
                // Includes record-layer failures: close without BYE.
                log::warn!("session {id}: {e}");
                return DisconnectReason::ProtocolError;
            }
        };
        if handle.is_closed() {
            // Ended from outside (replaced / server) or the writer failed;
            // the external reason, if any, overrides this one.
            if let Message::Text(mut t) = msg {
                t.zeroize(); // may be a password, like below
            }
            return DisconnectReason::Closed;
        }
        match msg {
            Message::Ping(p) => {
                handle.push_control(Message::Pong(p));
            }
            Message::Start(s) => {
                if started {
                    log::debug!("session {id}: ignoring repeated START");
                    continue;
                }
                let params = StreamParams::from_start(&s);
                let sink = FrameSink::new(id, Arc::downgrade(handle), Arc::downgrade(sh));
                match sh.start_source(id, params, sink) {
                    Ok(true) => {}
                    // Replaced or server stopping; the external reason wins.
                    Ok(false) => return DisconnectReason::Closed,
                    Err(e) => {
                        log::error!("session {id}: video source failed to start: {e}");
                        sh.events.error(&HostError::SourceStart(e.to_string()));
                        // BYE (any reason) tells the receiver not to
                        // reconnect; without it a broken encoder would
                        // cause an endless reconnect loop.
                        handle.finish(ByeReason::Unknown, DisconnectReason::SourceFailed);
                        return DisconnectReason::SourceFailed;
                    }
                }
                started = true;
                sh.events.client_state(ClientState::Streaming, &handle.info);
            }
            Message::RequestKeyframe => {
                if started && keyframe_gate.request(Instant::now()) {
                    sh.request_keyframe(id);
                }
            }
            Message::ClientBye(b) => {
                log::info!("session {id}: client said BYE {:?}", b.reason);
                return DisconnectReason::ClientBye;
            }
            Message::ClientHello(_) | Message::Auth(_) | Message::AuthConfirm(_) => {
                log::warn!("session {id}: handshake message after authentication");
                return DisconnectReason::ProtocolError;
            }
            m if is_control(&m) => {
                // The gate (spec §6): an authenticated mode AND the host's
                // Accessibility service is enabled, and only once the
                // session has started (START is the first client record).
                if !started {
                    drop_log.dropped(id, "before START");
                } else if !mode_ok {
                    drop_log.dropped(id, "auth mode none");
                } else if !sh.control_available() {
                    drop_log.dropped(id, "control unavailable");
                } else {
                    let cfg = lock(&sh.last_config).clone(); // an `Arc`
                    if !dispatch_control(&m, cfg.as_deref(), &*sh.control) {
                        log::debug!("session {id}: control message not delivered");
                    }
                }
                // Typed text may be a password: wipe the plaintext copy
                // (the record buffer it came from is wiped by the Opener).
                if let Message::Text(mut t) = m {
                    t.zeroize();
                }
            }
            other => log::debug!("session {id}: ignoring type 0x{:02x}", other.ty()),
        }
    }
}

/// Seal `msg` and what is already queued behind it (without waiting) into
/// `buf`, in queue order, up to [`MAX_WRITE_BATCH`] bytes. `is_final`:
/// `msg` is the final message. Returns whether the final message is in the
/// batch. Sealing runs outside the queue lock.
///
/// A batch holds at most one VIDEO_FRAME, as its last message: a frame
/// still queued stays under the queue's age-based backpressure while the
/// write of this batch blocks on a slow peer, instead of being committed to
/// the socket in advance.
fn seal_batch(
    h: &SessionHandle,
    mut msg: Message,
    mut is_final: bool,
    sealer: &mut Sealer,
    buf: &mut Vec<u8>,
) -> Result<bool, String> {
    loop {
        sealer
            .seal_message(&msg, buf)
            .map_err(|e| format!("seal: {e}"))?;
        if is_final || buf.len() >= MAX_WRITE_BATCH || matches!(msg, Message::VideoFrame(_)) {
            return Ok(is_final);
        }
        match lock(&h.queue).pop() {
            Some((m, f)) => (msg, is_final) = (m, f),
            None => return Ok(false),
        }
    }
}

/// Drain the queue to the socket. Returns the stream after a final message
/// was written and the write side half-closed; `None` otherwise.
fn writer_loop(h: &SessionHandle, mut stream: TcpStream, mut sealer: Sealer) -> Option<TcpStream> {
    let mut buf = Vec::new();
    loop {
        let (msg, is_final) = {
            let mut q = lock(&h.queue);
            loop {
                if let Some(x) = q.pop() {
                    break x;
                }
                if q.is_closed() {
                    return None;
                }
                q = h.cv.wait(q).unwrap_or_else(|e| e.into_inner());
            }
        };
        buf.clear();
        if buf.capacity() > 2 * KEEP_WRITE_BUF {
            buf.shrink_to(KEEP_WRITE_BUF);
        }
        let res = seal_batch(h, msg, is_final, &mut sealer, &mut buf).and_then(|is_final| {
            stream.write_all(&buf).map_err(|e| format!("write: {e}"))?;
            Ok(is_final)
        });
        let is_final = match res {
            Ok(f) => f,
            Err(e) => {
                // No BYE: the record stream is unusable (or the socket is).
                log::debug!("session {}: {e}", h.id);
                h.close();
                let _ = stream.shutdown(Shutdown::Both);
                return None;
            }
        };
        if is_final {
            // Half-close: the reader keeps draining until the peer closes,
            // so the BYE is not destroyed by a reset.
            let _ = stream.flush();
            let _ = stream.shutdown(Shutdown::Write);
            return Some(stream);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::queue::QueueLimits;
    use mirror_protocol::secure::SecretKey;
    use mirror_protocol::{VideoConfig, MAX_PAYLOAD};
    use std::net::TcpListener;

    /// The writer batches what is queued: every message arrives in order
    /// (also across the batch cap), the final BYE last, then EOF.
    fn info() -> ClientInfo {
        ClientInfo {
            session_id: 1,
            peer: "127.0.0.1:1".parse().unwrap(),
            name: "c".into(),
            id: "c".into(),
            auth: AuthMode::NoAuth,
        }
    }

    #[test]
    fn writer_batches_in_order_and_half_closes_after_the_final_bye() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (server, _) = l.accept().unwrap();
        let h = SessionHandle::new(1, info(), limits());
        let big = |b: u8| VideoConfig {
            width: 1,
            height: 1,
            display_width: 1,
            display_height: 1,
            rotation: 0,
            sps_pps: vec![b; MAX_WRITE_BATCH / 2],
        };
        let mut want = Vec::new();
        for i in 0..40u8 {
            // Two big configs fill a batch; the BYE comes mid-batch.
            let m = if i % 10 == 5 {
                lock(&h.queue).push_config(big(i));
                Message::VideoConfig(big(i))
            } else {
                assert!(h.push_control(Message::Pong([i; 8])));
                Message::Pong([i; 8])
            };
            want.push(m);
        }
        assert!(h.finish(ByeReason::Replaced, DisconnectReason::Replaced));
        want.push(Message::ServerBye(Bye {
            reason: ByeReason::Replaced,
        }));
        let key = SecretKey::from_bytes([7; 32]);
        let reader = thread::spawn(move || {
            let mut all = Vec::new();
            client.read_to_end(&mut all).unwrap();
            (client, all)
        });
        // Kept alive: the client's EOF must come from the half-close alone.
        let mut kept = writer_loop(&h, server, Sealer::new(&key, MAX_PAYLOAD)).expect("final");
        let (mut client, all) = reader.join().unwrap();
        let mut o = Opener::new(&key, MAX_PAYLOAD);
        o.push(&all);
        for m in want {
            assert_eq!(o.next(), Ok(Some(m)));
        }
        assert_eq!(o.next(), Ok(None));
        // Only the write side is closed: the server still reads.
        client.write_all(b"x").unwrap();
        let mut b = [0u8; 1];
        kept.read_exact(&mut b).unwrap();
        assert_eq!(&b, b"x");
    }

    fn limits() -> QueueLimits {
        QueueLimits {
            max_age: Duration::from_secs(60),
            max_frames: 64,
            max_bytes: 1 << 20,
            keyframe_retry: Duration::from_secs(1),
        }
    }

    /// A write batch carries control messages but at most one VIDEO_FRAME,
    /// as its last message: later frames stay queued (and subject to
    /// age-based backpressure) while it is written.
    #[test]
    fn a_write_batch_holds_at_most_one_video_frame() {
        use crate::types::EncodedFrame;
        let h = SessionHandle::new(1, info(), limits());
        let now = Instant::now();
        {
            let mut q = lock(&h.queue);
            q.push_config(VideoConfig {
                width: 1,
                height: 1,
                display_width: 1,
                display_height: 1,
                rotation: 0,
                sps_pps: vec![1],
            });
            q.push_control(Message::Pong([1; 8]));
            for i in 0..3 {
                let f = EncodedFrame {
                    pts_us: i,
                    keyframe: i == 0,
                    data: vec![0, 0, 0, 1, 0x65],
                };
                q.push_frame(f, now);
            }
            q.push_control(Message::Pong([2; 8]));
        }
        let key = SecretKey::from_bytes([7; 32]);
        let mut sealer = Sealer::new(&key, MAX_PAYLOAD);
        let mut buf = Vec::new();
        let (first, fin) = lock(&h.queue).pop().unwrap();
        assert_eq!(seal_batch(&h, first, fin, &mut sealer, &mut buf), Ok(false));
        let mut o = Opener::new(&key, MAX_PAYLOAD);
        o.push(&buf);
        let mut got = Vec::new();
        while let Ok(Some(m)) = o.next() {
            got.push(m.ty());
        }
        assert_eq!(got, [ty::VIDEO_CONFIG, ty::PONG, ty::VIDEO_FRAME]);
        // Two frames and the PONG are still queued, in order.
        let rest: Vec<u8> = std::iter::from_fn(|| lock(&h.queue).pop())
            .map(|(m, _)| m.ty())
            .collect();
        assert_eq!(rest, [ty::VIDEO_FRAME, ty::VIDEO_FRAME, ty::PONG]);
    }
}
