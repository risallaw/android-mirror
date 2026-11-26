//! Loopback integration tests: a tiny protocol client built directly on the
//! `mirror-protocol` sans-IO handshake, codec and record layer talks to a
//! real `Server` with a fake video source.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use mirror_protocol::auth::PairingKey;
use mirror_protocol::handshake::{
    ClientCredential, ClientHandshake, ClientStep, Established, HandshakeError,
};
use mirror_protocol::secure::{Opener, Sealer};
use mirror_protocol::wire::{flags, ty, Header};
use mirror_protocol::{
    encode, AuthMode, AuthReason, Bye, ByeReason, ClientHello, Decoder, GlobalAction, Message,
    ServerHello, Start, StatusState, VideoConfig, MAGIC, MAX_CLIENT_PAYLOAD, MAX_JSON_PAYLOAD,
};
use mirror_sender::{
    ClientInfo, ClientState, ControlSink, DisconnectReason, EncodedFrame, FrameSink, HostError,
    HostEvents, PairedClient, Server, ServerConfig, SourceError, StreamParams, VideoSource,
    MAX_PAIRINGS, MAX_PIN_FAILURES, PIN_LOCKOUT,
};

const T: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum SrcEvent {
    Start(StreamParams),
    Keyframe,
    Stop,
}

/// Pushes a config + keyframe + `frames` deltas on start, then an IDR for
/// every keyframe request until stopped.
struct FakeSource {
    tx: Mutex<Sender<SrcEvent>>,
    frames: u64,
    state: Mutex<Option<(Arc<AtomicBool>, JoinHandle<()>)>>,
    sink: Mutex<Option<FrameSink>>,
    kf_wanted: Arc<AtomicUsize>,
}

fn config() -> VideoConfig {
    VideoConfig {
        width: 64,
        height: 128,
        display_width: 1080,
        display_height: 2400,
        rotation: 0,
        sps_pps: vec![0, 0, 0, 1, 0x67, 1, 2, 0, 0, 0, 1, 0x68, 3],
    }
}

impl FakeSource {
    fn new(frames: u64) -> (Arc<Self>, Receiver<SrcEvent>) {
        let (tx, rx) = mpsc::channel();
        (
            Arc::new(FakeSource {
                tx: Mutex::new(tx),
                frames,
                state: Mutex::new(None),
                sink: Mutex::new(None),
                kf_wanted: Arc::new(AtomicUsize::new(0)),
            }),
            rx,
        )
    }
    fn send(&self, e: SrcEvent) {
        let _ = self.tx.lock().unwrap().send(e);
    }
}

impl VideoSource for FakeSource {
    fn start(&self, params: StreamParams, sink: FrameSink) -> Result<(), SourceError> {
        self.send(SrcEvent::Start(params));
        *self.sink.lock().unwrap() = Some(sink.clone());
        let stop = Arc::new(AtomicBool::new(false));
        let (st, n, kf) = (stop.clone(), self.frames, self.kf_wanted.clone());
        let th = thread::spawn(move || {
            sink.push_config(config());
            sink.push_frame(EncodedFrame {
                pts_us: 0,
                keyframe: true,
                data: vec![0, 0, 0, 1, 0x65, 0xAA],
            });
            for i in 1..=n {
                sink.push_frame(EncodedFrame {
                    pts_us: i * 16_666,
                    keyframe: false,
                    data: vec![0, 0, 0, 1, 0x41, i as u8],
                });
            }
            let mut pts = 1_000_000;
            while !st.load(Ordering::SeqCst) {
                if kf.swap(0, Ordering::SeqCst) > 0 {
                    pts += 1;
                    sink.push_frame(EncodedFrame {
                        pts_us: pts,
                        keyframe: true,
                        data: vec![0, 0, 0, 1, 0x65, 0xBB],
                    });
                }
                thread::sleep(Duration::from_millis(2));
            }
        });
        *self.state.lock().unwrap() = Some((stop, th));
        Ok(())
    }
    fn request_keyframe(&self) {
        self.kf_wanted.fetch_add(1, Ordering::SeqCst);
        self.send(SrcEvent::Keyframe);
    }
    fn stop(&self) {
        if let Some((stop, th)) = self.state.lock().unwrap().take() {
            stop.store(true, Ordering::SeqCst);
            th.join().unwrap();
        }
        self.send(SrcEvent::Stop);
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Ev {
    State(ClientState, String),
    Error(HostError),
}

/// Pairing notifications (separate channel so state assertions stay simple).
#[derive(Debug, Clone, PartialEq)]
enum PairEv {
    PinChanged(String),
    Paired(PairedClient),
    Failed(u32, Option<Duration>),
}

struct Events {
    tx: Mutex<Sender<Ev>>,
    pair: Mutex<Sender<PairEv>>,
    /// Auth mode of every client_state report.
    modes: Mutex<Vec<AuthMode>>,
    /// When set, `paired` blocks until the test signals (a deterministic
    /// window between PIN pairing and session activation).
    paired_gate: Mutex<Option<Receiver<()>>>,
}
impl HostEvents for Events {
    fn client_state(&self, s: ClientState, c: &ClientInfo) {
        self.modes.lock().unwrap().push(c.auth);
        let _ = self.tx.lock().unwrap().send(Ev::State(s, c.name.clone()));
    }
    fn error(&self, e: &HostError) {
        let _ = self.tx.lock().unwrap().send(Ev::Error(e.clone()));
    }
    fn pin_changed(&self, pin: &str) {
        let _ = self
            .pair
            .lock()
            .unwrap()
            .send(PairEv::PinChanged(pin.into()));
    }
    fn paired(&self, c: &PairedClient) {
        let _ = self.pair.lock().unwrap().send(PairEv::Paired(c.clone()));
        if let Some(gate) = self.paired_gate.lock().unwrap().take() {
            let _ = gate.recv_timeout(T);
        }
    }
    fn pairing_failed(&self, _peer: SocketAddr, left: u32, locked: Option<Duration>) {
        let _ = self.pair.lock().unwrap().send(PairEv::Failed(left, locked));
    }
}

#[derive(Default)]
struct CountingControl(AtomicUsize);
impl ControlSink for CountingControl {
    fn global_action(&self, _a: GlobalAction) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

struct Harness {
    server: Server,
    src: Arc<FakeSource>,
    src_rx: Receiver<SrcEvent>,
    ev_rx: Receiver<Ev>,
    pair_rx: Receiver<PairEv>,
    events: Arc<Events>,
    control: Arc<CountingControl>,
}

fn test_config() -> ServerConfig {
    let mut c = ServerConfig::new("Test Phone", "dev-1", "Pixel Test", 35);
    c.port = 0;
    c.bind_addr = Some("127.0.0.1".parse().unwrap());
    c.allow_no_auth = true;
    c.accept_poll_interval = Duration::from_millis(5);
    c.bye_linger = Duration::from_millis(300);
    c
}

/// Pairing required (no `none`).
fn paired_config() -> ServerConfig {
    let mut c = test_config();
    c.allow_no_auth = false;
    c
}

fn harness(cfg: ServerConfig) -> Harness {
    let (src, src_rx) = FakeSource::new(3);
    let (tx, ev_rx) = mpsc::channel();
    let (ptx, pair_rx) = mpsc::channel();
    let control = Arc::new(CountingControl::default());
    let events = Arc::new(Events {
        tx: Mutex::new(tx),
        pair: Mutex::new(ptx),
        modes: Mutex::new(Vec::new()),
        paired_gate: Mutex::new(None),
    });
    let server =
        Server::start(cfg, src.clone(), events.clone(), control.clone()).expect("server start");
    Harness {
        server,
        src,
        src_rx,
        ev_rx,
        pair_rx,
        events,
        control,
    }
}

impl Harness {
    fn client(&self) -> Client {
        Client::connect(self.server.port())
    }
    fn next_state(&self) -> (ClientState, String) {
        match self.ev_rx.recv_timeout(T).expect("host event") {
            Ev::State(s, n) => (s, n),
            Ev::Error(e) => panic!("unexpected host error {e}"),
        }
    }
    fn next_src(&self) -> SrcEvent {
        self.src_rx.recv_timeout(T).expect("source event")
    }
    fn next_pair(&self) -> PairEv {
        self.pair_rx.recv_timeout(T).expect("pairing event")
    }
    /// PIN-pair `name`; returns the stored key. Consumes the pairing events.
    fn pair(&self, name: &str) -> PairingKey {
        let pin = self.server.pin().to_string();
        let mut c = self.client();
        let est = c.auth(name, ClientCredential::Pin(pin)).expect("pairing");
        assert_eq!(est.mode, AuthMode::Pin);
        assert!(matches!(self.next_pair(), PairEv::Paired(p) if p.client_id == id_of(name)));
        assert!(matches!(self.next_pair(), PairEv::PinChanged(_)));
        assert_eq!(self.next_state().0, ClientState::Connecting);
        drop(c);
        assert_eq!(
            self.next_state().0,
            ClientState::Disconnected(DisconnectReason::Closed)
        );
        est.pairing_key.expect("PIN pairing yields a key")
    }
}

fn id_of(name: &str) -> String {
    format!("{name}-id")
}

/// A unique, self-deleting temp directory.
struct TempDir(PathBuf);
impl TempDir {
    fn new(tag: &str) -> TempDir {
        static N: AtomicUsize = AtomicUsize::new(0);
        let p = std::env::temp_dir().join(format!(
            "mirror-sender-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }
    fn store(&self) -> PathBuf {
        self.0.join("pairings.json")
    }
    fn names(&self) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(&self.0)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o700));
        }
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn read_store(path: &Path) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(path).expect("store file")).expect("store JSON")
}

// ---------------------------------------------------------------------------
// Test client
// ---------------------------------------------------------------------------

struct Client {
    s: TcpStream,
    dec: Decoder,
    /// Record layer, once authenticated.
    tx: Option<Sealer>,
    rx: Option<Opener>,
}

impl Client {
    fn connect(port: u16) -> Client {
        let s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
        s.set_read_timeout(Some(T)).unwrap();
        s.set_nodelay(true).unwrap();
        Client {
            s,
            dec: Decoder::new(true),
            tx: None,
            rx: None,
        }
    }
    fn send_raw(&mut self, b: &[u8]) {
        self.s.write_all(b).expect("write");
    }
    /// Plaintext frame before authentication, a record after.
    fn send(&mut self, m: &Message) {
        let mut out = Vec::new();
        match &mut self.tx {
            Some(tx) => tx.seal_message(m, &mut out).expect("seal"),
            None => out = encode(m),
        }
        self.send_raw(&out);
    }
    /// Next message; None on EOF/reset/timeout.
    fn recv(&mut self) -> Option<Message> {
        let mut buf = [0u8; 8192];
        loop {
            let next = match &mut self.rx {
                Some(o) => o.next(),
                None => self.dec.next(),
            };
            match next {
                Ok(Some(m)) => return Some(m),
                Ok(None) => {}
                Err(e) => panic!("client decode error: {e}"),
            }
            match self.s.read(&mut buf) {
                Ok(0) | Err(_) => return None,
                Ok(n) => match &mut self.rx {
                    Some(o) => o.push(&buf[..n]),
                    None => self.dec.push(&buf[..n]),
                },
            }
        }
    }
    fn expect(&mut self) -> Message {
        self.recv().expect("expected a message, got EOF")
    }
    /// Next STATUS (skipping video) must be `want`.
    fn expect_status(&mut self, want: StatusState) {
        loop {
            match self.expect() {
                Message::Status(s) => return assert_eq!(s.state, want),
                Message::VideoConfig(_) | Message::VideoFrame(_) => {}
                m => panic!("expected STATUS {want:?}, got {m:?}"),
            }
        }
    }
    /// True if the server closes the connection (EOF/reset) within `T`,
    /// skipping any bytes before that.
    fn closed_by_server(&mut self) -> bool {
        let start = Instant::now();
        let mut buf = [0u8; 8192];
        loop {
            match self.s.read(&mut buf) {
                Ok(0) => return true,
                Ok(_) => {}
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    return false
                }
                Err(_) => return true,
            }
            if start.elapsed() > T {
                return false;
            }
        }
    }
    /// Magic + CLIENT_HELLO; returns the handshake state.
    fn hello(&mut self, name: &str) -> ClientHandshake {
        let (hs, hello) = ClientHandshake::new(name, &id_of(name)).unwrap();
        self.send_raw(&MAGIC);
        self.send(&Message::ClientHello(hello));
        hs
    }
    fn server_hello(&mut self) -> ServerHello {
        match self.expect() {
            Message::ServerHello(h) => h,
            m => panic!("expected SERVER_HELLO, got {m:?}"),
        }
    }
    /// Run the handshake with `cred` against SERVER_HELLO `sh`; on success
    /// switch to records.
    fn finish_auth(
        &mut self,
        hs: ClientHandshake,
        sh: &ServerHello,
        cred: ClientCredential,
    ) -> Result<Established, HandshakeError> {
        let (auth, mut wait) = hs.authenticate(sh, cred)?;
        self.send(&auth);
        let est = loop {
            let m = self.expect();
            match wait.on_message(&m)? {
                ClientStep::Send(reply, next) => {
                    self.send(&reply);
                    wait = next;
                }
                ClientStep::Done(est) => break est,
            }
        };
        let (tx, mut rx) = est.keys.client_channel();
        rx.push(&self.dec.take_buffered());
        self.tx = Some(tx);
        self.rx = Some(rx);
        Ok(est)
    }
    /// Full handshake with `cred`.
    fn auth(&mut self, name: &str, cred: ClientCredential) -> Result<Established, HandshakeError> {
        let hs = self.hello(name);
        let sh = self.server_hello();
        self.finish_auth(hs, &sh, cred)
    }
    /// Expect BYE `auth_failed` (plaintext, after a refusal), then EOF.
    fn expect_auth_failed_bye(&mut self) {
        match self.expect() {
            Message::ServerBye(b) => assert_eq!(b.reason, ByeReason::AuthFailed),
            m => panic!("expected BYE auth_failed, got {m:?}"),
        }
        assert!(self.recv().is_none());
    }
    /// Full handshake with auth `none`; returns the SERVER_HELLO. Consumes
    /// the STATUS `control_unavailable` every `none` session starts with.
    fn handshake(&mut self, name: &str) -> ServerHello {
        let hs = self.hello(name);
        let sh = self.server_hello();
        self.finish_auth(hs, &sh, ClientCredential::NoAuth)
            .expect("auth none");
        self.expect_status(StatusState::ControlUnavailable);
        sh
    }
    /// Handshake + START; asserts VIDEO_CONFIG then a keyframe.
    fn stream(&mut self, name: &str) {
        self.handshake(name);
        self.send(&Message::Start(Start::default()));
        match self.expect() {
            Message::VideoConfig(c) => assert_eq!(c, config()),
            m => panic!("expected VIDEO_CONFIG, got {m:?}"),
        }
        match self.expect() {
            Message::VideoFrame(f) => assert_eq!(f.flags, flags::KEYFRAME),
            m => panic!("expected keyframe, got {m:?}"),
        }
    }
    /// PING round trip: everything sent before it has been processed.
    fn sync(&mut self, tag: u8) {
        self.send(&Message::Ping([tag; 8]));
        loop {
            match self.expect() {
                Message::Pong(p) if p == [tag; 8] => return,
                Message::VideoConfig(_) | Message::VideoFrame(_) => {}
                m => panic!("expected PONG, got {m:?}"),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn handshake_happy_path_streams_config_then_frames() {
    let h = harness(test_config());
    let mut c = h.client();
    let sh = c.handshake("mac");
    assert_eq!(sh.proto, 2);
    assert_eq!(sh.device_name, "Test Phone");
    assert_eq!(sh.device_id, "dev-1");
    assert_eq!(sh.model, "Pixel Test");
    assert_eq!(sh.sdk_int, 35);
    assert_eq!(sh.codecs, vec!["h264".to_string()]);
    assert_eq!(
        sh.auth_modes,
        vec![AuthMode::Token, AuthMode::Pin, AuthMode::NoAuth]
    );
    assert_eq!(sh.nonce_s.len(), 64);
    assert_eq!(sh.kx.len(), 64);
    assert_eq!(h.next_state(), (ClientState::Connecting, "mac".into()));
    assert_eq!(h.server.client().map(|c| c.name), Some("mac".into()));

    c.send(&Message::Start(Start {
        max_long_edge: Some(1280),
        max_fps: Some(30),
        bitrate: None,
    }));
    let p = match h.next_src() {
        SrcEvent::Start(p) => p,
        e => panic!("{e:?}"),
    };
    assert_eq!(
        (p.max_long_edge, p.max_fps, p.bitrate),
        (1280, 30, 4_000_000)
    );
    assert_eq!(h.next_state(), (ClientState::Streaming, "mac".into()));

    match c.expect() {
        Message::VideoConfig(cfg) => assert_eq!(cfg, config()),
        m => panic!("{m:?}"),
    }
    match c.expect() {
        Message::VideoFrame(f) => {
            assert_eq!((f.pts_us, f.flags), (0, flags::KEYFRAME));
        }
        m => panic!("{m:?}"),
    }
    for i in 1..=3u64 {
        match c.expect() {
            Message::VideoFrame(f) => {
                assert_eq!((f.pts_us, f.flags), (i * 16_666, 0));
                assert_eq!(f.data, vec![0, 0, 0, 1, 0x41, i as u8]);
            }
            m => panic!("{m:?}"),
        }
    }

    assert!(h.server.send_status(StatusState::ScreenOff));
    match c.expect() {
        Message::Status(s) => assert_eq!(s.state, StatusState::ScreenOff),
        m => panic!("{m:?}"),
    }

    c.send(&Message::ClientBye(Bye {
        reason: ByeReason::StoppedByUser,
    }));
    assert_eq!(
        h.next_state(),
        (
            ClientState::Disconnected(DisconnectReason::ClientBye),
            "mac".into()
        )
    );
    assert_eq!(h.next_src(), SrcEvent::Stop);
    assert!(h.server.client().is_none());
    assert!(c.closed_by_server());
}

#[test]
fn magic_mismatch_is_closed() {
    let h = harness(test_config());
    let mut c = h.client();
    c.send_raw(b"XXXX");
    assert!(c.closed_by_server());
    // A good client still works afterwards.
    let mut c2 = h.client();
    c2.handshake("ok");
}

#[test]
fn silent_peer_hits_handshake_timeout() {
    let mut cfg = test_config();
    cfg.handshake_timeout = Duration::from_millis(200);
    let h = harness(cfg);
    let t0 = Instant::now();
    let mut silent = h.client();
    assert!(silent.closed_by_server());
    assert!(t0.elapsed() < Duration::from_secs(3));
    // Magic + hello but no AUTH: also bounded by the handshake deadline.
    let mut c = h.client();
    let _hs = c.hello("slow");
    c.server_hello();
    assert!(c.closed_by_server());
    assert!(
        h.ev_rx.try_recv().is_err(),
        "no host events for failed handshakes"
    );
}

#[test]
fn oversize_payload_is_rejected() {
    let h = harness(test_config());
    // During the handshake: a JSON type above 64 KiB.
    let mut c = h.client();
    c.send_raw(&MAGIC);
    let hdr = Header {
        ty: ty::CLIENT_HELLO,
        flags: 0,
        length: MAX_JSON_PAYLOAD + 1,
        pts_us: 0,
    };
    c.send_raw(&hdr.encode());
    assert!(c.closed_by_server());

    // After auth: a record longer than a 64 KiB frame (+ header + tag) is
    // rejected from its length prefix alone, without a BYE.
    let mut c = h.client();
    c.handshake("big");
    assert_eq!(h.next_state().0, ClientState::Connecting);
    let too_long = 16 + MAX_CLIENT_PAYLOAD + 16 + 1;
    c.send_raw(&too_long.to_be_bytes());
    assert!(c.recv().is_none(), "closed without a BYE");
    assert_eq!(
        h.next_state().0,
        ClientState::Disconnected(DisconnectReason::ProtocolError)
    );
}

#[test]
fn second_client_replaces_first() {
    let h = harness(test_config());
    let mut a = h.client();
    a.stream("A");
    assert_eq!(h.next_state(), (ClientState::Connecting, "A".into()));
    assert_eq!(h.next_state(), (ClientState::Streaming, "A".into()));
    assert!(matches!(h.next_src(), SrcEvent::Start(_)));

    let mut b = h.client();
    b.handshake("B");
    // A gets BYE replaced, then the connection closes.
    loop {
        match a.expect() {
            Message::VideoFrame(_) => continue,
            Message::ServerBye(bye) => {
                assert_eq!(bye.reason, ByeReason::Replaced);
                break;
            }
            m => panic!("{m:?}"),
        }
    }
    assert!(a.recv().is_none(), "EOF after BYE");
    drop(a);

    // B streams from a fresh config + keyframe.
    b.send(&Message::Start(Start::default()));
    match b.expect() {
        Message::VideoConfig(_) => {}
        m => panic!("{m:?}"),
    }
    match b.expect() {
        Message::VideoFrame(f) => assert_eq!(f.flags, flags::KEYFRAME),
        m => panic!("{m:?}"),
    }

    let mut states = Vec::new();
    for _ in 0..3 {
        states.push(h.next_state());
    }
    for want in [
        (ClientState::Connecting, "B".to_string()),
        (
            ClientState::Disconnected(DisconnectReason::Replaced),
            "A".to_string(),
        ),
        (ClientState::Streaming, "B".to_string()),
    ] {
        assert!(states.contains(&want), "{want:?} not in {states:?}");
    }
    assert_eq!(h.server.client().map(|c| c.name), Some("B".into()));
    // Source was stopped for A and restarted for B (in that order).
    let mut src = Vec::new();
    while src.len() < 2 {
        match h.next_src() {
            SrcEvent::Keyframe => {}
            e => src.push(e),
        }
    }
    assert_eq!(src[0], SrcEvent::Stop);
    assert!(matches!(src[1], SrcEvent::Start(_)));
}

#[test]
fn ping_gets_pong() {
    let h = harness(test_config());
    let mut c = h.client();
    c.handshake("p");
    c.send(&Message::Ping([1, 2, 3, 4, 5, 6, 7, 8]));
    assert_eq!(c.expect(), Message::Pong([1, 2, 3, 4, 5, 6, 7, 8]));
}

#[test]
fn liveness_timeout_closes_silent_client() {
    let mut cfg = test_config();
    cfg.liveness_timeout = Duration::from_millis(300);
    let h = harness(cfg);
    let mut c = h.client();
    c.stream("quiet");
    assert_eq!(h.next_state().0, ClientState::Connecting);
    assert_eq!(h.next_state().0, ClientState::Streaming);
    // PINGs keep it alive past the timeout...
    for _ in 0..4 {
        thread::sleep(Duration::from_millis(100));
        c.send(&Message::Ping([0; 8]));
    }
    assert!(h.server.client().is_some());
    // ...silence does not.
    assert!(c.closed_by_server());
    assert_eq!(
        h.next_state(),
        (
            ClientState::Disconnected(DisconnectReason::Timeout),
            "quiet".into()
        )
    );
}

/// Deferred REQUEST_KEYFRAMEs wake the reader early, but those wake-ups
/// must not re-arm the liveness timeout: silence after them still ends the
/// session about one liveness timeout after the last byte.
#[test]
fn liveness_timeout_survives_keyframe_wakeups() {
    let mut cfg = test_config();
    cfg.liveness_timeout = Duration::from_millis(300);
    let h = harness(cfg);
    let mut c = h.client();
    c.stream("kf");
    assert_eq!(h.next_state().0, ClientState::Connecting);
    assert_eq!(h.next_state().0, ClientState::Streaming);
    // Taken before the sends so a pause of this thread after them cannot
    // make the server's count start before `t0`.
    let t0 = Instant::now();
    for _ in 0..3 {
        c.send(&Message::RequestKeyframe);
    }
    assert_eq!(
        h.next_state(),
        (
            ClientState::Disconnected(DisconnectReason::Timeout),
            "kf".into()
        )
    );
    let elapsed = t0.elapsed();
    // The deferred request fires ~250 ms in; the timeout still counts from
    // the last byte (~300 ms), not from that wake-up (~550 ms).
    assert!(
        elapsed >= Duration::from_millis(290) && elapsed < Duration::from_millis(500),
        "{elapsed:?}"
    );
}

#[test]
fn request_keyframe_reaches_source() {
    let h = harness(test_config());
    let mut c = h.client();
    c.stream("kf");
    assert!(matches!(h.next_src(), SrcEvent::Start(_)));
    c.send(&Message::RequestKeyframe);
    assert_eq!(h.next_src(), SrcEvent::Keyframe);
    // The fake source answers with an IDR.
    loop {
        match c.expect() {
            Message::VideoFrame(f) if f.data.ends_with(&[0xBB]) => {
                assert_eq!(f.flags, flags::KEYFRAME);
                break;
            }
            Message::VideoFrame(_) => {}
            m => panic!("{m:?}"),
        }
    }
}

#[test]
fn proto_mismatch_gets_bye() {
    let h = harness(test_config());
    let mut c = h.client();
    let (_, hello) = ClientHandshake::new("old", "o").unwrap();
    c.send_raw(&MAGIC);
    c.send(&Message::ClientHello(ClientHello { proto: 1, ..hello }));
    match c.expect() {
        Message::ServerBye(b) => assert_eq!(b.reason, ByeReason::ProtoMismatch),
        m => panic!("{m:?}"),
    }
    assert!(c.recv().is_none());
}

#[test]
fn control_refused_for_auth_none() {
    let h = harness(test_config());
    h.server.set_control_available(true);
    let mut c = h.client();
    c.handshake("ctl"); // told control_unavailable despite the host
    c.send(&Message::GlobalAction(GlobalAction::Home));
    // PING round-trip orders after the control message on the reader thread.
    c.send(&Message::Ping([9; 8]));
    // No STATUS for a `none` session when availability changes.
    h.server.set_control_available(false);
    h.server.set_control_available(true);
    assert_eq!(c.expect(), Message::Pong([9; 8]));
    c.sync(1);
    assert_eq!(h.control.0.load(Ordering::SeqCst), 0);
}

#[test]
fn busy_port_falls_back_to_ephemeral() {
    let blocker = TcpListener::bind("127.0.0.1:0").unwrap();
    let busy = blocker.local_addr().unwrap().port();
    let mut cfg = test_config();
    cfg.port = busy;
    let h = harness(cfg);
    assert_ne!(h.server.port(), busy);
    assert_ne!(h.server.port(), 0);
    h.client().handshake("ok");
}

#[test]
fn default_bind_accepts_ipv4_loopback() {
    let mut cfg = test_config();
    cfg.bind_addr = None; // dual-stack [::] where available
    let h = harness(cfg);
    h.client().handshake("v4");
}

#[test]
fn server_disconnect_sends_bye() {
    let h = harness(test_config());
    let mut c = h.client();
    c.stream("d");
    assert!(h.server.disconnect(ByeReason::ProjectionRevoked));
    loop {
        match c.expect() {
            Message::VideoFrame(_) => {}
            Message::ServerBye(b) => {
                assert_eq!(b.reason, ByeReason::ProjectionRevoked);
                break;
            }
            m => panic!("{m:?}"),
        }
    }
    assert!(c.recv().is_none());
}

#[test]
fn drop_client_closes_without_bye_and_accepts_a_new_client() {
    let h = harness(test_config());
    assert!(!h.server.drop_client(), "no client yet");
    let mut c = h.client();
    c.stream("d");
    assert_eq!(h.next_state(), (ClientState::Connecting, "d".into()));
    assert_eq!(h.next_state(), (ClientState::Streaming, "d".into()));

    assert!(h.server.drop_client());
    assert!(!h.server.drop_client(), "already ending");
    // Video may still arrive, but the connection ends without a BYE (EOF,
    // not the client's read timeout).
    let t0 = Instant::now();
    loop {
        match c.recv() {
            Some(Message::VideoFrame(_)) => {}
            Some(m) => panic!("expected EOF without BYE, got {m:?}"),
            None => break,
        }
    }
    assert!(t0.elapsed() < Duration::from_secs(2), "{:?}", t0.elapsed());
    assert_eq!(
        h.next_state(),
        (
            ClientState::Disconnected(DisconnectReason::Server),
            "d".into()
        )
    );
    assert!(h.server.client().is_none());
    // A BYE cannot follow on the dropped session.
    assert!(!h.server.disconnect(ByeReason::StoppedByUser));

    // The receiver reconnects and streams from a fresh config + keyframe.
    let mut again = h.client();
    again.stream("d2");
    assert_eq!(h.server.client().map(|c| c.name), Some("d2".into()));
}

#[test]
fn stop_joins_everything_and_is_idempotent() {
    let h = harness(test_config());
    let port = h.server.port();
    let mut streaming = h.client();
    streaming.stream("s");
    let mut half = h.client();
    let _hs = half.hello("half"); // stuck mid-handshake
    half.server_hello();
    let mut idle = h.client(); // connected, nothing sent

    let Harness {
        server,
        src,
        src_rx,
        ev_rx,
        ..
    } = h;
    let (done_tx, done_rx) = mpsc::channel();
    let stopper = thread::spawn(move || {
        server.stop();
        server.stop(); // idempotent
        drop(server); // Drop runs stop() again
        done_tx.send(()).unwrap();
    });
    done_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("stop() did not return");
    stopper.join().unwrap();

    loop {
        match streaming.recv() {
            Some(Message::VideoFrame(_)) => {}
            Some(Message::ServerBye(b)) => {
                assert_eq!(b.reason, ByeReason::StoppedByUser);
                break;
            }
            other => panic!("{other:?}"),
        }
    }
    assert!(streaming.recv().is_none());
    assert!(half.recv().is_none());
    assert!(idle.closed_by_server());

    // Source was stopped and its thread joined.
    let evs: Vec<SrcEvent> = src_rx.try_iter().collect();
    assert_eq!(evs.last(), Some(&SrcEvent::Stop), "{evs:?}");
    assert!(src.state.lock().unwrap().is_none());
    let states: Vec<Ev> = ev_rx.try_iter().collect();
    assert!(
        states.contains(&Ev::State(
            ClientState::Disconnected(DisconnectReason::Server),
            "s".into()
        )),
        "{states:?}"
    );
    // Nothing listens any more.
    assert!(TcpStream::connect(("127.0.0.1", port)).is_err());
}

#[test]
fn idle_socket_flood_cannot_lock_out_a_real_client() {
    // All test sockets share 127.0.0.1, so the per-IP cap (2) applies: each
    // new connection evicts that IP's oldest pending handshake instead of
    // being refused once the global cap (4) is reached. (Cross-IP fairness
    // is covered by the `pending` unit tests.)
    let h = harness(test_config());
    let mut idle: Vec<Client> = (0..4).map(|_| h.client()).collect();
    for c in &idle {
        c.s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    }
    let mut real = h.client();
    real.handshake("real");
    assert_eq!(h.next_state(), (ClientState::Connecting, "real".into()));
    // The oldest idle sockets were closed long before the 5 s handshake
    // timeout to make room.
    let t0 = Instant::now();
    for c in &mut idle[..3] {
        assert!(c.closed_by_server(), "oldest idle sockets are evicted");
    }
    assert!(t0.elapsed() < Duration::from_secs(2), "{:?}", t0.elapsed());
    real.send(&Message::Ping([7; 8]));
    assert_eq!(real.expect(), Message::Pong([7; 8]));
}

struct FailingSource;
impl VideoSource for FailingSource {
    fn start(&self, _p: StreamParams, _sink: FrameSink) -> Result<(), SourceError> {
        Err("encoder busy".into())
    }
    fn request_keyframe(&self) {}
    fn stop(&self) {}
}

#[test]
fn source_start_failure_sends_bye_unknown() {
    let (tx, ev_rx) = mpsc::channel();
    let (ptx, _prx) = mpsc::channel();
    let events = Events {
        tx: Mutex::new(tx),
        pair: Mutex::new(ptx),
        modes: Mutex::new(Vec::new()),
        paired_gate: Mutex::new(None),
    };
    let server = Server::start(
        test_config(),
        Arc::new(FailingSource),
        Arc::new(events),
        Arc::new(CountingControl::default()),
    )
    .expect("server start");
    let mut c = Client::connect(server.port());
    c.handshake("f");
    c.send(&Message::Start(Start::default()));
    match c.expect() {
        Message::ServerBye(b) => assert_eq!(b.reason, ByeReason::Unknown),
        m => panic!("expected BYE, got {m:?}"),
    }
    assert!(c.recv().is_none(), "EOF after BYE");
    let evs: Vec<Ev> = (0..3).map(|_| ev_rx.recv_timeout(T).unwrap()).collect();
    assert!(
        evs.contains(&Ev::State(
            ClientState::Disconnected(DisconnectReason::SourceFailed),
            "f".into()
        )),
        "{evs:?}"
    );
    assert!(
        evs.iter()
            .any(|e| matches!(e, Ev::Error(HostError::SourceStart(_)))),
        "{evs:?}"
    );
}

#[test]
fn screen_off_is_replayed_to_new_clients() {
    let h = harness(test_config());
    assert!(!h.server.send_status(StatusState::ScreenOff), "no client");
    assert!(
        !h.server.send_status(StatusState::Reconfiguring),
        "no client"
    );
    let mut c = h.client();
    c.handshake("late");
    // STATUS screen_off right after AUTH_RESULT; the transient
    // `reconfiguring` is not replayed.
    match c.expect() {
        Message::Status(s) => assert_eq!(s.state, StatusState::ScreenOff),
        m => panic!("expected STATUS screen_off, got {m:?}"),
    }
    // The documented START -> VIDEO_CONFIG -> keyframe order still holds.
    c.send(&Message::Start(Start::default()));
    match c.expect() {
        Message::VideoConfig(_) => {}
        m => panic!("{m:?}"),
    }
    match c.expect() {
        Message::VideoFrame(f) => assert_eq!(f.flags, flags::KEYFRAME),
        m => panic!("{m:?}"),
    }
    drop(c);

    // Screen back on: a new client is not told anything, and transient
    // states never become sticky.
    h.server.send_status(StatusState::ScreenOn);
    let t0 = Instant::now();
    while h.server.client().is_some() {
        assert!(t0.elapsed() < T, "dropped client never ended");
        thread::sleep(Duration::from_millis(5));
    }
    assert!(
        !h.server.send_status(StatusState::Reconfiguring),
        "no client"
    );
    let mut c = h.client();
    c.handshake("after");
    c.send(&Message::Ping([3; 8]));
    // The PONG is the first message after AUTH_RESULT: no STATUS before it.
    assert_eq!(c.expect(), Message::Pong([3; 8]));
}

// ---------------------------------------------------------------------------
// v2: pairing, records, control gate
// ---------------------------------------------------------------------------

/// A valid PIN that is not `pin`.
fn other_pin(pin: &str) -> String {
    let n: u32 = pin.parse().unwrap();
    format!("{:06}", (n + 1) % 1_000_000)
}

#[test]
fn pin_pairing_persists_rotates_and_token_reconnects() {
    let dir = TempDir::new("pair");
    let mut cfg = paired_config();
    cfg.pairing_store = Some(dir.store());
    let h = harness(cfg.clone());
    let pin0 = h.server.pin().to_string();
    assert!(pin0.len() == 6 && pin0.bytes().all(|b| b.is_ascii_digit()));

    let mut c = h.client();
    let est = c.auth("mac", ClientCredential::Pin(pin0.clone())).unwrap();
    assert_eq!(est.mode, AuthMode::Pin);
    let pk = est.pairing_key.expect("pairing key");
    c.expect_status(StatusState::ControlUnavailable);
    match h.next_pair() {
        PairEv::Paired(p) => {
            assert_eq!(
                (p.client_id.as_str(), p.client_name.as_str()),
                ("mac-id", "mac")
            );
            assert!(p.paired_at_ms > 0);
        }
        e => panic!("{e:?}"),
    }
    let pin1 = match h.next_pair() {
        PairEv::PinChanged(p) => p,
        e => panic!("{e:?}"),
    };
    assert_ne!(pin1, pin0, "PIN rotates after a pairing");
    assert_eq!(h.server.pin().to_string(), pin1);
    assert_eq!(h.next_state(), (ClientState::Connecting, "mac".into()));
    c.sync(1); // the session runs over records

    let listed = h.server.list_paired();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].client_id, "mac-id");

    // Persisted: version 1, the same key, owner-only permissions.
    let v = read_store(&dir.store());
    assert_eq!(v["version"], 1);
    assert_eq!(v["pairings"][0]["clientId"], "mac-id");
    assert_eq!(v["pairings"][0]["clientName"], "mac");
    assert_eq!(v["pairings"][0]["key"], pk.to_hex().as_str());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir.store()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "{mode:o}");
    }
    assert_eq!(dir.names(), ["pairings.json"], "no temp files left");
    drop(c);
    assert_eq!(
        h.next_state().0,
        ClientState::Disconnected(DisconnectReason::Closed)
    );

    // The used PIN is gone.
    let mut eve = h.client();
    assert_eq!(
        eve.auth("eve", ClientCredential::Pin(pin0)).unwrap_err(),
        HandshakeError::WrongPin
    );
    drop(eve);
    assert_eq!(h.next_pair(), PairEv::Failed(MAX_PIN_FAILURES - 1, None));

    // Token mode with the stored key.
    let mut c = h.client();
    let est = c.auth("mac", ClientCredential::Token(pk.clone())).unwrap();
    assert_eq!(est.mode, AuthMode::Token);
    assert!(est.pairing_key.is_none());
    c.expect_status(StatusState::ControlUnavailable);
    assert_eq!(h.next_state(), (ClientState::Connecting, "mac".into()));
    assert_eq!(h.server.client().map(|i| i.auth), Some(AuthMode::Token));
    assert_eq!(
        *h.events.modes.lock().unwrap(),
        vec![AuthMode::Pin, AuthMode::Pin, AuthMode::Token]
    );
    drop(c);
    drop(h);

    // ...and after a restart, from the file.
    let h = harness(cfg);
    assert_eq!(h.server.list_paired().len(), 1);
    let mut c = h.client();
    c.auth("mac", ClientCredential::Token(pk)).unwrap();
    c.expect_status(StatusState::ControlUnavailable);
}

#[test]
fn five_wrong_pins_lock_out_and_rotate() {
    let h = harness(paired_config());
    let pin0 = h.server.pin().to_string();
    let wrong = other_pin(&pin0);
    for left in (1..MAX_PIN_FAILURES).rev() {
        let mut c = h.client();
        assert_eq!(
            c.auth("eve", ClientCredential::Pin(wrong.clone()))
                .unwrap_err(),
            HandshakeError::WrongPin
        );
        drop(c); // the client closes without AUTH_CONFIRM
        assert_eq!(h.next_pair(), PairEv::Failed(left, None));
        assert_eq!(
            h.server.pin().to_string(),
            pin0,
            "no rotation before the limit"
        );
    }
    let mut c = h.client();
    assert!(c.auth("eve", ClientCredential::Pin(wrong)).is_err());
    drop(c);
    assert_eq!(h.next_pair(), PairEv::Failed(0, Some(PIN_LOCKOUT)));
    let pin1 = match h.next_pair() {
        PairEv::PinChanged(p) => p,
        e => panic!("{e:?}"),
    };
    assert_ne!(pin1, pin0);
    assert_eq!(h.server.pin().to_string(), pin1);

    // Even the new, correct PIN is refused during the lockout.
    let mut c = h.client();
    match c.auth("mac", ClientCredential::Pin(pin1)) {
        Err(HandshakeError::Rejected {
            reason: AuthReason::LockedOut,
            retry_after_ms: Some(ms),
        }) => assert!(
            (20_000..=PIN_LOCKOUT.as_millis() as u64).contains(&ms),
            "{ms}"
        ),
        r => panic!("expected locked_out, got {r:?}"),
    }
    c.expect_auth_failed_bye();
    match h.next_pair() {
        PairEv::Failed(0, Some(d)) => assert!(d <= PIN_LOCKOUT),
        e => panic!("{e:?}"),
    }
    assert!(h.ev_rx.try_recv().is_err(), "no session was reported");
}

#[test]
fn abandoned_pin_attempt_is_counted() {
    let h = harness(paired_config());
    let pin = h.server.pin().to_string();
    // AUTH pin with the right PIN, then disconnect before PAKE_REPLY.
    let mut c = h.client();
    let hs = c.hello("eve");
    let sh = c.server_hello();
    let (auth, _wait) = hs
        .authenticate(&sh, ClientCredential::Pin(pin.clone()))
        .unwrap();
    c.send(&auth);
    drop(c);
    assert_eq!(h.next_pair(), PairEv::Failed(MAX_PIN_FAILURES - 1, None));
    assert_eq!(h.server.pin().to_string(), pin);
    // A success afterwards resets the count (the next failure leaves 4).
    h.pair("mac");
    let mut c = h.client();
    assert!(c
        .auth("eve", ClientCredential::Pin(pin))
        .is_err_and(|e| e == HandshakeError::WrongPin));
    drop(c);
    assert_eq!(h.next_pair(), PairEv::Failed(MAX_PIN_FAILURES - 1, None));
}

#[test]
fn revoke_kicks_the_session_and_forgets_the_key() {
    let h = harness(paired_config());
    let pk = h.pair("mac");
    let mut c = h.client();
    c.auth("mac", ClientCredential::Token(pk.clone())).unwrap();
    c.expect_status(StatusState::ControlUnavailable);
    assert_eq!(h.next_state().0, ClientState::Connecting);

    assert!(h.server.revoke("mac-id"));
    match c.expect() {
        Message::ServerBye(b) => assert_eq!(b.reason, ByeReason::AuthFailed),
        m => panic!("{m:?}"),
    }
    assert!(c.recv().is_none());
    drop(c); // a receiver closes after BYE
    assert_eq!(
        h.next_state(),
        (
            ClientState::Disconnected(DisconnectReason::Server),
            "mac".into()
        )
    );
    assert!(!h.server.revoke("mac-id"), "already gone");
    assert!(h.server.list_paired().is_empty());

    let mut c = h.client();
    match c.auth("mac", ClientCredential::Token(pk)) {
        Err(HandshakeError::Rejected {
            reason: AuthReason::UnknownClient,
            ..
        }) => {}
        r => panic!("expected unknown_client, got {r:?}"),
    }
    c.expect_auth_failed_bye();
}

/// A receiver revoked while no server runs (the phone's "remove" before
/// mirroring starts) cannot authenticate once the server starts again.
#[test]
fn offline_revoke_is_durable_across_a_restart() {
    let dir = TempDir::new("offline-revoke");
    let mut cfg = paired_config();
    cfg.pairing_store = Some(dir.store());
    let h = harness(cfg.clone());
    let pk = h.pair("mac");
    let _ = h.pair("other");
    drop(h); // stops the server

    let ids = |v: Vec<PairedClient>| v.into_iter().map(|p| p.client_id).collect::<Vec<_>>();
    let listed = mirror_sender::list_paired_at(&dir.store()).unwrap();
    assert_eq!(ids(listed), ["mac-id", "other-id"]);
    assert_eq!(mirror_sender::revoke_at(&dir.store(), "mac-id"), Ok(true));
    assert_eq!(mirror_sender::revoke_at(&dir.store(), "mac-id"), Ok(false));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir.store()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "{mode:o}");
    }

    let h = harness(cfg);
    assert_eq!(ids(h.server.list_paired()), ["other-id"]);
    let mut c = h.client();
    match c.auth("mac", ClientCredential::Token(pk)) {
        Err(HandshakeError::Rejected {
            reason: AuthReason::UnknownClient,
            ..
        }) => {}
        r => panic!("expected unknown_client, got {r:?}"),
    }
    c.expect_auth_failed_bye();
}

/// A pairing revoked between key storage and activation: the session is
/// never active, so the host gets no client_state for it (a Connecting would
/// make the Android shell treat it as the new active session) and the
/// active client keeps streaming untouched.
#[test]
fn session_revoked_before_activation_is_invisible_to_the_host() {
    let h = harness(paired_config());
    let pk = h.pair("mac");
    let mut a = h.client();
    a.auth("mac", ClientCredential::Token(pk)).unwrap();
    a.expect_status(StatusState::ControlUnavailable);
    assert_eq!(h.next_state(), (ClientState::Connecting, "mac".into()));

    let (release, gate) = mpsc::channel();
    *h.events.paired_gate.lock().unwrap() = Some(gate);
    let pin = h.server.pin().to_string();
    let t = thread::spawn({
        let port = h.server.port();
        move || {
            let mut b = Client::connect(port);
            b.auth("eve", ClientCredential::Pin(pin)).expect("pairing");
            // Encrypted BYE auth_failed, then EOF; no STATUS first.
            match b.expect() {
                Message::ServerBye(bye) => assert_eq!(bye.reason, ByeReason::AuthFailed),
                m => panic!("expected BYE auth_failed, got {m:?}"),
            }
            assert!(b.recv().is_none());
        }
    });
    assert!(matches!(h.next_pair(), PairEv::Paired(p) if p.client_id == "eve-id"));
    assert!(h.server.revoke("eve-id"));
    release.send(()).unwrap();
    t.join().unwrap();

    assert!(
        h.ev_rx.recv_timeout(Duration::from_millis(500)).is_err(),
        "no client_state for a session that never became active"
    );
    assert_eq!(
        *h.events.modes.lock().unwrap(),
        [AuthMode::Pin, AuthMode::Pin, AuthMode::Token]
    );
    a.sync(1); // the active client is untouched
    assert_eq!(h.server.list_paired().len(), 1);
}

#[test]
fn token_with_a_wrong_key_is_bad_proof() {
    let h = harness(paired_config());
    h.pair("mac");
    let mut c = h.client();
    match c.auth(
        "mac",
        ClientCredential::Token(PairingKey::from_bytes([7; 32])),
    ) {
        Err(HandshakeError::Rejected {
            reason: AuthReason::BadProof,
            ..
        }) => {}
        r => panic!("expected bad_proof, got {r:?}"),
    }
    c.expect_auth_failed_bye();
    assert!(h.server.client().is_none());
}

#[test]
fn auth_none_refused_unless_allowed() {
    let h = harness(paired_config());
    let mut c = h.client();
    let hs = c.hello("x");
    let mut sh = c.server_hello();
    assert_eq!(sh.auth_modes, vec![AuthMode::Token, AuthMode::Pin]);
    sh.auth_modes.push(AuthMode::NoAuth); // a client that ignores the offer
    match c.finish_auth(hs, &sh, ClientCredential::NoAuth) {
        Err(HandshakeError::Rejected {
            reason: AuthReason::ModeUnsupported,
            ..
        }) => {}
        r => panic!("expected mode_unsupported, got {r:?}"),
    }
    c.expect_auth_failed_bye();
    assert!(h.ev_rx.try_recv().is_err(), "no session was reported");
}

#[test]
fn control_needs_pairing_and_availability() {
    let h = harness(paired_config());
    let pk = h.pair("mac");
    let count = || h.control.0.load(Ordering::SeqCst);
    let home = Message::GlobalAction(GlobalAction::Home);

    let mut c = h.client();
    c.auth("mac", ClientCredential::Token(pk.clone())).unwrap();
    c.expect_status(StatusState::ControlUnavailable);
    c.send(&Message::Start(Start::default()));
    c.send(&home);
    c.sync(1);
    assert_eq!(count(), 0, "dropped while unavailable");

    h.server.set_control_available(true);
    c.expect_status(StatusState::ControlAvailable);
    c.send(&home);
    c.sync(2);
    assert_eq!(count(), 1, "forwarded when paired and available");

    h.server.set_control_available(true); // no change: no STATUS
    h.server.set_control_available(false);
    c.expect_status(StatusState::ControlUnavailable);
    c.send(&home);
    c.sync(3);
    assert_eq!(count(), 1);

    // A new session is told the current state right after AUTH_RESULT.
    h.server.set_control_available(true);
    c.expect_status(StatusState::ControlAvailable);
    drop(c);
    let mut c = h.client();
    c.auth("mac", ClientCredential::Token(pk)).unwrap();
    c.expect_status(StatusState::ControlAvailable);
    // Control is accepted only after START (the first client record).
    c.send(&home);
    c.sync(4);
    assert_eq!(count(), 1, "dropped before START");
    c.send(&Message::Start(Start::default()));
    c.send(&home);
    c.sync(5);
    assert_eq!(count(), 2);
}

#[test]
fn bad_records_close_without_bye() {
    let h = harness(test_config());
    // Forged ciphertext with a plausible length.
    let mut c = h.client();
    c.handshake("g");
    assert_eq!(h.next_state().0, ClientState::Connecting);
    let mut rec = 40u32.to_be_bytes().to_vec();
    rec.extend([0xAB; 40]);
    c.send_raw(&rec);
    assert!(c.recv().is_none(), "closed without a BYE");
    assert_eq!(
        h.next_state().0,
        ClientState::Disconnected(DisconnectReason::ProtocolError)
    );

    // A replayed record (sequence number already used).
    let mut c = h.client();
    c.handshake("r");
    assert_eq!(h.next_state().0, ClientState::Connecting);
    let mut ping = Vec::new();
    c.tx.as_mut()
        .unwrap()
        .seal_message(&Message::Ping([5; 8]), &mut ping)
        .unwrap();
    c.send_raw(&ping);
    assert_eq!(c.expect(), Message::Pong([5; 8]));
    c.send_raw(&ping);
    assert!(c.recv().is_none());
    assert_eq!(
        h.next_state().0,
        ClientState::Disconnected(DisconnectReason::ProtocolError)
    );
}

#[test]
fn corrupt_store_is_moved_aside() {
    let dir = TempDir::new("corrupt");
    std::fs::write(dir.store(), b"{\"version\":1,\"pairings\":[").unwrap();
    let mut cfg = paired_config();
    cfg.pairing_store = Some(dir.store());
    let h = harness(cfg);
    assert!(h.server.list_paired().is_empty());
    assert!(!dir.store().exists());
    let bad = dir.0.join("pairings.json.bad");
    assert_eq!(
        std::fs::read(&bad).unwrap(),
        b"{\"version\":1,\"pairings\":[".to_vec()
    );
    h.pair("mac");
    assert_eq!(
        read_store(&dir.store())["pairings"][0]["clientId"],
        "mac-id"
    );
}

#[test]
fn store_evicts_the_oldest_beyond_the_cap() {
    let dir = TempDir::new("evict");
    let entries: Vec<serde_json::Value> = (0..MAX_PAIRINGS)
        .map(|i| {
            serde_json::json!({
                "clientId": format!("c{i}"),
                "clientName": format!("C{i}"),
                "key": format!("{:02x}", i).repeat(32),
                // c7 has the earliest timestamp, but eviction follows the
                // file (pairing) order, so a skewed clock cannot matter.
                "pairedAtMs": if i == 7 { 1 } else { 1000 + i as u64 },
            })
        })
        .collect();
    std::fs::write(
        dir.store(),
        serde_json::to_vec(&serde_json::json!({"version": 1, "pairings": entries})).unwrap(),
    )
    .unwrap();
    let mut cfg = paired_config();
    cfg.pairing_store = Some(dir.store());
    let h = harness(cfg);
    assert_eq!(h.server.list_paired().len(), MAX_PAIRINGS);

    // Keys loaded from the file authenticate.
    let mut c = Client::connect(h.server.port());
    let (hs, hello) = ClientHandshake::new("C3", "c3").unwrap();
    c.send_raw(&MAGIC);
    c.send(&Message::ClientHello(hello));
    let sh = c.server_hello();
    let key = PairingKey::from_bytes([3; 32]);
    c.finish_auth(hs, &sh, ClientCredential::Token(key))
        .unwrap();
    drop(c);

    h.pair("new");
    let ids: Vec<String> = h
        .server
        .list_paired()
        .into_iter()
        .map(|p| p.client_id)
        .collect();
    assert_eq!(ids.len(), MAX_PAIRINGS);
    assert!(!ids.contains(&"c0".to_string()), "first-paired evicted");
    assert!(ids.contains(&"c7".to_string()));
    assert!(ids.contains(&"new-id".to_string()));
    // Re-pairing the same client replaces its entry.
    h.pair("new");
    let list = h.server.list_paired();
    assert_eq!(list.len(), MAX_PAIRINGS);
    assert_eq!(list.iter().filter(|p| p.client_id == "new-id").count(), 1);
    assert_eq!(
        read_store(&dir.store())["pairings"]
            .as_array()
            .unwrap()
            .len(),
        MAX_PAIRINGS
    );
}

#[test]
fn fixed_pin_is_used_and_kept() {
    let mut cfg = paired_config();
    cfg.fixed_pin = Some("123456".into());
    let h = harness(cfg);
    assert_eq!(h.server.pin().to_string(), "123456");
    let mut c = h.client();
    c.auth("mac", ClientCredential::Pin("123456".into()))
        .unwrap();
    assert!(matches!(h.next_pair(), PairEv::Paired(_)));
    assert_eq!(h.server.pin().to_string(), "123456");
    assert!(
        h.pair_rx.recv_timeout(Duration::from_millis(200)).is_err(),
        "no pin_changed"
    );
}

#[test]
fn refused_pin_attempts_are_reported_at_most_once_per_interval() {
    let h = harness(paired_config());
    let wrong = other_pin(&h.server.pin());
    for _ in 0..MAX_PIN_FAILURES {
        let mut c = h.client();
        assert!(c.auth("eve", ClientCredential::Pin(wrong.clone())).is_err());
        drop(c);
        assert!(matches!(h.next_pair(), PairEv::Failed(..)));
    }
    assert!(matches!(h.next_pair(), PairEv::PinChanged(_)));
    // A flood of refused attempts during the lockout: every one is refused
    // with the remaining lockout, but the host hears about the first only.
    for _ in 0..4 {
        let mut c = h.client();
        assert!(matches!(
            c.auth("eve", ClientCredential::Pin(wrong.clone())),
            Err(HandshakeError::Rejected {
                reason: AuthReason::LockedOut,
                retry_after_ms: Some(_)
            })
        ));
        c.expect_auth_failed_bye();
    }
    assert!(matches!(h.next_pair(), PairEv::Failed(0, Some(_))));
    assert!(
        h.pair_rx.recv_timeout(Duration::from_millis(200)).is_err(),
        "one report per interval"
    );
}

/// All allowed attempts in flight (no lockout yet): the next one is told to
/// retry after the handshake timeout, not after a full lockout.
#[test]
fn in_flight_cap_retry_after_is_the_handshake_timeout() {
    let mut cfg = paired_config();
    cfg.max_pending_handshakes = 16;
    cfg.max_pending_handshakes_per_ip = 16;
    cfg.handshake_timeout = Duration::from_secs(4);
    let h = harness(cfg);
    let pin = h.server.pin().to_string();
    let mut held = Vec::new();
    for i in 0..MAX_PIN_FAILURES {
        let mut c = h.client();
        let hs = c.hello(&format!("p{i}"));
        let sh = c.server_hello();
        let (auth, _wait) = hs
            .authenticate(&sh, ClientCredential::Pin(pin.clone()))
            .unwrap();
        c.send(&auth);
        assert!(matches!(c.expect(), Message::PakeReply(_)), "admitted");
        held.push(c);
    }
    let mut c = h.client();
    match c.auth("late", ClientCredential::Pin(pin)) {
        Err(HandshakeError::Rejected {
            reason: AuthReason::LockedOut,
            retry_after_ms: Some(ms),
        }) => assert_eq!(ms, 4_000),
        r => panic!("expected locked_out, got {r:?}"),
    }
    c.expect_auth_failed_bye();
    // Not a lockout, and no attempt failed: the host is not told.
    assert!(h.pair_rx.recv_timeout(Duration::from_millis(300)).is_err());
    // The attempts in flight fail as they are dropped: the first reaches
    // the limit and starts the lockout (new PIN); the others then fail
    // during it and report it, never "0 left, not locked".
    drop(held);
    let evs: Vec<PairEv> = (0..=MAX_PIN_FAILURES).map(|_| h.next_pair()).collect();
    let locked = |e: &&PairEv| matches!(e, PairEv::Failed(0, Some(d)) if *d <= PIN_LOCKOUT);
    assert_eq!(
        evs.iter().filter(locked).count(),
        MAX_PIN_FAILURES as usize,
        "{evs:?}"
    );
    assert!(
        evs.contains(&PairEv::Failed(0, Some(PIN_LOCKOUT))),
        "{evs:?}"
    );
    assert_eq!(
        evs.iter()
            .filter(|e| matches!(e, PairEv::PinChanged(_)))
            .count(),
        1,
        "{evs:?}"
    );
}

/// A revoke whose removal cannot be written to the store returns false and
/// reports the error; the client is still forgotten (and kicked) until the
/// server stops.
#[cfg(unix)]
#[test]
fn revoke_that_cannot_be_persisted_returns_false() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new("revoke-ro");
    let mut cfg = paired_config();
    cfg.pairing_store = Some(dir.store());
    let h = harness(cfg.clone());
    let pk = h.pair("mac");
    std::fs::set_permissions(&dir.0, std::fs::Permissions::from_mode(0o500)).unwrap();
    if std::fs::write(dir.0.join("probe"), b"").is_ok() {
        return; // running as root: cannot make the directory read-only
    }
    assert!(!h.server.revoke("mac-id"));
    match h.ev_rx.recv_timeout(T).expect("host error") {
        Ev::Error(HostError::PairingStore(e)) => assert!(e.contains("pairings.json"), "{e}"),
        e => panic!("{e:?}"),
    }
    assert!(h.server.list_paired().is_empty(), "removed in memory");
    let mut c = h.client();
    assert!(matches!(
        c.auth("mac", ClientCredential::Token(pk.clone())),
        Err(HandshakeError::Rejected {
            reason: AuthReason::UnknownClient,
            ..
        })
    ));
    drop(c);
    drop(h);
    std::fs::set_permissions(&dir.0, std::fs::Permissions::from_mode(0o700)).unwrap();
    // Not persisted: after a restart the key is back.
    assert_eq!(harness(cfg).server.list_paired().len(), 1);
}

/// AUTH `pin` admitted, PAKE_REPLY received; the AUTH_CONFIRM not sent yet.
fn pin_in_flight(
    c: &mut Client,
    name: &str,
    pin: &str,
) -> (Message, mirror_protocol::handshake::ClientWait) {
    let hs = c.hello(name);
    let sh = c.server_hello();
    let (auth, wait) = hs
        .authenticate(&sh, ClientCredential::Pin(pin.into()))
        .unwrap();
    c.send(&auth);
    let reply = c.expect();
    assert!(matches!(reply, Message::PakeReply(_)), "admitted");
    (reply, wait)
}

/// A correct PIN whose attempt was in flight when the PIN rotated (another
/// receiver paired with it) does not pair: a PIN pairs exactly one receiver.
#[test]
fn pin_rotated_while_in_flight_does_not_pair() {
    let h = harness(paired_config());
    let pin = h.server.pin().to_string();
    let mut late = h.client();
    let (reply, wait) = pin_in_flight(&mut late, "late", &pin);
    h.pair("mac"); // rotates the PIN
    let ClientStep::Send(confirm, wait) = wait.on_message(&reply).unwrap() else {
        panic!("expected AUTH_CONFIRM to send");
    };
    late.send(&confirm);
    assert!(wait.on_message(&late.expect()).is_err(), "refused");
    late.expect_auth_failed_bye();
    assert!(matches!(h.next_pair(), PairEv::Failed(_, None)));
    let ids: Vec<_> = h
        .server
        .list_paired()
        .into_iter()
        .map(|p| p.client_id)
        .collect();
    assert_eq!(ids, [id_of("mac")]);
}

/// A PIN attempt cut short by `Server::stop` is not a failed attempt.
#[test]
fn pin_attempt_ended_by_stop_is_not_a_failure() {
    let h = harness(paired_config());
    let pin = h.server.pin().to_string();
    let mut c = h.client();
    let _in_flight = pin_in_flight(&mut c, "eve", &pin);
    h.server.stop();
    assert!(c.recv().is_none());
    assert!(
        h.pair_rx.recv_timeout(Duration::from_millis(300)).is_err(),
        "no pairing_failed"
    );
}

/// `FrameSink::fail` ends the sink's own session with BYE `unknown`; a
/// sink whose session was replaced does nothing (the new client stays).
#[test]
fn sink_fail_ends_only_its_own_session() {
    let h = harness(test_config());
    let mut a = h.client();
    a.stream("A");
    let sink_a = h.src.sink.lock().unwrap().clone().unwrap();
    let mut b = h.client();
    b.handshake("B"); // replaces A (no START yet: A's sink is still the source's)
    assert!(!sink_a.fail(), "A already ended");
    b.sync(1);
    assert_eq!(h.server.client().map(|c| c.name), Some("B".into()));

    b.send(&Message::Start(Start::default()));
    b.sync(2);
    let sink_b = loop {
        let s = h.src.sink.lock().unwrap().clone().unwrap();
        if s.is_active() {
            break s;
        }
        thread::sleep(Duration::from_millis(5));
    };
    assert!(sink_b.fail());
    loop {
        match b.expect() {
            Message::ServerBye(bye) => break assert_eq!(bye.reason, ByeReason::Unknown),
            Message::VideoConfig(_) | Message::VideoFrame(_) => {}
            m => panic!("{m:?}"),
        }
    }
    assert!(b.recv().is_none());
    let want = Ev::State(
        ClientState::Disconnected(DisconnectReason::SourceFailed),
        "B".into(),
    );
    while h.ev_rx.recv_timeout(T).expect("B disconnected") != want {}
    assert!(!sink_b.fail(), "only once");
}

/// A flood of REQUEST_KEYFRAME reaches the source rate-limited.
#[test]
fn client_keyframe_requests_are_throttled() {
    let h = harness(test_config());
    let mut c = h.client();
    c.stream("kf");
    assert!(matches!(h.next_src(), SrcEvent::Start(_)));
    let t0 = Instant::now();
    for _ in 0..50 {
        c.send(&Message::RequestKeyframe);
    }
    c.sync(1);
    let elapsed = t0.elapsed();
    let n = h
        .src_rx
        .try_iter()
        .filter(|e| *e == SrcEvent::Keyframe)
        .count();
    let allowed = 1 + (elapsed.as_millis() / 250) as usize;
    assert!(n >= 1 && n <= allowed, "{n} requests in {elapsed:?}");
}

/// A REQUEST_KEYFRAME inside the throttle interval is deferred, not
/// dropped: the receiver repeats an unanswered request only after 1 s
/// (backing off to 8 s; e.g. the IDR answering its previous request failed
/// to decode), so a dropped request would freeze the picture for that long.
/// Several coalesce into one, and it fires without further client traffic.
#[test]
fn throttled_keyframe_request_is_deferred_not_dropped() {
    let h = harness(test_config());
    let mut c = h.client();
    c.stream("kf");
    assert!(matches!(h.next_src(), SrcEvent::Start(_)));
    c.send(&Message::RequestKeyframe);
    assert_eq!(h.next_src(), SrcEvent::Keyframe);
    let t0 = Instant::now();
    c.send(&Message::RequestKeyframe);
    c.send(&Message::RequestKeyframe);
    // Within the interval plus scheduling slack, well before a PING (2 s)
    // would wake the reader.
    assert_eq!(
        h.src_rx.recv_timeout(Duration::from_millis(1500)),
        Ok(SrcEvent::Keyframe),
        "deferred request passed on"
    );
    assert!(
        t0.elapsed() >= Duration::from_millis(150),
        "{:?}",
        t0.elapsed()
    );
    assert!(
        h.src_rx.recv_timeout(Duration::from_millis(500)).is_err(),
        "coalesced into one"
    );
}

/// A replaced client that neither reads nor closes does not hold its
/// session (threads, socket) until the liveness timeout.
#[test]
fn replaced_stalled_session_ends_promptly() {
    let mut cfg = test_config();
    cfg.liveness_timeout = Duration::from_secs(20);
    let h = harness(cfg);
    let mut a = h.client();
    a.handshake("A"); // then silent: no PINGs, no reads, no close
    assert_eq!(h.next_state().0, ClientState::Connecting);
    let mut b = h.client();
    let t0 = Instant::now();
    b.handshake("B");
    let want = Ev::State(
        ClientState::Disconnected(DisconnectReason::Replaced),
        "A".into(),
    );
    while h.ev_rx.recv_timeout(T).expect("A disconnected") != want {}
    // About FAIL_LINGER (500 ms) in practice; anything well under the
    // liveness timeout proves the point, with room for a loaded CI host.
    assert!(t0.elapsed() < Duration::from_secs(10), "{:?}", t0.elapsed());
    drop(a);
}

/// Absurd durations are clamped instead of overflowing `Instant` math.
#[test]
fn huge_durations_do_not_break_the_server() {
    let mut cfg = test_config();
    cfg.handshake_timeout = Duration::MAX;
    cfg.liveness_timeout = Duration::MAX;
    cfg.bye_linger = Duration::MAX;
    cfg.keyframe_retry = Duration::MAX;
    let h = harness(cfg);
    let mut c = h.client();
    c.stream("big");
    c.sync(1);
}

/// `stop()` wakes the accept thread at once instead of waiting for a poll.
#[test]
fn stop_is_prompt() {
    let cfg = test_config();
    // No client, so no BYE linger is due; one linger of slack for a loaded
    // CI host. A hang (e.g. a missed wake-up) takes far longer.
    let bound = cfg.bye_linger + Duration::from_secs(2);
    let h = harness(cfg);
    let t0 = Instant::now();
    h.server.stop();
    assert!(t0.elapsed() < bound, "{:?}", t0.elapsed());
}

/// A malformed START (here a float `maxLongEdge`) is not skipped: the
/// client would wait for video forever. The session ends with BYE `unknown`.
#[test]
fn malformed_start_ends_the_session_with_bye_unknown() {
    let h = harness(test_config());
    let mut c = h.client();
    c.handshake("m");
    assert_eq!(h.next_state().0, ClientState::Connecting);
    c.send(&Message::Unknown {
        ty: ty::START,
        flags: 0,
        payload: br#"{"maxLongEdge":1920.0}"#.to_vec(),
    });
    match c.expect() {
        Message::ServerBye(b) => assert_eq!(b.reason, ByeReason::Unknown),
        m => panic!("expected BYE unknown, got {m:?}"),
    }
    assert!(c.recv().is_none(), "EOF after BYE");
    assert_eq!(
        h.next_state().0,
        ClientState::Disconnected(DisconnectReason::ProtocolError)
    );
    assert!(h.src_rx.try_recv().is_err(), "the source never started");
}

/// A tiny `maxLongEdge` reaches the source raised to `MIN_LONG_EDGE`.
#[test]
fn start_long_edge_floor_reaches_the_source() {
    let h = harness(test_config());
    let mut c = h.client();
    c.handshake("s");
    c.send(&Message::Start(Start {
        max_long_edge: Some(16),
        ..Start::default()
    }));
    match h.next_src() {
        SrcEvent::Start(p) => assert_eq!(p.max_long_edge, mirror_sender::MIN_LONG_EDGE),
        e => panic!("{e:?}"),
    }
}

/// `clientId` is bounded (it is persisted) and must not be empty: such a
/// hello gets no SERVER_HELLO.
#[test]
fn client_hello_fields_are_bounded() {
    let h = harness(test_config());
    let long = "x".repeat(257);
    for (name, id) in [("ok", ""), ("ok", long.as_str())] {
        let mut c = h.client();
        let (_hs, hello) = ClientHandshake::new(name, id).unwrap();
        c.send_raw(&MAGIC);
        c.send(&Message::ClientHello(hello));
        assert!(c.recv().is_none(), "refused: {} / {}", name.len(), id.len());
    }
    // 256 bytes each is fine.
    let max = "y".repeat(256);
    let mut c = h.client();
    let (hs, hello) = ClientHandshake::new(&max, &max).unwrap();
    c.send_raw(&MAGIC);
    c.send(&Message::ClientHello(hello));
    let sh = c.server_hello();
    c.finish_auth(hs, &sh, ClientCredential::NoAuth).unwrap();
}

/// An over-long `clientName` (a Mac's ComputerName may be long and
/// non-ASCII) still pairs; it is stored and shown cut to 256 bytes on a
/// character boundary, while the transcript binds the name as sent.
#[test]
fn over_long_client_name_pairs_and_is_truncated() {
    let h = harness(paired_config());
    let name = "é".repeat(200); // 400 bytes
    let id = "long-name-id";
    let pin = h.server.pin().to_string();
    let mut c = h.client();
    let (hs, hello) = ClientHandshake::new(&name, id).unwrap();
    c.send_raw(&MAGIC);
    c.send(&Message::ClientHello(hello));
    let sh = c.server_hello();
    c.finish_auth(hs, &sh, ClientCredential::Pin(pin))
        .expect("pairs");
    let cut = "é".repeat(128); // 256 bytes
    match h.next_pair() {
        PairEv::Paired(p) => assert_eq!((p.client_id.as_str(), p.client_name), (id, cut.clone())),
        e => panic!("{e:?}"),
    }
    assert!(matches!(h.next_pair(), PairEv::PinChanged(_)));
    assert_eq!(h.next_state(), (ClientState::Connecting, cut.clone()));
    assert_eq!(h.server.list_paired()[0].client_name, cut);
    // An odd cut point lands on the previous character boundary.
    let mut c = h.client();
    let odd = format!("x{name}"); // 401 bytes; byte 256 is mid-character
    let (hs, hello) = ClientHandshake::new(&odd, id).unwrap();
    c.send_raw(&MAGIC);
    c.send(&Message::ClientHello(hello));
    let sh = c.server_hello();
    let pin = h.server.pin().to_string();
    c.finish_auth(hs, &sh, ClientCredential::Pin(pin))
        .expect("pairs");
    match h.next_pair() {
        PairEv::Paired(p) => assert_eq!(p.client_name, format!("x{}", "é".repeat(127))),
        e => panic!("{e:?}"),
    }
}

/// Five wrong PINs from `eve`; returns the lockout. Consumes the failure
/// events and, unless the PIN is fixed, the rotation.
fn lock_out(h: &Harness, fixed: bool) -> Duration {
    let wrong = other_pin(&h.server.pin());
    for left in (0..MAX_PIN_FAILURES).rev() {
        let mut c = h.client();
        assert!(c.auth("eve", ClientCredential::Pin(wrong.clone())).is_err());
        drop(c);
        match h.next_pair() {
            PairEv::Failed(0, Some(d)) if left == 0 => {
                if !fixed {
                    assert!(matches!(h.next_pair(), PairEv::PinChanged(_)));
                }
                return d;
            }
            PairEv::Failed(l, None) => assert_eq!(l, left),
            e => panic!("{e:?}"),
        }
    }
    unreachable!()
}

/// "New PIN" rotates, clears the lockout and its escalation, and is not
/// echoed through `pin_changed` (the caller has the PIN).
#[test]
fn new_pin_clears_the_lockout_and_its_escalation() {
    let h = harness(paired_config());
    assert_eq!(lock_out(&h, false), PIN_LOCKOUT);
    let locked = h.server.pin().to_string();
    assert_eq!(h.server.pin_resets(), 0);
    let pin = h.server.new_pin();
    assert_eq!(h.server.pin_resets(), 1, "counts each New PIN");
    assert_ne!(*pin, locked);
    assert_eq!(*h.server.pin(), *pin);
    assert!(
        h.pair_rx.recv_timeout(Duration::from_millis(200)).is_err(),
        "no pin_changed for a host-initiated rotation"
    );
    // The escalation restarted: the next lockout is the first-level one.
    assert_eq!(lock_out(&h, false), PIN_LOCKOUT);
    let pin = h.server.new_pin();
    let mut c = h.client();
    c.auth("mac", ClientCredential::Pin(pin.to_string()))
        .expect("not locked out any more");
}

/// An attempt in flight on the old PIN fails after "New PIN".
#[test]
fn new_pin_refuses_attempts_in_flight_on_the_old_pin() {
    let h = harness(paired_config());
    let old = h.server.pin().to_string();
    let mut late = h.client();
    let (reply, wait) = pin_in_flight(&mut late, "late", &old);
    let _ = h.server.new_pin();
    let ClientStep::Send(confirm, wait) = wait.on_message(&reply).unwrap() else {
        panic!("expected AUTH_CONFIRM to send");
    };
    late.send(&confirm);
    assert!(wait.on_message(&late.expect()).is_err(), "refused");
    late.expect_auth_failed_bye();
    assert!(h.server.list_paired().is_empty());
}

/// With a fixed PIN, "New PIN" keeps it and only clears the lockout.
#[test]
fn new_pin_keeps_a_fixed_pin() {
    let mut cfg = paired_config();
    cfg.fixed_pin = Some("123456".into());
    let h = harness(cfg);
    lock_out(&h, true);
    assert_eq!(*h.server.new_pin(), "123456");
    let mut c = h.client();
    c.auth("mac", ClientCredential::Pin("123456".into()))
        .expect("lockout cleared");
}

/// A store that could not be loaded is an error for `try_list_paired`, not
/// an empty list ("nothing paired" would be wrong).
#[test]
fn unloadable_store_is_an_error_not_an_empty_list() {
    let dir = TempDir::new("newer");
    std::fs::write(dir.store(), br#"{"version":99,"pairings":[]}"#).unwrap();
    let mut cfg = paired_config();
    cfg.pairing_store = Some(dir.store());
    let h = harness(cfg.clone());
    assert!(h.server.try_list_paired().is_err());
    assert!(h.server.list_paired().is_empty());
    drop(h);
    std::fs::remove_file(dir.store()).unwrap();
    let h = harness(cfg);
    h.pair("mac");
    assert_eq!(h.server.try_list_paired().unwrap().len(), 1);
}
