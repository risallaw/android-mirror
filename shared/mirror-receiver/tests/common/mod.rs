//! Tiny scripted fake phone for client tests: a TcpListener on 127.0.0.1:0
//! speaking protocol v2 through `mirror-protocol`'s sans-IO handshake and
//! record layer.
#![allow(dead_code)]

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crossbeam_channel::Receiver;
use mirror_protocol::auth::PairingKey;
use mirror_protocol::handshake::{ServerHandshake, ServerStep};
use mirror_protocol::secure::{Opener, Sealer};
use mirror_protocol::{
    encode, Auth, AuthMode, AuthReason, Bye, ByeReason, ClientHello, Decoder, Message, ServerHello,
    Start, VideoConfig, VideoFrame, MAGIC, PROTO_VERSION,
};
use mirror_receiver::{ClientConfig, ClientEvent, Timeouts};

/// Generous upper bound for anything a test waits on; tests never rely on
/// it being short, only on it not being hit.
pub const WAIT: Duration = Duration::from_secs(5);

pub const DEVICE_ID: &str = "fake-1";
pub const DEVICE_NAME: &str = "Fake Phone";
pub const CLIENT_ID: &str = "client-1";

/// The phone's auth policy and pairing store.
#[derive(Debug, Clone)]
pub struct Phone {
    pub modes: Vec<AuthMode>,
    /// Current PIN (pin mode).
    pub pin: String,
    /// Pairing keys by clientId.
    pub keys: HashMap<String, PairingKey>,
    /// `Some(ms)`: refuse PIN attempts with `locked_out`.
    pub locked_ms: Option<u64>,
    /// Sealed and written in the same burst as the accepting AUTH_RESULT.
    pub pipelined: Vec<Message>,
}

impl Phone {
    /// Offers only `none` (and accepts it).
    pub fn open() -> Phone {
        Phone {
            modes: vec![AuthMode::NoAuth],
            pin: "123456".into(),
            keys: HashMap::new(),
            locked_ms: None,
            pipelined: Vec::new(),
        }
    }

    /// Offers `pin` + `token`, like the real app.
    pub fn paired_only(pin: &str) -> Phone {
        Phone {
            modes: vec![AuthMode::Pin, AuthMode::Token],
            pin: pin.into(),
            ..Phone::open()
        }
    }
}

/// How the server side of a handshake ended.
#[derive(Debug, PartialEq, Eq)]
pub enum ServerEnd {
    /// Accepted; START received.
    Accepted {
        hello: ClientHello,
        auth: Auth,
        start: Start,
    },
    /// The client hung up before sending AUTH (e.g. NeedsPin).
    NoAuth,
    /// The client hung up after PAKE_REPLY without AUTH_CONFIRM (it found
    /// the server's confirmation wrong).
    NoConfirm,
    /// We refused with this reason (AUTH_RESULT ok:false + BYE).
    Refused(AuthReason),
    /// Accepted, but the client never sent a valid START record.
    NoStart,
}

pub struct Conn {
    pub stream: TcpStream,
    dec: Decoder,
    /// Set once the handshake switched to records.
    secure: Option<(Sealer, Opener)>,
}

impl Conn {
    pub fn new(stream: TcpStream) -> Conn {
        stream.set_read_timeout(Some(WAIT)).unwrap();
        stream.set_nodelay(true).unwrap();
        Conn {
            stream,
            dec: Decoder::new(true),
            secure: None,
        }
    }

    pub fn write_raw(&mut self, b: &[u8]) {
        let _ = self.stream.write_all(b);
    }

    pub fn send_magic(&mut self) {
        self.write_raw(&MAGIC);
    }

    /// Plaintext before the handshake completes, a record afterwards.
    pub fn send(&mut self, m: &Message) {
        match &mut self.secure {
            Some((tx, _)) => {
                let mut out = Vec::new();
                tx.seal_message(m, &mut out).unwrap();
                self.write_raw(&out);
            }
            None => self.write_raw(&encode(m)),
        }
    }

    /// Seal raw frame bytes (header + payload) as one record.
    pub fn send_frame(&mut self, frame: &[u8]) {
        let (tx, _) = self.secure.as_mut().expect("secure channel");
        let mut out = Vec::new();
        tx.seal_frame(frame, &mut out).unwrap();
        self.write_raw(&out);
    }

    /// Next message (including PINGs); `None` on EOF, error or timeout.
    pub fn recv_any(&mut self) -> Option<Message> {
        let mut buf = [0u8; 4096];
        loop {
            let r = match &mut self.secure {
                Some((_, rx)) => rx.next(),
                None => self.dec.next(),
            };
            match r {
                Ok(Some(m)) => return Some(m),
                Ok(None) => {}
                Err(_) => return None,
            }
            match self.stream.read(&mut buf) {
                Ok(0) | Err(_) => return None,
                Ok(n) => match &mut self.secure {
                    Some((_, rx)) => rx.push(&buf[..n]),
                    None => self.dec.push(&buf[..n]),
                },
            }
        }
    }

    /// Next non-PING message; PINGs are answered with PONG.
    pub fn recv(&mut self) -> Option<Message> {
        loop {
            match self.recv_any()? {
                Message::Ping(p) => self.send(&Message::Pong(p)),
                m => return Some(m),
            }
        }
    }

    /// Server side of a v2 handshake under `phone`'s policy. New pairing
    /// keys are stored in `phone.keys`.
    pub fn accept(&mut self, phone: &mut Phone) -> ServerEnd {
        self.accept_with(phone, |_| {})
    }

    /// Like [`accept`](Self::accept); `tweak` may edit SERVER_HELLO after
    /// the handshake filled it in (e.g. to break the key exchange).
    pub fn accept_with(
        &mut self,
        phone: &mut Phone,
        tweak: impl FnOnce(&mut ServerHello),
    ) -> ServerEnd {
        self.send_magic();
        let hello = match self.recv() {
            Some(Message::ClientHello(h)) => h,
            other => panic!("expected CLIENT_HELLO, got {other:?}"),
        };
        let mut template = server_hello();
        template.auth_modes = phone.modes.clone();
        let (hs, mut sh) = ServerHandshake::new(&hello, template).expect("client hello");
        tweak(&mut sh);
        self.send(&Message::ServerHello(sh));
        let auth = match self.recv() {
            Some(Message::Auth(a)) => a,
            None => return ServerEnd::NoAuth,
            other => panic!("expected AUTH, got {other:?}"),
        };
        let offered = |m| phone.modes.contains(&m);
        let mut step = match auth.mode {
            AuthMode::Token if offered(AuthMode::Token) => {
                match phone.keys.get(hs.client_id()).cloned() {
                    Some(k) => hs.accept_token(&auth, &k),
                    None => reject(AuthReason::UnknownClient, None),
                }
            }
            AuthMode::Pin if offered(AuthMode::Pin) => match phone.locked_ms {
                Some(ms) => reject(AuthReason::LockedOut, Some(ms)),
                None => hs.start_pin(&auth, &phone.pin),
            },
            AuthMode::NoAuth if offered(AuthMode::NoAuth) => hs.accept_none(),
            _ => reject(AuthReason::ModeUnsupported, None),
        };
        if let ServerStep::Continue { reply, wait } = step {
            self.send(&reply);
            let confirm = match self.recv() {
                Some(Message::AuthConfirm(c)) => c,
                None => return ServerEnd::NoConfirm,
                other => panic!("expected AUTH_CONFIRM, got {other:?}"),
            };
            step = wait.on_confirm(&confirm);
        }
        match step {
            ServerStep::Accept { reply, session } => {
                if let Some(k) = session.pairing_key.clone() {
                    phone.keys.insert(hello.client_id.clone(), k);
                }
                let (mut tx, mut rx) = session.keys.server_channel();
                let mut burst = encode(&reply);
                for m in &phone.pipelined {
                    tx.seal_message(m, &mut burst).unwrap();
                }
                self.write_raw(&burst);
                rx.push(&self.dec.take_buffered());
                self.secure = Some((tx, rx));
                match self.recv() {
                    Some(Message::Start(start)) => ServerEnd::Accepted { hello, auth, start },
                    _ => ServerEnd::NoStart,
                }
            }
            ServerStep::Reject { reply, reason } => {
                self.send(&reply);
                self.send(&Message::ServerBye(Bye {
                    reason: ByeReason::AuthFailed,
                }));
                ServerEnd::Refused(reason)
            }
            ServerStep::Continue { .. } => unreachable!("pin wait handled above"),
        }
    }

    /// Magic, CLIENT_HELLO, a valid SERVER_HELLO offering `modes`; then the
    /// test scripts the rest by hand.
    pub fn hello(&mut self, modes: &[AuthMode]) -> ServerHandshake {
        self.send_magic();
        let hello = match self.recv() {
            Some(Message::ClientHello(h)) => h,
            other => panic!("expected CLIENT_HELLO, got {other:?}"),
        };
        let mut template = server_hello();
        template.auth_modes = modes.to_vec();
        let (hs, sh) = ServerHandshake::new(&hello, template).expect("client hello");
        self.send(&Message::ServerHello(sh));
        hs
    }

    /// Server side of a successful `none` handshake. Returns what the client sent.
    pub fn handshake(&mut self) -> (ClientHello, Auth, Start) {
        match self.accept(&mut Phone::open()) {
            ServerEnd::Accepted { hello, auth, start } => (hello, auth, start),
            other => panic!("handshake failed: {other:?}"),
        }
    }

    /// Read (answering PINGs) until EOF; returns every non-PING message.
    pub fn drain(&mut self) -> Vec<Message> {
        let mut v = Vec::new();
        while let Some(m) = self.recv() {
            v.push(m);
        }
        v
    }
}

fn reject(reason: AuthReason, retry_after_ms: Option<u64>) -> ServerStep {
    ServerStep::Reject {
        reply: ServerHandshake::rejection(reason, retry_after_ms),
        reason,
    }
}

/// SERVER_HELLO template (nonce/kx are filled in by the handshake).
pub fn server_hello() -> ServerHello {
    ServerHello {
        proto: PROTO_VERSION,
        device_name: DEVICE_NAME.into(),
        device_id: DEVICE_ID.into(),
        model: "Fake".into(),
        sdk_int: 35,
        codecs: vec!["h264".into()],
        caps: vec![],
        auth_modes: vec![AuthMode::NoAuth],
        nonce_s: String::new(),
        kx: String::new(),
    }
}

pub fn video_config() -> VideoConfig {
    VideoConfig {
        width: 864,
        height: 1920,
        display_width: 1080,
        display_height: 2400,
        rotation: 0,
        sps_pps: vec![0, 0, 0, 1, 0x67, 1, 2, 0, 0, 0, 1, 0x68, 3],
    }
}

pub fn frame(i: u64, key: bool) -> VideoFrame {
    VideoFrame {
        pts_us: i * 16_667,
        flags: if key { 1 } else { 0 },
        data: vec![0, 0, 0, 1, if key { 0x65 } else { 0x41 }, i as u8],
    }
}

/// Bind 127.0.0.1:0 and run `script` on each of the first `n` accepted
/// connections, in order, on one thread. Returns the script results.
pub fn serve_n<T, F>(n: usize, mut script: F) -> (SocketAddr, JoinHandle<Vec<T>>)
where
    T: Send + 'static,
    F: FnMut(usize, Conn) -> T + Send + 'static,
{
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let h = thread::spawn(move || {
        (0..n)
            .map(|i| {
                let (s, _) = l.accept().unwrap();
                script(i, Conn::new(s))
            })
            .collect()
    });
    (addr, h)
}

pub fn serve<T, F>(script: F) -> (SocketAddr, JoinHandle<T>)
where
    T: Send + 'static,
    F: FnOnce(Conn) -> T + Send + 'static,
{
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let h = thread::spawn(move || {
        let (s, _) = l.accept().unwrap();
        script(Conn::new(s))
    });
    (addr, h)
}

/// Test config: short but non-flaky timeouts; `none` allowed (most tests
/// are about transport, not auth).
pub fn config() -> ClientConfig {
    let mut c = ClientConfig::new("test-receiver", CLIENT_ID);
    c.allow_no_auth = true;
    c.timeouts = Timeouts {
        connect: Duration::from_secs(2),
        handshake: Duration::from_secs(2),
        ping_interval: Duration::from_millis(100),
        liveness: Duration::from_secs(3),
    };
    c
}

/// Test config for the auth tests: `none` not allowed.
pub fn secure_config() -> ClientConfig {
    let mut c = config();
    c.allow_no_auth = false;
    c
}

/// Next event other than `Rtt`; panics after [`WAIT`].
pub fn next(rx: &Receiver<ClientEvent>) -> ClientEvent {
    loop {
        match rx.recv_timeout(WAIT) {
            Ok(ClientEvent::Rtt(_)) => {}
            Ok(e) => return e,
            Err(e) => panic!("no event within {WAIT:?}: {e}"),
        }
    }
}
