//! Decode-thread tests: a scripted fake server + a fake decoder.

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::*;
use crossbeam_channel::{unbounded, Receiver};
use mirror_protocol::auth::PairingKey;
use mirror_protocol::{AuthMode, Key, Message, Status, StatusState, VideoConfig};
use mirror_receiver::address::Target;
use mirror_receiver::decoder::{
    DecodeError, FrameOutput, FramePool, FrameSlot, Nv12Frame, VideoDecoder,
};
use mirror_receiver::session::{Session, SessionMsg, SessionParams, MAX_DECODER_PANICS};
use mirror_receiver::stats::Stats;
use mirror_receiver::store::Store;
use mirror_receiver::{
    ClientConfig, ClientEvent, DecoderFactory, DisconnectReason, ReconnectPolicy, SendError,
};

/// Emits a 2x2 frame per decoded AU; fails on AUs whose last byte is 0xEE
/// and panics on 0xDD. A config without SPS/PPS is refused, and decoding
/// without an accepted config fails.
struct FakeDecoder {
    out: FrameOutput,
    log: Arc<Mutex<Vec<String>>>,
    configured: bool,
}

impl VideoDecoder for FakeDecoder {
    fn configure(&mut self, cfg: &VideoConfig) -> Result<(), DecodeError> {
        self.log
            .lock()
            .unwrap()
            .push(format!("config {}x{}", cfg.width, cfg.height));
        self.configured = !cfg.sps_pps.is_empty();
        if self.configured {
            Ok(())
        } else {
            Err(DecodeError::BadConfig("no SPS".into()))
        }
    }

    fn decode(&mut self, au: &[u8], pts_us: u64, key: bool) -> Result<(), DecodeError> {
        self.log
            .lock()
            .unwrap()
            .push(format!("decode {pts_us} key={key}"));
        if au.last() == Some(&0xDD) {
            panic!("fake decoder bug");
        }
        if !self.configured {
            return Err(DecodeError::NotConfigured);
        }
        if au.last() == Some(&0xEE) {
            return Err(DecodeError::Platform("boom".into()));
        }
        let mut y = self.out.pool().take(4);
        y.extend_from_slice(&[16; 4]);
        let mut uv = self.out.pool().take(2);
        uv.extend_from_slice(&[128; 2]);
        self.out.emit(Nv12Frame {
            width: 2,
            height: 2,
            y,
            y_stride: 2,
            uv,
            uv_stride: 2,
            pts_us,
        });
        Ok(())
    }
}

struct Harness {
    session: Session,
    msgs: Receiver<SessionMsg>,
    slot: FrameSlot,
    log: Arc<Mutex<Vec<String>>>,
}

fn start(addr: std::net::SocketAddr) -> Harness {
    start_with(addr, config())
}

fn start_with(addr: std::net::SocketAddr, client: ClientConfig) -> Harness {
    let log = Arc::new(Mutex::new(Vec::new()));
    let factory: DecoderFactory = {
        let log = log.clone();
        Arc::new(move |out| {
            Box::new(FakeDecoder {
                out,
                log: log.clone(),
                configured: false,
            }) as Box<dyn VideoDecoder>
        })
    };
    let (tx, msgs) = unbounded();
    let slot = FrameSlot::new(FramePool::new());
    let session = Session::start(SessionParams {
        target: Target {
            host: addr.ip().to_string(),
            port: addr.port(),
        },
        client,
        policy: ReconnectPolicy::default(),
        factory,
        slot: slot.clone(),
        stats: Arc::new(Mutex::new(Stats::new())),
        notify: Arc::new(move |m| {
            let _ = tx.send(m);
        }),
    })
    .unwrap();
    Harness {
        session,
        msgs,
        slot,
        log,
    }
}

fn next_msg(rx: &Receiver<SessionMsg>) -> SessionMsg {
    rx.recv_timeout(WAIT).expect("session message")
}

#[test]
fn gates_decodes_and_requests_keyframes() {
    let (addr, server) = serve(|mut c| {
        c.handshake();
        c.send(&Message::VideoConfig(video_config()));
        c.send(&Message::VideoFrame(frame(1, false))); // delta before IDR: dropped
                                                       // The drop asks for a keyframe.
        assert!(matches!(c.recv(), Some(Message::RequestKeyframe)));
        c.send(&Message::VideoFrame(frame(2, true)));
        c.send(&Message::VideoFrame(frame(3, false)));
        let mut bad = frame(4, false);
        bad.data.push(0xEE);
        c.send(&Message::VideoFrame(bad)); // decode error
        assert!(matches!(c.recv(), Some(Message::RequestKeyframe)));
        c.send(&Message::VideoFrame(frame(5, false))); // dropped until key
        c.send(&Message::VideoFrame(frame(6, true)));
        c.drain()
    });
    let h = start(addr);

    assert!(matches!(
        next_msg(&h.msgs),
        SessionMsg::Client(ClientEvent::Connected { .. })
    ));
    assert!(matches!(
        next_msg(&h.msgs),
        SessionMsg::Client(ClientEvent::VideoConfig(_))
    ));
    // Wait until the last keyframe was decoded.
    let deadline = std::time::Instant::now() + WAIT;
    while !h
        .log
        .lock()
        .unwrap()
        .iter()
        .any(|l| l.starts_with("decode 100002"))
    {
        assert!(std::time::Instant::now() < deadline, "{:?}", h.log);
        std::thread::sleep(Duration::from_millis(10));
    }
    let pts = |i: u64| i * 16_667;
    assert_eq!(
        *h.log.lock().unwrap(),
        vec![
            "config 864x1920".to_string(),
            format!("decode {} key=true", pts(2)),
            format!("decode {} key=false", pts(3)),
            format!("decode {} key=false", pts(4)),
            format!("decode {} key=true", pts(6)),
        ]
    );
    assert_eq!(h.slot.take().map(|f| f.pts_us), Some(pts(6)), "latest wins");

    // Stop: BYE goes out, final events and Ended arrive.
    assert!(h.session.stop_and_wait(WAIT));
    let mut rest = Vec::new();
    while let Ok(m) = h.msgs.try_recv() {
        rest.push(m);
    }
    assert!(matches!(rest.last(), Some(SessionMsg::Ended)), "{rest:?}");
    let sent = server.join().unwrap();
    assert!(
        sent.iter().any(|m| matches!(m, Message::ClientBye(_))),
        "{sent:?}"
    );
}

#[test]
fn a_decoded_frame_lets_the_next_failure_ask_for_a_keyframe_at_once() {
    use mirror_receiver::frame_gate::REREQUEST_AFTER;
    let (addr, server) = serve(|mut c| {
        c.handshake();
        c.send(&Message::VideoConfig(video_config()));
        c.send(&Message::VideoFrame(bad_frame(1, true, 0xEE))); // keyframe fails
        assert!(matches!(c.recv(), Some(Message::RequestKeyframe)));
        let first = std::time::Instant::now();
        c.send(&Message::VideoFrame(frame(2, true))); // decodes
                                                      // A delta that fails. The stream recovered in between, so this is
                                                      // a new wait: no backoff left over from the first request.
        c.send(&Message::VideoFrame(bad_frame(3, false, 0xEE)));
        // Bounded: the client's pings would keep a plain `recv` waiting.
        let again = loop {
            match c.recv_any() {
                Some(Message::RequestKeyframe) => break true,
                Some(Message::Ping(p)) => c.send(&Message::Pong(p)),
                Some(_) => {}
                None => break false,
            }
            if first.elapsed() > REREQUEST_AFTER * 2 {
                break false;
            }
        };
        (again, first.elapsed())
    });
    let h = start(addr);
    let (again, after) = server.join().unwrap();
    assert!(again, "a second request");
    assert!(
        after < REREQUEST_AFTER,
        "asked at once, not after the backoff: {after:?}"
    );
    assert!(h.session.stop_and_wait(WAIT));
}

#[test]
fn unresolvable_host_ends_the_session() {
    let log = Arc::new(Mutex::new(Vec::<String>::new()));
    let (tx, rx) = unbounded();
    let s = Session::start(SessionParams {
        target: Target {
            host: "no-such-host.invalid".into(),
            port: 1,
        },
        client: config(),
        policy: ReconnectPolicy::default(),
        factory: Arc::new(move |out| {
            Box::new(FakeDecoder {
                out,
                log: log.clone(),
                configured: false,
            }) as Box<dyn VideoDecoder>
        }),
        slot: FrameSlot::new(FramePool::new()),
        stats: Arc::new(Mutex::new(Stats::new())),
        notify: Arc::new(move |m| {
            let _ = tx.send(m);
        }),
    })
    .unwrap();
    assert!(matches!(next_msg(&rx), SessionMsg::ResolveFailed(_)));
    assert!(matches!(next_msg(&rx), SessionMsg::Ended));
    assert!(s.stop_and_wait(WAIT));
}

fn bad_frame(i: u64, key: bool, last: u8) -> mirror_protocol::VideoFrame {
    let mut f = frame(i, key);
    f.data.push(last);
    f
}

/// Wait until the fake decoder logged a line starting with `prefix`.
fn wait_for_log(h: &Harness, prefix: &str) {
    let deadline = std::time::Instant::now() + WAIT;
    while !h.log.lock().unwrap().iter().any(|l| l.starts_with(prefix)) {
        assert!(std::time::Instant::now() < deadline, "{:?}", h.log);
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn decoder_panic_restarts_the_decoder_and_asks_for_a_keyframe() {
    let (addr, server) = serve(|mut c| {
        c.handshake();
        c.send(&Message::VideoConfig(video_config()));
        c.send(&Message::VideoFrame(bad_frame(1, true, 0xDD)));
        // The rebuilt decoder needs an IDR.
        assert!(matches!(c.recv(), Some(Message::RequestKeyframe)));
        c.send(&Message::VideoFrame(frame(2, true)));
        c.drain()
    });
    let h = start(addr);
    wait_for_log(&h, &format!("decode {}", 2 * 16_667));
    let pts = |i: u64| i * 16_667;
    assert_eq!(
        *h.log.lock().unwrap(),
        vec![
            "config 864x1920".to_string(),
            format!("decode {} key=true", pts(1)),
            "config 864x1920".to_string(), // the fresh decoder, configured
            format!("decode {} key=true", pts(2)),
        ]
    );
    assert_eq!(h.slot.take().map(|f| f.pts_us), Some(pts(2)));
    assert!(h.session.stop_and_wait(WAIT));
    let mut rest = Vec::new();
    while let Ok(m) = h.msgs.try_recv() {
        rest.push(m);
    }
    assert!(
        rest.iter().any(|m| matches!(
            m,
            SessionMsg::Client(ClientEvent::Stopped(DisconnectReason::Closed))
        )),
        "the session kept running until stopped: {rest:?}"
    );
    server.join().unwrap();
}

#[test]
fn a_decoder_that_keeps_panicking_ends_the_session_visibly() {
    let (addr, server) = serve(|mut c| {
        c.handshake();
        c.send(&Message::VideoConfig(video_config()));
        for i in 1..MAX_DECODER_PANICS as u64 {
            c.send(&Message::VideoFrame(bad_frame(i, true, 0xDD)));
            if i == 1 {
                // Later failing keyframes wait out the request backoff.
                assert!(matches!(c.recv(), Some(Message::RequestKeyframe)));
            }
        }
        c.send(&Message::VideoFrame(bad_frame(9, true, 0xDD)));
        c.drain()
    });
    let h = start(addr);
    let mut got = Vec::new();
    loop {
        match h.msgs.recv_timeout(WAIT) {
            Ok(SessionMsg::Ended) => break,
            Ok(SessionMsg::Client(ev)) => got.push(ev),
            Ok(_) => {}
            Err(e) => panic!("no Ended after the decoder kept panicking ({e}): {got:?}"),
        }
    }
    match got.last() {
        Some(ClientEvent::Stopped(DisconnectReason::Protocol(m))) => {
            assert!(m.contains("decoder"), "{m}")
        }
        other => panic!("last event should explain the end, got {other:?} in {got:?}"),
    }
    assert!(
        !got.iter().any(|e| matches!(
            e,
            ClientEvent::Stopped(DisconnectReason::Closed)
                | ClientEvent::Disconnected(DisconnectReason::Closed)
        )),
        "the local close must not hide the reason: {got:?}"
    );
    assert!(h.session.stop_and_wait(WAIT), "thread is gone and joined");
    // The session hung up politely.
    let sent = server.join().unwrap();
    assert!(
        sent.iter().any(|m| matches!(m, Message::ClientBye(_))),
        "{sent:?}"
    );
}

#[test]
fn refused_config_asks_for_one_keyframe_not_one_per_failing_keyframe() {
    let (addr, server) = serve(|mut c| {
        c.handshake();
        let mut cfg = video_config();
        cfg.sps_pps.clear();
        c.send(&Message::VideoConfig(cfg));
        // One request for the decoder to retry on.
        assert!(matches!(c.recv(), Some(Message::RequestKeyframe)));
        for i in 1..=3 {
            c.send(&Message::VideoFrame(frame(i, true)));
            c.send(&Message::VideoFrame(frame(i * 10, false)));
        }
        // A good config recovers.
        c.send(&Message::VideoConfig(video_config()));
        c.send(&Message::VideoFrame(frame(7, true)));
        c.drain()
    });
    let h = start(addr);
    wait_for_log(&h, &format!("decode {}", 7 * 16_667));
    assert!(h.session.stop_and_wait(WAIT));
    let sent = server.join().unwrap();
    let requests = sent
        .iter()
        .filter(|m| matches!(m, Message::RequestKeyframe))
        .count();
    assert_eq!(requests, 0, "no more after the first: {sent:?}");
}

#[test]
fn pairs_by_pin_then_sends_control_once_available() {
    let (addr, server) = serve(|mut c| {
        let mut phone = Phone::paired_only("135790");
        phone.pipelined = vec![Message::Status(Status {
            state: StatusState::ControlAvailable,
        })];
        let end = c.accept(&mut phone);
        let got = c.recv();
        c.drain();
        (end, got, phone)
    });
    let store = Store::default();
    let mut cfg = secure_config();
    cfg.store = store.clone();
    cfg.pin = Some("135790".to_string().into());
    let h = start_with(addr, cfg);
    assert_eq!(
        h.session.send_control(Message::Key(Key::Tab)),
        Err(SendError::Disconnected)
    );
    let mut seen = Vec::new();
    while !matches!(
        seen.last(),
        Some(ClientEvent::Status(StatusState::ControlAvailable))
    ) {
        match next_msg(&h.msgs) {
            SessionMsg::Client(ev) => seen.push(ev),
            SessionMsg::FrameReady => {}
            m => panic!("unexpected {m:?}"),
        }
    }
    assert!(matches!(
        seen[0],
        ClientEvent::Connected {
            auth: AuthMode::Pin,
            ..
        }
    ));
    assert!(matches!(seen[1], ClientEvent::Paired { .. }), "{seen:?}");
    assert!(h.session.control_available());
    h.session.send_control(Message::Key(Key::Tab)).unwrap();
    assert!(h.session.stop_and_wait(WAIT));
    let (end, got, phone) = server.join().unwrap();
    assert!(matches!(end, ServerEnd::Accepted { .. }), "{end:?}");
    assert_eq!(got, Some(Message::Key(Key::Tab)));
    let key: PairingKey = phone.keys[CLIENT_ID].clone();
    assert_eq!(store.pairing_key(DEVICE_ID), Some(key));
}
