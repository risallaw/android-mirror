//! Client against a scripted fake server on loopback.

mod common;

use std::time::{Duration, Instant};

use common::*;
use mirror_protocol::{
    AuthMode, AuthReason, AuthResult, Bye, ByeReason, Header, Message, Start, Status, StatusState,
    MAX_PAYLOAD, PROTO_VERSION,
};
use mirror_receiver::{
    Client, ClientConfig, ClientEvent, DisconnectReason, SendError, TimeoutKind,
};

#[test]
fn default_event_queue_bounds_memory_from_huge_frames() {
    // Every queued event can be a MAX_PAYLOAD frame from a hostile phone.
    let cap = ClientConfig::new("r", "c").event_capacity;
    let worst = cap * MAX_PAYLOAD as usize;
    assert!(worst <= 128 << 20, "{cap} events = {} MiB", worst >> 20);
}

#[test]
fn happy_path_handshake_config_and_frames_in_order() {
    let (addr, server) = serve(|mut c| {
        let got = c.handshake();
        c.send(&Message::VideoConfig(video_config()));
        c.send(&Message::Status(Status {
            state: StatusState::Streaming,
        }));
        for i in 0..20 {
            c.send(&Message::VideoFrame(frame(i, i == 0)));
        }
        let rest = c.drain();
        (got, rest)
    });
    let mut cfg = config();
    cfg.start = Start {
        max_long_edge: Some(1280),
        max_fps: Some(30),
        bitrate: None,
    };
    let mut client = Client::connect(addr, cfg).expect("connect");
    let rx = client.events();
    match next(&rx) {
        ClientEvent::Connected {
            addr: a,
            server,
            auth,
        } => {
            assert_eq!(a, addr);
            assert_eq!(server.device_name, DEVICE_NAME);
            assert_eq!(server.kx.len(), 64);
            assert_eq!(auth, AuthMode::NoAuth);
        }
        e => panic!("expected Connected, got {e:?}"),
    }
    assert_eq!(client.auth_mode(), AuthMode::NoAuth);
    assert_eq!(client.server().device_id, "fake-1");
    assert_eq!(next(&rx), ClientEvent::VideoConfig(video_config()));
    assert_eq!(next(&rx), ClientEvent::Status(StatusState::Streaming));
    for i in 0..20 {
        assert_eq!(next(&rx), ClientEvent::VideoFrame(frame(i, i == 0)));
    }
    client.close();
    assert_eq!(
        next(&rx),
        ClientEvent::Disconnected(DisconnectReason::Closed)
    );

    let ((hello, auth, start), rest) = server.join().unwrap();
    assert_eq!(hello.proto, PROTO_VERSION);
    assert_eq!(hello.client_name, "test-receiver");
    assert_eq!(hello.client_id, "client-1");
    assert_eq!(hello.nonce_c.len(), 64);
    assert_eq!(hello.kx.len(), 64);
    assert_eq!(auth.mode, AuthMode::NoAuth);
    assert_eq!(auth.proof, "");
    assert_eq!(start.max_long_edge, Some(1280));
    assert_eq!(start.max_fps, Some(30));
    assert_eq!(start.bitrate, None);
    assert_eq!(
        rest,
        vec![Message::ClientBye(Bye {
            reason: ByeReason::StoppedByUser
        })]
    );
}

#[test]
fn a_long_computer_name_is_cut_to_what_the_phone_accepts() {
    let (addr, server) = serve(|mut c| {
        let (hello, ..) = c.handshake();
        c.drain();
        hello
    });
    let mut cfg = config();
    cfg.client_name = "Ä".repeat(200); // 400 bytes
    let mut client = Client::connect(addr, cfg).expect("connect");
    client.close();
    let hello = server.join().unwrap();
    assert_eq!(hello.client_name, "Ä".repeat(128));
}

#[test]
fn wrong_magic_is_protocol_error() {
    let (addr, server) = serve(|mut c| {
        c.write_raw(b"HTTP/1.1 400\r\n");
        c.drain();
    });
    let err = Client::connect(addr, config()).unwrap_err();
    assert!(
        matches!(&err, DisconnectReason::Protocol(m) if m.contains("magic")),
        "{err:?}"
    );
    server.join().unwrap();
}

#[test]
fn auth_result_not_ok_is_auth_failed() {
    let (addr, server) = serve(|mut c| {
        c.hello(&[AuthMode::NoAuth]);
        assert!(matches!(c.recv(), Some(Message::Auth(_))));
        c.send(&Message::AuthResult(AuthResult {
            ok: false,
            reason: Some(AuthReason::ModeUnsupported),
            ..Default::default()
        }));
        c.drain()
    });
    let err = Client::connect(addr, config()).unwrap_err();
    assert_eq!(
        err,
        DisconnectReason::AuthFailed {
            reason: Some(AuthReason::ModeUnsupported)
        }
    );
    assert!(err.to_string().contains("ModeUnsupported"), "{err}");
    // No START after a failed auth.
    assert!(server.join().unwrap().is_empty());
}

#[test]
fn bye_auth_failed_during_handshake_is_auth_failed() {
    let (addr, server) = serve(|mut c| {
        c.hello(&[AuthMode::NoAuth]);
        c.recv();
        c.send(&Message::ServerBye(Bye {
            reason: ByeReason::AuthFailed,
        }));
    });
    let err = Client::connect(addr, config()).unwrap_err();
    assert!(
        matches!(err, DisconnectReason::AuthFailed { .. }),
        "{err:?}"
    );
    server.join().unwrap();
}

#[test]
fn proto_mismatch_sends_bye_and_fails_clearly() {
    let (addr, server) = serve(|mut c| {
        c.send_magic();
        c.recv();
        let mut h = server_hello();
        h.proto = 7;
        c.send(&Message::ServerHello(h));
        c.drain()
    });
    let err = Client::connect(addr, config()).unwrap_err();
    assert_eq!(
        err,
        DisconnectReason::ProtoMismatch {
            ours: PROTO_VERSION,
            theirs: 7
        }
    );
    assert!(err.to_string().contains("v7"), "{err}");
    assert_eq!(
        server.join().unwrap(),
        vec![Message::ClientBye(Bye {
            reason: ByeReason::ProtoMismatch
        })]
    );
}

#[test]
fn no_usable_auth_mode_is_auth_unsupported_without_auth() {
    // Only `token` offered and no key stored: nothing we can send.
    let (addr, server) = serve(|mut c| {
        c.hello(&[AuthMode::Token]);
        c.drain()
    });
    let err = Client::connect(addr, config()).unwrap_err();
    assert_eq!(
        err,
        DisconnectReason::AuthUnsupported {
            offered: vec![AuthMode::Token]
        }
    );
    assert!(server.join().unwrap().is_empty());
}

#[test]
fn handshake_times_out_when_server_silent() {
    let (addr, server) = serve(|mut c| c.drain());
    let mut cfg = config();
    cfg.timeouts.handshake = Duration::from_millis(200);
    let t0 = Instant::now();
    let err = Client::connect(addr, cfg).unwrap_err();
    assert_eq!(err, DisconnectReason::Timeout(TimeoutKind::Handshake));
    assert!(t0.elapsed() >= Duration::from_millis(200));
    server.join().unwrap();
}

#[test]
fn connect_refused_is_io_error() {
    // Bind then drop to get a port with (almost certainly) no listener.
    let addr = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let err = Client::connect(addr, config()).unwrap_err();
    assert!(
        matches!(
            err,
            DisconnectReason::Io {
                kind: std::io::ErrorKind::ConnectionRefused,
                ..
            }
        ),
        "{err:?}"
    );
}

#[test]
fn ping_sent_and_pong_updates_rtt() {
    let (addr, server) = serve(|mut c| {
        c.handshake();
        // Wait for a PING, echo it, then keep echoing until the client closes.
        let p = loop {
            match c.recv_any() {
                Some(Message::Ping(p)) => break p,
                Some(_) => {}
                None => panic!("no PING"),
            }
        };
        c.send(&Message::Pong(p));
        c.drain();
    });
    let mut cfg = config();
    cfg.timeouts.ping_interval = Duration::from_millis(50);
    let mut client = Client::connect(addr, cfg).unwrap();
    let rx = client.events();
    assert!(matches!(next(&rx), ClientEvent::Connected { .. }));
    let rtt = match rx.recv_timeout(WAIT).expect("no RTT event") {
        ClientEvent::Rtt(d) => d,
        e => panic!("unexpected {e:?}"),
    };
    assert!(rtt < WAIT, "{rtt:?}");
    assert!(client.rtt().is_some());
    client.close();
    server.join().unwrap();
}

#[test]
fn liveness_timeout_when_server_goes_silent() {
    let (addr, server) = serve(|mut c| {
        c.handshake();
        // Never answer: read (ignoring PINGs) until the client hangs up.
        while c.recv_any().is_some() {}
    });
    let mut cfg = config();
    cfg.timeouts.liveness = Duration::from_millis(300);
    cfg.timeouts.ping_interval = Duration::from_millis(50);
    // Taken before connect: the liveness clock cannot start earlier.
    let t0 = Instant::now();
    let client = Client::connect(addr, cfg).unwrap();
    let rx = client.events();
    assert!(matches!(next(&rx), ClientEvent::Connected { .. }));
    assert_eq!(
        next(&rx),
        ClientEvent::Disconnected(DisconnectReason::Timeout(TimeoutKind::Liveness))
    );
    assert!(
        t0.elapsed() >= Duration::from_millis(300),
        "{:?}",
        t0.elapsed()
    );
    assert!(client.is_disconnected());
    drop(client);
    server.join().unwrap();
}

#[test]
fn server_bye_disconnects_with_reason() {
    let (addr, server) = serve(|mut c| {
        c.handshake();
        c.send(&Message::ServerBye(Bye {
            reason: ByeReason::Replaced,
        }));
        c.drain()
    });
    let mut client = Client::connect(addr, config()).unwrap();
    let rx = client.events();
    assert!(matches!(next(&rx), ClientEvent::Connected { .. }));
    assert_eq!(
        next(&rx),
        ClientEvent::Disconnected(DisconnectReason::Bye(ByeReason::Replaced))
    );
    assert_eq!(client.request_keyframe(), Err(SendError::Disconnected));
    client.close();
    // Exactly one Disconnected per connection.
    assert!(rx.recv_timeout(Duration::from_millis(100)).is_err());
    // The client did not answer the server's BYE with its own.
    assert!(server.join().unwrap().is_empty());
}

#[test]
fn peer_close_without_bye_is_connection_closed() {
    let (addr, server) = serve(|mut c| {
        c.handshake();
        c.send(&Message::VideoConfig(video_config()));
        // Dropping c closes the socket.
    });
    let client = Client::connect(addr, config()).unwrap();
    let rx = client.events();
    assert!(matches!(next(&rx), ClientEvent::Connected { .. }));
    assert_eq!(next(&rx), ClientEvent::VideoConfig(video_config()));
    match next(&rx) {
        ClientEvent::Disconnected(DisconnectReason::ConnectionClosed)
        | ClientEvent::Disconnected(DisconnectReason::Io { .. }) => {}
        e => panic!("unexpected {e:?}"),
    }
    server.join().unwrap();
}

#[test]
fn close_sends_bye_joins_threads_and_is_idempotent() {
    let (addr, server) = serve(|mut c| {
        c.handshake();
        c.drain()
    });
    let mut client = Client::connect(addr, config()).unwrap();
    let rx = client.events();
    assert!(matches!(next(&rx), ClientEvent::Connected { .. }));
    client.close();
    assert!(client.is_disconnected());
    assert_eq!(
        next(&rx),
        ClientEvent::Disconnected(DisconnectReason::Closed)
    );
    client.close();
    assert_eq!(client.request_keyframe(), Err(SendError::Disconnected));
    // Server saw BYE stopped_by_user followed by EOF (drain returned).
    assert_eq!(
        server.join().unwrap(),
        vec![Message::ClientBye(Bye {
            reason: ByeReason::StoppedByUser
        })]
    );
    assert!(rx.recv_timeout(Duration::from_millis(100)).is_err());
}

#[test]
fn drop_closes_with_bye() {
    let (addr, server) = serve(|mut c| {
        c.handshake();
        c.drain()
    });
    let client = Client::connect(addr, config()).unwrap();
    drop(client);
    assert_eq!(
        server.join().unwrap(),
        vec![Message::ClientBye(Bye {
            reason: ByeReason::StoppedByUser
        })]
    );
}

#[test]
fn close_does_not_hang_when_events_are_not_consumed() {
    let (addr, server) = serve(|mut c| {
        c.handshake();
        for i in 0..50 {
            c.send(&Message::VideoFrame(frame(i, i == 0)));
        }
        c.drain()
    });
    let mut cfg = config();
    cfg.event_capacity = 2;
    let mut client = Client::connect(addr, cfg).unwrap();
    std::thread::sleep(Duration::from_millis(100)); // let the reader block
    let t0 = Instant::now();
    client.close();
    assert!(t0.elapsed() < Duration::from_secs(2), "{:?}", t0.elapsed());
    server.join().unwrap();
}

#[test]
fn request_keyframe_and_generic_send_reach_server() {
    let (addr, server) = serve(|mut c| {
        c.handshake();
        let a = c.recv();
        let b = c.recv();
        c.send(&Message::ServerBye(Bye {
            reason: ByeReason::StoppedByUser,
        }));
        (a, b)
    });
    let client = Client::connect(addr, config()).unwrap();
    let rx = client.events();
    assert!(matches!(next(&rx), ClientEvent::Connected { .. }));
    client.request_keyframe().unwrap();
    client
        .send(Message::Text("hi".into()))
        .expect("send queued");
    assert_eq!(
        next(&rx),
        ClientEvent::Disconnected(DisconnectReason::Bye(ByeReason::StoppedByUser))
    );
    let (a, b) = server.join().unwrap();
    assert_eq!(a, Some(Message::RequestKeyframe));
    assert_eq!(b, Some(Message::Text("hi".into())));
}

#[test]
fn malformed_and_unknown_messages_are_skipped() {
    let (addr, server) = serve(|mut c| {
        c.handshake();
        c.send(&Message::VideoFrame(frame(0, true)));
        // Unknown type 0x30 with a payload: skipped by length.
        c.send(&Message::Unknown {
            ty: 0x30,
            flags: 0,
            payload: vec![1, 2, 3],
        });
        // Reserved audio type.
        c.send(&Message::Unknown {
            ty: 0x09,
            flags: 0,
            payload: vec![9; 100],
        });
        // Malformed STATUS JSON and a too-short VIDEO_CONFIG.
        let mut bad = Header {
            ty: 0x05,
            flags: 0,
            length: 3,
            pts_us: 0,
        }
        .encode()
        .to_vec();
        bad.extend_from_slice(b"{x}");
        let mut short = Header {
            ty: 0x03,
            flags: 2,
            length: 4,
            pts_us: 0,
        }
        .encode()
        .to_vec();
        short.extend_from_slice(&[0; 4]);
        c.send_frame(&bad);
        c.send_frame(&short);
        // A PONG we never asked for (garbage timestamp from the future).
        c.send(&Message::Pong([0xff; 8]));
        c.send(&Message::VideoFrame(frame(1, false)));
        c.drain();
    });
    let mut cfg = config();
    cfg.timeouts.ping_interval = Duration::from_secs(60);
    let mut client = Client::connect(addr, cfg).unwrap();
    let rx = client.events();
    assert!(matches!(next(&rx), ClientEvent::Connected { .. }));
    assert_eq!(next(&rx), ClientEvent::VideoFrame(frame(0, true)));
    assert_eq!(next(&rx), ClientEvent::VideoFrame(frame(1, false)));
    assert_eq!(client.rtt(), None, "future PONG ignored");
    client.close();
    assert_eq!(
        next(&rx),
        ClientEvent::Disconnected(DisconnectReason::Closed)
    );
    server.join().unwrap();
}

#[test]
fn oversize_record_is_protocol_error() {
    let (addr, server) = serve(|mut c| {
        c.handshake();
        // Only the length prefix: refused before any body arrives.
        c.write_raw(&(MAX_PAYLOAD + 16 + 16 + 1).to_be_bytes());
        c.drain();
    });
    let client = Client::connect(addr, config()).unwrap();
    let rx = client.events();
    assert!(matches!(next(&rx), ClientEvent::Connected { .. }));
    match next(&rx) {
        ClientEvent::Disconnected(r @ DisconnectReason::Protocol(_)) => {
            assert!(r.to_string().contains("record length"), "{r}");
            assert!(mirror_receiver::is_retryable(&r));
        }
        e => panic!("unexpected {e:?}"),
    }
    drop(client);
    server.join().unwrap();
}

#[test]
fn garbage_record_is_retryable_protocol_error() {
    // A well-sized record that fails authentication (tampering, or a
    // plaintext frame where a record belongs).
    let (addr, server) = serve(|mut c| {
        c.handshake();
        c.send(&Message::VideoConfig(video_config()));
        let mut junk = 40u32.to_be_bytes().to_vec();
        junk.extend_from_slice(&[0x5a; 40]);
        c.write_raw(&junk);
        c.drain();
    });
    let client = Client::connect(addr, config()).unwrap();
    let rx = client.events();
    assert!(matches!(next(&rx), ClientEvent::Connected { .. }));
    assert_eq!(next(&rx), ClientEvent::VideoConfig(video_config()));
    match next(&rx) {
        ClientEvent::Disconnected(r @ DisconnectReason::Protocol(_)) => {
            assert!(r.to_string().contains("authentication"), "{r}");
            assert!(mirror_receiver::is_retryable(&r));
            assert!(!r.is_auth_outcome());
        }
        e => panic!("unexpected {e:?}"),
    }
    drop(client);
    server.join().unwrap();
}

#[test]
fn plaintext_frame_after_handshake_is_rejected() {
    // A frame that is not sealed must never be accepted as data.
    let (addr, server) = serve(|mut c| {
        c.handshake();
        c.write_raw(&mirror_protocol::encode(&Message::VideoFrame(frame(
            0, true,
        ))));
        c.drain();
    });
    let client = Client::connect(addr, config()).unwrap();
    let rx = client.events();
    assert!(matches!(next(&rx), ClientEvent::Connected { .. }));
    assert!(
        matches!(
            next(&rx),
            ClientEvent::Disconnected(DisconnectReason::Protocol(_))
        ),
        "plaintext frame must kill the channel"
    );
    drop(client);
    server.join().unwrap();
}

#[test]
fn records_pipelined_with_auth_result_are_not_lost() {
    // Server writes AUTH_RESULT (plaintext) plus VIDEO_CONFIG and a frame
    // (records) in one burst before reading START: the records must reach
    // the reader thread via the decoder's leftover bytes.
    let (addr, server) = serve(|mut c| {
        let mut phone = Phone::open();
        phone.pipelined = vec![
            Message::VideoConfig(video_config()),
            Message::VideoFrame(frame(0, true)),
        ];
        let end = c.accept(&mut phone);
        assert!(matches!(end, ServerEnd::Accepted { .. }), "{end:?}");
        c.drain()
    });
    let client = Client::connect(addr, config()).unwrap();
    let rx = client.events();
    assert!(matches!(next(&rx), ClientEvent::Connected { .. }));
    assert_eq!(next(&rx), ClientEvent::VideoConfig(video_config()));
    assert_eq!(next(&rx), ClientEvent::VideoFrame(frame(0, true)));
    drop(client);
    let rest = server.join().unwrap();
    assert_eq!(
        rest,
        vec![Message::ClientBye(Bye {
            reason: ByeReason::StoppedByUser
        })]
    );
}

#[test]
fn close_does_not_wait_long_for_a_phone_that_stopped_reading() {
    let (addr, server) = serve(|mut c| {
        c.handshake();
        // Stop reading: the client's send buffer fills up.
        std::thread::sleep(Duration::from_secs(4));
        drop(c);
    });
    let mut cfg = config();
    cfg.timeouts.liveness = Duration::from_secs(10);
    cfg.timeouts.ping_interval = Duration::from_secs(60);
    let mut client = Client::connect(addr, cfg).unwrap();
    // Queue 60 KiB messages until the writer is stuck (queue stays full).
    let chunk = "x".repeat(60 * 1024);
    let mut full_since: Option<Instant> = None;
    let t0 = Instant::now();
    while full_since.is_none_or(|t| t.elapsed() < Duration::from_millis(300)) {
        assert!(t0.elapsed() < WAIT, "send buffer never filled");
        match client.send(Message::Text(chunk.clone())) {
            Ok(()) => full_since = None,
            Err(SendError::QueueFull) => {
                full_since.get_or_insert_with(Instant::now);
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => panic!("{e:?}"),
        }
    }
    let t = Instant::now();
    client.close();
    assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
    server.join().unwrap();
}

#[test]
fn a_slow_consumer_does_not_count_against_liveness() {
    let (addr, server) = serve(|mut c| {
        c.handshake();
        // One record: the reader has nothing more to read once it is past
        // the stall.
        c.send(&Message::VideoFrame(frame(0, true)));
        // Then silence (the client sends no PINGs to answer).
        std::thread::sleep(Duration::from_secs(3));
        drop(c);
    });
    let liveness = Duration::from_millis(500);
    let mut cfg = config();
    cfg.event_capacity = 1;
    cfg.timeouts.liveness = liveness;
    cfg.timeouts.ping_interval = Duration::from_secs(60);
    let client = Client::connect(addr, cfg).unwrap();
    let rx = client.events();
    // The UI is busy for longer than `liveness`; the reader waits on it.
    std::thread::sleep(Duration::from_millis(1200));
    assert!(matches!(next(&rx), ClientEvent::Connected { .. }));
    assert!(matches!(next(&rx), ClientEvent::VideoFrame(_)));
    let drained = Instant::now();
    assert_eq!(
        next(&rx),
        ClientEvent::Disconnected(DisconnectReason::Timeout(TimeoutKind::Liveness))
    );
    // Only real silence counts: a full `liveness` after the stall ended.
    assert!(
        drained.elapsed() >= liveness * 8 / 10,
        "{:?}",
        drained.elapsed()
    );
    drop(client);
    server.join().unwrap();
}
