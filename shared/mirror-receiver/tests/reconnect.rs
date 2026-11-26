//! Reconnect supervisor against a scripted fake server on loopback.

mod common;

use std::time::{Duration, Instant};

use common::*;
use crossbeam_channel::bounded;
use mirror_protocol::{Bye, ByeReason, Message};
use mirror_receiver::{ClientEvent, DisconnectReason, ReconnectPolicy, SendError, Supervisor};

fn fast_policy() -> ReconnectPolicy {
    ReconnectPolicy {
        delays: vec![Duration::from_millis(10), Duration::from_millis(30)],
        budget: Duration::from_millis(400),
        retry_initial: false,
        stable_after: Duration::from_secs(10),
    }
}

fn expect_connected(e: ClientEvent) {
    assert!(matches!(e, ClientEvent::Connected { .. }), "{e:?}");
}

#[test]
fn reconnects_after_server_drop_then_stops_on_bye() {
    let (addr, server) = serve_n(2, |i, mut c| {
        c.handshake();
        if i == 0 {
            return Vec::new(); // drop the connection without BYE
        }
        c.send(&Message::VideoFrame(frame(7, true)));
        c.send(&Message::ServerBye(Bye {
            reason: ByeReason::StoppedByUser,
        }));
        c.drain()
    });
    let mut sup = Supervisor::start(addr, config(), fast_policy());
    let rx = sup.events();
    expect_connected(next(&rx));
    match next(&rx) {
        ClientEvent::Disconnected(r) => assert!(mirror_receiver::is_retryable(&r), "{r:?}"),
        e => panic!("unexpected {e:?}"),
    }
    assert_eq!(
        next(&rx),
        ClientEvent::Reconnecting {
            attempt: 1,
            delay: Duration::from_millis(10)
        }
    );
    expect_connected(next(&rx));
    assert_eq!(next(&rx), ClientEvent::VideoFrame(frame(7, true)));
    let bye = DisconnectReason::Bye(ByeReason::StoppedByUser);
    assert_eq!(next(&rx), ClientEvent::Disconnected(bye.clone()));
    assert_eq!(next(&rx), ClientEvent::Stopped(bye));
    sup.close();
    assert!(server.join().unwrap().iter().all(|v| v.is_empty()));
    assert!(rx.recv_timeout(Duration::from_millis(100)).is_err());
}

#[test]
fn gives_up_after_budget_when_server_is_gone() {
    // One session, then the listener is dropped: every reconnect is refused.
    let (addr, server) = serve_n(1, |_, mut c| {
        c.handshake();
    });
    // First delay long enough that the listener is surely gone by then.
    let policy = ReconnectPolicy {
        delays: vec![Duration::from_millis(100), Duration::from_millis(30)],
        budget: Duration::from_millis(500),
        retry_initial: false,
        stable_after: Duration::from_secs(10),
    };
    let mut sup = Supervisor::start(addr, config(), policy);
    let rx = sup.events();
    expect_connected(next(&rx));
    assert!(matches!(next(&rx), ClientEvent::Disconnected(_)));
    server.join().unwrap();
    let mut attempts = 0;
    let (n, last) = loop {
        match next(&rx) {
            ClientEvent::Reconnecting { attempt, delay } => {
                attempts += 1;
                assert_eq!(attempt, attempts);
                let want = if attempt == 1 { 100 } else { 30 };
                assert_eq!(delay, Duration::from_millis(want));
            }
            ClientEvent::GaveUp { attempts, last } => break (attempts, last),
            e => panic!("unexpected {e:?}"),
        }
    };
    assert_eq!(n, attempts);
    // 100 + 30*k <= 500 ms: at most 14 attempts, at least a few.
    assert!((2..=14).contains(&n), "{n}");
    assert!(
        matches!(
            last,
            DisconnectReason::Io { .. } | DisconnectReason::Timeout(_)
        ),
        "{last:?}"
    );
    assert!(!sup.is_connected());
    assert_eq!(sup.request_keyframe(), Err(SendError::Disconnected));
    sup.close();
}

#[test]
fn bye_replaced_is_not_retried() {
    let (addr, server) = serve_n(1, |_, mut c| {
        c.handshake();
        c.send(&Message::ServerBye(Bye {
            reason: ByeReason::Replaced,
        }));
        c.drain()
    });
    let mut sup = Supervisor::start(addr, config(), fast_policy());
    let rx = sup.events();
    expect_connected(next(&rx));
    let r = DisconnectReason::Bye(ByeReason::Replaced);
    assert_eq!(next(&rx), ClientEvent::Disconnected(r.clone()));
    assert_eq!(next(&rx), ClientEvent::Stopped(r));
    sup.close();
    server.join().unwrap();
}

#[test]
fn initial_failure_is_final_unless_retry_initial() {
    let addr = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let mut sup = Supervisor::start(addr, config(), fast_policy());
    let rx = sup.events();
    assert!(
        matches!(next(&rx), ClientEvent::Stopped(DisconnectReason::Io { .. })),
        "first connect failure should stop immediately"
    );
    sup.close();

    let mut policy = fast_policy();
    policy.retry_initial = true;
    let mut sup = Supervisor::start(addr, config(), policy);
    let rx = sup.events();
    assert!(matches!(
        next(&rx),
        ClientEvent::Reconnecting { attempt: 1, .. }
    ));
    sup.close();
}

#[test]
fn close_sends_bye_and_stops() {
    let (addr, server) = serve_n(1, |_, mut c| {
        c.handshake();
        c.drain()
    });
    let mut sup = Supervisor::start(addr, config(), fast_policy());
    let rx = sup.events();
    expect_connected(next(&rx));
    assert!(sup.is_connected());
    sup.request_keyframe().unwrap();
    sup.close();
    sup.close(); // idempotent
    assert_eq!(
        next(&rx),
        ClientEvent::Disconnected(DisconnectReason::Closed)
    );
    assert_eq!(next(&rx), ClientEvent::Stopped(DisconnectReason::Closed));
    let got = server.join().unwrap().remove(0);
    assert_eq!(
        got,
        vec![
            Message::RequestKeyframe,
            Message::ClientBye(Bye {
                reason: ByeReason::StoppedByUser
            })
        ]
    );
}

/// Close `sup` on another thread; panics if that takes longer than `limit`.
fn close_within(mut sup: Supervisor, limit: Duration) {
    let (tx, rx) = bounded(1);
    std::thread::spawn(move || {
        sup.close();
        let _ = tx.send(());
    });
    rx.recv_timeout(limit)
        .unwrap_or_else(|_| panic!("Supervisor::close hung for {limit:?}"));
}

#[test]
fn close_does_not_hang_while_reconnect_blocks_on_full_channel() {
    let (up_tx, up_rx) = bounded(1);
    let (addr, server) = serve_n(2, move |i, mut c| {
        c.handshake();
        if i == 0 {
            return Vec::new();
        }
        up_tx.send(()).unwrap();
        c.drain()
    });
    let mut cfg = config();
    cfg.event_capacity = 1;
    let sup = Supervisor::start(addr, cfg, fast_policy());
    let rx = sup.events();
    expect_connected(next(&rx));
    assert!(matches!(next(&rx), ClientEvent::Disconnected(_)));
    // Stop consuming: `Reconnecting` fills the channel, so the second
    // session blocks emitting `Connected` when the consumer wants to close.
    up_rx.recv_timeout(WAIT).unwrap();
    std::thread::sleep(Duration::from_millis(100));
    close_within(sup, WAIT);
    server.join().unwrap();
}

#[test]
fn close_abandons_an_in_flight_handshake_without_sending_auth() {
    let (hello_tx, hello_rx) = bounded(1);
    let (addr, server) = serve(move |mut c| {
        c.send_magic();
        assert!(matches!(c.recv(), Some(Message::ClientHello(_))));
        hello_tx.send(()).unwrap();
        c.drain() // the phone is slow: no SERVER_HELLO yet
    });
    let mut cfg = config();
    cfg.timeouts.handshake = Duration::from_secs(60);
    let sup = Supervisor::start(addr, cfg, fast_policy());
    let rx = sup.events();
    hello_rx.recv_timeout(WAIT).unwrap();
    let t = Instant::now();
    close_within(sup, WAIT);
    assert!(t.elapsed() < Duration::from_secs(1), "{:?}", t.elapsed());
    assert_eq!(next(&rx), ClientEvent::Stopped(DisconnectReason::Closed));
    assert_eq!(server.join().unwrap(), Vec::<Message>::new());
}

/// Accept connections forever (detached thread); each one completes the
/// handshake, reads START, waits `hold(i)`, then hangs up without BYE.
fn serve_flapping(hold: fn(usize) -> Duration) -> std::net::SocketAddr {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    std::thread::spawn(move || {
        for (i, s) in l.incoming().enumerate() {
            let Ok(s) = s else { return };
            let mut c = Conn::new(s);
            c.handshake();
            std::thread::sleep(hold(i));
        }
    });
    addr
}

#[test]
fn handshake_then_immediate_drop_still_gives_up_within_budget() {
    let addr = serve_flapping(|_| Duration::ZERO);
    let policy = fast_policy(); // 400 ms budget, 10 s stability threshold
    let budget = policy.budget;
    let mut sup = Supervisor::start(addr, config(), policy);
    let rx = sup.events();
    let t = Instant::now();
    let mut attempts = 0;
    let n = loop {
        assert!(
            t.elapsed() < budget + Duration::from_secs(2),
            "no GaveUp after {:?} ({attempts} attempts)",
            t.elapsed()
        );
        match next(&rx) {
            ClientEvent::Connected { .. } | ClientEvent::Disconnected(_) => {}
            ClientEvent::Reconnecting { attempt, .. } => {
                attempts += 1;
                assert_eq!(attempt, attempts, "attempt counter must carry over");
            }
            ClientEvent::GaveUp { attempts, .. } => break attempts,
            e => panic!("unexpected {e:?}"),
        }
    };
    assert_eq!(n, attempts);
    assert!(n >= 2, "{n}");
    sup.close();
}

#[test]
fn stable_session_resets_the_attempt_counter() {
    // Sessions 0 and 1 drop at once; session 2 stays up past `stable_after`.
    let addr = serve_flapping(|i| Duration::from_millis(if i == 2 { 300 } else { 0 }));
    let mut policy = fast_policy();
    policy.budget = Duration::from_secs(5);
    policy.stable_after = Duration::from_millis(100);
    let mut sup = Supervisor::start(addr, config(), policy);
    let rx = sup.events();
    let mut seen = Vec::new();
    while seen.len() < 3 {
        if let ClientEvent::Reconnecting { attempt, .. } = next(&rx) {
            seen.push(attempt);
        }
    }
    // After session 0: 1; after session 1 (short): 2; after session 2
    // (stable): back to 1.
    assert_eq!(seen, vec![1, 2, 1]);
    sup.close();
}

#[test]
fn garbage_record_is_retried_like_a_lost_connection() {
    let (addr, server) = serve_n(2, |i, mut c| {
        c.handshake();
        if i == 0 {
            // A record that fails authentication.
            let mut junk = 40u32.to_be_bytes().to_vec();
            junk.extend_from_slice(&[0xa5; 40]);
            c.write_raw(&junk);
            return c.drain();
        }
        c.send(&Message::ServerBye(Bye {
            reason: ByeReason::StoppedByUser,
        }));
        c.drain()
    });
    let mut sup = Supervisor::start(addr, config(), fast_policy());
    let rx = sup.events();
    expect_connected(next(&rx));
    assert!(matches!(
        next(&rx),
        ClientEvent::Disconnected(DisconnectReason::Protocol(_))
    ));
    assert!(matches!(
        next(&rx),
        ClientEvent::Reconnecting { attempt: 1, .. }
    ));
    expect_connected(next(&rx));
    sup.close();
    server.join().unwrap();
}

#[test]
fn disconnected_is_delivered_even_when_the_consumer_lags() {
    // A tiny event channel that the consumer drains slowly: the client is
    // blocked handing over frames when the phone drops. The supervisor must
    // not close that client (which aborts blocked emits) before its
    // `Disconnected` went out.
    let (addr, server) = serve_n(1, |_, mut c| {
        c.handshake();
        c.send(&Message::VideoConfig(video_config()));
        for i in 0..8 {
            c.send(&Message::VideoFrame(frame(i, i == 0)));
        }
        // Dropping `c` closes the connection without BYE.
    });
    let mut cfg = config();
    cfg.event_capacity = 1;
    let mut sup = Supervisor::start(addr, cfg, fast_policy());
    let rx = sup.events();
    server.join().unwrap();
    let mut seen = Vec::new();
    loop {
        // Lag on the first events: long enough for the phone's drop to be
        // noticed (failed PING write) while the channel is full.
        if seen.len() < 3 {
            std::thread::sleep(Duration::from_millis(400));
        }
        let ev = next(&rx);
        let last = matches!(ev, ClientEvent::GaveUp { .. } | ClientEvent::Stopped(_));
        seen.push(ev);
        if last {
            break;
        }
    }
    sup.close();
    let disc = seen
        .iter()
        .position(|e| matches!(e, ClientEvent::Disconnected(_)));
    let recon = seen
        .iter()
        .position(|e| matches!(e, ClientEvent::Reconnecting { .. }));
    assert!(
        matches!((disc, recon), (Some(d), Some(r)) if d < r),
        "Disconnected must precede Reconnecting: {seen:?}"
    );
}
