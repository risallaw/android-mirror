//! v2 authentication against a fake phone: PIN pairing, stored tokens,
//! refusals, credential choice and control gating.

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::*;
use mirror_protocol::auth::PairingKey;
use mirror_protocol::handshake::ServerHandshake;
use mirror_protocol::{
    AuthMode, AuthReason, AuthResult, Bye, ByeReason, Key, Message, Status, StatusState,
};
use mirror_receiver::client::MAX_LOCKOUT;
use mirror_receiver::store::{self, PairedDevice, Store};
use mirror_receiver::{
    Client, ClientConfig, ClientEvent, DisconnectReason, ReconnectPolicy, SendError, Supervisor,
};

const PIN: &str = "482913";

fn with_pin(store: &Store, pin: &str) -> ClientConfig {
    let mut c = secure_config();
    c.store = store.clone();
    c.pin = Some(pin.to_string().into());
    c
}

fn with_store(store: &Store) -> ClientConfig {
    let mut c = secure_config();
    c.store = store.clone();
    c
}

fn store_with_key(key: [u8; 32]) -> Store {
    let s = Store::default();
    s.put_pairing(PairedDevice {
        device_id: DEVICE_ID.into(),
        device_name: DEVICE_NAME.into(),
        key: PairingKey::from_bytes(key),
        paired_at_ms: 1,
    })
    .unwrap();
    s
}

/// Retries everything it may, quickly: proves auth outcomes are final.
fn eager_policy() -> ReconnectPolicy {
    ReconnectPolicy {
        delays: vec![Duration::from_millis(10)],
        budget: Duration::from_secs(2),
        retry_initial: true,
        stable_after: Duration::from_secs(10),
    }
}

fn temp_dir(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "mirror-receiver-auth-{name}-{}",
        store::new_client_id()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Serve one connection under a shared phone policy.
fn serve_phone(
    phone: &Arc<Mutex<Phone>>,
) -> (std::net::SocketAddr, std::thread::JoinHandle<ServerEnd>) {
    let phone = phone.clone();
    serve(move |mut c| {
        let end = c.accept(&mut phone.lock().unwrap());
        if matches!(end, ServerEnd::Accepted { .. }) {
            c.drain();
        }
        end
    })
}

fn accepted_mode(end: &ServerEnd) -> AuthMode {
    match end {
        ServerEnd::Accepted { auth, .. } => auth.mode,
        e => panic!("not accepted: {e:?}"),
    }
}

#[test]
fn pin_pairing_stores_key_and_next_connect_uses_token() {
    let dir = temp_dir("pair");
    let path = dir.join("settings.json");
    let store = Store::open(Some(path.clone()));
    let phone = Arc::new(Mutex::new(Phone::paired_only(PIN)));

    // 1: pair with the PIN.
    let (addr, server) = serve_phone(&phone);
    let mut client = Client::connect(addr, with_pin(&store, PIN)).expect("pairing");
    let rx = client.events();
    assert!(matches!(
        next(&rx),
        ClientEvent::Connected {
            auth: AuthMode::Pin,
            ..
        }
    ));
    assert_eq!(
        next(&rx),
        ClientEvent::Paired {
            device_id: DEVICE_ID.into(),
            device_name: DEVICE_NAME.into(),
            save_error: None,
        }
    );
    client.close();
    assert_eq!(accepted_mode(&server.join().unwrap()), AuthMode::Pin);

    // Both sides hold the same key; ours is on disk, private, as hex.
    let phone_key = phone.lock().unwrap().keys[CLIENT_ID].clone();
    assert_eq!(store.pairing_key(DEVICE_ID), Some(phone_key.clone()));
    let on_disk = store::load(&path).unwrap();
    let entry = on_disk.pairing(DEVICE_ID).unwrap();
    assert_eq!(entry.key, phone_key);
    assert_eq!(entry.device_name, DEVICE_NAME);
    assert!(entry.paired_at_ms > 0);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    assert!(std::fs::read_to_string(&path)
        .unwrap()
        .contains(&phone_key.to_hex()));
    // Key never shows up in Debug output of anything that holds it.
    let dbg = format!("{store:?} {:?} {on_disk:?}", with_pin(&store, PIN));
    assert!(!dbg.contains(&phone_key.to_hex()), "{dbg}");
    assert!(!dbg.contains(PIN), "{dbg}");

    // 2: the PIN rotated on the phone; a fresh connect without a PIN (and a
    // reloaded store) authenticates with the stored key.
    phone.lock().unwrap().pin = "000000".into();
    let (addr, server) = serve_phone(&phone);
    let store2 = Store::open(Some(path.clone()));
    let mut client = Client::connect(addr, with_store(&store2)).expect("token");
    assert!(matches!(
        next(&client.events()),
        ClientEvent::Connected {
            auth: AuthMode::Token,
            ..
        }
    ));
    assert_eq!(client.auth_mode(), AuthMode::Token);
    client.close();
    assert_eq!(accepted_mode(&server.join().unwrap()), AuthMode::Token);
    std::fs::remove_dir_all(dir).unwrap();
}

#[cfg(unix)]
#[test]
fn a_pairing_that_cannot_be_saved_is_reported_and_kept_for_this_run() {
    use std::os::unix::fs::PermissionsExt;
    let dir = temp_dir("unsaved");
    let store = Store::open(Some(dir.join("settings.json")));
    // Read-only directory: no temp file can be created there.
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();
    let phone = Arc::new(Mutex::new(Phone::paired_only(PIN)));
    let (addr, server) = serve_phone(&phone);
    let mut client = Client::connect(addr, with_pin(&store, PIN)).expect("pairing");
    let rx = client.events();
    assert!(matches!(next(&rx), ClientEvent::Connected { .. }));
    let ev = next(&rx);
    client.close();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    match ev {
        ClientEvent::Paired {
            save_error: Some(why),
            ..
        } => assert!(why.contains("settings.json"), "{why}"),
        e => panic!("expected an unsaved pairing, got {e:?}"),
    }
    assert_eq!(accepted_mode(&server.join().unwrap()), AuthMode::Pin);
    let phone_key = phone.lock().unwrap().keys[CLIENT_ID].clone();
    assert_eq!(store.pairing_key(DEVICE_ID), Some(phone_key), "in memory");
    assert!(!dir.join("settings.json").exists());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn supplied_pin_is_preferred_over_a_stored_token() {
    let mut p = Phone::paired_only(PIN);
    p.keys
        .insert(CLIENT_ID.into(), PairingKey::from_bytes([7; 32]));
    let phone = Arc::new(Mutex::new(p));
    let (addr, server) = serve_phone(&phone);
    let store = store_with_key([7; 32]);
    let client = Client::connect(addr, with_pin(&store, PIN)).unwrap();
    drop(client);
    assert_eq!(accepted_mode(&server.join().unwrap()), AuthMode::Pin);
}

#[test]
fn stored_token_is_used_without_a_pin() {
    let mut p = Phone::paired_only(PIN);
    p.keys
        .insert(CLIENT_ID.into(), PairingKey::from_bytes([7; 32]));
    let phone = Arc::new(Mutex::new(p));
    let (addr, server) = serve_phone(&phone);
    let store = store_with_key([7; 32]);
    drop(Client::connect(addr, with_store(&store)).unwrap());
    assert_eq!(accepted_mode(&server.join().unwrap()), AuthMode::Token);
}

#[test]
fn pin_is_preferred_over_none_even_when_none_is_allowed() {
    let mut p = Phone::paired_only(PIN);
    p.modes.push(AuthMode::NoAuth);
    let phone = Arc::new(Mutex::new(p));
    let (addr, server) = serve_phone(&phone);
    let mut cfg = with_pin(&Store::default(), PIN);
    cfg.allow_no_auth = true;
    drop(Client::connect(addr, cfg).unwrap());
    assert_eq!(accepted_mode(&server.join().unwrap()), AuthMode::Pin);
}

#[test]
fn wrong_pin_is_final_and_never_retried() {
    let store = Store::default();
    let phone = Arc::new(Mutex::new(Phone::paired_only(PIN)));
    let (addr, server) = serve_phone(&phone);
    let mut sup = Supervisor::start(addr, with_pin(&store, "111111"), eager_policy());
    let rx = sup.events();
    assert_eq!(next(&rx), ClientEvent::Stopped(DisconnectReason::WrongPin));
    // The client saw the bad server confirmation and never sent its own.
    assert_eq!(server.join().unwrap(), ServerEnd::NoConfirm);
    assert!(
        rx.recv_timeout(Duration::from_millis(200)).is_err(),
        "no retry"
    );
    sup.close();
    assert!(store.pairings().is_empty());
}

#[test]
fn server_refusing_our_pin_confirmation_is_wrong_pin() {
    let (addr, server) = serve(|mut c| {
        c.hello(&[AuthMode::Pin]);
        assert!(matches!(c.recv(), Some(Message::Auth(_))));
        c.send(&ServerHandshake::rejection(AuthReason::BadProof, None));
        c.send(&Message::ServerBye(Bye {
            reason: ByeReason::AuthFailed,
        }));
        c.drain()
    });
    let err = Client::connect(addr, with_pin(&Store::default(), PIN)).unwrap_err();
    assert_eq!(err, DisconnectReason::WrongPin);
    server.join().unwrap();
}

#[test]
fn malformed_pin_is_refused_locally_without_auth() {
    let phone = Arc::new(Mutex::new(Phone::paired_only(PIN)));
    let (addr, server) = serve_phone(&phone);
    let err = Client::connect(addr, with_pin(&Store::default(), "12345")).unwrap_err();
    assert_eq!(err, DisconnectReason::WrongPin);
    assert_eq!(
        server.join().unwrap(),
        ServerEnd::NoAuth,
        "no attempt burned"
    );
}

#[test]
fn locked_out_reports_retry_after_and_is_final() {
    let mut p = Phone::paired_only(PIN);
    p.locked_ms = Some(12_345);
    let phone = Arc::new(Mutex::new(p));
    let (addr, server) = serve_phone(&phone);
    let mut sup = Supervisor::start(addr, with_pin(&Store::default(), PIN), eager_policy());
    let rx = sup.events();
    let want = DisconnectReason::LockedOut {
        retry_after: Duration::from_millis(12_345),
    };
    assert_eq!(next(&rx), ClientEvent::Stopped(want.clone()));
    assert!(want.to_string().contains("13 s"), "{want}");
    assert_eq!(
        server.join().unwrap(),
        ServerEnd::Refused(AuthReason::LockedOut)
    );
    assert!(
        rx.recv_timeout(Duration::from_millis(200)).is_err(),
        "no retry"
    );
    sup.close();
}

#[test]
fn absurd_retry_after_is_clamped_so_deadline_math_cannot_overflow() {
    // The refusal is unauthenticated plaintext: anyone at the phone's
    // address can send `retryAfterMs: u64::MAX`.
    let mut p = Phone::paired_only(PIN);
    p.locked_ms = Some(u64::MAX);
    let phone = Arc::new(Mutex::new(p));
    let (addr, server) = serve_phone(&phone);
    let err = Client::connect(addr, with_pin(&Store::default(), PIN)).unwrap_err();
    let DisconnectReason::LockedOut { retry_after } = err else {
        panic!("{err:?}");
    };
    assert_eq!(retry_after, MAX_LOCKOUT);
    // What the UI does with it (state.rs: `stopped_at + retry_after`).
    let _ = std::time::Instant::now() + retry_after;
    server.join().unwrap();
}

#[test]
fn locked_out_without_retry_after_defaults_to_30s() {
    let (addr, server) = serve(|mut c| {
        c.hello(&[AuthMode::Pin]);
        c.recv();
        c.send(&ServerHandshake::rejection(AuthReason::LockedOut, None));
        c.drain()
    });
    let err = Client::connect(addr, with_pin(&Store::default(), PIN)).unwrap_err();
    assert_eq!(
        err,
        DisconnectReason::LockedOut {
            retry_after: Duration::from_secs(30)
        }
    );
    server.join().unwrap();
}

#[test]
fn unknown_client_keeps_the_key_and_reports_pairing_removed() {
    let dir = temp_dir("revoked");
    let path = dir.join("settings.json");
    let store = Store::open(Some(path.clone()));
    store
        .put_pairing(PairedDevice {
            device_id: DEVICE_ID.into(),
            device_name: DEVICE_NAME.into(),
            key: PairingKey::from_bytes([7; 32]),
            paired_at_ms: 1,
        })
        .unwrap();
    // The phone forgot us (revoked): no key for our clientId.
    let phone = Arc::new(Mutex::new(Phone::paired_only(PIN)));
    let (addr, server) = serve_phone(&phone);
    let mut sup = Supervisor::start(addr, with_store(&store), eager_policy());
    let rx = sup.events();
    assert_eq!(
        next(&rx),
        ClientEvent::Stopped(DisconnectReason::PairingRemoved {
            device_id: DEVICE_ID.into()
        })
    );
    assert_eq!(
        server.join().unwrap(),
        ServerEnd::Refused(AuthReason::UnknownClient)
    );
    assert!(
        rx.recv_timeout(Duration::from_millis(200)).is_err(),
        "no retry"
    );
    sup.close();
    // The refusal is unauthenticated: it must not be able to unpair us.
    assert_eq!(
        store.pairing_key(DEVICE_ID),
        Some(PairingKey::from_bytes([7; 32]))
    );
    assert_eq!(
        store::load(&path).unwrap().pairings.len(),
        1,
        "kept on disk"
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn bad_proof_for_token_keeps_the_key() {
    // The phone re-paired us with another key meanwhile: ours is stale.
    let mut p = Phone::paired_only(PIN);
    p.keys
        .insert(CLIENT_ID.into(), PairingKey::from_bytes([8; 32]));
    let phone = Arc::new(Mutex::new(p));
    let (addr, server) = serve_phone(&phone);
    let store = store_with_key([7; 32]);
    let err = Client::connect(addr, with_store(&store)).unwrap_err();
    assert_eq!(
        err,
        DisconnectReason::PairingRemoved {
            device_id: DEVICE_ID.into()
        }
    );
    assert_eq!(
        server.join().unwrap(),
        ServerEnd::Refused(AuthReason::BadProof)
    );
    assert_eq!(
        store.pairing_key(DEVICE_ID),
        Some(PairingKey::from_bytes([7; 32]))
    );
}

#[test]
fn pin_re_pairs_over_a_refused_kept_key() {
    // The phone re-paired us with another key; ours ([7]) is refused but
    // kept. Re-pairing with the PIN must use the PIN (not the stale key)
    // and replace the stored key with the new one.
    let mut p = Phone::paired_only(PIN);
    p.keys
        .insert(CLIENT_ID.into(), PairingKey::from_bytes([8; 32]));
    let phone = Arc::new(Mutex::new(p));
    let store = store_with_key([7; 32]);
    let (addr, server) = serve_phone(&phone);
    assert!(matches!(
        Client::connect(addr, with_store(&store)),
        Err(DisconnectReason::PairingRemoved { .. })
    ));
    server.join().unwrap();
    let (addr, server) = serve_phone(&phone);
    let client = Client::connect(addr, with_pin(&store, PIN)).expect("re-pairing");
    drop(client);
    assert_eq!(accepted_mode(&server.join().unwrap()), AuthMode::Pin);
    let phone_key = phone.lock().unwrap().keys[CLIENT_ID].clone();
    assert_ne!(phone_key, PairingKey::from_bytes([7; 32]));
    assert_eq!(store.pairing_key(DEVICE_ID), Some(phone_key));
}

#[test]
fn server_proof_mismatch_is_identity_changed_and_keeps_the_key() {
    // A device claiming our phone's id accepts our token without proving it
    // knows the key (wrong proof, then no proof at all).
    for proof in [Some("00".repeat(32)), None] {
        let (addr, server) = serve(move |mut c| {
            c.hello(&[AuthMode::Token, AuthMode::Pin]);
            assert!(matches!(c.recv(), Some(Message::Auth(a)) if a.mode == AuthMode::Token));
            c.send(&Message::AuthResult(AuthResult {
                ok: true,
                server_proof: proof,
                ..Default::default()
            }));
            c.drain()
        });
        let store = store_with_key([7; 32]);
        let mut sup = Supervisor::start(addr, with_store(&store), eager_policy());
        let rx = sup.events();
        assert_eq!(
            next(&rx),
            ClientEvent::Stopped(DisconnectReason::IdentityChanged {
                device_id: DEVICE_ID.into()
            })
        );
        // Nothing after AUTH: no START (or anything else) reached the impostor.
        assert!(server.join().unwrap().is_empty());
        assert!(
            rx.recv_timeout(Duration::from_millis(200)).is_err(),
            "no retry"
        );
        sup.close();
        assert_eq!(
            store.pairing_key(DEVICE_ID),
            Some(PairingKey::from_bytes([7; 32])),
            "an impostor must not be able to unpair us"
        );
    }
}

#[test]
fn no_key_and_no_pin_needs_pin_without_sending_auth() {
    let phone = Arc::new(Mutex::new(Phone::paired_only(PIN)));
    let (addr, server) = serve_phone(&phone);
    let mut sup = Supervisor::start(addr, with_store(&Store::default()), eager_policy());
    let rx = sup.events();
    assert_eq!(
        next(&rx),
        ClientEvent::Stopped(DisconnectReason::NeedsPin {
            device_id: DEVICE_ID.into(),
            device_name: DEVICE_NAME.into()
        })
    );
    assert_eq!(server.join().unwrap(), ServerEnd::NoAuth);
    assert!(
        rx.recv_timeout(Duration::from_millis(200)).is_err(),
        "no retry"
    );
    sup.close();
}

#[test]
fn none_is_never_chosen_unless_allowed() {
    // Phone offers everything: without a key or PIN we must ask for a PIN,
    // not fall back to an unauthenticated session.
    let mut p = Phone::paired_only(PIN);
    p.modes.push(AuthMode::NoAuth);
    let phone = Arc::new(Mutex::new(p));
    let (addr, server) = serve_phone(&phone);
    let err = Client::connect(addr, with_store(&Store::default())).unwrap_err();
    assert!(matches!(err, DisconnectReason::NeedsPin { .. }), "{err:?}");
    assert_eq!(server.join().unwrap(), ServerEnd::NoAuth);

    // A phone offering only `none`.
    let phone = Arc::new(Mutex::new(Phone::open()));
    let (addr, server) = serve_phone(&phone);
    let err = Client::connect(addr, with_store(&Store::default())).unwrap_err();
    assert_eq!(
        err,
        DisconnectReason::AuthUnsupported {
            offered: vec![AuthMode::NoAuth]
        }
    );
    assert_eq!(server.join().unwrap(), ServerEnd::NoAuth);

    // Explicitly allowed: works (still encrypted).
    let (addr, server) = serve_phone(&phone);
    let mut cfg = with_store(&Store::default());
    cfg.allow_no_auth = true;
    drop(Client::connect(addr, cfg).unwrap());
    assert_eq!(accepted_mode(&server.join().unwrap()), AuthMode::NoAuth);
}

#[test]
fn pin_is_not_replayed_after_pairing() {
    // Session 0 pairs, then drops. Session 1 offers only `pin` (so the
    // stored key cannot be used): the supervisor must not resend the PIN.
    let phone = Arc::new(Mutex::new(Phone::paired_only(PIN)));
    let p = phone.clone();
    let (addr, server) = serve_n(2, move |i, mut c| {
        let mut phone = p.lock().unwrap();
        if i == 1 {
            phone.modes = vec![AuthMode::Pin];
        }
        c.accept(&mut phone)
    });
    let store = Store::default();
    let mut sup = Supervisor::start(addr, with_pin(&store, PIN), eager_policy());
    let rx = sup.events();
    assert!(matches!(
        next(&rx),
        ClientEvent::Connected {
            auth: AuthMode::Pin,
            ..
        }
    ));
    assert!(matches!(next(&rx), ClientEvent::Paired { .. }));
    assert!(matches!(next(&rx), ClientEvent::Disconnected(_)));
    assert!(matches!(next(&rx), ClientEvent::Reconnecting { .. }));
    assert!(matches!(
        next(&rx),
        ClientEvent::Stopped(DisconnectReason::NeedsPin { .. })
    ));
    sup.close();
    let ends = server.join().unwrap();
    assert_eq!(accepted_mode(&ends[0]), AuthMode::Pin);
    assert_eq!(ends[1], ServerEnd::NoAuth);
}

#[test]
fn pin_is_not_replayed_after_a_retryable_failure_once_sent() {
    // Attempt 0: the link drops right after our PIN AUTH (the phone may
    // have paired and rotated its PIN). That is retryable, but the retry
    // must not resend the PIN: with no stored key it needs a new one.
    let phone = Arc::new(Mutex::new(Phone::paired_only(PIN)));
    let p = phone.clone();
    let (addr, server) = serve_n(2, move |i, mut c| {
        if i == 0 {
            c.hello(&[AuthMode::Pin, AuthMode::Token]);
            assert!(matches!(c.recv(), Some(Message::Auth(_))));
            return ServerEnd::NoConfirm; // hang up
        }
        c.accept(&mut p.lock().unwrap())
    });
    let mut sup = Supervisor::start(addr, with_pin(&Store::default(), PIN), eager_policy());
    let rx = sup.events();
    assert!(matches!(next(&rx), ClientEvent::Reconnecting { .. }));
    assert!(matches!(
        next(&rx),
        ClientEvent::Stopped(DisconnectReason::NeedsPin { .. })
    ));
    sup.close();
    assert_eq!(
        server.join().unwrap()[1],
        ServerEnd::NoAuth,
        "PIN not resent"
    );
}

#[test]
fn pin_is_kept_for_a_retry_when_it_was_never_sent() {
    // Attempt 0 fails before AUTH (no SERVER_HELLO): the PIN was not used,
    // so the retry may still pair with it.
    let phone = Arc::new(Mutex::new(Phone::paired_only(PIN)));
    let p = phone.clone();
    let (addr, server) = serve_n(2, move |i, mut c| {
        if i == 0 {
            c.send_magic();
            c.recv();
            return ServerEnd::NoAuth; // hang up before SERVER_HELLO
        }
        let end = c.accept(&mut p.lock().unwrap());
        c.send(&Message::ServerBye(Bye {
            reason: ByeReason::StoppedByUser,
        }));
        c.drain();
        end
    });
    let mut sup = Supervisor::start(addr, with_pin(&Store::default(), PIN), eager_policy());
    let rx = sup.events();
    assert!(matches!(next(&rx), ClientEvent::Reconnecting { .. }));
    assert!(matches!(
        next(&rx),
        ClientEvent::Connected {
            auth: AuthMode::Pin,
            ..
        }
    ));
    sup.close();
    assert_eq!(accepted_mode(&server.join().unwrap()[1]), AuthMode::Pin);
}

#[test]
fn reconnect_after_pairing_uses_the_new_token() {
    let phone = Arc::new(Mutex::new(Phone::paired_only(PIN)));
    let p = phone.clone();
    let (addr, server) = serve_n(2, move |i, mut c| {
        let end = c.accept(&mut p.lock().unwrap());
        if i == 1 {
            c.send(&Message::ServerBye(Bye {
                reason: ByeReason::StoppedByUser,
            }));
            c.drain();
        }
        end
    });
    let mut sup = Supervisor::start(addr, with_pin(&Store::default(), PIN), eager_policy());
    let rx = sup.events();
    let mut modes = Vec::new();
    loop {
        match next(&rx) {
            ClientEvent::Connected { auth, .. } => modes.push(auth),
            ClientEvent::Stopped(_) | ClientEvent::GaveUp { .. } => break,
            _ => {}
        }
    }
    sup.close();
    assert_eq!(modes, vec![AuthMode::Pin, AuthMode::Token]);
    let ends = server.join().unwrap();
    assert_eq!(accepted_mode(&ends[1]), AuthMode::Token);
}

fn key_msg() -> Message {
    Message::Key(Key::Enter)
}

fn status(s: StatusState) -> Message {
    Message::Status(Status { state: s })
}

#[test]
fn control_needs_an_authenticated_session_and_control_available() {
    let mut p = Phone::paired_only(PIN);
    p.keys
        .insert(CLIENT_ID.into(), PairingKey::from_bytes([7; 32]));
    let phone = Arc::new(Mutex::new(p));
    let (go_tx, go_rx) = crossbeam_channel::bounded::<()>(1);
    let ph = phone.clone();
    let (addr, server) = serve(move |mut c| {
        assert_eq!(
            accepted_mode(&c.accept(&mut ph.lock().unwrap())),
            AuthMode::Token
        );
        go_rx.recv().unwrap();
        c.send(&status(StatusState::ControlAvailable));
        let got = c.recv();
        c.send(&status(StatusState::ControlUnavailable));
        c.drain();
        got
    });
    let client = Client::connect(addr, with_store(&store_with_key([7; 32]))).unwrap();
    let rx = client.events();
    assert!(matches!(next(&rx), ClientEvent::Connected { .. }));
    // Before the phone says so: refused.
    assert!(!client.control_available());
    assert_eq!(
        client.send_control(key_msg()),
        Err(SendError::ControlUnavailable)
    );
    go_tx.send(()).unwrap();
    assert_eq!(
        next(&rx),
        ClientEvent::Status(StatusState::ControlAvailable)
    );
    assert!(client.control_available());
    assert_eq!(
        client.send_control(Message::RequestKeyframe),
        Err(SendError::NotControl)
    );
    assert_eq!(
        client.send_control(Message::Text("x".repeat(70 * 1024))),
        Err(SendError::TooLarge)
    );
    client.send_control(key_msg()).unwrap();
    assert_eq!(
        next(&rx),
        ClientEvent::Status(StatusState::ControlUnavailable)
    );
    assert!(!client.control_available());
    assert_eq!(
        client.send_control(key_msg()),
        Err(SendError::ControlUnavailable)
    );
    drop(client);
    assert_eq!(
        server.join().unwrap(),
        Some(key_msg()),
        "sealed and delivered"
    );
}

#[test]
fn control_is_refused_on_an_unauthenticated_session() {
    let (addr, server) = serve(|mut c| {
        c.handshake();
        c.send(&status(StatusState::ControlAvailable));
        c.drain()
    });
    let client = Client::connect(addr, config()).unwrap();
    let rx = client.events();
    assert!(matches!(
        next(&rx),
        ClientEvent::Connected {
            auth: AuthMode::NoAuth,
            ..
        }
    ));
    assert_eq!(
        next(&rx),
        ClientEvent::Status(StatusState::ControlAvailable)
    );
    assert!(!client.control_available());
    assert_eq!(
        client.send_control(key_msg()),
        Err(SendError::ControlUnavailable)
    );
    drop(client);
    let sent = server.join().unwrap();
    assert!(!sent.contains(&key_msg()), "{sent:?}");
}

#[test]
fn supervisor_link_gates_control_too() {
    let mut p = Phone::paired_only(PIN);
    p.keys
        .insert(CLIENT_ID.into(), PairingKey::from_bytes([7; 32]));
    p.pipelined = vec![status(StatusState::ControlAvailable)];
    let phone = Arc::new(Mutex::new(p));
    let ph = phone.clone();
    let (addr, server) = serve(move |mut c| {
        c.accept(&mut ph.lock().unwrap());
        c.recv()
    });
    let mut sup = Supervisor::start(addr, with_store(&store_with_key([7; 32])), eager_policy());
    let link = sup.link();
    assert_eq!(link.send_control(key_msg()), Err(SendError::Disconnected));
    let rx = sup.events();
    assert!(matches!(next(&rx), ClientEvent::Connected { .. }));
    assert_eq!(
        next(&rx),
        ClientEvent::Status(StatusState::ControlAvailable)
    );
    assert!(link.control_available());
    link.send_control(key_msg()).unwrap();
    assert_eq!(server.join().unwrap(), Some(key_msg()));
    sup.close();
    assert!(!link.control_available());
    assert_eq!(link.send_control(key_msg()), Err(SendError::Disconnected));
}
