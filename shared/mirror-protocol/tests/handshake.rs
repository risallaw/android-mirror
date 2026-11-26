//! Protocol v2 handshake: round trips, failure modes, downgrade binding and
//! the published token-mode test vector (PROTOCOL.md).

use hmac::{Hmac, Mac};
use mirror_protocol::auth::{from_hex, to_hex, PairingKey};
use mirror_protocol::handshake::*;
use mirror_protocol::*;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn bytes32(start: u8) -> [u8; 32] {
    std::array::from_fn(|i| start + i as u8)
}

fn template(modes: &[AuthMode]) -> ServerHello {
    ServerHello {
        proto: 0,
        device_name: "Pixel".into(),
        device_id: "pixel-8-abc".into(),
        model: "Pixel 8".into(),
        sdk_int: 35,
        codecs: vec!["h264".into()],
        caps: vec!["control".into()],
        auth_modes: modes.to_vec(),
        nonce_s: String::new(),
        kx: String::new(),
    }
}

const ALL_MODES: [AuthMode; 3] = [AuthMode::Pin, AuthMode::Token, AuthMode::NoAuth];

/// Fresh client + server after the hello exchange.
fn hellos() -> (ClientHandshake, ServerHandshake, ServerHello) {
    let (c, ch) = ClientHandshake::new("Mac", "mac-client-1").unwrap();
    let (s, sh) = ServerHandshake::new(&ch, template(&ALL_MODES)).unwrap();
    (c, s, sh)
}

fn auth_of(m: Message) -> Auth {
    match m {
        Message::Auth(a) => a,
        other => panic!("expected AUTH, got {other:?}"),
    }
}

fn accept(step: ServerStep) -> (Message, Established) {
    match step {
        ServerStep::Accept { reply, session } => (reply, session),
        other => panic!("expected Accept, got {other:?}"),
    }
}

fn rejected(step: ServerStep) -> AuthReason {
    match step {
        ServerStep::Reject { reply, reason } => {
            let Message::AuthResult(r) = reply else {
                panic!()
            };
            assert!(!r.ok);
            assert_eq!(r.reason, Some(reason));
            reason
        }
        other => panic!("expected Reject, got {other:?}"),
    }
}

fn done(step: ClientStep) -> Established {
    match step {
        ClientStep::Done(e) => e,
        other => panic!("expected Done, got {other:?}"),
    }
}

/// Both sides derived the same keys; records flow both ways.
fn assert_same_session(c: &Established, s: &Established) {
    assert_eq!(c.mode, s.mode);
    assert_eq!(c.keys.c2s(), s.keys.c2s());
    assert_eq!(c.keys.s2c(), s.keys.s2c());
    assert_ne!(c.keys.c2s(), c.keys.s2c());
    assert_eq!(c.transcript_hash, s.transcript_hash);
    assert_eq!(c.pairing_key, s.pairing_key);

    let (mut ctx, mut crx) = c.keys.client_channel();
    let (mut stx, mut srx) = s.keys.server_channel();
    let mut wire = Vec::new();
    ctx.seal_message(&Message::Start(Start::default()), &mut wire)
        .unwrap();
    srx.push(&wire);
    assert_eq!(srx.next().unwrap(), Some(Message::Start(Start::default())));
    wire.clear();
    stx.seal_message(&Message::Pong([9; 8]), &mut wire).unwrap();
    crx.push(&wire);
    assert_eq!(crx.next().unwrap(), Some(Message::Pong([9; 8])));
}

/// Full token handshake with `pk` on both sides.
fn token_session(pk: &PairingKey) -> (Established, Established) {
    let (c, s, sh) = hellos();
    let (auth, wait) = c
        .authenticate(&sh, ClientCredential::Token(pk.clone()))
        .unwrap();
    let (reply, server) = accept(s.accept_token(&auth_of(auth), pk));
    let client = done(wait.on_message(&reply).unwrap());
    (client, server)
}

/// Full PIN handshake; `Err` carries the client-side failure.
fn pin_session(
    client_pin: &str,
    server_pin: &str,
) -> Result<(Established, Established), HandshakeError> {
    let (c, s, sh) = hellos();
    let (auth, wait) = c
        .authenticate(&sh, ClientCredential::Pin(client_pin.into()))
        .unwrap();
    let auth = auth_of(auth);
    assert_eq!(auth.mode, AuthMode::Pin);
    assert_eq!(auth.proof, "");
    let ServerStep::Continue { reply, wait: sw } = s.start_pin(&auth, server_pin) else {
        panic!("server refused to start PIN")
    };
    let ClientStep::Send(confirm, wait) = wait.on_message(&reply)? else {
        panic!("expected AUTH_CONFIRM")
    };
    let Message::AuthConfirm(confirm) = confirm else {
        panic!()
    };
    let (reply, server) = accept(sw.on_confirm(&confirm));
    let client = done(wait.on_message(&reply)?);
    Ok((client, server))
}

// Independent re-implementation of the spec formulas (PROTOCOL.md), used to
// play a misbehaving client and to check the server's outputs.
fn lp(out: &mut Vec<u8>, x: &[u8]) {
    out.extend_from_slice(&(x.len() as u16).to_be_bytes());
    out.extend_from_slice(x);
}
fn spec_mac(key: &[u8], label: &[u8], th: &[u8]) -> Vec<u8> {
    let mut m = Hmac::<Sha256>::new_from_slice(key).unwrap();
    let mut msg = Vec::new();
    lp(&mut msg, label);
    lp(&mut msg, th);
    m.update(&msg);
    m.finalize().into_bytes().to_vec()
}
/// `ls(xs) = lp(x1) || … || lp(xn)`.
fn spec_ls(xs: &[&str]) -> Vec<u8> {
    let mut out = Vec::new();
    for x in xs {
        lp(&mut out, x.as_bytes());
    }
    out
}
fn spec_ctx(ch: &ClientHello, sh: &ServerHello, mode: &str) -> Vec<u8> {
    let modes: Vec<&str> = sh.auth_modes.iter().filter_map(|m| m.as_str()).collect();
    let caps: Vec<&str> = sh.caps.iter().map(String::as_str).collect();
    let mut c = Vec::new();
    for f in [
        &b"amr2"[..],
        &from_hex(&ch.nonce_c).unwrap(),
        &from_hex(&sh.nonce_s).unwrap(),
        &from_hex(&ch.kx).unwrap(),
        &from_hex(&sh.kx).unwrap(),
        ch.client_id.as_bytes(),
        sh.device_id.as_bytes(),
        mode.as_bytes(),
        ch.client_name.as_bytes(),
        sh.device_name.as_bytes(),
        sh.model.as_bytes(),
        &spec_ls(&modes),
        &spec_ls(&caps),
    ] {
        lp(&mut c, f);
    }
    c
}

// ---------------------------------------------------------------------------
// Round trips
// ---------------------------------------------------------------------------

#[test]
fn token_round_trip() {
    let pk = PairingKey::from_bytes(bytes32(0x80));
    let (c, s) = token_session(&pk);
    assert_eq!(c.mode, AuthMode::Token);
    assert_eq!(c.pairing_key, None);
    assert_same_session(&c, &s);
    // Fresh ephemeral keys/nonces: a second session has different keys.
    let (c2, _) = token_session(&pk);
    assert_ne!(c.keys.c2s(), c2.keys.c2s());
}

#[test]
fn pin_round_trip_yields_identical_pairing_key() {
    let (c, s) = pin_session("314159", "314159").unwrap();
    assert_eq!(c.mode, AuthMode::Pin);
    let pk = c.pairing_key.clone().expect("new pairing key");
    assert_eq!(s.pairing_key.as_ref(), Some(&pk));
    assert_ne!(pk.as_bytes(), &[0; 32]);
    assert_same_session(&c, &s);
    // The new key works for token mode.
    let (tc, ts) = token_session(&pk);
    assert_same_session(&tc, &ts);
    // And every pairing produces a different key.
    let (c2, _) = pin_session("314159", "314159").unwrap();
    assert_ne!(c2.pairing_key, Some(pk));
}

#[test]
fn none_round_trip_is_encrypted_but_unauthenticated() {
    let (c, s, sh) = hellos();
    let (auth, wait) = c.authenticate(&sh, ClientCredential::NoAuth).unwrap();
    let auth = auth_of(auth);
    assert_eq!(
        (auth.mode, auth.proof.as_str(), &auth.pake),
        (AuthMode::NoAuth, "", &None)
    );
    let (reply, server) = accept(s.accept_none());
    let client = done(wait.on_message(&reply).unwrap());
    assert_eq!(client.mode, AuthMode::NoAuth);
    assert_same_session(&client, &server);
}

// ---------------------------------------------------------------------------
// Failures
// ---------------------------------------------------------------------------

#[test]
fn wrong_pin_fails_client_side_before_revealing_confirm() {
    assert_eq!(
        pin_session("111111", "222222").unwrap_err(),
        HandshakeError::WrongPin
    );
}

/// A client that ignores the server's confirmation and sends a confirm
/// computed with the wrong PIN is refused by the server. With the right PIN
/// the same hand-rolled client (spec formulas only) is accepted and agrees on
/// the new pairing key: checks the server against the spec independently.
#[test]
fn server_confirm_check_against_spec_client() {
    use spake2::{Ed25519Group, Identity, Password, Spake2};
    for (client_pin, should_pass) in [("999999", false), ("123456", true)] {
        let (_, ch) = ClientHandshake::new("Mac", "mac-client-1").unwrap();
        let (s, sh) = ServerHandshake::new(&ch, template(&ALL_MODES)).unwrap();
        // Our ClientHello kx is from a ClientHandshake we dropped: only the
        // DH (session keys) depends on its secret, not the PIN flow.
        let (spake, msg_a) = Spake2::<Ed25519Group>::start_a(
            &Password::new(format!("androidmirror-pin{client_pin}")),
            &Identity::new(ch.client_id.as_bytes()),
            &Identity::new(sh.device_id.as_bytes()),
        );
        let auth = Auth {
            mode: AuthMode::Pin,
            proof: String::new(),
            pake: Some(to_hex(&msg_a)),
        };
        let ServerStep::Continue { reply, wait } = s.start_pin(&auth, "123456") else {
            panic!()
        };
        let Message::PakeReply(r) = reply else {
            panic!()
        };
        let msg_b = from_hex(&r.pake).unwrap();
        let kp = spake.finish(&msg_b).unwrap();
        let mut t = spec_ctx(&ch, &sh, "pin");
        lp(&mut t, &msg_a);
        lp(&mut t, &msg_b);
        let th_p = Sha256::digest(&t);
        assert_eq!(
            spec_mac(&kp, b"S", &th_p) == from_hex(&r.server_proof).unwrap(),
            should_pass
        );
        let confirm = AuthConfirm {
            proof: to_hex(&spec_mac(&kp, b"C", &th_p)),
        };
        let step = wait.on_confirm(&confirm);
        if should_pass {
            let (_, est) = accept(step);
            let mut pk = [0u8; 32];
            hkdf::Hkdf::<Sha256>::new(Some(&th_p), &kp)
                .expand(b"amr2 pairing key", &mut pk)
                .unwrap();
            assert_eq!(est.pairing_key, Some(PairingKey::from_bytes(pk)));
            assert_eq!(est.transcript_hash[..], th_p[..]);
        } else {
            assert_eq!(rejected(step), AuthReason::BadProof);
        }
    }
}

#[test]
fn server_rejects_garbage_or_replayed_pin_confirm() {
    // Garbage / non-hex / empty proofs.
    for proof in ["", "zz", &"00".repeat(32), &"00".repeat(31)] {
        let (c, s, sh) = hellos();
        let (auth, _) = c
            .authenticate(&sh, ClientCredential::Pin("123456".into()))
            .unwrap();
        let ServerStep::Continue { wait, .. } = s.start_pin(&auth_of(auth), "123456") else {
            panic!()
        };
        let step = wait.on_confirm(&AuthConfirm {
            proof: proof.into(),
        });
        assert_eq!(rejected(step), AuthReason::BadProof);
    }
    // A valid confirm from another session (same PIN) is bound to that transcript.
    let (c1, s1, sh1) = hellos();
    let (a1, w1) = c1
        .authenticate(&sh1, ClientCredential::Pin("123456".into()))
        .unwrap();
    let ServerStep::Continue { reply, .. } = s1.start_pin(&auth_of(a1), "123456") else {
        panic!()
    };
    let ClientStep::Send(Message::AuthConfirm(confirm1), _) = w1.on_message(&reply).unwrap() else {
        panic!()
    };
    let (c2, s2, sh2) = hellos();
    let (a2, _) = c2
        .authenticate(&sh2, ClientCredential::Pin("123456".into()))
        .unwrap();
    let ServerStep::Continue { wait: w2, .. } = s2.start_pin(&auth_of(a2), "123456") else {
        panic!()
    };
    assert_eq!(rejected(w2.on_confirm(&confirm1)), AuthReason::BadProof);
}

#[test]
fn server_rejects_missing_or_bad_pake() {
    for pake in [
        None,
        Some("zz".to_string()),
        Some("41".repeat(10)),
        Some("42".repeat(33)),
    ] {
        let (_, s, _) = hellos();
        let auth = Auth {
            mode: AuthMode::Pin,
            proof: String::new(),
            pake,
        };
        assert_eq!(rejected(s.start_pin(&auth, "123456")), AuthReason::BadProof);
    }
}

#[test]
fn wrong_token_key_is_rejected_by_server() {
    let (c, s, sh) = hellos();
    let (auth, _) = c
        .authenticate(
            &sh,
            ClientCredential::Token(PairingKey::from_bytes([1; 32])),
        )
        .unwrap();
    let step = s.accept_token(&auth_of(auth), &PairingKey::from_bytes([2; 32]));
    assert_eq!(rejected(step), AuthReason::BadProof);
}

/// A phone that does not hold the client's key (impostor, or the key was
/// reset) cannot produce the server proof: missing, wrong or non-hex proofs
/// are all refused by the client.
#[test]
fn client_detects_impostor_server_in_token_mode() {
    for server_proof in [None, Some("00".repeat(32)), Some("not hex".into())] {
        let (c, _, sh) = hellos();
        let (_, wait) = c
            .authenticate(
                &sh,
                ClientCredential::Token(PairingKey::from_bytes([1; 32])),
            )
            .unwrap();
        let reply = Message::AuthResult(AuthResult {
            ok: true,
            server_proof,
            reason: None,
            retry_after_ms: None,
        });
        assert_eq!(
            wait.on_message(&reply).unwrap_err(),
            HandshakeError::ServerProofMismatch
        );
    }
    // A proof made with another key over the right transcript is refused.
    let (c, ch) = ClientHandshake::new("Mac", "m").unwrap();
    let (_, sh) = ServerHandshake::new(&ch, template(&ALL_MODES)).unwrap();
    let (_, wait) = c
        .authenticate(
            &sh,
            ClientCredential::Token(PairingKey::from_bytes([1; 32])),
        )
        .unwrap();
    let wrong = spec_mac(&[2; 32], b"S", &Sha256::digest(spec_ctx(&ch, &sh, "token")));
    let reply = Message::AuthResult(AuthResult {
        ok: true,
        server_proof: Some(to_hex(&wrong)),
        reason: None,
        retry_after_ms: None,
    });
    assert_eq!(
        wait.on_message(&reply).unwrap_err(),
        HandshakeError::ServerProofMismatch
    );
}

#[test]
fn rejection_is_surfaced_with_retry_after() {
    let (c, _, sh) = hellos();
    let (_, wait) = c
        .authenticate(&sh, ClientCredential::Pin("123456".into()))
        .unwrap();
    let reply = ServerHandshake::rejection(AuthReason::LockedOut, Some(30_000));
    assert_eq!(
        wait.on_message(&reply).unwrap_err(),
        HandshakeError::Rejected {
            reason: AuthReason::LockedOut,
            retry_after_ms: Some(30_000)
        }
    );
    // A reason this version does not know.
    let (c, _, sh) = hellos();
    let (_, wait) = c
        .authenticate(
            &sh,
            ClientCredential::Token(PairingKey::from_bytes([1; 32])),
        )
        .unwrap();
    let reply = Message::AuthResult(AuthResult {
        ok: false,
        ..AuthResult::default()
    });
    assert_eq!(
        wait.on_message(&reply).unwrap_err(),
        HandshakeError::Rejected {
            reason: AuthReason::Unknown,
            retry_after_ms: None
        }
    );
}

#[test]
fn unexpected_messages_are_errors() {
    let (c, _, sh) = hellos();
    let (_, wait) = c
        .authenticate(
            &sh,
            ClientCredential::Token(PairingKey::from_bytes([1; 32])),
        )
        .unwrap();
    let pr = Message::PakeReply(PakeReply {
        pake: String::new(),
        server_proof: String::new(),
    });
    assert_eq!(
        wait.on_message(&pr).unwrap_err(),
        HandshakeError::Unexpected(0x0A)
    );
    let (c, _, sh) = hellos();
    let (_, wait) = c
        .authenticate(&sh, ClientCredential::Pin("1".into()))
        .unwrap();
    let ok = Message::AuthResult(AuthResult {
        ok: true,
        ..AuthResult::default()
    });
    // PIN mode: AUTH_RESULT ok before PAKE_REPLY would skip authentication.
    assert_eq!(
        wait.on_message(&ok).unwrap_err(),
        HandshakeError::Unexpected(0x02)
    );
}

#[test]
fn mode_must_be_offered_and_must_match() {
    let (c, ch) = ClientHandshake::new("Mac", "m").unwrap();
    let (s, sh) = ServerHandshake::new(&ch, template(&[AuthMode::Pin])).unwrap();
    assert_eq!(
        c.authenticate(&sh, ClientCredential::NoAuth).unwrap_err(),
        HandshakeError::ModeNotOffered(AuthMode::NoAuth)
    );
    // Server-side helpers refuse an AUTH of another mode.
    let a = Auth {
        mode: AuthMode::Pin,
        proof: String::new(),
        pake: None,
    };
    assert_eq!(
        rejected(s.accept_token(&a, &PairingKey::from_bytes([0; 32]))),
        AuthReason::ModeUnsupported
    );
}

#[test]
fn proto_mismatch_both_directions() {
    let (_, mut ch) = ClientHandshake::new("Mac", "m").unwrap();
    ch.proto = 1;
    assert_eq!(
        ServerHandshake::new(&ch, template(&ALL_MODES)).unwrap_err(),
        HandshakeError::ProtoMismatch(1)
    );
    let (c, s, mut sh) = hellos();
    drop(s);
    sh.proto = 3;
    assert_eq!(
        c.authenticate(&sh, ClientCredential::NoAuth).unwrap_err(),
        HandshakeError::ProtoMismatch(3)
    );
}

#[test]
fn bad_fields_are_rejected() {
    let (_, ch) = ClientHandshake::new("Mac", "m").unwrap();
    type Edit = fn(&mut ClientHello);
    let cases: Vec<(Edit, &str)> = vec![
        (|h| h.nonce_c = "00".repeat(31), "nonceC"),
        (|h| h.nonce_c = "zz".repeat(32), "nonceC"),
        (|h| h.kx = String::new(), "kx"),
        (|h| h.kx = "00".repeat(33), "kx"),
        (|h| h.client_id = "x".repeat(65536), "clientId too long"),
        (|h| h.client_name = "x".repeat(65536), "clientName too long"),
    ];
    for (f, what) in cases {
        let mut bad = ch.clone();
        f(&mut bad);
        assert_eq!(
            ServerHandshake::new(&bad, template(&ALL_MODES)).unwrap_err(),
            HandshakeError::BadField(what)
        );
    }
    // Ids up to 65535 bytes are fine.
    let mut ok = ch.clone();
    ok.client_id = "x".repeat(65535);
    assert!(ServerHandshake::new(&ok, template(&ALL_MODES)).is_ok());

    let (c, _, mut sh) = hellos();
    sh.nonce_s = "abc".into();
    assert_eq!(
        c.authenticate(&sh, ClientCredential::NoAuth).unwrap_err(),
        HandshakeError::BadField("nonceS")
    );

    // Bound SERVER_HELLO text: over-long fields fail on both sides.
    type ShEdit = fn(&mut ServerHello);
    let cases: Vec<(ShEdit, &str)> = vec![
        (|h| h.device_name = "x".repeat(65536), "deviceName too long"),
        (|h| h.model = "x".repeat(65536), "model too long"),
        // 2 + 65534 = 65536 bytes of ls() encoding.
        (|h| h.caps = vec!["x".repeat(65534)], "caps too long"),
        (
            |h| h.caps = vec!["c".into(); 65536 / 3 + 1],
            "caps too long",
        ),
    ];
    for (f, what) in cases {
        let mut t = template(&ALL_MODES);
        f(&mut t);
        assert_eq!(
            ServerHandshake::new(&ch, t).unwrap_err(),
            HandshakeError::BadField(what)
        );
        let (c, _, mut sh) = hellos();
        f(&mut sh);
        assert_eq!(
            c.authenticate(&sh, ClientCredential::NoAuth).unwrap_err(),
            HandshakeError::BadField(what)
        );
    }
    // The largest encodable list is fine.
    let mut t = template(&ALL_MODES);
    t.caps = vec!["x".repeat(65533)];
    assert!(ServerHandshake::new(&ch, t).is_ok());
}

#[test]
fn all_zero_dh_is_rejected() {
    // u = 0 and u = 1 (a low-order point) both give an all-zero X25519 output.
    let mut u1 = [0u8; 32];
    u1[0] = 1;
    for kx in [[0u8; 32], u1] {
        let (_, mut ch) = ClientHandshake::new("Mac", "m").unwrap();
        ch.kx = to_hex(&kx);
        assert_eq!(
            ServerHandshake::new(&ch, template(&ALL_MODES)).unwrap_err(),
            HandshakeError::WeakKeyExchange
        );
        let (c, _, mut sh) = hellos();
        sh.kx = to_hex(&kx);
        assert_eq!(
            c.authenticate(&sh, ClientCredential::NoAuth).unwrap_err(),
            HandshakeError::WeakKeyExchange
        );
    }
}

// ---------------------------------------------------------------------------
// Downgrade / tamper binding: a relay that rewrites any hello field or the
// mode makes the proofs fail.
// ---------------------------------------------------------------------------

/// Token handshake where `tamper_ch` edits CLIENT_HELLO on its way to the
/// server and `tamper_sh` edits SERVER_HELLO on its way to the client.
fn tampered_token(tamper_ch: impl Fn(&mut ClientHello), tamper_sh: impl Fn(&mut ServerHello)) {
    let pk = PairingKey::from_bytes(bytes32(0x80));
    let (c, mut ch) = ClientHandshake::new("Mac", "mac-client-1").unwrap();
    tamper_ch(&mut ch);
    let (s, mut sh) = ServerHandshake::new(&ch, template(&ALL_MODES)).unwrap();
    tamper_sh(&mut sh);
    let (auth, _) = c
        .authenticate(&sh, ClientCredential::Token(pk.clone()))
        .unwrap();
    assert_eq!(
        rejected(s.accept_token(&auth_of(auth), &pk)),
        AuthReason::BadProof
    );
}

/// A different valid X25519 public key (an attacker's).
fn other_kx() -> String {
    let (_, ch) = ClientHandshake::new("x", "y").unwrap();
    ch.kx
}

#[test]
fn tampered_hellos_fail_token_proof() {
    // Untampered control run passes.
    let pk = PairingKey::from_bytes(bytes32(0x80));
    token_session(&pk);

    tampered_token(|ch| ch.kx = other_kx(), |_| {});
    tampered_token(|_| {}, |sh| sh.kx = other_kx());
    tampered_token(|ch| ch.nonce_c = "11".repeat(32), |_| {});
    tampered_token(|_| {}, |sh| sh.nonce_s = "22".repeat(32));
    tampered_token(|ch| ch.client_id = "mac-client-2".into(), |_| {});
    tampered_token(|_| {}, |sh| sh.device_id = "pixel-8-abd".into());
    // The rest of the hellos is bound too (names, model, offered modes, caps).
    tampered_token(|ch| ch.client_name = "Mallory".into(), |_| {});
    tampered_token(|_| {}, |sh| sh.device_name = "Pixel 9".into());
    tampered_token(|_| {}, |sh| sh.model = "Pixel 9".into());
    tampered_token(|_| {}, |sh| sh.auth_modes = vec![AuthMode::Token]);
    tampered_token(
        |_| {},
        |sh| sh.auth_modes = vec![AuthMode::Token, AuthMode::Pin, AuthMode::NoAuth],
    );
    tampered_token(|_| {}, |sh| sh.caps = vec![]);
    tampered_token(|_| {}, |sh| sh.caps.push("audio".into()));
    // List items are length-prefixed: splitting or merging items is not
    // the same list (["control"] vs ["con", "trol"] vs ["con,trol"]).
    tampered_token(|_| {}, |sh| sh.caps = vec!["con".into(), "trol".into()]);
    tampered_token(|_| {}, |sh| sh.caps = vec!["control".into(), String::new()]);
}

/// A mode this version does not know is skipped by both sides: it can be
/// neither bound nor rejected, so adding one is not a tamper.
#[test]
fn unknown_offered_mode_is_not_bound() {
    let pk = PairingKey::from_bytes(bytes32(0x80));
    let (c, ch) = ClientHandshake::new("Mac", "mac-client-1").unwrap();
    let (s, mut sh) = ServerHandshake::new(&ch, template(&ALL_MODES)).unwrap();
    sh.auth_modes.insert(1, AuthMode::Unknown);
    let (auth, wait) = c
        .authenticate(&sh, ClientCredential::Token(pk.clone()))
        .unwrap();
    let (reply, server) = accept(s.accept_token(&auth_of(auth), &pk));
    assert_same_session(&done(wait.on_message(&reply).unwrap()), &server);
}

/// Hello text tampered in transit also breaks PIN pairing (the client sees
/// a "wrong PIN" before revealing its confirmation).
#[test]
fn tampered_hello_text_fails_pin_confirmation() {
    type Tamper = fn(&mut ClientHello, &mut ServerHello);
    let cases: [Tamper; 4] = [
        |ch, _| ch.client_name = "Mallory".into(),
        |_, sh| sh.device_name = "Evil".into(),
        |_, sh| sh.auth_modes = vec![AuthMode::Pin],
        |_, sh| sh.caps = vec![],
    ];
    for tamper in cases {
        let (c, mut ch) = ClientHandshake::new("Mac", "mac-client-1").unwrap();
        let mut dummy = template(&ALL_MODES);
        tamper(&mut ch, &mut dummy);
        let (s, mut sh) = ServerHandshake::new(&ch, template(&ALL_MODES)).unwrap();
        let mut dummy_ch = ch.clone();
        tamper(&mut dummy_ch, &mut sh);
        let (auth, wait) = c
            .authenticate(&sh, ClientCredential::Pin("123456".into()))
            .unwrap();
        let ServerStep::Continue { reply, .. } = s.start_pin(&auth_of(auth), "123456") else {
            panic!()
        };
        assert_eq!(
            wait.on_message(&reply).unwrap_err(),
            HandshakeError::WrongPin
        );
    }
}

#[test]
fn tampered_pin_hello_fails_confirmation() {
    let (c, mut ch) = ClientHandshake::new("Mac", "mac-client-1").unwrap();
    ch.nonce_c = "11".repeat(32);
    let (s, sh) = ServerHandshake::new(&ch, template(&ALL_MODES)).unwrap();
    let (auth, wait) = c
        .authenticate(&sh, ClientCredential::Pin("123456".into()))
        .unwrap();
    let ServerStep::Continue { reply, .. } = s.start_pin(&auth_of(auth), "123456") else {
        panic!()
    };
    // Same PIN, but the transcripts differ: the client sees a "wrong PIN".
    assert_eq!(
        wait.on_message(&reply).unwrap_err(),
        HandshakeError::WrongPin
    );
}

#[test]
fn mode_downgrade_is_detected() {
    // Client authenticates with token; a relay rewrites AUTH to mode none and
    // the server (allowing none) accepts. The client sees no valid proof.
    let pk = PairingKey::from_bytes(bytes32(0x80));
    let (c, s, sh) = hellos();
    let (_auth, wait) = c.authenticate(&sh, ClientCredential::Token(pk)).unwrap();
    let (reply, _) = accept(s.accept_none());
    assert_eq!(
        wait.on_message(&reply).unwrap_err(),
        HandshakeError::ServerProofMismatch
    );

    // A token proof is bound to the mode string: the same hellos with the
    // proof recomputed under another mode label are refused.
    let pk = PairingKey::from_bytes(bytes32(0x80));
    let (c, ch) = ClientHandshake::new("Mac", "mac-client-1").unwrap();
    let (s, sh) = ServerHandshake::new(&ch, template(&ALL_MODES)).unwrap();
    drop(c);
    let forged = spec_mac(
        pk.as_bytes(),
        b"C",
        &Sha256::digest(spec_ctx(&ch, &sh, "pin")),
    );
    let auth = Auth {
        mode: AuthMode::Token,
        proof: to_hex(&forged),
        pake: None,
    };
    assert_eq!(rejected(s.accept_token(&auth, &pk)), AuthReason::BadProof);
}

// ---------------------------------------------------------------------------
// Published test vector (PROTOCOL.md "Test vector"), computed independently
// with a pure-Python X25519 (RFC 7748) + hashlib/hmac.
// ---------------------------------------------------------------------------

#[test]
fn token_mode_test_vector() {
    let nonce_c = bytes32(0x00);
    let nonce_s = bytes32(0x20);
    let sk_c = Zeroizing::new(bytes32(0x40));
    let sk_s = Zeroizing::new(bytes32(0x60));
    let pk = PairingKey::from_bytes(bytes32(0x80));

    let (c, ch) = ClientHandshake::with_secrets("Mac", "mac-client-1", nonce_c, sk_c);
    let (s, sh) = ServerHandshake::with_secrets(&ch, template(&ALL_MODES), nonce_s, sk_s).unwrap();
    assert_eq!(
        ch.kx,
        "79a631eede1bf9c98f12032cdeadd0e7a079398fc786b88cc846ec89af85a51a"
    );
    assert_eq!(
        sh.kx,
        "675dd574ed7789310b3d2e7681f3790b466c773b1521fecf36577958371ea52f"
    );
    assert_eq!(ch.nonce_c, to_hex(&nonce_c));
    assert_eq!(sh.nonce_s, to_hex(&nonce_s));
    // `dh` is internal; pin the published value and derive the session keys
    // from it with the spec formula below.
    let kx_s: [u8; 32] = from_hex(&sh.kx).unwrap().try_into().unwrap();
    let dh = x25519_dalek::StaticSecret::from(bytes32(0x40))
        .diffie_hellman(&x25519_dalek::PublicKey::from(kx_s));
    assert_eq!(
        to_hex(dh.as_bytes()),
        "d6fb939511b2381bc8599b4b8edc5968829450dfd7a87aebe78a703cd04cd54e"
    );

    let (auth, wait) = c
        .authenticate(&sh, ClientCredential::Token(pk.clone()))
        .unwrap();
    let auth = auth_of(auth);
    assert_eq!(
        auth.proof,
        "2b93c9dd914f20a4687c0522e999746c0eb670ec75949e91d17ddf824c8a6342"
    );
    let (reply, server) = accept(s.accept_token(&auth, &pk));
    let Message::AuthResult(r) = &reply else {
        panic!()
    };
    assert_eq!(
        r.server_proof.as_deref(),
        Some("b37320d4a45f706b5e2e8ee747d397ed7e18dde27e5f732e7ba573c7aa3b25b8")
    );
    let client = done(wait.on_message(&reply).unwrap());
    // The independent spec implementation agrees with the pinned value.
    assert_eq!(
        client.transcript_hash[..],
        Sha256::digest(spec_ctx(&ch, &sh, "token"))[..]
    );
    assert_eq!(
        to_hex(&client.transcript_hash),
        "7a11c3c950adcfcbdb632a10228a67cec2091ef60702af0dac1403f894bb353d"
    );
    assert_eq!(
        to_hex(client.keys.c2s()),
        "cda68a732e33f6741d17ab1a16ec36d47b4769eacf97661bf620570330c619ab"
    );
    assert_eq!(
        to_hex(client.keys.s2c()),
        "7c1576301d7901f27d8b7e18fb538d0624f623c86d311067bb3545e56a5a77c5"
    );
    // Spec: PRK = HKDF-Extract(salt = K, ikm = dh),
    // OKM = HKDF-Expand(PRK, "amr2 session keys" || thF, 64).
    let mut okm = [0u8; 64];
    hkdf::Hkdf::<Sha256>::new(Some(pk.as_bytes()), dh.as_bytes())
        .expand(
            &[&b"amr2 session keys"[..], &client.transcript_hash].concat(),
            &mut okm,
        )
        .unwrap();
    assert_eq!(&okm[..32], client.keys.c2s());
    assert_eq!(&okm[32..], client.keys.s2c());
    assert_same_session(&client, &server);
}

/// Same inputs, mode `none` (K = 32 zero bytes).
#[test]
fn none_mode_test_vector() {
    let (c, ch) = ClientHandshake::with_secrets(
        "Mac",
        "mac-client-1",
        bytes32(0x00),
        Zeroizing::new(bytes32(0x40)),
    );
    let (s, sh) = ServerHandshake::with_secrets(
        &ch,
        template(&ALL_MODES),
        bytes32(0x20),
        Zeroizing::new(bytes32(0x60)),
    )
    .unwrap();
    let (_, wait) = c.authenticate(&sh, ClientCredential::NoAuth).unwrap();
    let (reply, server) = accept(s.accept_none());
    let client = done(wait.on_message(&reply).unwrap());
    assert_eq!(
        to_hex(&client.transcript_hash),
        "9fb9364fae0219e59698ca322d527a6db19e170f322a06c679355e1e7b66b657"
    );
    assert_eq!(
        to_hex(client.keys.c2s()),
        "aab2a0688bf0c61bae92bc8f4a07a08bb026d2efd9d32c237bf337783f044981"
    );
    assert_eq!(
        to_hex(client.keys.s2c()),
        "d4054938d4b7a616512bb6792e00ed5c9ba36972336e17c113e4e7ab86c86ee8"
    );
    assert_same_session(&client, &server);
}

// ---------------------------------------------------------------------------
// Secret hygiene
// ---------------------------------------------------------------------------

#[test]
fn debug_output_is_redacted() {
    let pk = PairingKey::from_bytes([0xab; 32]);
    let (c, s) = token_session(&pk);
    let secret_hex = [
        to_hex(pk.as_bytes()),
        to_hex(c.keys.c2s()),
        to_hex(c.keys.s2c()),
    ];
    let dumps = [
        format!("{pk:?}"),
        format!("{c:?}"),
        format!("{s:?}"),
        format!("{:?}", ClientCredential::Token(pk.clone())),
        format!("{:?}", ClientCredential::Pin("987654".into())),
        format!("{:?}", c.keys.client_channel()),
    ];
    for d in &dumps {
        assert!(d.contains("redacted") || d.contains(".."), "{d}");
        for h in &secret_hex {
            assert!(!d.contains(h.as_str()), "{d}");
        }
        assert!(!d.contains("987654"), "{d}");
        // Byte-array style dumps of the key would show "171, 171".
        assert!(!d.contains("171, 171"), "{d}");
    }
}

#[test]
fn pairing_key_hex_round_trip() {
    let pk = PairingKey::from_bytes(bytes32(1));
    assert_eq!(PairingKey::from_hex(&pk.to_hex()), Some(pk.clone()));
    assert_eq!(PairingKey::from_hex(&pk.to_hex()[2..]), None);
    assert_eq!(PairingKey::from_hex("zz"), None);
    assert_ne!(Some(pk), PairingKey::from_hex(&"00".repeat(32)));
}
