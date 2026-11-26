use std::convert::Infallible;

use mirror_protocol::annexb::*;
use mirror_protocol::auth::*;
use mirror_protocol::geometry::*;
use mirror_protocol::wire::{flags, ty, Header, HEADER_LEN};
use mirror_protocol::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Deterministic xorshift64* RNG (tests only; marked CryptoRng to satisfy bounds).
struct TestRng(u64);
impl rand_core::TryRng for TestRng {
    type Error = Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok((self.try_next_u64()? >> 32) as u32)
    }
    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        Ok(x.wrapping_mul(0x2545_F491_4F6C_DD1D))
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        for c in dst.chunks_mut(8) {
            let v = self.try_next_u64()?.to_le_bytes();
            c.copy_from_slice(&v[..c.len()]);
        }
        Ok(())
    }
}
impl rand_core::TryCryptoRng for TestRng {}

fn all_messages() -> Vec<Message> {
    vec![
        Message::ServerHello(ServerHello {
            proto: PROTO_VERSION,
            device_name: "Risal's Pixel".into(),
            device_id: "dev-123".into(),
            model: "Pixel 8".into(),
            sdk_int: 35,
            codecs: vec!["h264".into()],
            caps: vec!["control".into()],
            auth_modes: vec![AuthMode::Pin, AuthMode::Token, AuthMode::NoAuth],
            nonce_s: "00ff".repeat(16),
            kx: "ee".repeat(32),
        }),
        Message::AuthResult(AuthResult {
            ok: true,
            server_proof: Some("ab".repeat(32)),
            reason: None,
            retry_after_ms: None,
        }),
        Message::AuthResult(AuthResult {
            ok: false,
            server_proof: None,
            reason: Some(AuthReason::BadProof),
            retry_after_ms: None,
        }),
        Message::AuthResult(AuthResult {
            ok: false,
            server_proof: None,
            reason: Some(AuthReason::LockedOut),
            retry_after_ms: Some(30_000),
        }),
        Message::PakeReply(PakeReply {
            pake: "42".repeat(33),
            server_proof: "5a".repeat(32),
        }),
        Message::VideoConfig(VideoConfig {
            width: 864,
            height: 1920,
            display_width: 1080,
            display_height: 2400,
            rotation: 1,
            sps_pps: vec![0, 0, 0, 1, 0x67, 1, 2, 0, 0, 0, 1, 0x68, 3],
        }),
        Message::VideoFrame(VideoFrame {
            pts_us: 123_456_789_012,
            flags: flags::KEYFRAME | flags::DISCONTINUITY,
            data: vec![0, 0, 0, 1, 0x65, 9, 9, 9],
        }),
        Message::VideoFrame(VideoFrame {
            pts_us: 1,
            flags: 0,
            data: vec![],
        }),
        Message::Status(Status {
            state: StatusState::Streaming,
        }),
        Message::Status(Status {
            state: StatusState::ControlUnavailable,
        }),
        Message::Pong([1, 2, 3, 4, 5, 6, 7, 8]),
        Message::ServerBye(Bye {
            reason: ByeReason::ProjectionRevoked,
        }),
        Message::ClientHello(ClientHello {
            proto: PROTO_VERSION,
            client_name: "MacBook".into(),
            client_id: "c-1".into(),
            nonce_c: "11".repeat(32),
            kx: "dd".repeat(32),
        }),
        Message::Auth(Auth {
            mode: AuthMode::Token,
            proof: "cd".repeat(32),
            pake: None,
        }),
        Message::Auth(Auth {
            mode: AuthMode::Pin,
            proof: String::new(),
            pake: Some("41".repeat(33)),
        }),
        Message::Auth(Auth {
            mode: AuthMode::NoAuth,
            proof: String::new(),
            pake: None,
        }),
        Message::AuthConfirm(AuthConfirm {
            proof: "c0".repeat(32),
        }),
        Message::Start(Start {
            max_long_edge: Some(1920),
            max_fps: Some(60),
            bitrate: Some(8_000_000),
        }),
        Message::Start(Start::default()),
        Message::RequestKeyframe,
        Message::Ping([8, 7, 6, 5, 4, 3, 2, 1]),
        Message::ClientBye(Bye {
            reason: ByeReason::StoppedByUser,
        }),
        Message::TouchGesture(TouchGesture {
            kind: GestureKind::Path,
            points: vec![
                GesturePoint {
                    x: 0,
                    y: 65535,
                    dt_ms: 0,
                },
                GesturePoint {
                    x: 32768,
                    y: 100,
                    dt_ms: 16,
                },
                GesturePoint {
                    x: 65535,
                    y: 0,
                    dt_ms: 17,
                },
            ],
        }),
        Message::TouchGesture(TouchGesture {
            kind: GestureKind::Tap,
            points: vec![GesturePoint {
                x: 5,
                y: 6,
                dt_ms: 0,
            }],
        }),
        Message::TouchGesture(TouchGesture {
            kind: GestureKind::LongPress,
            points: vec![],
        }),
        Message::GlobalAction(GlobalAction::Back),
        Message::GlobalAction(GlobalAction::VolumeDown),
        Message::GlobalAction(GlobalAction::Other(42)),
        Message::Text("héllo 👋\n".into()),
        Message::Key(Key::Enter),
        Message::Key(Key::Tab),
        Message::Scroll(Scroll {
            x: 100,
            y: 200,
            dx: -120,
            dy: 32767,
        }),
        Message::TouchLive(TouchLive {
            phase: TouchPhase::Down,
            x: 1,
            y: 2,
        }),
        Message::TouchLive(TouchLive {
            phase: TouchPhase::Cancel,
            x: 65535,
            y: 65535,
        }),
        Message::Unknown {
            ty: 0x08,
            flags: 3,
            payload: vec![1, 2, 3],
        },
        Message::Unknown {
            ty: 0x7f,
            flags: 0,
            payload: vec![],
        },
    ]
}

fn stream(msgs: &[Message]) -> Vec<u8> {
    let mut b = MAGIC.to_vec();
    for m in msgs {
        b.extend(encode(m));
    }
    b
}

fn drain(d: &mut Decoder, out: &mut Vec<Message>) {
    while let Some(m) = d.next().unwrap() {
        out.push(m);
    }
}

// ---------------------------------------------------------------------------
// Wire / codec
// ---------------------------------------------------------------------------

#[test]
fn constants() {
    assert_eq!(&MAGIC, &[0x41, 0x4D, 0x52, 0x31]);
    assert_eq!(DEFAULT_PORT, 47800);
    assert_eq!(SERVICE_TYPE, "_androidmirror._tcp");
    assert_eq!(MAX_PAYLOAD, 8 * 1024 * 1024);
    assert_eq!(MAX_CLIENT_PAYLOAD, 64 * 1024);
    assert_eq!(PROTO_VERSION, 2);
    assert_eq!(ty::PAKE_REPLY, 0x0A);
    assert_eq!(ty::AUTH_CONFIRM, 0x16);
    assert!(ty::is_json(ty::PAKE_REPLY) && ty::is_json(ty::AUTH_CONFIRM));
}

/// Every wire code and string in PROTOCOL.md, pinned one by one: renaming or
/// renumbering anything must fail here, not only in a round trip.
#[test]
fn wire_codes_and_strings_are_pinned() {
    assert_eq!(MAX_JSON_PAYLOAD, 64 * 1024);
    assert_eq!(HEADER_LEN, 16);
    let types = [
        (ty::SERVER_HELLO, 0x01, true),
        (ty::AUTH_RESULT, 0x02, true),
        (ty::VIDEO_CONFIG, 0x03, false),
        (ty::VIDEO_FRAME, 0x04, false),
        (ty::STATUS, 0x05, true),
        (ty::PONG, 0x06, false),
        (ty::SERVER_BYE, 0x07, true),
        (ty::AUDIO_CONFIG, 0x08, false),
        (ty::AUDIO_FRAME, 0x09, false),
        (ty::PAKE_REPLY, 0x0A, true),
        (ty::CLIENT_HELLO, 0x10, true),
        (ty::AUTH, 0x11, true),
        (ty::START, 0x12, true),
        (ty::REQUEST_KEYFRAME, 0x13, false),
        (ty::PING, 0x14, false),
        (ty::CLIENT_BYE, 0x15, true),
        (ty::AUTH_CONFIRM, 0x16, true),
        (ty::TOUCH_GESTURE, 0x20, false),
        (ty::GLOBAL_ACTION, 0x21, false),
        (ty::TEXT, 0x22, false),
        (ty::KEY, 0x23, false),
        (ty::SCROLL, 0x24, false),
        (ty::TOUCH_LIVE, 0x25, false),
    ];
    for (code, wire, json) in types {
        assert_eq!(code, wire);
        assert_eq!(ty::is_json(code), json, "0x{code:02x}");
    }
    // No other type is JSON.
    let json_count = (0..=255u8).filter(|&t| ty::is_json(t)).count();
    assert_eq!(json_count, types.iter().filter(|t| t.2).count());
    assert_eq!(
        (flags::KEYFRAME, flags::CONFIG, flags::DISCONTINUITY),
        (1, 2, 4)
    );

    let json = |v: serde_json::Value| v.as_str().unwrap().to_owned();
    for (m, w) in [
        (AuthMode::Pin, "pin"),
        (AuthMode::Token, "token"),
        (AuthMode::NoAuth, "none"),
    ] {
        assert_eq!(json(serde_json::to_value(m).unwrap()), w);
        assert_eq!(m.as_str(), Some(w));
    }
    assert_eq!(AuthMode::Unknown.as_str(), None);
    for (st, w) in [
        (StatusState::Streaming, "streaming"),
        (StatusState::ScreenOff, "screen_off"),
        (StatusState::ScreenOn, "screen_on"),
        (StatusState::Reconfiguring, "reconfiguring"),
        (StatusState::ControlAvailable, "control_available"),
        (StatusState::ControlUnavailable, "control_unavailable"),
    ] {
        assert_eq!(json(serde_json::to_value(st).unwrap()), w);
    }
    for (r, w) in [
        (ByeReason::StoppedByUser, "stopped_by_user"),
        (ByeReason::ProjectionRevoked, "projection_revoked"),
        (ByeReason::Replaced, "replaced"),
        (ByeReason::AuthFailed, "auth_failed"),
        (ByeReason::ProtoMismatch, "proto_mismatch"),
        (ByeReason::Unknown, "unknown"),
    ] {
        assert_eq!(json(serde_json::to_value(r).unwrap()), w);
    }

    let actions = [
        GlobalAction::Back,
        GlobalAction::Home,
        GlobalAction::Recents,
        GlobalAction::Notifications,
        GlobalAction::QuickSettings,
        GlobalAction::Lock,
        GlobalAction::VolumeUp,
        GlobalAction::VolumeDown,
    ];
    let keys = [
        Key::Backspace,
        Key::Enter,
        Key::Left,
        Key::Right,
        Key::Up,
        Key::Down,
        Key::DeleteForward,
        Key::Tab,
    ];
    for (i, (a, k)) in actions.into_iter().zip(keys).enumerate() {
        let code = i as u8 + 1;
        assert_eq!((a.to_u8(), k.to_u8()), (code, code));
        assert_eq!((GlobalAction::from_u8(code), Key::from_u8(code)), (a, k));
    }
    assert_eq!(GlobalAction::from_u8(9), GlobalAction::Other(9));
    assert_eq!(Key::from_u8(0), Key::Other(0));
    assert_eq!(
        [GestureKind::Tap, GestureKind::LongPress, GestureKind::Path].map(GestureKind::to_u8),
        [1, 2, 3]
    );
    assert_eq!(
        [
            TouchPhase::Down,
            TouchPhase::Move,
            TouchPhase::Up,
            TouchPhase::Cancel
        ]
        .map(TouchPhase::to_u8),
        [0, 1, 2, 3]
    );
}

/// SERVER_HELLO and PING/PONG, byte for byte.
#[test]
fn known_answer_hello_and_ping_encodings() {
    let Message::ServerHello(sh) = all_messages().swap_remove(0) else {
        panic!()
    };
    let b = encode(&Message::ServerHello(ServerHello {
        nonce_s: "00".into(),
        kx: "01".into(),
        ..sh
    }));
    let payload = br#"{"proto":2,"deviceName":"Risal's Pixel","deviceId":"dev-123","model":"Pixel 8","sdkInt":35,"codecs":["h264"],"caps":["control"],"authModes":["pin","token","none"],"nonceS":"00","kx":"01"}"#;
    assert_eq!(&b[..8], &[0x01, 0, 0, 0, 0, 0, 0, payload.len() as u8]);
    assert_eq!(&b[HEADER_LEN..], payload);
    let ping = encode(&Message::Ping([1, 2, 3, 4, 5, 6, 7, 8]));
    assert_eq!(
        ping,
        [0x14, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8]
    );
    let pong = encode(&Message::Pong([1, 2, 3, 4, 5, 6, 7, 8]));
    assert_eq!(pong[0], 0x06);
    assert_eq!(pong[1..], ping[1..]);
}

#[test]
fn header_roundtrip_and_layout() {
    let h = Header {
        ty: 0x04,
        flags: 0x05,
        length: 0x0102_0304,
        pts_us: 0x1122_3344_5566_7788,
    };
    let b = h.encode();
    assert_eq!(
        b,
        [0x04, 0x05, 0, 0, 1, 2, 3, 4, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]
    );
    assert_eq!(Header::decode(&b), h);
    // Reserved bytes are ignored on decode.
    let mut b2 = b;
    b2[2] = 0xff;
    b2[3] = 0xee;
    assert_eq!(Header::decode(&b2), h);
}

#[test]
fn roundtrip_every_message() {
    for m in all_messages() {
        let bytes = encode(&m);
        let mut d = Decoder::new(false);
        d.push(&bytes);
        assert_eq!(
            d.next().unwrap().as_ref(),
            Some(&m),
            "type 0x{:02x}",
            m.ty()
        );
        assert_eq!(d.next().unwrap(), None);
        assert_eq!(d.buffered(), 0);
    }
}

#[test]
fn json_field_names_are_camel_case() {
    let p = all_messages()[0].encode_payload();
    let v: serde_json::Value = serde_json::from_slice(&p).unwrap();
    for k in [
        "proto",
        "deviceName",
        "deviceId",
        "model",
        "sdkInt",
        "codecs",
        "caps",
        "authModes",
        "nonceS",
        "kx",
    ] {
        assert!(v.get(k).is_some(), "missing {k}");
    }
    assert_eq!(v["authModes"], serde_json::json!(["pin", "token", "none"]));
    let p = encode(&Message::Start(Start {
        max_long_edge: Some(1280),
        max_fps: Some(30),
        bitrate: Some(4_000_000),
    }));
    assert_eq!(
        &p[HEADER_LEN..],
        br#"{"maxLongEdge":1280,"maxFps":30,"bitrate":4000000}"#
    );
    let p = encode(&Message::Status(Status {
        state: StatusState::ScreenOff,
    }));
    assert_eq!(&p[HEADER_LEN..], br#"{"state":"screen_off"}"#);
    let p = encode(&Message::ServerBye(Bye {
        reason: ByeReason::ProtoMismatch,
    }));
    assert_eq!(&p[HEADER_LEN..], br#"{"reason":"proto_mismatch"}"#);
    let p = encode(&Message::AuthResult(AuthResult {
        ok: true,
        server_proof: Some("aa".into()),
        reason: None,
        retry_after_ms: None,
    }));
    assert_eq!(&p[HEADER_LEN..], br#"{"ok":true,"serverProof":"aa"}"#);
    let p = encode(&Message::AuthResult(AuthResult {
        ok: false,
        server_proof: None,
        reason: Some(AuthReason::LockedOut),
        retry_after_ms: Some(1500),
    }));
    assert_eq!(
        &p[HEADER_LEN..],
        br#"{"ok":false,"reason":"locked_out","retryAfterMs":1500}"#
    );
    let p = encode(&Message::ClientHello(ClientHello {
        proto: 2,
        client_name: "m".into(),
        client_id: "c".into(),
        nonce_c: "00".into(),
        kx: "01".into(),
    }));
    assert_eq!(
        &p[HEADER_LEN..],
        br#"{"proto":2,"clientName":"m","clientId":"c","nonceC":"00","kx":"01"}"#
    );
    let p = encode(&Message::Auth(Auth {
        mode: AuthMode::Pin,
        proof: String::new(),
        pake: Some("41".into()),
    }));
    assert_eq!(
        &p[HEADER_LEN..],
        br#"{"mode":"pin","proof":"","pake":"41"}"#
    );
    let p = encode(&Message::PakeReply(PakeReply {
        pake: "42".into(),
        server_proof: "aa".into(),
    }));
    assert_eq!(p[0], 0x0A);
    assert_eq!(&p[HEADER_LEN..], br#"{"pake":"42","serverProof":"aa"}"#);
    let p = encode(&Message::AuthConfirm(AuthConfirm { proof: "bb".into() }));
    assert_eq!(p[0], 0x16);
    assert_eq!(&p[HEADER_LEN..], br#"{"proof":"bb"}"#);
    for (r, w) in [
        (AuthReason::UnknownClient, "unknown_client"),
        (AuthReason::BadProof, "bad_proof"),
        (AuthReason::LockedOut, "locked_out"),
        (AuthReason::ModeUnsupported, "mode_unsupported"),
    ] {
        assert_eq!(serde_json::to_value(r).unwrap(), serde_json::json!(w));
    }
}

#[test]
fn known_answer_binary_encodings() {
    let b = encode(&Message::Scroll(Scroll {
        x: 0x0102,
        y: 0x0304,
        dx: -1,
        dy: 2,
    }));
    assert_eq!(
        b,
        [0x24, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 0xff, 0xff, 0, 2]
    );
    let b = encode(&Message::TouchLive(TouchLive {
        phase: TouchPhase::Move,
        x: 0xabcd,
        y: 1,
    }));
    assert_eq!(&b[..8], &[0x25, 0, 0, 0, 0, 0, 0, 6]);
    assert_eq!(&b[16..], &[1, 0, 0xab, 0xcd, 0, 1]);
    let b = encode(&Message::TouchGesture(TouchGesture {
        kind: GestureKind::Tap,
        points: vec![GesturePoint {
            x: 0x1000,
            y: 0x2000,
            dt_ms: 50,
        }],
    }));
    assert_eq!(&b[16..], &[1, 1, 0, 0, 0x10, 0, 0x20, 0, 0, 50]);
    let b = encode(&Message::VideoConfig(VideoConfig {
        width: 864,
        height: 1920,
        display_width: 1080,
        display_height: 2400,
        rotation: 3,
        sps_pps: vec![0xaa],
    }));
    assert_eq!(b[0], ty::VIDEO_CONFIG);
    assert_eq!(b[1], flags::CONFIG);
    assert_eq!(
        &b[16..],
        &[0x03, 0x60, 0x07, 0x80, 0x04, 0x38, 0x09, 0x60, 3, 0, 0, 0, 0xaa]
    );
    let b = encode(&Message::VideoFrame(VideoFrame {
        pts_us: 16_666,
        flags: flags::KEYFRAME,
        data: vec![7],
    }));
    assert_eq!(b, [4, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0x41, 0x1a, 7]);
    assert_eq!(
        encode(&Message::GlobalAction(GlobalAction::Home))[16..],
        [2]
    );
    assert_eq!(encode(&Message::Key(Key::DeleteForward))[16..], [7]);
    assert_eq!(
        encode(&Message::RequestKeyframe),
        [0x13, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    );
}

#[test]
fn decode_byte_at_a_time() {
    let msgs = all_messages();
    let bytes = stream(&msgs);
    let mut d = Decoder::new(true);
    let mut out = Vec::new();
    for b in &bytes {
        d.push(std::slice::from_ref(b));
        drain(&mut d, &mut out);
    }
    assert_eq!(out, msgs);
    assert!(d.magic_seen());
}

#[test]
fn decode_random_chunks() {
    let msgs = all_messages();
    let bytes = stream(&msgs);
    let mut rng = TestRng(0x9e37_79b9_7f4a_7c15);
    for _ in 0..200 {
        let mut d = Decoder::new(true);
        let mut out = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            let n = 1 + (rand_core::Rng::next_u32(&mut rng) as usize % 97);
            let e = (i + n).min(bytes.len());
            d.push(&bytes[i..e]);
            drain(&mut d, &mut out);
            i = e;
        }
        assert_eq!(out, msgs);
    }
    // All at once.
    let mut d = Decoder::default();
    d.push(&bytes);
    let mut out = Vec::new();
    drain(&mut d, &mut out);
    assert_eq!(out, msgs);
}

#[test]
fn bad_magic_is_fatal_and_detected_early() {
    let mut d = Decoder::new(true);
    d.push(b"AM");
    assert_eq!(d.next().unwrap(), None);
    d.push(b"X1");
    assert_eq!(d.next(), Err(ProtocolError::BadMagic(*b"AMX1")));
    assert_eq!(d.next(), Err(ProtocolError::Poisoned));
    d.push(&stream(&[Message::RequestKeyframe]));
    assert_eq!(d.next(), Err(ProtocolError::Poisoned));

    // First byte wrong: fails without waiting for 4 bytes.
    let mut d = Decoder::new(true);
    d.push(b"G");
    assert!(matches!(d.next(), Err(ProtocolError::BadMagic(_))));
    assert!(ProtocolError::BadMagic(*b"GET ").is_fatal());
}

#[test]
fn oversize_rejected_from_header_alone() {
    let h = Header {
        ty: ty::VIDEO_FRAME,
        flags: 0,
        length: MAX_PAYLOAD + 1,
        pts_us: 0,
    };
    let mut d = Decoder::new(false);
    d.push(&h.encode());
    assert_eq!(
        d.next(),
        Err(ProtocolError::PayloadTooLarge {
            len: MAX_PAYLOAD + 1,
            max: MAX_PAYLOAD
        })
    );
    assert_eq!(d.next(), Err(ProtocolError::Poisoned));

    // Exactly MAX is accepted (header-wise: decoder waits for the body).
    let h = Header {
        ty: ty::VIDEO_FRAME,
        flags: 0,
        length: MAX_PAYLOAD,
        pts_us: 0,
    };
    let mut d = Decoder::new(false);
    d.push(&h.encode());
    assert_eq!(d.next(), Ok(None));

    // Custom limit.
    let mut d = Decoder::new(false).with_max_payload(4);
    d.push(&encode(&Message::Text("hello".into())));
    assert!(matches!(
        d.next(),
        Err(ProtocolError::PayloadTooLarge { len: 5, max: 4 })
    ));
}

#[test]
fn unknown_types_surface_and_stream_stays_in_sync() {
    let mut bytes = Header {
        ty: 0x99,
        flags: 0x80,
        length: 3,
        pts_us: 77,
    }
    .encode()
    .to_vec();
    bytes.extend([1, 2, 3]);
    bytes.extend(encode(&Message::Key(Key::Up)));
    let mut d = Decoder::new(false);
    d.push(&bytes);
    assert_eq!(
        d.next().unwrap(),
        Some(Message::Unknown {
            ty: 0x99,
            flags: 0x80,
            payload: vec![1, 2, 3]
        })
    );
    assert_eq!(d.next().unwrap(), Some(Message::Key(Key::Up)));
}

#[test]
fn malformed_payload_is_recoverable() {
    let mut bytes = Header {
        ty: ty::STATUS,
        flags: 0,
        length: 3,
        pts_us: 0,
    }
    .encode()
    .to_vec();
    bytes.extend(b"{x}");
    bytes.extend(
        Header {
            ty: ty::PING,
            flags: 0,
            length: 2,
            pts_us: 0,
        }
        .encode(),
    );
    bytes.extend([0, 0]);
    bytes.extend(
        Header {
            ty: ty::TOUCH_GESTURE,
            flags: 0,
            length: 4,
            pts_us: 0,
        }
        .encode(),
    );
    bytes.extend([3, 2, 0, 0]); // count 2 but no points
    bytes.extend(
        Header {
            ty: ty::TEXT,
            flags: 0,
            length: 1,
            pts_us: 0,
        }
        .encode(),
    );
    bytes.extend([0xff]);
    bytes.extend(encode(&Message::RequestKeyframe));
    let mut d = Decoder::new(false);
    d.push(&bytes);
    for expected_ty in [ty::STATUS, ty::PING, ty::TOUCH_GESTURE, ty::TEXT] {
        match d.next() {
            Err(e @ ProtocolError::Malformed { ty, .. }) => {
                assert_eq!(ty, expected_ty);
                assert!(!e.is_fatal());
            }
            other => panic!("expected malformed, got {other:?}"),
        }
    }
    assert_eq!(d.next().unwrap(), Some(Message::RequestKeyframe));
}

#[test]
fn lenient_decoding() {
    // Unknown JSON fields ignored, unknown enum strings map to Unknown.
    let mut b = Header {
        ty: ty::STATUS,
        flags: 0,
        length: 0,
        pts_us: 0,
    }
    .encode()
    .to_vec();
    let p = br#"{"state":"quantum","extra":1}"#;
    b[4..8].copy_from_slice(&(p.len() as u32).to_be_bytes());
    b.extend(p);
    // Empty START = defaults.
    b.extend(
        Header {
            ty: ty::START,
            flags: 0,
            length: 0,
            pts_us: 0,
        }
        .encode(),
    );
    let mut d = Decoder::new(false);
    d.push(&b);
    assert_eq!(
        d.next().unwrap(),
        Some(Message::Status(Status {
            state: StatusState::Unknown
        }))
    );
    assert_eq!(d.next().unwrap(), Some(Message::Start(Start::default())));
}

#[test]
fn lenient_auth_decoding() {
    let decode = |t: u8, p: &[u8]| {
        let h = Header {
            ty: t,
            flags: 0,
            length: p.len() as u32,
            pts_us: 0,
        };
        Message::decode_frame(&h, p).unwrap()
    };
    // Unknown reason strings decode as Unknown; extra fields are ignored.
    assert_eq!(
        decode(
            ty::AUTH_RESULT,
            br#"{"ok":false,"reason":"solar_flare","x":1}"#
        ),
        Message::AuthResult(AuthResult {
            ok: false,
            server_proof: None,
            reason: Some(AuthReason::Unknown),
            retry_after_ms: None,
        })
    );
    // A v1 CLIENT_HELLO (no kx) still decodes, so the phone can read `proto`
    // and answer BYE proto_mismatch instead of a decode error.
    let Message::ClientHello(ch) = decode(
        ty::CLIENT_HELLO,
        br#"{"proto":1,"clientName":"m","clientId":"c","nonceC":"00"}"#,
    ) else {
        panic!()
    };
    assert_eq!((ch.proto, ch.kx.as_str()), (1, ""));
    // v1 AUTH without pake.
    assert_eq!(
        decode(ty::AUTH, br#"{"mode":"token","proof":"ab"}"#),
        Message::Auth(Auth {
            mode: AuthMode::Token,
            proof: "ab".into(),
            pake: None,
        })
    );
}

/// `proto` that is missing or not a u32 decodes as 0 (a mismatch, answered
/// with BYE `proto_mismatch`), never as a decode error.
#[test]
fn non_u32_proto_decodes_as_a_mismatch() {
    let decode = |t: u8, p: &[u8]| {
        let h = Header {
            ty: t,
            flags: 0,
            length: p.len() as u32,
            pts_us: 0,
        };
        Message::decode_frame(&h, p)
    };
    for proto in [
        "\"2\"",
        "3.0",
        "-1",
        "4294967296",
        "null",
        "[2]",
        "{\"major\":3}",
    ] {
        let p = format!(r#"{{"proto":{proto},"clientName":"m","clientId":"c","nonceC":"00"}}"#);
        let Ok(Message::ClientHello(ch)) = decode(ty::CLIENT_HELLO, p.as_bytes()) else {
            panic!("{proto}")
        };
        assert_eq!(ch.proto, 0, "{proto}");
    }
    let Ok(Message::ClientHello(ch)) = decode(
        ty::CLIENT_HELLO,
        br#"{"clientName":"m","clientId":"c","nonceC":"00"}"#,
    ) else {
        panic!()
    };
    assert_eq!(ch.proto, 0);
    let p =
        br#"{"proto":"3","deviceName":"d","deviceId":"i","model":"m","sdkInt":35,"nonceS":"00"}"#;
    let Ok(Message::ServerHello(sh)) = decode(ty::SERVER_HELLO, p) else {
        panic!()
    };
    assert_eq!(sh.proto, 0);
    // A real u32 is kept as is.
    let Ok(Message::ClientHello(ch)) = decode(
        ty::CLIENT_HELLO,
        br#"{"proto":4294967295,"clientName":"m","clientId":"c","nonceC":"00"}"#,
    ) else {
        panic!()
    };
    assert_eq!(ch.proto, u32::MAX);
}

/// `Malformed.reason` quotes peer text (serde echoes the bad value) and is
/// logged: it must stay short and free of raw control characters.
#[test]
fn malformed_reason_is_bounded_and_escaped() {
    let hostile = "x\n[ERROR] forged\r\u{1b}[31m\u{202e}".to_string() + &"A".repeat(60_000);
    // Unknown enum strings decode as Unknown, so use a wrong type to make
    // serde quote the value: `invalid type: string "...", expected u32`.
    let p = format!(
        r#"{{"proto":2,"deviceName":{},"deviceId":"i","model":"m","sdkInt":{},"nonceS":"00"}}"#,
        serde_json::to_string("d").unwrap(),
        serde_json::to_string(&hostile).unwrap(),
    );
    let h = Header {
        ty: ty::SERVER_HELLO,
        flags: 0,
        length: p.len() as u32,
        pts_us: 0,
    };
    let Err(ProtocolError::Malformed { ty, reason }) = Message::decode_frame(&h, p.as_bytes())
    else {
        panic!("expected malformed")
    };
    assert_eq!(ty, ty::SERVER_HELLO);
    assert!(reason.starts_with("invalid type: string"), "{reason}");
    assert!(
        reason.chars().count() <= 161,
        "{} chars",
        reason.chars().count()
    );
    assert!(reason.ends_with('…'), "{reason}");
    assert!(
        !reason.chars().any(|c| c.is_control() || c == '\u{202e}'),
        "{reason:?}"
    );
    // Short, plain reasons are unchanged.
    let h = Header {
        ty: ty::PING,
        flags: 0,
        length: 2,
        pts_us: 0,
    };
    assert_eq!(
        Message::decode_frame(&h, &[0, 0]),
        Err(ProtocolError::Malformed {
            ty: ty::PING,
            reason: "expected 8 bytes, got 2".into()
        })
    );
}

// ---------------------------------------------------------------------------
// Annex-B
// ---------------------------------------------------------------------------

#[test]
fn nal_ranges_3_and_4_byte_start_codes() {
    // AUD(4-byte) SPS(4-byte) PPS(3-byte) IDR(3-byte)
    let d = [
        0, 0, 0, 1, 0x09, 0xf0, //
        0, 0, 0, 1, 0x67, 0x42, 0x00, 0x1f, //
        0, 0, 1, 0x68, 0xce, 0x38, //
        0, 0, 1, 0x65, 0x88, 0x84, 0x00, 0x21,
    ];
    let r = nal_ranges(&d);
    assert_eq!(r, vec![4..6, 10..14, 17..20, 23..28]);
    let types: Vec<_> = nals(&d).map(|n| nal_type(n).unwrap()).collect();
    assert_eq!(types, vec![9, 7, 8, 5]);
    // Embedded 00 inside a NAL payload (0x00 0x21 at end) is preserved.
    assert_eq!(&d[r[3].clone()], &[0x65, 0x88, 0x84, 0x00, 0x21]);
}

#[test]
fn nal_ranges_edge_cases() {
    assert!(nal_ranges(&[]).is_empty());
    assert!(nal_ranges(&[1, 2, 3, 4]).is_empty());
    assert!(nal_ranges(&[0, 0, 1]).is_empty()); // empty NAL dropped
                                                // Leading garbage ignored; trailing zero bytes stripped.
    let d = [0xaa, 0, 0, 1, 0x41, 0x9a, 0, 0, 0, 0, 1, 0x41, 0x9b];
    assert_eq!(nal_ranges(&d), vec![4..6, 11..13]);
    assert!(nals(&d).eq([&d[4..6], &d[11..13]]));
}

#[test]
fn avcc_conversion() {
    let d = [
        0, 0, 0, 1, 0x09, 0xf0, // AUD (dropped)
        0, 0, 0, 1, 0x67, 0x42, // SPS (dropped)
        0, 0, 1, 0x68, 0xce, // PPS (dropped)
        0, 0, 1, 0x06, 0x05, 0x01, // SEI
        0, 0, 0, 1, 0x65, 0x88, 0x84, // IDR
    ];
    assert_eq!(
        annexb_to_avcc(&d),
        vec![0, 0, 0, 3, 0x06, 0x05, 0x01, 0, 0, 0, 3, 0x65, 0x88, 0x84]
    );
    assert!(annexb_to_avcc(&[0, 0, 1, 0x67, 1]).is_empty());
}

#[test]
fn sps_pps_extraction() {
    let d = [
        0, 0, 0, 1, 0x67, 0x42, 0x00, 0x1f, 0, 0, 0, 1, 0x68, 0xce, 0x38, 0x80,
    ];
    let (sps, pps) = extract_sps_pps(&d).unwrap();
    assert_eq!(sps, vec![0x67, 0x42, 0x00, 0x1f]);
    assert_eq!(pps, vec![0x68, 0xce, 0x38, 0x80]);
    assert_eq!(extract_sps_pps(&d[..8]), None);
}

// ---------------------------------------------------------------------------
// Geometry
// ---------------------------------------------------------------------------

#[test]
fn encode_size_cases() {
    assert_eq!(encode_size(1080, 2400, 1920), (864, 1920));
    assert_eq!(encode_size(2400, 1080, 1920), (1920, 864));
    assert_eq!(encode_size(1080, 2400, 1280), (576, 1280));
    // No upscaling; flooring to 16.
    assert_eq!(encode_size(720, 1600, 1920), (720, 1600));
    assert_eq!(encode_size(1080, 2340, 1920), (880, 1920)); // 886.15 -> 886 -> 880
    assert_eq!(encode_size(1440, 3120, 1920), (880, 1920)); // 886.15
    assert_eq!(encode_size(1170, 2532, 1920), (880, 1920)); // 887.2 -> 887 -> 880
    assert_eq!(encode_size(10, 5, 1920), (16, 16)); // minimum 16
    assert_eq!(encode_size(0, 0, 1920), (16, 16));
    for (w, h) in [
        (1080, 2400),
        (1440, 3200),
        (1264, 2780),
        (1080, 1920),
        (2560, 1600),
        (999, 777),
    ] {
        let (ew, eh) = encode_size(w, h, 1920);
        assert!(ew.max(eh) <= 1920);
        assert_eq!(ew % 16, 0);
        assert_eq!(eh % 16, 0);
    }
}

#[test]
fn fit_rect_letterbox() {
    // Portrait 864x1920 video in a 1000x1000 window: pillarbox.
    let r = fit_rect(864, 1920, 1000.0, 1000.0);
    assert!((r.h - 1000.0).abs() < 1e-9);
    assert!((r.w - 450.0).abs() < 1e-9);
    assert!((r.x - 275.0).abs() < 1e-9);
    assert_eq!(r.y, 0.0);
    // Landscape video in tall window: letterbox.
    let r = fit_rect(1920, 864, 960.0, 1000.0);
    assert!((r.w - 960.0).abs() < 1e-9);
    assert!((r.h - 432.0).abs() < 1e-9);
    assert!((r.y - 284.0).abs() < 1e-9);
    assert_eq!(fit_rect(0, 10, 100.0, 100.0), Rect::default());
}

#[test]
fn view_mapping_and_letterbox_rejection() {
    let r = fit_rect(864, 1920, 1000.0, 1000.0); // x 275..725
    assert_eq!(view_to_norm(&r, 100.0, 500.0), None); // left bar
    assert_eq!(view_to_norm(&r, 900.0, 500.0), None); // right bar
    assert_eq!(view_to_norm(&r, 275.0, 0.0), Some((0, 0)));
    assert_eq!(view_to_norm(&r, 725.0, 1000.0), Some((65535, 65535)));
    assert_eq!(view_to_norm(&r, 500.0, 500.0), Some((32768, 32768)));
    assert_eq!(view_to_norm_clamped(&r, 0.0, 2000.0), Some((0, 65535)));
    assert_eq!(view_to_norm(&Rect::default(), 0.0, 0.0), None);
    // Round trip view -> norm -> view within one normalised step.
    for &(x, y) in &[(300.5, 10.25), (700.0, 999.0), (500.0, 1.0)] {
        let (nx, ny) = view_to_norm(&r, x, y).unwrap();
        let vx = r.x + nx as f64 / 65535.0 * r.w;
        let vy = r.y + ny as f64 / 65535.0 * r.h;
        assert!((vx - x).abs() <= r.w / 65535.0);
        assert!((vy - y).abs() <= r.h / 65535.0);
    }
}

/// PROTOCOL.md: `n = round(pixel × 65535 / (size − 1))` (the receiver side).
fn spec_px_to_norm(px: u32, size: u32) -> u16 {
    if size <= 1 {
        return 0;
    }
    let d = size as u64 - 1;
    ((px.min(size - 1) as u64 * 65535 + d / 2) / d) as u16
}

#[test]
fn pixel_mapping_roundtrips() {
    for size in [1u32, 2, 16, 864, 1080, 1920, 2400, 4096, 65535, 65536] {
        assert_eq!(norm_to_px(0, size), 0);
        assert_eq!(norm_to_px(65535, size), size.saturating_sub(1));
        let step = (size / 997).max(1);
        let mut p = 0;
        while p < size {
            assert_eq!(
                norm_to_px(spec_px_to_norm(p, size), size),
                p,
                "size {size} px {p}"
            );
            p += step;
        }
        assert_eq!(norm_to_px(spec_px_to_norm(size - 1, size), size), size - 1);
    }
    assert_eq!(spec_px_to_norm(5000, 1080), 65535); // clamped
                                                    // Video -> display mapping: video centre maps to display centre.
    let n = spec_px_to_norm(432, 865);
    assert_eq!(norm_to_px(n, 1081), 540);
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

#[test]
fn pin_generation() {
    let mut rng = TestRng(12345);
    let mut seen = std::collections::HashSet::new();
    for _ in 0..1000 {
        let pin = generate_pin(&mut rng);
        assert_eq!(pin.len(), PIN_DIGITS);
        assert!(pin.bytes().all(|b| b.is_ascii_digit()));
        seen.insert(pin);
    }
    assert!(seen.len() > 990);
    // Deterministic for a given RNG state.
    assert_eq!(generate_pin(&mut TestRng(7)), generate_pin(&mut TestRng(7)));
}

#[test]
fn hex_helpers() {
    assert_eq!(to_hex(&[0x00, 0xab, 0xff]), "00abff");
    assert_eq!(from_hex("00ABff"), Some(vec![0, 0xab, 0xff]));
    assert_eq!(from_hex("abc"), None);
    assert_eq!(from_hex("zz"), None);
    assert_eq!(from_hex(""), Some(vec![]));
}

// ---------------------------------------------------------------------------
// Hardening
// ---------------------------------------------------------------------------

#[test]
fn json_types_are_limited_from_header_alone() {
    let header = |ty, length| {
        Header {
            ty,
            flags: 0,
            length,
            pts_us: 0,
        }
        .encode()
    };
    let mut d = Decoder::new(false);
    d.push(&header(ty::CLIENT_HELLO, MAX_JSON_PAYLOAD + 1));
    assert_eq!(
        d.next(),
        Err(ProtocolError::PayloadTooLarge {
            len: MAX_JSON_PAYLOAD + 1,
            max: MAX_JSON_PAYLOAD
        })
    );

    let mut d = Decoder::new(false);
    d.push(&header(ty::SERVER_HELLO, MAX_JSON_PAYLOAD));
    assert_eq!(d.next(), Ok(None));

    // Binary types keep the full limit.
    let mut d = Decoder::new(false);
    d.push(&header(ty::TEXT, MAX_JSON_PAYLOAD + 1));
    assert_eq!(d.next(), Ok(None));
}

#[test]
fn max_payload_override_is_clamped_to_protocol_max() {
    let mut d = Decoder::new(false).with_max_payload(u32::MAX);
    d.push(
        &Header {
            ty: ty::VIDEO_FRAME,
            flags: 0,
            length: u32::MAX,
            pts_us: 0,
        }
        .encode(),
    );
    assert_eq!(
        d.next(),
        Err(ProtocolError::PayloadTooLarge {
            len: u32::MAX,
            max: MAX_PAYLOAD
        })
    );
}

/// Every type with every 0- and 1-byte payload, plus random payloads up to
/// 64 bytes: decoding must return, never panic.
#[test]
fn decode_frame_never_panics_on_hostile_payloads() {
    let mut rng = TestRng(0xDEAD_BEEF);
    let mut buf = [0u8; 64];
    for t in 0..=255u8 {
        let h = Header {
            ty: t,
            flags: 0xff,
            length: 0,
            pts_us: u64::MAX,
        };
        let _ = Message::decode_frame(&h, &[]);
        for b in 0..=255u8 {
            let _ = Message::decode_frame(&h, &[b]);
        }
        for _ in 0..500 {
            let n = (rand_core::Rng::next_u32(&mut rng) % 65) as usize;
            rand_core::Rng::fill_bytes(&mut rng, &mut buf[..n]);
            let _ = Message::decode_frame(&h, &buf[..n]);
        }
    }
}

/// Random byte streams (with plausible headers mixed in) fed in random chunks.
#[test]
fn decoder_never_panics_on_random_streams() {
    let mut rng = TestRng(42);
    for _ in 0..300 {
        let mut bytes = MAGIC.to_vec();
        for _ in 0..20 {
            let r = rand_core::Rng::next_u32(&mut rng);
            let len = r % 40;
            bytes.extend(
                Header {
                    ty: (r >> 8) as u8 % 0x30,
                    flags: (r >> 16) as u8,
                    length: len,
                    pts_us: 0,
                }
                .encode(),
            );
            let start = bytes.len();
            bytes.resize(start + len as usize, 0);
            rand_core::Rng::fill_bytes(&mut rng, &mut bytes[start..]);
        }
        let mut d = Decoder::new(true);
        for chunk in bytes.chunks(1 + (rand_core::Rng::next_u32(&mut rng) % 17) as usize) {
            d.push(chunk);
            while let Ok(Some(_)) | Err(ProtocolError::Malformed { .. }) = d.next() {}
        }
    }
}

/// The original eager scanner, kept as the reference for the lazy one.
fn reference_nal_ranges(d: &[u8]) -> Vec<std::ops::Range<usize>> {
    let mut out = Vec::new();
    let mut i = 0usize;
    let mut start: Option<usize> = None;
    let push = |s: usize, mut e: usize, out: &mut Vec<std::ops::Range<usize>>| {
        while e > s && d[e - 1] == 0 {
            e -= 1;
        }
        if e > s {
            out.push(s..e);
        }
    };
    while i + 3 <= d.len() {
        let sc = if d[i..].starts_with(&[0, 0, 1]) {
            3
        } else if d[i..].starts_with(&[0, 0, 0, 1]) {
            4
        } else {
            0
        };
        if sc > 0 {
            if let Some(s) = start {
                push(s, i, &mut out);
            }
            start = Some(i + sc);
            i += sc;
        } else {
            i += 1;
        }
    }
    if let Some(s) = start {
        push(s, d.len(), &mut out);
    }
    out
}

/// Exhaustive over all buffers up to 9 bytes drawn from {0, 1, 0x65}.
#[test]
fn nal_ranges_invariants_exhaustive() {
    const ALPHABET: [u8; 3] = [0, 1, 0x65];
    for len in 0..=9u32 {
        for mut code in 0..3usize.pow(len) {
            let d: Vec<u8> = (0..len)
                .map(|_| {
                    let b = ALPHABET[code % 3];
                    code /= 3;
                    b
                })
                .collect();
            let ranges = nal_ranges(&d);
            assert_eq!(ranges, reference_nal_ranges(&d), "{d:?}");
            let mut prev_end = 0;
            for r in ranges {
                assert!(r.start >= prev_end && r.start < r.end && r.end <= d.len());
                assert_ne!(d[r.end - 1], 0, "{d:?} {r:?}");
                prev_end = r.end;
            }
            let _ = annexb_to_avcc(&d);
        }
    }
}

#[test]
fn non_finite_view_sizes_give_empty_rect() {
    for (w, h) in [
        (f64::NAN, 100.0),
        (100.0, f64::NAN),
        (f64::INFINITY, 100.0),
        (100.0, f64::INFINITY),
    ] {
        assert_eq!(fit_rect(864, 1920, w, h), Rect::default());
    }
    let nan = Rect {
        x: 0.0,
        y: 0.0,
        w: f64::NAN,
        h: 100.0,
    };
    assert_eq!(view_to_norm_clamped(&nan, 10.0, 10.0), None);
    assert_eq!(view_to_norm(&nan, 10.0, 10.0), None);
}

#[test]
fn encode_size_zero_cap_means_uncapped() {
    assert_eq!(encode_size(1080, 2400, 0), (1072, 2400));
}

/// RNG that replays a fixed list of `u32`s.
struct SeqRng(Vec<u32>);
impl rand_core::TryRng for SeqRng {
    type Error = Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok(self.0.remove(0))
    }
    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        unimplemented!()
    }
    fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), Infallible> {
        unimplemented!()
    }
}
impl rand_core::TryCryptoRng for SeqRng {}

#[test]
fn generate_pin_rejection_boundary() {
    // 4_294_000_000 = 4294 * 10^6 is the first value that would bias "000000".
    let mut rng = SeqRng(vec![u32::MAX, 4_294_000_000, 4_293_999_999]);
    assert_eq!(generate_pin(&mut rng), "999999");
    let mut rng = SeqRng(vec![123]);
    assert_eq!(generate_pin(&mut rng), "000123");
}
