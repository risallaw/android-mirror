//! Record layer (PROTOCOL.md "Record layer").

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::ChaCha20Poly1305;
use mirror_protocol::auth::{from_hex, to_hex};
use mirror_protocol::secure::{Opener, Sealer, SecretKey, TAG_LEN};
use mirror_protocol::wire::{ty, Header, HEADER_LEN};
use mirror_protocol::*;

const KEY: [u8; 32] = [7; 32];

fn key() -> SecretKey {
    SecretKey::from_bytes(KEY)
}

fn pair(max: u32) -> (Sealer, Opener) {
    (Sealer::new(&key(), max), Opener::new(&key(), max))
}

fn sample() -> Vec<Message> {
    vec![
        Message::Start(Start {
            max_long_edge: Some(1920),
            max_fps: Some(60),
            bitrate: None,
        }),
        Message::RequestKeyframe,
        Message::Ping([1, 2, 3, 4, 5, 6, 7, 8]),
        Message::Text("héllo".into()),
        Message::VideoFrame(VideoFrame {
            pts_us: 42,
            flags: 1,
            data: (0..200_000u32).map(|i| i as u8).collect(),
        }),
        Message::Scroll(Scroll {
            x: 1,
            y: 2,
            dx: -3,
            dy: 4,
        }),
    ]
}

fn seal_all(s: &mut Sealer, msgs: &[Message]) -> Vec<u8> {
    let mut out = Vec::new();
    for m in msgs {
        s.seal_message(m, &mut out).unwrap();
    }
    out
}

fn drain(o: &mut Opener) -> Result<Vec<Message>, ProtocolError> {
    let mut v = Vec::new();
    while let Some(m) = o.next()? {
        v.push(m);
    }
    Ok(v)
}

/// Build a record by hand (spec formulas, independent of `Sealer`).
fn raw_record(key: &[u8; 32], seq: u64, plaintext: &[u8]) -> Vec<u8> {
    let len = ((plaintext.len() + TAG_LEN) as u32).to_be_bytes();
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&seq.to_be_bytes());
    let mut body = plaintext.to_vec();
    let tag = ChaCha20Poly1305::new(key.into())
        .encrypt_in_place_detached(&nonce.into(), &len, &mut body)
        .unwrap();
    [&len[..], &body, &tag].concat()
}

fn frame(t: u8, payload: &[u8]) -> Vec<u8> {
    let h = Header {
        ty: t,
        flags: 0,
        length: payload.len() as u32,
        pts_us: 0,
    };
    [&h.encode()[..], payload].concat()
}

// ---------------------------------------------------------------------------

#[test]
fn round_trip() {
    let (mut s, mut o) = pair(MAX_PAYLOAD);
    let msgs = sample();
    let wire = seal_all(&mut s, &msgs);
    o.push(&wire);
    assert_eq!(drain(&mut o).unwrap(), msgs);
    assert_eq!(o.buffered(), 0);
    // Ciphertext does not contain the plaintext.
    assert!(!wire
        .windows(5)
        .any(|w| w == "héllo".as_bytes()[..5].as_ref()));
}

#[test]
fn byte_at_a_time() {
    let (mut s, mut o) = pair(MAX_PAYLOAD);
    let msgs: Vec<Message> = sample()
        .into_iter()
        .filter(|m| m.ty() != ty::VIDEO_FRAME)
        .collect();
    let wire = seal_all(&mut s, &msgs);
    let mut got = Vec::new();
    for b in &wire {
        o.push(std::slice::from_ref(b));
        got.extend(drain(&mut o).unwrap());
    }
    assert_eq!(got, msgs);
}

#[test]
fn seal_frame_matches_seal_message() {
    let (mut a, _) = pair(MAX_PAYLOAD);
    let (mut b, _) = pair(MAX_PAYLOAD);
    for m in sample() {
        let mut x = Vec::new();
        let mut y = Vec::new();
        a.seal_message(&m, &mut x).unwrap();
        b.seal_frame(&encode(&m), &mut y).unwrap();
        assert_eq!(x, y);
    }
}

/// Published record vector (PROTOCOL.md): key = key_c2s of the token test
/// vector; computed with an independent pure-Python ChaCha20-Poly1305
/// (checked against RFC 8439 §2.8.2).
#[test]
fn record_test_vector() {
    let k: [u8; 32] = from_hex("cda68a732e33f6741d17ab1a16ec36d47b4769eacf97661bf620570330c619ab")
        .unwrap()
        .try_into()
        .unwrap();
    let mut s = Sealer::new(&SecretKey::from_bytes(k), MAX_CLIENT_PAYLOAD);
    let mut out = Vec::new();
    s.seal_message(&Message::RequestKeyframe, &mut out).unwrap();
    assert_eq!(
        to_hex(&out),
        "00000020fb5b75dbd30c66073ed891805848b72aa576431a7ec3b3680c3047af6db6cded"
    );
    out.clear();
    s.seal_message(&Message::Ping([1, 2, 3, 4, 5, 6, 7, 8]), &mut out)
        .unwrap();
    assert_eq!(
        to_hex(&out),
        "00000028479470c3dfdcecd54637bd01dc0db1a3f6108f95c765795417e4e7b5c0346818715c0c72adf4d1c1"
    );
}

#[test]
fn tampered_tag_body_or_length_fail() {
    let (mut s, _) = pair(MAX_PAYLOAD);
    let rec = seal_all(&mut s, &[Message::Ping([1; 8])]);
    // Every single-bit flip anywhere in the record is detected.
    for i in 0..rec.len() {
        for bit in 0..8 {
            let mut bad = rec.clone();
            bad[i] ^= 1 << bit;
            let mut o = Opener::new(&key(), MAX_PAYLOAD);
            o.push(&bad);
            // A larger tampered length waits for more bytes: supply them
            // (zeros) when within the limit, so the record is complete.
            let claimed = u32::from_be_bytes(bad[..4].try_into().unwrap()) as usize;
            if claimed + 4 > bad.len() && claimed <= 16 + MAX_PAYLOAD as usize + 16 {
                o.push(&vec![0; claimed + 4 - bad.len()]);
            }
            let r = o.next();
            assert!(
                matches!(
                    r,
                    Err(ProtocolError::BadRecord)
                        | Err(ProtocolError::RecordTooLarge { .. })
                        | Err(ProtocolError::RecordTooShort { .. })
                ),
                "byte {i} bit {bit}: {r:?}"
            );
            assert_eq!(o.next(), Err(ProtocolError::Poisoned));
        }
    }
}

#[test]
fn reordered_replayed_or_dropped_records_fail() {
    let (mut s, _) = pair(MAX_PAYLOAD);
    let mut r0 = Vec::new();
    let mut r1 = Vec::new();
    let mut r2 = Vec::new();
    s.seal_message(&Message::Ping([0; 8]), &mut r0).unwrap();
    s.seal_message(&Message::Ping([1; 8]), &mut r1).unwrap();
    s.seal_message(&Message::Ping([2; 8]), &mut r2).unwrap();

    for stream in [
        [&r1[..], &r0[..]].concat(), // reorder
        [&r0[..], &r0[..]].concat(), // replay
        [&r0[..], &r2[..]].concat(), // drop
    ] {
        let mut o = Opener::new(&key(), MAX_PAYLOAD);
        o.push(&stream);
        let first = o.next();
        let second = o.next();
        assert!(
            first == Err(ProtocolError::BadRecord) || second == Err(ProtocolError::BadRecord),
            "{first:?} {second:?}"
        );
    }
}

#[test]
fn wrong_key_or_direction_fails() {
    let mut s = Sealer::new(&key(), MAX_PAYLOAD);
    let wire = seal_all(&mut s, &[Message::RequestKeyframe]);
    let mut o = Opener::new(&SecretKey::from_bytes([8; 32]), MAX_PAYLOAD);
    o.push(&wire);
    assert_eq!(o.next(), Err(ProtocolError::BadRecord));
}

#[test]
fn oversize_length_rejected_from_prefix_alone() {
    let max = MAX_CLIENT_PAYLOAD;
    let limit = 16 + max + 16;
    for len in [limit + 1, u32::MAX, MAX_PAYLOAD + 32 + 1] {
        let mut o = Opener::new(&key(), max);
        o.push(&len.to_be_bytes());
        assert_eq!(
            o.next(),
            Err(ProtocolError::RecordTooLarge { len, max: limit }),
            "len {len}"
        );
        assert_eq!(o.next(), Err(ProtocolError::Poisoned));
    }
    // Shorter than header + tag can never be valid.
    for len in [0u32, 1, 16, 31] {
        let mut o = Opener::new(&key(), max);
        o.push(&len.to_be_bytes());
        assert_eq!(
            o.next(),
            Err(ProtocolError::RecordTooShort { len, min: 32 }),
            "len {len}"
        );
        assert_eq!(o.next(), Err(ProtocolError::Poisoned));
    }
    // Exactly at the limit: waits for the body.
    let mut o = Opener::new(&key(), max);
    o.push(&limit.to_be_bytes());
    assert_eq!(o.next(), Ok(None));
    // The limit is clamped to the protocol maximum.
    let mut o = Opener::new(&key(), u32::MAX);
    o.push(&(MAX_PAYLOAD + 33).to_be_bytes());
    assert!(matches!(
        o.next(),
        Err(ProtocolError::RecordTooLarge { .. })
    ));
}

#[test]
fn plaintext_must_be_exactly_one_frame() {
    let one = frame(ty::PING, &[1; 8]);
    let cases: Vec<Vec<u8>> = vec![
        // Header claims 8 bytes, only 7 present.
        one[..one.len() - 1].to_vec(),
        // Trailing byte after the frame.
        [&one[..], &[0]].concat(),
        // Two frames in one record.
        [&one[..], &one[..]].concat(),
    ];
    for pt in cases {
        let mut o = Opener::new(&key(), MAX_PAYLOAD);
        o.push(&raw_record(&KEY, 0, &pt));
        assert_eq!(o.next(), Err(ProtocolError::BadRecordPlaintext));
        assert_eq!(o.next(), Err(ProtocolError::Poisoned));
    }
    // Control: the hand-built record of one frame is accepted.
    let mut o = Opener::new(&key(), MAX_PAYLOAD);
    o.push(&raw_record(&KEY, 0, &one));
    assert_eq!(o.next(), Ok(Some(Message::Ping([1; 8]))));

    // The sealer refuses the same inputs and leaves `out` untouched.
    let mut s = Sealer::new(&key(), MAX_PAYLOAD);
    let mut out = vec![0xAA];
    for bad in [
        &one[..one.len() - 1],
        &[&one[..], &one[..]].concat()[..],
        &one[..10],
        &[][..],
    ] {
        assert_eq!(
            s.seal_frame(bad, &mut out),
            Err(ProtocolError::BadRecordPlaintext)
        );
        assert_eq!(out, [0xAA]);
    }
    // ...and its sequence number did not advance: the next record is seq 0.
    s.seal_frame(&one, &mut out).unwrap();
    o = Opener::new(&key(), MAX_PAYLOAD);
    o.push(&out[1..]);
    assert_eq!(o.next(), Ok(Some(Message::Ping([1; 8]))));
}

#[test]
fn frame_limits_apply_inside_records() {
    // JSON types keep their 64 KiB cap even in an 8 MiB direction.
    let big_json = frame(ty::STATUS, &vec![b' '; MAX_JSON_PAYLOAD as usize + 1]);
    let mut o = Opener::new(&key(), MAX_PAYLOAD);
    o.push(&raw_record(&KEY, 0, &big_json));
    assert_eq!(
        o.next(),
        Err(ProtocolError::PayloadTooLarge {
            len: MAX_JSON_PAYLOAD + 1,
            max: MAX_JSON_PAYLOAD
        })
    );
    // The sealer refuses frames over the peer's limit (nothing appended).
    let mut s = Sealer::new(&key(), MAX_CLIENT_PAYLOAD);
    let mut out = Vec::new();
    let text = Message::Text("x".repeat(MAX_CLIENT_PAYLOAD as usize + 1));
    assert!(matches!(
        s.seal_message(&text, &mut out),
        Err(ProtocolError::PayloadTooLarge { .. })
    ));
    assert!(out.is_empty());
    let text = Message::Text("x".repeat(MAX_CLIENT_PAYLOAD as usize));
    s.seal_message(&text, &mut out).unwrap();
    let mut o = Opener::new(&key(), MAX_CLIENT_PAYLOAD);
    o.push(&out);
    assert_eq!(o.next(), Ok(Some(text)));
}

#[test]
fn malformed_payload_in_authentic_record_is_recoverable() {
    let mut wire = raw_record(&KEY, 0, &frame(ty::STATUS, b"{not json"));
    let mut s = Sealer::new(&key(), MAX_PAYLOAD);
    // Continue the sequence at 1 with the real sealer: seal and discard one record.
    s.seal_message(&Message::RequestKeyframe, &mut Vec::new())
        .unwrap();
    s.seal_message(&Message::Ping([3; 8]), &mut wire).unwrap();
    let mut o = Opener::new(&key(), MAX_PAYLOAD);
    o.push(&wire);
    let e = o.next().unwrap_err();
    assert!(!e.is_fatal(), "{e:?}");
    assert_eq!(o.next(), Ok(Some(Message::Ping([3; 8]))));
}

#[test]
fn record_errors_are_fatal() {
    for e in [
        ProtocolError::BadRecord,
        ProtocolError::BadRecordPlaintext,
        ProtocolError::SeqExhausted,
        ProtocolError::RecordTooLarge { len: 1, max: 0 },
        ProtocolError::RecordTooShort { len: 1, min: 32 },
    ] {
        assert!(e.is_fatal());
    }
}

/// The plaintext decoder hands over bytes that already belong to the record
/// stream (a client that sends START right behind AUTH).
#[test]
fn decoder_hands_over_buffered_record_bytes() {
    let (mut s, mut o) = pair(MAX_CLIENT_PAYLOAD);
    let mut wire = MAGIC.to_vec();
    wire.extend(encode(&Message::Auth(Auth {
        mode: AuthMode::Token,
        proof: "00".into(),
        pake: None,
    })));
    s.seal_message(&Message::Start(Start::default()), &mut wire)
        .unwrap();
    let mut d = Decoder::new(true);
    d.push(&wire);
    assert!(matches!(d.next(), Ok(Some(Message::Auth(_)))));
    let rest = d.take_buffered();
    assert_eq!(d.buffered(), 0);
    o.push(&rest);
    assert_eq!(o.next(), Ok(Some(Message::Start(Start::default()))));
    // The decoder still works for later plaintext (not used in practice).
    d.push(&encode(&Message::RequestKeyframe));
    assert_eq!(d.next(), Ok(Some(Message::RequestKeyframe)));
}

#[test]
fn header_len_constant() {
    assert_eq!(HEADER_LEN, 16);
    assert_eq!(TAG_LEN, 16);
}
