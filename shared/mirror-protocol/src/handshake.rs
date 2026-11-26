//! Sans-IO protocol v2 handshake: X25519 key agreement plus `token`
//! (stored pairing key) or `pin` (SPAKE2) authentication, ending in the
//! per-direction session keys for the [record layer](crate::secure).
//!
//! ```text
//! lp(x)  = u16_be(len(x)) || x
//! ls(xs) = lp(x1) || lp(x2) || … || lp(xn)                  (empty list: empty string)
//! ctx    = lp("amr2") || lp(nonceC) || lp(nonceS) || lp(kxC) || lp(kxS)
//!          || lp(clientId) || lp(deviceId) || lp(mode)
//!          || lp(clientName) || lp(deviceName) || lp(model)
//!          || lp(ls(authModes)) || lp(ls(caps))
//! th     = SHA-256(ctx)
//! dh     = X25519(own secret, peer kx)                       (all-zero rejected)
//!
//! token: K = PK;  clientProof = HMAC(K, lp("C") || lp(th));  serverProof = HMAC(K, lp("S") || lp(th));  thF = th
//! pin:   Kp = SPAKE2 key (Ed25519 group; A = client, B = phone;
//!             password = "androidmirror-pin" || PIN, idA = clientId, idB = deviceId)
//!        thP = SHA-256(ctx || lp(msgA) || lp(msgB))
//!        serverConfirm = HMAC(Kp, lp("S") || lp(thP));  clientConfirm = HMAC(Kp, lp("C") || lp(thP))
//!        K = Kp;  thF = thP;  new PK = HKDF-SHA256(salt = thP, ikm = Kp, info = "amr2 pairing key", 32)
//! none:  K = 32 zero bytes;  thF = th
//!
//! PRK = HKDF-Extract(salt = K, ikm = dh)
//! OKM = HKDF-Expand(PRK, info = "amr2 session keys" || thF, 64);  key_c2s = OKM[..32], key_s2c = OKM[32..]
//! ```
//!
//! Why this shape:
//! - The ephemeral X25519 secret gives every session fresh keys (forward
//!   secrecy) and `K` makes them depend on the authentication secret, so a
//!   MITM that cannot authenticate cannot derive them either.
//! - `th` binds everything both sides said, *including the mode*: a relay that
//!   rewrites a nonce, a key share, an id, a name, the offered modes or caps,
//!   or downgrades the mode gets proofs and session keys that do not match.
//!   Lists are bound item by item in the order sent (`authModes`: only the
//!   v2 modes `pin`/`token`/`none`, as their wire strings; an entry this
//!   version does not know is skipped on both sides). `proto`, `sdkInt` and
//!   `codecs` are not bound.
//! - SPAKE2 lets a 6-digit PIN authenticate without exposing it to offline
//!   guessing: a sniffer learns nothing, an active attacker gets one online
//!   guess per connection (the phone rate-limits those).
//!
//! # Usage
//!
//! Both sides are linear: each step consumes the previous state, so a step
//! cannot be skipped or repeated. Transport is up to the caller (plaintext
//! frames via [`encode`](crate::encode) / [`Decoder`](crate::Decoder)).
//!
//! ```
//! use mirror_protocol::auth::PairingKey;
//! use mirror_protocol::handshake::*;
//! use mirror_protocol::{AuthMode, Message, ServerHello};
//!
//! // Client (receiver): CLIENT_HELLO.
//! let (client, client_hello) = ClientHandshake::new("MacBook", "mac-1").unwrap();
//!
//! // Server (phone): validate CLIENT_HELLO, fill the nonce/kx into SERVER_HELLO.
//! let template = ServerHello {
//!     proto: 0, // filled in
//!     device_name: "Pixel".into(),
//!     device_id: "pixel-1".into(),
//!     model: "Pixel 8".into(),
//!     sdk_int: 35,
//!     codecs: vec!["h264".into()],
//!     caps: vec![],
//!     auth_modes: vec![AuthMode::Pin, AuthMode::Token],
//!     nonce_s: String::new(), // filled in
//!     kx: String::new(),      // filled in
//! };
//! let (server, server_hello) = ServerHandshake::new(&client_hello, template).unwrap();
//!
//! // Client: pick credentials (a PIN the user supplied, else the key stored
//! // for server_hello.device_id).
//! let (auth, mut wait) = client
//!     .authenticate(&server_hello, ClientCredential::Pin("123456".into()))
//!     .unwrap();
//! let Message::Auth(auth) = auth else { unreachable!() };
//!
//! // Server: dispatch on auth.mode (lockout / key lookup is the caller's policy).
//! let ServerStep::Continue { reply, wait: server_wait } = server.start_pin(&auth, "123456") else {
//!     panic!("rejected")
//! };
//!
//! // Client: feed every received message until Done.
//! let confirm = match wait.on_message(&reply).unwrap() {
//!     ClientStep::Send(m, next) => { wait = next; m }
//!     ClientStep::Done(_) => unreachable!(),
//! };
//! let Message::AuthConfirm(confirm) = confirm else { unreachable!() };
//! let ServerStep::Accept { reply, session: server_session } = server_wait.on_confirm(&confirm) else {
//!     panic!("rejected")
//! };
//! let ClientStep::Done(client_session) = wait.on_message(&reply).unwrap() else { panic!() };
//!
//! // Both store the new pairing key and switch to records.
//! assert_eq!(client_session.pairing_key, server_session.pairing_key);
//! let (mut client_tx, _client_rx) = client_session.keys.client_channel();
//! let (_server_tx, mut server_rx) = server_session.keys.server_channel();
//! let mut wire = Vec::new();
//! client_tx.seal_message(&Message::RequestKeyframe, &mut wire).unwrap();
//! server_rx.push(&wire);
//! assert_eq!(server_rx.next().unwrap(), Some(Message::RequestKeyframe));
//! ```
//!
//! Switching to records: the server's last plaintext frame is AUTH_RESULT,
//! the client's is AUTH (token/none) or AUTH_CONFIRM (pin). Bytes the
//! plaintext [`Decoder`](crate::Decoder) already buffered past that frame
//! belong to the record stream: move them over with
//! [`Decoder::take_buffered`](crate::Decoder::take_buffered).

use std::fmt;

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use spake2::{Ed25519Group, Identity, Password, Spake2};
use thiserror::Error;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::auth::{ct_eq, from_hex, to_hex, Nonce, PairingKey, KEY_LEN, PIN_KEY_PREFIX};
use crate::messages::{
    Auth, AuthConfirm, AuthMode, AuthReason, AuthResult, ClientHello, Message, PakeReply,
    ServerHello,
};
use crate::secure::{Opener, Sealer, SecretKey};
use crate::wire::{MAX_CLIENT_PAYLOAD, MAX_PAYLOAD, PROTO_VERSION};

type HmacSha256 = Hmac<Sha256>;

/// X25519 public key / secret length.
pub const KX_LEN: usize = 32;

const CTX_LABEL: &[u8] = b"amr2";
const SESSION_INFO: &[u8] = b"amr2 session keys";
const PAIRING_INFO: &[u8] = b"amr2 pairing key";

/// Why a handshake step failed.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum HandshakeError {
    /// The peer's `proto` is not [`PROTO_VERSION`]. The server answers with
    /// BYE `proto_mismatch`.
    #[error("peer speaks protocol {0}, expected {PROTO_VERSION}")]
    ProtoMismatch(u32),
    /// A hello / auth field is missing, not hex, the wrong length, or a
    /// bound hello field (id, name, model, `authModes`/`caps` encoding) is
    /// longer than 65535 bytes.
    #[error("bad handshake field: {0}")]
    BadField(&'static str),
    /// The X25519 result was all zeros (the peer sent a low-order key).
    #[error("key exchange produced an all-zero shared secret")]
    WeakKeyExchange,
    /// The client chose a mode the server did not list in `authModes`.
    #[error("server does not offer auth mode {0:?}")]
    ModeNotOffered(AuthMode),
    /// The server refused (AUTH_RESULT `ok:false`). In token mode,
    /// `unknown_client`/`bad_proof` mean the phone no longer accepts the
    /// stored key. The refusal is unauthenticated: ask for a PIN, but do not
    /// delete the key on its say-so (a PIN pairing replaces it).
    #[error("authentication refused: {reason:?}")]
    Rejected {
        reason: AuthReason,
        retry_after_ms: Option<u64>,
    },
    /// Token mode: the server could not prove it holds the pairing key
    /// ("device identity changed").
    #[error("server proof mismatch (device identity changed?)")]
    ServerProofMismatch,
    /// PIN mode: the server's confirmation did not verify, i.e. the PIN was
    /// wrong (or someone in the middle does not know it).
    #[error("wrong PIN")]
    WrongPin,
    /// A message that has no place at this point of the handshake.
    #[error("unexpected message type 0x{0:02x} during the handshake")]
    Unexpected(u8),
    /// The OS random number generator failed.
    #[error("random number generator failed: {0}")]
    Rng(String),
}

// ---------------------------------------------------------------------------
// Keys and results
// ---------------------------------------------------------------------------

/// The two direction keys of one session. Zeroized on drop; `Debug` redacted.
#[derive(Debug, Clone)]
pub struct SessionKeys {
    c2s: SecretKey,
    s2c: SecretKey,
}

impl SessionKeys {
    /// Receiver (client) -> phone key.
    pub fn c2s(&self) -> &[u8; 32] {
        self.c2s.as_bytes()
    }
    /// Phone (server) -> receiver key.
    pub fn s2c(&self) -> &[u8; 32] {
        self.s2c.as_bytes()
    }
    /// Client side: `(sealer, opener)` with the protocol's direction limits
    /// (sends at most [`MAX_CLIENT_PAYLOAD`], receives up to [`MAX_PAYLOAD`]).
    pub fn client_channel(&self) -> (Sealer, Opener) {
        (
            Sealer::new(&self.c2s, MAX_CLIENT_PAYLOAD),
            Opener::new(&self.s2c, MAX_PAYLOAD),
        )
    }
    /// Server side: `(sealer, opener)` with the protocol's direction limits
    /// (sends up to [`MAX_PAYLOAD`], receives at most [`MAX_CLIENT_PAYLOAD`]).
    pub fn server_channel(&self) -> (Sealer, Opener) {
        (
            Sealer::new(&self.s2c, MAX_PAYLOAD),
            Opener::new(&self.c2s, MAX_CLIENT_PAYLOAD),
        )
    }
}

/// A completed handshake.
#[derive(Debug)]
pub struct Established {
    /// The mode that authenticated this session. Control must be refused for
    /// [`AuthMode::NoAuth`].
    pub mode: AuthMode,
    pub keys: SessionKeys,
    /// PIN mode only: the new pairing key to store (phone: by `clientId`,
    /// receiver: by `deviceId`), replacing any previous one.
    pub pairing_key: Option<PairingKey>,
    /// The final transcript hash `thF` (public; identical on both sides).
    pub transcript_hash: [u8; 32],
}

// ---------------------------------------------------------------------------
// Transcript and key schedule
// ---------------------------------------------------------------------------

/// The text fields of the two hellos that are bound into `ctx`.
struct HelloText<'a> {
    client_id: &'a str,
    device_id: &'a str,
    client_name: &'a str,
    device_name: &'a str,
    model: &'a str,
    auth_modes: &'a [AuthMode],
    caps: &'a [String],
}

/// Everything the two hellos agreed on, plus the DH result.
struct Hellos {
    nonce_c: Nonce,
    nonce_s: Nonce,
    kx_c: [u8; KX_LEN],
    kx_s: [u8; KX_LEN],
    client_id: String,
    device_id: String,
    /// `lp(clientName) || lp(deviceName) || lp(model) || lp(ls(authModes))
    /// || lp(ls(caps))`, the tail of `ctx` after the mode.
    tail: Vec<u8>,
    dh: SharedSecret, // zeroized on drop
}

impl Hellos {
    fn new(
        nonce_c: Nonce,
        nonce_s: Nonce,
        kx_c: [u8; KX_LEN],
        kx_s: [u8; KX_LEN],
        text: HelloText<'_>,
        dh: SharedSecret,
    ) -> Result<Self, HandshakeError> {
        // Every field is length-prefixed with a u16: reject, never truncate.
        check_len(text.client_id, "clientId too long")?;
        check_len(text.device_id, "deviceId too long")?;
        let modes = ls(text.auth_modes.iter().filter_map(|m| m.as_str()))
            .ok_or(HandshakeError::BadField("authModes too long"))?;
        let caps = ls(text.caps.iter().map(String::as_str))
            .ok_or(HandshakeError::BadField("caps too long"))?;
        let mut tail = Vec::with_capacity(
            10 + text.client_name.len()
                + text.device_name.len()
                + text.model.len()
                + modes.len()
                + caps.len(),
        );
        for (f, what) in [
            (text.client_name.as_bytes(), "clientName too long"),
            (text.device_name.as_bytes(), "deviceName too long"),
            (text.model.as_bytes(), "model too long"),
        ] {
            check_len(f, what)?;
            lp(&mut tail, f);
        }
        // `ls` already bounded both to one `lp()`.
        lp(&mut tail, &modes);
        lp(&mut tail, &caps);
        // An all-zero result means the peer's key was a low-order point: the
        // "shared" secret would be known to anyone.
        if !dh.was_contributory() {
            return Err(HandshakeError::WeakKeyExchange);
        }
        Ok(Hellos {
            nonce_c,
            nonce_s,
            kx_c,
            kx_s,
            client_id: text.client_id.to_owned(),
            device_id: text.device_id.to_owned(),
            tail,
            dh,
        })
    }

    /// `ctx` for `mode` (see module docs).
    fn ctx(&self, mode: AuthMode) -> Vec<u8> {
        let mode = mode.as_str().expect("only known modes are negotiated");
        let mut c = Vec::with_capacity(256 + self.tail.len());
        for f in [
            CTX_LABEL,
            &self.nonce_c,
            &self.nonce_s,
            &self.kx_c,
            &self.kx_s,
            self.client_id.as_bytes(),
            self.device_id.as_bytes(),
            mode.as_bytes(),
        ] {
            lp(&mut c, f);
        }
        c.extend_from_slice(&self.tail);
        c
    }

    /// `PRK = HKDF-Extract(salt = K, ikm = dh)`,
    /// `OKM = HKDF-Expand(PRK, "amr2 session keys" || thF, 64)`.
    fn session_keys(&self, k: &[u8; KEY_LEN], th_f: &[u8; 32]) -> SessionKeys {
        let hk = Hkdf::<Sha256>::new(Some(k), self.dh.as_bytes());
        let mut okm = Zeroizing::new([0u8; 64]);
        hk.expand_multi_info(&[SESSION_INFO, th_f], &mut okm[..])
            .expect("64 bytes is a valid HKDF-SHA256 output length");
        // Copy straight into the zeroizing key types: no plain stack copy.
        let mut keys = SessionKeys {
            c2s: SecretKey::from_bytes([0; 32]),
            s2c: SecretKey::from_bytes([0; 32]),
        };
        keys.c2s.0.copy_from_slice(&okm[..32]);
        keys.s2c.0.copy_from_slice(&okm[32..]);
        keys
    }
}

/// Append `u16_be(len(x)) || x`. Callers guarantee `x.len() <= u16::MAX`
/// (hello text is checked in [`Hellos::new`], everything else is fixed-size).
fn lp(out: &mut Vec<u8>, x: &[u8]) {
    let len = u16::try_from(x.len()).expect("field length checked by caller");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(x);
}

fn check_len(x: impl AsRef<[u8]>, what: &'static str) -> Result<(), HandshakeError> {
    if x.as_ref().len() > u16::MAX as usize {
        return Err(HandshakeError::BadField(what));
    }
    Ok(())
}

/// `ls(xs) = lp(x1) || … || lp(xn)`: a list as length-prefixed items, so
/// item boundaries are unambiguous whatever the items contain. `None` if the
/// encoding would not fit in one `lp()` (65535 bytes).
fn ls<'a>(items: impl Iterator<Item = &'a str>) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    for x in items {
        if out.len() + 2 + x.len() > u16::MAX as usize {
            return None;
        }
        lp(&mut out, x.as_bytes());
    }
    Some(out)
}

fn sha256(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

/// `HMAC-SHA256(key, lp(label) || lp(th))`: proofs/confirmations. The
/// label ("C"/"S") makes the two directions' values distinct so neither can
/// be reflected back.
fn mac(key: &[u8], label: &[u8], th: &[u8; 32]) -> [u8; 32] {
    let mut m = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    let mut msg = Vec::with_capacity(4 + label.len() + 32);
    lp(&mut msg, label);
    lp(&mut msg, th);
    m.update(&msg);
    m.finalize().into_bytes().into()
}

/// Constant-time check of a hex-encoded proof against the expected value.
fn proof_matches(expected: &[u8; 32], got_hex: &str) -> bool {
    from_hex(got_hex).is_some_and(|got| ct_eq(expected, &got))
}

fn parse32(s: &str, what: &'static str) -> Result<[u8; 32], HandshakeError> {
    from_hex(s)
        .and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok())
        .ok_or(HandshakeError::BadField(what))
}

fn random32() -> Result<[u8; 32], HandshakeError> {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).map_err(|e| HandshakeError::Rng(e.to_string()))?;
    Ok(b)
}

/// A fresh X25519 secret, generated in place in its zeroizing wrapper.
fn random_secret() -> Result<Zeroizing<[u8; KX_LEN]>, HandshakeError> {
    let mut b = Zeroizing::new([0u8; KX_LEN]);
    getrandom::fill(&mut b[..]).map_err(|e| HandshakeError::Rng(e.to_string()))?;
    Ok(b)
}

/// SPAKE2 password: `"androidmirror-pin" || PIN`.
fn pin_password(pin: &str) -> Password {
    let mut pw = Zeroizing::new(Vec::with_capacity(PIN_KEY_PREFIX.len() + pin.len()));
    pw.extend_from_slice(PIN_KEY_PREFIX);
    pw.extend_from_slice(pin.as_bytes());
    Password::new(&pw[..])
}

/// `thP = SHA-256(ctx || lp(msgA) || lp(msgB))`.
fn pin_transcript(ctx: &[u8], msg_a: &[u8], msg_b: &[u8]) -> [u8; 32] {
    let mut t = ctx.to_vec();
    lp(&mut t, msg_a);
    lp(&mut t, msg_b);
    sha256(&t)
}

/// `new PK = HKDF-SHA256(salt = thP, ikm = Kp, info = "amr2 pairing key", 32)`.
fn new_pairing_key(kp: &[u8; 32], th_p: &[u8; 32]) -> PairingKey {
    // Expand straight into the zeroizing key: no plain stack copy.
    let mut pk = PairingKey::from_bytes([0; KEY_LEN]);
    Hkdf::<Sha256>::new(Some(th_p), kp)
        .expand(PAIRING_INFO, pk.as_mut_bytes())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    pk
}

/// The SPAKE2 key as a fixed-size, zeroizing array.
fn spake_key(k: Vec<u8>) -> Result<Zeroizing<[u8; 32]>, HandshakeError> {
    let k = Zeroizing::new(k);
    let mut arr = Zeroizing::new([0u8; 32]);
    if k.len() != arr.len() {
        return Err(HandshakeError::BadField("pake"));
    }
    arr.copy_from_slice(&k);
    Ok(arr)
}

const ZERO_KEY: [u8; KEY_LEN] = [0; KEY_LEN];

// ---------------------------------------------------------------------------
// Client (receiver)
// ---------------------------------------------------------------------------

/// What the client authenticates with. `Debug` is redacted; the PIN and key
/// are zeroized on drop.
pub enum ClientCredential {
    /// The pairing key stored for this `deviceId`.
    Token(PairingKey),
    /// The PIN shown on the phone (pairing; yields a new pairing key).
    Pin(String),
    /// No authentication. Only if the caller's config explicitly allows it.
    NoAuth,
}

impl ClientCredential {
    pub fn mode(&self) -> AuthMode {
        match self {
            ClientCredential::Token(_) => AuthMode::Token,
            ClientCredential::Pin(_) => AuthMode::Pin,
            ClientCredential::NoAuth => AuthMode::NoAuth,
        }
    }
}

impl Drop for ClientCredential {
    fn drop(&mut self) {
        // PairingKey zeroizes itself.
        if let ClientCredential::Pin(pin) = self {
            pin.zeroize();
        }
    }
}

impl fmt::Debug for ClientCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ClientCredential::{:?}(<redacted>)", self.mode())
    }
}

/// Client state after sending CLIENT_HELLO.
pub struct ClientHandshake {
    client_name: String,
    client_id: String,
    nonce_c: Nonce,
    secret: StaticSecret, // zeroized on drop
    kx_c: [u8; KX_LEN],
}

impl fmt::Debug for ClientHandshake {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientHandshake")
            .field("client_id", &self.client_id)
            .finish_non_exhaustive()
    }
}

impl ClientHandshake {
    /// Fresh nonce and X25519 key from the OS RNG. Send the returned
    /// CLIENT_HELLO (after the `AMR1` magic).
    pub fn new(client_name: &str, client_id: &str) -> Result<(Self, ClientHello), HandshakeError> {
        Ok(Self::from_secrets(
            client_name,
            client_id,
            random32()?,
            random_secret()?,
        ))
    }

    /// Deterministic variant of [`new`](Self::new), for test vectors only:
    /// reusing a nonce or secret across connections breaks forward secrecy.
    /// Only built with the `test-vectors` feature.
    #[cfg(feature = "test-vectors")]
    #[doc(hidden)]
    pub fn with_secrets(
        client_name: &str,
        client_id: &str,
        nonce_c: Nonce,
        kx_secret: Zeroizing<[u8; KX_LEN]>,
    ) -> (Self, ClientHello) {
        Self::from_secrets(client_name, client_id, nonce_c, kx_secret)
    }

    fn from_secrets(
        client_name: &str,
        client_id: &str,
        nonce_c: Nonce,
        kx_secret: Zeroizing<[u8; KX_LEN]>,
    ) -> (Self, ClientHello) {
        let secret = StaticSecret::from(*kx_secret);
        let kx_c = PublicKey::from(&secret).to_bytes();
        let hello = ClientHello {
            proto: PROTO_VERSION,
            client_name: client_name.to_owned(),
            client_id: client_id.to_owned(),
            nonce_c: to_hex(&nonce_c),
            kx: to_hex(&kx_c),
        };
        let hs = ClientHandshake {
            client_name: client_name.to_owned(),
            client_id: client_id.to_owned(),
            nonce_c,
            secret,
            kx_c,
        };
        (hs, hello)
    }

    /// Process SERVER_HELLO and produce AUTH ([`Message::Auth`]) to send.
    ///
    /// Policy (the caller's): `Pin` if offered and the user supplied a PIN
    /// for this attempt (it wins over a stored key, for re-pairing), else
    /// `Token` if a key is stored for `server_hello.device_id` (otherwise
    /// close and ask the user for the PIN), `NoAuth` only when explicitly
    /// allowed. Errors: `ProtoMismatch`, `ModeNotOffered`, `BadField`,
    /// `WeakKeyExchange`, `Rng`.
    pub fn authenticate(
        self,
        server_hello: &ServerHello,
        mut credential: ClientCredential,
    ) -> Result<(Message, ClientWait), HandshakeError> {
        let sh = server_hello;
        if sh.proto != PROTO_VERSION {
            return Err(HandshakeError::ProtoMismatch(sh.proto));
        }
        let mode = credential.mode();
        if !sh.auth_modes.contains(&mode) {
            return Err(HandshakeError::ModeNotOffered(mode));
        }
        let nonce_s = parse32(&sh.nonce_s, "nonceS")?;
        let kx_s = parse32(&sh.kx, "kx")?;
        let dh = self.secret.diffie_hellman(&PublicKey::from(kx_s));
        let hellos = Hellos::new(
            self.nonce_c,
            nonce_s,
            self.kx_c,
            kx_s,
            HelloText {
                client_id: &self.client_id,
                device_id: &sh.device_id,
                client_name: &self.client_name,
                device_name: &sh.device_name,
                model: &sh.model,
                auth_modes: &sh.auth_modes,
                caps: &sh.caps,
            },
            dh,
        )?;
        let ctx = hellos.ctx(mode);
        // The PIN is taken out below; `credential` wipes itself on drop.
        let (auth, state) = match &mut credential {
            ClientCredential::Token(pk) => {
                let pk = pk.clone();
                let th = sha256(&ctx);
                let proof = mac(pk.as_bytes(), b"C", &th);
                let auth = Auth {
                    mode,
                    proof: to_hex(&proof),
                    pake: None,
                };
                (auth, Wait::Token { pk, th })
            }
            ClientCredential::Pin(pin) => {
                let pin = Zeroizing::new(std::mem::take(pin));
                let (spake, msg_a) = Spake2::<Ed25519Group>::start_a(
                    &pin_password(&pin),
                    &Identity::new(hellos.client_id.as_bytes()),
                    &Identity::new(hellos.device_id.as_bytes()),
                );
                let auth = Auth {
                    mode,
                    proof: String::new(),
                    pake: Some(to_hex(&msg_a)),
                };
                (
                    auth,
                    Wait::PinReply {
                        spake: Box::new(spake),
                        ctx,
                        msg_a,
                    },
                )
            }
            ClientCredential::NoAuth => {
                let auth = Auth {
                    mode,
                    proof: String::new(),
                    pake: None,
                };
                (auth, Wait::NoAuth { th: sha256(&ctx) })
            }
        };
        Ok((
            Message::Auth(auth),
            ClientWait {
                hellos: Box::new(hellos),
                state,
            },
        ))
    }
}

/// Client state after sending AUTH: feed it every received message.
pub struct ClientWait {
    // Boxed: keeps `ClientStep` small (clippy::large_enum_variant).
    hellos: Box<Hellos>,
    state: Wait,
}

enum Wait {
    Token {
        pk: PairingKey,
        th: [u8; 32],
    },
    PinReply {
        spake: Box<Spake2<Ed25519Group>>,
        ctx: Vec<u8>,
        msg_a: Vec<u8>,
    },
    PinResult {
        kp: Zeroizing<[u8; 32]>,
        th_p: [u8; 32],
    },
    NoAuth {
        th: [u8; 32],
    },
}

impl fmt::Debug for ClientWait {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = match self.state {
            Wait::Token { .. } => "token",
            Wait::PinReply { .. } => "pin: waiting for PAKE_REPLY",
            Wait::PinResult { .. } => "pin: waiting for AUTH_RESULT",
            Wait::NoAuth { .. } => "none",
        };
        f.debug_struct("ClientWait")
            .field("state", &state)
            .finish_non_exhaustive()
    }
}

/// What the client does next.
#[derive(Debug)]
pub enum ClientStep {
    /// Send this message (AUTH_CONFIRM, plaintext), keep feeding the new state.
    Send(Message, ClientWait),
    /// Authenticated. Switch to the record layer (START is the first record).
    Done(Established),
}

impl ClientWait {
    /// Process one message from the server.
    ///
    /// Errors: `Rejected` (AUTH_RESULT `ok:false`; the server then sends BYE
    /// `auth_failed`), `ServerProofMismatch` (token), `WrongPin` (pin),
    /// `BadField`, `Unexpected`. On any error, close the connection.
    pub fn on_message(self, msg: &Message) -> Result<ClientStep, HandshakeError> {
        if let Message::AuthResult(r) = msg {
            if !r.ok {
                return Err(HandshakeError::Rejected {
                    reason: r.reason.unwrap_or(AuthReason::Unknown),
                    retry_after_ms: r.retry_after_ms,
                });
            }
        }
        let ClientWait { hellos, state } = self;
        match (state, msg) {
            (Wait::Token { pk, th }, Message::AuthResult(r)) => {
                // Only the holder of PK can produce this: it authenticates the phone.
                let expected = mac(pk.as_bytes(), b"S", &th);
                let ok = r
                    .server_proof
                    .as_deref()
                    .is_some_and(|p| proof_matches(&expected, p));
                if !ok {
                    return Err(HandshakeError::ServerProofMismatch);
                }
                Ok(ClientStep::Done(Established {
                    mode: AuthMode::Token,
                    keys: hellos.session_keys(pk.as_bytes(), &th),
                    pairing_key: None,
                    transcript_hash: th,
                }))
            }
            (Wait::PinReply { spake, ctx, msg_a }, Message::PakeReply(reply)) => {
                let msg_b = from_hex(&reply.pake).ok_or(HandshakeError::BadField("pake"))?;
                // A wrong PIN still "finishes" with a different key; only a
                // malformed message errors here.
                let kp = spake_key(
                    spake
                        .finish(&msg_b)
                        .map_err(|_| HandshakeError::BadField("pake"))?,
                )?;
                let th_p = pin_transcript(&ctx, &msg_a, &msg_b);
                // Check the server's confirmation before revealing ours, so a
                // fake phone learns nothing it could test PIN guesses against.
                if !proof_matches(&mac(&kp[..], b"S", &th_p), &reply.server_proof) {
                    return Err(HandshakeError::WrongPin);
                }
                let confirm = AuthConfirm {
                    proof: to_hex(&mac(&kp[..], b"C", &th_p)),
                };
                Ok(ClientStep::Send(
                    Message::AuthConfirm(confirm),
                    ClientWait {
                        hellos,
                        state: Wait::PinResult { kp, th_p },
                    },
                ))
            }
            (Wait::PinResult { kp, th_p }, Message::AuthResult(_)) => {
                Ok(ClientStep::Done(Established {
                    mode: AuthMode::Pin,
                    keys: hellos.session_keys(&kp, &th_p),
                    pairing_key: Some(new_pairing_key(&kp, &th_p)),
                    transcript_hash: th_p,
                }))
            }
            (Wait::NoAuth { th }, Message::AuthResult(_)) => Ok(ClientStep::Done(Established {
                mode: AuthMode::NoAuth,
                keys: hellos.session_keys(&ZERO_KEY, &th),
                pairing_key: None,
                transcript_hash: th,
            })),
            (_, other) => Err(HandshakeError::Unexpected(other.ty())),
        }
    }
}

// ---------------------------------------------------------------------------
// Server (phone)
// ---------------------------------------------------------------------------

/// Server state after receiving CLIENT_HELLO and sending SERVER_HELLO.
pub struct ServerHandshake {
    hellos: Hellos,
}

impl fmt::Debug for ServerHandshake {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerHandshake")
            .field("client_id", &self.hellos.client_id)
            .finish_non_exhaustive()
    }
}

/// What the server does next.
#[derive(Debug)]
pub enum ServerStep {
    /// Send `reply` (AUTH_RESULT `ok:true`, the last plaintext frame), then
    /// switch to the record layer.
    Accept {
        reply: Message,
        session: Established,
    },
    /// Send `reply` (PAKE_REPLY), read AUTH_CONFIRM, call
    /// [`ServerPinWait::on_confirm`].
    Continue { reply: Message, wait: ServerPinWait },
    /// Send `reply` (AUTH_RESULT `ok:false`), then BYE `auth_failed`, close.
    Reject { reply: Message, reason: AuthReason },
}

impl ServerHandshake {
    /// Validate CLIENT_HELLO and complete `hello` (its `proto`, `nonce_s` and
    /// `kx` are overwritten; its ids, names, model, `auth_modes` and `caps`
    /// are bound into the proofs, so send it unchanged).
    /// Send the returned SERVER_HELLO.
    ///
    /// Errors: `ProtoMismatch` (send BYE `proto_mismatch`), `BadField`,
    /// `WeakKeyExchange`, `Rng` (close).
    pub fn new(
        client_hello: &ClientHello,
        hello: ServerHello,
    ) -> Result<(Self, ServerHello), HandshakeError> {
        Self::from_secrets(client_hello, hello, random32()?, random_secret()?)
    }

    /// Deterministic variant of [`new`](Self::new), for test vectors only.
    /// Only built with the `test-vectors` feature.
    #[cfg(feature = "test-vectors")]
    #[doc(hidden)]
    pub fn with_secrets(
        client_hello: &ClientHello,
        hello: ServerHello,
        nonce_s: Nonce,
        kx_secret: Zeroizing<[u8; KX_LEN]>,
    ) -> Result<(Self, ServerHello), HandshakeError> {
        Self::from_secrets(client_hello, hello, nonce_s, kx_secret)
    }

    fn from_secrets(
        client_hello: &ClientHello,
        mut hello: ServerHello,
        nonce_s: Nonce,
        kx_secret: Zeroizing<[u8; KX_LEN]>,
    ) -> Result<(Self, ServerHello), HandshakeError> {
        let ch = client_hello;
        if ch.proto != PROTO_VERSION {
            return Err(HandshakeError::ProtoMismatch(ch.proto));
        }
        let nonce_c = parse32(&ch.nonce_c, "nonceC")?;
        let kx_c = parse32(&ch.kx, "kx")?;
        let secret = StaticSecret::from(*kx_secret);
        let kx_s = PublicKey::from(&secret).to_bytes();
        let dh = secret.diffie_hellman(&PublicKey::from(kx_c));
        let hellos = Hellos::new(
            nonce_c,
            nonce_s,
            kx_c,
            kx_s,
            HelloText {
                client_id: &ch.client_id,
                device_id: &hello.device_id,
                client_name: &ch.client_name,
                device_name: &hello.device_name,
                model: &hello.model,
                auth_modes: &hello.auth_modes,
                caps: &hello.caps,
            },
            dh,
        )?;
        hello.proto = PROTO_VERSION;
        hello.nonce_s = to_hex(&nonce_s);
        hello.kx = to_hex(&kx_s);
        Ok((ServerHandshake { hellos }, hello))
    }

    /// The client's id from CLIENT_HELLO (pairing-store key).
    pub fn client_id(&self) -> &str {
        &self.hellos.client_id
    }

    /// AUTH_RESULT `ok:false` for a refusal decided by the caller's policy
    /// (`unknown_client` when no key is stored, `locked_out` with
    /// `retry_after_ms`, `mode_unsupported`).
    pub fn rejection(reason: AuthReason, retry_after_ms: Option<u64>) -> Message {
        Message::AuthResult(AuthResult {
            ok: false,
            server_proof: None,
            reason: Some(reason),
            retry_after_ms,
        })
    }

    fn reject(reason: AuthReason) -> ServerStep {
        ServerStep::Reject {
            reply: Self::rejection(reason, None),
            reason,
        }
    }

    /// AUTH mode `token` with the key stored for [`client_id`](Self::client_id).
    pub fn accept_token(self, auth: &Auth, pk: &PairingKey) -> ServerStep {
        if auth.mode != AuthMode::Token {
            return Self::reject(AuthReason::ModeUnsupported);
        }
        let th = sha256(&self.hellos.ctx(AuthMode::Token));
        if !proof_matches(&mac(pk.as_bytes(), b"C", &th), &auth.proof) {
            return Self::reject(AuthReason::BadProof);
        }
        let reply = Message::AuthResult(AuthResult {
            ok: true,
            server_proof: Some(to_hex(&mac(pk.as_bytes(), b"S", &th))),
            reason: None,
            retry_after_ms: None,
        });
        ServerStep::Accept {
            reply,
            session: Established {
                mode: AuthMode::Token,
                keys: self.hellos.session_keys(pk.as_bytes(), &th),
                pairing_key: None,
                transcript_hash: th,
            },
        }
    }

    /// AUTH mode `pin` with the PIN currently shown. The caller counts the
    /// attempt *before* calling (a client that disconnects after PAKE_REPLY
    /// still burns one) and checks the lockout first.
    pub fn start_pin(self, auth: &Auth, pin: &str) -> ServerStep {
        if auth.mode != AuthMode::Pin {
            return Self::reject(AuthReason::ModeUnsupported);
        }
        let Some(msg_a) = auth.pake.as_deref().and_then(from_hex) else {
            return Self::reject(AuthReason::BadProof);
        };
        let h = &self.hellos;
        let (spake, msg_b) = Spake2::<Ed25519Group>::start_b(
            &pin_password(pin),
            &Identity::new(h.client_id.as_bytes()),
            &Identity::new(h.device_id.as_bytes()),
        );
        let Ok(kp) = spake
            .finish(&msg_a)
            .map_err(drop)
            .and_then(|k| spake_key(k).map_err(drop))
        else {
            return Self::reject(AuthReason::BadProof);
        };
        let th_p = pin_transcript(&h.ctx(AuthMode::Pin), &msg_a, &msg_b);
        let reply = Message::PakeReply(PakeReply {
            pake: to_hex(&msg_b),
            server_proof: to_hex(&mac(&kp[..], b"S", &th_p)),
        });
        ServerStep::Continue {
            reply,
            wait: ServerPinWait {
                hellos: self.hellos,
                kp,
                th_p,
            },
        }
    }

    /// AUTH mode `none`. Call only when the server config allows it;
    /// otherwise answer with [`rejection`](Self::rejection)`(ModeUnsupported)`.
    /// The session is still encrypted, but unauthenticated: refuse control.
    pub fn accept_none(self) -> ServerStep {
        let th = sha256(&self.hellos.ctx(AuthMode::NoAuth));
        ServerStep::Accept {
            reply: Message::AuthResult(AuthResult {
                ok: true,
                ..AuthResult::default()
            }),
            session: Established {
                mode: AuthMode::NoAuth,
                keys: self.hellos.session_keys(&ZERO_KEY, &th),
                pairing_key: None,
                transcript_hash: th,
            },
        }
    }
}

/// Server state after PAKE_REPLY (PIN mode).
pub struct ServerPinWait {
    hellos: Hellos,
    kp: Zeroizing<[u8; 32]>,
    th_p: [u8; 32],
}

impl fmt::Debug for ServerPinWait {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerPinWait")
            .field("client_id", &self.hellos.client_id)
            .finish_non_exhaustive()
    }
}

impl ServerPinWait {
    /// Verify AUTH_CONFIRM. `Accept` carries the new pairing key to store
    /// (then rotate the PIN and reset the failure count); `Reject` is a
    /// wrong PIN.
    pub fn on_confirm(self, confirm: &AuthConfirm) -> ServerStep {
        let ServerPinWait { hellos, kp, th_p } = self;
        if !proof_matches(&mac(&kp[..], b"C", &th_p), &confirm.proof) {
            return ServerHandshake::reject(AuthReason::BadProof);
        }
        ServerStep::Accept {
            reply: Message::AuthResult(AuthResult {
                ok: true,
                ..AuthResult::default()
            }),
            session: Established {
                mode: AuthMode::Pin,
                keys: hellos.session_keys(&kp, &th_p),
                pairing_key: Some(new_pairing_key(&kp, &th_p)),
                transcript_hash: th_p,
            },
        }
    }
}
