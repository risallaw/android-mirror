//! Authentication primitives shared by the v2 handshake: PIN generation, the stored [`PairingKey`], constant-time comparison and hex.
//!
//! The handshake itself (X25519, SPAKE2, proofs, key schedule) lives in
//! [`crate::handshake`]; see `PROTOCOL.md` for the wire-level description.

use std::fmt;

use rand_core::CryptoRng;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Length of a 256-bit key / proof.
pub const KEY_LEN: usize = 32;
/// Required nonce length in bytes.
pub const NONCE_LEN: usize = 32;
/// Number of digits in a pairing PIN.
pub const PIN_DIGITS: usize = 6;
/// Domain-separation prefix of the SPAKE2 password: `"androidmirror-pin" || PIN`.
pub const PIN_KEY_PREFIX: &[u8] = b"androidmirror-pin";

pub type Nonce = [u8; NONCE_LEN];

/// The 32-byte pairing key both sides store after a successful PIN pairing
/// (phone keyed by `clientId`, receiver keyed by `deviceId`) and use for
/// mode `token` afterwards.
///
/// Zeroized on drop; `Debug` never prints the key. Persist it with
/// [`to_hex`](PairingKey::to_hex) / [`from_hex`](PairingKey::from_hex).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PairingKey([u8; KEY_LEN]);

impl PairingKey {
    pub fn from_bytes(b: [u8; KEY_LEN]) -> Self {
        PairingKey(b)
    }
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
    pub(crate) fn as_mut_bytes(&mut self) -> &mut [u8; KEY_LEN] {
        &mut self.0
    }
    /// Lowercase hex, for the pairing store. Treat the string as a secret.
    pub fn to_hex(&self) -> String {
        to_hex(&self.0)
    }
    /// Parse a stored key; `None` unless exactly 64 hex digits.
    pub fn from_hex(s: &str) -> Option<Self> {
        let mut v = from_hex(s)?;
        let k = <[u8; KEY_LEN]>::try_from(v.as_slice()).ok().map(PairingKey);
        v.zeroize();
        k
    }
}

impl PartialEq for PairingKey {
    /// Constant time.
    fn eq(&self, other: &Self) -> bool {
        ct_eq(&self.0, &other.0)
    }
}
impl Eq for PairingKey {}

impl fmt::Debug for PairingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PairingKey(<redacted>)")
    }
}

/// Constant-time equality (length differences are not hidden).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

/// Uniformly random 6-digit PIN (`"000000"`..=`"999999"`), via rejection sampling.
pub fn generate_pin<R: CryptoRng + ?Sized>(rng: &mut R) -> String {
    const N: u32 = 1_000_000;
    // Accept 0..4294*N (the largest multiple of N <= 2^32) to avoid modulo bias.
    const ZONE: u32 = u32::MAX - (u32::MAX % N) - 1;
    loop {
        let v = rng.next_u32();
        if v <= ZONE {
            return format!("{:06}", v % N);
        }
    }
}

/// Lowercase hex encoding.
pub fn to_hex(b: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for &x in b {
        s.push(H[(x >> 4) as usize] as char);
        s.push(H[(x & 15) as usize] as char);
    }
    s
}

/// Hex decoding (accepts upper or lower case). `None` on odd length or bad digit.
pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    fn d(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }
    let b = s.as_bytes();
    if !b.len().is_multiple_of(2) {
        return None;
    }
    b.chunks(2)
        .map(|c| Some(d(c[0])? << 4 | d(c[1])?))
        .collect()
}
