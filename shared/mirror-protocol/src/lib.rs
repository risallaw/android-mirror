//! Android Mirror wire protocol v2.
//!
//! Pure, platform-neutral, sans-IO building blocks shared by the sender
//! (Android) and the receivers (macOS, later Windows):
//!
//! - [`wire`]: constants and the 16-byte frame [`Header`].
//! - [`messages`]: the typed [`Message`] enum.
//! - [`codec`]: [`encode`] and the incremental [`Decoder`].
//! - [`auth`]: PIN generation, the stored [`auth::PairingKey`], hex.
//! - [`handshake`]: sans-IO v2 handshake (X25519 + token proofs / SPAKE2 PIN
//!   pairing) producing the session keys.
//! - [`secure`]: the encrypted record layer ([`secure::Sealer`],
//!   [`secure::Opener`]) used after authentication.
//! - [`geometry`]: encode sizing, letterboxing and coordinate mapping.
//! - [`annexb`]: H.264 Annex-B parsing and AVCC conversion.
//!
//! See `PROTOCOL.md` in this crate for the full wire specification.

pub mod annexb;
pub mod auth;
pub mod codec;
pub mod error;
pub mod geometry;
pub mod handshake;
pub mod messages;
pub mod secure;
pub mod wire;

pub use codec::{encode, Decoder};
pub use error::ProtocolError;
pub use messages::*;
pub use wire::{
    Header, DEFAULT_PORT, MAGIC, MAX_CLIENT_PAYLOAD, MAX_JSON_PAYLOAD, MAX_PAYLOAD, PROTO_VERSION,
    SERVICE_TYPE,
};

/// Re-export so callers can name the RNG traits without a direct dependency.
pub use rand_core;
