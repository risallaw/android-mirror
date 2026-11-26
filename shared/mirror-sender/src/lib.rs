//! Platform-neutral Android Mirror sender (the phone side).
//!
//! A [`Server`] listens on TCP (default port 47800), runs the protocol v2
//! handshake (`mirror-protocol`, see its `PROTOCOL.md`: X25519 plus a stored
//! pairing key or SPAKE2 PIN pairing), and streams the video a host-provided
//! [`VideoSource`] pushes into a [`FrameSink`] to the newest authenticated
//! client over the encrypted record layer. Input from a paired client is
//! routed to a [`ControlSink`] while the host says control is available;
//! lifecycle and pairing changes are reported to [`HostEvents`].
//!
//! Design constraints (it runs inside the Android app via JNI and in the
//! desktop fake server): std threads and blocking sockets only, no async
//! runtime, no panics on network input, every thread joined by
//! [`Server::stop`], logging through the `log` facade.
//!
//! Threads:
//! - `mirror-accept`: accepts connections (blocking on Linux/Android, woken
//!   by `stop`; polled elsewhere), applies the LAN-only
//!   peer check and the pending-handshake cap, spawns session threads, reaps
//!   finished ones.
//! - `mirror-session-N`: handshake (bounded by `handshake_timeout`), then the
//!   reader loop (opens records; PING→PONG, START, REQUEST_KEYFRAME, BYE,
//!   control) with the liveness timeout, then teardown (stops the source,
//!   reports the state).
//! - `mirror-writer-N`: drains the session's [`SendQueue`](queue::SendQueue)
//!   to the socket, sealing each message into a record.
//! - The [`VideoSource`]'s own thread(s) push into the [`FrameSink`]; the
//!   backpressure policy runs inline in that push.

mod config;
pub mod control;
mod net;
mod pairing;
mod pending;
pub mod queue;
mod server;
mod session;
mod sink;
mod throttle;
mod types;

pub use config::ServerConfig;
pub use net::is_allowed_peer;
pub use pairing::{
    is_valid_pin, list_paired_at, revoke_at, PairedClient, MAX_PAIRINGS, MAX_PIN_FAILURES,
    PIN_LOCKOUT, PIN_LOCKOUT_MAX,
};
pub use server::Server;
pub use sink::FrameSink;
pub use throttle::short as log_str;
pub use types::*;

/// Re-export so hosts can name protocol types without a direct dependency.
pub use mirror_protocol;
