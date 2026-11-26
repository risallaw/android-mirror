//! mirror-receiver: platform-neutral receiver.
//!
//! - [`client`]: network client (handshake, reader/writer threads, PING/RTT,
//!   liveness) emitting [`ClientEvent`]s on a crossbeam channel.
//! - [`reconnect`]: [`Supervisor`] that keeps a client alive with backoff.
//! - [`frame_gate`]: [`FrameGate`], keyframe gating for the decoder layer.
//! - [`decoder`]: the platform-neutral [`VideoDecoder`] trait and NV12
//!   frame plumbing (pool, latest-frame slot).
//! - [`session`]: the decode thread (supervisor events → gate → decoder).
//! - [`render`]: wgpu NV12 renderer; `ui`: egui chrome; [`state`]: UI
//!   connection state machine; [`stats`], [`address`], [`store`].
//! - the winit + wgpu + egui app shell ([`run`]).
//!
//! Discovery arrives in M5 (see PLAN.md §5).

pub mod address;
mod app;
pub mod client;
pub mod decoder;
pub mod frame_gate;
pub mod input;
pub mod reconnect;
pub mod render;
pub mod session;
pub mod state;
pub mod stats;
pub mod store;
mod ui;

pub use app::{run, PlatformHooks, RunOptions, UserEvent};
pub use client::{
    is_control_message, is_valid_pin, Client, ClientConfig, ClientEvent, DisconnectReason,
    SendError, TimeoutKind, Timeouts,
};
pub use decoder::{
    DecodeError, DecoderFactory, FrameOutput, FramePool, FrameSlot, Nv12Frame, VideoDecoder,
};
pub use frame_gate::{FrameGate, GateAction};
pub use reconnect::{is_retryable, ReconnectPolicy, SessionLink, Supervisor};
