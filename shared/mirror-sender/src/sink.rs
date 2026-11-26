//! [`FrameSink`]: where a [`VideoSource`](crate::VideoSource) pushes encoded
//! video for the session it was started for.

use std::sync::{Arc, Weak};
use std::time::Instant;

use mirror_protocol::{ByeReason, VideoConfig};

use crate::queue::FrameOutcome;
use crate::server::{lock, Shared};
use crate::session::SessionHandle;
use crate::types::{DisconnectReason, EncodedFrame};

/// Handle a [`VideoSource`](crate::VideoSource) pushes video into. Cheap to
/// clone, `Send + Sync`. Bound to one client session: once that session ends
/// (or the source is restarted for another client) every push is a no-op, so
/// a source thread that races with `stop()` cannot leak frames into the next
/// client. Holds only weak references; keeping a sink alive keeps nothing
/// else alive.
#[derive(Clone)]
pub struct FrameSink {
    session_id: u64,
    session: Weak<SessionHandle>,
    shared: Weak<Shared>,
}

impl std::fmt::Debug for FrameSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FrameSink")
            .field("session_id", &self.session_id)
            .field("active", &self.is_active())
            .finish()
    }
}

impl FrameSink {
    pub(crate) fn new(session_id: u64, session: Weak<SessionHandle>, shared: Weak<Shared>) -> Self {
        FrameSink {
            session_id,
            session,
            shared,
        }
    }

    /// True while pushes still reach a client.
    pub fn is_active(&self) -> bool {
        self.live()
            .is_some_and(|(session, _)| !lock(&session.queue).is_closed())
    }

    /// Push a new VIDEO_CONFIG (SPS+PPS and geometry). Send one before the
    /// first keyframe of every start and again on every geometry change (a
    /// keyframe before the first config is dropped). The server keeps the
    /// latest config to map control coordinates.
    pub fn push_config(&self, cfg: VideoConfig) {
        let Some((session, shared)) = self.live() else {
            return;
        };
        {
            let mut q = lock(&session.queue);
            if q.is_closed() {
                return;
            }
            q.push_config(cfg.clone());
        }
        session.cv.notify_one();
        *lock(&shared.last_config) = Some(Arc::new(cfg));
    }

    /// End the session this sink is bound to, e.g. when the encoder failed
    /// for good: it gets BYE `unknown` (so the receiver does not reconnect
    /// into the same failure) and ends with
    /// [`DisconnectReason::SourceFailed`]. Unlike
    /// [`Server::disconnect`](crate::Server::disconnect), it never touches a
    /// newer client that replaced this one. False if the session already
    /// ended (or the source was restarted for another session).
    pub fn fail(&self) -> bool {
        self.live().is_some_and(|(session, _)| {
            session.finish(ByeReason::Unknown, DisconnectReason::SourceFailed)
        })
    }

    /// Push one encoded access unit. Returns true if it was queued for
    /// sending, false if dropped (backpressure, waiting for a keyframe, or
    /// the session is gone). When the policy needs a resync this calls
    /// [`VideoSource::request_keyframe`](crate::VideoSource::request_keyframe)
    /// synchronously, from the calling thread.
    pub fn push_frame(&self, frame: EncodedFrame) -> bool {
        let Some((session, shared)) = self.live() else {
            return false;
        };
        // Every start pushes its own config; until it has, frames are
        // dropped (the previous session's config, maybe of another geometry,
        // must never prefix a frame). A closed queue drops the frame too.
        let outcome = lock(&session.queue).push_frame(frame, Instant::now());
        match outcome {
            FrameOutcome::Queued => {
                session.cv.notify_one();
                true
            }
            FrameOutcome::Dropped => false,
            FrameOutcome::DroppedRequestKeyframe => {
                shared.request_keyframe(self.session_id);
                false
            }
        }
    }

    /// The session and server while this sink's session owns the source.
    /// Whether its queue is closed is left to the queue operation itself
    /// (one lock per push).
    fn live(&self) -> Option<(Arc<SessionHandle>, Arc<Shared>)> {
        let session = self.session.upgrade()?;
        let shared = self.shared.upgrade()?;
        if shared.source_owner() != self.session_id {
            return None;
        }
        Some((session, shared))
    }
}
