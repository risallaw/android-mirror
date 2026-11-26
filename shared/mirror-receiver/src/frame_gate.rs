//! [`FrameGate`]: decides which received video frames may reach the decoder.
//!
//! An H.264 decoder can only start (or restart) on an IDR frame that follows
//! the SPS/PPS it was configured with. Frames that arrive before the first
//! VIDEO_CONFIG, after a new VIDEO_CONFIG but before its IDR, after a sender
//! DISCONTINUITY (backpressure drop), or after a local decode error would
//! only produce garbage or decoder errors, so they are dropped until the next
//! keyframe. Pure state machine: no I/O; the caller passes the time.
//!
//! The sender rate-limits REQUEST_KEYFRAME (a request inside its window is
//! deferred and coalesced with others, not answered at once), and a
//! keyframe may also fail to decode, so a request is repeated after
//! [`REREQUEST_AFTER`], backing off to [`MAX_REREQUEST_AFTER`] until a frame
//! decodes again.

use std::time::{Duration, Instant};

/// A REQUEST_KEYFRAME that brought no keyframe is repeated after this long.
pub const REREQUEST_AFTER: Duration = Duration::from_secs(1);
/// Longest gap between repeated requests within one wait.
pub const MAX_REREQUEST_AFTER: Duration = Duration::from_secs(8);

/// What the decoder layer should do with one frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateAction {
    /// Feed the frame to the decoder.
    Decode,
    /// Drop the frame.
    Drop,
    /// Drop the frame and send REQUEST_KEYFRAME (returned on the first
    /// non-key frame dropped after the stream was configured, then again
    /// only if no keyframe came within the backoff, so a stream of deltas
    /// does not spam the sender).
    DropAndRequestKeyframe,
}

/// Keyframe gate. Starts unconfigured.
#[derive(Debug, Clone, Default)]
pub struct FrameGate {
    /// A VIDEO_CONFIG has been seen (cleared by [`reset`](Self::reset)).
    configured: bool,
    /// Dropping until the next keyframe.
    waiting_for_key: bool,
    /// When REQUEST_KEYFRAME was last asked for since a frame last decoded.
    requested: Option<Instant>,
    /// How long that request gets before it is repeated.
    retry_after: Duration,
}

impl FrameGate {
    pub fn new() -> Self {
        FrameGate {
            configured: false,
            waiting_for_key: true,
            requested: None,
            retry_after: REREQUEST_AFTER,
        }
    }

    /// A VIDEO_CONFIG arrived (new SPS/PPS): the decoder is rebuilt and needs
    /// an IDR. The sender always follows a config with an IDR, so no request
    /// is needed yet.
    pub fn on_config(&mut self) {
        self.configured = true;
        self.enter_wait();
    }

    /// The local decoder failed (or was recreated): drop until a keyframe.
    /// Returns true when the caller should send REQUEST_KEYFRAME now (only if
    /// configured, and not already requested during this wait unless that
    /// request is overdue).
    pub fn on_decode_error(&mut self, now: Instant) -> bool {
        self.enter_wait();
        self.configured && self.request_due(now)
    }

    /// A frame decoded: the stream is healthy, so the next wait starts
    /// with a fresh request and the shortest backoff.
    pub fn on_decoded(&mut self) {
        self.requested = None;
    }

    /// Forget everything (new connection): back to unconfigured.
    pub fn reset(&mut self) {
        *self = FrameGate::new();
    }

    /// True while frames are being dropped.
    pub fn is_waiting(&self) -> bool {
        self.waiting_for_key
    }

    /// True once a VIDEO_CONFIG has been seen since the last reset.
    pub fn is_configured(&self) -> bool {
        self.configured
    }

    /// Classify one VIDEO_FRAME by its header flags.
    pub fn on_frame(&mut self, keyframe: bool, discontinuity: bool, now: Instant) -> GateAction {
        if !self.configured {
            // Nothing to decode with; a VIDEO_CONFIG is always coming.
            return GateAction::Drop;
        }
        if discontinuity && !keyframe {
            // Frames were dropped upstream; deltas reference missing data.
            self.enter_wait();
        }
        if keyframe {
            // The backoff ends only when it decodes (`on_decoded`): a
            // keyframe that fails must not restart it at 1 s.
            self.waiting_for_key = false;
            return GateAction::Decode;
        }
        if !self.waiting_for_key {
            return GateAction::Decode;
        }
        if self.request_due(now) {
            GateAction::DropAndRequestKeyframe
        } else {
            GateAction::Drop
        }
    }

    /// Whether to send REQUEST_KEYFRAME now: the first time in a wait, or
    /// when the last request went unanswered for `retry_after` (which then
    /// doubles, up to [`MAX_REREQUEST_AFTER`]).
    fn request_due(&mut self, now: Instant) -> bool {
        match self.requested {
            None => self.retry_after = REREQUEST_AFTER,
            Some(at) if now.saturating_duration_since(at) < self.retry_after => return false,
            Some(_) => self.retry_after = (self.retry_after * 2).min(MAX_REREQUEST_AFTER),
        }
        self.requested = Some(now);
        true
    }

    fn enter_wait(&mut self) {
        self.waiting_for_key = true;
    }
}

#[cfg(test)]
mod tests {
    use super::GateAction::*;
    use super::*;

    /// One instant for tests that do not depend on time passing.
    fn t0() -> Instant {
        static T0: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
        *T0.get_or_init(Instant::now)
    }

    #[test]
    fn drops_everything_before_first_config() {
        let mut g = FrameGate::new();
        assert!(!g.is_configured());
        assert_eq!(g.on_frame(false, false, t0()), Drop);
        assert_eq!(g.on_frame(true, false, t0()), Drop);
        assert_eq!(g.on_frame(false, true, t0()), Drop);
        assert!(g.is_waiting());
    }

    #[test]
    fn config_then_keyframe_passes_and_deltas_follow() {
        let mut g = FrameGate::new();
        g.on_config();
        assert!(g.is_waiting());
        assert_eq!(g.on_frame(true, false, t0()), Decode);
        assert_eq!(g.on_frame(false, false, t0()), Decode);
        assert_eq!(g.on_frame(false, false, t0()), Decode);
        assert!(!g.is_waiting());
    }

    #[test]
    fn delta_after_config_drops_and_requests_once() {
        let mut g = FrameGate::new();
        g.on_config();
        assert_eq!(g.on_frame(false, false, t0()), DropAndRequestKeyframe);
        assert_eq!(g.on_frame(false, false, t0()), Drop);
        assert_eq!(g.on_frame(false, false, t0()), Drop);
        assert_eq!(g.on_frame(true, false, t0()), Decode);
        assert_eq!(g.on_frame(false, false, t0()), Decode);
    }

    #[test]
    fn new_config_mid_stream_waits_for_keyframe() {
        let mut g = FrameGate::new();
        g.on_config();
        assert_eq!(g.on_frame(true, false, t0()), Decode);
        g.on_config(); // rotation
        assert_eq!(g.on_frame(false, false, t0()), DropAndRequestKeyframe);
        assert_eq!(g.on_frame(true, false, t0()), Decode);
    }

    #[test]
    fn discontinuity_on_delta_waits_for_keyframe() {
        let mut g = FrameGate::new();
        g.on_config();
        assert_eq!(g.on_frame(true, false, t0()), Decode);
        assert_eq!(g.on_frame(false, true, t0()), DropAndRequestKeyframe);
        assert_eq!(g.on_frame(false, false, t0()), Drop);
        assert_eq!(g.on_frame(true, false, t0()), Decode);
        assert_eq!(g.on_frame(false, false, t0()), Decode);
    }

    #[test]
    fn discontinuity_on_keyframe_passes() {
        // The sender's backpressure resync marks the sync frame itself.
        let mut g = FrameGate::new();
        g.on_config();
        assert_eq!(g.on_frame(true, false, t0()), Decode);
        assert_eq!(g.on_frame(true, true, t0()), Decode);
        assert_eq!(g.on_frame(false, false, t0()), Decode);
    }

    #[test]
    fn decode_error_requests_once_then_drops_until_keyframe() {
        let mut g = FrameGate::new();
        g.on_config();
        assert_eq!(g.on_frame(true, false, t0()), Decode);
        assert!(g.on_decode_error(t0()));
        assert!(
            !g.on_decode_error(t0()),
            "second error in same wait: no re-request"
        );
        assert_eq!(g.on_frame(false, false, t0()), Drop);
        assert_eq!(g.on_frame(true, false, t0()), Decode);
        // A fresh error after recovery asks again.
        g.on_decoded();
        assert!(g.on_decode_error(t0()));
    }

    #[test]
    fn keyframes_that_fail_to_decode_keep_the_backoff() {
        let mut g = FrameGate::new();
        g.on_config();
        let t = t0();
        let mut requests = Vec::new();
        for ms in (0..8000).step_by(50) {
            let now = t + Duration::from_millis(ms);
            assert_eq!(g.on_frame(true, false, now), Decode);
            if g.on_decode_error(now) {
                requests.push(ms);
            }
        }
        assert_eq!(requests, [0, 1000, 3000, 7000]);
    }

    #[test]
    fn decode_error_before_config_does_not_request() {
        let mut g = FrameGate::new();
        assert!(!g.on_decode_error(t0()));
        assert_eq!(g.on_frame(true, false, t0()), Drop);
    }

    #[test]
    fn reset_returns_to_unconfigured() {
        let mut g = FrameGate::new();
        g.on_config();
        assert_eq!(g.on_frame(true, false, t0()), Decode);
        g.reset();
        assert!(!g.is_configured());
        assert_eq!(g.on_frame(true, false, t0()), Drop);
    }

    #[test]
    fn an_unanswered_request_is_repeated_with_backoff() {
        let mut g = FrameGate::new();
        g.on_config();
        let t = t0();
        let at = |ms: u64| t + Duration::from_millis(ms);
        assert_eq!(g.on_frame(false, false, at(0)), DropAndRequestKeyframe);
        assert_eq!(g.on_frame(false, false, at(999)), Drop);
        assert_eq!(g.on_frame(false, false, at(1000)), DropAndRequestKeyframe);
        // Then 2 s, 4 s, 8 s, and never longer.
        assert_eq!(g.on_frame(false, false, at(2999)), Drop);
        assert_eq!(g.on_frame(false, false, at(3000)), DropAndRequestKeyframe);
        assert!(!g.on_decode_error(at(6999)));
        assert!(g.on_decode_error(at(7000)));
        assert_eq!(g.on_frame(false, false, at(14_999)), Drop);
        assert_eq!(g.on_frame(false, false, at(15_000)), DropAndRequestKeyframe);
        assert_eq!(g.on_frame(false, false, at(22_999)), Drop);
        assert_eq!(g.on_frame(false, false, at(23_000)), DropAndRequestKeyframe);
        // A keyframe ends the wait; the next wait starts at 1 s again.
        assert_eq!(g.on_frame(true, false, at(23_100)), Decode);
        g.on_decoded();
        assert!(g.on_decode_error(at(23_200)));
        assert!(!g.on_decode_error(at(24_199)));
        assert!(g.on_decode_error(at(24_200)));
    }
}
