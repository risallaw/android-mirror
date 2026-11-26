//! Outgoing queue with the video backpressure policy (PLAN §6), as a pure
//! data structure: no locking, no I/O, time passed in by the caller.
//!
//! Policy:
//! - Control messages (STATUS, BYE) are never dropped. PONGs are refused
//!   once [`MAX_PENDING_CONTROL`] control entries are queued (a PING flood
//!   from a peer that does not read).
//! - VIDEO_FRAMEs over the protocol's `MAX_PAYLOAD` are dropped (the
//!   receiver would close the connection) and trigger a keyframe resync.
//! - VIDEO_CONFIG is never dropped.
//! - When a frame is pushed and the oldest queued video frame is older than
//!   `max_age` (or the frame/byte caps would be exceeded), every queued video
//!   frame is dropped and the queue enters "await keyframe": non-key frames
//!   are dropped (and a keyframe requested, rate-limited) until a keyframe
//!   arrives, which is queued with the DISCONTINUITY flag.
//! - A new session starts in "await keyframe" without DISCONTINUITY, so the
//!   client's first frame is always an IDR preceded by a VIDEO_CONFIG: a
//!   keyframe pushed before this session's first config is dropped (an IDR
//!   without SPS/PPS is undecodable) and a keyframe requested.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use mirror_protocol::wire::flags;
use mirror_protocol::{Message, VideoConfig, VideoFrame, MAX_PAYLOAD};

use crate::types::EncodedFrame;

/// PONGs are refused once this many non-video entries are queued. A receiver
/// PINGs every 2 s, so a backlog this deep means the peer floods PINGs
/// without reading; without the cap the queue would grow without bound.
pub const MAX_PENDING_CONTROL: usize = 64;

/// Queue limits; see the matching [`ServerConfig`](crate::ServerConfig) fields.
#[derive(Debug, Clone, Copy)]
pub struct QueueLimits {
    pub max_age: Duration,
    pub max_frames: usize,
    pub max_bytes: usize,
    pub keyframe_retry: Duration,
}

/// Result of [`SendQueue::push_frame`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameOutcome {
    /// Queued (possibly with DISCONTINUITY set).
    Queued,
    /// Dropped; no action needed.
    Dropped,
    /// Dropped; the caller should ask the source for a keyframe.
    DroppedRequestKeyframe,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VideoState {
    Flowing,
    AwaitKeyframe { discontinuity: bool },
}

#[derive(Debug)]
struct Entry {
    msg: Message,
    /// Set for VIDEO_FRAME entries only.
    video: Option<(Instant, usize)>,
}

/// The per-session outgoing queue.
#[derive(Debug)]
pub struct SendQueue {
    entries: VecDeque<Entry>,
    limits: QueueLimits,
    video_frames: usize,
    video_bytes: usize,
    state: VideoState,
    config_sent: bool,
    last_kf_request: Option<Instant>,
    /// No more pushes accepted (a final message was queued or the session
    /// is shutting down).
    closed: bool,
    /// The last queued entry is the final message; the writer closes the
    /// socket after sending it.
    has_final: bool,
    dropped_frames: u64,
}

impl SendQueue {
    pub fn new(limits: QueueLimits) -> Self {
        SendQueue {
            entries: VecDeque::new(),
            limits,
            video_frames: 0,
            video_bytes: 0,
            state: VideoState::AwaitKeyframe {
                discontinuity: false,
            },
            config_sent: false,
            last_kf_request: None,
            closed: false,
            has_final: false,
            dropped_frames: 0,
        }
    }

    /// Queue a control message. Returns false if the queue is closed, or if
    /// `msg` is a PONG and [`MAX_PENDING_CONTROL`] entries are already queued.
    pub fn push_control(&mut self, msg: Message) -> bool {
        if self.closed
            || (matches!(msg, Message::Pong(_))
                && self.entries.len() - self.video_frames >= MAX_PENDING_CONTROL)
        {
            return false;
        }
        self.entries.push_back(Entry { msg, video: None });
        true
    }

    /// Queue the last message of the session (a BYE): drops queued video so
    /// it goes out promptly, then closes the queue. Returns false if the
    /// queue was already closed.
    pub fn push_final(&mut self, msg: Message) -> bool {
        if self.closed {
            return false;
        }
        self.drop_queued_video();
        self.entries.push_back(Entry { msg, video: None });
        self.closed = true;
        self.has_final = true;
        true
    }

    /// Close without a final message; queued entries are still drained.
    pub fn close(&mut self) {
        self.closed = true;
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Queue a VIDEO_CONFIG (never dropped).
    pub fn push_config(&mut self, cfg: VideoConfig) {
        if self.closed {
            return;
        }
        self.entries.push_back(Entry {
            msg: Message::VideoConfig(cfg),
            video: None,
        });
        self.config_sent = true;
    }

    /// Queue a video frame under the backpressure policy. Frames before this
    /// session's first [`push_config`](Self::push_config) are dropped.
    pub fn push_frame(&mut self, f: EncodedFrame, now: Instant) -> FrameOutcome {
        if self.closed {
            return FrameOutcome::Dropped;
        }
        let len = f.data.len();
        if len > MAX_PAYLOAD as usize {
            // The receiver would reject the frame and close the connection.
            log::warn!("dropping {len}-byte access unit (over the {MAX_PAYLOAD}-byte frame limit)");
            if self.state == VideoState::Flowing {
                self.state = VideoState::AwaitKeyframe {
                    discontinuity: true,
                };
            }
            return self.drop_and_maybe_request(now);
        }
        if self.video_frames > 0 && self.overloaded(now, len) {
            let n = self.drop_queued_video();
            log::debug!("backpressure: dropped {n} queued frames; resync on next keyframe");
            self.state = VideoState::AwaitKeyframe {
                discontinuity: true,
            };
        }
        let discontinuity = match self.state {
            VideoState::Flowing => false,
            VideoState::AwaitKeyframe { discontinuity } => {
                if !f.keyframe {
                    return self.drop_and_maybe_request(now);
                }
                if !self.config_sent {
                    // An IDR without SPS/PPS is undecodable.
                    return self.drop_and_maybe_request(now);
                }
                discontinuity
            }
        };
        let mut fl = 0;
        if f.keyframe {
            fl |= flags::KEYFRAME;
        }
        if discontinuity {
            fl |= flags::DISCONTINUITY;
        }
        self.state = VideoState::Flowing;
        self.last_kf_request = None;
        self.video_frames += 1;
        self.video_bytes += len;
        self.entries.push_back(Entry {
            msg: Message::VideoFrame(VideoFrame {
                pts_us: f.pts_us,
                flags: fl,
                data: f.data,
            }),
            video: Some((now, len)),
        });
        FrameOutcome::Queued
    }

    /// Next message to write, and whether it is the final one.
    pub fn pop(&mut self) -> Option<(Message, bool)> {
        let e = self.entries.pop_front()?;
        if let Some((_, len)) = e.video {
            self.video_frames -= 1;
            self.video_bytes -= len;
        }
        let is_final = self.has_final && self.entries.is_empty();
        Some((e.msg, is_final))
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Number of queued entries (all kinds).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Frames dropped by backpressure so far.
    pub fn dropped_frames(&self) -> u64 {
        self.dropped_frames
    }

    fn overloaded(&self, now: Instant, incoming: usize) -> bool {
        let oldest = self.entries.iter().find_map(|e| e.video.map(|(t, _)| t));
        let too_old =
            oldest.is_some_and(|t| now.saturating_duration_since(t) > self.limits.max_age);
        too_old
            || self.video_frames >= self.limits.max_frames
            || self.video_bytes.saturating_add(incoming) > self.limits.max_bytes
    }

    fn drop_queued_video(&mut self) -> usize {
        let before = self.entries.len();
        self.entries.retain(|e| e.video.is_none());
        let n = before - self.entries.len();
        self.dropped_frames += n as u64;
        self.video_frames = 0;
        self.video_bytes = 0;
        n
    }

    fn drop_and_maybe_request(&mut self, now: Instant) -> FrameOutcome {
        self.dropped_frames += 1;
        let due = self
            .last_kf_request
            .is_none_or(|t| now.saturating_duration_since(t) >= self.limits.keyframe_retry);
        if due {
            self.last_kf_request = Some(now);
            FrameOutcome::DroppedRequestKeyframe
        } else {
            FrameOutcome::Dropped
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mirror_protocol::{Bye, ByeReason};

    const MS: Duration = Duration::from_millis(1);

    fn limits() -> QueueLimits {
        QueueLimits {
            max_age: 250 * MS,
            max_frames: 100,
            max_bytes: 1 << 20,
            keyframe_retry: 1000 * MS,
        }
    }

    fn cfg() -> VideoConfig {
        VideoConfig {
            width: 64,
            height: 128,
            display_width: 64,
            display_height: 128,
            rotation: 0,
            sps_pps: vec![0, 0, 0, 1, 0x67, 0, 0, 0, 1, 0x68],
        }
    }

    fn fr(pts: u64, key: bool) -> EncodedFrame {
        EncodedFrame {
            pts_us: pts,
            keyframe: key,
            data: vec![pts as u8; 10],
        }
    }

    fn drain(q: &mut SendQueue) -> Vec<Message> {
        std::iter::from_fn(|| q.pop().map(|(m, _)| m)).collect()
    }

    fn frame_of(m: &Message) -> (u64, u8) {
        match m {
            Message::VideoFrame(f) => (f.pts_us, f.flags),
            other => panic!("expected frame, got {other:?}"),
        }
    }

    /// Queue already streaming (config + keyframe sent and written).
    fn flowing(t0: Instant) -> SendQueue {
        let mut q = SendQueue::new(limits());
        q.push_config(cfg());
        assert_eq!(q.push_frame(fr(0, true), t0), FrameOutcome::Queued);
        drain(&mut q);
        q
    }

    #[test]
    fn new_session_waits_for_keyframe_then_flows() {
        let t = Instant::now();
        let mut q = SendQueue::new(limits());
        q.push_config(cfg());
        assert_eq!(
            q.push_frame(fr(1, false), t),
            FrameOutcome::DroppedRequestKeyframe
        );
        // Rate-limited re-request.
        assert_eq!(q.push_frame(fr(2, false), t + MS), FrameOutcome::Dropped);
        assert_eq!(q.push_frame(fr(3, true), t + 2 * MS), FrameOutcome::Queued);
        assert_eq!(q.push_frame(fr(4, false), t + 3 * MS), FrameOutcome::Queued);
        let out = drain(&mut q);
        assert!(matches!(out[0], Message::VideoConfig(_)));
        // First keyframe of a session is not a discontinuity.
        assert_eq!(frame_of(&out[1]), (3, flags::KEYFRAME));
        assert_eq!(frame_of(&out[2]), (4, 0));
        assert_eq!(q.dropped_frames(), 2);
    }

    #[test]
    fn keyframe_request_retried_after_interval() {
        let t = Instant::now();
        let mut q = SendQueue::new(limits());
        q.push_config(cfg());
        assert_eq!(
            q.push_frame(fr(1, false), t),
            FrameOutcome::DroppedRequestKeyframe
        );
        assert_eq!(
            q.push_frame(fr(2, false), t + 999 * MS),
            FrameOutcome::Dropped
        );
        assert_eq!(
            q.push_frame(fr(3, false), t + 1000 * MS),
            FrameOutcome::DroppedRequestKeyframe
        );
    }

    #[test]
    fn keyframe_before_the_first_config_is_dropped() {
        let t = Instant::now();
        let mut q = SendQueue::new(limits());
        // No config yet: the keyframe is useless, dropped.
        assert_eq!(
            q.push_frame(fr(1, true), t),
            FrameOutcome::DroppedRequestKeyframe
        );
        let c = cfg();
        q.push_config(c.clone());
        assert_eq!(q.push_frame(fr(2, true), t), FrameOutcome::Queued);
        let out = drain(&mut q);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0], Message::VideoConfig(c));
        assert_eq!(frame_of(&out[1]), (2, flags::KEYFRAME));
    }

    #[test]
    fn stale_queue_drops_video_and_resyncs_with_discontinuity() {
        let t0 = Instant::now();
        let mut q = flowing(t0);
        assert_eq!(q.push_frame(fr(1, false), t0), FrameOutcome::Queued);
        assert!(q.push_control(Message::Pong([7; 8])));
        assert_eq!(
            q.push_frame(fr(2, false), t0 + 100 * MS),
            FrameOutcome::Queued
        );
        // Exactly 250 ms is still fine.
        assert_eq!(
            q.push_frame(fr(3, false), t0 + 250 * MS),
            FrameOutcome::Queued
        );
        // Oldest frame now 251 ms old: drop everything queued, request key.
        assert_eq!(
            q.push_frame(fr(4, false), t0 + 251 * MS),
            FrameOutcome::DroppedRequestKeyframe
        );
        assert_eq!(
            q.push_frame(fr(5, false), t0 + 260 * MS),
            FrameOutcome::Dropped
        );
        assert_eq!(
            q.push_frame(fr(6, true), t0 + 270 * MS),
            FrameOutcome::Queued
        );
        assert_eq!(
            q.push_frame(fr(7, false), t0 + 280 * MS),
            FrameOutcome::Queued
        );
        let out = drain(&mut q);
        assert_eq!(out.len(), 3, "{out:?}");
        assert_eq!(out[0], Message::Pong([7; 8]), "control survives");
        assert_eq!(
            frame_of(&out[1]),
            (6, flags::KEYFRAME | flags::DISCONTINUITY)
        );
        assert_eq!(frame_of(&out[2]), (7, 0));
        assert_eq!(q.dropped_frames(), 5);
    }

    #[test]
    fn overload_on_keyframe_needs_no_request() {
        let t0 = Instant::now();
        let mut q = flowing(t0);
        q.push_frame(fr(1, false), t0);
        assert_eq!(
            q.push_frame(fr(2, true), t0 + 300 * MS),
            FrameOutcome::Queued
        );
        let out = drain(&mut q);
        assert_eq!(out.len(), 1);
        assert_eq!(
            frame_of(&out[0]),
            (2, flags::KEYFRAME | flags::DISCONTINUITY)
        );
    }

    #[test]
    fn config_survives_resync() {
        let t0 = Instant::now();
        let mut q = flowing(t0);
        q.push_frame(fr(1, false), t0);
        q.push_config(cfg());
        q.push_frame(fr(2, true), t0 + 300 * MS);
        let out = drain(&mut q);
        assert!(matches!(out[0], Message::VideoConfig(_)));
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn frame_and_byte_caps() {
        let t0 = Instant::now();
        let mut q = SendQueue::new(QueueLimits {
            max_frames: 3,
            ..limits()
        });
        q.push_config(cfg());
        for i in 0..3 {
            assert_eq!(q.push_frame(fr(i, i == 0), t0), FrameOutcome::Queued);
        }
        assert_eq!(
            q.push_frame(fr(3, false), t0),
            FrameOutcome::DroppedRequestKeyframe
        );
        assert_eq!(q.len(), 1, "only the config is left");

        let mut q = SendQueue::new(QueueLimits {
            max_bytes: 25,
            ..limits()
        });
        q.push_config(cfg());
        assert_eq!(q.push_frame(fr(0, true), t0), FrameOutcome::Queued);
        assert_eq!(q.push_frame(fr(1, false), t0), FrameOutcome::Queued);
        assert_eq!(
            q.push_frame(fr(2, false), t0),
            FrameOutcome::DroppedRequestKeyframe
        );
    }

    #[test]
    fn final_message_drops_video_and_closes() {
        let t0 = Instant::now();
        let mut q = flowing(t0);
        q.push_frame(fr(1, false), t0);
        q.push_control(Message::Pong([1; 8]));
        let bye = Message::ServerBye(Bye {
            reason: ByeReason::Replaced,
        });
        assert!(q.push_final(bye.clone()));
        assert!(!q.push_final(bye.clone()));
        assert!(!q.push_control(Message::Pong([2; 8])));
        assert_eq!(q.push_frame(fr(2, true), t0), FrameOutcome::Dropped);
        assert_eq!(q.pop(), Some((Message::Pong([1; 8]), false)));
        assert_eq!(q.pop(), Some((bye, true)));
        assert_eq!(q.pop(), None);
    }

    #[test]
    fn pong_backlog_is_capped() {
        let t0 = Instant::now();
        let mut q = flowing(t0);
        q.push_frame(fr(1, false), t0);
        let accepted = (0..1000)
            .filter(|_| q.push_control(Message::Pong([0; 8])))
            .count();
        assert_eq!(accepted, MAX_PENDING_CONTROL);
        assert_eq!(q.len(), MAX_PENDING_CONTROL + 1, "video does not count");
        // Other control messages and the final BYE are never refused.
        assert!(q.push_control(Message::Status(mirror_protocol::Status {
            state: mirror_protocol::StatusState::ScreenOn,
        })));
        q.pop();
        q.pop();
        q.pop();
        assert!(q.push_control(Message::Pong([1; 8])));
        assert!(q.push_final(Message::ServerBye(Bye {
            reason: ByeReason::Replaced,
        })));
    }

    #[test]
    fn oversize_frame_is_dropped_and_resyncs() {
        let t0 = Instant::now();
        let mut q = flowing(t0);
        let big = EncodedFrame {
            pts_us: 1,
            keyframe: false,
            data: vec![0; MAX_PAYLOAD as usize + 1],
        };
        assert_eq!(
            q.push_frame(big.clone(), t0),
            FrameOutcome::DroppedRequestKeyframe
        );
        assert!(q.is_empty());
        assert_eq!(q.push_frame(fr(2, false), t0), FrameOutcome::Dropped);
        assert_eq!(q.push_frame(fr(3, true), t0), FrameOutcome::Queued);
        assert_eq!(
            frame_of(&drain(&mut q)[0]),
            (3, flags::KEYFRAME | flags::DISCONTINUITY)
        );
        // Before the first frame of a session no DISCONTINUITY is implied.
        let mut q = SendQueue::new(limits());
        q.push_config(cfg());
        let big_key = EncodedFrame {
            keyframe: true,
            ..big
        };
        assert_eq!(
            q.push_frame(big_key, t0),
            FrameOutcome::DroppedRequestKeyframe
        );
        assert_eq!(q.push_frame(fr(4, true), t0), FrameOutcome::Queued);
        let out = drain(&mut q);
        assert_eq!(frame_of(&out[1]), (4, flags::KEYFRAME));
    }

    /// `max_bytes = 0` (no byte budget): frames still flow one at a time,
    /// a second queued frame is backpressure, and a keyframe resyncs.
    #[test]
    fn zero_byte_budget_sends_one_frame_at_a_time() {
        let t = Instant::now();
        let mut q = SendQueue::new(QueueLimits {
            max_bytes: 0,
            ..limits()
        });
        q.push_config(cfg());
        assert_eq!(q.push_frame(fr(1, true), t), FrameOutcome::Queued);
        // Writer has not taken it yet: the next frame overflows the budget.
        assert_eq!(
            q.push_frame(fr(2, false), t),
            FrameOutcome::DroppedRequestKeyframe
        );
        assert_eq!(q.push_frame(fr(3, true), t), FrameOutcome::Queued);
        let out = drain(&mut q);
        assert!(matches!(out[0], Message::VideoConfig(_)));
        assert_eq!(
            frame_of(&out[1]),
            (3, flags::KEYFRAME | flags::DISCONTINUITY)
        );
        // Drained: the next frame goes through.
        assert_eq!(q.push_frame(fr(4, false), t), FrameOutcome::Queued);
    }
}
