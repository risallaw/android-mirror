//! What the encoder thread does when a codec's drain thread stops on its own
//! (dequeue errors, unexpected end of stream, panic), and when a requested
//! keyframe does not come. Pure so it is tested on the host.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// Coalesces a repeated signal into one queued command: only the caller
/// whose [`Latch::raise`] returns true queues it, and the consumer calls
/// [`Latch::lower`] before acting, so a raise after that queues a new one.
#[derive(Debug, Default)]
pub struct Latch(AtomicBool);

impl Latch {
    /// True if the latch was down (the caller must queue the command).
    pub fn raise(&self) -> bool {
        !self.0.swap(true, Ordering::SeqCst)
    }

    pub fn lower(&self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

/// Restarts allowed in a row for codecs that fail before streaming for a while.
pub const MAX_CODEC_RESTARTS: u32 = 3;
/// A failed codec earns a fresh restart budget only after emitting at least
/// this many frames (a codec that emits one frame and errors must not restart
/// forever).
pub const MIN_FRAMES_FOR_RESET: u32 = 30;
/// Extra start attempts after a display change fails to start a codec.
pub const MAX_RECONFIGURE_RETRIES: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconfigureAction {
    /// Tear down and try to start the codec again.
    Retry,
    /// Release the codec, report the error and end the client's session.
    GiveUp,
}

/// Decide what to do after starting a codec for a display change failed;
/// `retries` is how many retries were already made for this change.
pub fn after_reconfigure_failure(retries: u32) -> ReconfigureAction {
    if retries < MAX_RECONFIGURE_RETRIES {
        ReconfigureAction::Retry
    } else {
        ReconfigureAction::GiveUp
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrainAction {
    /// The failure belongs to a codec that was already replaced or released.
    Ignore,
    /// Release the codec and start a new one for the same client.
    Restart,
    /// Release the codec, report the error and end the client's session.
    GiveUp,
}

/// Decide how to handle the drain thread of codec generation `failed_gen`
/// stopping by itself. `running_gen` is the generation currently running;
/// `frames_out` is how many frames the failed codec emitted (one that
/// emitted at least `MIN_FRAMES_FOR_RESET` earns a fresh restart budget). `restarts` counts
/// restarts in a row and is updated.
pub fn after_drain_failure(
    running_gen: Option<u64>,
    failed_gen: u64,
    frames_out: u32,
    restarts: &mut u32,
) -> DrainAction {
    if running_gen != Some(failed_gen) {
        return DrainAction::Ignore;
    }
    if frames_out >= MIN_FRAMES_FOR_RESET {
        *restarts = 0;
    }
    if *restarts >= MAX_CODEC_RESTARTS {
        return DrainAction::GiveUp;
    }
    *restarts += 1;
    DrainAction::Restart
}

/// A codec with no output for longer than this is idle (static screen):
/// `request-sync` alone cannot be answered until the screen changes.
pub const IDLE_BEFORE_REFRESH: Duration = Duration::from_secs(1);
/// How long a busy codec gets to answer `request-sync` on its own, and how
/// long a surface refresh gets before the codec is restarted instead.
pub const KEYFRAME_WAIT: Duration = Duration::from_millis(300);
/// At most one surface refresh per this interval.
pub const MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyframeStep {
    /// Nothing more to do: a keyframe came out after the request.
    Done,
    /// Check again at this time.
    Wait(Instant),
    /// Make the display composite a fresh frame now (re-attach the encoder
    /// surface) so the pending `request-sync` produces an IDR.
    Refresh,
    /// The refresh produced no keyframe: restart the codec (new SPS/PPS and
    /// IDR, the reconfigure path). Ends the request.
    Restart,
}

/// Decide what to do about a keyframe requested at `requested` (the oldest
/// unanswered request). `last_output`/`last_key` are when the running codec
/// last emitted any frame / a keyframe (counting from its start);
/// `refreshed` is when the surface was refreshed for this request, and
/// `last_refresh` the last refresh for any request.
pub fn keyframe_step(
    now: Instant,
    requested: Instant,
    last_output: Option<Instant>,
    last_key: Option<Instant>,
    refreshed: Option<Instant>,
    last_refresh: Option<Instant>,
) -> KeyframeStep {
    if last_key.is_some_and(|k| k >= requested) {
        return KeyframeStep::Done;
    }
    if let Some(r) = refreshed {
        let deadline = r + KEYFRAME_WAIT;
        return if now >= deadline {
            KeyframeStep::Restart
        } else {
            KeyframeStep::Wait(deadline)
        };
    }
    if let Some(r) = last_refresh {
        let next = r + MIN_REFRESH_INTERVAL;
        if now < next {
            return KeyframeStep::Wait(next);
        }
    }
    let idle = last_output.is_none_or(|t| now.saturating_duration_since(t) > IDLE_BEFORE_REFRESH);
    let deadline = requested + KEYFRAME_WAIT;
    if idle || now >= deadline {
        KeyframeStep::Refresh
    } else {
        KeyframeStep::Wait(deadline)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: Duration = Duration::from_millis(1);

    #[test]
    fn latch_queues_one_command_until_consumed() {
        let l = Latch::default();
        assert!(l.raise(), "first request queues");
        for _ in 0..1000 {
            assert!(!l.raise(), "requests while queued are coalesced");
        }
        l.lower();
        assert!(l.raise(), "a request after the consumer ran queues again");
        assert!(!l.raise());
    }

    #[test]
    fn keyframe_after_the_request_is_done() {
        let t0 = Instant::now();
        let req = t0 + 5000 * MS;
        let now = req + 10 * MS;
        assert_eq!(
            keyframe_step(now, req, Some(req), Some(req), None, None),
            KeyframeStep::Done
        );
        // Even when the codec was idle before and a refresh just happened.
        assert_eq!(
            keyframe_step(now, req, Some(now), Some(now), Some(now), Some(now)),
            KeyframeStep::Done
        );
    }

    #[test]
    fn idle_codec_is_refreshed_at_once() {
        let t0 = Instant::now();
        let req = t0 + 5000 * MS;
        // Last frame 5 s ago (static screen), keyframe long before that.
        assert_eq!(
            keyframe_step(req, req, Some(t0), Some(t0), None, None),
            KeyframeStep::Refresh
        );
        // A codec that never produced anything is idle too.
        assert_eq!(
            keyframe_step(req, req, None, None, None, None),
            KeyframeStep::Refresh
        );
        // Idle means strictly longer than the threshold.
        let last = req - IDLE_BEFORE_REFRESH;
        assert_eq!(
            keyframe_step(req, req, Some(last), Some(t0), None, None),
            KeyframeStep::Wait(req + KEYFRAME_WAIT)
        );
        assert_eq!(
            keyframe_step(req, req, Some(last - MS), Some(t0), None, None),
            KeyframeStep::Refresh
        );
    }

    #[test]
    fn busy_codec_gets_time_then_is_refreshed() {
        let t0 = Instant::now();
        let req = t0 + 5000 * MS;
        let recent = Some(req - 20 * MS);
        let old_key = Some(t0);
        assert_eq!(
            keyframe_step(req, req, recent, old_key, None, None),
            KeyframeStep::Wait(req + KEYFRAME_WAIT)
        );
        let almost = req + KEYFRAME_WAIT - MS;
        assert_eq!(
            keyframe_step(almost, req, Some(almost), old_key, None, None),
            KeyframeStep::Wait(req + KEYFRAME_WAIT)
        );
        let due = req + KEYFRAME_WAIT;
        assert_eq!(
            keyframe_step(due, req, Some(due), old_key, None, None),
            KeyframeStep::Refresh
        );
        // A delta (not a keyframe) after the request does not count.
        assert_eq!(
            keyframe_step(due, req, Some(due), Some(req - MS), None, None),
            KeyframeStep::Refresh
        );
    }

    #[test]
    fn refreshes_are_rate_limited() {
        let t0 = Instant::now();
        let req = t0 + 5000 * MS;
        let r = req - 400 * MS;
        assert_eq!(
            keyframe_step(req, req, Some(t0), Some(t0), None, Some(r)),
            KeyframeStep::Wait(r + MIN_REFRESH_INTERVAL)
        );
        let later = r + MIN_REFRESH_INTERVAL;
        assert_eq!(
            keyframe_step(later, req, Some(t0), Some(t0), None, Some(r)),
            KeyframeStep::Refresh
        );
    }

    #[test]
    fn stale_generation_is_ignored() {
        let mut n = 0;
        assert_eq!(
            after_drain_failure(Some(2), 1, 0, &mut n),
            DrainAction::Ignore
        );
        assert_eq!(after_drain_failure(None, 1, 0, &mut n), DrainAction::Ignore);
        assert_eq!(n, 0);
    }

    #[test]
    fn restarts_then_gives_up_when_codecs_never_produce() {
        let mut n = 0;
        for _ in 0..MAX_CODEC_RESTARTS {
            assert_eq!(
                after_drain_failure(Some(1), 1, 0, &mut n),
                DrainAction::Restart
            );
        }
        assert_eq!(
            after_drain_failure(Some(1), 1, 0, &mut n),
            DrainAction::GiveUp
        );
    }

    #[test]
    fn a_codec_that_produced_output_resets_the_budget() {
        let mut n = MAX_CODEC_RESTARTS;
        assert_eq!(
            after_drain_failure(Some(7), 7, MIN_FRAMES_FOR_RESET, &mut n),
            DrainAction::Restart
        );
        assert_eq!(n, 1);
    }

    #[test]
    fn a_codec_with_a_few_frames_does_not_reset_the_budget() {
        let mut n = MAX_CODEC_RESTARTS;
        assert_eq!(
            after_drain_failure(Some(7), 7, MIN_FRAMES_FOR_RESET - 1, &mut n),
            DrainAction::GiveUp
        );
        assert_eq!(n, MAX_CODEC_RESTARTS);
    }

    #[test]
    fn failed_reconfigure_retries_once_then_gives_up() {
        assert_eq!(after_reconfigure_failure(0), ReconfigureAction::Retry);
        assert_eq!(
            after_reconfigure_failure(MAX_RECONFIGURE_RETRIES),
            ReconfigureAction::GiveUp
        );
    }

    #[test]
    fn refresh_without_keyframe_falls_back_to_restart() {
        let t0 = Instant::now();
        let req = t0 + 5000 * MS;
        let r = req + MS;
        // Waiting for the refresh to produce a keyframe...
        assert_eq!(
            keyframe_step(r, req, Some(t0), Some(t0), Some(r), Some(r)),
            KeyframeStep::Wait(r + KEYFRAME_WAIT)
        );
        // ...a delta is not enough...
        let late = r + KEYFRAME_WAIT - MS;
        assert_eq!(
            keyframe_step(late, req, Some(late), Some(t0), Some(r), Some(r)),
            KeyframeStep::Wait(r + KEYFRAME_WAIT)
        );
        // ...then restart, even within the refresh rate limit.
        let due = r + KEYFRAME_WAIT;
        assert_eq!(
            keyframe_step(due, req, Some(t0), Some(t0), Some(r), Some(r)),
            KeyframeStep::Restart
        );
        // A keyframe from the refresh ends it.
        assert_eq!(
            keyframe_step(due, req, Some(r + MS), Some(r + MS), Some(r), Some(r)),
            KeyframeStep::Done
        );
    }
}
