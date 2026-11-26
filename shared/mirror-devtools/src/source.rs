//! [`FileSource`]: a [`VideoSource`] that replays an [`H264Stream`].

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use mirror_sender::mirror_protocol::VideoConfig;
use mirror_sender::{EncodedFrame, FrameSink, SourceError, StreamParams, VideoSource};

use crate::splitter::H264Stream;

/// Playback options.
#[derive(Debug, Clone)]
pub struct FakeOptions {
    /// Frames per second (capped by the client's `max_fps`).
    pub fps: u32,
    /// Restart at the first IDR at end of file; otherwise go idle.
    pub looping: bool,
    /// Simulate rotation: every this often push a new VIDEO_CONFIG with
    /// width/height (and display size) swapped and `rotation` toggled
    /// between 0 and 1, followed by an IDR. The video content itself is not
    /// rotated, so the receiver sees geometry changes that do not match the
    /// decoded picture size.
    pub rotate_every: Option<Duration>,
}

impl Default for FakeOptions {
    fn default() -> Self {
        FakeOptions {
            fps: 60,
            looping: false,
            rotate_every: None,
        }
    }
}

struct Running {
    stop: Arc<AtomicBool>,
    thread: JoinHandle<()>,
}

/// Replays a file at a fixed rate. `request_keyframe` jumps to the next IDR
/// in the file (restarting at the first IDR when there is none ahead).
pub struct FileSource {
    stream: Arc<H264Stream>,
    opts: FakeOptions,
    keyframe_requested: Arc<AtomicBool>,
    running: Mutex<Option<Running>>,
}

impl FileSource {
    pub fn new(stream: Arc<H264Stream>, opts: FakeOptions) -> FileSource {
        FileSource {
            stream,
            opts,
            keyframe_requested: Arc::new(AtomicBool::new(false)),
            running: Mutex::new(None),
        }
    }

    fn stop_running(&self) {
        let r = self
            .running
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(r) = r {
            r.stop.store(true, Ordering::SeqCst);
            let _ = r.thread.join();
        }
    }
}

impl VideoSource for FileSource {
    fn start(&self, params: StreamParams, sink: FrameSink) -> Result<(), SourceError> {
        // Held throughout: two concurrent starts must not both spawn a
        // thread (the first one would never be stopped).
        let mut running = self.running.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(r) = running.take() {
            r.stop.store(true, Ordering::SeqCst);
            let _ = r.thread.join();
        }
        self.keyframe_requested.store(false, Ordering::SeqCst);
        let stop = Arc::new(AtomicBool::new(false));
        let (stream, opts, kf, stop2) = (
            self.stream.clone(),
            self.opts.clone(),
            self.keyframe_requested.clone(),
            stop.clone(),
        );
        let thread = thread::Builder::new()
            .name("fake-source".into())
            .spawn(move || run(stream, opts, params, sink, kf, stop2))?;
        *running = Some(Running { stop, thread });
        Ok(())
    }

    fn request_keyframe(&self) {
        self.keyframe_requested.store(true, Ordering::SeqCst);
    }

    fn stop(&self) {
        self.stop_running();
    }
}

fn config(stream: &H264Stream, swapped: bool) -> VideoConfig {
    let (w, h) = (stream.info.width as u16, stream.info.height as u16);
    let (w, h) = if swapped { (h, w) } else { (w, h) };
    VideoConfig {
        width: w,
        height: h,
        display_width: w,
        display_height: h,
        rotation: u8::from(swapped),
        sps_pps: stream.sps_pps_annexb(),
    }
}

/// Whether a rotation is due at `now` (`next` is when). If so, `next` moves
/// one period (`every`) past `now`, not past when it was due, so a stalled
/// source does not catch up with a rotation every frame. An absurd period
/// means "never" instead of an overflow panic.
fn rotation_due(next: &mut Option<Instant>, every: Option<Duration>, now: Instant) -> bool {
    match *next {
        Some(t) if now >= t => {
            *next = every.and_then(|d| now.checked_add(d));
            true
        }
        _ => false,
    }
}

/// Time of frame `n` at `fps`, from frame 0: exact (no per-frame rounding
/// that would drift), and no overflow for any `n`.
fn frame_time(n: u64, fps: u64) -> Duration {
    let ns = u128::from(n) * 1_000_000_000 / u128::from(fps);
    Duration::from_nanos(u64::try_from(ns).unwrap_or(u64::MAX))
}

/// Frames we may fall behind schedule (a stalled thread, a sleeping
/// machine) before the schedule is restarted from now instead of pushing
/// every missed frame in a burst.
const MAX_LAG_FRAMES: u64 = 2;

/// Sleep until `deadline` in small slices; false if `stop` was set.
fn sleep_until(deadline: Instant, stop: &AtomicBool) -> bool {
    loop {
        if stop.load(Ordering::SeqCst) {
            return false;
        }
        let now = Instant::now();
        if now >= deadline {
            return true;
        }
        thread::sleep((deadline - now).min(Duration::from_millis(10)));
    }
}

fn run(
    stream: Arc<H264Stream>,
    opts: FakeOptions,
    params: StreamParams,
    sink: FrameSink,
    kf_req: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
) {
    let fps = opts.fps.clamp(1, params.max_fps.max(1)) as u64;
    let first_idr = stream.next_keyframe(0).unwrap_or(0);
    let mut swapped = false;
    sink.push_config(config(&stream, swapped));
    log::info!(
        "source started: {}x{} @ {fps} fps, {} AUs",
        stream.info.width,
        stream.info.height,
        stream.aus.len()
    );
    let t0 = Instant::now();
    // checked_add: an absurd interval just means "never" instead of a panic.
    let mut next_rotate = opts.rotate_every.and_then(|d| t0.checked_add(d));
    let mut idx = first_idr;
    // Frame number (gives the pts) and the schedule it is timed against:
    // frame `n` is due at `base + frame_time(n - base_n)`.
    let mut n: u64 = 0;
    let (mut base, mut base_n) = (t0, 0u64);
    let mut eof_logged = false;
    loop {
        let deadline = base + frame_time(n - base_n, fps);
        let now = Instant::now();
        if now.saturating_duration_since(deadline) > frame_time(MAX_LAG_FRAMES, fps) {
            log::debug!(
                "source fell behind by {:?}; resuming from now",
                now - deadline
            );
            (base, base_n) = (now, n);
        }
        let deadline = base + frame_time(n - base_n, fps);
        if !sleep_until(deadline, &stop) {
            return;
        }
        let mut jump = false;
        if rotation_due(&mut next_rotate, opts.rotate_every, Instant::now()) {
            swapped = !swapped;
            sink.push_config(config(&stream, swapped));
            log::info!("simulated rotation -> rotation {}", u8::from(swapped));
            jump = true; // a config must be followed by an IDR
        }
        if kf_req.swap(false, Ordering::SeqCst) {
            jump = true;
        }
        if jump {
            // From `idx`: the frame about to be sent may itself be an IDR.
            idx = stream
                .next_keyframe(idx)
                .or_else(|| stream.next_keyframe(0))
                .unwrap_or(first_idr);
            eof_logged = false;
        }
        if idx >= stream.aus.len() {
            if opts.looping {
                idx = first_idr;
            } else {
                if !eof_logged {
                    log::info!("end of file, idle (use --loop to repeat)");
                    eof_logged = true;
                }
                // Keep the clock moving so we do not spin.
                n += 1;
                continue;
            }
        }
        let au = &stream.aus[idx];
        sink.push_frame(EncodedFrame {
            pts_us: frame_time(n, fps).as_micros() as u64,
            keyframe: au.keyframe,
            data: stream.au_bytes(idx).to_vec(),
        });
        idx += 1;
        n += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_late_rotation_schedules_the_next_one_from_now() {
        let t0 = Instant::now();
        let s = Duration::from_secs;
        let every = Some(s(2));
        let mut next = t0.checked_add(s(2));
        assert!(!rotation_due(&mut next, every, t0 + s(1)));
        // The source stalled for 5 s: one rotation, then a full period.
        assert!(rotation_due(&mut next, every, t0 + s(7)));
        assert_eq!(next, Some(t0 + s(9)));
        assert!(!rotation_due(
            &mut next,
            every,
            t0 + s(7) + Duration::from_millis(1)
        ));
        assert!(rotation_due(&mut next, Some(Duration::MAX), t0 + s(9)));
        assert_eq!(next, None, "overflow means never");
        assert!(!rotation_due(&mut next, every, t0 + s(100)));
    }

    #[test]
    fn frame_times_do_not_drift_or_overflow() {
        // 60 fps: 16_666.67 µs per frame; truncating the period drifts.
        assert_eq!(frame_time(60, 60), Duration::from_secs(1));
        assert_eq!(frame_time(3_600 * 60, 60), Duration::from_secs(3_600));
        assert_eq!(frame_time(1, 60).as_micros(), 16_666);
        // Past u32 frames (the old `n as u32` wrapped here).
        let n = u64::from(u32::MAX) + 1;
        assert_eq!(frame_time(n, 1), Duration::from_secs(n));
        assert!(frame_time(u64::MAX, 1) > Duration::ZERO);
    }
}
