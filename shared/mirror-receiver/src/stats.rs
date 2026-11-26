//! Stream statistics for the stats overlay: decoded fps, received Mbps,
//! decoded resolution and RTT over a sliding one-second window. Pure: the
//! caller supplies the clock.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Window the rates are computed over.
pub const WINDOW: Duration = Duration::from_secs(1);

/// What the overlay shows.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct StatsSnapshot {
    /// Decoded frames per second.
    pub fps: f32,
    /// Received video payload, megabits per second.
    pub mbps: f32,
    /// Size of the latest decoded frame.
    pub resolution: Option<(u32, u32)>,
    pub rtt: Option<Duration>,
    /// Frames dropped before decoding (keyframe gate) since connect.
    pub dropped: u64,
    /// Decoder errors since connect.
    pub decode_errors: u64,
}

#[derive(Debug, Default)]
pub struct Stats {
    /// (arrival, payload bytes) of received frames inside the window.
    received: VecDeque<(Instant, usize)>,
    received_bytes: usize,
    /// Times of decoded frames inside the window.
    decoded: VecDeque<Instant>,
    resolution: Option<(u32, u32)>,
    rtt: Option<Duration>,
    dropped: u64,
    decode_errors: u64,
}

impl Stats {
    pub fn new() -> Self {
        Self::default()
    }

    /// Forget everything (new connection).
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    fn prune(&mut self, now: Instant) {
        let Some(cutoff) = now.checked_sub(WINDOW) else {
            return;
        };
        while let Some(&(t, n)) = self.received.front() {
            if t > cutoff {
                break;
            }
            self.received.pop_front();
            self.received_bytes -= n;
        }
        while self.decoded.front().is_some_and(|&t| t <= cutoff) {
            self.decoded.pop_front();
        }
    }

    pub fn on_received(&mut self, now: Instant, bytes: usize) {
        self.received.push_back((now, bytes));
        self.received_bytes += bytes;
        self.prune(now);
    }

    pub fn on_decoded(&mut self, now: Instant, width: u32, height: u32) {
        self.decoded.push_back(now);
        self.resolution = Some((width, height));
        self.prune(now);
    }

    pub fn on_dropped(&mut self) {
        self.dropped += 1;
    }

    pub fn on_decode_error(&mut self) {
        self.decode_errors += 1;
    }

    pub fn set_rtt(&mut self, rtt: Duration) {
        self.rtt = Some(rtt);
    }

    pub fn snapshot(&mut self, now: Instant) -> StatsSnapshot {
        self.prune(now);
        let secs = WINDOW.as_secs_f32();
        StatsSnapshot {
            fps: self.decoded.len() as f32 / secs,
            mbps: self.received_bytes as f32 * 8.0 / secs / 1_000_000.0,
            resolution: self.resolution,
            rtt: self.rtt,
            dropped: self.dropped,
            decode_errors: self.decode_errors,
        }
    }
}

/// Round-trip time for display: whole milliseconds, `<1 ms` on loopback.
pub fn format_rtt(d: Duration) -> String {
    if d < Duration::from_millis(1) {
        "<1 ms".to_string()
    } else {
        format!("{} ms", d.as_millis())
    }
}

/// One-line summary for the overlay, e.g. `60 fps · 1088×2400 · 7.9 Mbps · RTT 3 ms`.
pub fn summary(s: &StatsSnapshot) -> String {
    let res = s
        .resolution
        .map_or_else(|| "–".to_string(), |(w, h)| format!("{w}×{h}"));
    let rtt = s.rtt.map_or_else(|| "–".to_string(), format_rtt);
    format!("{:.0} fps · {res} · {:.1} Mbps · RTT {rtt}", s.fps, s.mbps)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn sixty_fps_at_one_megabit() {
        let t0 = Instant::now();
        let mut s = Stats::new();
        // 60 frames over one second, 2083 bytes each ≈ 1 Mbit.
        for i in 0..60u64 {
            let t = t0 + Duration::from_micros(i * 16_667);
            s.on_received(t, 2083);
            s.on_decoded(t, 1088, 2400);
        }
        let snap = s.snapshot(t0 + ms(990));
        assert_eq!(snap.fps, 60.0);
        assert!((snap.mbps - 0.99984).abs() < 1e-3, "{}", snap.mbps);
        assert_eq!(snap.resolution, Some((1088, 2400)));
    }

    #[test]
    fn old_samples_leave_the_window() {
        let t0 = Instant::now();
        let mut s = Stats::new();
        s.on_received(t0, 1000);
        s.on_decoded(t0, 2, 2);
        let later = s.snapshot(t0 + ms(1500));
        assert_eq!(later.fps, 0.0);
        assert_eq!(later.mbps, 0.0);
        assert_eq!(later.resolution, Some((2, 2)), "resolution is sticky");
    }

    #[test]
    fn counters_rtt_and_reset() {
        let mut s = Stats::new();
        s.on_dropped();
        s.on_dropped();
        s.on_decode_error();
        s.set_rtt(ms(4));
        let snap = s.snapshot(Instant::now());
        assert_eq!((snap.dropped, snap.decode_errors), (2, 1));
        assert_eq!(snap.rtt, Some(ms(4)));
        s.reset();
        assert_eq!(s.snapshot(Instant::now()), StatsSnapshot::default());
    }

    #[test]
    fn rtt_formatting() {
        assert_eq!(format_rtt(Duration::from_micros(300)), "<1 ms");
        assert_eq!(format_rtt(ms(12)), "12 ms");
    }

    #[test]
    fn summary_formats() {
        let snap = StatsSnapshot {
            fps: 59.6,
            mbps: 7.94,
            resolution: Some((1088, 2400)),
            rtt: Some(ms(3)),
            ..Default::default()
        };
        assert_eq!(summary(&snap), "60 fps · 1088×2400 · 7.9 Mbps · RTT 3 ms");
        assert_eq!(
            summary(&StatsSnapshot::default()),
            "0 fps · – · 0.0 Mbps · RTT –"
        );
    }
}
