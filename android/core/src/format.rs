//! Encoder format selection (PLAN §4): the `AMediaFormat` keys for H.264
//! surface-input encoding and the configure fallback ladder.
//!
//! Pure logic so it is unit-tested on the host; `encoder.rs` turns an
//! [`EncoderSpec`] into an `AMediaFormat`.

use mirror_protocol::geometry::encode_size;
use mirror_sender::StreamParams;

/// MIME type of the only codec in the protocol (`codecs: ["h264"]`).
pub const MIME_AVC: &str = "video/avc";
/// `COLOR_FormatSurface`.
pub const COLOR_FORMAT_SURFACE: i32 = 0x7F00_0789;
/// Highest frame rate we ask an encoder for, whatever START says.
pub const MAX_ENCODER_FPS: u32 = 60;
/// Frame rate of the `Fps30` rung.
pub const FALLBACK_FPS: u32 = 30;
/// Long-edge cap of the `Cap1280` rung.
pub const FALLBACK_LONG_EDGE: u32 = 1280;
/// Smallest long-edge cap honoured. `mirror_sender` already raises START's
/// `maxLongEdge` to its `MIN_LONG_EDGE` (also 320); this floor keeps the
/// encoder safe on its own. Below it, rounding both edges to multiples of 16
/// squashes the picture (1080×2400 at a cap of 16 would encode as 16×16) and
/// hardware encoders reject such sizes; at 320 a 20:9 phone encodes at
/// 144×320 with its aspect kept. Displays smaller than this are not upscaled.
pub const MIN_ENCODE_LONG_EDGE: u32 = 320;
/// Seconds between IDR frames when nothing asks for one earlier.
pub const I_FRAME_INTERVAL_S: i32 = 10;
/// Re-encode the last frame after this long without a new one, so a static
/// screen still produces output (and a new client gets frames). Required.
pub const REPEAT_PREVIOUS_FRAME_AFTER_US: i64 = 100_000;

/// One step of the configure fallback ladder. Each rung keeps the reductions
/// of the previous ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rung {
    /// Every key from the PLAN §4 table.
    Full,
    /// Only the required keys (some encoders reject unknown/unsupported ones).
    Required,
    /// Required keys at 30 fps.
    Fps30,
    /// Required keys at 30 fps with the long edge capped to 1280.
    Cap1280,
}

impl Rung {
    /// Rungs in the order they are tried.
    pub const LADDER: [Rung; 4] = [Rung::Full, Rung::Required, Rung::Fps30, Rung::Cap1280];

    fn optional_keys(self) -> bool {
        self == Rung::Full
    }

    fn fps_cap(self) -> u32 {
        match self {
            Rung::Full | Rung::Required => MAX_ENCODER_FPS,
            Rung::Fps30 | Rung::Cap1280 => FALLBACK_FPS,
        }
    }
}

/// A typed `AMediaFormat` value.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Value {
    I32(i32),
    I64(i64),
    F32(f32),
}

/// What the encoder is configured with for one rung.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncoderSpec {
    pub rung: Rung,
    /// Encoded frame size (multiples of 16).
    pub width: u32,
    pub height: u32,
    pub fps: u32,
    /// Bits per second.
    pub bitrate: u32,
}

impl EncoderSpec {
    /// Spec for a display of `display_w`×`display_h` (current orientation)
    /// and the client's stream parameters.
    pub fn new(rung: Rung, display_w: u32, display_h: u32, params: &StreamParams) -> Self {
        let mut long_edge = match params.max_long_edge {
            0 => 0,
            v => v.max(MIN_ENCODE_LONG_EDGE),
        };
        let mut bitrate = params.bitrate;
        if rung == Rung::Cap1280 {
            if long_edge == 0 || long_edge > FALLBACK_LONG_EDGE {
                long_edge = FALLBACK_LONG_EDGE;
            }
            bitrate = bitrate.min(StreamParams::default_bitrate(FALLBACK_LONG_EDGE));
        }
        let (width, height) = encode_size(display_w, display_h, long_edge);
        let fps = params.max_fps.clamp(1, rung.fps_cap());
        EncoderSpec {
            rung,
            width,
            height,
            fps,
            bitrate,
        }
    }

    /// The ladder for one display and client, deduplicated (a rung that
    /// would configure exactly what an earlier rung already tried is skipped,
    /// e.g. `Cap1280` when the encode size is already ≤ 1280).
    pub fn ladder(display_w: u32, display_h: u32, params: &StreamParams) -> Vec<EncoderSpec> {
        let mut out: Vec<EncoderSpec> = Vec::with_capacity(Rung::LADDER.len());
        for rung in Rung::LADDER {
            let spec = EncoderSpec::new(rung, display_w, display_h, params);
            let dup = out.iter().any(|s| {
                s.rung.optional_keys() == spec.rung.optional_keys()
                    && (s.width, s.height, s.fps, s.bitrate)
                        == (spec.width, spec.height, spec.fps, spec.bitrate)
            });
            if !dup {
                out.push(spec);
            }
        }
        out
    }

    /// Format entries (besides `mime`) for `AMediaFormat`.
    pub fn entries(&self) -> Vec<(&'static str, Value)> {
        let fps = self.fps as i32;
        let mut e = vec![
            ("width", Value::I32(self.width as i32)),
            ("height", Value::I32(self.height as i32)),
            ("color-format", Value::I32(COLOR_FORMAT_SURFACE)),
            (
                "bitrate",
                Value::I32(self.bitrate.min(i32::MAX as u32) as i32),
            ),
            ("frame-rate", Value::I32(fps)),
            ("i-frame-interval", Value::I32(I_FRAME_INTERVAL_S)),
            (
                "repeat-previous-frame-after",
                Value::I64(REPEAT_PREVIOUS_FRAME_AFTER_US),
            ),
        ];
        if self.rung.optional_keys() {
            e.extend([
                // BITRATE_MODE_VBR
                ("bitrate-mode", Value::I32(1)),
                ("max-fps-to-encoder", Value::F32(self.fps as f32)),
                ("max-bframes", Value::I32(0)),
                // Realtime priority.
                ("priority", Value::I32(0)),
                ("operating-rate", Value::I32(fps)),
                ("latency", Value::I32(1)),
                // BT.709, limited range.
                ("color-standard", Value::I32(1)),
                ("color-range", Value::I32(2)),
            ]);
        }
        e
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(max_long_edge: u32, max_fps: u32, bitrate: u32) -> StreamParams {
        StreamParams {
            max_long_edge,
            max_fps,
            bitrate,
        }
    }

    fn get(e: &[(&str, Value)], k: &str) -> Option<Value> {
        e.iter().find(|(key, _)| *key == k).map(|(_, v)| *v)
    }

    #[test]
    fn full_rung_has_every_plan_key() {
        let s = EncoderSpec::new(Rung::Full, 1080, 2400, &StreamParams::default());
        assert_eq!(
            (s.width, s.height, s.fps, s.bitrate),
            (864, 1920, 60, 8_000_000)
        );
        let e = s.entries();
        for k in [
            "width",
            "height",
            "color-format",
            "bitrate",
            "bitrate-mode",
            "frame-rate",
            "max-fps-to-encoder",
            "i-frame-interval",
            "repeat-previous-frame-after",
            "max-bframes",
            "priority",
            "operating-rate",
            "latency",
            "color-standard",
            "color-range",
        ] {
            assert!(get(&e, k).is_some(), "missing {k}");
        }
        assert_eq!(get(&e, "color-format"), Some(Value::I32(0x7F00_0789)));
        assert_eq!(
            get(&e, "repeat-previous-frame-after"),
            Some(Value::I64(100_000))
        );
        assert_eq!(get(&e, "max-fps-to-encoder"), Some(Value::F32(60.0)));
        assert_eq!(get(&e, "color-range"), Some(Value::I32(2)));
    }

    #[test]
    fn required_rung_drops_optional_keys_but_keeps_repeat() {
        let e = EncoderSpec::new(Rung::Required, 1080, 2400, &StreamParams::default()).entries();
        assert_eq!(e.len(), 7);
        assert!(get(&e, "latency").is_none());
        assert!(get(&e, "bitrate-mode").is_none());
        assert!(get(&e, "repeat-previous-frame-after").is_some());
        assert_eq!(get(&e, "frame-rate"), Some(Value::I32(60)));
    }

    #[test]
    fn fallback_rungs_lower_fps_then_size() {
        let p = StreamParams::default();
        let s = EncoderSpec::new(Rung::Fps30, 1080, 2400, &p);
        assert_eq!((s.width, s.height, s.fps), (864, 1920, 30));
        let s = EncoderSpec::new(Rung::Cap1280, 1080, 2400, &p);
        assert_eq!(
            (s.width, s.height, s.fps, s.bitrate),
            (576, 1280, 30, 4_000_000)
        );
        // Landscape.
        let s = EncoderSpec::new(Rung::Cap1280, 2400, 1080, &p);
        assert_eq!((s.width, s.height), (1280, 576));
        // Uncapped client still gets capped on the last rung.
        let s = EncoderSpec::new(Rung::Cap1280, 1440, 3120, &params(0, 60, 20_000_000));
        assert_eq!((s.height, s.bitrate), (1280, 4_000_000));
    }

    #[test]
    fn fps_respects_client_and_encoder_caps() {
        let s = EncoderSpec::new(Rung::Full, 1080, 2400, &params(1920, 120, 8_000_000));
        assert_eq!(s.fps, 60);
        let s = EncoderSpec::new(Rung::Full, 1080, 2400, &params(1920, 24, 8_000_000));
        assert_eq!(s.fps, 24);
        let s = EncoderSpec::new(Rung::Fps30, 1080, 2400, &params(1920, 24, 8_000_000));
        assert_eq!(s.fps, 24);
    }

    #[test]
    fn ladder_is_ordered_and_deduplicated() {
        let l = EncoderSpec::ladder(1080, 2400, &StreamParams::default());
        let rungs: Vec<Rung> = l.iter().map(|s| s.rung).collect();
        assert_eq!(rungs, Rung::LADDER.to_vec());

        // Small display at 30 fps and 4 Mbps: Fps30 and Cap1280 repeat Required.
        let l = EncoderSpec::ladder(720, 1280, &params(1280, 30, 4_000_000));
        let rungs: Vec<Rung> = l.iter().map(|s| s.rung).collect();
        assert_eq!(rungs, vec![Rung::Full, Rung::Required]);
    }

    #[test]
    fn tiny_long_edge_keeps_the_aspect() {
        for max_long_edge in [16, 17, 100, 319] {
            let p = params(max_long_edge, 60, 4_000_000);
            for (w, h) in [(1080, 2400), (2400, 1080), (1440, 3200)] {
                let s = EncoderSpec::new(Rung::Full, w, h, &p);
                assert_eq!(s.width.max(s.height), MIN_ENCODE_LONG_EDGE);
                let (src, enc) = (w as f64 / h as f64, s.width as f64 / s.height as f64);
                assert!(
                    (src - enc).abs() / src < 0.15,
                    "{w}x{h} cap {max_long_edge} -> {}x{}",
                    s.width,
                    s.height
                );
            }
        }
        // A display already below the floor is not upscaled.
        let s = EncoderSpec::new(Rung::Full, 240, 320, &params(16, 60, 4_000_000));
        assert_eq!((s.width, s.height), (240, 320));
        // 0 still means "no cap".
        let s = EncoderSpec::new(Rung::Full, 1080, 2400, &params(0, 60, 8_000_000));
        assert_eq!((s.width, s.height), (1072, 2400));
    }

    #[test]
    fn sizes_are_multiples_of_16() {
        for (w, h) in [
            (1080, 2400),
            (1440, 3200),
            (720, 1600),
            (1080, 2340),
            (1179, 2556),
        ] {
            for s in EncoderSpec::ladder(w, h, &StreamParams::default()) {
                assert_eq!(s.width % 16, 0);
                assert_eq!(s.height % 16, 0);
                assert!(s.width.max(s.height) <= 1920);
            }
        }
    }
}
