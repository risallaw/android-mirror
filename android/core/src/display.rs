//! Display geometry from Kotlin and the VIDEO_CONFIG built from it.

use mirror_protocol::VideoConfig;

use crate::format::EncoderSpec;

/// The captured display as reported by `nativeSetDisplay` (current
/// orientation, so width/height swap on rotation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DisplayInfo {
    pub width: u32,
    pub height: u32,
    /// `Surface.ROTATION_*` (0..=3).
    pub rotation: u8,
    pub dpi: u32,
}

impl DisplayInfo {
    /// Validate raw JNI values. `None` for non-positive or absurd sizes
    /// (the protocol carries display sizes as u16).
    pub fn from_raw(width: i32, height: i32, rotation: i32, dpi: i32) -> Option<Self> {
        let dim = |v: i32| u16::try_from(v).ok().filter(|v| *v > 0).map(u32::from);
        Some(DisplayInfo {
            width: dim(width)?,
            height: dim(height)?,
            rotation: rotation.rem_euclid(4) as u8,
            dpi: dpi.clamp(1, 10_000) as u32,
        })
    }

    /// VIDEO_CONFIG for this display encoded with `spec`.
    pub fn video_config(&self, spec: &EncoderSpec, sps_pps: Vec<u8>) -> VideoConfig {
        VideoConfig {
            width: spec.width as u16,
            height: spec.height as u16,
            display_width: self.width as u16,
            display_height: self.height as u16,
            rotation: self.rotation,
            sps_pps,
        }
    }
}

/// True if `d` starts with a 3- or 4-byte Annex-B start code.
fn has_start_code(d: &[u8]) -> bool {
    d.starts_with(&[0, 0, 1]) || d.starts_with(&[0, 0, 0, 1])
}

/// Append one parameter-set blob in Annex-B form (adds a start code if the
/// encoder delivered a bare NAL unit).
fn push_annexb(out: &mut Vec<u8>, nal: &[u8]) {
    if nal.is_empty() {
        return;
    }
    if !has_start_code(nal) {
        out.extend_from_slice(&[0, 0, 0, 1]);
    }
    out.extend_from_slice(nal);
}

/// SPS+PPS in Annex-B form from the output format's `csd-0` (SPS) and
/// `csd-1` (PPS). Android encoders put start codes in csd buffers, but be
/// lenient. Empty if `csd0` is empty.
pub fn sps_pps_from_csd(csd0: &[u8], csd1: Option<&[u8]>) -> Vec<u8> {
    let mut out = Vec::with_capacity(csd0.len() + csd1.map_or(0, |c| c.len()) + 8);
    if csd0.is_empty() {
        return out;
    }
    push_annexb(&mut out, csd0);
    if let Some(c) = csd1 {
        push_annexb(&mut out, c);
    }
    out
}

/// Normalise a codec-config output buffer (BUFFER_FLAG_CODEC_CONFIG) to
/// Annex-B. Empty if the buffer is empty.
pub fn sps_pps_from_config_buffer(buf: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(buf.len() + 4);
    push_annexb(&mut out, buf);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::{EncoderSpec, Rung};
    use mirror_sender::StreamParams;

    #[test]
    fn from_raw_validates() {
        assert_eq!(
            DisplayInfo::from_raw(1080, 2400, 0, 420),
            Some(DisplayInfo {
                width: 1080,
                height: 2400,
                rotation: 0,
                dpi: 420
            })
        );
        assert_eq!(
            DisplayInfo::from_raw(2400, 1080, 5, 420).unwrap().rotation,
            1
        );
        assert_eq!(
            DisplayInfo::from_raw(2400, 1080, -1, 420).unwrap().rotation,
            3
        );
        assert_eq!(DisplayInfo::from_raw(1, 1, 0, 0).unwrap().dpi, 1);
        assert!(DisplayInfo::from_raw(0, 2400, 0, 420).is_none());
        assert!(DisplayInfo::from_raw(-5, 2400, 0, 420).is_none());
        assert!(DisplayInfo::from_raw(70_000, 2400, 0, 420).is_none());
    }

    #[test]
    fn video_config_uses_encode_and_display_sizes() {
        let d = DisplayInfo::from_raw(2400, 1080, 1, 420).unwrap();
        let spec = EncoderSpec::new(Rung::Full, d.width, d.height, &StreamParams::default());
        let cfg = d.video_config(&spec, vec![0, 0, 0, 1, 0x67]);
        assert_eq!((cfg.width, cfg.height), (1920, 864));
        assert_eq!((cfg.display_width, cfg.display_height), (2400, 1080));
        assert_eq!(cfg.rotation, 1);
        assert_eq!(cfg.sps_pps, vec![0, 0, 0, 1, 0x67]);
    }

    #[test]
    fn csd_gets_start_codes() {
        assert_eq!(
            sps_pps_from_csd(&[0, 0, 0, 1, 0x67, 1], Some(&[0, 0, 0, 1, 0x68, 2])),
            vec![0, 0, 0, 1, 0x67, 1, 0, 0, 0, 1, 0x68, 2]
        );
        assert_eq!(
            sps_pps_from_csd(&[0x67, 1], Some(&[0x68, 2])),
            vec![0, 0, 0, 1, 0x67, 1, 0, 0, 0, 1, 0x68, 2]
        );
        assert_eq!(
            sps_pps_from_csd(&[0, 0, 1, 0x67], None),
            vec![0, 0, 1, 0x67]
        );
        assert!(sps_pps_from_csd(&[], Some(&[0x68])).is_empty());
        assert_eq!(sps_pps_from_config_buffer(&[0x67]), vec![0, 0, 0, 1, 0x67]);
        assert!(sps_pps_from_config_buffer(&[]).is_empty());
    }
}
