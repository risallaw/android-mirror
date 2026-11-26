//! Minimal H.264 SPS parser: just enough to get the coded picture size.

use std::fmt;

/// Result of [`parse_sps`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpsInfo {
    pub profile_idc: u8,
    pub level_idc: u8,
    pub chroma_format_idc: u32,
    /// Output width in pixels (after frame cropping).
    pub width: u32,
    /// Output height in pixels (after frame cropping).
    pub height: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpsError {
    /// Ran out of bits.
    Truncated,
    /// Not an SPS NAL, or an invalid field value.
    Invalid(&'static str),
}

impl fmt::Display for SpsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SpsError::Truncated => write!(f, "SPS truncated"),
            SpsError::Invalid(m) => write!(f, "invalid SPS: {m}"),
        }
    }
}

impl std::error::Error for SpsError {}

struct Bits {
    d: Vec<u8>,
    pos: usize,
}

impl Bits {
    /// `nal` without start code; skips the NAL header, removes emulation
    /// prevention bytes.
    fn new(nal: &[u8]) -> Bits {
        let mut d = Vec::with_capacity(nal.len());
        let mut zeros = 0;
        for &b in nal.iter().skip(1) {
            if zeros >= 2 && b == 3 {
                zeros = 0;
                continue;
            }
            zeros = if b == 0 { zeros + 1 } else { 0 };
            d.push(b);
        }
        Bits { d, pos: 0 }
    }
    fn bit(&mut self) -> Result<u32, SpsError> {
        let byte = *self.d.get(self.pos / 8).ok_or(SpsError::Truncated)?;
        let v = (byte >> (7 - self.pos % 8)) & 1;
        self.pos += 1;
        Ok(v as u32)
    }
    fn bits(&mut self, n: u32) -> Result<u32, SpsError> {
        let mut v = 0;
        for _ in 0..n {
            v = (v << 1) | self.bit()?;
        }
        Ok(v)
    }
    /// ue(v). At most 31 leading zeros: 32 would encode a value of at
    /// least 2^32 - 1, beyond every SPS field (the spec caps ue(v) at
    /// 2^32 - 2).
    fn ue(&mut self) -> Result<u32, SpsError> {
        let mut zeros = 0;
        while self.bit()? == 0 {
            zeros += 1;
            if zeros > 31 {
                return Err(SpsError::Invalid("exp-Golomb too long"));
            }
        }
        Ok(((1u64 << zeros) - 1 + self.bits(zeros)? as u64) as u32)
    }
    fn se(&mut self) -> Result<i32, SpsError> {
        let k = self.ue()? as i64;
        Ok(if k & 1 == 1 { (k + 1) / 2 } else { -(k / 2) } as i32)
    }
    fn skip_scaling_list(&mut self, size: usize) -> Result<(), SpsError> {
        // i64: a hostile delta_scale near i32::MAX would overflow i32 here.
        let (mut last, mut next) = (8i64, 8i64);
        for _ in 0..size {
            if next != 0 {
                next = (last + self.se()? as i64 + 256).rem_euclid(256);
            }
            if next != 0 {
                last = next;
            }
        }
        Ok(())
    }
}

/// Parse an SPS NAL unit (without start code, including the NAL header).
pub fn parse_sps(nal: &[u8]) -> Result<SpsInfo, SpsError> {
    if nal.first().map(|b| b & 0x1f) != Some(7) {
        return Err(SpsError::Invalid("not an SPS NAL"));
    }
    let mut b = Bits::new(nal);
    let profile_idc = b.bits(8)? as u8;
    b.bits(8)?; // constraint flags + reserved
    let level_idc = b.bits(8)? as u8;
    b.ue()?; // seq_parameter_set_id
    let mut chroma = 1;
    if matches!(
        profile_idc,
        100 | 110 | 122 | 244 | 44 | 83 | 86 | 118 | 128 | 138 | 139 | 134 | 135
    ) {
        chroma = b.ue()?;
        if chroma > 3 {
            return Err(SpsError::Invalid("chroma_format_idc"));
        }
        if chroma == 3 {
            b.bit()?; // separate_colour_plane_flag
        }
        b.ue()?; // bit_depth_luma_minus8
        b.ue()?; // bit_depth_chroma_minus8
        b.bit()?; // qpprime_y_zero_transform_bypass_flag
        if b.bit()? == 1 {
            let n = if chroma != 3 { 8 } else { 12 };
            for i in 0..n {
                if b.bit()? == 1 {
                    b.skip_scaling_list(if i < 6 { 16 } else { 64 })?;
                }
            }
        }
    }
    b.ue()?; // log2_max_frame_num_minus4
    match b.ue()? {
        0 => {
            b.ue()?;
        }
        1 => {
            b.bit()?;
            b.se()?;
            b.se()?;
            let n = b.ue()?;
            if n > 255 {
                return Err(SpsError::Invalid("num_ref_frames_in_pic_order_cnt_cycle"));
            }
            for _ in 0..n {
                b.se()?;
            }
        }
        _ => {}
    }
    b.ue()?; // max_num_ref_frames
    b.bit()?; // gaps_in_frame_num_value_allowed_flag
    let w_mbs = b.ue()?.checked_add(1).ok_or(SpsError::Invalid("width"))?;
    let h_map = b.ue()?.checked_add(1).ok_or(SpsError::Invalid("height"))?;
    let frame_mbs_only = b.bit()?;
    if frame_mbs_only == 0 {
        b.bit()?; // mb_adaptive_frame_field_flag
    }
    b.bit()?; // direct_8x8_inference_flag
    let (mut cl, mut cr, mut ct, mut cb) = (0u32, 0u32, 0u32, 0u32);
    if b.bit()? == 1 {
        cl = b.ue()?;
        cr = b.ue()?;
        ct = b.ue()?;
        cb = b.ue()?;
    }
    let (sub_w, sub_h) = match chroma {
        0 => (1, 1),
        1 => (2, 2),
        2 => (2, 1),
        _ => (1, 1),
    };
    let unit_x = sub_w;
    let unit_y = sub_h * (2 - frame_mbs_only);
    let full_w = w_mbs.checked_mul(16).ok_or(SpsError::Invalid("width"))?;
    let full_h = h_map
        .checked_mul(16 * (2 - frame_mbs_only))
        .ok_or(SpsError::Invalid("height"))?;
    let crop_w = (cl as u64 + cr as u64) * unit_x as u64;
    let crop_h = (ct as u64 + cb as u64) * unit_y as u64;
    if crop_w >= full_w as u64 || crop_h >= full_h as u64 {
        return Err(SpsError::Invalid("cropping exceeds picture"));
    }
    Ok(SpsInfo {
        profile_idc,
        level_idc,
        chroma_format_idc: chroma,
        width: full_w - crop_w as u32,
        height: full_h - crop_h as u32,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn high_profile_1080p_with_cropping() {
        let sps = [
            0x67, 0x64, 0x00, 0x28, 0xAC, 0xD9, 0x40, 0x78, 0x02, 0x27, 0xE5, 0xC0, 0x44, 0x00,
            0x00, 0x03, 0x00, 0x04, 0x00, 0x00, 0x03, 0x00, 0xF0, 0x3C, 0x60, 0xC6, 0x58,
        ];
        let i = parse_sps(&sps).unwrap();
        assert_eq!((i.width, i.height, i.profile_idc), (1920, 1080, 100));
    }

    /// MSB-first bit writer for building hostile SPS payloads.
    #[derive(Default)]
    struct W(Vec<bool>);
    impl W {
        fn bits(&mut self, v: u64, n: u32) {
            self.0.extend((0..n).rev().map(|i| v >> i & 1 == 1));
        }
        fn ue(&mut self, v: u64) {
            let n = 64 - (v + 1).leading_zeros() - 1;
            self.bits(0, n);
            self.bits(v + 1, n + 1);
        }
        fn bytes(&self) -> Vec<u8> {
            let mut out = vec![0x67];
            out.extend(self.0.chunks(8).map(|c| {
                c.iter()
                    .enumerate()
                    .fold(0u8, |a, (i, &b)| a | (u8::from(b) << (7 - i)))
            }));
            out
        }
    }

    fn xorshift(s: &mut u64) -> u64 {
        *s ^= *s << 13;
        *s ^= *s >> 7;
        *s ^= *s << 17;
        *s
    }

    #[test]
    fn huge_scaling_list_delta_does_not_overflow() {
        let mut w = W::default();
        w.bits(100, 8); // High profile
        w.bits(0, 8);
        w.bits(40, 8);
        w.ue(0); // sps id
        w.ue(1); // chroma_format_idc
        w.ue(0);
        w.ue(0);
        w.bits(0, 1); // transform bypass
        w.bits(1, 1); // scaling matrix present
        w.bits(1, 1); // list 0 present
        w.ue(4_294_967_293); // delta_scale = i32::MAX
                             // Must return (error: truncated), not panic on overflow.
        assert!(parse_sps(&w.bytes()).is_err());
    }

    #[test]
    fn random_input_never_panics() {
        let mut s = 0x9E37_79B9_7F4A_7C15u64;
        let seed = [
            0x67, 0x64, 0x00, 0x28, 0xAC, 0xD9, 0x40, 0x78, 0x02, 0x27, 0xE5, 0xC0, 0x44, 0x00,
            0x00, 0x03, 0x00, 0x04, 0x00, 0x00, 0x03, 0x00, 0xF0, 0x3C, 0x60, 0xC6, 0x58,
        ];
        for i in 0..200_000 {
            let mut v: Vec<u8> = if i % 2 == 0 {
                let n = xorshift(&mut s) as usize % 48;
                (0..n).map(|_| xorshift(&mut s) as u8).collect()
            } else {
                seed.to_vec()
            };
            if i % 2 == 1 {
                for _ in 0..1 + xorshift(&mut s) % 3 {
                    let k = xorshift(&mut s) as usize % v.len();
                    v[k] = if xorshift(&mut s).is_multiple_of(3) {
                        0
                    } else {
                        xorshift(&mut s) as u8
                    };
                }
            }
            if i % 4 < 2 {
                v.insert(0, 0x67);
            }
            let _ = parse_sps(&v);
        }
    }

    /// 32 leading zeros (value >= 2^32 - 1) is invalid, not `u32::MAX`
    /// with its suffix bits left unread.
    #[test]
    fn ue_with_32_leading_zeros_is_invalid() {
        let mut w = W::default();
        w.bits(0, 32);
        w.bits(1, 1);
        w.bits(0, 32);
        let mut b = Bits {
            d: w.bytes()[1..].to_vec(),
            pos: 0,
        };
        assert_eq!(b.ue(), Err(SpsError::Invalid("exp-Golomb too long")));
        let mut w = W::default();
        w.ue(u32::MAX as u64 - 1); // 31 zeros: the largest valid value
        let mut b = Bits {
            d: w.bytes()[1..].to_vec(),
            pos: 0,
        };
        assert_eq!(b.ue(), Ok(u32::MAX - 1));
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_sps(&[]).is_err());
        assert!(parse_sps(&[0x68, 1, 2]).is_err());
        assert_eq!(parse_sps(&[0x67, 0x64]), Err(SpsError::Truncated));
    }
}
