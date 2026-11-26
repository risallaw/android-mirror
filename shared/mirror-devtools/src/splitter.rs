//! Annex-B elementary stream -> access units.

use std::fmt;
use std::ops::Range;
use std::path::Path;

use mirror_protocol::annexb::{
    extract_sps_pps, nal_ranges, nal_type, nals, NAL_IDR, NAL_PPS, NAL_SLICE, NAL_SPS,
};

use crate::sps::{parse_sps, SpsError, SpsInfo};

/// One access unit: a byte range of the source buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessUnit {
    /// Range in the original buffer, start codes included.
    pub range: Range<usize>,
    /// Contains an IDR slice.
    pub keyframe: bool,
}

/// Split an Annex-B stream into access units.
///
/// A new AU starts at a VCL NAL (type 1 or 5) with `first_mb_in_slice == 0`
/// (top bit of the first byte after the NAL header set) when the current AU
/// already holds a VCL NAL. Non-VCL NALs (SPS/PPS/SEI/AUD...) following the
/// last VCL NAL belong to the next AU. The ranges are contiguous and cover
/// the whole input (bytes before the first start code join the first AU), so
/// concatenating them reproduces the input exactly.
pub fn split_access_units(d: &[u8]) -> Vec<AccessUnit> {
    let mut out = Vec::new();
    let mut cur_start = 0usize;
    let mut has_vcl = false;
    let mut keyframe = false;
    // Start of the first non-VCL NAL seen after the current AU's last VCL.
    let mut pending: Option<usize> = None;
    for r in nal_ranges(d) {
        // Include the start code (3 bytes, or 4 with a leading zero byte).
        let mut start = r.start - 3;
        if start > 0 && d[start - 1] == 0 {
            start -= 1;
        }
        let ty = nal_type(&d[r.clone()]).unwrap_or(0);
        if ty == NAL_SLICE || ty == NAL_IDR {
            let first_mb0 = d.get(r.start + 1).is_some_and(|b| b & 0x80 != 0);
            if has_vcl && first_mb0 {
                let boundary = pending.unwrap_or(start);
                out.push(AccessUnit {
                    range: cur_start..boundary,
                    keyframe,
                });
                cur_start = boundary;
                keyframe = false;
            }
            has_vcl = true;
            keyframe |= ty == NAL_IDR;
            pending = None;
        } else if has_vcl && pending.is_none() && !matches!(ty, 10..=12) {
            pending = Some(start);
        }
    }
    if has_vcl || cur_start < d.len() {
        out.push(AccessUnit {
            range: cur_start..d.len(),
            keyframe,
        });
    }
    out
}

#[derive(Debug)]
pub enum StreamError {
    Io(std::io::Error),
    NoSpsPps,
    NoFrames,
    /// More than one distinct SPS or PPS: VIDEO_CONFIG carries one pair, so
    /// a stream that changes them midway would be mis-described.
    MultipleParameterSets,
    Sps(SpsError),
    /// Width or height does not fit the protocol's u16.
    TooLarge(u32, u32),
}

impl fmt::Display for StreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StreamError::Io(e) => write!(f, "{e}"),
            StreamError::NoSpsPps => write!(f, "no SPS/PPS found in stream"),
            StreamError::NoFrames => write!(
                f,
                "no IDR frame found in stream (streams that only use recovery-point \
                 SEIs / intra refresh are not supported; re-encode with IDR frames)"
            ),
            StreamError::MultipleParameterSets => write!(
                f,
                "stream changes its SPS/PPS midway (not supported; use a stream with \
                 one resolution and encoder configuration)"
            ),
            StreamError::Sps(e) => write!(f, "{e}"),
            StreamError::TooLarge(w, h) => write!(f, "{w}x{h} exceeds 65535"),
        }
    }
}

impl std::error::Error for StreamError {}

/// A parsed `.h264` file: bytes, access units, SPS/PPS and dimensions.
#[derive(Debug, Clone)]
pub struct H264Stream {
    pub data: Vec<u8>,
    pub aus: Vec<AccessUnit>,
    /// SPS NAL without start code.
    pub sps: Vec<u8>,
    /// PPS NAL without start code.
    pub pps: Vec<u8>,
    pub info: SpsInfo,
}

impl H264Stream {
    pub fn from_file(path: impl AsRef<Path>) -> Result<H264Stream, StreamError> {
        H264Stream::parse(std::fs::read(path).map_err(StreamError::Io)?)
    }

    pub fn parse(data: Vec<u8>) -> Result<H264Stream, StreamError> {
        let (sps, pps) = extract_sps_pps(&data).ok_or(StreamError::NoSpsPps)?;
        // Repeated identical parameter sets (e.g. before every IDR) are fine.
        let differs = nals(&data).any(|n| match nal_type(n) {
            Some(NAL_SPS) => n != sps.as_slice(),
            Some(NAL_PPS) => n != pps.as_slice(),
            _ => false,
        });
        if differs {
            return Err(StreamError::MultipleParameterSets);
        }
        let info = parse_sps(&sps).map_err(StreamError::Sps)?;
        if info.width > u16::MAX as u32 || info.height > u16::MAX as u32 {
            return Err(StreamError::TooLarge(info.width, info.height));
        }
        let aus = split_access_units(&data);
        if !aus.iter().any(|a| a.keyframe) {
            return Err(StreamError::NoFrames);
        }
        Ok(H264Stream {
            data,
            aus,
            sps,
            pps,
            info,
        })
    }

    /// SPS + PPS in Annex-B form (4-byte start codes), as in VIDEO_CONFIG.
    pub fn sps_pps_annexb(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(self.sps.len() + self.pps.len() + 8);
        for n in [&self.sps, &self.pps] {
            v.extend_from_slice(&[0, 0, 0, 1]);
            v.extend_from_slice(n);
        }
        v
    }

    pub fn au_bytes(&self, i: usize) -> &[u8] {
        &self.data[self.aus[i].range.clone()]
    }

    /// Index of the first keyframe AU at or after `from`.
    pub fn next_keyframe(&self, from: usize) -> Option<usize> {
        (from..self.aus.len()).find(|&i| self.aus[i].keyframe)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_split() {
        // AUD SPS PPS IDR(mb0) | SEI P(mb0) | P(mb0) with 3-byte codes mixed
        let mut d = vec![];
        d.extend([0, 0, 0, 1, 9, 0xf0]);
        d.extend([0, 0, 0, 1, 0x67, 1, 2]);
        d.extend([0, 0, 1, 0x68, 3]);
        d.extend([0, 0, 0, 1, 0x65, 0x88, 9]);
        d.extend([0, 0, 1, 0x65, 0x10, 9]); // second slice, same AU (mb != 0)
        d.extend([0, 0, 0, 1, 6, 5]); // SEI -> next AU
        d.extend([0, 0, 0, 1, 0x41, 0x80, 7]);
        d.extend([0, 0, 0, 1, 0x41, 0x80, 8]);
        let aus = split_access_units(&d);
        assert_eq!(aus.len(), 3);
        assert!(aus[0].keyframe && !aus[1].keyframe && !aus[2].keyframe);
        assert_eq!(aus[1].range.start, 6 + 7 + 5 + 7 + 6);
        let cat: Vec<u8> = aus
            .iter()
            .flat_map(|a| d[a.range.clone()].to_vec())
            .collect();
        assert_eq!(cat, d);
    }

    #[test]
    fn random_input_is_covered_contiguously() {
        let mut s = 0x2545_F491_4F6C_DD1Du64;
        let alphabet = [0u8, 0, 0, 1, 0x65, 0x41, 0x67, 6, 9, 0x80, 0x10, 3];
        for _ in 0..20_000 {
            let n = {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                s as usize % 64
            };
            let d: Vec<u8> = (0..n)
                .map(|_| {
                    s ^= s << 13;
                    s ^= s >> 7;
                    s ^= s << 17;
                    alphabet[s as usize % alphabet.len()]
                })
                .collect();
            let mut end = 0;
            for a in split_access_units(&d) {
                assert_eq!(a.range.start, end);
                end = a.range.end;
            }
            assert_eq!(end, if d.is_empty() { 0 } else { d.len() });
        }
    }

    const SPS: [u8; 27] = [
        0x67, 0x64, 0x00, 0x28, 0xAC, 0xD9, 0x40, 0x78, 0x02, 0x27, 0xE5, 0xC0, 0x44, 0x00, 0x00,
        0x03, 0x00, 0x04, 0x00, 0x00, 0x03, 0x00, 0xF0, 0x3C, 0x60, 0xC6, 0x58,
    ];

    fn nal(d: &mut Vec<u8>, n: &[u8]) {
        d.extend([0, 0, 0, 1]);
        d.extend(n);
    }

    #[test]
    fn repeated_parameter_sets_are_fine_changed_ones_are_not() {
        let mut d = Vec::new();
        for _ in 0..2 {
            nal(&mut d, &SPS);
            nal(&mut d, &[0x68, 0xCE, 0x3C, 0x80]);
            nal(&mut d, &[0x65, 0x88, 1]);
        }
        assert!(H264Stream::parse(d.clone()).is_ok());
        let mut other = SPS;
        other[3] = 0x29; // another level
        nal(&mut d, &other);
        nal(&mut d, &[0x65, 0x88, 2]);
        assert!(matches!(
            H264Stream::parse(d),
            Err(StreamError::MultipleParameterSets)
        ));
    }

    #[test]
    fn empty_input() {
        assert!(split_access_units(&[]).is_empty());
    }
}
