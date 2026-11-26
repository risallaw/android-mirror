//! H.264 Annex-B utilities.

use std::ops::Range;

pub const NAL_SLICE: u8 = 1;
pub const NAL_IDR: u8 = 5;
pub const NAL_SPS: u8 = 7;
pub const NAL_PPS: u8 = 8;
pub const NAL_AUD: u8 = 9;

/// Byte ranges of NAL units (start codes excluded) in an Annex-B buffer.
/// Accepts 3-byte (`00 00 01`) and 4-byte (`00 00 00 01`) start codes.
/// Trailing zero bytes before the next start code (`trailing_zero_8bits`)
/// are excluded; empty NALs are dropped. Bytes before the first start code
/// are ignored.
pub fn nal_ranges(d: &[u8]) -> Vec<Range<usize>> {
    NalRanges::new(d).collect()
}

/// The NAL slices themselves (see [`nal_ranges`]), found lazily: no allocation.
pub fn nals(d: &[u8]) -> impl Iterator<Item = &[u8]> {
    NalRanges::new(d).map(move |r| &d[r])
}

/// Lazy scanner behind [`nal_ranges`] and [`nals`].
struct NalRanges<'a> {
    d: &'a [u8],
    /// Scan position.
    i: usize,
    /// Start of the NAL being scanned (just past its start code).
    start: Option<usize>,
}

impl<'a> NalRanges<'a> {
    fn new(d: &'a [u8]) -> Self {
        NalRanges {
            d,
            i: 0,
            start: None,
        }
    }

    /// `s..e` without trailing zero bytes; `None` if that leaves it empty.
    fn trimmed(&self, s: usize, mut e: usize) -> Option<Range<usize>> {
        while e > s && self.d[e - 1] == 0 {
            e -= 1;
        }
        (e > s).then_some(s..e)
    }
}

impl Iterator for NalRanges<'_> {
    type Item = Range<usize>;

    fn next(&mut self) -> Option<Range<usize>> {
        let d = self.d;
        while self.i + 3 <= d.len() {
            let i = self.i;
            let sc = if d[i..].starts_with(&[0, 0, 1]) {
                3
            } else if d[i..].starts_with(&[0, 0, 0, 1]) {
                4
            } else {
                0
            };
            if sc == 0 {
                self.i += 1;
                continue;
            }
            self.i += sc;
            if let Some(r) = self.start.replace(i + sc).and_then(|s| self.trimmed(s, i)) {
                return Some(r);
            }
        }
        // End of input: the last NAL runs to the end.
        let s = self.start.take()?;
        self.i = d.len();
        self.trimmed(s, d.len())
    }
}

/// `nal_unit_type` (low 5 bits of the first byte); `None` for an empty NAL.
pub fn nal_type(nal: &[u8]) -> Option<u8> {
    nal.first().map(|b| b & 0x1f)
}

/// Convert an Annex-B access unit to AVCC (4-byte big-endian length prefixes),
/// dropping SPS (7), PPS (8) and AUD (9) NALs, which live in the format
/// description instead.
pub fn annexb_to_avcc(d: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(d.len() + 16);
    for nal in nals(d) {
        if matches!(nal_type(nal), Some(NAL_SPS | NAL_PPS | NAL_AUD)) {
            continue;
        }
        out.extend_from_slice(&(nal.len() as u32).to_be_bytes());
        out.extend_from_slice(nal);
    }
    out
}

/// First SPS and first PPS NAL (without start codes), if both are present.
pub fn extract_sps_pps(d: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let mut sps = None;
    let mut pps = None;
    for nal in nals(d) {
        match nal_type(nal) {
            Some(NAL_SPS) if sps.is_none() => sps = Some(nal.to_vec()),
            Some(NAL_PPS) if pps.is_none() => pps = Some(nal.to_vec()),
            _ => {}
        }
    }
    Some((sps?, pps?))
}
