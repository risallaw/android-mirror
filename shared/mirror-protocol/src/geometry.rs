//! Encode sizing, aspect-fit letterboxing and normalised coordinate mapping.
//!
//! Normalised coordinates are `u16` in `0..=65535` spanning the video frame:
//! 0 is the first pixel (left/top edge) and 65535 the last (right/bottom edge).

/// Default maximum long edge for encoding.
pub const DEFAULT_MAX_LONG_EDGE: u32 = 1920;
/// Encoder dimension alignment.
pub const ALIGN: u32 = 16;
/// Largest normalised coordinate.
pub const NORM_MAX: u16 = u16::MAX;

/// Encode size for a display of `width`×`height`:
/// `scale = min(1, max_long_edge / long_edge)`; each dimension is scaled,
/// rounded, then floored to a multiple of 16 (minimum 16).
///
/// Returns `(16, 16)` for degenerate (zero) input. `max_long_edge == 0`
/// means "no cap" (scale 1).
pub fn encode_size(width: u32, height: u32, max_long_edge: u32) -> (u32, u32) {
    let long = width.max(height);
    let scale = if long == 0 || max_long_edge == 0 {
        1.0
    } else {
        (max_long_edge as f64 / long as f64).min(1.0)
    };
    let dim = |d: u32| {
        let r = (d as f64 * scale).round() as u32;
        (r / ALIGN * ALIGN).max(ALIGN)
    };
    (dim(width), dim(height))
}

/// Axis-aligned rectangle in view coordinates (e.g. logical window pixels).
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct Rect {
    pub x: f64,
    pub y: f64,
    pub w: f64,
    pub h: f64,
}

impl Rect {
    /// True unless both sides are positive and finite (NaN counts as empty).
    fn is_empty(&self) -> bool {
        !(is_positive(self.w) && is_positive(self.h))
    }

    pub fn contains(&self, px: f64, py: f64) -> bool {
        px >= self.x && py >= self.y && px <= self.x + self.w && py <= self.y + self.h
    }
}

fn is_positive(v: f64) -> bool {
    v > 0.0 && v.is_finite()
}

/// Largest rect with the content's aspect ratio that fits in the view,
/// centred (letterbox / pillarbox). Zero-sized content or a view that is not
/// positive and finite yields an empty rect.
pub fn fit_rect(content_w: u32, content_h: u32, view_w: f64, view_h: f64) -> Rect {
    if content_w == 0 || content_h == 0 || !is_positive(view_w) || !is_positive(view_h) {
        return Rect::default();
    }
    let (cw, ch) = (content_w as f64, content_h as f64);
    // Compare aspect ratios by cross-multiplication and set the constrained
    // axis exactly, so the fitted edge has no rounding error.
    let (w, h) = if view_w * ch <= view_h * cw {
        (view_w, ch * view_w / cw)
    } else {
        (cw * view_h / ch, view_h)
    };
    Rect {
        x: (view_w - w) / 2.0,
        y: (view_h - h) / 2.0,
        w,
        h,
    }
}

/// Normalised coordinate -> integer pixel in `0..size` (0 maps to 0, 65535
/// to `size-1`), rounding to nearest (PROTOCOL.md "Coordinates").
pub fn norm_to_px(n: u16, size: u32) -> u32 {
    if size <= 1 {
        return 0;
    }
    let num = n as u64 * (size as u64 - 1);
    ((num + NORM_MAX as u64 / 2) / NORM_MAX as u64) as u32
}

/// Fractional `0.0..=1.0` -> normalised (clamped).
pub fn unit_to_norm(f: f64) -> u16 {
    (f.clamp(0.0, 1.0) * NORM_MAX as f64).round() as u16
}

/// Map a point in view coordinates to normalised video coordinates, given the
/// aspect-fit rect the video is drawn in. Returns `None` for points in the
/// letterbox (outside `rect`) or for an empty rect.
pub fn view_to_norm(rect: &Rect, px: f64, py: f64) -> Option<(u16, u16)> {
    if rect.is_empty() || !rect.contains(px, py) {
        return None;
    }
    Some((
        unit_to_norm((px - rect.x) / rect.w),
        unit_to_norm((py - rect.y) / rect.h),
    ))
}

/// Like [`view_to_norm`] but clamps points outside the rect onto its edge
/// (useful for drags that leave the video area). `None` for an empty rect.
pub fn view_to_norm_clamped(rect: &Rect, px: f64, py: f64) -> Option<(u16, u16)> {
    if rect.is_empty() {
        return None;
    }
    Some((
        unit_to_norm((px - rect.x) / rect.w),
        unit_to_norm((py - rect.y) / rect.h),
    ))
}
