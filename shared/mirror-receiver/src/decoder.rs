//! Platform-neutral video decoder interface (PLAN.md §5).
//!
//! A platform crate (VideoToolbox on macOS, Media Foundation later on
//! Windows) implements [`VideoDecoder`]; the receiver's decode thread feeds
//! it one VIDEO_CONFIG and then Annex-B access units. Decoded pictures leave
//! as plain NV12 ([`Nv12Frame`]) through a [`FrameOutput`], so no platform
//! type crosses into this crate (PLAN.md §8).
//!
//! Plane buffers come from a small [`FramePool`] and are handed back by the
//! renderer after upload, so steady-state decoding does not allocate.

use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};

use mirror_protocol::VideoConfig;

/// One decoded picture in NV12 (8-bit 4:2:0, interleaved CbCr), BT.709
/// limited range.
///
/// `y` holds `height` rows of `y_stride` bytes (the first `width` of each are
/// pixels); `uv` holds `(height + 1) / 2` rows of `uv_stride` bytes with
/// `(width + 1) / 2` Cb/Cr pairs each.
#[derive(Clone, PartialEq, Eq)]
pub struct Nv12Frame {
    pub width: u32,
    pub height: u32,
    pub y: Vec<u8>,
    pub y_stride: u32,
    pub uv: Vec<u8>,
    pub uv_stride: u32,
    pub pts_us: u64,
}

impl fmt::Debug for Nv12Frame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Nv12Frame")
            .field("width", &self.width)
            .field("height", &self.height)
            .field("y_stride", &self.y_stride)
            .field("uv_stride", &self.uv_stride)
            .field("pts_us", &self.pts_us)
            .finish_non_exhaustive()
    }
}

impl Nv12Frame {
    /// Height of the chroma plane in rows.
    pub fn uv_height(&self) -> u32 {
        self.height.div_ceil(2)
    }

    /// Width of the chroma plane in Cb/Cr pairs.
    pub fn uv_width(&self) -> u32 {
        self.width.div_ceil(2)
    }

    /// True when both planes are large enough for the declared geometry
    /// (the renderer refuses anything else instead of reading out of bounds).
    pub fn is_consistent(&self) -> bool {
        let rows_ok = |len: usize, stride: u32, row: u32, rows: u32| {
            rows == 0
                || (stride >= row && (stride as u64) * (rows as u64 - 1) + row as u64 <= len as u64)
        };
        self.width > 0
            && self.height > 0
            && rows_ok(self.y.len(), self.y_stride, self.width, self.height)
            && rows_ok(
                self.uv.len(),
                self.uv_stride,
                self.uv_width() * 2,
                self.uv_height(),
            )
    }
}

/// Row alignment that lets wgpu upload a plane with one bulk copy
/// (`wgpu::COPY_BYTES_PER_ROW_ALIGNMENT`). Decoders should produce planes
/// with strides that are multiples of it when they copy anyway.
pub const UPLOAD_ROW_ALIGN: usize = 256;

/// Smallest multiple of [`UPLOAD_ROW_ALIGN`] that holds `row_bytes`.
pub fn aligned_stride(row_bytes: usize) -> usize {
    row_bytes.div_ceil(UPLOAD_ROW_ALIGN) * UPLOAD_ROW_ALIGN
}

/// Append `rows` rows of `row_bytes` from `src` (rows `src_stride` apart)
/// to `dst` at an [`aligned_stride`]; padding bytes are zero. Returns the
/// destination stride. Panics if `src` is too short.
pub fn copy_plane_aligned(
    src: &[u8],
    src_stride: usize,
    row_bytes: usize,
    rows: usize,
    dst: &mut Vec<u8>,
) -> usize {
    let stride = aligned_stride(row_bytes);
    dst.reserve(stride * rows);
    let pad = stride - row_bytes;
    for r in 0..rows {
        let start = r * src_stride;
        dst.extend_from_slice(&src[start..start + row_bytes]);
        dst.resize(dst.len() + pad, 0);
    }
    stride
}

/// Why a decoder call failed. The decode thread reacts the same way to every
/// error (drop until the next keyframe, ask the sender for one, except while
/// the current config is refused); the variants exist for logs. A decoder
/// that panics is replaced by a fresh one from the factory (see
/// [`crate::session`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// `decode` before a successful `configure`.
    NotConfigured,
    /// The VIDEO_CONFIG has no usable SPS/PPS, or the platform rejected it.
    BadConfig(String),
    /// The platform decoder failed (status code / message).
    Platform(String),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::NotConfigured => write!(f, "decoder not configured"),
            DecodeError::BadConfig(m) => write!(f, "bad video config: {m}"),
            DecodeError::Platform(m) => write!(f, "decoder error: {m}"),
        }
    }
}

impl std::error::Error for DecodeError {}

pub type Result<T, E = DecodeError> = std::result::Result<T, E>;

/// An H.264 decoder. Driven from one dedicated thread; never shared.
pub trait VideoDecoder: Send {
    /// New stream parameters (SPS/PPS in Annex-B in `cfg.sps_pps`). Called
    /// before the first frame and on every VIDEO_CONFIG (rotation, reconnect).
    /// Implementations may keep their session when the parameters did not
    /// change.
    fn configure(&mut self, cfg: &VideoConfig) -> Result<()>;

    /// Decode one Annex-B access unit. Decoded pictures go to the
    /// [`FrameOutput`] the decoder was created with, before or after this
    /// returns. After an error the caller drops frames until the next
    /// keyframe; the implementation should be ready to restart on it
    /// (recreating its session if needed).
    fn decode(&mut self, au: &[u8], pts_us: u64, key: bool) -> Result<()>;
}

/// Creates a decoder that emits into the given output. Called on the decode
/// thread once per session (the decoder survives reconnects; every
/// VIDEO_CONFIG reaches it through `configure`), and again only to replace a
/// decoder that panicked.
pub type DecoderFactory = Arc<dyn Fn(FrameOutput) -> Box<dyn VideoDecoder> + Send + Sync>;

/// Reusable plane buffers, shared by the decoder (takes) and the renderer
/// (gives back).
#[derive(Clone, Default)]
pub struct FramePool {
    free: Arc<Mutex<Vec<Vec<u8>>>>,
}

/// Buffers kept for reuse: two frames in flight (slot + renderer) plus slack.
const POOL_MAX: usize = 8;

impl FramePool {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, Vec<Vec<u8>>> {
        self.free.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// A zero-length buffer with capacity for at least `len` bytes (filled
    /// by the caller), reused when possible.
    pub fn take(&self, len: usize) -> Vec<u8> {
        let mut free = self.lock();
        // Best fit: a small (UV) request must not take the big (Y) buffer
        // and leave the next Y request to allocate.
        let fit = free
            .iter()
            .enumerate()
            .filter(|(_, b)| b.capacity() >= len)
            .min_by_key(|(_, b)| b.capacity())
            .map(|(i, _)| i);
        let mut buf = match fit {
            Some(i) => free.swap_remove(i),
            None => {
                free.pop(); // a too-small buffer would just be reallocated
                Vec::with_capacity(len)
            }
        };
        buf.clear();
        buf
    }

    /// Give a buffer back.
    pub fn give(&self, buf: Vec<u8>) {
        let mut free = self.lock();
        if free.len() < POOL_MAX && buf.capacity() > 0 {
            free.push(buf);
        }
    }

    /// Give both planes of a frame back.
    pub fn recycle(&self, frame: Nv12Frame) {
        self.give(frame.y);
        self.give(frame.uv);
    }

    /// Buffers currently free (tests, diagnostics).
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Where a decoder delivers pictures: the pool to allocate planes from and
/// the sink to emit finished frames to. Cheap to clone; `Send + Sync`, so a
/// platform callback thread may emit.
#[derive(Clone)]
pub struct FrameOutput {
    pool: FramePool,
    sink: Arc<dyn Fn(Nv12Frame) + Send + Sync>,
}

impl FrameOutput {
    pub fn new(pool: FramePool, sink: Arc<dyn Fn(Nv12Frame) + Send + Sync>) -> Self {
        FrameOutput { pool, sink }
    }

    pub fn pool(&self) -> &FramePool {
        &self.pool
    }

    /// Deliver a decoded picture.
    pub fn emit(&self, frame: Nv12Frame) {
        (self.sink)(frame);
    }
}

impl fmt::Debug for FrameOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FrameOutput").finish_non_exhaustive()
    }
}

/// Latest-frame-wins hand-off between the decode thread and the renderer.
/// A newer frame replaces an unrendered older one (which goes back to the
/// pool), so a slow display never builds a queue.
#[derive(Clone, Default)]
pub struct FrameSlot {
    inner: Arc<Mutex<Option<Nv12Frame>>>,
    pool: FramePool,
}

impl FrameSlot {
    pub fn new(pool: FramePool) -> Self {
        FrameSlot {
            inner: Arc::default(),
            pool,
        }
    }

    fn lock(&self) -> MutexGuard<'_, Option<Nv12Frame>> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Store `frame`; returns true when the slot was empty (the consumer
    /// needs a wake-up; otherwise one is already pending).
    pub fn put(&self, frame: Nv12Frame) -> bool {
        let old = self.lock().replace(frame);
        match old {
            Some(old) => {
                self.pool.recycle(old);
                false
            }
            None => true,
        }
    }

    pub fn take(&self) -> Option<Nv12Frame> {
        self.lock().take()
    }

    /// Drop any pending frame.
    pub fn clear(&self) {
        if let Some(old) = self.take() {
            self.pool.recycle(old);
        }
    }

    pub fn pool(&self) -> &FramePool {
        &self.pool
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(w: u32, h: u32, pts: u64) -> Nv12Frame {
        let ys = w.next_multiple_of(16);
        let uvs = ys;
        Nv12Frame {
            width: w,
            height: h,
            y: vec![16; (ys * h) as usize],
            y_stride: ys,
            uv: vec![128; (uvs * h.div_ceil(2)) as usize],
            uv_stride: uvs,
            pts_us: pts,
        }
    }

    #[test]
    fn consistent_frames_pass_and_short_planes_fail() {
        assert!(frame(1088, 2400, 0).is_consistent());
        assert!(frame(7, 5, 0).is_consistent(), "odd sizes");
        let mut f = frame(64, 64, 0);
        f.y.truncate(f.y.len() - 1);
        assert!(!f.is_consistent());
        let mut f = frame(64, 64, 0);
        f.uv_stride = 10; // narrower than 2 * 32
        assert!(!f.is_consistent());
        let mut f = frame(64, 64, 0);
        f.width = 0;
        assert!(!f.is_consistent());
    }

    #[test]
    fn last_row_may_omit_stride_padding() {
        let mut f = frame(10, 4, 0);
        f.y_stride = 16;
        f.y = vec![0; 16 * 3 + 10];
        assert!(f.is_consistent());
    }

    #[test]
    fn planes_are_restrided_to_upload_alignment() {
        assert_eq!(aligned_stride(1), 256);
        assert_eq!(aligned_stride(256), 256);
        assert_eq!(aligned_stride(1088), 1280);
        // 3 rows of 4 bytes, source stride 6.
        let src: Vec<u8> = (0..18).collect();
        let mut dst = vec![];
        let stride = copy_plane_aligned(&src, 6, 4, 3, &mut dst);
        assert_eq!(stride, 256);
        assert_eq!(dst.len(), 3 * 256);
        assert_eq!(&dst[..4], &[0, 1, 2, 3]);
        assert_eq!(&dst[256..260], &[6, 7, 8, 9]);
        assert_eq!(&dst[512..516], &[12, 13, 14, 15]);
        assert!(dst[4..256].iter().all(|&b| b == 0));
        let f = Nv12Frame {
            width: 4,
            height: 3,
            y: dst,
            y_stride: 256,
            uv: vec![0; 2 * 256],
            uv_stride: 256,
            pts_us: 0,
        };
        assert!(f.is_consistent());
    }

    #[test]
    fn slot_keeps_latest_and_recycles_older() {
        let pool = FramePool::new();
        let slot = FrameSlot::new(pool.clone());
        assert!(slot.put(frame(16, 16, 1)), "empty slot wants a wake-up");
        assert!(!slot.put(frame(16, 16, 2)), "wake-up already pending");
        assert_eq!(pool.len(), 2, "replaced frame's planes went back");
        assert_eq!(slot.take().map(|f| f.pts_us), Some(2));
        assert!(slot.take().is_none());
        assert!(slot.put(frame(16, 16, 3)));
        slot.clear();
        assert!(slot.take().is_none());
    }

    #[test]
    fn pool_reuses_large_enough_buffers_and_is_bounded() {
        let pool = FramePool::new();
        pool.give(Vec::with_capacity(100));
        let b = pool.take(50);
        assert!(b.capacity() >= 100 && b.is_empty());
        for _ in 0..20 {
            pool.give(Vec::with_capacity(10));
        }
        assert_eq!(pool.len(), POOL_MAX);
        let big = pool.take(1000);
        assert!(big.capacity() >= 1000);
        assert_eq!(pool.len(), POOL_MAX - 1, "dropped one too-small buffer");
        pool.give(Vec::new());
        assert_eq!(pool.len(), POOL_MAX - 1, "zero-capacity buffers ignored");
    }

    #[test]
    fn pool_takes_the_smallest_buffer_that_fits() {
        let pool = FramePool::new();
        pool.give(Vec::with_capacity(4096)); // Y
        pool.give(Vec::with_capacity(1024)); // UV
        let uv = pool.take(1000);
        assert!(
            uv.capacity() >= 1000 && uv.capacity() < 4096,
            "{}",
            uv.capacity()
        );
        let y = pool.take(4000);
        assert!(y.capacity() >= 4096);
        assert!(pool.is_empty(), "nothing was dropped or allocated");
    }

    #[test]
    fn output_emits_to_sink() {
        let got = Arc::new(Mutex::new(Vec::new()));
        let sink = {
            let got = got.clone();
            Arc::new(move |f: Nv12Frame| got.lock().unwrap().push(f.pts_us))
        };
        let out = FrameOutput::new(FramePool::new(), sink);
        out.clone().emit(frame(2, 2, 7));
        assert_eq!(*got.lock().unwrap(), vec![7]);
    }
}
