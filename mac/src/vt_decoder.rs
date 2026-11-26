//! H.264 decoding with VideoToolbox (`VTDecompressionSession`), PLAN.md §5.
//!
//! - `configure`: SPS/PPS from VIDEO_CONFIG →
//!   `CMVideoFormatDescriptionCreateFromH264ParameterSets` (NAL length 4) →
//!   a session that outputs `kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange`
//!   (NV12, video range) with `kVTDecompressionPropertyKey_RealTime`. The
//!   session is kept when the parameter sets did not change (reconnect).
//! - `decode`: Annex-B → AVCC written straight into a CoreMedia-owned
//!   `CMBlockBuffer` (no intermediate buffer, nothing borrowed from the
//!   caller) → `CMSampleBuffer` → synchronous `VTDecompressionSessionDecodeFrame`;
//!   the output callback copies both planes (with strides) into pooled
//!   buffers and emits an [`Nv12Frame`].
//! - On any error the session is torn down and rebuilt from the stored
//!   parameter sets on the next call; the caller's `FrameGate` drops frames
//!   and asks the phone for a keyframe meanwhile.
//!
//! All unsafe code of the decoder lives in this file.

use std::ffi::c_void;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr::{self, NonNull};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

use mirror_protocol::annexb::{extract_sps_pps, nal_type, nals, NAL_AUD, NAL_PPS, NAL_SPS};
use mirror_protocol::VideoConfig;
use mirror_receiver::decoder::{
    aligned_stride, copy_plane_aligned, DecodeError, FrameOutput, Nv12Frame, Result, VideoDecoder,
};
use mirror_receiver::session::{LogLimiter, LOG_INTERVAL};
use objc2_core_foundation::{CFBoolean, CFDictionary, CFNumber, CFRetained, CFString, CFType};
use objc2_core_media::{
    kCMBlockBufferAssureMemoryNowFlag, CMBlockBuffer, CMFormatDescription, CMSampleBuffer,
    CMSampleTimingInfo, CMTime, CMTimeFlags, CMVideoFormatDescriptionCreateFromH264ParameterSets,
    CMVideoFormatDescriptionGetDimensions,
};
use objc2_core_video::{
    kCVPixelBufferPixelFormatTypeKey, kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange,
    CVImageBuffer, CVPixelBuffer, CVPixelBufferGetBaseAddressOfPlane,
    CVPixelBufferGetBytesPerRowOfPlane, CVPixelBufferGetHeight, CVPixelBufferGetHeightOfPlane,
    CVPixelBufferGetPixelFormatType, CVPixelBufferGetWidth, CVPixelBufferGetWidthOfPlane,
    CVPixelBufferLockBaseAddress, CVPixelBufferLockFlags, CVPixelBufferUnlockBaseAddress,
};
use objc2_video_toolbox::{
    kVTDecompressionPropertyKey_RealTime, VTDecodeFrameFlags, VTDecodeInfoFlags,
    VTDecompressionOutputCallbackRecord, VTDecompressionSession, VTSessionSetProperty,
};

/// `CMTime` timescale for our microsecond timestamps.
const US_TIMESCALE: i32 = 1_000_000;

/// Largest accepted picture side, in pixels.
const MAX_SIDE: u32 = 8192;
/// Largest accepted picture area: H.264 level 6.2 `MaxFS` (139 264
/// macroblocks of 16x16). Bounds the pooled plane memory a hostile
/// sender can make us allocate per frame (~53 MB of NV12).
const MAX_PIXELS: u64 = 139_264 * 256;

/// True when a `width` x `height` picture is within what we decode.
fn dimensions_ok(width: u32, height: u32) -> bool {
    (1..=MAX_SIDE).contains(&width)
        && (1..=MAX_SIDE).contains(&height)
        && u64::from(width) * u64::from(height) <= MAX_PIXELS
}

/// State shared with the output callback. Boxed so its address is stable
/// for the session's lifetime (it is the callback's refcon).
struct CallbackCtx {
    output: FrameOutput,
    /// Last non-zero status reported to the callback (0 = none).
    status: AtomicI32,
}

/// A live decompression session and what it was built from.
struct Session {
    session: CFRetained<VTDecompressionSession>,
    format: CFRetained<CMFormatDescription>,
    /// Owned `Box<CallbackCtx>`, freed in `Drop` after `invalidate`.
    ctx: NonNull<CallbackCtx>,
}

// SAFETY: VideoToolbox sessions, format descriptions and our callback
// context may be used from any thread as long as calls are not concurrent.
// A `Session` is owned by one `VtDecoder`, which is only driven through
// `&mut self` from the decode thread; the callback only reads `ctx` (its
// `FrameOutput` is `Send + Sync`, `status` is atomic).
unsafe impl Send for Session {}

impl Drop for Session {
    fn drop(&mut self) {
        // SAFETY: waiting drains any in-flight frame (each `decode` already
        // waits, so this is normally a no-op), and invalidate stops the
        // session so no further callbacks run; only then is the context
        // freed (allocated by `Box::into_raw` in `Session::new`, freed
        // exactly once here).
        unsafe {
            self.session.wait_for_asynchronous_frames();
            self.session.invalidate();
            drop(Box::from_raw(self.ctx.as_ptr()));
        }
    }
}

fn os_err(what: &str, status: i32) -> DecodeError {
    DecodeError::Platform(format!("{what} failed (OSStatus {status})"))
}

/// Take ownership of the object a CoreFoundation `Create` call wrote to its
/// out parameter. On a non-zero `status` the object is released instead of
/// leaked, whatever the call left in the out parameter.
///
/// # Safety
/// `ptr` is null or a +1 retained object from a `Create`-rule out parameter.
unsafe fn take_created<T: objc2_core_foundation::Type>(
    ptr: *mut T,
    status: i32,
) -> Option<CFRetained<T>> {
    // SAFETY: per the contract above, we own one retain count of `ptr`.
    let owned = NonNull::new(ptr).map(|p| unsafe { CFRetained::from_raw(p) });
    if status == 0 {
        owned
    } else {
        None // dropping `owned` (if any) releases it
    }
}

/// Rate-limited log line for per-frame / per-rebuild conditions (a broken
/// stream would otherwise print one line per frame).
fn log_limited(msg: impl FnOnce() -> String) {
    static LIMITER: OnceLock<Mutex<LogLimiter>> = OnceLock::new();
    let limiter = LIMITER.get_or_init(|| Mutex::new(LogLimiter::new(LOG_INTERVAL)));
    let n = limiter
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .check(Instant::now());
    if let Some(n) = n {
        eprintln!("VideoToolbox: {} ({n} similar suppressed)", msg());
    }
}

/// True for the one pixel format the renderer's shader decodes (BT.709
/// limited range). The session asks VideoToolbox for it, so anything else
/// (notably full range) would be shown with wrong levels: refuse it.
fn format_is_renderable(fmt: u32) -> bool {
    fmt == kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange
}

impl Session {
    fn new(sps: &[u8], pps: &[u8], output: &FrameOutput) -> Result<Session> {
        if sps.is_empty() || pps.is_empty() {
            return Err(DecodeError::BadConfig("empty SPS or PPS".into()));
        }
        let format = format_description(sps, pps)?;
        // SAFETY: `format` is a valid video format description.
        let dims = unsafe { CMVideoFormatDescriptionGetDimensions(&format) };
        let (w, h) = (
            u32::try_from(dims.width).unwrap_or(0),
            u32::try_from(dims.height).unwrap_or(0),
        );
        if !dimensions_ok(w, h) {
            return Err(DecodeError::BadConfig(format!(
                "unsupported picture size {}x{}",
                dims.width, dims.height
            )));
        }

        let ctx = Box::into_raw(Box::new(CallbackCtx {
            output: output.clone(),
            status: AtomicI32::new(0),
        }));
        // SAFETY: `ctx` came from Box::into_raw just above and is non-null.
        let ctx = unsafe { NonNull::new_unchecked(ctx) };
        let free_ctx = || {
            // SAFETY: the session was not created, so nothing else refers
            // to `ctx`; it is freed exactly once on this error path.
            unsafe { drop(Box::from_raw(ctx.as_ptr())) }
        };

        let record = VTDecompressionOutputCallbackRecord {
            decompressionOutputCallback: Some(output_callback),
            decompressionOutputRefCon: ctx.as_ptr().cast(),
        };
        // Destination: NV12, video range.
        let pixel_format =
            CFNumber::new_i32(kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange as i32);
        // SAFETY: reading an immutable CFString constant exported by CoreVideo.
        let key: &CFString = unsafe { kCVPixelBufferPixelFormatTypeKey };
        let attrs = CFDictionary::<CFString, CFNumber>::from_slices(&[key], &[&pixel_format]);

        let mut raw: *mut VTDecompressionSession = ptr::null_mut();
        // SAFETY: all references are valid CF objects for the call; `record`
        // is a valid struct read during the call; `raw` is a valid out
        // pointer. On success we own one retain count of the session.
        let status = unsafe {
            VTDecompressionSession::create(
                None,
                &format,
                None,
                Some(attrs.as_opaque()),
                &record,
                NonNull::from(&mut raw),
            )
        };
        // SAFETY: `create` wrote a +1 retained session or null (Create rule).
        let Some(session) = (unsafe { take_created(raw, status) }) else {
            free_ctx();
            return Err(os_err("VTDecompressionSessionCreate", status));
        };

        // Low latency: decode each frame as soon as possible.
        let real_time: &CFType = CFBoolean::new(true).as_ref();
        let vt_session: &CFType = (*session).as_ref();
        // SAFETY: valid session and property key/value; RealTime takes a CFBoolean.
        let status = unsafe {
            VTSessionSetProperty(
                vt_session,
                kVTDecompressionPropertyKey_RealTime,
                Some(real_time),
            )
        };
        if status != 0 {
            // Not fatal: older decoders may not support it.
            log_limited(|| format!("RealTime property not set (OSStatus {status})"));
        }
        Ok(Session {
            session,
            format,
            ctx,
        })
    }

    fn ctx(&self) -> &CallbackCtx {
        // SAFETY: `ctx` is valid until `Drop`, and only shared references
        // to it are ever created.
        unsafe { self.ctx.as_ref() }
    }

    /// Decode one Annex-B access unit synchronously. `Ok` without decoding
    /// when it holds nothing but parameter sets / AUD.
    fn decode(&self, au: &[u8], pts_us: u64) -> Result<()> {
        let Some((block, len)) = avcc_block(au)? else {
            return Ok(());
        };
        let pts = CMTime {
            value: i64::try_from(pts_us).unwrap_or(i64::MAX),
            timescale: US_TIMESCALE,
            flags: CMTimeFlags::Valid,
            epoch: 0,
        };
        let invalid = CMTime {
            value: 0,
            timescale: 0,
            flags: CMTimeFlags::empty(),
            epoch: 0,
        };
        let timing = CMSampleTimingInfo {
            duration: invalid,
            presentationTimeStamp: pts,
            decodeTimeStamp: invalid,
        };
        let mut sample: *mut CMSampleBuffer = ptr::null_mut();
        // SAFETY: valid block buffer and format description; one sample of
        // `len` bytes with one timing entry; `sample` is a valid out pointer.
        let status = unsafe {
            CMSampleBuffer::create_ready(
                None,
                Some(&block),
                Some(&self.format),
                1,
                1,
                &timing,
                1,
                &len,
                NonNull::from(&mut sample),
            )
        };
        // SAFETY: `create_ready` wrote a +1 retained sample or null.
        let Some(sample) = (unsafe { take_created(sample, status) }) else {
            return Err(os_err("CMSampleBufferCreateReady", status));
        };

        self.ctx().status.store(0, Ordering::Relaxed);
        let mut info = VTDecodeInfoFlags::empty();
        // SAFETY: valid session and sample buffer; flags 0 = synchronous
        // decode (the callback runs before this returns); the frame refcon
        // is unused (null); `info` is a valid out pointer.
        let status = unsafe {
            self.session
                .decode_frame(&sample, VTDecodeFrameFlags(0), ptr::null_mut(), &mut info)
        };
        // SAFETY: valid session. Makes sure no callback still reads the
        // sample's memory after we return.
        let wait = unsafe { self.session.wait_for_asynchronous_frames() };
        if status != 0 {
            return Err(os_err("VTDecompressionSessionDecodeFrame", status));
        }
        if wait != 0 {
            return Err(os_err(
                "VTDecompressionSessionWaitForAsynchronousFrames",
                wait,
            ));
        }
        match self.ctx().status.load(Ordering::Relaxed) {
            0 => Ok(()),
            s => Err(os_err("decode callback", s)),
        }
    }
}

/// True for the parameter-set / delimiter NALs that live in the format
/// description instead of the sample.
fn is_parameter_nal(nal: &[u8]) -> bool {
    matches!(nal_type(nal), Some(NAL_SPS | NAL_PPS | NAL_AUD))
}

/// Bytes the AVCC form of `au` takes: a 4-byte length per NAL, parameter
/// sets and AUD dropped (they live in the format description).
fn avcc_len(au: &[u8]) -> usize {
    nals(au)
        .filter(|n| !is_parameter_nal(n))
        .map(|n| 4 + n.len())
        .sum()
}

/// Convert an Annex-B access unit to AVCC inside a new CoreMedia-owned
/// `CMBlockBuffer`: the length prefixes and NALs are written straight into
/// CoreMedia's memory, so there is no per-frame Rust allocation and the
/// block never borrows the caller's bytes (which would have to outlive
/// whatever VideoToolbox does with the buffer). Returns the block and its
/// length, or `None` when nothing is left after dropping the parameter sets.
fn avcc_block(au: &[u8]) -> Result<Option<(CFRetained<CMBlockBuffer>, usize)>> {
    let total = avcc_len(au);
    if total == 0 {
        return Ok(None);
    }
    let mut raw: *mut CMBlockBuffer = ptr::null_mut();
    // SAFETY: a null memory block with the default allocator and
    // `AssureMemoryNow` makes CoreMedia allocate and own `total` bytes now;
    // `raw` is a valid out pointer.
    let status = unsafe {
        CMBlockBuffer::create_with_memory_block(
            None,
            ptr::null_mut(),
            total,
            None,
            ptr::null(),
            0,
            total,
            kCMBlockBufferAssureMemoryNowFlag,
            NonNull::from(&mut raw),
        )
    };
    // SAFETY: Create rule: a +1 retained buffer or null.
    let block = unsafe { take_created(raw, status) }
        .ok_or_else(|| os_err("CMBlockBufferCreateWithMemoryBlock", status))?;
    let mut at = 0;
    let mut put = |bytes: &[u8]| -> Result<()> {
        let src = NonNull::from(bytes).cast();
        // SAFETY: `src` is `bytes.len()` readable bytes; the destination
        // range `at..at + len` lies inside the `total` bytes allocated.
        let status = unsafe { CMBlockBuffer::replace_data_bytes(src, &block, at, bytes.len()) };
        if status != 0 {
            return Err(os_err("CMBlockBufferReplaceDataBytes", status));
        }
        at += bytes.len();
        Ok(())
    };
    for nal in nals(au).filter(|n| !is_parameter_nal(n)) {
        put(&(nal.len() as u32).to_be_bytes())?;
        put(nal)?;
    }
    Ok(Some((block, total)))
}

/// Build an H.264 format description from one SPS and one PPS (no start codes).
fn format_description(sps: &[u8], pps: &[u8]) -> Result<CFRetained<CMFormatDescription>> {
    let ptrs = [NonNull::from(&sps[0]), NonNull::from(&pps[0])];
    let sizes = [sps.len(), pps.len()];
    let mut out: *const CMFormatDescription = ptr::null();
    // SAFETY: two parameter sets with matching pointer/size arrays that
    // outlive the call (CoreMedia copies them); NAL length size 4 matches
    // our AVCC conversion; `out` is a valid out pointer.
    let status = unsafe {
        CMVideoFormatDescriptionCreateFromH264ParameterSets(
            None,
            2,
            NonNull::from(&ptrs[0]),
            NonNull::from(&sizes[0]),
            4,
            NonNull::from(&mut out),
        )
    };
    // SAFETY: the call wrote a +1 retained description or null (Create rule).
    match unsafe { take_created(out.cast_mut(), status) } {
        Some(f) => Ok(f),
        None => Err(DecodeError::BadConfig(format!(
            "CMVideoFormatDescriptionCreateFromH264ParameterSets failed (OSStatus {status})"
        ))),
    }
}

/// VideoToolbox output callback (C ABI). Never unwinds into VideoToolbox.
unsafe extern "C-unwind" fn output_callback(
    refcon: *mut c_void,
    _source_frame_refcon: *mut c_void,
    status: i32,
    flags: VTDecodeInfoFlags,
    image: *mut CVImageBuffer,
    pts: CMTime,
    _duration: CMTime,
) {
    if refcon.is_null() {
        return;
    }
    // SAFETY: `refcon` is the `CallbackCtx` registered with this session;
    // it stays valid until the session is invalidated (see `Session::drop`).
    let ctx = unsafe { &*refcon.cast::<CallbackCtx>() };
    let result = catch_unwind(AssertUnwindSafe(|| {
        if status != 0 {
            return status;
        }
        if flags.contains(VTDecodeInfoFlags::FrameDropped) {
            return 0;
        }
        let Some(image) = NonNull::new(image) else {
            return -1;
        };
        // SAFETY: VideoToolbox passes a valid pixel buffer for the duration
        // of the callback when status is 0 (we do not keep it).
        let pb: &CVPixelBuffer = unsafe { image.as_ref() };
        let pts_us = if pts.flags.contains(CMTimeFlags::Valid) && pts.timescale == US_TIMESCALE {
            u64::try_from(pts.value).unwrap_or(0)
        } else {
            0
        };
        match copy_nv12(pb, pts_us, &ctx.output) {
            Some(frame) => {
                ctx.output.emit(frame);
                0
            }
            None => -2,
        }
    }));
    let code = result.unwrap_or(-3);
    if code != 0 {
        ctx.status.store(code, Ordering::Relaxed);
    }
}

/// Copy an NV12 pixel buffer (locked here, read-only) into pooled planes.
fn copy_nv12(pb: &CVPixelBuffer, pts_us: u64, output: &FrameOutput) -> Option<Nv12Frame> {
    let fmt = CVPixelBufferGetPixelFormatType(pb);
    if !format_is_renderable(fmt) {
        log_limited(|| format!("unexpected pixel format {fmt:#x}"));
        return None;
    }
    let width = u32::try_from(CVPixelBufferGetWidth(pb)).ok()?;
    let height = u32::try_from(CVPixelBufferGetHeight(pb)).ok()?;
    if !dimensions_ok(width, height) {
        return None;
    }

    // SAFETY: valid pixel buffer; read-only lock, balanced by the unlock below.
    if unsafe { CVPixelBufferLockBaseAddress(pb, CVPixelBufferLockFlags::ReadOnly) } != 0 {
        return None;
    }
    // Planes are re-strided to `UPLOAD_ROW_ALIGN` so the renderer's texture
    // upload is one bulk copy instead of a row-by-row restage on the UI thread.
    let plane = |i: usize, bytes_per_px: usize| -> Option<(Vec<u8>, u32)> {
        let base = CVPixelBufferGetBaseAddressOfPlane(pb, i);
        let stride = CVPixelBufferGetBytesPerRowOfPlane(pb, i);
        let rows = CVPixelBufferGetHeightOfPlane(pb, i);
        let row_bytes = CVPixelBufferGetWidthOfPlane(pb, i).checked_mul(bytes_per_px)?;
        if base.is_null() || stride < row_bytes || rows == 0 {
            return None;
        }
        let len = stride.checked_mul(rows)?;
        // SAFETY: while the base address is locked, plane `i` is readable
        // for `bytes_per_row * height_of_plane` bytes starting at `base`.
        let src = unsafe { std::slice::from_raw_parts(base.cast::<u8>(), len) };
        let mut buf = output
            .pool()
            .take(aligned_stride(row_bytes).checked_mul(rows)?);
        let dst_stride = copy_plane_aligned(src, stride, row_bytes, rows, &mut buf);
        Some((buf, u32::try_from(dst_stride).ok()?))
    };
    let (y, uv) = (plane(0, 1), plane(1, 2));
    // SAFETY: balances the lock above with the same flags.
    unsafe { CVPixelBufferUnlockBaseAddress(pb, CVPixelBufferLockFlags::ReadOnly) };

    let ((y, y_stride), (uv, uv_stride)) = match (y, uv) {
        (Some(y), Some(uv)) => (y, uv),
        (y, uv) => {
            // Hand a plane that did copy back to the pool.
            for (buf, _) in [y, uv].into_iter().flatten() {
                output.pool().give(buf);
            }
            return None;
        }
    };
    let frame = Nv12Frame {
        width,
        height,
        y,
        y_stride,
        uv,
        uv_stride,
        pts_us,
    };
    if frame.is_consistent() {
        Some(frame)
    } else {
        output.pool().recycle(frame);
        None
    }
}

/// [`VideoDecoder`] backed by VideoToolbox.
pub struct VtDecoder {
    output: FrameOutput,
    /// Parameter sets of the current stream (kept to rebuild after errors).
    params: Option<(Vec<u8>, Vec<u8>)>,
    session: Option<Session>,
}

impl VtDecoder {
    pub fn new(output: FrameOutput) -> Self {
        VtDecoder {
            output,
            params: None,
            session: None,
        }
    }
}

impl VideoDecoder for VtDecoder {
    fn configure(&mut self, cfg: &VideoConfig) -> Result<()> {
        let (sps, pps) = extract_sps_pps(&cfg.sps_pps)
            .ok_or_else(|| DecodeError::BadConfig("VIDEO_CONFIG lacks SPS/PPS".into()))?;
        let same = self
            .params
            .as_ref()
            .is_some_and(|(s, p)| *s == sps && *p == pps);
        if same && self.session.is_some() {
            return Ok(());
        }
        self.session = None; // invalidate the old session first
        self.params = Some((sps, pps));
        let (sps, pps) = self
            .params
            .as_ref()
            .map(|(s, p)| (s.as_slice(), p.as_slice()))
            .unwrap_or_default();
        self.session = Some(Session::new(sps, pps, &self.output)?);
        Ok(())
    }

    fn decode(&mut self, au: &[u8], pts_us: u64, _key: bool) -> Result<()> {
        if self.session.is_none() {
            // Rebuild after an earlier error (the gate only lets a keyframe
            // through after one).
            let (sps, pps) = self.params.as_ref().ok_or(DecodeError::NotConfigured)?;
            self.session = Some(Session::new(sps, pps, &self.output)?);
        }
        let Some(session) = &self.session else {
            return Err(DecodeError::NotConfigured);
        };
        let r = session.decode(au, pts_us);
        if r.is_err() {
            self.session = None;
        }
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mirror_receiver::decoder::FramePool;
    use std::sync::{Arc, Mutex};

    fn output() -> (FrameOutput, Arc<Mutex<Vec<Nv12Frame>>>) {
        let got = Arc::new(Mutex::new(Vec::new()));
        let g = got.clone();
        (
            FrameOutput::new(
                FramePool::new(),
                Arc::new(move |f| g.lock().unwrap().push(f)),
            ),
            got,
        )
    }

    #[test]
    fn config_without_parameter_sets_is_rejected() {
        let (out, _) = output();
        let mut d = VtDecoder::new(out);
        let cfg = VideoConfig {
            width: 16,
            height: 16,
            display_width: 16,
            display_height: 16,
            rotation: 0,
            sps_pps: vec![0, 0, 0, 1, 0x65, 0],
        };
        assert!(matches!(d.configure(&cfg), Err(DecodeError::BadConfig(_))));
        assert_eq!(
            d.decode(&[0, 0, 0, 1, 0x65], 0, true),
            Err(DecodeError::NotConfigured)
        );
    }

    #[test]
    fn garbage_parameter_sets_fail_cleanly() {
        let (out, _) = output();
        let mut d = VtDecoder::new(out);
        let cfg = VideoConfig {
            width: 16,
            height: 16,
            display_width: 16,
            display_height: 16,
            rotation: 0,
            sps_pps: vec![0, 0, 0, 1, 0x67, 0xff, 0, 0, 0, 1, 0x68, 0xff],
        };
        assert!(d.configure(&cfg).is_err());
    }

    #[test]
    fn avcc_conversion_matches_the_protocol_crate_and_skips_parameter_sets() {
        use mirror_protocol::annexb::annexb_to_avcc;
        // AUD, SPS, PPS, SEI, IDR (3-byte and 4-byte start codes mixed).
        let au = [
            0, 0, 0, 1, 0x09, 0xf0, // AUD
            0, 0, 0, 1, 0x67, 1, 2, 3, // SPS
            0, 0, 1, 0x68, 4, 5, // PPS
            0, 0, 0, 1, 0x06, 9, // SEI
            0, 0, 0, 1, 0x65, 7, 7, 7, 7, // IDR
        ];
        let want = annexb_to_avcc(&au);
        assert_eq!(avcc_len(&au), want.len());
        assert_eq!(want.len(), (4 + 2) + (4 + 5));
        let (block, len) = avcc_block(&au).unwrap().unwrap();
        assert_eq!(len, want.len());
        // SAFETY: reading the block's own contiguous memory back for the check.
        let got = unsafe {
            let mut ptr: *mut std::ffi::c_char = ptr::null_mut();
            let status = block.data_pointer(0, ptr::null_mut(), ptr::null_mut(), &mut ptr);
            assert_eq!(status, 0);
            std::slice::from_raw_parts(ptr.cast::<u8>(), len).to_vec()
        };
        assert_eq!(got, want);
        // Only parameter sets: nothing to decode, and no block is made.
        assert!(avcc_block(&[0, 0, 0, 1, 0x67, 1, 0, 0, 0, 1, 0x68, 2])
            .unwrap()
            .is_none());
        assert!(avcc_block(&[]).unwrap().is_none());
    }

    #[test]
    fn failed_create_calls_release_what_they_returned() {
        // A Create call that fails but still wrote an object must not leak it.
        // Long enough not to be a tagged pointer (those are immortal).
        let n = CFString::from_str("a heap allocated string for the retain count probe");
        let probe: &CFType = n.as_ref();
        let base = probe.retain_count();
        let extra = CFRetained::into_raw(n.clone()).as_ptr();
        assert_eq!(probe.retain_count(), base + 1);
        // SAFETY: `extra` is a +1 retained CFString, as a Create call returns.
        assert!(unsafe { take_created(extra, -1) }.is_none());
        assert_eq!(probe.retain_count(), base, "released, not leaked");
        let extra = CFRetained::into_raw(n.clone()).as_ptr();
        // SAFETY: as above.
        let kept = unsafe { take_created(extra, 0) }.unwrap();
        assert_eq!(probe.retain_count(), base + 1, "ownership moved on success");
        drop(kept);
        assert_eq!(probe.retain_count(), base);
        // SAFETY: null is allowed.
        assert!(unsafe { take_created::<CFString>(ptr::null_mut(), -5) }.is_none());
    }

    #[test]
    fn only_video_range_is_renderable() {
        assert!(format_is_renderable(
            kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange
        ));
        assert!(!format_is_renderable(
            objc2_core_video::kCVPixelFormatType_420YpCbCr8BiPlanarFullRange
        ));
        assert!(!format_is_renderable(0));
    }

    #[test]
    fn dimension_caps() {
        assert!(dimensions_ok(1088, 2400));
        assert!(dimensions_ok(1, 1));
        assert!(dimensions_ok(MAX_SIDE, 4352), "level 6.2 8K");
        assert!(!dimensions_ok(0, 16));
        assert!(!dimensions_ok(16, 0));
        assert!(!dimensions_ok(MAX_SIDE + 1, 16));
        assert!(!dimensions_ok(16, MAX_SIDE + 1));
        assert!(!dimensions_ok(MAX_SIDE, MAX_SIDE), "area above MaxFS");
        assert!(!dimensions_ok(u32::MAX, u32::MAX));
    }

    /// Encode `frames` frames of `w`x`h` with ffmpeg (one IDR, AUDs) and
    /// split the stream into Annex-B access units. `None` (after printing
    /// `SKIPPED <test name>`) when ffmpeg is not on PATH or has no libx264,
    /// unless `MIRROR_REQUIRE_FFMPEG` is set (as in mirror-devtools' tests).
    fn ffmpeg_clip(w: u32, h: u32, frames: u32) -> Option<Vec<Vec<u8>>> {
        use mirror_protocol::annexb::{nal_type, nals, NAL_AUD};
        let skip = |why: String| {
            assert!(
                std::env::var_os("MIRROR_REQUIRE_FFMPEG").is_none(),
                "ffmpeg required: {why}"
            );
            let test = std::thread::current().name().unwrap_or("?").to_owned();
            eprintln!("SKIPPED {test}: {why}");
            None
        };
        let encoders = std::process::Command::new("ffmpeg")
            .args(["-hide_banner", "-encoders"])
            .stdin(std::process::Stdio::null())
            .output();
        match encoders {
            Err(e) => return skip(format!("ffmpeg not found on PATH ({e})")),
            Ok(o) if !String::from_utf8_lossy(&o.stdout).contains("libx264") => {
                return skip("ffmpeg has no libx264 encoder".into());
            }
            Ok(_) => {}
        }
        let dir = std::env::temp_dir().join(format!(
            "mirror-mac-vt-{}-{w}x{h}-{frames}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("clip.h264");
        let status = std::process::Command::new("ffmpeg")
            .args(["-y", "-loglevel", "error", "-f", "lavfi", "-i"])
            .arg(format!("testsrc2=size={w}x{h}:rate=30"))
            .args(["-frames:v", &frames.to_string(), "-c:v", "libx264"])
            .args(["-bf", "0", "-g", "1000", "-pix_fmt", "yuv420p"])
            .args(["-x264-params", "aud=1", "-f", "h264"])
            .arg(&path)
            .stdin(std::process::Stdio::null())
            .status()
            .expect("ffmpeg ran a moment ago");
        let data = std::fs::read(&path);
        let _ = std::fs::remove_dir_all(&dir);
        assert!(status.success(), "ffmpeg failed: {status}");
        let mut aus: Vec<Vec<u8>> = Vec::new();
        for nal in nals(&data.unwrap()) {
            if nal_type(nal) == Some(NAL_AUD) || aus.is_empty() {
                aus.push(Vec::new());
            }
            let au = aus.last_mut()?;
            au.extend_from_slice(&[0, 0, 0, 1]);
            au.extend_from_slice(nal);
        }
        Some(aus)
    }

    fn config_for(au: &[u8], w: u32, h: u32) -> VideoConfig {
        let (w, h) = (u16::try_from(w).unwrap(), u16::try_from(h).unwrap());
        VideoConfig {
            width: w,
            height: h,
            display_width: w,
            display_height: h,
            rotation: 0,
            sps_pps: au.to_vec(),
        }
    }

    #[test]
    fn decodes_real_clip_and_follows_format_changes() {
        let (Some(a), Some(b)) = (ffmpeg_clip(320, 240, 8), ffmpeg_clip(176, 144, 4)) else {
            return;
        };
        let (out, got) = output();
        let pool = out.pool().clone();
        let mut d = VtDecoder::new(out);
        for (clip, w, h) in [(&a, 320, 240), (&b, 176, 144), (&a, 320, 240)] {
            got.lock().unwrap().clear();
            d.configure(&config_for(&clip[0], w, h)).unwrap();
            for (i, au) in clip.iter().enumerate() {
                d.decode(au, i as u64 * 33_333, i == 0).unwrap();
            }
            let frames = std::mem::take(&mut *got.lock().unwrap());
            assert_eq!(frames.len(), clip.len(), "{w}x{h}");
            for (i, f) in frames.iter().enumerate() {
                assert_eq!((f.width, f.height), (w, h));
                assert_eq!(f.y_stride as usize, aligned_stride(w as usize));
                assert_eq!(f.uv_stride as usize, aligned_stride(w as usize));
                assert!(f.is_consistent());
                assert_eq!(f.pts_us, i as u64 * 33_333);
                // testsrc2 is not a flat picture; limited range luma.
                let row = &f.y[..w as usize];
                assert!(row.iter().any(|&v| v != row[0]));
            }
            for f in frames {
                pool.recycle(f);
            }
        }
        assert!(!pool.is_empty(), "planes are pooled");
    }

    #[test]
    fn garbage_frames_fail_and_the_next_keyframe_recovers() {
        let Some(clip) = ffmpeg_clip(320, 240, 3) else {
            return;
        };
        let (out, got) = output();
        let mut d = VtDecoder::new(out);
        d.configure(&config_for(&clip[0], 320, 240)).unwrap();
        // Truncated keyframe, then pure noise as a slice.
        let idr = &clip[0];
        let _ = d.decode(&idr[..idr.len() / 3], 0, true);
        let mut noise = vec![0, 0, 0, 1, 0x65];
        noise.extend((0..4096u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8));
        let _ = d.decode(&noise, 1, true);
        let _ = d.decode(&[0, 0, 0, 1], 2, true); // empty NAL
        got.lock().unwrap().clear();
        for (i, au) in clip.iter().enumerate() {
            d.decode(au, 10 + i as u64, i == 0).unwrap();
        }
        assert_eq!(got.lock().unwrap().len(), clip.len());
    }

    #[test]
    fn oversized_stream_is_rejected_at_configure() {
        // 8200 wide exceeds MAX_SIDE; x264 accepts it.
        let Some(clip) = ffmpeg_clip(8200, 64, 1) else {
            return;
        };
        let (out, _) = output();
        let mut d = VtDecoder::new(out);
        assert!(matches!(
            d.configure(&config_for(&clip[0], 8200, 64)),
            Err(DecodeError::BadConfig(_))
        ));
    }
}
