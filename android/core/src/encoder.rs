//! [`VideoSource`] on NDK `AMediaCodec` with a surface input (PLAN §4).
//!
//! Threads:
//! - `mirror-encoder` (one per core): owns every codec. `start`/`stop`
//!   (from mirror-sender session threads or `nativeDestroy`) and display
//!   changes (`nativeSetDisplay`) are commands to this thread, so codec
//!   lifecycle is serialised without holding a Rust mutex across the
//!   `onSurfaceReady`/`onSurfaceGone` upcalls it makes.
//! - `mirror-drain` (one per running codec): dequeues output with a 10 ms
//!   timeout and pushes VIDEO_CONFIG/frames into the session's `FrameSink`.
//!   It also applies keyframe requests (`request-sync`), so
//!   [`VideoSource::request_keyframe`] only sets an atomic flag (and queues a
//!   command) and never blocks. On a static screen the codec gets no input
//!   and cannot answer `request-sync`, so the encoder thread watches each
//!   request ([`keyframe_step`]) and, when no keyframe comes, asks Kotlin to
//!   re-attach the surface (`onSurfaceRefresh`), which makes the display
//!   composite a fresh frame; if that fails or still yields no keyframe it
//!   restarts the codec (new SPS/PPS and IDR).
//!   If it stops by itself (persistent dequeue errors, end of
//!   stream, panic) it tells the encoder thread, which restarts the codec or,
//!   after [`MAX_CODEC_RESTARTS`] failures in a row, reports the error and
//!   ends the client's session through its sink ([`FrameSink::fail`]).
//!
//! Encoder lifetime = client session × display geometry: no client means no
//! codec and a null VirtualDisplay surface, so every new client (and every
//! reconfigure) starts with SPS/PPS and an IDR.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use mirror_sender::{EncodedFrame, FrameSink, SourceError, StreamParams, VideoSource};
use ndk::media::media_codec::{DequeuedOutputBufferInfoResult, MediaCodec, MediaCodecDirection};
use ndk::media::media_format::MediaFormat;
use ndk::native_window::NativeWindow;

use crate::callbacks::Callbacks;
use crate::display::{sps_pps_from_config_buffer, sps_pps_from_csd, DisplayInfo};
use crate::format::{EncoderSpec, Value, MIME_AVC};
use crate::guarded;
use crate::recovery::{
    after_drain_failure, after_reconfigure_failure, keyframe_step, DrainAction, KeyframeStep,
    Latch, ReconfigureAction, MAX_CODEC_RESTARTS,
};

const DEQUEUE_TIMEOUT: Duration = Duration::from_millis(10);
/// Bound on how long a session thread waits for the encoder thread.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);
/// Consecutive dequeue errors before the drain thread gives up (and the
/// encoder thread restarts the codec).
const MAX_DRAIN_ERRORS: u32 = 50;

// The bindgen constant type differs per target arch.
#[allow(clippy::unnecessary_cast)]
const FLAG_KEY_FRAME: u32 = ndk_sys::AMEDIACODEC_BUFFER_FLAG_KEY_FRAME as u32;
#[allow(clippy::unnecessary_cast)]
const FLAG_CODEC_CONFIG: u32 = ndk_sys::AMEDIACODEC_BUFFER_FLAG_CODEC_CONFIG as u32;
#[allow(clippy::unnecessary_cast)]
const FLAG_END_OF_STREAM: u32 = ndk_sys::AMEDIACODEC_BUFFER_FLAG_END_OF_STREAM as u32;

/// `MediaCodec` shared between the encoder thread (lifecycle) and its drain
/// thread (dequeue/release/setParameters).
struct Codec(MediaCodec);

// SAFETY: AMediaCodec is internally synchronised (the platform routes every
// call through its own looper/locks); using it from the owning thread and one
// drain thread is the standard pattern. Lifecycle calls (stop/delete) happen
// only after the drain thread has been joined.
unsafe impl Send for Codec {}
unsafe impl Sync for Codec {}

enum Cmd {
    Start {
        params: StreamParams,
        sink: FrameSink,
        reply: SyncSender<Result<(), String>>,
    },
    Stop {
        reply: SyncSender<()>,
    },
    Display(DisplayInfo),
    /// The receiver asked for a keyframe. At most one is queued at a time
    /// (see [`Latch`]), so requests cannot pile up in the channel.
    Keyframe,
    /// The drain thread of codec generation `gen` stopped by itself.
    DrainFailed {
        gen: u64,
        frames_out: u32,
    },
    Quit,
}

/// When the running codec last emitted a frame / a keyframe; written by its
/// drain thread, read by the encoder thread. Microseconds since `epoch`
/// plus one; 0 = never.
struct Activity {
    epoch: Instant,
    output: AtomicU64,
    key: AtomicU64,
}

impl Activity {
    fn new() -> Self {
        Activity {
            epoch: Instant::now(),
            output: AtomicU64::new(0),
            key: AtomicU64::new(0),
        }
    }

    fn encode(&self, t: Instant) -> u64 {
        // Rounded up, so a stamp never reads earlier than the event.
        let d = t.saturating_duration_since(self.epoch);
        u64::try_from(d.as_nanos().div_ceil(1000)).unwrap_or(u64::MAX - 1) + 1
    }

    fn decode(&self, v: u64) -> Option<Instant> {
        v.checked_sub(1)
            .map(|us| self.epoch + Duration::from_micros(us))
    }

    /// A frame came out now.
    fn frame(&self, keyframe: bool) {
        let t = self.encode(Instant::now());
        self.output.store(t, Ordering::SeqCst);
        if keyframe {
            self.key.store(t, Ordering::SeqCst);
        }
    }

    /// A fresh codec starts: it emits SPS/PPS and an IDR by itself.
    fn reset(&self, now: Instant) {
        let t = self.encode(now);
        self.output.store(t, Ordering::SeqCst);
        self.key.store(t, Ordering::SeqCst);
    }

    fn last_output(&self) -> Option<Instant> {
        self.decode(self.output.load(Ordering::SeqCst))
    }

    fn last_key(&self) -> Option<Instant> {
        self.decode(self.key.load(Ordering::SeqCst))
    }
}

/// The Android [`VideoSource`].
pub struct Encoder {
    tx: Sender<Cmd>,
    /// Set by `request_keyframe`, consumed by the drain thread.
    keyframe: Arc<AtomicBool>,
    /// Raised while a `Cmd::Keyframe` is queued.
    kf_queued: Arc<Latch>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl Encoder {
    pub fn new(cb: Arc<Callbacks>) -> std::io::Result<Encoder> {
        let (tx, rx) = mpsc::channel();
        let keyframe = Arc::new(AtomicBool::new(false));
        let kf_queued = Arc::new(Latch::default());
        let a = Actor {
            cb,
            tx: tx.clone(),
            keyframe: keyframe.clone(),
            kf_queued: kf_queued.clone(),
            display: None,
            session: None,
            running: None,
            gen: 0,
            restarts: 0,
            activity: Arc::new(Activity::new()),
            kf_requested: None,
            kf_refreshed: None,
            last_refresh: None,
        };
        let thread = thread::Builder::new()
            .name("mirror-encoder".into())
            .spawn(move || actor_thread(rx, a))?;
        Ok(Encoder {
            tx,
            keyframe,
            kf_queued,
            thread: Mutex::new(Some(thread)),
        })
    }

    /// New display geometry; reconfigures a running codec. Non-blocking.
    pub fn set_display(&self, d: DisplayInfo) {
        let _ = self.tx.send(Cmd::Display(d));
    }

    /// Stop the encoder thread (releasing any codec). Idempotent. Must not
    /// be called from an upcall.
    pub fn shutdown(&self) {
        let t = self.thread.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(t) = t {
            let _ = self.tx.send(Cmd::Quit);
            if t.join().is_err() {
                log::error!("encoder thread panicked");
            }
        }
    }
}

impl Drop for Encoder {
    fn drop(&mut self) {
        self.shutdown();
    }
}

impl VideoSource for Encoder {
    fn start(&self, params: StreamParams, sink: FrameSink) -> Result<(), SourceError> {
        let (reply, rx) = mpsc::sync_channel(1);
        self.tx
            .send(Cmd::Start {
                params,
                sink,
                reply,
            })
            .map_err(|_| "encoder thread is gone")?;
        match rx.recv_timeout(COMMAND_TIMEOUT) {
            Ok(r) => r.map_err(Into::into),
            Err(_) => Err("encoder did not start in time".into()),
        }
    }

    fn request_keyframe(&self) {
        self.keyframe.store(true, Ordering::SeqCst);
        // Watched by the encoder thread in case the codec cannot answer. A
        // request made while one is still queued is covered by it: the
        // encoder thread lowers the latch before it reads the request time.
        if self.kf_queued.raise() {
            let _ = self.tx.send(Cmd::Keyframe);
        }
    }

    fn stop(&self) {
        let (reply, rx) = mpsc::sync_channel(1);
        if self.tx.send(Cmd::Stop { reply }).is_ok() && rx.recv_timeout(COMMAND_TIMEOUT).is_err() {
            log::error!("encoder did not stop in time");
        }
    }
}

/// A configured, started codec and its drain thread.
struct Running {
    codec: Arc<Codec>,
    /// Keeps the input surface alive while the VirtualDisplay renders into it.
    window: NativeWindow,
    stop: Arc<AtomicBool>,
    drain: Option<JoinHandle<()>>,
    /// True once Kotlin may hold the surface (so it must get `onSurfaceGone`).
    surface_given: bool,
    gen: u64,
}

struct Actor {
    cb: Arc<Callbacks>,
    /// Lets drain threads report failures back to this thread.
    tx: Sender<Cmd>,
    keyframe: Arc<AtomicBool>,
    kf_queued: Arc<Latch>,
    display: Option<DisplayInfo>,
    session: Option<(StreamParams, FrameSink)>,
    running: Option<Running>,
    /// Generation of the last started codec (stale drain failures are ignored).
    gen: u64,
    /// Codec restarts in a row after drain failures (see `recovery`).
    restarts: u32,
    /// Output times of the running codec (shared with its drain thread).
    activity: Arc<Activity>,
    /// Oldest keyframe request not answered yet.
    kf_requested: Option<Instant>,
    /// When the surface was refreshed for that request.
    kf_refreshed: Option<Instant>,
    /// Last surface refresh.
    last_refresh: Option<Instant>,
}

fn actor_thread(rx: Receiver<Cmd>, mut a: Actor) {
    // When to look at a pending keyframe request again.
    let mut wake: Option<Instant> = None;
    loop {
        let cmd = match wake {
            Some(t) => match rx.recv_timeout(t.saturating_duration_since(Instant::now())) {
                Ok(c) => Some(c),
                Err(RecvTimeoutError::Timeout) => None,
                Err(RecvTimeoutError::Disconnected) => break,
            },
            None => match rx.recv() {
                Ok(c) => Some(c),
                Err(_) => break,
            },
        };
        let quit = matches!(cmd, Some(Cmd::Quit));
        if let Some(cmd) = cmd {
            if let Err(p) = guarded(|| a.handle(cmd)) {
                log::error!("panic in encoder thread: {p}");
            }
        }
        if quit {
            break;
        }
        wake = guarded(|| a.watch_keyframe(Instant::now())).unwrap_or_else(|p| {
            log::error!("panic in encoder thread: {p}");
            None
        });
    }
    if let Err(p) = guarded(|| a.teardown()) {
        log::error!("panic releasing encoder: {p}");
    }
    log::debug!("encoder thread exiting");
}

impl Actor {
    fn handle(&mut self, cmd: Cmd) {
        match cmd {
            Cmd::Start {
                params,
                sink,
                reply,
            } => {
                self.teardown();
                self.session = Some((params, sink));
                self.restarts = 0;
                let r = self.start_codec();
                if r.is_err() {
                    self.session = None;
                }
                let _ = reply.send(r);
            }
            Cmd::Stop { reply } => {
                self.teardown();
                self.session = None;
                let _ = reply.send(());
            }
            Cmd::Display(d) => {
                if self.display == Some(d) {
                    return;
                }
                log::info!(
                    "display {}x{} rotation {} dpi {}",
                    d.width,
                    d.height,
                    d.rotation,
                    d.dpi
                );
                let size_changed = self.display.is_none_or(|o| {
                    (o.width, o.height, o.rotation) != (d.width, d.height, d.rotation)
                });
                self.display = Some(d);
                if self.session.is_some() && (size_changed || self.running.is_none()) {
                    let mut retries = 0;
                    loop {
                        self.teardown();
                        let Err(e) = self.start_codec() else { break };
                        log::error!("reconfigure failed: {e}");
                        match after_reconfigure_failure(retries) {
                            ReconfigureAction::Retry => retries += 1,
                            ReconfigureAction::GiveUp => {
                                self.give_up(&format!("reconfigure failed: {e}"));
                                break;
                            }
                        }
                    }
                }
            }
            Cmd::Keyframe => {
                self.kf_queued.lower();
                let at = Instant::now();
                if self.running.is_some() {
                    self.kf_requested = Some(self.kf_requested.map_or(at, |p| p.min(at)));
                }
            }
            Cmd::DrainFailed { gen, frames_out } => {
                let running = self.running.as_ref().map(|r| r.gen);
                match after_drain_failure(running, gen, frames_out, &mut self.restarts) {
                    DrainAction::Ignore => {}
                    DrainAction::Restart => {
                        log::warn!("encoder output stopped; restarting codec");
                        self.teardown();
                        if let Err(e) = self.start_codec() {
                            log::error!("codec restart failed: {e}");
                            self.give_up(&e);
                        }
                    }
                    DrainAction::GiveUp => {
                        self.give_up(&format!(
                            "encoder failed {MAX_CODEC_RESTARTS} times in a row"
                        ));
                    }
                }
            }
            Cmd::Quit => {}
        }
    }

    /// Follow up on a pending keyframe request; returns when to look again.
    fn watch_keyframe(&mut self, now: Instant) -> Option<Instant> {
        let requested = self.kf_requested?;
        if self.running.is_none() {
            self.kf_requested = None;
            self.kf_refreshed = None;
            return None;
        }
        let step = keyframe_step(
            now,
            requested,
            self.activity.last_output(),
            self.activity.last_key(),
            self.kf_refreshed,
            self.last_refresh,
        );
        match step {
            KeyframeStep::Done => {
                self.kf_requested = None;
                self.kf_refreshed = None;
                None
            }
            KeyframeStep::Wait(t) => Some(t),
            KeyframeStep::Refresh => {
                self.kf_refreshed = Some(now);
                self.last_refresh = Some(now);
                // The frame the refresh produces must be an IDR.
                self.keyframe.store(true, Ordering::SeqCst);
                log::info!("keyframe requested but encoder idle; refreshing the surface");
                match self.cb.surface_refresh() {
                    Ok(()) => self.watch_keyframe(Instant::now()),
                    Err(e) => {
                        log::warn!("{e}");
                        self.restart_for_keyframe();
                        None
                    }
                }
            }
            KeyframeStep::Restart => {
                self.restart_for_keyframe();
                None
            }
        }
    }

    /// No keyframe is coming: restart the codec, which starts with SPS/PPS
    /// and an IDR (the reconfigure path). Ends the pending request.
    fn restart_for_keyframe(&mut self) {
        log::warn!("no keyframe after the surface refresh; restarting the codec");
        self.teardown();
        if let Err(e) = self.start_codec() {
            log::error!("codec restart failed: {e}");
            self.give_up(&e);
        }
    }

    /// Release the codec, tell Kotlin, and end the client's session so the
    /// receiver does not sit on a frozen picture.
    fn give_up(&mut self, why: &str) {
        log::error!("giving up on the encoder: {why}");
        self.teardown();
        self.cb.error(&format!("Encoder stopped: {why}"));
        // Ends only the session this codec served (BYE `unknown`, the
        // protocol's final phone-side failure), never a client that replaced it.
        if !self.session.as_ref().is_some_and(|(_, sink)| sink.fail()) {
            log::info!("encoder's session already ended; no client to disconnect");
        }
    }

    /// Start a codec for the current session and display. Ok without a
    /// codec when the display is not known yet (started on `Display`).
    fn start_codec(&mut self) -> Result<(), String> {
        let (Some(display), Some((params, sink))) = (self.display, self.session.clone()) else {
            if self.session.is_some() {
                log::warn!("client started before the display size is known; waiting");
            }
            return Ok(());
        };
        let (codec, spec) = configure_ladder(&display, &params)?;
        let window = codec
            .create_input_surface()
            .map_err(|e| format!("createInputSurface: {e}"))?;
        codec.start().map_err(|e| format!("start: {e}"))?;
        let name = codec.name().unwrap_or_else(|_| "unknown".into());
        log::info!(
            "encoder {name} started: {}x{} @{} fps, {} bps, rung {:?}",
            spec.width,
            spec.height,
            spec.fps,
            spec.bitrate,
            spec.rung
        );

        let codec = Arc::new(Codec(codec));
        let stop = Arc::new(AtomicBool::new(false));
        self.gen += 1;
        let gen = self.gen;
        // A fresh codec starts with an IDR anyway.
        self.keyframe.store(false, Ordering::SeqCst);
        self.kf_requested = None;
        self.kf_refreshed = None;
        self.activity.reset(Instant::now());
        let drain = {
            let (codec, stop, kf) = (codec.clone(), stop.clone(), self.keyframe.clone());
            let activity = self.activity.clone();
            let tx = self.tx.clone();
            thread::Builder::new()
                .name("mirror-drain".into())
                .spawn(move || {
                    let frames_out =
                        guarded(|| drain_loop(&codec, &stop, &kf, &activity, &sink, display, spec))
                            .unwrap_or_else(|p| {
                                log::error!("panic in drain thread: {p}");
                                0
                            });
                    if !stop.load(Ordering::SeqCst) {
                        let _ = tx.send(Cmd::DrainFailed { gen, frames_out });
                    }
                })
                .map_err(|e| format!("spawn drain thread: {e}"))
        };
        let drain = match drain {
            Ok(t) => t,
            Err(e) => {
                let _ = codec.0.stop();
                return Err(e);
            }
        };
        self.running = Some(Running {
            codec,
            window,
            stop,
            drain: Some(drain),
            // Set before the upcall: if Kotlin throws after attaching the
            // surface, teardown must still detach it before the codec goes.
            surface_given: true,
            gen,
        });

        // Upcall with no lock held.
        let window = &self.running.as_ref().expect("just set").window;
        if let Err(e) = self.cb.surface_ready(window, spec.width, spec.height) {
            self.teardown();
            return Err(e);
        }
        self.cb
            .stream_info(spec.width, spec.height, spec.fps, &name);
        Ok(())
    }

    /// Detach the surface from the VirtualDisplay (Kotlin returns when done),
    /// then stop the drain thread and release the codec.
    fn teardown(&mut self) {
        let Some(mut r) = self.running.take() else {
            return;
        };
        if r.surface_given {
            if let Err(e) = self.cb.surface_gone() {
                log::warn!("{e}");
            }
        }
        r.stop.store(true, Ordering::SeqCst);
        if let Some(t) = r.drain.take() {
            if t.join().is_err() {
                log::error!("drain thread panicked");
            }
        }
        if let Err(e) = r.codec.0.stop() {
            log::warn!("codec stop: {e}");
        }
        // Drop order: codec (AMediaCodec_delete) then the input surface.
        drop(r.codec);
        drop(r.window);
        log::info!("encoder released");
    }
}

fn build_format(spec: &EncoderSpec) -> MediaFormat {
    let mut f = MediaFormat::new();
    f.set_str("mime", MIME_AVC);
    for (k, v) in spec.entries() {
        match v {
            Value::I32(v) => f.set_i32(k, v),
            Value::I64(v) => f.set_i64(k, v),
            Value::F32(v) => f.set_f32(k, v),
        }
    }
    f
}

/// Try each ladder rung with a fresh codec until `configure` succeeds.
fn configure_ladder(
    display: &DisplayInfo,
    params: &StreamParams,
) -> Result<(MediaCodec, EncoderSpec), String> {
    let mut last_err = String::from("no rung tried");
    for spec in EncoderSpec::ladder(display.width, display.height, params) {
        let codec = MediaCodec::from_encoder_type(MIME_AVC)
            .ok_or_else(|| "no H.264 encoder on this device".to_string())?;
        let format = build_format(&spec);
        match codec.configure(&format, None, MediaCodecDirection::Encoder) {
            Ok(()) => {
                log::info!("configure ok on rung {:?}: {format}", spec.rung);
                return Ok((codec, spec));
            }
            Err(e) => {
                log::warn!("configure failed on rung {:?} ({format}): {e}", spec.rung);
                last_err = format!("configure: {e}");
            }
        }
    }
    Err(last_err)
}

fn request_sync(codec: &MediaCodec) {
    let mut p = MediaFormat::new();
    p.set_i32("request-sync", 0);
    if let Err(e) = codec.set_parameters(p) {
        log::warn!("request-sync failed: {e}");
    }
}

fn drain_loop(
    codec: &Codec,
    stop: &AtomicBool,
    keyframe: &AtomicBool,
    activity: &Activity,
    sink: &FrameSink,
    display: DisplayInfo,
    spec: EncoderSpec,
) -> u32 {
    let codec = &codec.0;
    let mut produced = 0u32;
    let mut last_sps_pps: Option<Vec<u8>> = None;
    // `output_format()` allocates a copy: look for csd there at most once.
    let mut csd_checked = false;
    let mut errors = 0u32;
    let push_config = |sps_pps: Vec<u8>, last: &mut Option<Vec<u8>>| {
        if sps_pps.is_empty() || last.as_ref() == Some(&sps_pps) {
            return;
        }
        log::debug!(
            "VIDEO_CONFIG {}x{} ({} bytes)",
            spec.width,
            spec.height,
            sps_pps.len()
        );
        *last = Some(sps_pps.clone());
        sink.push_config(display.video_config(&spec, sps_pps));
    };
    while !stop.load(Ordering::SeqCst) {
        if keyframe.swap(false, Ordering::SeqCst) {
            request_sync(codec);
        }
        match codec.dequeue_output_buffer(DEQUEUE_TIMEOUT) {
            Ok(DequeuedOutputBufferInfoResult::Buffer(buf)) => {
                errors = 0;
                let info = *buf.info();
                let flags = info.flags();
                let data = {
                    let all = buf.buffer();
                    let off = usize::try_from(info.offset()).unwrap_or(0);
                    let len = usize::try_from(info.size()).unwrap_or(0);
                    all.get(off..off.saturating_add(len)).unwrap_or(&[])
                };
                if flags & FLAG_CODEC_CONFIG != 0 {
                    push_config(sps_pps_from_config_buffer(data), &mut last_sps_pps);
                } else if !data.is_empty() {
                    if last_sps_pps.is_none() && !csd_checked {
                        csd_checked = true;
                        // Some encoders only publish csd-0/1 in the format.
                        let f = codec.output_format();
                        if let Some(csd0) = f.buffer("csd-0") {
                            push_config(
                                sps_pps_from_csd(csd0, f.buffer("csd-1")),
                                &mut last_sps_pps,
                            );
                        }
                    }
                    produced = produced.saturating_add(1);
                    let key = flags & FLAG_KEY_FRAME != 0;
                    activity.frame(key);
                    sink.push_frame(EncodedFrame {
                        pts_us: info.presentation_time_us().max(0) as u64,
                        keyframe: key,
                        data: data.to_vec(),
                    });
                }
                if let Err(e) = codec.release_output_buffer(buf, false) {
                    log::warn!("releaseOutputBuffer: {e}");
                }
                if flags & FLAG_END_OF_STREAM != 0 {
                    break;
                }
            }
            Ok(DequeuedOutputBufferInfoResult::OutputFormatChanged) => {
                let f = codec.output_format();
                log::debug!("output format: {f}");
                if let Some(csd0) = f.buffer("csd-0") {
                    push_config(sps_pps_from_csd(csd0, f.buffer("csd-1")), &mut last_sps_pps);
                }
            }
            Ok(_) => {}
            Err(e) => {
                errors += 1;
                log::warn!("dequeueOutputBuffer: {e}");
                if errors >= MAX_DRAIN_ERRORS {
                    log::error!("encoder output failing; drain thread giving up");
                    break;
                }
                thread::sleep(DEQUEUE_TIMEOUT);
            }
        }
    }
    produced
}
