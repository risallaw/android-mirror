//! One mirroring session on its own **decode thread**.
//!
//! The thread resolves the target, runs a [`Supervisor`] (connect +
//! reconnect), and consumes its events: VIDEO_CONFIG / VIDEO_FRAME go
//! through the [`FrameGate`] into the platform [`VideoDecoder`]; decoded
//! pictures land in the latest-frame-wins [`FrameSlot`] and wake the UI with
//! [`SessionMsg::FrameReady`]. Everything the UI cares about (connection
//! state, config, status) is forwarded as [`SessionMsg::Client`]. The UI
//! thread never blocks on the network or the decoder.
//!
//! A decoder that panics is replaced by a fresh one (configured with the
//! current VIDEO_CONFIG) and the stream resumes at the next keyframe; after
//! [`MAX_DECODER_PANICS`] panics in a row the session ends with
//! `Client(Stopped(Protocol(..)))` saying so, instead of vanishing.
//!
//! Input goes the other way through [`Session::send_control`], which only
//! queues (sealing happens on the client's writer thread).
//!
//! Pairing: put the PIN in `SessionParams::client.pin` and the shared
//! [`Store`](crate::store::Store) in `client.store`; the client saves the
//! new key there itself (see [`crate::client`], "Credentials").

use std::panic::AssertUnwindSafe;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crossbeam_channel::{bounded, select, Receiver, Sender};
use mirror_protocol::{Message, VideoConfig, VideoFrame};

use crate::address::{resolve, Target};
use crate::client::{is_control_message, ClientConfig, ClientEvent, DisconnectReason, SendError};
use crate::decoder::{DecoderFactory, FrameOutput, FrameSlot, Nv12Frame, VideoDecoder};
use crate::frame_gate::{FrameGate, GateAction};
use crate::reconnect::{ReconnectPolicy, SessionLink, Supervisor};
use crate::stats::Stats;

/// What the decode thread tells the UI.
// A handful of these per session (frames only send `FrameReady`): boxing
// the large `ClientEvent` would buy nothing.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum SessionMsg {
    /// A supervisor event (never `VideoFrame` or `Rtt`; those stay on the
    /// decode thread).
    Client(ClientEvent),
    /// The target name did not resolve; the session is over.
    ResolveFailed(String),
    /// A new frame is waiting in the slot.
    FrameReady,
    /// The thread is exiting; always the last message.
    Ended,
}

/// Callback into the UI (wraps winit's `EventLoopProxy` in the app). Must
/// not block.
pub type Notify = Arc<dyn Fn(SessionMsg) + Send + Sync>;

/// Shared stream statistics (written by the decode thread and the decoder
/// output, read by the UI).
pub type SharedStats = Arc<Mutex<Stats>>;

pub fn lock_stats(s: &SharedStats) -> MutexGuard<'_, Stats> {
    s.lock().unwrap_or_else(|p| p.into_inner())
}

/// Rate limiter for per-frame log lines: the first event logs at once, later
/// ones are counted and surface as one summary per `interval`.
#[derive(Debug)]
pub struct LogLimiter {
    interval: Duration,
    last: Option<Instant>,
    suppressed: u64,
}

impl LogLimiter {
    pub fn new(interval: Duration) -> Self {
        LogLimiter {
            interval,
            last: None,
            suppressed: 0,
        }
    }

    /// Call once per event. `Some(n)`: log now, `n` events were suppressed
    /// since the last line. `None`: stay quiet.
    pub fn check(&mut self, now: Instant) -> Option<u64> {
        match self.last {
            Some(t) if now.saturating_duration_since(t) < self.interval => {
                self.suppressed += 1;
                None
            }
            _ => {
                self.last = Some(now);
                Some(std::mem::take(&mut self.suppressed))
            }
        }
    }
}

/// Minimum spacing between repeated per-frame log lines.
pub const LOG_INTERVAL: Duration = Duration::from_secs(5);

pub struct SessionParams {
    pub target: Target,
    pub client: ClientConfig,
    pub policy: ReconnectPolicy,
    pub factory: DecoderFactory,
    pub slot: FrameSlot,
    pub stats: SharedStats,
    pub notify: Notify,
}

/// Handle to a running session. Dropping it asks the thread to stop
/// without waiting.
pub struct Session {
    stop: Sender<()>,
    done: Receiver<()>,
    thread: Option<JoinHandle<()>>,
    /// Set by the decode thread once its supervisor exists.
    link: Arc<OnceLock<SessionLink>>,
}

impl Session {
    pub fn start(p: SessionParams) -> std::io::Result<Session> {
        let (stop_tx, stop_rx) = bounded(1);
        let (done_tx, done_rx) = bounded(1);
        let link = Arc::new(OnceLock::new());
        let thread = {
            let link = Arc::clone(&link);
            thread::Builder::new()
                .name("mirror-decode".into())
                .spawn(move || {
                    let _end = EndGuard {
                        notify: p.notify.clone(),
                        done: done_tx,
                    };
                    run(p, &stop_rx, &link);
                })?
        };
        Ok(Session {
            stop: stop_tx,
            done: done_rx,
            thread: Some(thread),
            link,
        })
    }

    /// Queue an input message (from [`crate::input`]) for the phone. Never
    /// blocks. Refused with [`SendError::ControlUnavailable`] unless
    /// [`control_available`](Self::control_available), with
    /// [`SendError::Disconnected`] while not connected, and with
    /// [`SendError::QueueFull`] when the link is congested (drop the input).
    pub fn send_control(&self, msg: Message) -> Result<(), SendError> {
        match self.link.get() {
            Some(l) => l.send_control(msg),
            None if is_control_message(&msg) => Err(SendError::Disconnected),
            None => Err(SendError::NotControl),
        }
    }

    /// True while connected over an authenticated (`pin`/`token`) session
    /// and the phone's latest STATUS was `control_available`. The UI also
    /// sees the STATUS events; this is the authoritative check.
    pub fn control_available(&self) -> bool {
        self.link.get().is_some_and(SessionLink::control_available)
    }

    /// Ask the session to end (BYE, stop reconnecting). Non-blocking.
    pub fn stop(&self) {
        let _ = self.stop.try_send(());
    }

    /// Stop and wait up to `timeout` for the thread to finish. Returns true
    /// if it did (then it is joined).
    pub fn stop_and_wait(mut self, timeout: Duration) -> bool {
        self.stop();
        if self.done.recv_timeout(timeout).is_ok() {
            if let Some(t) = self.thread.take() {
                let _ = t.join();
            }
            true
        } else {
            false
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Sends [`SessionMsg::Ended`] and signals `done` when the thread exits,
/// also if it unwinds (e.g. a decoder panic), so the UI never waits on a
/// dead session.
struct EndGuard {
    notify: Notify,
    done: Sender<()>,
}

impl Drop for EndGuard {
    fn drop(&mut self) {
        (self.notify)(SessionMsg::Ended);
        let _ = self.done.send(());
    }
}

fn run(p: SessionParams, stop: &Receiver<()>, link: &OnceLock<SessionLink>) {
    let SessionParams {
        target,
        client,
        policy,
        factory,
        slot,
        stats,
        notify,
    } = p;

    let addr = match resolve(&target) {
        Ok(a) => a,
        Err(e) => {
            notify(SessionMsg::ResolveFailed(format!(
                "Couldn't find \"{}\": {e}",
                target.host
            )));
            return;
        }
    };
    if stop.try_recv().is_ok() {
        return;
    }

    lock_stats(&stats).reset();
    slot.clear();
    let output = {
        let slot = slot.clone();
        let stats = stats.clone();
        let notify = notify.clone();
        FrameOutput::new(
            slot.pool().clone(),
            Arc::new(move |f: Nv12Frame| {
                lock_stats(&stats).on_decoded(Instant::now(), f.width, f.height);
                if slot.put(f) {
                    notify(SessionMsg::FrameReady);
                }
            }),
        )
    };
    let mut video = match Video::new(factory, output) {
        Ok(v) => v,
        Err(why) => {
            notify(SessionMsg::Client(ClientEvent::Stopped(
                DisconnectReason::Protocol(why),
            )));
            return;
        }
    };
    let mut sup = Supervisor::start(addr, client, policy);
    let _ = link.set(sup.link());
    let events = sup.events();

    let mut fatal = None;
    loop {
        select! {
            recv(events) -> ev => {
                let Ok(ev) = ev else { break };
                let last = matches!(ev, ClientEvent::GaveUp { .. } | ClientEvent::Stopped(_));
                if let Err(why) = handle(ev, &mut video, &sup, &stats, &notify) {
                    fatal = Some(why);
                    break;
                }
                if last {
                    return;
                }
            }
            recv(stop) -> _ => break,
        }
    }
    // Local stop (or a dead decoder): BYE + join (bounded by the
    // connect/handshake timeouts), then forward whatever final events are
    // left. After a decoder failure the session ends with that reason
    // instead of the local close.
    sup.close();
    while let Ok(ev) = events.try_recv() {
        let skip = match ev {
            ClientEvent::VideoFrame(_) | ClientEvent::Rtt(_) => true,
            ClientEvent::Disconnected(_) | ClientEvent::Stopped(_) => fatal.is_some(),
            _ => false,
        };
        if !skip {
            notify(SessionMsg::Client(ev));
        }
    }
    if let Some(why) = fatal {
        notify(SessionMsg::Client(ClientEvent::Stopped(
            DisconnectReason::Protocol(why),
        )));
    }
}

/// After this many decoder panics without a frame decoded in between, the
/// session ends (with a visible reason) instead of restarting it again.
pub const MAX_DECODER_PANICS: u32 = 3;
/// The `Protocol` reason a session ends with when the video decoder cannot
/// be started, restarted, or kept crashing ([`MAX_DECODER_PANICS`]); the UI
/// matches it to show a decoder headline, not "Unexpected data". The exact
/// cause is logged.
pub const DECODER_FAILED: &str = "the video decoder failed";

/// Run `f`, turning a panic into `None`. Decoders wrap platform code; one
/// that panics is rebuilt instead of taking the session down silently.
fn guarded<T>(f: impl FnOnce() -> T) -> Option<T> {
    std::panic::catch_unwind(AssertUnwindSafe(f)).ok()
}

/// The decoder side of the decode thread: gate, decoder and recovery.
struct Video {
    factory: DecoderFactory,
    output: FrameOutput,
    decoder: Box<dyn VideoDecoder>,
    gate: FrameGate,
    /// Latest VIDEO_CONFIG, to configure a decoder rebuilt after a panic.
    config: Option<VideoConfig>,
    /// The decoder refused the latest config. More keyframes cannot fix
    /// that (only a new config can), so after the one request made when it
    /// failed none are requested until a frame decodes again: otherwise
    /// every failing keyframe would ask for the next one, at RTT rate.
    config_failed: bool,
    /// Decoder panics since the last decoded frame.
    panics: u32,
    log: LogLimiter,
}

impl Video {
    fn new(factory: DecoderFactory, output: FrameOutput) -> Result<Video, String> {
        let decoder = guarded(|| factory(output.clone())).ok_or_else(|| {
            eprintln!("the video decoder could not be started");
            DECODER_FAILED.to_string()
        })?;
        Ok(Video {
            factory,
            output,
            decoder,
            gate: FrameGate::new(),
            config: None,
            config_failed: false,
            panics: 0,
            log: LogLimiter::new(LOG_INTERVAL),
        })
    }

    /// New connection: wait for its VIDEO_CONFIG.
    fn reset(&mut self) {
        self.gate.reset();
        self.config = None;
        self.config_failed = false;
    }

    fn on_config(&mut self, cfg: &VideoConfig, sup: &Supervisor, stats: &SharedStats) -> Fallible {
        self.gate.on_config();
        self.config = Some(cfg.clone());
        self.config_failed = false;
        match guarded(|| self.decoder.configure(cfg)) {
            Some(Ok(())) => Ok(()),
            Some(Err(e)) => {
                // `failed` asks for one keyframe (the decoder may recover on
                // it); then the config counts as refused.
                self.failed(format_args!("decoder configure failed: {e}"), sup, stats);
                self.config_failed = true;
                Ok(())
            }
            None => self.crashed(sup, stats),
        }
    }

    fn on_frame(&mut self, f: &VideoFrame, sup: &Supervisor, stats: &SharedStats) -> Fallible {
        lock_stats(stats).on_received(Instant::now(), f.data.len());
        let key = f.is_keyframe();
        match self
            .gate
            .on_frame(key, f.is_discontinuity(), Instant::now())
        {
            GateAction::Decode => match guarded(|| self.decoder.decode(&f.data, f.pts_us, key)) {
                Some(Ok(())) => {
                    self.gate.on_decoded();
                    self.panics = 0;
                    self.config_failed = false;
                }
                Some(Err(e)) => self.failed(
                    format_args!("decode failed (pts {}): {e}", f.pts_us),
                    sup,
                    stats,
                ),
                None => return self.crashed(sup, stats),
            },
            GateAction::DropAndRequestKeyframe => {
                lock_stats(stats).on_dropped();
                if !self.config_failed {
                    let _ = sup.request_keyframe();
                }
            }
            GateAction::Drop => lock_stats(stats).on_dropped(),
        }
        Ok(())
    }

    /// A decoder call failed: log (rate-limited), count, drop until the
    /// next keyframe and ask for one.
    fn failed(&mut self, what: std::fmt::Arguments<'_>, sup: &Supervisor, stats: &SharedStats) {
        if let Some(n) = self.log.check(Instant::now()) {
            eprintln!("{what} ({n} similar errors suppressed)");
        }
        lock_stats(stats).on_decode_error();
        if self.gate.on_decode_error(Instant::now()) && !self.config_failed {
            let _ = sup.request_keyframe();
        }
    }

    /// The decoder panicked: replace it with a fresh one (configured with
    /// the current config) and resume at the next keyframe, or give up
    /// after [`MAX_DECODER_PANICS`] in a row.
    fn crashed(&mut self, sup: &Supervisor, stats: &SharedStats) -> Fallible {
        self.panics += 1;
        if self.panics >= MAX_DECODER_PANICS {
            eprintln!("the video decoder kept crashing");
            return Err(DECODER_FAILED.into());
        }
        eprintln!(
            "video decoder panicked; restarting it ({}/{MAX_DECODER_PANICS})",
            self.panics
        );
        let fresh = guarded(|| (self.factory)(self.output.clone())).ok_or_else(|| {
            eprintln!("the video decoder could not be restarted");
            DECODER_FAILED.to_string()
        })?;
        let old = std::mem::replace(&mut self.decoder, fresh);
        // Its state is unknown after a panic: dropping it may panic too.
        let _ = guarded(move || drop(old));
        self.config_failed = false;
        if let Some(cfg) = self.config.clone() {
            match guarded(|| self.decoder.configure(&cfg)) {
                Some(Ok(())) => {}
                Some(Err(_)) => self.config_failed = true,
                None => return self.crashed(sup, stats),
            }
        }
        self.failed(format_args!("video decoder restarted"), sup, stats);
        Ok(())
    }
}

/// `Err(why)` ends the session (user-facing reason).
type Fallible = Result<(), String>;

fn handle(
    ev: ClientEvent,
    video: &mut Video,
    sup: &Supervisor,
    stats: &SharedStats,
    notify: &Notify,
) -> Fallible {
    match ev {
        ClientEvent::VideoFrame(f) => video.on_frame(&f, sup, stats)?,
        ClientEvent::VideoConfig(cfg) => {
            let r = video.on_config(&cfg, sup, stats);
            notify(SessionMsg::Client(ClientEvent::VideoConfig(cfg)));
            r?;
        }
        ClientEvent::Rtt(d) => lock_stats(stats).set_rtt(d),
        ClientEvent::Connected { .. } => {
            video.reset();
            lock_stats(stats).reset();
            notify(SessionMsg::Client(ev));
        }
        other => notify(SessionMsg::Client(other)),
    }
    Ok(())
}

#[cfg(test)]
mod limiter_tests {
    use super::*;

    #[test]
    fn logs_first_then_one_summary_per_interval() {
        let mut l = LogLimiter::new(Duration::from_secs(5));
        let t0 = Instant::now();
        assert_eq!(l.check(t0), Some(0));
        for i in 1..=100 {
            assert_eq!(l.check(t0 + Duration::from_millis(i * 10)), None);
        }
        assert_eq!(l.check(t0 + Duration::from_secs(5)), Some(100));
        assert_eq!(l.check(t0 + Duration::from_secs(6)), None);
        assert_eq!(l.check(t0 + Duration::from_secs(10)), Some(1));
    }
}

#[cfg(test)]
mod decoder_failure_tests {
    use super::*;
    use crate::decoder::FramePool;

    #[test]
    fn a_decoder_that_cannot_start_gets_the_decoder_headline() {
        let factory: DecoderFactory = Arc::new(|_| panic!("no decoder here"));
        let output = FrameOutput::new(FramePool::new(), Arc::new(|_| {}));
        let Err(why) = Video::new(factory, output) else {
            panic!("a decoder that cannot start must end the session");
        };
        let (headline, _) = crate::state::describe(&DisconnectReason::Protocol(why));
        assert_eq!(headline, "Video decoder failed");
    }
}
