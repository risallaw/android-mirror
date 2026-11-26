//! winit `ApplicationHandler` + wgpu surface + NV12 video + egui overlay.
//!
//! Threads: the UI/event-loop thread (this file: input, egui, wgpu) and one
//! decode thread per session ([`crate::session`]), which owns the network
//! supervisor and the platform decoder. Decoded frames reach the UI through
//! a latest-frame-wins [`FrameSlot`]; the decode thread wakes the event loop
//! with a user event, so the UI redraws only for new frames or input.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use egui_winit::accesskit_winit;
use winit::application::ApplicationHandler;
use winit::dpi::LogicalSize;
use winit::event::{ElementState, StartCause, WindowEvent};
use winit::event_loop::{
    ActiveEventLoop, ControlFlow, EventLoop, EventLoopBuilder, EventLoopProxy,
};
use winit::window::{Window, WindowId};
use zeroize::Zeroizing;

use crate::address::{parse_target, Target};
use crate::client::{ClientConfig, ClientEvent, DisconnectReason};
use crate::decoder::{DecoderFactory, FramePool, FrameSlot, Nv12Frame};
use crate::input::{self, InputMapper, Mods};
use crate::reconnect::ReconnectPolicy;
use crate::render::VideoRenderer;
use crate::session::{
    lock_stats, LogLimiter, Session, SessionMsg, SessionParams, SharedStats, LOG_INTERVAL,
};
use crate::state::{ConnState, Phase};
use crate::stats::Stats;
use crate::store::{self, PairedDevice, Store};
use crate::ui::{self, UiAction, UiState, View};
use mirror_protocol::geometry::Rect;
use mirror_protocol::Message;

/// Per-OS integration points. Implemented by `mirror-mac` (and later
/// `mirror-windows`); this crate never touches platform-native types.
/// Called on the event-loop (main) thread.
pub trait PlatformHooks {
    /// Adjust the event loop before it is built (e.g. platform menus).
    fn configure_event_loop(&self, _builder: &mut EventLoopBuilder<UserEvent>) {}
    /// Called once, right after the main window is created.
    fn on_window_created(&self, _window: &Window) {}
    /// A stream with this encoded size started or changed (rotation): lock
    /// the window's content aspect ratio to it and resize, keeping the long
    /// edge (see [`crate::state::window_size_for_video`]).
    fn on_video_size(&self, _window: &Window, _width: u32, _height: u32) {}
    /// No video any more (back home): release the aspect lock.
    fn on_video_cleared(&self, _window: &Window) {}
    /// Plain text on the clipboard, for pasting to the phone (Cmd+V while
    /// controlling). Called on the main thread, only when the user pastes.
    fn clipboard_text(&self) -> Option<String> {
        None
    }
    /// A screen reader is running (macOS: VoiceOver). Keeps the top bar
    /// pinned so its buttons can be reached. Polled at most once a second.
    fn screen_reader_on(&self) -> bool {
        false
    }
}

/// Startup options from the platform binary.
#[derive(Debug, Clone, Default)]
pub struct RunOptions {
    /// `clientName` shown on the phone.
    pub client_name: String,
    /// Connect to this address right away (dev: `--connect host:port`).
    pub auto_connect: Option<String>,
    /// Settings file override (`None` = the user's app data dir).
    pub settings_path: Option<PathBuf>,
    /// PIN for the first connect (dev/scripted: `--pin 123456`). Wiped on drop.
    pub pin: Option<Zeroizing<String>>,
}

/// Wake-ups for the event loop from other threads.
#[derive(Debug)]
pub enum UserEvent {
    Session {
        id: u64,
        msg: SessionMsg,
    },
    /// A screen reader (VoiceOver) asked for the UI tree or acted on it.
    AccessKit(accesskit_winit::Event),
}

impl From<accesskit_winit::Event> for UserEvent {
    fn from(e: accesskit_winit::Event) -> Self {
        UserEvent::AccessKit(e)
    }
}

/// Create the event loop and run the receiver app until the window is closed.
/// `decoder_factory` builds the platform video decoder for each session.
pub fn run(
    hooks: Box<dyn PlatformHooks>,
    decoder_factory: DecoderFactory,
    options: RunOptions,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut builder = EventLoop::<UserEvent>::with_user_event();
    hooks.configure_event_loop(&mut builder);
    let event_loop = builder.build()?;
    event_loop.set_control_flow(ControlFlow::Wait);
    let mut app = App::new(hooks, decoder_factory, options, event_loop.create_proxy());
    event_loop.run_app(&mut app)?;
    app.shutdown();
    app.error.map_or(Ok(()), Err)
}

/// Smallest window (logical points) on home; with video, the same long
/// edge at the video's aspect ratio so an aspect-locked window can shrink.
const MIN_HOME: (f64, f64) = (240.0, 320.0);

fn min_window_size(video: Option<(u32, u32)>) -> (f64, f64) {
    let Some((w, h)) = video.filter(|&(w, h)| w > 0 && h > 0) else {
        return MIN_HOME;
    };
    let long = MIN_HOME.1;
    let (w, h) = (f64::from(w), f64::from(h));
    if h >= w {
        ((long * w / h).round(), long)
    } else {
        (long, (long * h / w).round())
    }
}

/// Brightness of the picture while the phone screen is off / reconnecting.
const DIM_SCREEN_OFF: f32 = 0.35;
const DIM_RECONNECTING: f32 = 0.4;
/// How long closing the window waits for the session to say BYE.
const CLOSE_WAIT: Duration = Duration::from_millis(1500);
/// The "pairing not saved" warning is longer than a normal toast.
const UNSAVED_PAIRING_TOAST: Duration = Duration::from_secs(10);

fn to_wgpu(c: egui::Color32) -> wgpu::Color {
    let f = |v: u8| f64::from(v) / 255.0;
    wgpu::Color {
        r: f(c.r()),
        g: f(c.g()),
        b: f(c.b()),
        a: 1.0,
    }
}

/// Per-session hand-off state (see [`App::shared`]).
struct SessionShared {
    slot: FrameSlot,
    stats: SharedStats,
}

impl SessionShared {
    fn new() -> Self {
        SessionShared {
            slot: FrameSlot::new(FramePool::new()),
            stats: Arc::new(Mutex::new(Stats::new())),
        }
    }

    /// Start a new session's state, detached from the old session's.
    fn renew(&mut self) {
        *self = Self::new();
    }
}

struct App {
    hooks: Box<dyn PlatformHooks>,
    factory: DecoderFactory,
    options: RunOptions,
    proxy: EventLoopProxy<UserEvent>,
    gfx: Option<Gfx>,
    /// Startup failure, returned from `run` so the process exits non-zero.
    error: Option<Box<dyn std::error::Error>>,
    conn: ConnState,
    ui: UiState,
    /// A press was handed to the phone and not yet released: egui hover
    /// (e.g. over the top bar) must not interrupt that drag.
    phone_drag: bool,
    session: Option<(u64, Session)>,
    next_session: u64,
    /// Frame slot and stats of the current session only; every session gets
    /// fresh ones so a stopped session's late frames can never show up.
    shared: SessionShared,
    /// Settings + pairings, shared with the network client.
    store: Store,
    /// Video size the window is currently locked to.
    locked: Option<(u32, u32)>,
    title: String,
    auto_connect: Option<String>,
    /// `--pin`, used by the first connect only (wiped on drop).
    first_pin: Option<Zeroizing<String>>,
    /// Pointer / key input for the phone (see [`crate::input`]).
    mapper: InputMapper,
    mods: Mods,
    /// Last cursor position, window physical pixels.
    cursor: (f64, f64),
    /// IME is enabled on the window (only while controlling).
    ime_on: bool,
    /// The window is hidden or minimised: frames are neither uploaded nor
    /// drawn (the decoder keeps going, so the picture is current on return).
    occluded: bool,
    /// The picture last uploaded, kept CPU-side so a rebuilt GPU device can
    /// show it again without waiting for the phone to send a new frame.
    last_frame: Option<Nv12Frame>,
    /// Drawing has been failing for a while (see [`display_in_trouble`]):
    /// said in the window title, as the surface itself cannot show it.
    display_trouble: bool,
    /// Paired phones, for the UI. Cached: reading the store takes its lock,
    /// which a concurrent save holds through write + fsync. Refreshed when
    /// pairings change (`Paired`, forget).
    paired: Vec<PairedDevice>,
    /// The last address as it should be on disk (see [`save_last_address`]).
    last_address: Arc<Mutex<Option<String>>>,
    /// An accessibility client asked for the UI tree (egui builds it only
    /// then). Any client does, not only screen readers: see `screen_reader`.
    accesskit_on: bool,
    /// The latest screen-reader action asked for while the window was
    /// hidden, and when (see [`fresh_action`]).
    held_action: Option<(egui::accesskit::ActionRequest, Instant)>,
    /// When the event loop last woke up (see [`wake_at`]).
    woke: Instant,
    /// Whether the platform says a screen reader is running.
    screen_reader: ScreenReaderPoll,
    /// Rebuilding the GPU state failed; it is retried with backoff.
    gpu_retry: Option<GpuRetry>,
}

/// A window whose GPU state could not be rebuilt yet.
struct GpuRetry {
    window: Arc<Window>,
    /// The screen-reader adapter of the window, carried over to the next
    /// `Gfx` (a new one cannot be made for a window that is already shown).
    accesskit: Option<accesskit_winit::Adapter>,
    failures: u32,
    at: Instant,
}

/// How long to wait before rebuilding the GPU state again after `failures`
/// failed attempts: quick at first, then about once a second.
fn gpu_retry_delay(failures: u32) -> Duration {
    Duration::from_millis(250 << failures.saturating_sub(1).min(2))
}

impl App {
    fn new(
        hooks: Box<dyn PlatformHooks>,
        factory: DecoderFactory,
        options: RunOptions,
        proxy: EventLoopProxy<UserEvent>,
    ) -> Self {
        let mut options = options;
        let store = Store::open(options.settings_path.clone().or_else(store::default_path));
        // Keeps an id another instance wrote first (see `ensure_client_id`).
        store.ensure_client_id();
        let options_pin = options.pin.take().filter(|p| {
            let ok = crate::is_valid_pin(p);
            if !ok {
                eprintln!("ignoring the startup PIN: it must be exactly 6 digits");
            }
            ok
        });
        let last_address = store.get().last_address;
        let ui = UiState::with_address(last_address.clone().unwrap_or_default());
        let paired = store.pairings();
        App {
            hooks,
            factory,
            auto_connect: options.auto_connect.clone(),
            options,
            proxy,
            gfx: None,
            error: None,
            conn: ConnState::new(),
            ui,
            phone_drag: false,
            session: None,
            next_session: 0,
            shared: SessionShared::new(),
            store,
            locked: None,
            title: String::new(),
            first_pin: options_pin,
            mapper: InputMapper::new(),
            mods: Mods::default(),
            cursor: (0.0, 0.0),
            ime_on: false,
            occluded: false,
            last_frame: None,
            display_trouble: false,
            paired,
            last_address: Arc::new(Mutex::new(last_address)),
            accesskit_on: false,
            held_action: None,
            screen_reader: ScreenReaderPoll::default(),
            woke: Instant::now(),
            gpu_retry: None,
        }
    }

    fn start_session(&mut self, target: Target, pin: Option<Zeroizing<String>>) {
        self.stop_session();
        self.shared.renew();
        self.clear_picture();
        self.conn.connect(target.clone());
        self.next_session += 1;
        let id = self.next_session;
        let proxy = self.proxy.clone();
        let mut client = ClientConfig::new(
            self.options.client_name.clone(),
            self.store.ensure_client_id(),
        );
        client.store = self.store.clone();
        client.pin = pin;
        let params = SessionParams {
            target,
            client,
            policy: ReconnectPolicy::default(),
            factory: self.factory.clone(),
            slot: self.shared.slot.clone(),
            stats: self.shared.stats.clone(),
            notify: Arc::new(move |msg| {
                // Fails only once the event loop is gone (shutting down).
                let _ = proxy.send_event(UserEvent::Session { id, msg });
            }),
        };
        match Session::start(params) {
            Ok(s) => self.session = Some((id, s)),
            Err(e) => self.conn.on_start_failed(e.to_string()),
        }
    }

    /// Forget the current picture (back to home / a new session).
    fn clear_picture(&mut self) {
        if let Some(g) = self.gfx.as_mut() {
            g.video.clear();
        }
        self.last_frame = None;
    }

    /// Show the kept picture again on a fresh GPU renderer.
    fn restore_picture(&mut self) {
        if let (Some(g), Some(f)) = (self.gfx.as_mut(), &self.last_frame) {
            g.upload(f);
        }
    }

    /// Ask the running session to end; its thread finishes in the
    /// background and its late events are ignored (stale id).
    fn stop_session(&mut self) {
        if let Some((_, s)) = self.session.take() {
            s.stop();
        }
        self.shared.slot.clear();
    }

    fn shutdown(&mut self) {
        if let Some((_, s)) = self.session.take() {
            if !s.stop_and_wait(CLOSE_WAIT) {
                eprintln!("session did not end within {CLOSE_WAIT:?}");
            }
        }
        flush_unsaved(&self.store);
    }

    fn apply(&mut self, action: UiAction) {
        match action {
            UiAction::Connect(raw) => match parse_target(&raw) {
                Ok(t) => {
                    self.ui.address_error = None;
                    let pin = self.first_pin.take();
                    self.start_session(t, pin);
                }
                Err(e) => self.ui.address_error = Some(e.to_string()),
            },
            UiAction::Retry => {
                if let Some(t) = self.conn.target.clone() {
                    self.start_session(t, None);
                }
            }
            UiAction::SubmitPin(pin) => {
                if let (true, Some(t)) = (crate::is_valid_pin(&pin), self.conn.target.clone()) {
                    self.start_session(t, Some(pin));
                }
            }
            UiAction::Forget(id) => self.forget(&id),
            UiAction::ForgetAndRepair(id) => {
                self.forget(&id);
                if let Some(t) = self.conn.target.clone() {
                    // Without a key the client asks for the PIN again.
                    self.start_session(t, None);
                }
            }
            UiAction::Disconnect => {
                self.stop_session();
                self.conn.go_home();
                self.clear_picture();
            }
        }
        self.sync_window();
    }

    /// The video rect (window physical pixels) the renderer draws to.
    fn video_rect(&self) -> Option<Rect> {
        let g = self.gfx.as_ref()?;
        g.video.fit(g.config.width, g.config.height)
    }

    fn session_allows_control(&self) -> bool {
        self.session
            .as_ref()
            .is_some_and(|(_, s)| s.control_available())
    }

    /// Send `msgs` in order; stops at the first failure (sending later
    /// parts of a paste after a dropped one would garble it). Returns
    /// whether everything was sent.
    fn send_control(&self, msgs: Vec<Message>) -> bool {
        let Some((_, s)) = &self.session else {
            return msgs.is_empty();
        };
        send_all(msgs, |m| s.send_control(m).is_ok())
    }

    /// Turn window events into phone input (after egui had its look).
    /// `consumed`: egui used this event.
    fn on_input_event(&mut self, event: &WindowEvent, consumed: bool) {
        let now = Instant::now();
        match event {
            WindowEvent::Focused(false) => {
                self.mapper.cancel();
                self.phone_drag = false;
                return;
            }
            // A drag that leaves the window continues (clamped to the
            // video's edge, see `input`).
            WindowEvent::CursorLeft { .. } => {
                self.mapper.cursor_left();
                return;
            }
            WindowEvent::ModifiersChanged(m) => {
                self.mods = input::mods_from_winit(m.state());
                return;
            }
            WindowEvent::CursorMoved { position, .. } => self.cursor = (position.x, position.y),
            _ => {}
        }
        let rect = self.video_rect();
        let Some(rect) = rect
            .filter(|_| input_enabled(&self.conn, self.session_allows_control(), rect.is_some()))
        else {
            self.mapper.cancel();
            self.phone_drag = false;
            return;
        };
        self.mapper.set_rect(rect);
        let Some(gfx) = self.gfx.as_ref() else { return };
        let egui_ctx = gfx.egui_state.egui_ctx();
        // The top bar sits over the phone's status bar: a press on its
        // background (not a button) is the phone's, and a drag that began
        // there or on the video stays the phone's whatever egui hovers.
        let ppp = egui_ctx.pixels_per_point();
        let pos = egui::pos2((self.cursor.0 as f32) / ppp, (self.cursor.1 as f32) / ppp);
        let on_bar_chrome = self.ui.bar_passes_to_phone(pos, egui_ctx.layer_id_at(pos));
        let pointer_free =
            on_bar_chrome || self.phone_drag || (!consumed && !egui_ctx.egui_wants_pointer_input());
        // While controlling, egui never sees keys (`keep_keys_for_phone`),
        // so its focus must not gate them either: every key goes to the phone.
        let cursor = self.cursor;
        let msgs = match event {
            WindowEvent::CursorMoved { .. } => {
                if pointer_free {
                    self.mapper.pointer_moved(cursor, now);
                } else {
                    self.mapper.cancel();
                }
                Vec::new()
            }
            WindowEvent::MouseInput { state, button, .. } => {
                match (input::button_from_winit(*button), state) {
                    (Some(b), ElementState::Pressed) if pointer_free => {
                        self.phone_drag = input::drag_held_after(self.phone_drag, b, true, true);
                        self.mapper.button_pressed(b, cursor, now)
                    }
                    (Some(_), ElementState::Pressed) => {
                        self.mapper.cancel();
                        self.phone_drag = false;
                        Vec::new()
                    }
                    (Some(b), ElementState::Released) => {
                        self.phone_drag = input::drag_held_after(self.phone_drag, b, false, false);
                        self.mapper.button_released(b, cursor, now)
                    }
                    _ => Vec::new(),
                }
            }
            WindowEvent::MouseWheel { delta, .. } if pointer_free => {
                self.mapper.wheel(input::wheel_from_winit(*delta))
            }
            WindowEvent::KeyboardInput { event: e, .. } if e.state == ElementState::Pressed => {
                let key = input::key_from_winit(&e.logical_key, e.physical_key);
                let hooks = &self.hooks;
                let msgs =
                    self.mapper
                        .key_event(key, self.mods, e.text.as_deref(), e.repeat, || {
                            hooks.clipboard_text()
                        });
                let pasting = input::is_paste(key, self.mods) && !msgs.is_empty();
                let mut toast = self.mapper.take_notice().map(input::Notice::text);
                if !self.send_control(msgs) && pasting {
                    toast = Some(input::Notice::PasteInterrupted.text());
                }
                if let Some(t) = toast {
                    self.toast(t);
                }
                return;
            }
            WindowEvent::Ime(ime) => input::ime_commit_text(ime)
                .map(|t| self.mapper.text(t))
                .unwrap_or_default(),
            _ => Vec::new(),
        };
        self.send_control(msgs);
        if let Some(n) = self.mapper.take_notice() {
            self.toast(n.text());
        }
    }

    fn toast(&mut self, text: &str) {
        self.ui.show_toast(text);
        if let Some(g) = &self.gfx {
            g.window.request_redraw();
        }
    }

    /// Runs on the UI thread on purpose: it is a rare click, the save is one
    /// small file, and "Forget and pair again" must have the key gone before
    /// the new session looks it up (off-thread, that needs a hand-off).
    fn forget(&mut self, device_id: &str) {
        if let Err(e) = self.store.remove_pairing(device_id) {
            eprintln!("settings: {e}");
            let text = crate::state::unsaved_forget_notice(&e.to_string());
            self.ui.show_toast_for(&text, UNSAVED_PAIRING_TOAST);
        }
        self.paired = self.store.pairings();
    }

    fn on_user_event(&mut self, ev: UserEvent) {
        let (id, msg) = match ev {
            UserEvent::Session { id, msg } => (id, msg),
            UserEvent::AccessKit(e) => return self.on_accesskit(e.window_event),
        };
        if self.session.as_ref().map(|(sid, _)| *sid) != Some(id) {
            return; // a stopped session's late message
        }
        if !syncs_window(&msg) {
            if let Some(g) = &self.gfx {
                g.window.request_redraw();
            }
            return;
        }
        match msg {
            SessionMsg::FrameReady => {}
            SessionMsg::Client(ev) => {
                match &ev {
                    ClientEvent::Connected { .. } => self.remember_target(),
                    // The phone's text stays out of the UI (see `describe`).
                    ClientEvent::Disconnected(DisconnectReason::Protocol(m))
                    | ClientEvent::Stopped(DisconnectReason::Protocol(m)) => {
                        eprintln!("session: protocol error: {m:?}");
                    }
                    ClientEvent::Paired { save_error, .. } => {
                        self.paired = self.store.pairings();
                        if let Some(text) =
                            crate::state::unsaved_pairing_notice(save_error.as_deref())
                        {
                            self.ui.show_toast_for(&text, UNSAVED_PAIRING_TOAST);
                        }
                    }
                    _ => {}
                }
                self.conn.on_event(&ev, Instant::now());
            }
            SessionMsg::ResolveFailed(m) => self.conn.on_resolve_failed(m),
            SessionMsg::Ended => {
                self.session = None;
                if self.conn.is_active() {
                    // Defensive: the thread ended without a final event.
                    self.conn.go_home();
                }
            }
        }
        if !matches!(
            self.conn.phase,
            Phase::Mirroring { .. } | Phase::Reconnecting { .. }
        ) {
            self.clear_picture();
        }
        self.sync_window();
        if let Some(g) = &self.gfx {
            g.window.request_redraw();
        }
    }

    fn on_accesskit(&mut self, ev: accesskit_winit::WindowEvent) {
        use accesskit_winit::WindowEvent as E;
        // Recorded even while the GPU is being rebuilt: the screen reader
        // asks for the tree only once, and the rebuild turns it back on.
        self.accesskit_on = accesskit_wanted(self.accesskit_on, &ev);
        // A screen reader that just started asks for the tree: re-check now.
        self.screen_reader.invalidate();
        let Some(g) = self.gfx.as_mut() else { return };
        match ev {
            E::InitialTreeRequested => g.egui_state.egui_ctx().enable_accesskit(),
            // egui runs actions on its next pass, which a hidden window does
            // not get: queued, it would fire whenever the window shows again.
            // Only the latest is held, and used only if the window shows
            // right after (the action itself may have brought it forward).
            E::ActionRequested(r) => {
                if !should_render(self.occluded, g.window.is_minimized()) {
                    self.held_action = Some((r, Instant::now()));
                    return;
                }
                self.held_action = None;
                g.egui_state.on_accesskit_action_request(r);
            }
            E::AccessibilityDeactivated => g.egui_state.egui_ctx().disable_accesskit(),
        }
        g.window.request_redraw();
    }

    fn remember_target(&mut self) {
        let Some(t) = &self.conn.target else { return };
        let addr = t.to_string();
        self.ui.address.clone_from(&addr);
        {
            let mut want = lock_ignoring_poison(&self.last_address);
            if !address_save_needed(want.as_deref(), &addr, self.store.unsaved()) {
                return;
            }
            *want = Some(addr);
        }
        save_last_address(self.store.clone(), self.last_address.clone());
    }

    /// The main window, with or without working GPU state.
    fn window(&self) -> Option<&Arc<Window>> {
        self.gfx
            .as_ref()
            .map(|g| &g.window)
            .or(self.gpu_retry.as_ref().map(|r| &r.window))
    }

    /// Title and aspect lock follow the connection state.
    fn sync_window(&mut self) {
        let Some(window) = self.window().cloned() else {
            return;
        };
        let window = &*window;
        let mut title = self.conn.title();
        if self.display_trouble {
            title.push_str(" \u{2014} can't draw, retrying");
        }
        if title != self.title {
            window.set_title(&title);
            self.title = title;
        }
        let want = match self.conn.phase {
            Phase::Mirroring { video: Some(v) } => Some(v),
            // Keep the lock while waiting for the first config / reconnecting.
            Phase::Mirroring { video: None } | Phase::Reconnecting { .. } => self.locked,
            _ => None,
        };
        if want != self.locked {
            let (min_w, min_h) = min_window_size(want);
            window.set_min_inner_size(Some(LogicalSize::new(min_w, min_h)));
            match want {
                Some((w, h)) => self.hooks.on_video_size(window, w, h),
                None => self.hooks.on_video_cleared(window),
            }
            self.locked = want;
        }
    }

    /// Rebuild the GPU state after a lost device or a forced rebuild. A
    /// failed rebuild keeps the window open and is retried with backoff
    /// (the title says so), as the GPU often comes back (driver reset,
    /// eGPU replugged).
    fn rebuild_gpu_if_needed(&mut self, now: Instant) {
        if let Some(mut old) = self.gfx.take_if(|g| g.device_lost.load(Ordering::Acquire)) {
            self.gpu_retry = Some(GpuRetry {
                window: old.window.clone(),
                accesskit: old.egui_state.accesskit.take(),
                failures: 0,
                at: now,
            });
            drop(old); // release the dead device before creating a new one
        }
        let Some(retry) = self.gpu_retry.as_mut().filter(|r| now >= r.at) else {
            return;
        };
        match Gfx::new(retry.window.clone()) {
            Ok(mut gfx) => {
                gfx.egui_state.accesskit = retry.accesskit.take();
                if self.accesskit_on {
                    gfx.egui_state.egui_ctx().enable_accesskit();
                }
                self.gpu_retry = None;
                self.display_trouble = false;
                gfx.window.request_redraw();
                self.gfx = Some(gfx);
                // The new renderer has no picture: show the last one again.
                self.restore_picture();
            }
            Err(e) => {
                retry.failures = retry.failures.saturating_add(1);
                let wait = gpu_retry_delay(retry.failures);
                retry.at = now + wait;
                eprintln!("cannot rebuild the GPU state ({e}); retrying in {wait:?}");
                self.display_trouble = true;
            }
        }
        self.sync_window();
    }

    fn redraw(&mut self, event_loop: &ActiveEventLoop) {
        // Keys go to the phone, not to egui (see `keep_keys_for_phone`).
        let forwarding = input_enabled(
            &self.conn,
            self.session_allows_control(),
            self.video_rect().is_some(),
        );
        let Some(gfx) = self.gfx.as_mut() else { return };
        if !should_render(self.occluded, gfx.window.is_minimized()) {
            // Frames stay in the slot (latest wins); `Occluded(false)` redraws.
            event_loop.set_control_flow(ControlFlow::Wait);
            return;
        }
        let video_phase = matches!(
            self.conn.phase,
            Phase::Mirroring { .. } | Phase::Reconnecting { .. }
        );
        if let Some(f) = self.shared.slot.take() {
            // A stopped session's last frame may still land here; don't keep it.
            if video_phase {
                gfx.upload(&f);
                if let Some(old) = self.last_frame.replace(f) {
                    self.shared.slot.pool().recycle(old);
                }
            } else {
                self.shared.slot.pool().recycle(f);
            }
        }
        let has_video = video_phase && gfx.video.frame_size().is_some();
        let dim = match self.conn.phase {
            Phase::Reconnecting { .. } => DIM_RECONNECTING,
            _ if self.conn.screen_off => DIM_SCREEN_OFF,
            _ => 1.0,
        };
        let now = Instant::now();
        let stats = (self.ui.show_stats && matches!(self.conn.phase, Phase::Mirroring { .. }))
            .then(|| lock_stats(&self.shared.stats).snapshot(now));
        let paired: &[PairedDevice] = match self.conn.phase {
            Phase::Home | Phase::Disconnected { .. } => &self.paired,
            _ => &[],
        };
        let view = View {
            conn: &self.conn,
            has_video,
            forwarding,
            stats,
            paired,
            now,
        };
        let clear = if has_video { ui::LETTERBOX } else { ui::NAVY };
        self.ui.screen_reader = self
            .screen_reader
            .get(now, || self.hooks.screen_reader_on());
        let ui_state = &mut self.ui;
        let mut actions = Vec::new();
        let delay = gfx.redraw(
            to_wgpu(clear),
            has_video.then_some(dim),
            forwarding,
            |root| {
                actions = ui::draw(root, ui_state, &view);
            },
        );
        let had_actions = !actions.is_empty();
        for a in actions {
            self.apply(a);
        }
        let trouble = self
            .gfx
            .as_ref()
            .is_some_and(|g| display_in_trouble(g.failures));
        if trouble != self.display_trouble {
            self.display_trouble = trouble;
            self.sync_window();
        }
        let Some(gfx) = self.gfx.as_ref() else { return };
        if delay.is_zero() || had_actions {
            gfx.window.request_redraw();
        }
        event_loop.set_control_flow(control_flow_after(delay, Instant::now()));
    }
}

/// While keys are forwarded to the phone, egui must not act on them: Tab
/// would move focus to the top bar's buttons (then Enter/Space click
/// Disconnect, and egui's focus would block forwarding). Drop keyboard
/// events from egui's input and release any focus. Pointer input stays.
fn keep_keys_for_phone(ctx: &egui::Context, raw: &mut egui::RawInput) {
    raw.events.retain(|e| {
        !matches!(
            e,
            egui::Event::Key { .. }
                | egui::Event::Text(_)
                | egui::Event::Paste(_)
                | egui::Event::Copy
                | egui::Event::Cut
                | egui::Event::Ime(_)
        )
    });
    ctx.memory_mut(|m| {
        if let Some(id) = m.focused() {
            m.surrender_focus(id);
        }
    });
}

/// Input may go to the phone only while streaming a picture over a session
/// that is allowed to control it (the UI's STATUS view and the session's
/// authoritative flag agree).
fn input_enabled(conn: &ConnState, session_allows: bool, has_rect: bool) -> bool {
    matches!(conn.phase, Phase::Mirroring { .. })
        && conn.control_available
        && session_allows
        && has_rect
}

/// Send `msgs` in order with `send`, stopping at the first failure.
fn send_all(msgs: Vec<Message>, send: impl FnMut(Message) -> bool) -> bool {
    msgs.into_iter().all(send)
}

/// Session messages that can change what the window shows besides the
/// picture (state, title, aspect lock). A new frame only needs a redraw.
fn syncs_window(msg: &SessionMsg) -> bool {
    !matches!(msg, SessionMsg::FrameReady)
}

fn lock_ignoring_poison<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Whether a screen reader is on after `ev` (`on` before it).
fn accesskit_wanted(on: bool, ev: &accesskit_winit::WindowEvent) -> bool {
    use accesskit_winit::WindowEvent as E;
    match ev {
        E::InitialTreeRequested => true,
        E::AccessibilityDeactivated => false,
        E::ActionRequested(_) => on,
    }
}

/// The platform's "screen reader on" answer, re-read at most once a
/// second (it is asked on every redraw).
#[derive(Debug, Default)]
struct ScreenReaderPoll {
    on: bool,
    checked: Option<Instant>,
}

impl ScreenReaderPoll {
    const INTERVAL: Duration = Duration::from_secs(1);

    fn get(&mut self, now: Instant, read: impl FnOnce() -> bool) -> bool {
        let due = self
            .checked
            .is_none_or(|t| now.saturating_duration_since(t) >= Self::INTERVAL);
        if due {
            self.on = read();
            self.checked = Some(now);
        }
        self.on
    }

    /// Read the platform again on the next `get`.
    fn invalidate(&mut self) {
        self.checked = None;
    }
}

/// How long a screen-reader action asked for while the window was hidden
/// stays valid: long enough for the window to come forward because of it,
/// short enough that a stale one never fires on a later, unrelated show.
const HELD_ACTION_TTL: Duration = Duration::from_secs(1);

/// The held action, if it was asked for less than [`HELD_ACTION_TTL`] ago.
fn fresh_action<T>(held: Option<(T, Instant)>, now: Instant) -> Option<T> {
    held.and_then(|(r, at)| (now.saturating_duration_since(at) < HELD_ACTION_TTL).then_some(r))
}

/// Last chance to write changes whose save failed (quitting): one more
/// save, which replays them onto the file.
fn flush_unsaved(store: &Store) {
    if store.unsaved() {
        if let Err(e) = store.update(|_| ()) {
            eprintln!("settings: still not saved at quit: {e}");
        }
    }
}

/// Whether connecting to `addr` must save it. `want` is the address the
/// last save was asked to write; after a failed save (`unsaved`) it is not
/// on disk, so the same address is saved again rather than skipped.
fn address_save_needed(want: Option<&str>, addr: &str, unsaved: bool) -> bool {
    unsaved || want != Some(addr)
}

/// Save the last address off the UI thread: a save fsyncs and may wait on
/// the store lock. The value is read from `latest` when the save runs, so
/// saves that finish out of order still leave the newest address on disk.
fn save_last_address(
    store: Store,
    latest: Arc<Mutex<Option<String>>>,
) -> Option<std::thread::JoinHandle<()>> {
    let spawned = std::thread::Builder::new()
        .name("settings-save".into())
        .spawn(move || {
            if let Err(e) = store.update(|s| s.last_address = lock_ignoring_poison(&latest).clone())
            {
                eprintln!("settings: {e}");
            }
        });
    spawned
        .inspect_err(|e| eprintln!("settings: cannot start a save: {e}"))
        .ok()
}

/// What the event loop should do after egui asked to repaint in `delay`.
fn control_flow_after(delay: Duration, now: Instant) -> ControlFlow {
    match now.checked_add(delay) {
        Some(at) if !delay.is_zero() => ControlFlow::WaitUntil(at),
        _ => ControlFlow::Wait,
    }
}

/// `current` extended to also wake at `at`. A `WaitUntil` from before the
/// last wake-up (`woke`) is stale and is dropped: keeping it would wake the
/// loop at once, forever. One set since then is kept even if it has just
/// passed (a repaint egui asked for), so the loop wakes for it right away.
fn wake_at(current: ControlFlow, at: Instant, woke: Instant) -> ControlFlow {
    match current {
        ControlFlow::WaitUntil(t) if t > woke => ControlFlow::WaitUntil(t.min(at)),
        _ => ControlFlow::WaitUntil(at),
    }
}

/// Immediate retries allowed after a failed frame acquisition before backing off.
const MAX_IMMEDIATE_RETRIES: u32 = 3;
/// Delay between retries once `MAX_IMMEDIATE_RETRIES` consecutive failures happened.
const RETRY_BACKOFF: Duration = Duration::from_millis(200);

/// How long to wait before retrying after `failures` consecutive failed frames:
/// immediately for the first few, then a fixed backoff so a persistent error
/// cannot spin the CPU.
fn retry_delay(failures: u32) -> Duration {
    if failures <= MAX_IMMEDIATE_RETRIES {
        Duration::ZERO
    } else {
        RETRY_BACKOFF
    }
}

/// Consecutive failed frames after which the window title says drawing is
/// stuck (the surface itself cannot show anything then): the immediate
/// retries plus about a second of backoff.
const TROUBLE_AFTER: u32 = MAX_IMMEDIATE_RETRIES + 5;
/// Consecutive failed frames after which the GPU state is rebuilt from
/// scratch (about seven seconds of backoff), as after a lost device.
const REBUILD_AFTER: u32 = MAX_IMMEDIATE_RETRIES + 35;

fn display_in_trouble(failures: u32) -> bool {
    failures >= TROUBLE_AFTER
}

/// True exactly once per streak of failures, so one rebuild is requested.
fn rebuild_due(failures: u32) -> bool {
    failures == REBUILD_AFTER
}

/// Frames are drawn only into a window somebody can see.
fn should_render(occluded: bool, minimized: Option<bool>) -> bool {
    !occluded && minimized != Some(true)
}

/// Device-lost callback: flags the loss so the next event rebuilds the GPU state.
/// Without it a lost device only surfaces as endless `Validation` frame failures.
fn on_device_lost(flag: Arc<AtomicBool>) -> impl Fn(wgpu::DeviceLostReason, String) {
    move |reason, message| {
        // `Destroyed` is our own teardown, not a failure to recover from.
        if reason != wgpu::DeviceLostReason::Destroyed {
            eprintln!("GPU device lost ({reason:?}): {message}");
            flag.store(true, Ordering::Release);
        }
    }
}

struct Gfx {
    /// Consecutive frames that failed to acquire a surface texture.
    failures: u32,
    /// Limits the malformed-frame log line.
    frame_log: LogLimiter,
    /// Set by the device-lost callback; checked before handling each window event.
    device_lost: Arc<AtomicBool>,
    instance: wgpu::Instance,
    window: Arc<Window>,
    surface: wgpu::Surface<'static>,
    device: wgpu::Device,
    queue: wgpu::Queue,
    config: wgpu::SurfaceConfiguration,
    egui_state: egui_winit::State,
    egui_renderer: egui_wgpu::Renderer,
    video: VideoRenderer,
}

impl Gfx {
    fn new(window: Arc<Window>) -> Result<Self, Box<dyn std::error::Error>> {
        let instance =
            wgpu::Instance::new(wgpu::InstanceDescriptor::new_without_display_handle_from_env());
        let surface = instance.create_surface(window.clone())?;
        let adapter = pollster::block_on(instance.request_adapter(&wgpu::RequestAdapterOptions {
            power_preference: wgpu::PowerPreference::HighPerformance,
            force_fallback_adapter: false,
            compatible_surface: Some(&surface),
            ..Default::default()
        }))?;
        let (device, queue) =
            pollster::block_on(adapter.request_device(&wgpu::DeviceDescriptor {
                label: Some("mirror-receiver"),
                ..Default::default()
            }))?;
        let device_lost = Arc::new(AtomicBool::new(false));
        device.set_device_lost_callback(on_device_lost(device_lost.clone()));

        let size = window.inner_size();
        let mut config = surface
            .get_default_config(&adapter, size.width.max(1), size.height.max(1))
            .ok_or("surface not supported by adapter")?;
        // Prefer a non-sRGB format: egui-wgpu expects to write gamma-space colours.
        let caps = surface.get_capabilities(&adapter);
        if let Some(fmt) = caps.formats.iter().copied().find(|f| !f.is_srgb()) {
            config.format = fmt;
        }
        config.present_mode = wgpu::PresentMode::AutoVsync;
        config.desired_maximum_frame_latency = 1;
        surface.configure(&device, &config);

        let egui_ctx = egui::Context::default();
        ui::apply_theme(&egui_ctx);
        let egui_state = egui_winit::State::new(
            egui_ctx,
            egui::ViewportId::ROOT,
            &window,
            Some(window.scale_factor() as f32),
            window.theme(),
            Some(device.limits().max_texture_dimension_2d as usize),
        );
        let egui_renderer = egui_wgpu::Renderer::new(
            &device,
            config.format,
            egui_wgpu::RendererOptions::default(),
        );
        let video = VideoRenderer::new(&device, config.format);

        Ok(Self {
            failures: 0,
            frame_log: LogLimiter::new(LOG_INTERVAL),
            device_lost,
            instance,
            window,
            surface,
            device,
            queue,
            config,
            egui_state,
            egui_renderer,
            video,
        })
    }

    fn upload(&mut self, frame: &Nv12Frame) {
        if !self.video.upload(&self.device, &self.queue, frame) {
            if let Some(n) = self.frame_log.check(Instant::now()) {
                eprintln!("dropping malformed frame {frame:?} ({n} similar suppressed)");
            }
        }
    }

    fn resize(&mut self, width: u32, height: u32) {
        if width == 0 || height == 0 {
            return;
        }
        self.config.width = width;
        self.config.height = height;
        self.surface.configure(&self.device, &self.config);
    }

    /// Records a failed frame and returns when to retry.
    fn retry_after_failure(&mut self) -> Duration {
        self.failures = self.failures.saturating_add(1);
        if self.failures == MAX_IMMEDIATE_RETRIES + 1 {
            eprintln!(
                "surface keeps failing; retrying every {}ms",
                RETRY_BACKOFF.as_millis()
            );
        }
        if rebuild_due(self.failures) {
            eprintln!("surface still failing; rebuilding the GPU state");
            self.device_lost.store(true, Ordering::Release);
        }
        retry_delay(self.failures)
    }

    /// Renders one frame (video first when `video_dim` is `Some`, then the
    /// egui UI built by `run_ui`) and returns when egui wants the next one.
    fn redraw(
        &mut self,
        clear: wgpu::Color,
        video_dim: Option<f32>,
        forward_keys: bool,
        mut run_ui: impl FnMut(&mut egui::Ui),
    ) -> Duration {
        // A suboptimal frame is still drawn; the surface is reconfigured only after
        // it is presented, because wgpu rejects `configure` while a frame is held.
        let (frame, reconfigure) = match self.surface.get_current_texture() {
            wgpu::CurrentSurfaceTexture::Success(f) => (f, false),
            wgpu::CurrentSurfaceTexture::Suboptimal(f) => (f, true),
            // Reconfigure to the window's current size; a minimised (0x0) window
            // can't be presented to, so wait for the Resized event instead of
            // rebuilding the swapchain in a loop.
            wgpu::CurrentSurfaceTexture::Outdated => {
                let size = self.window.inner_size();
                if size.width == 0 || size.height == 0 {
                    return Duration::MAX;
                }
                self.resize(size.width, size.height);
                return self.retry_after_failure();
            }
            wgpu::CurrentSurfaceTexture::Lost => {
                match self.instance.create_surface(self.window.clone()) {
                    Ok(surface) => {
                        surface.configure(&self.device, &self.config);
                        self.surface = surface;
                        return self.retry_after_failure();
                    }
                    Err(e) => eprintln!("failed to recreate lost surface: {e}"),
                }
                return Duration::MAX;
            }
            wgpu::CurrentSurfaceTexture::Timeout | wgpu::CurrentSurfaceTexture::Validation => {
                return self.retry_after_failure();
            }
            // Occluded: the next window event (e.g. un-minimise) redraws.
            wgpu::CurrentSurfaceTexture::Occluded => return Duration::MAX,
        };
        self.failures = 0;
        let view = frame
            .texture
            .create_view(&wgpu::TextureViewDescriptor::default());

        let mut raw_input = self.egui_state.take_egui_input(&self.window);
        if forward_keys {
            keep_keys_for_phone(self.egui_state.egui_ctx(), &mut raw_input);
        }
        let mut full_output = self.egui_state.egui_ctx().run_ui(raw_input, &mut run_ui);
        self.egui_state
            .handle_platform_output(&self.window, full_output.platform_output);

        let ppp = full_output.pixels_per_point;
        let prims = self
            .egui_state
            .egui_ctx()
            .tessellate(full_output.shapes, ppp);
        let screen = egui_wgpu::ScreenDescriptor {
            size_in_pixels: [self.config.width, self.config.height],
            pixels_per_point: ppp,
        };
        for (id, deltas) in &full_output.textures_delta.set {
            for delta in deltas {
                self.egui_renderer
                    .update_texture(&self.device, &self.queue, *id, delta);
            }
        }

        if let Some(dim) = video_dim {
            self.video.set_dim(&self.queue, dim);
        }
        let mut encoder = self
            .device
            .create_command_encoder(&wgpu::CommandEncoderDescriptor {
                label: Some("frame"),
            });
        let extra = self.egui_renderer.update_buffers(
            &self.device,
            &self.queue,
            &mut encoder,
            &prims,
            &screen,
        );
        {
            let mut pass = encoder
                .begin_render_pass(&wgpu::RenderPassDescriptor {
                    label: Some("main"),
                    color_attachments: &[Some(wgpu::RenderPassColorAttachment {
                        view: &view,
                        depth_slice: None,
                        resolve_target: None,
                        ops: wgpu::Operations {
                            load: wgpu::LoadOp::Clear(clear),
                            store: wgpu::StoreOp::Store,
                        },
                    })],
                    depth_stencil_attachment: None,
                    timestamp_writes: None,
                    occlusion_query_set: None,
                    multiview_mask: None,
                })
                .forget_lifetime();
            if video_dim.is_some() {
                self.video
                    .draw(&mut pass, self.config.width, self.config.height);
            }
            // egui sets its own full-surface viewport.
            self.egui_renderer.render(&mut pass, &prims, &screen);
        }
        self.queue
            .submit(extra.into_iter().chain(std::iter::once(encoder.finish())));
        self.window.pre_present_notify();
        self.queue.present(frame);
        if reconfigure {
            self.surface.configure(&self.device, &self.config);
        }

        for id in &full_output.textures_delta.free {
            self.egui_renderer.free_texture(id);
        }
        // Handled above; egui's debug builds panic if a non-empty delta is dropped.
        full_output.textures_delta.clear();
        full_output
            .viewport_output
            .get(&egui::ViewportId::ROOT)
            .map_or(Duration::MAX, |v| v.repaint_delay)
    }
}

impl ApplicationHandler<UserEvent> for App {
    fn resumed(&mut self, event_loop: &ActiveEventLoop) {
        if self.gfx.is_some() {
            return;
        }
        // Hidden until the screen-reader adapter exists (it must be made
        // before the window is first shown).
        let attrs = Window::default_attributes()
            .with_title("Android Mirror")
            .with_visible(false)
            .with_inner_size(LogicalSize::new(480.0, 900.0))
            .with_min_inner_size(LogicalSize::new(MIN_HOME.0, MIN_HOME.1));
        let window = match event_loop.create_window(attrs) {
            Ok(w) => Arc::new(w),
            Err(e) => {
                self.error = Some(Box::new(e));
                event_loop.exit();
                return;
            }
        };
        self.hooks.on_window_created(&window);
        match Gfx::new(window.clone()) {
            Ok(mut gfx) => {
                gfx.egui_state
                    .init_accesskit(event_loop, &window, self.proxy.clone());
                self.gfx = Some(gfx);
            }
            Err(e) => {
                self.error = Some(e);
                event_loop.exit();
                return;
            }
        }
        window.set_visible(true);
        self.restore_picture();
        if let Some(addr) = self.auto_connect.take() {
            self.ui.address.clone_from(&addr);
            self.apply(UiAction::Connect(addr));
        }
        self.sync_window();
        window.request_redraw();
    }

    fn suspended(&mut self, _event_loop: &ActiveEventLoop) {
        // Platforms that suspend (Android, iOS; not macOS) require the
        // surface to be released: drop all GPU state and the window, and
        // let `resumed` build them again. The session keeps running.
        self.mapper.cancel();
        self.phone_drag = false;
        self.ime_on = false;
        self.occluded = false;
        self.locked = None; // the new window needs its aspect lock again
        self.title.clear();
        self.gfx = None;
        self.gpu_retry = None;
    }

    fn exiting(&mut self, _event_loop: &ActiveEventLoop) {
        // Also reached from Quit (⌘Q), where AppKit ends the process
        // without returning from `run_app`: say BYE to the phone first.
        self.shutdown();
    }

    fn user_event(&mut self, _event_loop: &ActiveEventLoop, event: UserEvent) {
        self.on_user_event(event);
    }

    fn new_events(&mut self, _event_loop: &ActiveEventLoop, cause: StartCause) {
        self.woke = Instant::now();
        if let StartCause::ResumeTimeReached { .. } = cause {
            self.rebuild_gpu_if_needed(Instant::now());
            if let Some(gfx) = &self.gfx {
                gfx.window.request_redraw();
            }
        }
    }

    fn window_event(&mut self, event_loop: &ActiveEventLoop, _id: WindowId, event: WindowEvent) {
        self.rebuild_gpu_if_needed(Instant::now());
        if matches!(event, WindowEvent::CloseRequested) {
            self.shutdown();
            event_loop.exit();
            return;
        }
        let Some(gfx) = self.gfx.as_mut() else { return };
        let response = gfx.egui_state.on_window_event(&gfx.window, &event);
        match event {
            WindowEvent::Resized(size) => {
                gfx.resize(size.width, size.height);
                gfx.window.request_redraw();
            }
            WindowEvent::Occluded(occluded) => {
                self.occluded = occluded;
                if !occluded {
                    if let Some(r) = fresh_action(self.held_action.take(), Instant::now()) {
                        gfx.egui_state.on_accesskit_action_request(r);
                    }
                    gfx.window.request_redraw();
                }
            }
            WindowEvent::RedrawRequested => self.redraw(event_loop),
            _ => {
                if response.repaint {
                    gfx.window.request_redraw();
                }
                self.on_input_event(&event, response.consumed);
            }
        }
    }

    fn about_to_wait(&mut self, event_loop: &ActiveEventLoop) {
        let controlling = input_enabled(
            &self.conn,
            self.session_allows_control(),
            self.video_rect().is_some(),
        );
        if !controlling {
            self.mapper.cancel();
            self.phone_drag = false;
        }
        if controlling != self.ime_on {
            if let Some(g) = &self.gfx {
                g.window.set_ime_allowed(controlling);
            }
            self.ime_on = controlling;
        }
        let now = Instant::now();
        let msgs = self.mapper.tick(now);
        let _ = self.send_control(msgs);
        // Wake up for the long-press threshold and the GPU rebuild retry.
        let wake = [
            self.mapper.next_tick_at(),
            self.gpu_retry.as_ref().map(|r| r.at),
        ];
        if let Some(at) = wake.into_iter().flatten().min() {
            let flow = wake_at(event_loop.control_flow(), at, self.woke);
            event_loop.set_control_flow(flow);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn old_session_frame_never_reaches_new_session() {
        let mut shared = SessionShared::new();
        let old_slot = shared.slot.clone(); // held by the old decode thread
        shared.renew(); // new session starts
        old_slot.put(Nv12Frame {
            width: 2,
            height: 2,
            y: vec![0; 4],
            y_stride: 2,
            uv: vec![0; 2],
            uv_stride: 2,
            pts_us: 1,
        });
        assert!(shared.slot.take().is_none());
    }

    #[test]
    fn failed_gpu_rebuilds_back_off_to_about_a_second() {
        let delays: Vec<Duration> = (1..=6).map(gpu_retry_delay).collect();
        assert!(delays[0] > Duration::ZERO, "never a busy retry");
        assert!(delays.windows(2).all(|w| w[0] <= w[1]), "{delays:?}");
        assert_eq!(delays[5], Duration::from_secs(1));
        assert_eq!(gpu_retry_delay(u32::MAX), Duration::from_secs(1));
    }

    #[test]
    fn a_new_frame_does_not_resync_the_window() {
        assert!(!syncs_window(&SessionMsg::FrameReady));
        assert!(syncs_window(&SessionMsg::Ended));
    }

    #[test]
    fn last_address_saves_off_the_ui_thread_and_keeps_the_newest() {
        let store = Store::default();
        let latest = Arc::new(Mutex::new(Some("10.0.0.1:47800".to_string())));
        let mut handle = None;
        // The store is busy (its lock held) when the save starts, and the
        // address changes meanwhile: the save must write the newer one.
        store
            .update(|_| {
                handle = save_last_address(store.clone(), latest.clone());
                *latest.lock().unwrap() = Some("10.0.0.2:47800".into());
            })
            .unwrap();
        handle.unwrap().join().unwrap();
        assert_eq!(store.get().last_address.as_deref(), Some("10.0.0.2:47800"));
    }

    #[test]
    fn a_stale_deadline_does_not_spin_the_event_loop() {
        let now = Instant::now();
        let soon = now + Duration::from_millis(500);
        let stale = ControlFlow::WaitUntil(now - Duration::from_millis(1));
        assert_eq!(wake_at(stale, soon, now), ControlFlow::WaitUntil(soon));
        assert_eq!(
            wake_at(ControlFlow::Wait, soon, now),
            ControlFlow::WaitUntil(soon)
        );
        let sooner = now + Duration::from_millis(10);
        let flow = ControlFlow::WaitUntil(sooner);
        assert_eq!(
            wake_at(flow, soon, now),
            flow,
            "an earlier future wake-up wins"
        );
        // Set after the wake-up and passed while events were handled: due
        // now, not stale.
        let woke = now - Duration::from_millis(5);
        let due = ControlFlow::WaitUntil(now - Duration::from_millis(1));
        assert_eq!(wake_at(due, soon, woke), due);
    }

    #[test]
    fn screen_reader_state_is_tracked_without_a_gpu() {
        use accesskit_winit::WindowEvent as E;
        assert!(accesskit_wanted(false, &E::InitialTreeRequested));
        assert!(!accesskit_wanted(true, &E::AccessibilityDeactivated));
        assert!(!accesskit_wanted(false, &E::AccessibilityDeactivated));
    }

    #[test]
    fn screen_reader_is_polled_at_most_once_a_second() {
        let t0 = Instant::now();
        let mut poll = ScreenReaderPoll::default();
        let reads = std::cell::Cell::new(0);
        let get = |p: &mut ScreenReaderPoll, at: Duration, on: bool| {
            p.get(t0 + at, || {
                reads.set(reads.get() + 1);
                on
            })
        };
        assert!(!get(&mut poll, Duration::ZERO, false));
        assert!(!get(&mut poll, Duration::from_millis(900), true), "cached");
        assert_eq!(reads.get(), 1);
        assert!(get(&mut poll, Duration::from_millis(1000), true));
        assert_eq!(reads.get(), 2);
        poll.invalidate();
        assert!(!get(&mut poll, Duration::from_millis(1001), false));
        assert_eq!(reads.get(), 3, "re-read after invalidate");
    }

    #[test]
    fn a_failed_address_save_is_retried() {
        assert!(!address_save_needed(Some("a:1"), "a:1", false));
        assert!(address_save_needed(Some("a:1"), "b:1", false));
        assert!(address_save_needed(None, "a:1", false));
        assert!(address_save_needed(Some("a:1"), "a:1", true), "retry");
    }

    #[test]
    fn device_lost_callback_flags_rebuild() {
        let flag = Arc::new(AtomicBool::new(false));
        on_device_lost(flag.clone())(wgpu::DeviceLostReason::Unknown, "test".into());
        assert!(flag.load(Ordering::Acquire));
    }

    #[test]
    fn device_destroyed_by_us_does_not_flag_rebuild() {
        let flag = Arc::new(AtomicBool::new(false));
        on_device_lost(flag.clone())(wgpu::DeviceLostReason::Destroyed, "drop".into());
        assert!(!flag.load(Ordering::Acquire));
    }

    #[test]
    fn hidden_windows_are_not_rendered() {
        assert!(should_render(false, None));
        assert!(should_render(false, Some(false)));
        assert!(!should_render(true, Some(false)), "occluded");
        assert!(!should_render(false, Some(true)), "minimised");
    }

    #[test]
    fn persistent_failures_surface_then_rebuild_once() {
        assert!(!display_in_trouble(0));
        assert!(!display_in_trouble(MAX_IMMEDIATE_RETRIES));
        assert!(display_in_trouble(TROUBLE_AFTER));
        assert!(display_in_trouble(u32::MAX));
        let due: Vec<u32> = (0..REBUILD_AFTER + 50)
            .filter(|&f| rebuild_due(f))
            .collect();
        assert_eq!(due, vec![REBUILD_AFTER], "one rebuild per streak");
        const { assert!(REBUILD_AFTER > TROUBLE_AFTER, "the user is told first") };
    }

    #[test]
    fn idle_repaint_waits_for_events() {
        let now = Instant::now();
        assert!(matches!(
            control_flow_after(Duration::MAX, now),
            ControlFlow::Wait
        ));
        assert!(matches!(
            control_flow_after(Duration::ZERO, now),
            ControlFlow::Wait
        ));
    }

    #[test]
    fn first_failures_retry_immediately() {
        for failures in 1..=MAX_IMMEDIATE_RETRIES {
            assert_eq!(retry_delay(failures), Duration::ZERO);
        }
    }

    #[test]
    fn persistent_failures_back_off() {
        assert_eq!(retry_delay(MAX_IMMEDIATE_RETRIES + 1), RETRY_BACKOFF);
        assert_eq!(retry_delay(u32::MAX), RETRY_BACKOFF);
        assert!(matches!(
            control_flow_after(retry_delay(u32::MAX), Instant::now()),
            ControlFlow::WaitUntil(_)
        ));
    }

    #[test]
    fn min_size_follows_video_aspect() {
        assert_eq!(min_window_size(None), MIN_HOME);
        assert_eq!(min_window_size(Some((0, 10))), MIN_HOME);
        assert_eq!(min_window_size(Some((1088, 2400))), (145.0, 320.0));
        assert_eq!(min_window_size(Some((2400, 1088))), (320.0, 145.0));
    }

    /// Frames of the mirroring UI (pointer over the top bar so it shows)
    /// fed `keys` one per frame; from key number `forward_from` on (0:
    /// always, `usize::MAX`: never) frames apply `keep_keys_for_phone`.
    /// Returns the UI's actions and whether egui ended up wanting keys.
    fn mirroring_ui_with_keys(keys: &[egui::Key], forward_from: usize) -> (Vec<UiAction>, bool) {
        use crate::client::ClientEvent;
        let ctx = egui::Context::default();
        ui::apply_theme(&ctx);
        let mut conn = ConnState::new();
        conn.connect(Target {
            host: "10.0.0.2".into(),
            port: 47800,
        });
        conn.phase = Phase::Mirroring {
            video: Some((1080, 2400)),
        };
        conn.on_event(
            &ClientEvent::Status(mirror_protocol::StatusState::ControlAvailable),
            Instant::now(),
        );
        let mut state = UiState::default();
        let view = View {
            conn: &conn,
            has_video: true,
            forwarding: true,
            stats: None,
            paired: &[],
            now: Instant::now(),
        };
        let screen = egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(480.0, 900.0));
        let mut actions = Vec::new();
        let mut frame = |i: usize, forwarding: bool, events: Vec<egui::Event>| {
            let mut raw = egui::RawInput {
                time: Some(i as f64 * 0.016),
                screen_rect: Some(screen),
                events,
                ..Default::default()
            };
            if forwarding {
                keep_keys_for_phone(&ctx, &mut raw);
            }
            let mut out = ctx.run_ui(raw, |root| {
                actions.extend(ui::draw(root, &mut state, &view))
            });
            out.textures_delta.clear();
        };
        let fwd = forward_from == 0;
        frame(
            0,
            fwd,
            vec![egui::Event::PointerMoved(egui::pos2(240.0, 400.0))],
        );
        frame(
            1,
            fwd,
            vec![egui::Event::PointerMoved(egui::pos2(200.0, 10.0))],
        );
        for (i, &key) in keys.iter().enumerate() {
            let ev = |pressed| egui::Event::Key {
                key,
                physical_key: None,
                pressed,
                repeat: false,
                modifiers: egui::Modifiers::NONE,
            };
            let fwd = i >= forward_from;
            frame(2 + 2 * i, fwd, vec![ev(true)]);
            frame(3 + 2 * i, fwd, vec![ev(false)]);
        }
        (actions, ctx.egui_wants_keyboard_input())
    }

    #[test]
    fn keys_never_reach_egui_while_controlling() {
        use egui::Key::{Enter, Space, Tab};
        // Tab focuses the top bar's Disconnect; Enter / Space click it.
        for keys in [[Tab, Enter], [Tab, Space]] {
            let (actions, wants_keys) = mirroring_ui_with_keys(&keys, 0);
            assert!(actions.is_empty(), "{keys:?} acted on the UI: {actions:?}");
            assert!(!wants_keys, "egui focus would block forwarding");
        }
        // Keyboard events are dropped, pointer events kept.
        let pointer = egui::Event::PointerMoved(egui::pos2(1.0, 2.0));
        let mut raw = egui::RawInput {
            events: vec![
                egui::Event::Text("a".into()),
                pointer.clone(),
                egui::Event::Paste("p".into()),
                egui::Event::Key {
                    key: Tab,
                    physical_key: None,
                    pressed: true,
                    repeat: false,
                    modifiers: egui::Modifiers::NONE,
                },
            ],
            ..Default::default()
        };
        keep_keys_for_phone(&egui::Context::default(), &mut raw);
        assert_eq!(raw.events, vec![pointer]);
        // Guard for the test itself: without the filter the bug shows.
        let (actions, wants_keys) = mirroring_ui_with_keys(&[Tab, Enter], usize::MAX);
        assert!(
            wants_keys && matches!(actions[..], [UiAction::Disconnect]),
            "{actions:?}"
        );
        // Focus taken before control started (view-only) is released.
        let (actions, wants_keys) = mirroring_ui_with_keys(&[Tab, Enter], 1);
        assert!(actions.is_empty(), "{actions:?}");
        assert!(!wants_keys, "stale focus would block forwarding");
    }

    #[test]
    fn send_all_stops_at_the_first_failure() {
        let msgs = || {
            (0..4)
                .map(|i| Message::Text(i.to_string()))
                .collect::<Vec<_>>()
        };
        let mut sent = Vec::new();
        let ok = send_all(msgs(), |m| {
            let fail = m == Message::Text("1".into());
            sent.push(m);
            !fail
        });
        assert!(!ok);
        assert_eq!(sent.len(), 2, "nothing after the dropped chunk");
        assert!(send_all(msgs(), |_| true));
        assert!(send_all(Vec::new(), |_| false));
    }

    #[test]
    fn finite_repaint_delay_schedules_wakeup() {
        let now = Instant::now();
        let d = Duration::from_millis(50);
        assert!(matches!(control_flow_after(d, now), ControlFlow::WaitUntil(t) if t == now + d));
    }

    #[test]
    fn input_is_gated_on_streaming_control_and_picture() {
        use crate::client::ClientEvent;
        let mut conn = ConnState::new();
        assert!(!input_enabled(&conn, true, true), "home");
        conn.connect(Target {
            host: "10.0.0.2".into(),
            port: 47800,
        });
        conn.phase = Phase::Mirroring {
            video: Some((100, 200)),
        };
        assert!(!input_enabled(&conn, true, true), "phone said view-only");
        conn.on_event(
            &ClientEvent::Status(mirror_protocol::StatusState::ControlAvailable),
            Instant::now(),
        );
        assert!(input_enabled(&conn, true, true));
        assert!(!input_enabled(&conn, false, true), "session refuses");
        assert!(!input_enabled(&conn, true, false), "no picture yet");
        conn.phase = Phase::Reconnecting {
            attempt: 1,
            retry_at: Instant::now(),
        };
        assert!(!input_enabled(&conn, true, true), "reconnecting");
    }

    #[test]
    fn an_action_held_while_hidden_is_used_only_if_the_window_shows_soon() {
        let at = Instant::now();
        assert_eq!(fresh_action(Some((7, at)), at), Some(7));
        let soon = at + HELD_ACTION_TTL - Duration::from_millis(1);
        assert_eq!(fresh_action(Some((7, at)), soon), Some(7));
        assert_eq!(fresh_action(Some((7, at)), at + HELD_ACTION_TTL), None);
        assert_eq!(fresh_action::<u8>(None, at), None);
    }

    #[cfg(unix)]
    #[test]
    fn quitting_saves_changes_whose_save_failed() {
        use std::os::unix::fs::PermissionsExt;
        let d = std::env::temp_dir().join(format!("mirror-app-flush-{}", store::new_client_id()));
        std::fs::create_dir_all(&d).unwrap();
        let p = d.join("settings.json");
        let s = Store::open(Some(p.clone()));
        flush_unsaved(&s);
        assert!(!p.exists(), "nothing to save, nothing written");
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o500)).unwrap();
        let device = PairedDevice {
            device_id: "ph".into(),
            device_name: "Phone".into(),
            key: mirror_protocol::auth::PairingKey::from_bytes([1; 32]),
            paired_at_ms: 1,
        };
        assert!(s.put_pairing(device).is_err());
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
        flush_unsaved(&s);
        assert!(!s.unsaved());
        assert!(store::load(&p).unwrap().pairing("ph").is_some());
        std::fs::remove_dir_all(d).unwrap();
    }
}
