//! Connection state as the UI sees it, driven by user actions and
//! [`ClientEvent`]s. Pure: no I/O, the caller supplies the clock.

use std::io::ErrorKind;
use std::time::{Duration, Instant};

use mirror_protocol::geometry::fit_rect;
use mirror_protocol::{AuthMode, AuthReason, ByeReason, StatusState};

use crate::address::Target;
use crate::client::{ClientEvent, DisconnectReason, TimeoutKind};

/// Base window title.
pub const APP_TITLE: &str = "Android Mirror";

/// Longest phone-supplied name shown anywhere (title, dialogs, lists), in
/// grapheme clusters.
pub const MAX_NAME_CHARS: usize = 64;

/// Most scalar values kept in one grapheme cluster: a flood of combining
/// marks ("zalgo") on one letter would otherwise spill over the window.
const MAX_CLUSTER_CHARS: usize = 8;

const ZWNJ: char = '\u{200C}';
const ZWJ: char = '\u{200D}';

/// Characters that draw nothing or reorder surrounding text, so a hostile
/// phone could use them to hide or spoof text: controls, every Unicode
/// format (Cf) character (bidi overrides, invisible operators, tags, ...),
/// and the blank-looking Hangul fillers and combining grapheme joiner.
fn is_invisible(c: char) -> bool {
    use unicode_general_category::{get_general_category, GeneralCategory};
    c.is_control()
        || get_general_category(c) == GeneralCategory::Format
        || matches!(
            c,
            '\u{034F}'
                | '\u{115F}'
                | '\u{1160}'
                | '\u{17B4}'
                | '\u{17B5}'
                | '\u{3164}'
                | '\u{FFA0}'
        )
}

/// Make untrusted text (phone name / model) safe to show: control, format
/// and filler characters dropped, whitespace runs collapsed to one space,
/// at most `max` grapheme clusters (never cut mid-cluster) with a trailing
/// ellipsis. The ONE helper for every phone-controlled string, so a hostile
/// phone cannot spoof a dialog or fill the window. Reads at most `max + 1`
/// visible clusters of the input.
///
/// ZWJ / ZWNJ are format characters, but they glue emoji sequences and
/// shape Indic and Arabic text, so they are kept inside a cluster that has
/// a visible character, and dropped anywhere else.
pub fn display_text(s: &str, max: usize) -> String {
    use unicode_segmentation::UnicodeSegmentation;
    let mut out: Vec<String> = Vec::new();
    let mut space = false;
    for g in s.graphemes(true) {
        if g.chars().next().is_some_and(char::is_whitespace) {
            space = !out.is_empty();
            continue;
        }
        let cluster: String = g
            .chars()
            .filter(|&c| matches!(c, ZWJ | ZWNJ) || (!is_invisible(c) && !c.is_whitespace()))
            .take(MAX_CLUSTER_CHARS)
            .collect();
        if !cluster.chars().any(|c| !matches!(c, ZWJ | ZWNJ)) {
            continue;
        }
        if space {
            out.push(" ".into());
            space = false;
        }
        out.push(cluster);
        if out.len() > max {
            break;
        }
    }
    if out.len() > max {
        out.truncate(max.saturating_sub(1));
        while out.last().is_some_and(|c| c == " ") {
            out.pop();
        }
        out.push('\u{2026}'.to_string());
    }
    out.concat()
}

/// Video sizes from the phone outside these limits are ignored: they would
/// produce a zero-size window or degenerate aspect lock.
const MIN_VIDEO_SIDE: u32 = 16;
const MAX_VIDEO_ASPECT: u32 = 8;

pub fn video_size_is_sane(w: u32, h: u32) -> bool {
    w >= MIN_VIDEO_SIDE
        && h >= MIN_VIDEO_SIDE
        && w <= h.saturating_mul(MAX_VIDEO_ASPECT)
        && h <= w.saturating_mul(MAX_VIDEO_ASPECT)
}

#[derive(Debug, Clone, PartialEq)]
pub enum Phase {
    /// No session: address entry.
    Home,
    /// First connect attempt in flight.
    Connecting,
    /// Session up. `video` is the encoded size from the latest VIDEO_CONFIG.
    Mirroring { video: Option<(u32, u32)> },
    /// Connection lost; next attempt at `retry_at`.
    Reconnecting { attempt: u32, retry_at: Instant },
    /// Ended without (further) retrying.
    Disconnected { reason: DisconnectReason },
    /// The session thread could not be started (not a network problem).
    StartFailed { message: String },
    /// The reconnect budget ran out.
    GaveUp {
        attempts: u32,
        last: DisconnectReason,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct ConnState {
    pub phase: Phase,
    /// What we connect / connected to (kept for Retry).
    pub target: Option<Target>,
    /// Phone name from SERVER_HELLO.
    pub device: Option<String>,
    /// STATUS screen_off seen (cleared by screen_on / streaming / reconnect).
    pub screen_off: bool,
    /// Why the current outage started (while reconnecting).
    pub lost: Option<DisconnectReason>,
    /// The phone's latest STATUS said `control_available` (cleared by
    /// `control_unavailable` and on every (re)connect / disconnect). Gate
    /// input on this; `Session::send_control` checks it again (and refuses
    /// unauthenticated sessions).
    pub control_available: bool,
    /// When the control indicator last changed (connect, or control turned
    /// on / off): it is shown for a moment from then.
    pub control_changed: Option<Instant>,
    /// How the current session authenticated (set on connect).
    pub auth: Option<AuthMode>,
    /// When the last final event arrived (drives the lockout countdown).
    pub stopped_at: Option<Instant>,
    /// Phone name remembered from `NeedsPin`, so the PIN dialog can still
    /// name the phone after a wrong PIN. Cleared on going home.
    pub pin_device: Option<String>,
}

impl Default for ConnState {
    fn default() -> Self {
        ConnState {
            phase: Phase::Home,
            target: None,
            device: None,
            screen_off: false,
            lost: None,
            control_available: false,
            control_changed: None,
            auth: None,
            stopped_at: None,
            pin_device: None,
        }
    }
}

impl ConnState {
    pub fn new() -> Self {
        Self::default()
    }

    /// User pressed Connect (or Retry).
    pub fn connect(&mut self, target: Target) {
        self.phase = Phase::Connecting;
        self.target = Some(target);
        self.device = None;
        self.screen_off = false;
        self.lost = None;
        self.control_available = false;
        self.auth = None;
        self.stopped_at = None;
    }

    /// User pressed Disconnect / Back / Cancel.
    pub fn go_home(&mut self) {
        self.phase = Phase::Home;
        self.device = None;
        self.screen_off = false;
        self.lost = None;
        self.control_available = false;
        self.auth = None;
        self.stopped_at = None;
        self.pin_device = None;
    }

    /// The target name did not resolve.
    pub fn on_resolve_failed(&mut self, message: String) {
        self.phase = Phase::Disconnected {
            reason: DisconnectReason::Io {
                kind: ErrorKind::NotFound,
                message,
            },
        };
    }

    /// True while a session thread should be running.
    pub fn is_active(&self) -> bool {
        matches!(
            self.phase,
            Phase::Connecting | Phase::Mirroring { .. } | Phase::Reconnecting { .. }
        )
    }

    /// The session thread could not be started.
    pub fn on_start_failed(&mut self, message: String) {
        self.phase = Phase::StartFailed { message };
    }

    pub fn on_event(&mut self, ev: &ClientEvent, now: Instant) {
        match ev {
            ClientEvent::Connected { server, auth, .. } => {
                self.auth = Some(*auth);
                let mut name = display_text(&server.device_name, MAX_NAME_CHARS);
                if name.is_empty() {
                    name = display_text(&server.model, MAX_NAME_CHARS);
                }
                self.device = (!name.is_empty()).then_some(name);
                self.phase = Phase::Mirroring { video: None };
                self.screen_off = false;
                self.lost = None;
                self.control_available = false;
                self.control_changed = Some(now);
            }
            ClientEvent::VideoConfig(cfg) => {
                if let Phase::Mirroring { video } = &mut self.phase {
                    let (w, h) = (u32::from(cfg.width), u32::from(cfg.height));
                    if video_size_is_sane(w, h) {
                        *video = Some((w, h));
                    }
                }
            }
            ClientEvent::Status(s) => match s {
                StatusState::ScreenOff => self.screen_off = true,
                StatusState::ScreenOn | StatusState::Streaming => self.screen_off = false,
                StatusState::ControlAvailable | StatusState::ControlUnavailable => {
                    let on = *s == StatusState::ControlAvailable;
                    if on != self.control_available {
                        self.control_available = on;
                        self.control_changed = Some(now);
                    }
                }
                _ => {}
            },
            ClientEvent::Disconnected(reason) => {
                self.control_available = false;
                if self.is_active() {
                    self.lost = Some(reason.clone());
                }
            }
            ClientEvent::Reconnecting { attempt, delay } => {
                if self.is_active() {
                    self.phase = Phase::Reconnecting {
                        attempt: *attempt,
                        retry_at: now + *delay,
                    };
                }
            }
            ClientEvent::GaveUp { attempts, last } => {
                if self.is_active() {
                    self.phase = Phase::GaveUp {
                        attempts: *attempts,
                        last: last.clone(),
                    };
                }
            }
            ClientEvent::Stopped(reason) => {
                if !self.is_active() {
                    return; // user already left; late final event
                }
                self.stopped_at = Some(now);
                if let DisconnectReason::NeedsPin { device_name, .. } = reason {
                    self.pin_device = Some(display_text(device_name, MAX_NAME_CHARS));
                }
                match reason {
                    DisconnectReason::Closed => self.go_home(),
                    r => {
                        self.phase = Phase::Disconnected { reason: r.clone() };
                    }
                }
            }
            // The pairing itself lives in the store; nothing to track here.
            ClientEvent::Paired { .. } => {}
            ClientEvent::VideoFrame(_) | ClientEvent::Rtt(_) => {}
        }
    }

    /// Window title for the current state.
    pub fn title(&self) -> String {
        match (&self.phase, &self.device) {
            (Phase::Mirroring { .. } | Phase::Reconnecting { .. }, Some(d)) => {
                format!("{APP_TITLE} — {d}")
            }
            _ => APP_TITLE.to_string(),
        }
    }
}

/// Seconds until `retry_at`, rounded up (for "next try in 2 s").
pub fn seconds_until(retry_at: Instant, now: Instant) -> u64 {
    let left = retry_at.saturating_duration_since(now);
    left.as_millis().div_ceil(1000) as u64
}

/// User-facing (headline, explanation) for why a session ended.
pub fn describe(reason: &DisconnectReason) -> (&'static str, String) {
    use DisconnectReason::*;
    match reason {
        Closed => ("Disconnected", "You ended the session.".into()),
        Bye(ByeReason::StoppedByUser) => (
            "Mirroring stopped",
            "Screen sharing was stopped on the phone.".into(),
        ),
        Bye(ByeReason::ProjectionRevoked) => (
            "Screen capture ended",
            "The phone ended screen capture (it may have locked). Start mirroring on the phone again.".into(),
        ),
        Bye(ByeReason::Replaced) => (
            "Another receiver took over",
            "The phone is now mirroring to a different computer.".into(),
        ),
        Bye(ByeReason::AuthFailed) | AuthFailed { .. } => (
            "Pairing failed",
            match reason {
                AuthFailed { reason: Some(r) } => {
                    format!("The phone rejected this Mac: {}.", auth_reason_text(*r))
                }
                _ => "The phone rejected this Mac.".into(),
            },
        ),
        NeedsPin { device_name, .. } => (
            "Pairing required",
            format!(
                "Enter the PIN shown on {}.",
                display_text(device_name, MAX_NAME_CHARS)
            ),
        ),
        WrongPin => (
            "Wrong PIN",
            "Check the PIN shown on the phone and try again.".into(),
        ),
        LockedOut { retry_after } => (
            "Too many attempts",
            format!(
                "The phone is not accepting PINs for {} s.",
                retry_after.as_millis().div_ceil(1000)
            ),
        ),
        PairingRemoved { .. } => (
            "Pairing required",
            "The phone no longer knows this Mac. Pair again with the PIN shown on the phone.".into(),
        ),
        IdentityChanged { .. } => (
            "Device identity changed",
            "This phone could not prove it is the device you paired with. If you reset or reinstalled the app on it, forget the device and pair again.".into(),
        ),
        Bye(ByeReason::ProtoMismatch) | ProtoMismatch { .. } => (
            "Version mismatch",
            "The phone app and this Mac app speak different protocol versions. Update both.".into(),
        ),
        Bye(ByeReason::Unknown) => ("Disconnected", "The phone ended the session.".into()),
        AuthUnsupported { .. } => (
            "Can't authenticate",
            "The phone offers no sign-in method this Mac can use. Update both apps.".into(),
        ),
        ConnectionClosed => (
            "Connection lost",
            "The phone closed the connection.".into(),
        ),
        Timeout(TimeoutKind::Connect) | Timeout(TimeoutKind::Handshake) => (
            "Phone not responding",
            "Check that the phone is on the same Wi-Fi and mirroring is started, then try again.".into(),
        ),
        Timeout(TimeoutKind::Liveness) => (
            "Connection lost",
            "The phone stopped responding. It may have left the Wi-Fi or gone to sleep.".into(),
        ),
        Io { kind, message } => match kind {
            ErrorKind::ConnectionRefused => (
                "Can't reach the phone",
                "Nothing is listening at that address. Start mirroring on the phone and check the IP and port.".into(),
            ),
            ErrorKind::NotFound => ("Address not found", format!("{message}.")),
            ErrorKind::HostUnreachable | ErrorKind::NetworkUnreachable => (
                "Phone unreachable",
                "This Mac has no route to that address. Are both devices on the same network?".into(),
            ),
            _ => ("Network error", capitalise(message)),
        },
        Protocol(m) if m == crate::session::DECODER_FAILED => (
            "Video decoder failed",
            "This Mac's video decoder stopped working on the phone's stream. Try connecting again.".into(),
        ),
        // The phone's own wording (a parser message) is logged, not shown.
        Protocol(_) => (
            "Unexpected data",
            "The phone sent something this Mac couldn't read. Try connecting again.".into(),
        ),
    }
}

/// Warning for a pairing that worked but could not be written to disk yet:
/// every later settings save (and quitting) tries again, and only if none
/// succeeds is the PIN needed again next time.
pub fn unsaved_pairing_notice(save_error: Option<&str>) -> Option<String> {
    save_error.map(|why| {
        format!(
            "Paired, but this Mac couldn't save the pairing yet ({}). It will keep trying; if it can't, you'll need the phone's PIN again next time.",
            display_text(why, 120)
        )
    })
}

/// Warning for a "Forget" that took effect for this run but could not be
/// written to disk yet (retried like an unsaved pairing).
pub fn unsaved_forget_notice(save_error: &str) -> String {
    format!(
        "Forgot the phone, but this Mac couldn't save that yet ({}). It will keep trying; if it can't, the phone may still be paired next time.",
        display_text(save_error, 120)
    )
}

fn auth_reason_text(r: AuthReason) -> &'static str {
    match r {
        AuthReason::UnknownClient => "it doesn't know this Mac",
        AuthReason::BadProof => "the proof didn't verify",
        AuthReason::LockedOut => "too many wrong PINs",
        AuthReason::ModeUnsupported => "it doesn't accept this sign-in method",
        AuthReason::Unknown => "no reason given",
    }
}

fn capitalise(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().chain(c).collect::<String>() + ".",
        None => String::new(),
    }
}

/// Content size for a window showing `video`: keeps the current long edge,
/// takes the video's aspect ratio, and shrinks (aspect kept) to fit within
/// `max` (e.g. 85% of the screen's visible height). Sizes in logical points.
pub fn window_size_for_video(
    current: (f64, f64),
    video: (u32, u32),
    max: (f64, f64),
) -> (f64, f64) {
    let (vw, vh) = (f64::from(video.0.max(1)), f64::from(video.1.max(1)));
    let one = |v: f64| v.max(1.0);
    let pair = |w: f64, h: f64| (one(w), one(h));
    let long = current.0.max(current.1).max(1.0);
    let (w, h) = if vh >= vw {
        (long * vw / vh, long)
    } else {
        (long, long * vh / vw)
    };
    if w <= max.0 && h <= max.1 {
        return pair(w.round(), h.round());
    }
    let r = fit_rect(video.0.max(1), video.1.max(1), max.0, max.1);
    if r.w > 0.0 && r.h > 0.0 {
        pair(r.w.floor(), r.h.floor())
    } else {
        pair(w.round(), h.round())
    }
}

/// Digits in a pairing PIN.
pub const PIN_LEN: usize = 6;

/// Why the PIN dialog is showing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinIssue {
    /// First pairing: the phone is waiting for a PIN.
    Needed,
    /// The PIN we sent was wrong.
    Wrong,
    /// Too many wrong PINs; allowed again at `until`.
    LockedOut { until: Instant },
    /// The phone forgot this Mac.
    Removed,
}

/// The sign-in screen to show for a final auth outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthPrompt {
    Pin {
        issue: PinIssue,
        /// `None` when the phone's name was never seen.
        device_name: Option<String>,
    },
    /// The device at this address is not the phone we paired with.
    Identity { device_id: String },
}

impl ConnState {
    /// The PIN / identity prompt for the current state, if it ended with an
    /// auth outcome the user can act on.
    pub fn auth_prompt(&self) -> Option<AuthPrompt> {
        let Phase::Disconnected { reason } = &self.phase else {
            return None;
        };
        let pin = |issue| AuthPrompt::Pin {
            issue,
            device_name: self.pin_device.clone(),
        };
        Some(match reason {
            DisconnectReason::NeedsPin { device_name, .. } => AuthPrompt::Pin {
                issue: PinIssue::Needed,
                device_name: Some(display_text(device_name, MAX_NAME_CHARS)),
            },
            DisconnectReason::WrongPin => pin(PinIssue::Wrong),
            DisconnectReason::LockedOut { retry_after } => pin(PinIssue::LockedOut {
                until: self.stopped_at?.checked_add(*retry_after)?,
            }),
            DisconnectReason::PairingRemoved { .. } => pin(PinIssue::Removed),
            DisconnectReason::IdentityChanged { device_id } => AuthPrompt::Identity {
                device_id: device_id.clone(),
            },
            _ => return None,
        })
    }
}

/// Seconds of lockout left (rounded up), `None` once it has passed.
pub fn lockout_left(issue: &PinIssue, now: Instant) -> Option<u64> {
    match issue {
        PinIssue::LockedOut { until } => Some(seconds_until(*until, now)).filter(|&s| s > 0),
        _ => None,
    }
}

/// Whether the PIN dialog may submit `pin` now.
pub fn can_submit_pin(pin: &str, issue: &PinIssue, now: Instant) -> bool {
    pin.len() == PIN_LEN
        && pin.bytes().all(|b| b.is_ascii_digit())
        && lockout_left(issue, now).is_none()
}

/// What the streaming overlay says about remote control; `None` when the
/// session cannot be controlled at all (unauthenticated). The bool is
/// "control is on".
pub fn control_indicator(auth: Option<AuthMode>, available: bool) -> Option<(bool, &'static str)> {
    if !matches!(auth, Some(AuthMode::Pin | AuthMode::Token)) {
        return None;
    }
    Some(if available {
        (true, "Control on")
    } else {
        (
            false,
            "View only \u{2014} turn on Remote control on the phone",
        )
    })
}

/// "5 Mar 2026" (UTC) for a unix-millisecond timestamp.
pub fn format_date(ms: u64) -> String {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    // Days since 1970-01-01 -> civil date (Howard Hinnant's algorithm).
    let z = (ms / 86_400_000) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{day} {} {year}", MONTHS[(month - 1) as usize])
}

/// How long the mirroring top bar stays visible after the pointer moved.
pub const BAR_LINGER: Duration = Duration::from_millis(2500);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unsaved_pairing_is_announced_and_a_saved_one_is_not() {
        assert_eq!(unsaved_pairing_notice(None), None);
        let text = unsaved_pairing_notice(Some("disk full")).unwrap();
        assert!(
            text.contains("disk full") && text.contains("PIN again"),
            "{text}"
        );
        assert!(
            text.contains("keep trying"),
            "a later save may work: {text}"
        );
        let text = unsaved_forget_notice("disk full");
        assert!(
            text.starts_with("Forgot") && text.contains("disk full"),
            "{text}"
        );
    }

    #[test]
    fn a_crashing_decoder_has_its_own_headline() {
        let r = DisconnectReason::Protocol(crate::session::DECODER_FAILED.into());
        assert_eq!(describe(&r).0, "Video decoder failed");
    }
    use mirror_protocol::{ServerHello, VideoConfig};

    fn target() -> Target {
        Target {
            host: "192.168.1.42".into(),
            port: 47800,
        }
    }

    fn connected(name: &str) -> ClientEvent {
        ClientEvent::Connected {
            addr: "192.168.1.42:47800".parse().unwrap(),
            server: ServerHello {
                proto: 1,
                device_name: name.into(),
                device_id: "id".into(),
                model: "Pixel 8".into(),
                sdk_int: 35,
                codecs: vec![],
                caps: vec![],
                auth_modes: vec![],
                nonce_s: String::new(),
                kx: String::new(),
            },
            auth: mirror_protocol::AuthMode::Token,
        }
    }

    /// The video size the window would be locked to.
    fn video_of(s: &ConnState) -> Option<(u32, u32)> {
        match s.phase {
            Phase::Mirroring { video } => video,
            _ => None,
        }
    }

    fn config(w: u16, h: u16) -> ClientEvent {
        ClientEvent::VideoConfig(VideoConfig {
            width: w,
            height: h,
            display_width: w,
            display_height: h,
            rotation: 0,
            sps_pps: vec![],
        })
    }

    #[test]
    fn control_change_is_stamped_when_it_arrives() {
        let t0 = Instant::now();
        let at = |ms| t0 + Duration::from_millis(ms);
        let mut s = ConnState::new();
        s.connect(target());
        s.on_event(&connected("P"), at(0));
        assert_eq!(s.control_changed, Some(at(0)), "the indicator appears");
        s.on_event(&ClientEvent::Status(StatusState::ControlAvailable), at(10));
        assert_eq!(s.control_changed, Some(at(10)));
        // A repeated STATUS is not a change.
        s.on_event(&ClientEvent::Status(StatusState::ControlAvailable), at(20));
        assert_eq!(s.control_changed, Some(at(10)));
        s.on_event(
            &ClientEvent::Status(StatusState::ControlUnavailable),
            at(30),
        );
        assert_eq!(s.control_changed, Some(at(30)));
    }

    #[test]
    fn the_phones_parser_text_is_not_shown() {
        let m = "invalid type: map, expected a string at line 1 column 9";
        let (_, detail) = describe(&DisconnectReason::Protocol(m.into()));
        assert!(!detail.contains("invalid type"), "{detail}");
    }

    #[test]
    fn control_flag_follows_status_and_resets_on_reconnect() {
        let now = Instant::now();
        let mut s = ConnState::new();
        s.connect(target());
        s.on_event(&connected("P"), now);
        assert!(!s.control_available);
        s.on_event(&ClientEvent::Status(StatusState::ControlAvailable), now);
        assert!(s.control_available);
        s.on_event(&ClientEvent::Status(StatusState::ControlUnavailable), now);
        assert!(!s.control_available);
        s.on_event(&ClientEvent::Status(StatusState::ControlAvailable), now);
        s.on_event(
            &ClientEvent::Disconnected(DisconnectReason::ConnectionClosed),
            now,
        );
        assert!(!s.control_available, "a new session must re-announce it");
    }

    #[test]
    fn happy_path_and_titles() {
        let now = Instant::now();
        let mut s = ConnState::new();
        assert_eq!(s.title(), "Android Mirror");
        s.connect(target());
        assert_eq!(s.phase, Phase::Connecting);
        assert!(s.is_active());
        s.on_event(&connected("Risa's Pixel"), now);
        assert_eq!(s.phase, Phase::Mirroring { video: None });
        assert_eq!(s.title(), "Android Mirror — Risa's Pixel");
        s.on_event(&config(1088, 2400), now);
        assert_eq!(video_of(&s), Some((1088, 2400)));
        s.on_event(&config(2400, 1088), now); // rotation
        assert_eq!(video_of(&s), Some((2400, 1088)));
        s.go_home();
        assert_eq!(s.phase, Phase::Home);
        assert_eq!(s.title(), "Android Mirror");
        assert_eq!(s.target, Some(target()), "kept for the address field");
    }

    #[test]
    fn empty_device_name_falls_back_to_model() {
        let mut s = ConnState::new();
        s.connect(target());
        s.on_event(&connected("  "), Instant::now());
        assert_eq!(s.device.as_deref(), Some("Pixel 8"));
    }

    #[test]
    fn reconnect_cycle() {
        let now = Instant::now();
        let mut s = ConnState::new();
        s.connect(target());
        s.on_event(&connected("P"), now);
        s.on_event(&ClientEvent::Status(StatusState::ScreenOff), now);
        assert!(s.screen_off);
        s.on_event(
            &ClientEvent::Disconnected(DisconnectReason::ConnectionClosed),
            now,
        );
        assert_eq!(s.lost, Some(DisconnectReason::ConnectionClosed));
        s.on_event(
            &ClientEvent::Reconnecting {
                attempt: 2,
                delay: Duration::from_secs(1),
            },
            now,
        );
        assert_eq!(
            s.phase,
            Phase::Reconnecting {
                attempt: 2,
                retry_at: now + Duration::from_secs(1)
            }
        );
        assert_eq!(s.title(), "Android Mirror — P");
        s.on_event(&connected("P"), now);
        assert_eq!(s.phase, Phase::Mirroring { video: None });
        assert!(!s.screen_off && s.lost.is_none());
    }

    #[test]
    fn final_events() {
        let now = Instant::now();
        let mut s = ConnState::new();
        s.connect(target());
        let refused = DisconnectReason::Io {
            kind: ErrorKind::ConnectionRefused,
            message: "refused".into(),
        };
        s.on_event(&ClientEvent::Stopped(refused.clone()), now);
        assert_eq!(s.phase, Phase::Disconnected { reason: refused });
        assert!(!s.is_active());

        s.connect(target());
        s.on_event(
            &ClientEvent::GaveUp {
                attempts: 8,
                last: DisconnectReason::Timeout(TimeoutKind::Connect),
            },
            now,
        );
        assert!(matches!(s.phase, Phase::GaveUp { attempts: 8, .. }));

        s.connect(target());
        s.on_event(&ClientEvent::Stopped(DisconnectReason::Closed), now);
        assert_eq!(s.phase, Phase::Home);
    }

    #[test]
    fn late_events_after_leaving_are_ignored() {
        let now = Instant::now();
        let mut s = ConnState::new();
        s.connect(target());
        s.go_home();
        s.on_event(
            &ClientEvent::Stopped(DisconnectReason::ConnectionClosed),
            now,
        );
        s.on_event(
            &ClientEvent::Reconnecting {
                attempt: 1,
                delay: Duration::ZERO,
            },
            now,
        );
        assert_eq!(s.phase, Phase::Home);
    }

    #[test]
    fn resolve_failure_is_a_disconnect() {
        let mut s = ConnState::new();
        s.connect(target());
        s.on_resolve_failed("no address found for phone.lan".into());
        let Phase::Disconnected { reason } = &s.phase else {
            panic!("{:?}", s.phase)
        };
        assert_eq!(describe(reason).0, "Address not found");
    }

    #[test]
    fn countdown_rounds_up() {
        let now = Instant::now();
        assert_eq!(seconds_until(now + Duration::from_millis(1200), now), 2);
        assert_eq!(seconds_until(now + Duration::from_millis(1000), now), 1);
        assert_eq!(seconds_until(now, now + Duration::from_secs(1)), 0);
    }

    #[test]
    fn descriptions_are_human() {
        let (h, d) = describe(&DisconnectReason::Bye(ByeReason::StoppedByUser));
        assert_eq!(h, "Mirroring stopped");
        assert!(d.ends_with('.'));
        let (h, d) = describe(&DisconnectReason::Io {
            kind: ErrorKind::Other,
            message: "broken pipe".into(),
        });
        assert_eq!((h, d.as_str()), ("Network error", "Broken pipe."));
        let (h, _) = describe(&DisconnectReason::Io {
            kind: ErrorKind::ConnectionRefused,
            message: String::new(),
        });
        assert_eq!(h, "Can't reach the phone");
    }

    #[test]
    fn window_keeps_long_edge_and_takes_video_aspect() {
        let max = (1600.0, 1000.0);
        // Home window 480x900 -> portrait 1088x2400 video: height stays 900.
        assert_eq!(
            window_size_for_video((480.0, 900.0), (1088, 2400), max),
            (408.0, 900.0)
        );
        // Rotation to landscape keeps the 900 long edge as width.
        assert_eq!(
            window_size_for_video((408.0, 900.0), (2400, 1088), max),
            (900.0, 408.0)
        );
    }

    #[test]
    fn window_shrinks_to_fit_screen() {
        // Long edge 1200 > max height 850: scaled to fit, aspect kept.
        let (w, h) = window_size_for_video((500.0, 1200.0), (1080, 2400), (1600.0, 850.0));
        assert_eq!(h, 850.0);
        assert_eq!(w, (850.0f64 * 1080.0 / 2400.0).floor());
        // Landscape limited by width.
        let (w, h) = window_size_for_video((2000.0, 900.0), (2400, 1080), (1500.0, 850.0));
        assert_eq!(w, 1500.0);
        assert!(h <= 850.0);
        // Degenerate input does not panic.
        let _ = window_size_for_video((0.0, 0.0), (0, 0), (0.0, 0.0));
    }

    fn stopped(s: &mut ConnState, r: DisconnectReason, now: Instant) {
        s.connect(target());
        s.on_event(&ClientEvent::Stopped(r), now);
    }

    #[test]
    fn pin_dialog_state_machine() {
        let now = Instant::now();
        let mut s = ConnState::new();
        stopped(
            &mut s,
            DisconnectReason::NeedsPin {
                device_id: "d".into(),
                device_name: "Pixel".into(),
            },
            now,
        );
        assert_eq!(
            s.auth_prompt(),
            Some(AuthPrompt::Pin {
                issue: PinIssue::Needed,
                device_name: Some("Pixel".into())
            })
        );
        // The retry with a PIN fails: the name survives the reconnect.
        stopped(&mut s, DisconnectReason::WrongPin, now);
        assert_eq!(
            s.auth_prompt(),
            Some(AuthPrompt::Pin {
                issue: PinIssue::Wrong,
                device_name: Some("Pixel".into())
            })
        );
        stopped(
            &mut s,
            DisconnectReason::PairingRemoved {
                device_id: "d".into(),
            },
            now,
        );
        assert!(matches!(
            s.auth_prompt(),
            Some(AuthPrompt::Pin {
                issue: PinIssue::Removed,
                ..
            })
        ));
        stopped(
            &mut s,
            DisconnectReason::IdentityChanged {
                device_id: "d".into(),
            },
            now,
        );
        assert_eq!(
            s.auth_prompt(),
            Some(AuthPrompt::Identity {
                device_id: "d".into()
            })
        );
        stopped(&mut s, DisconnectReason::ConnectionClosed, now);
        assert_eq!(s.auth_prompt(), None);
        s.go_home();
        assert_eq!(s.pin_device, None);
    }

    #[test]
    fn lockout_counts_down_and_gates_submit() {
        let t0 = Instant::now();
        let mut s = ConnState::new();
        stopped(
            &mut s,
            DisconnectReason::LockedOut {
                retry_after: Duration::from_millis(29_500),
            },
            t0,
        );
        let Some(AuthPrompt::Pin { issue, .. }) = s.auth_prompt() else {
            panic!("no prompt");
        };
        assert_eq!(lockout_left(&issue, t0), Some(30));
        assert_eq!(lockout_left(&issue, t0 + Duration::from_secs(29)), Some(1));
        assert!(!can_submit_pin(
            "123456",
            &issue,
            t0 + Duration::from_secs(29)
        ));
        let later = t0 + Duration::from_secs(30);
        assert_eq!(lockout_left(&issue, later), None);
        assert!(can_submit_pin("123456", &issue, later));
    }

    #[test]
    fn pin_submit_needs_six_digits() {
        let now = Instant::now();
        assert!(can_submit_pin("246810", &PinIssue::Wrong, now));
        assert!(!can_submit_pin("24681", &PinIssue::Needed, now));
        assert!(!can_submit_pin("24681a", &PinIssue::Needed, now));
    }

    #[test]
    fn control_indicator_only_for_authenticated_sessions() {
        assert_eq!(control_indicator(Some(AuthMode::NoAuth), true), None);
        assert_eq!(control_indicator(None, false), None);
        assert_eq!(
            control_indicator(Some(AuthMode::Token), true),
            Some((true, "Control on"))
        );
        let (on, text) = control_indicator(Some(AuthMode::Pin), false).unwrap();
        assert!(!on && text.starts_with("View only"));
    }

    #[test]
    fn connected_records_auth_mode() {
        let mut s = ConnState::new();
        s.connect(target());
        s.on_event(&connected("P"), Instant::now());
        assert_eq!(s.auth, Some(AuthMode::Token));
        s.go_home();
        assert_eq!(s.auth, None);
    }

    #[test]
    fn dates_are_formatted_in_utc() {
        assert_eq!(format_date(0), "1 Jan 1970");
        assert_eq!(format_date(1_772_755_200_000), "6 Mar 2026");
        assert_eq!(format_date(951_782_400_000), "29 Feb 2000");
    }

    #[test]
    fn auth_failed_text_is_a_sentence() {
        let (_, d) = describe(&DisconnectReason::AuthFailed {
            reason: Some(AuthReason::BadProof),
        });
        assert!(!d.contains("BadProof") && d.ends_with('.'));
    }

    #[test]
    fn display_text_strips_spoofing_and_truncates() {
        let evil = "Pixel\n\u{202E}Pair with bank\u{2069}\t\u{0007}  8\r\n";
        assert_eq!(display_text(evil, 64), "Pixel Pair with bank 8");
        assert_eq!(display_text("  \n ", 64), "");
        let long = "x".repeat(1_000_000);
        let t = display_text(&long, 10);
        assert_eq!(t.chars().count(), 10);
        assert!(t.ends_with('\u{2026}'));
        assert_eq!(display_text("abc", 3), "abc");
    }

    #[test]
    fn display_text_strips_every_format_char_and_fillers() {
        // Soft hyphen, Arabic number sign, word joiner, invisible
        // operators, isolates, language tag, BOM, Hangul fillers, CGJ.
        for c in [
            '\u{00AD}',
            '\u{0600}',
            '\u{2060}',
            '\u{2062}',
            '\u{206A}',
            '\u{2066}',
            '\u{E0041}',
            '\u{FEFF}',
            '\u{115F}',
            '\u{1160}',
            '\u{3164}',
            '\u{FFA0}',
            '\u{034F}',
            '\u{180E}',
        ] {
            assert_eq!(
                display_text(&format!("a{c}b"), 64),
                "ab",
                "U+{:04X}",
                c as u32
            );
        }
        assert_eq!(
            display_text("\u{3164}\u{FFA0}\u{200D}", 64),
            "",
            "all blank"
        );
    }

    #[test]
    fn display_text_truncates_by_grapheme_and_keeps_zwj_sequences() {
        // Family emoji: 7 scalars, one cluster; must never be cut in half.
        let family = "\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}";
        assert_eq!(display_text(family, 1), family);
        let t = display_text(&format!("{family}{family}{family}"), 2);
        assert_eq!(t, format!("{family}\u{2026}"));
        // Combining accents stay with their letter.
        let e = "e\u{0301}";
        assert_eq!(display_text(&e.repeat(5), 3), format!("{e}{e}\u{2026}"));
        // Flag = two regional indicators = one cluster.
        assert_eq!(
            display_text("\u{1F1EE}\u{1F1E9}ab", 2),
            "\u{1F1EE}\u{1F1E9}\u{2026}"
        );
        // A joiner with nothing visible to join is dropped; zalgo is capped.
        assert_eq!(display_text("a \u{200D} b", 64), "a b");
        let zalgo = format!("a{}", "\u{0301}".repeat(1000));
        assert!(display_text(&zalgo, 64).chars().count() <= MAX_CLUSTER_CHARS);
    }

    #[test]
    fn start_failure_is_not_an_address_error() {
        let mut s = ConnState::new();
        s.connect(target());
        s.on_start_failed("Couldn't start the session: out of threads".into());
        assert!(matches!(s.phase, Phase::StartFailed { .. }));
        assert!(!s.is_active());
        assert_eq!(s.auth_prompt(), None);
    }

    #[test]
    fn hostile_device_name_is_sanitized_everywhere() {
        let now = Instant::now();
        let evil = format!("A\n\u{202E}B{}", "z".repeat(5000));
        let mut s = ConnState::new();
        s.connect(target());
        s.on_event(&connected(&evil), now);
        let dev = s.device.clone().unwrap();
        assert!(dev.chars().count() <= MAX_NAME_CHARS && !dev.contains('\n'));
        assert!(!s.title().contains('\u{202E}') && s.title().chars().count() < 100);

        let mut s = ConnState::new();
        s.connect(target());
        let reason = DisconnectReason::NeedsPin {
            device_name: evil.clone(),
            device_id: "id".into(),
        };
        s.on_event(&ClientEvent::Stopped(reason.clone()), now);
        let AuthPrompt::Pin { device_name, .. } = s.auth_prompt().unwrap() else {
            panic!()
        };
        assert!(device_name.unwrap().chars().count() <= MAX_NAME_CHARS);
        // The remembered name is reused for later WrongPin prompts.
        s.connect(target());
        s.on_event(&ClientEvent::Stopped(DisconnectReason::WrongPin), now);
        let AuthPrompt::Pin { device_name, .. } = s.auth_prompt().unwrap() else {
            panic!()
        };
        assert!(device_name.unwrap().chars().count() <= MAX_NAME_CHARS);
        let (_, text) = describe(&reason);
        assert!(!text.contains('\u{202E}') && text.chars().count() < 120);
    }

    #[test]
    fn insane_video_config_is_ignored() {
        let now = Instant::now();
        for (w, h) in [
            (0, 0),
            (0, 100),
            (1, 65535),
            (65535, 1),
            (15, 800),
            (4000, 100),
        ] {
            let mut s = ConnState::new();
            s.connect(target());
            s.on_event(&connected("P"), now);
            s.on_event(&config(w, h), now);
            assert_eq!(video_of(&s), None, "{w}x{h}");
        }
        let mut s = ConnState::new();
        s.connect(target());
        s.on_event(&connected("P"), now);
        s.on_event(&config(1080, 2400), now);
        s.on_event(&config(0, 0), now);
        assert_eq!(video_of(&s), Some((1080, 2400)));
        for v in [(0, 0), (1, 65535), (u32::MAX, 1)] {
            let (w, h) = window_size_for_video((900.0, 600.0), v, (1000.0, 1000.0));
            assert!(w >= 1.0 && h >= 1.0 && w.is_finite() && h.is_finite());
        }
    }

    #[test]
    fn lockout_deadline_overflow_does_not_panic() {
        let mut s = ConnState::new();
        s.connect(target());
        let reason = DisconnectReason::LockedOut {
            retry_after: Duration::MAX,
        };
        s.on_event(&ClientEvent::Stopped(reason), Instant::now());
        assert!(s.auth_prompt().is_none());
    }
}
