//! Platform-neutral input mapping for remote control (spec §8).
//!
//! [`InputMapper`] is pure and deterministic: callers pass plain positions
//! (window physical pixels), our own button/key enums and the current time.
//! It returns the control [`Message`]s to send. The `winit` adapters at the
//! bottom of the file are thin conversions kept apart from the logic.
//!
//! Gestures: left press+release with < [`TAP_SLOP_PX`] movement and
//! < [`LONG_PRESS`] is a tap; a still hold for [`LONG_PRESS`] is a long press
//! (emitted by [`InputMapper::tick`] or on release, never followed by a tap);
//! anything that moved further is a drag, sent as a path on release. Moving
//! after a long press drags nothing (the phone has no live touch yet), and
//! the user is told so ([`Notice::DragAfterLongPress`]).

use mirror_protocol::geometry::{view_to_norm, view_to_norm_clamped, Rect};
use mirror_protocol::{
    GestureKind, GesturePoint, GlobalAction, Key, Message, Scroll, TouchGesture,
};
use std::time::{Duration, Instant};

/// Movement (physical px) at which a press becomes a drag.
pub const TAP_SLOP_PX: f64 = 8.0;
/// Hold time at which a still press becomes a long press.
pub const LONG_PRESS: Duration = Duration::from_millis(500);
/// Most points in a sent drag path.
pub const MAX_PATH_POINTS: usize = 64;
/// Most raw points remembered for one drag (later ones replace the last).
const MAX_RAW_POINTS: usize = 8192;
/// Most bytes in one TEXT message produced by paste.
pub const MAX_TEXT_BYTES: usize = 64 * 1024;
/// Most bytes one paste may send; larger clipboards are refused whole.
pub const MAX_PASTE_BYTES: usize = 1024 * 1024;
/// Lines of wheel scrolling that equal one full rect height.
const LINES_PER_RECT: f64 = 20.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Button {
    Left,
    Right,
    Middle,
}

/// Wheel / trackpad delta in the units the OS reported.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum WheelDelta {
    Pixels(f64, f64),
    Lines(f64, f64),
}

/// A key as the mapper cares about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyInput {
    /// Backspace, Enter, arrows, Tab, Delete.
    Named(Key),
    /// A character key (used for Cmd shortcuts; matched case-insensitively).
    Char(char),
    Other,
}

/// Whether a press that began on the phone's picture is still held, after
/// a button event. Only the left button drags (right and middle are
/// one-shot Back / Home), so a right click during a left drag must not end
/// the drag. `to_phone`: the press was handed to the phone.
pub fn drag_held_after(held: bool, button: Button, pressed: bool, to_phone: bool) -> bool {
    match (button, pressed) {
        (Button::Left, true) => to_phone,
        (Button::Left, false) => false,
        _ => held,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Mods {
    pub cmd: bool,
    pub ctrl: bool,
    pub shift: bool,
}

#[derive(Debug, Clone, Copy)]
struct RawPoint {
    x: u16,
    y: u16,
    at: Instant,
}

#[derive(Debug)]
struct Press {
    start_pos: (f64, f64),
    start: RawPoint,
    start_time: Instant,
    /// Moved at least [`TAP_SLOP_PX`] from the start: this is a drag.
    dragging: bool,
    long_sent: bool,
    points: Vec<RawPoint>,
}

/// Something the user should be told about (shown briefly by the UI).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Notice {
    /// The clipboard is over [`MAX_PASTE_BYTES`]; nothing was sent.
    PasteTooLarge,
    /// Part of a paste could not be sent; the rest was dropped.
    PasteInterrupted,
    /// The pointer moved after a long press; that drag is not sent.
    DragAfterLongPress,
}

impl Notice {
    pub fn text(self) -> &'static str {
        match self {
            Notice::PasteTooLarge => "Clipboard too large to paste (max 1 MB)",
            Notice::PasteInterrupted => "Paste interrupted",
            Notice::DragAfterLongPress => "Drag after long-press isn't supported yet",
        }
    }
}

#[derive(Debug, Default)]
pub struct InputMapper {
    rect: Rect,
    cursor: Option<(f64, f64)>,
    press: Option<Press>,
    notice: Option<Notice>,
}

impl InputMapper {
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the video rect in window physical pixels (the aspect-fit rect the
    /// renderer draws to).
    ///
    /// A different aspect ratio means the video rotated: a press in
    /// progress was normalised against the old rect, so its later points
    /// would not line up with its start. It is dropped. (A plain resize
    /// keeps the aspect, and the normalised path stays valid.)
    pub fn set_rect(&mut self, rect: Rect) {
        let (old, new) = (self.rect, rect);
        if self.press.is_some() && (old.w * new.h - new.w * old.h).abs() > 0.01 * old.h * new.w {
            self.press = None;
        }
        self.rect = rect;
    }

    /// Drop any in-progress gesture (focus lost, egui took the pointer).
    pub fn cancel(&mut self) {
        self.press = None;
    }

    /// The pointer left the window. A drag in progress continues (the OS
    /// keeps reporting a held button's moves and its release; points are
    /// clamped to the rect). With nothing held the position is forgotten.
    pub fn cursor_left(&mut self) {
        if self.press.is_none() {
            self.cursor = None;
        }
    }

    /// The latest notice for the user, if any (cleared by taking it).
    pub fn take_notice(&mut self) -> Option<Notice> {
        self.notice.take()
    }

    /// Pointer moved to `pos` (also call when no button is down: wheel events
    /// use the last cursor position).
    pub fn pointer_moved(&mut self, pos: (f64, f64), now: Instant) {
        self.cursor = Some(pos);
        let Some(p) = self.press.as_mut() else { return };
        if p.long_sent {
            self.notice = self.notice.or(moved_after_long_press(p, pos));
            return;
        }
        if !p.dragging && dist(p.start_pos, pos) >= TAP_SLOP_PX {
            p.dragging = true;
        }
        if p.dragging {
            if let Some(n) = view_to_norm_clamped(&self.rect, pos.0, pos.1) {
                push_point(
                    &mut p.points,
                    RawPoint {
                        x: n.0,
                        y: n.1,
                        at: now,
                    },
                );
            }
        }
    }

    pub fn button_pressed(
        &mut self,
        button: Button,
        pos: (f64, f64),
        now: Instant,
    ) -> Vec<Message> {
        self.cursor = Some(pos);
        // A press in the letterbox is ignored entirely.
        let Some((x, y)) = view_to_norm(&self.rect, pos.0, pos.1) else {
            return Vec::new();
        };
        match button {
            Button::Left => {
                let start = RawPoint { x, y, at: now };
                self.press = Some(Press {
                    start_pos: pos,
                    start,
                    start_time: now,
                    dragging: false,
                    long_sent: false,
                    points: vec![start],
                });
                Vec::new()
            }
            Button::Right => vec![Message::GlobalAction(GlobalAction::Back)],
            Button::Middle => vec![Message::GlobalAction(GlobalAction::Home)],
        }
    }

    pub fn button_released(
        &mut self,
        button: Button,
        pos: (f64, f64),
        now: Instant,
    ) -> Vec<Message> {
        self.cursor = Some(pos);
        if button != Button::Left {
            return Vec::new();
        }
        let Some(mut p) = self.press.take() else {
            return Vec::new();
        };
        if p.long_sent {
            self.notice = self.notice.or(moved_after_long_press(&mut p, pos));
            return Vec::new();
        }
        if !p.dragging && dist(p.start_pos, pos) >= TAP_SLOP_PX {
            p.dragging = true;
        }
        if p.dragging {
            if let Some(n) = view_to_norm_clamped(&self.rect, pos.0, pos.1) {
                push_point(
                    &mut p.points,
                    RawPoint {
                        x: n.0,
                        y: n.1,
                        at: now,
                    },
                );
            }
            return vec![path_message(&p.points)];
        }
        let kind = if now.saturating_duration_since(p.start_time) >= LONG_PRESS {
            GestureKind::LongPress
        } else {
            GestureKind::Tap
        };
        vec![point_gesture(kind, p.start)]
    }

    /// Call periodically (e.g. on a timer while a button is down): emits the
    /// long press once the still hold reaches [`LONG_PRESS`].
    pub fn tick(&mut self, now: Instant) -> Vec<Message> {
        let Some(p) = self.press.as_mut() else {
            return Vec::new();
        };
        if p.dragging || p.long_sent || now.saturating_duration_since(p.start_time) < LONG_PRESS {
            return Vec::new();
        }
        p.long_sent = true;
        vec![point_gesture(GestureKind::LongPress, p.start)]
    }

    /// When the next [`tick`](Self::tick) could emit something, if a press is
    /// pending (lets the app schedule a wake-up).
    pub fn next_tick_at(&self) -> Option<Instant> {
        let p = self.press.as_ref()?;
        (!p.dragging && !p.long_sent).then(|| p.start_time + LONG_PRESS)
    }

    /// Wheel / trackpad scroll at the last cursor position. Ignored when the
    /// cursor is unknown or in the letterbox. A positive `dy` means the
    /// finger moves down, matching winit's positive-y wheel delta.
    pub fn wheel(&mut self, delta: WheelDelta) -> Vec<Message> {
        let Some((cx, cy)) = self.cursor else {
            return Vec::new();
        };
        let Some((x, y)) = view_to_norm(&self.rect, cx, cy) else {
            return Vec::new();
        };
        let (fx, fy) = match delta {
            WheelDelta::Pixels(dx, dy) => (dx / self.rect.w, dy / self.rect.h),
            WheelDelta::Lines(dx, dy) => (dx / LINES_PER_RECT, dy / LINES_PER_RECT),
        };
        let (dx, dy) = (scroll_norm(fx), scroll_norm(fy));
        if dx == 0 && dy == 0 {
            return Vec::new();
        }
        vec![Message::Scroll(Scroll { x, y, dx, dy })]
    }

    /// Committed text (typed characters, IME commit).
    pub fn text(&mut self, text: &str) -> Vec<Message> {
        let clean: String = text.chars().filter(|c| !c.is_control()).collect();
        if clean.is_empty() {
            Vec::new()
        } else {
            vec![Message::Text(clean)]
        }
    }

    /// A key press from the OS; `repeat` is true for auto-repeat. Repeats
    /// of Cmd shortcuts are ignored (holding Cmd+V must not paste over and
    /// over); other keys (characters, arrows, Backspace) repeat normally.
    pub fn key_event(
        &mut self,
        key: KeyInput,
        mods: Mods,
        text: Option<&str>,
        repeat: bool,
        clipboard: impl FnOnce() -> Option<String>,
    ) -> Vec<Message> {
        if repeat && mods.cmd {
            return Vec::new();
        }
        self.key_pressed(key, mods, text, clipboard)
    }

    /// A key press. `text` is the text the key produced, if any.
    ///
    /// Shortcuts: Cmd+B back, Cmd+H home, Cmd+R recents, Cmd+N
    /// notifications, Cmd+Shift+N quick settings, Cmd+V pastes `clipboard()`
    /// (called only then). Other Cmd/Ctrl combinations produce nothing.
    pub fn key_pressed(
        &mut self,
        key: KeyInput,
        mods: Mods,
        text: Option<&str>,
        clipboard: impl FnOnce() -> Option<String>,
    ) -> Vec<Message> {
        if mods.cmd {
            return match key {
                KeyInput::Char(c) => match c.to_ascii_lowercase() {
                    'b' => vec![Message::GlobalAction(GlobalAction::Back)],
                    'h' => vec![Message::GlobalAction(GlobalAction::Home)],
                    'r' => vec![Message::GlobalAction(GlobalAction::Recents)],
                    'n' if mods.shift => vec![Message::GlobalAction(GlobalAction::QuickSettings)],
                    'n' => vec![Message::GlobalAction(GlobalAction::Notifications)],
                    'v' => match clipboard() {
                        Some(s) if s.len() > MAX_PASTE_BYTES => {
                            self.notice = Some(Notice::PasteTooLarge);
                            Vec::new()
                        }
                        Some(s) => paste_messages(&s),
                        None => Vec::new(),
                    },
                    _ => Vec::new(),
                },
                _ => Vec::new(),
            };
        }
        if let KeyInput::Named(k) = key {
            return vec![Message::Key(k)];
        }
        if mods.ctrl {
            return Vec::new();
        }
        text.map_or_else(Vec::new, |t| self.text(t))
    }
}

/// Cmd+V: the key press that pastes.
pub fn is_paste(key: KeyInput, mods: Mods) -> bool {
    mods.cmd && matches!(key, KeyInput::Char(c) if c.eq_ignore_ascii_case(&'v'))
}

/// Clipboard text as TEXT messages of at most [`MAX_TEXT_BYTES`] bytes,
/// split at char boundaries.
pub fn paste_messages(s: &str) -> Vec<Message> {
    let mut out = Vec::new();
    let mut rest = s;
    while !rest.is_empty() {
        let mut end = rest.len().min(MAX_TEXT_BYTES);
        while !rest.is_char_boundary(end) {
            end -= 1;
        }
        let (head, tail) = rest.split_at(end);
        out.push(Message::Text(head.to_string()));
        rest = tail;
    }
    out
}

/// The first move past [`TAP_SLOP_PX`] after a long press, which the phone
/// cannot follow: the live touch it would need (TOUCH_LIVE) is not
/// implemented on Android yet. Reported once per press.
fn moved_after_long_press(p: &mut Press, pos: (f64, f64)) -> Option<Notice> {
    if p.dragging || dist(p.start_pos, pos) < TAP_SLOP_PX {
        return None;
    }
    p.dragging = true;
    Some(Notice::DragAfterLongPress)
}

fn dist(a: (f64, f64), b: (f64, f64)) -> f64 {
    (a.0 - b.0).hypot(a.1 - b.1)
}

fn push_point(points: &mut Vec<RawPoint>, p: RawPoint) {
    // A point where the pointer already is (the release lands where the last
    // move did, or a drag held against the clamped edge) adds no shape:
    // only the time moves on, so the dwell is kept without a duplicate. The
    // start point stays, so a path always has two points.
    let keep_start = points.len() <= 1;
    if let Some(last) = points.last_mut().filter(|_| !keep_start) {
        if (last.x, last.y) == (p.x, p.y) {
            last.at = p.at;
            return;
        }
    }
    if points.len() >= MAX_RAW_POINTS {
        points.pop();
    }
    points.push(p);
}

fn point_gesture(kind: GestureKind, p: RawPoint) -> Message {
    Message::TouchGesture(TouchGesture {
        kind,
        points: vec![GesturePoint {
            x: p.x,
            y: p.y,
            dt_ms: 0,
        }],
    })
}

/// Fraction of the rect -> signed normalised delta, clamped to i16.
fn scroll_norm(fraction: f64) -> i16 {
    (fraction * f64::from(u16::MAX))
        .round()
        .clamp(f64::from(i16::MIN), f64::from(i16::MAX)) as i16
}

/// Path message from raw points, evenly subsampled to [`MAX_PATH_POINTS`]
/// (first and last kept); `dt_ms` is the time since the previous kept point.
fn path_message(raw: &[RawPoint]) -> Message {
    let n = raw.len();
    let picked: Vec<RawPoint> = if n <= MAX_PATH_POINTS {
        raw.to_vec()
    } else {
        (0..MAX_PATH_POINTS)
            .map(|i| raw[i * (n - 1) / (MAX_PATH_POINTS - 1)])
            .collect()
    };
    let mut prev = picked[0].at;
    let points = picked
        .iter()
        .map(|p| {
            let dt = p.at.saturating_duration_since(prev).as_millis();
            prev = p.at;
            GesturePoint {
                x: p.x,
                y: p.y,
                dt_ms: dt.min(u128::from(u16::MAX)) as u16,
            }
        })
        .collect();
    Message::TouchGesture(TouchGesture {
        kind: GestureKind::Path,
        points,
    })
}

// ---------------------------------------------------------------------------
// winit adapters (no logic beyond conversion)
// ---------------------------------------------------------------------------

pub fn button_from_winit(b: winit::event::MouseButton) -> Option<Button> {
    use winit::event::MouseButton as M;
    match b {
        M::Left => Some(Button::Left),
        M::Right => Some(Button::Right),
        M::Middle => Some(Button::Middle),
        _ => None,
    }
}

pub fn wheel_from_winit(d: winit::event::MouseScrollDelta) -> WheelDelta {
    use winit::event::MouseScrollDelta as D;
    match d {
        D::LineDelta(x, y) => WheelDelta::Lines(f64::from(x), f64::from(y)),
        D::PixelDelta(p) => WheelDelta::Pixels(p.x, p.y),
    }
}

pub fn mods_from_winit(m: winit::keyboard::ModifiersState) -> Mods {
    Mods {
        cmd: m.super_key(),
        ctrl: m.control_key(),
        shift: m.shift_key(),
    }
}

/// The key a shortcut should see. `logical` follows the keyboard layout; on
/// a non-Latin layout (Cyrillic, Greek, Hebrew, ...) it is not an ASCII
/// letter, so shortcuts fall back to the letter printed on that physical key
/// of a US keyboard. A Latin layout (Dvorak included) keeps its own letters,
/// as macOS does for ⌘ shortcuts.
pub fn key_from_winit(
    logical: &winit::keyboard::Key,
    physical: winit::keyboard::PhysicalKey,
) -> KeyInput {
    use winit::keyboard::{Key as K, PhysicalKey};
    match (logical_key(logical), physical) {
        (KeyInput::Char(c), PhysicalKey::Code(code)) if !c.is_ascii_alphabetic() => {
            physical_letter(code).map_or(KeyInput::Char(c), KeyInput::Char)
        }
        (KeyInput::Other, PhysicalKey::Code(code)) if matches!(logical, K::Dead(_)) => {
            physical_letter(code).map_or(KeyInput::Other, KeyInput::Char)
        }
        (key, _) => key,
    }
}

/// The US-layout letter on a physical key.
fn physical_letter(code: winit::keyboard::KeyCode) -> Option<char> {
    use winit::keyboard::KeyCode as C;
    Some(match code {
        C::KeyA => 'a',
        C::KeyB => 'b',
        C::KeyC => 'c',
        C::KeyD => 'd',
        C::KeyE => 'e',
        C::KeyF => 'f',
        C::KeyG => 'g',
        C::KeyH => 'h',
        C::KeyI => 'i',
        C::KeyJ => 'j',
        C::KeyK => 'k',
        C::KeyL => 'l',
        C::KeyM => 'm',
        C::KeyN => 'n',
        C::KeyO => 'o',
        C::KeyP => 'p',
        C::KeyQ => 'q',
        C::KeyR => 'r',
        C::KeyS => 's',
        C::KeyT => 't',
        C::KeyU => 'u',
        C::KeyV => 'v',
        C::KeyW => 'w',
        C::KeyX => 'x',
        C::KeyY => 'y',
        C::KeyZ => 'z',
        _ => return None,
    })
}

fn logical_key(k: &winit::keyboard::Key) -> KeyInput {
    use winit::keyboard::{Key as K, NamedKey as N};
    match k {
        K::Named(N::Backspace) => KeyInput::Named(Key::Backspace),
        K::Named(N::Enter) => KeyInput::Named(Key::Enter),
        K::Named(N::ArrowLeft) => KeyInput::Named(Key::Left),
        K::Named(N::ArrowRight) => KeyInput::Named(Key::Right),
        K::Named(N::ArrowUp) => KeyInput::Named(Key::Up),
        K::Named(N::ArrowDown) => KeyInput::Named(Key::Down),
        K::Named(N::Delete) => KeyInput::Named(Key::DeleteForward),
        K::Named(N::Tab) => KeyInput::Named(Key::Tab),
        K::Character(s) => {
            let mut chars = s.chars();
            match (chars.next(), chars.next()) {
                (Some(c), None) => KeyInput::Char(c),
                _ => KeyInput::Other,
            }
        }
        _ => KeyInput::Other,
    }
}

/// Text of an `Ime::Commit`, if the event is one.
pub fn ime_commit_text(ime: &winit::event::Ime) -> Option<&str> {
    match ime {
        winit::event::Ime::Commit(s) => Some(s),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mirror_protocol::geometry::unit_to_norm;

    /// 1000x500 rect at (100, 50) in a 1200x600 window.
    fn mapper() -> (InputMapper, Instant) {
        let mut m = InputMapper::new();
        m.set_rect(Rect {
            x: 100.0,
            y: 50.0,
            w: 1000.0,
            h: 500.0,
        });
        (m, Instant::now())
    }

    fn ms(t: Instant, n: u64) -> Instant {
        t + Duration::from_millis(n)
    }

    fn no_clip() -> Option<String> {
        panic!("clipboard must not be read")
    }

    fn gesture(m: &Message) -> &TouchGesture {
        match m {
            Message::TouchGesture(g) => g,
            other => panic!("not a gesture: {other:?}"),
        }
    }

    #[test]
    fn tap_center() {
        let (mut m, t) = mapper();
        assert!(m.button_pressed(Button::Left, (600.0, 300.0), t).is_empty());
        let out = m.button_released(Button::Left, (600.0, 300.0), ms(t, 100));
        let g = gesture(&out[0]);
        assert_eq!(g.kind, GestureKind::Tap);
        assert_eq!(
            g.points,
            vec![GesturePoint {
                x: 32768,
                y: 32768,
                dt_ms: 0
            }]
        );
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn tap_slop_boundary() {
        for (dx, kind) in [(7.9, GestureKind::Tap), (8.0, GestureKind::Path)] {
            let (mut m, t) = mapper();
            m.button_pressed(Button::Left, (600.0, 300.0), t);
            m.pointer_moved((600.0 + dx, 300.0), ms(t, 10));
            let out = m.button_released(Button::Left, (600.0 + dx, 300.0), ms(t, 20));
            assert_eq!(gesture(&out[0]).kind, kind, "dx={dx}");
        }
    }

    #[test]
    fn tap_time_boundary() {
        for (n, kind) in [(499, GestureKind::Tap), (500, GestureKind::LongPress)] {
            let (mut m, t) = mapper();
            m.button_pressed(Button::Left, (600.0, 300.0), t);
            let out = m.button_released(Button::Left, (600.0, 300.0), ms(t, n));
            assert_eq!(gesture(&out[0]).kind, kind, "n={n}");
        }
    }

    #[test]
    fn long_press_on_tick_then_no_tap() {
        let (mut m, t) = mapper();
        m.button_pressed(Button::Left, (600.0, 300.0), t);
        assert_eq!(m.next_tick_at(), Some(ms(t, 500)));
        assert!(m.tick(ms(t, 499)).is_empty());
        let out = m.tick(ms(t, 500));
        assert_eq!(gesture(&out[0]).kind, GestureKind::LongPress);
        assert!(m.tick(ms(t, 600)).is_empty(), "only once");
        assert_eq!(m.next_tick_at(), None);
        assert!(m
            .button_released(Button::Left, (600.0, 300.0), ms(t, 700))
            .is_empty());
    }

    #[test]
    fn long_press_then_move_sends_nothing() {
        let (mut m, t) = mapper();
        m.button_pressed(Button::Left, (600.0, 300.0), t);
        m.tick(ms(t, 500));
        m.pointer_moved((605.0, 300.0), ms(t, 550));
        assert_eq!(m.take_notice(), None, "within the slop");
        m.pointer_moved((800.0, 300.0), ms(t, 600));
        // The user is told while dragging, once per press.
        assert_eq!(m.take_notice(), Some(Notice::DragAfterLongPress));
        m.pointer_moved((900.0, 300.0), ms(t, 650));
        assert!(m
            .button_released(Button::Left, (900.0, 300.0), ms(t, 700))
            .is_empty());
        assert_eq!(m.take_notice(), None);
        // Moved only by the release: still told.
        m.button_pressed(Button::Left, (600.0, 300.0), t);
        m.tick(ms(t, 500));
        m.button_released(Button::Left, (800.0, 300.0), ms(t, 700));
        assert_eq!(m.take_notice(), Some(Notice::DragAfterLongPress));
        // A still long press says nothing.
        m.button_pressed(Button::Left, (600.0, 300.0), t);
        m.tick(ms(t, 500));
        m.button_released(Button::Left, (600.0, 300.0), ms(t, 700));
        assert_eq!(m.take_notice(), None);
    }

    #[test]
    fn exact_slop_move_cancels_long_press() {
        let (mut m, t) = mapper();
        m.button_pressed(Button::Left, (600.0, 300.0), t);
        m.pointer_moved((608.0, 300.0), ms(t, 10));
        assert!(m.tick(ms(t, 900)).is_empty());
        m.cancel();
        m.button_pressed(Button::Left, (600.0, 300.0), t);
        m.pointer_moved((607.9, 300.0), ms(t, 10));
        assert_eq!(m.tick(ms(t, 900)).len(), 1);
    }

    #[test]
    fn tick_after_drag_does_nothing() {
        let (mut m, t) = mapper();
        m.button_pressed(Button::Left, (600.0, 300.0), t);
        m.pointer_moved((700.0, 300.0), ms(t, 10));
        assert!(m.tick(ms(t, 900)).is_empty());
    }

    #[test]
    fn drag_path_with_dt() {
        let (mut m, t) = mapper();
        m.button_pressed(Button::Left, (100.0, 50.0), t);
        m.pointer_moved((600.0, 300.0), ms(t, 30));
        let out = m.button_released(Button::Left, (1100.0, 550.0), ms(t, 100));
        let g = gesture(&out[0]);
        assert_eq!(g.kind, GestureKind::Path);
        assert_eq!(
            g.points,
            vec![
                GesturePoint {
                    x: 0,
                    y: 0,
                    dt_ms: 0
                },
                GesturePoint {
                    x: 32768,
                    y: 32768,
                    dt_ms: 30
                },
                GesturePoint {
                    x: 65535,
                    y: 65535,
                    dt_ms: 70
                },
            ]
        );
    }

    #[test]
    fn drag_subsampled_to_64_monotonic() {
        let (mut m, t) = mapper();
        m.button_pressed(Button::Left, (200.0, 300.0), t);
        for i in 1..=500u64 {
            m.pointer_moved((200.0 + i as f64, 300.0), ms(t, i * 2));
        }
        let out = m.button_released(Button::Left, (701.0, 300.0), ms(t, 1002));
        let g = gesture(&out[0]);
        assert_eq!(g.points.len(), MAX_PATH_POINTS);
        assert_eq!(g.points[0].dt_ms, 0);
        assert!(g.points.windows(2).all(|w| w[1].x >= w[0].x));
        assert!(g.points[1..].iter().all(|p| p.dt_ms > 0));
        let total: u32 = g.points.iter().map(|p| u32::from(p.dt_ms)).sum();
        assert_eq!(total, 1002, "first and last timestamps kept");
        let last = g.points.last().unwrap();
        assert_eq!(last.x, unit_to_norm(601.0 / 1000.0));
    }

    #[test]
    fn exactly_64_points_unchanged() {
        let (mut m, t) = mapper();
        m.button_pressed(Button::Left, (200.0, 300.0), t);
        for i in 1..63u64 {
            m.pointer_moved((200.0 + 10.0 * i as f64, 300.0), ms(t, i));
        }
        let out = m.button_released(Button::Left, (900.0, 300.0), ms(t, 63));
        assert_eq!(gesture(&out[0]).points.len(), 64);
    }

    #[test]
    fn dt_saturates() {
        let (mut m, t) = mapper();
        m.button_pressed(Button::Left, (200.0, 300.0), t);
        m.pointer_moved((300.0, 300.0), ms(t, 100_000));
        let out = m.button_released(Button::Left, (300.0, 300.0), ms(t, 100_001));
        assert_eq!(gesture(&out[0]).points[1].dt_ms, u16::MAX);
    }

    #[test]
    fn rotation_mid_press_drops_the_gesture_but_resize_keeps_it() {
        let (mut m, t) = mapper();
        m.button_pressed(Button::Left, (200.0, 100.0), t);
        // Same aspect, smaller window: the drag continues.
        m.set_rect(Rect {
            x: 50.0,
            y: 25.0,
            w: 500.0,
            h: 250.0,
        });
        m.pointer_moved((300.0, 150.0), ms(t, 10));
        let out = m.button_released(Button::Left, (300.0, 150.0), ms(t, 20));
        assert_eq!(gesture(&out[0]).kind, GestureKind::Path);
        // Rotated video: the gesture is dropped, the release sends nothing.
        m.button_pressed(Button::Left, (300.0, 150.0), ms(t, 30));
        m.set_rect(Rect {
            x: 375.0,
            y: 0.0,
            w: 250.0,
            h: 500.0,
        });
        assert!(m
            .button_released(Button::Left, (500.0, 300.0), ms(t, 40))
            .is_empty());
        assert!(m.next_tick_at().is_none());
    }

    #[test]
    fn letterbox_press_ignored() {
        let (mut m, t) = mapper();
        for pos in [
            (50.0, 300.0),
            (600.0, 10.0),
            (1150.0, 300.0),
            (600.0, 580.0),
        ] {
            assert!(m.button_pressed(Button::Left, pos, t).is_empty());
            assert!(m
                .button_released(Button::Left, (600.0, 300.0), ms(t, 10))
                .is_empty());
            assert!(m.button_pressed(Button::Right, pos, t).is_empty());
            assert!(m.button_pressed(Button::Middle, pos, t).is_empty());
        }
    }

    #[test]
    fn drag_leaving_rect_is_clamped() {
        let (mut m, t) = mapper();
        m.button_pressed(Button::Left, (600.0, 300.0), t);
        m.pointer_moved((5000.0, -300.0), ms(t, 10));
        let out = m.button_released(Button::Left, (5000.0, -300.0), ms(t, 20));
        let p = gesture(&out[0]).points.last().copied().unwrap();
        assert_eq!((p.x, p.y), (65535, 0));
    }

    #[test]
    fn cursor_leaving_mid_drag_keeps_the_drag() {
        let (mut m, t) = mapper();
        m.button_pressed(Button::Left, (600.0, 300.0), t);
        m.pointer_moved((900.0, 300.0), ms(t, 10));
        m.cursor_left();
        m.pointer_moved((5000.0, 300.0), ms(t, 20));
        let out = m.button_released(Button::Left, (5000.0, 300.0), ms(t, 30));
        assert_eq!(out.len(), 1, "drag still sent");
        let p = gesture(&out[0]).points.last().copied().unwrap();
        assert_eq!(p.x, 65535, "clamped to the edge");
        // Nothing held: leaving forgets the position (no stale scrolls).
        m.pointer_moved((600.0, 300.0), ms(t, 40));
        assert!(!m.wheel(WheelDelta::Lines(0.0, 1.0)).is_empty());
        m.cursor_left();
        assert!(m.wheel(WheelDelta::Lines(0.0, 1.0)).is_empty());
    }

    #[test]
    fn right_and_middle_click() {
        let (mut m, t) = mapper();
        assert_eq!(
            m.button_pressed(Button::Right, (600.0, 300.0), t),
            vec![Message::GlobalAction(GlobalAction::Back)]
        );
        assert_eq!(
            m.button_pressed(Button::Middle, (600.0, 300.0), t),
            vec![Message::GlobalAction(GlobalAction::Home)]
        );
        assert!(m
            .button_released(Button::Right, (600.0, 300.0), t)
            .is_empty());
    }

    #[test]
    fn cancel_drops_gesture() {
        let (mut m, t) = mapper();
        m.button_pressed(Button::Left, (600.0, 300.0), t);
        m.cancel();
        assert!(m.tick(ms(t, 900)).is_empty());
        assert!(m
            .button_released(Button::Left, (600.0, 300.0), ms(t, 950))
            .is_empty());
    }

    #[test]
    fn scroll_pixels_sign_and_scale() {
        let (mut m, t) = mapper();
        m.pointer_moved((600.0, 300.0), t);
        // 50 px of 500 px height = 10% = 6554 (rounded).
        assert_eq!(
            m.wheel(WheelDelta::Pixels(0.0, 50.0)),
            vec![Message::Scroll(Scroll {
                x: 32768,
                y: 32768,
                dx: 0,
                dy: 6554
            })]
        );
        // 100 px of 1000 px width = 10%, negative.
        assert_eq!(
            m.wheel(WheelDelta::Pixels(-100.0, 0.0)),
            vec![Message::Scroll(Scroll {
                x: 32768,
                y: 32768,
                dx: -6554,
                dy: 0
            })]
        );
    }

    #[test]
    fn scroll_lines_one_twentieth() {
        let (mut m, t) = mapper();
        m.pointer_moved((600.0, 300.0), t);
        let Message::Scroll(s) = &m.wheel(WheelDelta::Lines(0.0, -1.0))[0] else {
            panic!()
        };
        assert_eq!(s.dy, -3277);
    }

    #[test]
    fn scroll_clamped_and_zero_dropped() {
        let (mut m, t) = mapper();
        m.pointer_moved((600.0, 300.0), t);
        let Message::Scroll(s) = &m.wheel(WheelDelta::Pixels(1e9, -1e9))[0] else {
            panic!()
        };
        assert_eq!((s.dx, s.dy), (i16::MAX, i16::MIN));
        assert!(m.wheel(WheelDelta::Pixels(0.0, 0.0)).is_empty());
        assert!(m.wheel(WheelDelta::Pixels(0.001, 0.0)).is_empty());
    }

    #[test]
    fn scroll_ignored_in_letterbox_or_unknown_cursor() {
        let (mut m, t) = mapper();
        assert!(m.wheel(WheelDelta::Lines(0.0, 1.0)).is_empty());
        m.pointer_moved((10.0, 10.0), t);
        assert!(m.wheel(WheelDelta::Lines(0.0, 1.0)).is_empty());
    }

    #[test]
    fn text_and_special_keys() {
        let (mut m, _) = mapper();
        let none = Mods::default();
        assert_eq!(
            m.key_pressed(KeyInput::Char('a'), none, Some("a"), no_clip),
            vec![Message::Text("a".into())]
        );
        assert_eq!(m.text("héllo"), vec![Message::Text("héllo".into())]);
        assert!(m.text("").is_empty());
        for (k, want) in [
            (Key::Backspace, Key::Backspace),
            (Key::Enter, Key::Enter),
            (Key::Left, Key::Left),
            (Key::DeleteForward, Key::DeleteForward),
            (Key::Tab, Key::Tab),
        ] {
            // The control character some platforms attach must not become text.
            assert_eq!(
                m.key_pressed(KeyInput::Named(k), none, Some("\u{8}"), no_clip),
                vec![Message::Key(want)]
            );
        }
    }

    #[test]
    fn cmd_shortcuts_emit_no_text() {
        let (mut m, _) = mapper();
        let cmd = Mods {
            cmd: true,
            ctrl: false,
            shift: false,
        };
        for (c, a) in [
            ('b', GlobalAction::Back),
            ('H', GlobalAction::Home),
            ('r', GlobalAction::Recents),
        ] {
            assert_eq!(
                m.key_pressed(KeyInput::Char(c), cmd, Some("x"), no_clip),
                vec![Message::GlobalAction(a)]
            );
        }
        assert!(m
            .key_pressed(KeyInput::Char('q'), cmd, Some("q"), no_clip)
            .is_empty());
        assert!(m
            .key_pressed(KeyInput::Named(Key::Enter), cmd, None, no_clip)
            .is_empty());
    }

    #[test]
    fn ctrl_combo_emits_no_text() {
        let (mut m, _) = mapper();
        let ctrl = Mods {
            cmd: false,
            ctrl: true,
            shift: false,
        };
        assert!(m
            .key_pressed(KeyInput::Char('c'), ctrl, Some("\u{3}"), no_clip)
            .is_empty());
    }

    #[test]
    fn cmd_n_is_notifications_and_cmd_shift_n_quick_settings() {
        let (mut m, _) = mapper();
        let cmd = Mods {
            cmd: true,
            ..Mods::default()
        };
        let cmd_shift = Mods { shift: true, ..cmd };
        for c in ['n', 'N'] {
            assert_eq!(
                m.key_pressed(KeyInput::Char(c), cmd, Some("n"), no_clip),
                vec![Message::GlobalAction(GlobalAction::Notifications)]
            );
            assert_eq!(
                m.key_pressed(KeyInput::Char(c), cmd_shift, Some("N"), no_clip),
                vec![Message::GlobalAction(GlobalAction::QuickSettings)]
            );
        }
        // Without Cmd it is plain typing.
        let plain = Mods::default();
        assert_eq!(
            m.key_pressed(KeyInput::Char('n'), plain, Some("n"), no_clip),
            vec![Message::Text("n".into())]
        );
        // Held key does not repeat the action.
        assert!(m
            .key_event(KeyInput::Char('n'), cmd, Some("n"), true, no_clip)
            .is_empty());
    }

    #[test]
    fn cmd_v_pastes_clipboard() {
        let (mut m, _) = mapper();
        let cmd = Mods {
            cmd: true,
            ctrl: false,
            shift: false,
        };
        assert_eq!(
            m.key_pressed(KeyInput::Char('v'), cmd, Some("v"), || Some("hi".into())),
            vec![Message::Text("hi".into())]
        );
        assert!(m
            .key_pressed(KeyInput::Char('v'), cmd, Some("v"), || None)
            .is_empty());
        assert!(m
            .key_pressed(KeyInput::Char('v'), cmd, None, || Some(String::new()))
            .is_empty());
    }

    #[test]
    fn cmd_shortcut_repeats_are_ignored_but_typing_repeats() {
        let (mut m, _) = mapper();
        let cmd = Mods {
            cmd: true,
            ctrl: false,
            shift: false,
        };
        let clip = || Some("hi".to_string());
        for c in ['v', 'b', 'h', 'r'] {
            assert!(!m
                .key_event(KeyInput::Char(c), cmd, None, false, clip)
                .is_empty());
            assert!(
                m.key_event(KeyInput::Char(c), cmd, None, true, clip)
                    .is_empty(),
                "held Cmd+{c} fires once"
            );
        }
        let none = Mods::default();
        assert_eq!(
            m.key_event(KeyInput::Char('a'), none, Some("a"), true, no_clip),
            vec![Message::Text("a".into())]
        );
        for k in [Key::Backspace, Key::Left, Key::Enter] {
            assert_eq!(
                m.key_event(KeyInput::Named(k), none, None, true, no_clip),
                vec![Message::Key(k)]
            );
        }
    }

    #[test]
    fn oversized_paste_is_refused_with_a_notice() {
        let (mut m, _) = mapper();
        let cmd = Mods {
            cmd: true,
            ctrl: false,
            shift: false,
        };
        let at_limit = "a".repeat(MAX_PASTE_BYTES);
        let out = m.key_pressed(KeyInput::Char('v'), cmd, None, || Some(at_limit));
        assert_eq!(out.len(), MAX_PASTE_BYTES / MAX_TEXT_BYTES);
        assert_eq!(m.take_notice(), None);
        let over = "a".repeat(MAX_PASTE_BYTES + 1);
        assert!(m
            .key_pressed(KeyInput::Char('v'), cmd, None, || Some(over))
            .is_empty());
        assert_eq!(m.take_notice(), Some(Notice::PasteTooLarge));
        assert_eq!(m.take_notice(), None, "taken once");
        assert!(is_paste(KeyInput::Char('V'), cmd));
        assert!(!is_paste(KeyInput::Char('v'), Mods::default()));
        assert!(!is_paste(KeyInput::Char('b'), cmd));
    }

    fn texts(msgs: &[Message]) -> Vec<&str> {
        msgs.iter()
            .map(|m| match m {
                Message::Text(s) => s.as_str(),
                _ => panic!(),
            })
            .collect()
    }

    #[test]
    fn paste_split_exact_boundary() {
        let s = "a".repeat(MAX_TEXT_BYTES);
        assert_eq!(texts(&paste_messages(&s)).len(), 1);
        let s = "a".repeat(MAX_TEXT_BYTES + 1);
        let out = paste_messages(&s);
        let t = texts(&out);
        assert_eq!((t[0].len(), t[1].len()), (MAX_TEXT_BYTES, 1));
    }

    #[test]
    fn paste_split_multibyte_boundary() {
        // 3-byte chars: 65536 is not a multiple of 3, so chunks end at 65535.
        let s = "€".repeat(30_000);
        let out = paste_messages(&s);
        let t = texts(&out);
        assert!(t.iter().all(|c| c.len() <= MAX_TEXT_BYTES));
        assert_eq!(t[0].len(), 65_535);
        assert_eq!(t.concat(), s);
        // Char boundary exactly at the limit stays full.
        let s = "é".repeat(MAX_TEXT_BYTES / 2 + 1);
        let out = paste_messages(&s);
        assert_eq!(texts(&out)[0].len(), MAX_TEXT_BYTES);
        assert_eq!(texts(&out).concat(), s);
        assert!(paste_messages("").is_empty());
    }

    #[test]
    fn winit_adapters() {
        use winit::event::{Ime, MouseButton, MouseScrollDelta};
        use winit::keyboard::{Key as K, KeyCode, ModifiersState, NamedKey, PhysicalKey, SmolStr};
        let phys = PhysicalKey::Code(KeyCode::KeyB);
        assert_eq!(button_from_winit(MouseButton::Back), None);
        assert_eq!(button_from_winit(MouseButton::Right), Some(Button::Right));
        assert_eq!(
            wheel_from_winit(MouseScrollDelta::LineDelta(1.0, -2.0)),
            WheelDelta::Lines(1.0, -2.0)
        );
        assert_eq!(
            key_from_winit(&K::Named(NamedKey::Delete), phys),
            KeyInput::Named(Key::DeleteForward)
        );
        assert_eq!(
            key_from_winit(&K::Character(SmolStr::new("B")), phys),
            KeyInput::Char('B')
        );
        assert_eq!(
            key_from_winit(&K::Character(SmolStr::new("ab")), phys),
            KeyInput::Other
        );
        assert_eq!(
            key_from_winit(&K::Named(NamedKey::Shift), phys),
            KeyInput::Other
        );
        let m = mods_from_winit(ModifiersState::SUPER | ModifiersState::SHIFT);
        assert_eq!(
            m,
            Mods {
                cmd: true,
                ctrl: false,
                shift: true
            }
        );
        assert_eq!(ime_commit_text(&Ime::Commit("x".into())), Some("x"));
        assert_eq!(ime_commit_text(&Ime::Enabled), None);
    }

    #[test]
    fn shortcuts_work_on_non_latin_layouts() {
        use winit::keyboard::{Key as K, KeyCode, PhysicalKey, SmolStr};
        let key = |logical: &str, code| {
            key_from_winit(
                &K::Character(SmolStr::new(logical)),
                PhysicalKey::Code(code),
            )
        };
        // Russian layout: the B key types "и", H types "р", V types "м".
        assert_eq!(key("и", KeyCode::KeyB), KeyInput::Char('b'));
        assert_eq!(key("р", KeyCode::KeyH), KeyInput::Char('h'));
        assert!(is_paste(
            key("м", KeyCode::KeyV),
            Mods {
                cmd: true,
                ..Mods::default()
            }
        ));
        // A Latin layout keeps its own letters (Dvorak: the key at QWERTY
        // "B" types "x"), like macOS does for ⌘ shortcuts.
        assert_eq!(key("x", KeyCode::KeyB), KeyInput::Char('x'));
        // Non-letters on a non-Latin layout stay as typed.
        assert_eq!(key("1", KeyCode::Digit1), KeyInput::Char('1'));
        assert_eq!(key("ж", KeyCode::Semicolon), KeyInput::Char('ж'));
        // And the mapper acts on it: ⌘ + the Cyrillic B key is Back.
        let (mut m, _) = mapper();
        let cmd = Mods {
            cmd: true,
            ..Mods::default()
        };
        let out = m.key_pressed(key("и", KeyCode::KeyB), cmd, Some("и"), no_clip);
        assert_eq!(out, vec![Message::GlobalAction(GlobalAction::Back)]);
    }

    #[test]
    fn right_click_during_a_left_drag_keeps_the_drag() {
        // Left press handed to the phone, right press + release, left still down.
        let mut held = drag_held_after(false, Button::Left, true, true);
        assert!(held);
        held = drag_held_after(held, Button::Right, true, true);
        held = drag_held_after(held, Button::Right, false, false);
        assert!(held, "the left drag continues");
        assert!(!drag_held_after(held, Button::Left, false, false));
        // A left press egui took is not a phone drag.
        assert!(!drag_held_after(false, Button::Left, true, false));
        // A right click alone never starts one.
        assert!(!drag_held_after(false, Button::Right, true, true));
    }

    #[test]
    fn path_has_no_duplicate_end_points() {
        let (mut m, t) = mapper();
        m.button_pressed(Button::Left, (200.0, 300.0), t);
        m.pointer_moved((400.0, 300.0), ms(t, 10));
        m.pointer_moved((600.0, 300.0), ms(t, 20));
        // Release exactly where the last move was, 30 ms later.
        let out = m.button_released(Button::Left, (600.0, 300.0), ms(t, 50));
        let g = gesture(&out[0]);
        let xy: Vec<_> = g.points.iter().map(|p| (p.x, p.y)).collect();
        assert_eq!(xy.len(), 3, "{xy:?}");
        assert!(xy.windows(2).all(|w| w[0] != w[1]), "{xy:?}");
        assert_eq!(g.points.last().unwrap().dt_ms, 40, "end time kept");

        // Held against the clamped edge: one end point, not many.
        let (mut m, t) = mapper();
        m.button_pressed(Button::Left, (600.0, 300.0), t);
        for i in 1..=5u64 {
            m.pointer_moved((5000.0 + i as f64, 300.0), ms(t, i));
        }
        let out = m.button_released(Button::Left, (5000.0, 300.0), ms(t, 9));
        assert_eq!(gesture(&out[0]).points.len(), 2);
    }
}
