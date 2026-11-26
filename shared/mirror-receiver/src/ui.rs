//! egui chrome: home (connect by IP), connecting / reconnecting /
//! disconnected screens, and the mirroring overlays (auto-hiding top bar,
//! stats, screen-off notice). Palette matches the app icon: dark navy
//! surfaces, teal accent, white/grey text.
//!
//! [`draw`] is immediate-mode: it reads the connection state and returns
//! [`UiAction`]s for the app to apply; it never touches the network.

use std::time::{Duration, Instant};

use egui::{
    vec2, Align, Align2, Color32, CornerRadius, FontFamily, FontId, Frame, Id, Key, LayerId,
    Layout, Margin, Order, RichText, Sense, Stroke, StrokeKind, TextStyle, Ui,
};
use zeroize::{Zeroize, Zeroizing};

use crate::state::{
    can_submit_pin, control_indicator, describe, format_date, lockout_left, seconds_until,
    AuthPrompt, ConnState, Phase, PinIssue, BAR_LINGER, PIN_LEN,
};
use crate::stats::StatsSnapshot;
use crate::store::PairedDevice;

// Palette (from the app icon).
pub const NAVY: Color32 = Color32::from_rgb(0x0F, 0x1B, 0x3D);
/// Letterbox around the video: darker than the home background.
pub const LETTERBOX: Color32 = Color32::from_rgb(0x07, 0x0D, 0x1F);
pub const SURFACE: Color32 = Color32::from_rgb(0x11, 0x18, 0x27);
const INPUT: Color32 = Color32::from_rgb(0x1A, 0x24, 0x3B);
const HOVER: Color32 = Color32::from_rgb(0x22, 0x30, 0x50);
const BORDER: Color32 = Color32::from_rgb(0x26, 0x33, 0x52);
pub const TEAL: Color32 = Color32::from_rgb(0x14, 0xB8, 0xA6);
const TEAL_HI: Color32 = Color32::from_rgb(0x2D, 0xD4, 0xBF);
const TEAL_DOWN: Color32 = Color32::from_rgb(0x0D, 0x94, 0x88);
const ON_TEAL: Color32 = Color32::from_rgb(0x04, 0x2F, 0x2E);
const TEXT: Color32 = Color32::from_rgb(0xF8, 0xFA, 0xFC);
const MUTED: Color32 = Color32::from_rgb(0x94, 0xA3, 0xB8);
/// Placeholder text in input fields: dimmer than MUTED so it reads as a
/// hint, still above 4.5:1 against the field background.
const HINT: Color32 = Color32::from_rgb(0x87, 0x95, 0xAD);
const DANGER: Color32 = Color32::from_rgb(0xF8, 0x71, 0x71);
const WARN: Color32 = Color32::from_rgb(0xFB, 0xBF, 0x24);

/// Height of the mirroring top bar, points.
const BAR_H: f32 = 48.0;
/// Widest the centred home column gets, points.
const COLUMN_MAX: f32 = 380.0;

/// Ids of the overlay areas. Hashed once: the same id every frame keeps
/// each area's state (size, animation) and costs no per-frame hashing.
struct Ids {
    topbar: Id,
    topbar_shown: Id,
    stats: Id,
    screen_off: Id,
    toast: Id,
    control_indicator: Id,
    card: Id,
}

fn ids() -> &'static Ids {
    static IDS: std::sync::LazyLock<Ids> = std::sync::LazyLock::new(|| Ids {
        topbar: Id::unique("topbar"),
        topbar_shown: Id::unique("topbar-shown"),
        stats: Id::unique("stats"),
        screen_off: Id::unique("screen-off"),
        toast: Id::unique("toast"),
        control_indicator: Id::unique("control-indicator"),
        card: Id::unique("centered-card"),
    });
    &IDS
}

/// What the user asked for this frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UiAction {
    /// Connect to the address in the field (raw text).
    Connect(String),
    /// Retry the last target.
    Retry,
    /// Leave the current session / screen and go home.
    Disconnect,
    /// Connect again to the last target with this 6-digit PIN (wiped on drop).
    SubmitPin(Zeroizing<String>),
    /// Forget a paired phone (its stored key).
    Forget(String),
    /// Forget a paired phone, then connect again (shows the PIN dialog).
    ForgetAndRepair(String),
}

/// UI-only state that survives between frames.
#[derive(Debug, Default)]
pub struct UiState {
    pub address: String,
    pub address_error: Option<String>,
    pub show_stats: bool,
    /// A screen reader is on: the top bar stays up, since its buttons
    /// (Disconnect, Stats) must be in the accessibility tree to be reached.
    pub screen_reader: bool,
    /// Height of the home column last frame (for vertical centring).
    home_height: f32,
    /// PIN being typed in the pairing dialog.
    pin: PinBuffer,
    /// The PIN field already got its automatic focus for this dialog.
    pin_focused: bool,
    /// Paired device whose "Forget?" confirmation is open on home.
    confirm_forget: Option<String>,
    /// Short message at the bottom of the window (e.g. "Paste interrupted"),
    /// since when it is on screen (set when first drawn) and for how long.
    toast: Option<(String, Option<Instant>, Duration)>,
    /// Hit areas of the top bar as drawn last frame (points); `None` when hidden.
    bar_zone: Option<BarZone>,
}

/// The top bar's outer rect and its clickable buttons.
#[derive(Debug, Clone)]
pub struct BarZone {
    pub bar: egui::Rect,
    pub buttons: Vec<egui::Rect>,
    /// The bar's own layer.
    pub layer: LayerId,
}

impl BarZone {
    /// True if a press at `pos` lands on the bar's chrome (background), not
    /// on a button: that press belongs to the phone (its status bar lies
    /// under the bar), so egui must not swallow it. `top_layer` is egui's
    /// topmost interactive layer at `pos`; anything but the bar itself
    /// (a dialog or popup drawn above it) keeps the press for egui.
    pub fn passes_to_phone(&self, pos: egui::Pos2, top_layer: Option<LayerId>) -> bool {
        self.bar.contains(pos)
            && !self.buttons.iter().any(|b| b.contains(pos))
            && top_layer == Some(self.layer)
    }
}

/// The PIN being typed. A text-edit buffer that only takes ASCII digits up
/// to [`PIN_LEN`] and never outgrows its allocation, so the one buffer that
/// holds the digits is the one wiped on drop (a growing `String` would leave
/// stale copies behind in freed memory). Clearing and deleting wipe the
/// bytes they free too.
///
/// egui still copies the text each frame (layout, its undo history, which
/// cannot be turned off; see `pin_dialog`) into plain strings it frees
/// without wiping. This buffer only keeps our own copy clean.
struct PinBuffer(Zeroizing<String>);

impl Default for PinBuffer {
    fn default() -> Self {
        PinBuffer(Zeroizing::new(String::with_capacity(PIN_LEN)))
    }
}

impl PinBuffer {
    fn len(&self) -> usize {
        self.0.len()
    }

    /// Empty the buffer, zeroing its whole allocation.
    fn clear(&mut self) {
        self.0.zeroize();
    }

    fn as_str(&self) -> &str {
        &self.0
    }

    /// Hand the digits over, leaving this buffer empty (same allocation).
    fn submit(&mut self) -> Zeroizing<String> {
        let mut out = Zeroizing::new(String::with_capacity(PIN_LEN));
        out.push_str(&self.0);
        self.clear();
        out
    }
}

impl std::fmt::Debug for PinBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PinBuffer(<redacted>)")
    }
}

impl egui::TextBuffer for PinBuffer {
    fn is_mutable(&self) -> bool {
        true
    }

    fn as_str(&self) -> &str {
        PinBuffer::as_str(self)
    }

    fn insert_text(&mut self, text: &str, char_index: egui::text::CharIndex) -> usize {
        // Digits only (ASCII, so chars are bytes), up to the PIN length.
        let room = PIN_LEN.saturating_sub(self.0.len());
        let digits: String = text
            .chars()
            .filter(char::is_ascii_digit)
            .take(room)
            .collect();
        let at = char_index.0.min(self.0.len());
        self.0.insert_str(at, &digits);
        digits.len()
    }

    fn delete_char_range(&mut self, range: std::ops::Range<egui::text::CharIndex>) {
        let end = range.end.0.min(self.0.len());
        let start = range.start.0.min(end);
        // `drain` would shift the tail left and leave its old bytes past
        // the end: rebuild from a wiped copy instead.
        let mut kept = Zeroizing::new([0u8; PIN_LEN]);
        let mut n = 0;
        for (i, b) in self.0.bytes().enumerate() {
            if !(start..end).contains(&i) && n < PIN_LEN {
                kept[n] = b;
                n += 1;
            }
        }
        self.clear();
        // Only ASCII digits are ever inserted, so this is valid UTF-8.
        self.0
            .push_str(std::str::from_utf8(&kept[..n]).unwrap_or_default());
    }

    fn type_id(&self) -> std::any::TypeId {
        std::any::TypeId::of::<Self>()
    }
}

/// How long the control indicator stays after control turns on / off.
const CONTROL_HINT: Duration = Duration::from_secs(4);
/// How long a toast stays.
const TOAST: Duration = Duration::from_secs(3);

impl UiState {
    /// See [`BarZone::passes_to_phone`]; false while the bar is hidden.
    pub fn bar_passes_to_phone(&self, pos: egui::Pos2, top_layer: Option<LayerId>) -> bool {
        self.bar_zone
            .as_ref()
            .is_some_and(|z| z.passes_to_phone(pos, top_layer))
    }

    pub fn with_address(address: String) -> Self {
        UiState {
            address,
            ..Default::default()
        }
    }

    /// Show `text` briefly at the bottom of the window.
    pub fn show_toast(&mut self, text: &str) {
        self.show_toast_for(text, TOAST);
    }

    /// Like [`Self::show_toast`], for a message that needs longer to read.
    /// The time counts from when it is first drawn, so it cannot run out
    /// while the window is hidden.
    pub fn show_toast_for(&mut self, text: &str, how_long: Duration) {
        self.toast = Some((text.to_string(), None, how_long));
    }
}

/// Read-only inputs for one frame.
pub struct View<'a> {
    pub conn: &'a ConnState,
    /// A decoded picture is on screen.
    pub has_video: bool,
    /// Keys go to the phone (control is on and the session allows it): the
    /// app's own gate, so letters like "s" are not UI shortcuts.
    pub forwarding: bool,
    pub stats: Option<StatsSnapshot>,
    /// Paired phones (only filled where the UI lists or names them).
    pub paired: &'a [PairedDevice],
    pub now: Instant,
}

/// Install fonts sizes, spacing and the navy/teal visuals.
pub fn apply_theme(ctx: &egui::Context) {
    ctx.all_styles_mut(|style| {
        use egui::FontFamily::{Monospace, Proportional};
        style.text_styles = [
            (TextStyle::Heading, FontId::new(26.0, Proportional)),
            (TextStyle::Body, FontId::new(15.0, Proportional)),
            (TextStyle::Button, FontId::new(15.0, Proportional)),
            (TextStyle::Small, FontId::new(12.5, Proportional)),
            (TextStyle::Monospace, FontId::new(13.5, Monospace)),
        ]
        .into();
        style.spacing.item_spacing = vec2(10.0, 10.0);
        style.spacing.button_padding = vec2(14.0, 8.0);
        style.spacing.interact_size.y = 34.0;

        let v = &mut style.visuals;
        *v = egui::Visuals::dark();
        v.panel_fill = NAVY;
        v.window_fill = SURFACE;
        v.extreme_bg_color = INPUT;
        v.text_edit_bg_color = Some(INPUT);
        v.faint_bg_color = SURFACE;
        v.hyperlink_color = TEAL_HI;
        v.error_fg_color = DANGER;
        v.warn_fg_color = WARN;
        v.selection.bg_fill = TEAL.gamma_multiply(0.45);
        v.selection.stroke = Stroke::new(1.0, TEAL_HI);
        v.text_cursor.stroke = Stroke::new(2.0, TEAL_HI);
        let radius = CornerRadius::same(10);
        let w = &mut v.widgets;
        w.noninteractive.fg_stroke = Stroke::new(1.0, TEXT);
        w.noninteractive.bg_stroke = Stroke::new(1.0, BORDER);
        for (wv, fill, stroke) in [
            (&mut w.inactive, INPUT, BORDER),
            (&mut w.hovered, HOVER, TEAL.gamma_multiply(0.7)),
            (&mut w.active, HOVER, TEAL_HI),
            (&mut w.open, HOVER, TEAL),
        ] {
            wv.bg_fill = fill;
            wv.weak_bg_fill = fill;
            wv.bg_stroke = Stroke::new(1.0, stroke);
            wv.fg_stroke = Stroke::new(1.5, TEXT);
            wv.corner_radius = radius;
            wv.expansion = 0.0;
        }
    });
}

/// Draw one frame of UI. `ui` is egui's root ui (whole window).
pub fn draw(ui: &mut Ui, state: &mut UiState, view: &View<'_>) -> Vec<UiAction> {
    let mut actions = Vec::new();
    let screen = ui.max_rect();
    let prompt = view.conn.auth_prompt();
    if prompt.is_none() {
        state.pin.clear();
        state.pin_focused = false;
    }
    if !matches!(view.conn.phase, Phase::Mirroring { .. }) {
        state.bar_zone = None; // no bar outside mirroring, whatever it last was
    }
    if !matches!(view.conn.phase, Phase::Home) {
        state.confirm_forget = None;
    }
    match &view.conn.phase {
        Phase::Home => home(ui, state, view, &mut actions),
        Phase::Connecting => {
            let target = target_text(view.conn);
            centered_card(ui, Some(NAVY), |ui, w| {
                spinner(ui);
                ui.label(RichText::new("Connecting…").size(20.0).strong().color(TEXT));
                ui.label(RichText::new(format!("to {target}")).color(MUTED));
                ui.add_space(6.0);
                if secondary_button(ui, "Cancel", w).clicked() {
                    actions.push(UiAction::Disconnect);
                }
            });
        }
        Phase::Mirroring { .. } => mirroring(ui, state, view, &mut actions),
        Phase::Reconnecting { attempt, retry_at } => {
            let left = seconds_until(*retry_at, view.now);
            if left > 0 {
                ui.ctx().request_repaint_after(Duration::from_millis(250));
            }
            let bg = (!view.has_video).then_some(NAVY);
            centered_card(ui, bg, |ui, w| {
                spinner(ui);
                ui.label(
                    RichText::new("Reconnecting…")
                        .size(20.0)
                        .strong()
                        .color(TEXT),
                );
                if let Some(lost) = &view.conn.lost {
                    ui.label(RichText::new(describe(lost).1).color(MUTED));
                }
                let when = if left > 0 {
                    format!("Attempt {attempt} · next try in {left} s")
                } else {
                    format!("Attempt {attempt} · trying now")
                };
                ui.label(RichText::new(when).small().color(MUTED));
                ui.add_space(6.0);
                if secondary_button(ui, "Stop", w).clicked() {
                    actions.push(UiAction::Disconnect);
                }
            });
        }
        Phase::Disconnected { .. } if prompt.is_some() => {
            auth_dialog(ui, state, view, prompt.as_ref(), &mut actions);
        }
        Phase::Disconnected { reason } => {
            let (head, detail) = describe(reason);
            ended(ui, view.conn, head, &detail, &mut actions);
        }
        Phase::StartFailed { message } => {
            let detail = format!("The connection could not be set up ({message}). Try again.");
            ended(ui, view.conn, "Couldn't start", &detail, &mut actions);
        }
        Phase::GaveUp { attempts, last } => {
            let detail = format!(
                "Tried {attempts} time{}. {}",
                if *attempts == 1 { "" } else { "s" },
                describe(last).1
            );
            ended(ui, view.conn, "Couldn't reconnect", &detail, &mut actions);
        }
    }
    // On every screen: a notice (e.g. "pairing not saved") can arrive while
    // connecting or waiting for video.
    toast(ui.ctx(), state, view.now, screen);
    actions
}

fn target_text(conn: &ConnState) -> String {
    conn.target
        .as_ref()
        .map_or_else(|| "phone".to_string(), ToString::to_string)
}

// ---------------------------------------------------------------------------
// Home
// ---------------------------------------------------------------------------

fn home(ui: &mut Ui, state: &mut UiState, view: &View<'_>, actions: &mut Vec<UiAction>) {
    let full = ui.max_rect();
    ui.painter().rect_filled(full, 0, NAVY);
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            let avail = ui.available_size();
            let col = (avail.x - 32.0).clamp(180.0, COLUMN_MAX);
            let top = ((avail.y - state.home_height) / 2.0).max(20.0);
            let start = ui.cursor().top();
            ui.add_space(top);
            ui.vertical_centered(|ui| {
                logo(ui, 64.0);
                ui.add_space(4.0);
                ui.label(
                    RichText::new("Android Mirror")
                        .heading()
                        .strong()
                        .color(TEXT),
                );
                // Wrap inside the column, not at the window's edges.
                ui.scope(|ui| {
                    ui.set_max_width(col);
                    ui.label(RichText::new("See your phone's screen on this Mac.").color(MUTED));
                });
                ui.add_space(14.0);
                card(ui, col, |ui, w| connect_form(ui, state, w, actions));
                ui.add_space(4.0);
                if !view.paired.is_empty() {
                    card(ui, col, |ui, w| {
                        paired_list(ui, state, view.paired, w, actions)
                    });
                    ui.add_space(4.0);
                }
                card(ui, col, nearby_placeholder);
            });
            ui.add_space(20.0);
            let h = ui.cursor().top() - start - top;
            if (h - state.home_height).abs() > 1.0 {
                state.home_height = h;
                ui.ctx().request_discard("centre home column");
            }
        });
}

fn connect_form(ui: &mut Ui, state: &mut UiState, w: f32, actions: &mut Vec<UiAction>) {
    let label = caption(ui, "CONNECT BY IP");
    let edit = egui::TextEdit::singleline(&mut state.address)
        .hint_text(RichText::new("e.g. 192.168.1.42").color(HINT))
        .desired_width(w)
        .margin(Margin::symmetric(12, 10))
        .text_color(TEXT)
        .font(TextStyle::Body);
    let resp = ui.add(edit).labelled_by(label.id);
    if resp.changed() {
        state.address_error = None;
    }
    let submitted = resp.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));
    if let Some(err) = &state.address_error {
        ui.label(RichText::new(err).small().color(DANGER));
    }
    if primary_button(ui, "Connect", w).clicked() || submitted {
        actions.push(UiAction::Connect(state.address.clone()));
    }
    ui.label(
        RichText::new("Start mirroring on the phone and enter the address it shows. Port 47800 is used unless you add one (host:port).")
            .small()
            .color(MUTED),
    );
}

fn nearby_placeholder(ui: &mut Ui, w: f32) {
    if w >= 230.0 {
        ui.horizontal(|ui| {
            caption(ui, "NEARBY DEVICES");
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                pill(ui, "Coming soon");
            });
        });
    } else {
        caption(ui, "NEARBY DEVICES");
        pill(ui, "Coming soon");
    }
    ui.horizontal(|ui| {
        let (rect, _) = ui.allocate_exact_size(vec2(36.0, 36.0), Sense::hover());
        let c = rect.center();
        let p = ui.painter();
        for (r, a) in [(16.0, 0.25), (10.5, 0.45), (5.0, 0.9)] {
            p.circle_stroke(c, r, Stroke::new(1.5, TEAL.gamma_multiply(a)));
        }
        p.circle_filled(c, 2.5, TEAL_HI);
        ui.add(
            egui::Label::new(
                RichText::new("Phones on this Wi-Fi will show up here automatically.")
                    .small()
                    .color(MUTED),
            )
            .wrap(),
        );
    });
}

// ---------------------------------------------------------------------------
// Paired devices
// ---------------------------------------------------------------------------

fn paired_list(
    ui: &mut Ui,
    state: &mut UiState,
    paired: &[PairedDevice],
    w: f32,
    actions: &mut Vec<UiAction>,
) {
    caption(ui, "PAIRED DEVICES");
    for d in paired {
        let name = shorten(&d.device_name, 28);
        let name = if name.is_empty() {
            "Unnamed phone"
        } else {
            &name
        };
        if state.confirm_forget.as_deref() == Some(d.device_id.as_str()) {
            ui.add(
                egui::Label::new(
                    RichText::new(format!("Forget {name}? This Mac will need the PIN again."))
                        .color(TEXT),
                )
                .wrap(),
            );
            ui.horizontal(|ui| {
                let half = (w - ui.spacing().item_spacing.x) / 2.0;
                let forget = paint_button(ui, "Forget", half, 34.0, false, true, false);
                ui.ctx().accesskit_node_builder(forget.id, |n| {
                    n.set_label(format!("Forget {name}"));
                });
                if forget.clicked() {
                    actions.push(UiAction::Forget(d.device_id.clone()));
                    state.confirm_forget = None;
                }
                if paint_button(ui, "Keep", half, 34.0, false, false, false).clicked() {
                    state.confirm_forget = None;
                }
            });
            continue;
        }
        ui.horizontal(|ui| {
            let button_w = 76.0;
            ui.allocate_ui(vec2(w - button_w - 10.0, 40.0), |ui| {
                ui.vertical(|ui| {
                    ui.set_min_width(w - button_w - 10.0);
                    ui.spacing_mut().item_spacing.y = 2.0;
                    ui.add(egui::Label::new(RichText::new(name).strong().color(TEXT)).truncate());
                    ui.label(
                        RichText::new(format!("Paired {}", format_date(d.paired_at_ms)))
                            .small()
                            .color(MUTED),
                    );
                });
            });
            let forget = paint_button(ui, "Forget", button_w, 34.0, false, false, false)
                .on_hover_text("Forget this phone");
            // Every row has a "Forget": the spoken name says which phone.
            ui.ctx().accesskit_node_builder(forget.id, |n| {
                n.set_label(format!("Forget {name}"));
            });
            if forget.clicked() {
                state.confirm_forget = Some(d.device_id.clone());
            }
        });
    }
}

/// `s` cut to at most `max` characters, with an ellipsis.
fn shorten(s: &str, max: usize) -> String {
    crate::state::display_text(s, max)
}

// ---------------------------------------------------------------------------
// PIN pairing / identity warning
// ---------------------------------------------------------------------------

fn auth_dialog(
    ui: &mut Ui,
    state: &mut UiState,
    view: &View<'_>,
    prompt: Option<&AuthPrompt>,
    actions: &mut Vec<UiAction>,
) {
    match prompt {
        Some(AuthPrompt::Pin { issue, device_name }) => {
            pin_dialog(ui, state, view.now, issue, device_name.as_deref(), actions);
        }
        Some(AuthPrompt::Identity { device_id }) => {
            let name = view
                .paired
                .iter()
                .find(|d| &d.device_id == device_id)
                .map_or_else(|| "your phone".to_string(), |d| shorten(&d.device_name, 22));
            identity_dialog(ui, device_id, &name, actions);
        }
        None => {}
    }
}

fn pin_dialog(
    ui: &mut Ui,
    state: &mut UiState,
    now: Instant,
    issue: &PinIssue,
    device_name: Option<&str>,
    actions: &mut Vec<UiAction>,
) {
    let name = device_name.map_or_else(|| "your phone".to_string(), |n| shorten(n, 24));
    let left = lockout_left(issue, now);
    if left.is_some() {
        ui.ctx().request_repaint_after(Duration::from_millis(250));
    }
    centered_card(ui, Some(NAVY), |ui, w| {
        ui.label(
            RichText::new(format!("Pair with {name}"))
                .size(20.0)
                .strong()
                .color(TEXT),
        );
        match issue {
            PinIssue::Needed => {}
            PinIssue::Wrong => message(
                ui,
                "Wrong PIN \u{2014} check the phone and try again",
                DANGER,
            ),
            PinIssue::LockedOut { .. } => message(
                ui,
                &format!("Too many wrong PINs. Try again in {} s.", left.unwrap_or(0)),
                DANGER,
            ),
            PinIssue::Removed => message(
                ui,
                "The phone didn't accept this Mac's pairing. Enter the PIN shown on the phone to pair again.",
                WARN,
            ),
        }
        let label = ui.add(
            egui::Label::new(
                RichText::new("Enter the 6-digit PIN shown on the phone").color(MUTED),
            )
            .wrap(),
        );
        let edit = egui::TextEdit::singleline(&mut state.pin)
            .id_salt("pin-field")
            .hint_text(RichText::new("000000").color(HINT))
            .desired_width(w)
            .align(Align2::CENTER_CENTER)
            .margin(Margin::symmetric(12, 10))
            .text_color(TEXT)
            .font(FontId::new(28.0, FontFamily::Monospace));
        let resp = ui.add_enabled(left.is_none(), edit).labelled_by(label.id);
        // egui keeps undo snapshots (plain copies) of every text field and
        // has no switch to turn that off: drop them every frame so the
        // digits are not kept around for the life of the field.
        if let Some(mut s) = egui::text_edit::TextEditState::load(ui.ctx(), resp.id) {
            s.clear_undoer();
            s.store(ui.ctx(), resp.id);
        }
        if !state.pin_focused && left.is_none() {
            resp.request_focus();
            state.pin_focused = true;
        }
        let ready = can_submit_pin(state.pin.as_str(), issue, now);
        let enter = resp.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));
        ui.add_space(2.0);
        let pair = ui
            .add_enabled_ui(ready, |ui| primary_button(ui, "Pair", w))
            .inner;
        if ready && (pair.clicked() || enter) {
            actions.push(UiAction::SubmitPin(state.pin.submit()));
            state.pin_focused = false;
        } else if enter {
            resp.request_focus(); // Enter on an incomplete PIN keeps typing
        }
        if secondary_button(ui, "Cancel", w).clicked() {
            actions.push(UiAction::Disconnect);
        }
        ui.label(
            RichText::new(format!("{}/{PIN_LEN} digits", state.pin.len()))
                .small()
                .color(MUTED),
        );
    });
}

fn identity_dialog(ui: &mut Ui, device_id: &str, name: &str, actions: &mut Vec<UiAction>) {
    centered_card(ui, Some(NAVY), |ui, w| {
        alert_icon(ui);
        ui.label(
            RichText::new("This isn't the phone you paired with")
                .size(20.0)
                .strong()
                .color(WARN),
        );
        ui.add(
            egui::Label::new(
                RichText::new(format!(
                    "The device at this address isn't the phone you paired with ({name}). \
                     It may be a different phone, or someone on your network. \
                     If you reset or reinstalled the app on your phone, you can pair again."
                ))
                .color(TEXT),
            )
            .wrap(),
        );
        ui.add_space(4.0);
        let forget = paint_button(
            ui,
            &format!("Forget {} and pair again", shorten(name, 14)),
            w,
            40.0,
            false,
            true,
            false,
        );
        if forget.clicked() {
            actions.push(UiAction::ForgetAndRepair(device_id.to_string()));
        }
        if secondary_button(ui, "Cancel", w).clicked() {
            actions.push(UiAction::Disconnect);
        }
    });
}

/// A wrapped, coloured status line inside a dialog.
fn message(ui: &mut Ui, text: &str, color: Color32) {
    ui.add(egui::Label::new(RichText::new(text).strong().color(color)).wrap());
}

// ---------------------------------------------------------------------------
// Session ended
// ---------------------------------------------------------------------------

fn ended(ui: &mut Ui, conn: &ConnState, head: &str, detail: &str, actions: &mut Vec<UiAction>) {
    let target = conn.target.as_ref().map(ToString::to_string);
    centered_card(ui, Some(NAVY), |ui, w| {
        alert_icon(ui);
        ui.label(RichText::new(head).size(20.0).strong().color(TEXT));
        ui.add(egui::Label::new(RichText::new(detail).color(MUTED)).wrap());
        if let Some(t) = &target {
            ui.label(RichText::new(t).small().monospace().color(MUTED));
        }
        ui.add_space(6.0);
        if target.is_some() && primary_button(ui, "Try again", w).clicked() {
            actions.push(UiAction::Retry);
        }
        if secondary_button(ui, "Back", w).clicked() {
            actions.push(UiAction::Disconnect);
        }
    });
}

// ---------------------------------------------------------------------------
// Mirroring
// ---------------------------------------------------------------------------

fn mirroring(ui: &mut Ui, state: &mut UiState, view: &View<'_>, actions: &mut Vec<UiAction>) {
    let ctx = ui.ctx().clone();
    let screen = ui.max_rect();
    let device = view.conn.device.as_deref().unwrap_or("Phone");

    let focused = ctx.memory(|m| m.focused().is_some());
    // While keys go to the phone, "s" is typed text for it, not a shortcut.
    if !focused && !view.forwarding && ctx.input(|i| i.key_pressed(Key::S) && i.modifiers.is_none())
    {
        state.show_stats = !state.show_stats;
    }

    if !view.has_video {
        state.bar_zone = None;
        centered_card(ui, Some(NAVY), |ui, w| {
            spinner(ui);
            ui.label(
                RichText::new("Waiting for video…")
                    .size(20.0)
                    .strong()
                    .color(TEXT),
            );
            ui.label(RichText::new(format!("Connected to {device}")).color(MUTED));
            ui.add_space(6.0);
            if secondary_button(ui, "Disconnect", w).clicked() {
                actions.push(UiAction::Disconnect);
            }
        });
        return;
    }

    // Top bar: visible while the pointer is near the top or recently moved.
    let (hover, since_move) =
        ctx.input(|i| (i.pointer.hover_pos(), i.pointer.time_since_last_movement()));
    let near_top = hover.is_some_and(|p| p.y <= BAR_H + 16.0);
    let linger = BAR_LINGER.as_secs_f32();
    let recent = hover.is_some() && since_move < linger;
    if recent && !near_top {
        ctx.request_repaint_after(Duration::from_secs_f32((linger - since_move).max(0.05)));
    }
    let shown = ctx.animate_bool(
        ids().topbar_shown,
        state.screen_reader || near_top || recent,
    );
    if shown > 0.0 {
        // Hover-only: the bar's background must not capture presses/drags.
        let zone = egui::Area::new(ids().topbar)
            .order(Order::Foreground)
            .sense(Sense::hover())
            .fixed_pos(screen.min)
            .show(&ctx, |ui| {
                ui.multiply_opacity(shown);
                top_bar(ui, state, device, screen.width(), actions)
            })
            .inner;
        state.bar_zone = Some(zone);
    } else {
        state.bar_zone = None;
    }

    control_overlay(&ctx, view, screen, shown > 0.0);

    if state.show_stats {
        if let Some(s) = view.stats {
            ctx.request_repaint_after(Duration::from_millis(500));
            let y = 12.0 + if shown > 0.5 { BAR_H } else { 0.0 };
            egui::Area::new(ids().stats)
                .order(Order::Foreground)
                .interactable(false)
                .fixed_pos(screen.min + vec2(12.0, y))
                .show(&ctx, |ui| stats_overlay(ui, &s));
        }
    }

    if view.conn.screen_off {
        egui::Area::new(ids().screen_off)
            .order(Order::Middle)
            .interactable(false)
            .anchor(Align2::CENTER_CENTER, vec2(0.0, 0.0))
            .show(&ctx, |ui| {
                Frame::new()
                    .fill(SURFACE.gamma_multiply(0.92))
                    .stroke(Stroke::new(1.0, BORDER))
                    .corner_radius(CornerRadius::same(20))
                    .inner_margin(Margin::symmetric(18, 10))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            moon(ui);
                            ui.label(RichText::new("Phone screen is off").color(TEXT));
                        });
                    });
            });
    }
}

/// The current toast, above the control indicator, for its duration.
fn toast(ctx: &egui::Context, state: &mut UiState, now: Instant, screen: egui::Rect) {
    let Some((text, since, how_long)) = &mut state.toast else {
        return;
    };
    let age = now.saturating_duration_since(*since.get_or_insert(now));
    if age >= *how_long {
        state.toast = None;
        return;
    }
    ctx.request_repaint_after(*how_long - age);
    egui::Area::new(ids().toast)
        .order(Order::Foreground)
        .interactable(false)
        .anchor(Align2::CENTER_BOTTOM, vec2(0.0, -64.0))
        .show(ctx, |ui| {
            ui.set_max_width((screen.width() - 32.0).max(80.0));
            Frame::new()
                .fill(Color32::from_rgba_unmultiplied(0x0B, 0x14, 0x2E, 235))
                .stroke(Stroke::new(1.0, BORDER))
                .corner_radius(CornerRadius::same(16))
                .inner_margin(Margin::symmetric(14, 8))
                .show(ui, |ui| {
                    let label =
                        ui.add(egui::Label::new(RichText::new(text.as_str()).color(TEXT)).wrap());
                    // A live region: VoiceOver reads the toast when it appears.
                    ctx.accesskit_node_builder(label.id, |n| {
                        n.set_live(egui::accesskit::Live::Polite);
                    });
                });
        });
}

/// "Control on" / "View only" pill at the bottom of the video: shown with
/// the top bar, and for [`CONTROL_HINT`] after control turns on or off.
fn control_overlay(ctx: &egui::Context, view: &View<'_>, screen: egui::Rect, bar_shown: bool) {
    let Some((on, text)) = control_indicator(view.conn.auth, view.conn.control_available) else {
        return;
    };
    let since = view
        .conn
        .control_changed
        .map_or(CONTROL_HINT, |t| view.now.saturating_duration_since(t));
    let recent = since < CONTROL_HINT;
    if recent {
        ctx.request_repaint_after(CONTROL_HINT - since);
    }
    if !(bar_shown || recent) {
        return;
    }
    egui::Area::new(ids().control_indicator)
        .order(Order::Foreground)
        .interactable(false)
        .anchor(Align2::CENTER_BOTTOM, vec2(0.0, -14.0))
        .show(ctx, |ui| {
            ui.set_max_width((screen.width() - 32.0).max(80.0));
            Frame::new()
                .fill(Color32::from_rgba_unmultiplied(0x0B, 0x14, 0x2E, 235))
                .stroke(Stroke::new(1.0, BORDER))
                .corner_radius(CornerRadius::same(16))
                .inner_margin(Margin::symmetric(14, 8))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        let (dot, _) = ui.allocate_exact_size(vec2(10.0, 10.0), Sense::hover());
                        let color = if on { TEAL_HI } else { WARN };
                        ui.painter().circle_filled(dot.center(), 4.0, color);
                        ui.add(egui::Label::new(RichText::new(text).color(TEXT)).wrap());
                    });
                });
        });
}

fn top_bar(
    ui: &mut Ui,
    state: &mut UiState,
    device: &str,
    width: f32,
    actions: &mut Vec<UiAction>,
) -> BarZone {
    let mut buttons = Vec::new();
    let frame = Frame::new()
        .fill(Color32::from_rgba_unmultiplied(0x0B, 0x14, 0x2E, 235))
        .stroke(Stroke::new(1.0, BORDER))
        .inner_margin(Margin::symmetric(12, 8))
        .show(ui, |ui| {
            ui.set_width(width - 24.0);
            ui.set_height(BAR_H - 16.0);
            let compact = width < 330.0;
            let buttons_w = if compact {
                2.0 * 40.0 + 10.0
            } else {
                70.0 + 110.0 + 10.0
            };
            ui.horizontal_centered(|ui| {
                let (dot, _) = ui.allocate_exact_size(vec2(10.0, 10.0), Sense::hover());
                ui.painter().circle_filled(dot.center(), 4.0, TEAL_HI);
                let label_w = (ui.available_width() - buttons_w - 10.0).max(20.0);
                ui.allocate_ui(vec2(label_w, 24.0), |ui| {
                    ui.add(egui::Label::new(RichText::new(device).strong().color(TEXT)).truncate());
                });
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    // Compact: icon-only buttons (painted; no glyph-font
                    // dependency), still named for screen readers.
                    let d = bar_button(
                        ui,
                        "Disconnect",
                        !compact,
                        if compact { 40.0 } else { 110.0 },
                        true,
                        false,
                    )
                    .on_hover_text("End mirroring");
                    if compact {
                        paint_close_icon(ui, d.rect);
                    }
                    buttons.push(d.rect);
                    if d.clicked() {
                        actions.push(UiAction::Disconnect);
                    }
                    let s = bar_button(
                        ui,
                        "Stats",
                        !compact,
                        if compact { 40.0 } else { 70.0 },
                        false,
                        state.show_stats,
                    )
                    .on_hover_text("Show stream statistics (S)");
                    // A toggle: screen readers say whether it is on.
                    ui.ctx().accesskit_node_builder(s.id, |n| {
                        n.set_toggled(state.show_stats.into());
                    });
                    if compact {
                        paint_stats_icon(ui, s.rect);
                    }
                    buttons.push(s.rect);
                    if s.clicked() {
                        state.show_stats = !state.show_stats;
                    }
                });
            });
        });
    BarZone {
        bar: frame.response.rect,
        buttons,
        layer: ui.layer_id(),
    }
}

fn stats_overlay(ui: &mut Ui, s: &StatsSnapshot) {
    Frame::new()
        .fill(Color32::from_rgba_unmultiplied(0x0B, 0x14, 0x2E, 215))
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(CornerRadius::same(10))
        .inner_margin(Margin::symmetric(12, 10))
        .show(ui, |ui| {
            let row = |ui: &mut Ui, k: &str, v: String| {
                ui.label(RichText::new(k).small().color(MUTED));
                ui.label(RichText::new(v).monospace().color(TEXT));
                ui.end_row();
            };
            ui.spacing_mut().interact_size.y = 18.0;
            egui::Grid::new("stats-grid")
                .num_columns(2)
                .spacing(vec2(14.0, 4.0))
                .show(ui, |ui| {
                    row(ui, "Frame rate", format!("{:.0} fps", s.fps));
                    row(
                        ui,
                        "Resolution",
                        s.resolution
                            .map_or("–".into(), |(w, h)| format!("{w} × {h}")),
                    );
                    row(ui, "Bitrate", format!("{:.1} Mbps", s.mbps));
                    row(
                        ui,
                        "Round trip",
                        s.rtt.map_or("–".into(), crate::stats::format_rtt),
                    );
                    if s.dropped > 0 || s.decode_errors > 0 {
                        row(
                            ui,
                            "Dropped",
                            format!("{} / {} err", s.dropped, s.decode_errors),
                        );
                    }
                });
        });
}

// ---------------------------------------------------------------------------
// Building blocks
// ---------------------------------------------------------------------------

/// A centred card on top of `bg` (or on top of the video when `None`).
fn centered_card(ui: &mut Ui, bg: Option<Color32>, add: impl FnOnce(&mut Ui, f32)) {
    let full = ui.max_rect();
    if let Some(bg) = bg {
        ui.painter().rect_filled(full, 0, bg);
    }
    let col = (full.width() - 32.0).clamp(180.0, 340.0);
    egui::Area::new(ids().card)
        .order(Order::Middle)
        .anchor(Align2::CENTER_CENTER, vec2(0.0, 0.0))
        .show(ui.ctx(), |ui| {
            card(ui, col, |ui, w| {
                ui.vertical_centered(|ui| add(ui, w));
            });
        });
}

/// A surface card `width` wide (outer); `add` gets the inner width.
fn card(ui: &mut Ui, width: f32, add: impl FnOnce(&mut Ui, f32)) {
    let pad = 18.0;
    Frame::new()
        .fill(SURFACE)
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(CornerRadius::same(14))
        .inner_margin(Margin::same(pad as i8))
        .shadow(egui::Shadow {
            offset: [0, 6],
            blur: 18,
            spread: 0,
            color: Color32::from_black_alpha(70),
        })
        .show(ui, |ui| {
            let inner = width - 2.0 * pad;
            ui.set_width(inner);
            ui.with_layout(Layout::top_down(Align::Min), |ui| add(ui, inner));
        });
}

fn caption(ui: &mut Ui, text: &str) -> egui::Response {
    ui.label(
        RichText::new(text)
            .font(FontId::new(11.5, FontFamily::Proportional))
            .strong()
            .color(MUTED),
    )
}

fn pill(ui: &mut Ui, text: &str) {
    let galley = ui.painter().layout_no_wrap(
        text.to_string(),
        FontId::new(12.0, FontFamily::Proportional),
        TEAL_HI,
    );
    let size = galley.size() + vec2(16.0, 6.0);
    let (rect, _) = ui.allocate_exact_size(size, Sense::hover());
    ui.painter()
        .rect_filled(rect, CornerRadius::same(10), TEAL.gamma_multiply(0.16));
    ui.painter()
        .galley(rect.center() - galley.size() / 2.0, galley, TEAL_HI);
}

/// Time between spinner frames. `egui::Spinner` asks for a repaint every
/// frame (60 fps of full wgpu passes while connecting); 20 fps looks smooth
/// enough for a 30 px indicator.
const SPINNER_FRAME: Duration = Duration::from_millis(50);

/// Same look as `egui::Spinner`, but repainting at [`SPINNER_FRAME`].
fn spinner(ui: &mut Ui) {
    let size = 30.0;
    let (rect, _) = ui.allocate_exact_size(vec2(size, size), Sense::hover());
    if !ui.is_rect_visible(rect) {
        return;
    }
    ui.ctx().request_repaint_after(SPINNER_FRAME);
    let radius = size * 0.5 - 2.0;
    let time = ui.input(|i| i.time);
    let start = time * std::f64::consts::TAU;
    let end = start + 240f64.to_radians() * time.sin();
    let points: Vec<_> = (0..radius.round() as u32)
        .map(|i| {
            let a = start + (end - start) * f64::from(i) / f64::from(radius.round());
            rect.center() + radius * vec2(a.cos() as f32, a.sin() as f32)
        })
        .collect();
    ui.painter()
        .add(egui::Shape::line(points, Stroke::new(3.0, TEAL_HI)));
}

fn paint_button(
    ui: &mut Ui,
    text: &str,
    width: f32,
    height: f32,
    primary: bool,
    danger: bool,
    on: bool,
) -> egui::Response {
    labeled_button(ui, text, true, width, height, primary, danger, on)
}

/// [`paint_button`] whose `text` is drawn only when `show_text` (an icon
/// button paints its own icon); it is the accessible name either way.
#[allow(clippy::too_many_arguments)]
fn labeled_button(
    ui: &mut Ui,
    text: &str,
    show_text: bool,
    width: f32,
    height: f32,
    primary: bool,
    danger: bool,
    on: bool,
) -> egui::Response {
    let (rect, resp) = ui.allocate_exact_size(vec2(width, height), Sense::click());
    let resp = resp.on_hover_cursor(egui::CursorIcon::PointingHand);
    resp.widget_info(|| egui::WidgetInfo::labeled(egui::Role::Button, ui.is_enabled(), text));
    let down = resp.is_pointer_button_down_on();
    let hovered = resp.hovered();
    let (fill, stroke, fg) = if primary {
        let fill = if down {
            TEAL_DOWN
        } else if hovered {
            TEAL_HI
        } else {
            TEAL
        };
        (fill, Stroke::NONE, ON_TEAL)
    } else if danger {
        let a = if down {
            0.45
        } else if hovered {
            0.32
        } else {
            0.18
        };
        (
            DANGER.gamma_multiply(a),
            Stroke::new(1.0, DANGER.gamma_multiply(0.6)),
            TEXT,
        )
    } else if on {
        (TEAL.gamma_multiply(0.3), Stroke::new(1.0, TEAL), TEXT)
    } else {
        let fill = if down || hovered { HOVER } else { INPUT };
        let stroke = if hovered {
            TEAL.gamma_multiply(0.7)
        } else {
            BORDER
        };
        (fill, Stroke::new(1.0, stroke), TEXT)
    };
    let p = ui.painter();
    p.rect_filled(rect, 10, fill);
    if stroke.width > 0.0 {
        p.rect_stroke(rect, 10, stroke, StrokeKind::Inside);
    }
    if resp.has_focus() {
        // Visible keyboard focus ring.
        p.rect_stroke(
            rect.expand(2.0),
            11,
            Stroke::new(2.0, TEAL_HI),
            StrokeKind::Outside,
        );
    }
    if show_text {
        p.text(
            rect.center(),
            Align2::CENTER_CENTER,
            text,
            FontId::new(15.0, FontFamily::Proportional),
            fg,
        );
    }
    resp
}

fn primary_button(ui: &mut Ui, text: &str, width: f32) -> egui::Response {
    paint_button(ui, text, width, 40.0, true, false, false)
}

fn secondary_button(ui: &mut Ui, text: &str, width: f32) -> egui::Response {
    paint_button(ui, text, width, 38.0, false, false, false)
}

fn bar_button(
    ui: &mut Ui,
    text: &str,
    show_text: bool,
    width: f32,
    danger: bool,
    on: bool,
) -> egui::Response {
    labeled_button(ui, text, show_text, width, 30.0, false, danger, on)
}

/// App mark, after the app icon: a blue-navy tile with a white screen
/// outline, a teal phone in front of it and teal "cast" arcs.
fn logo(ui: &mut Ui, size: f32) {
    let (rect, _) = ui.allocate_exact_size(vec2(size, size), Sense::hover());
    let p = ui.painter();
    let s = size / 64.0;
    let r = |v: f32| CornerRadius::same((v * s) as u8);
    p.rect_filled(rect, r(15.0), Color32::from_rgb(0x1E, 0x2F, 0x6E));
    p.rect_stroke(
        rect,
        r(15.0),
        Stroke::new(1.0, Color32::from_rgb(0x2B, 0x3F, 0x85)),
        StrokeKind::Inside,
    );
    let o = rect.min;
    // Screen outline (landscape).
    let screen = egui::Rect::from_min_size(o + vec2(10.0 * s, 16.0 * s), vec2(40.0 * s, 28.0 * s));
    p.rect_stroke(
        screen,
        r(5.0),
        Stroke::new(3.0 * s, TEXT),
        StrokeKind::Middle,
    );
    // Phone (portrait) overlapping the screen's left edge.
    let phone = egui::Rect::from_min_size(o + vec2(14.0 * s, 24.0 * s), vec2(13.0 * s, 26.0 * s));
    p.rect_filled(
        phone.expand(2.0 * s),
        r(5.0),
        Color32::from_rgb(0x1E, 0x2F, 0x6E),
    );
    p.rect_filled(phone, r(3.5), TEAL);
    // Arcs.
    let c = o + vec2(33.0 * s, 31.0 * s);
    for rad in [6.0, 10.5, 15.0] {
        let pts: Vec<_> = (0..=12)
            .map(|i| {
                let a = -0.8 + 1.6 * i as f32 / 12.0;
                c + vec2(a.cos(), a.sin()) * rad * s
            })
            .collect();
        p.add(egui::Shape::line(pts, Stroke::new(2.4 * s, TEAL_HI)));
    }
}

fn paint_close_icon(ui: &Ui, rect: egui::Rect) {
    let c = rect.center();
    let d = 5.0;
    let st = Stroke::new(2.0, TEXT);
    let p = ui.painter();
    p.line_segment([c + vec2(-d, -d), c + vec2(d, d)], st);
    p.line_segment([c + vec2(-d, d), c + vec2(d, -d)], st);
}

fn paint_stats_icon(ui: &Ui, rect: egui::Rect) {
    let c = rect.center();
    let p = ui.painter();
    for (i, h) in [6.0, 11.0, 8.0].into_iter().enumerate() {
        let x = c.x - 6.0 + i as f32 * 5.5;
        let bar =
            egui::Rect::from_min_max(egui::pos2(x, c.y + 6.0 - h), egui::pos2(x + 3.5, c.y + 6.0));
        p.rect_filled(bar, 1, TEXT);
    }
}

fn alert_icon(ui: &mut Ui) {
    let (rect, _) = ui.allocate_exact_size(vec2(44.0, 44.0), Sense::hover());
    let p = ui.painter();
    p.circle_filled(rect.center(), 21.0, WARN.gamma_multiply(0.15));
    p.circle_stroke(rect.center(), 20.0, Stroke::new(2.0, WARN));
    p.line_segment(
        [
            rect.center() + vec2(0.0, -9.0),
            rect.center() + vec2(0.0, 3.0),
        ],
        Stroke::new(3.0, WARN),
    );
    p.circle_filled(rect.center() + vec2(0.0, 9.0), 2.0, WARN);
}

fn moon(ui: &mut Ui) {
    let (rect, _) = ui.allocate_exact_size(vec2(16.0, 16.0), Sense::hover());
    let p = ui.painter();
    p.circle_filled(rect.center(), 7.0, MUTED);
    p.circle_filled(rect.center() + vec2(3.5, -3.0), 6.0, SURFACE);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::Target;

    #[test]
    fn bar_background_passes_presses_to_phone_but_buttons_do_not() {
        let r = |x0, y0, x1, y1| egui::Rect::from_min_max(egui::pos2(x0, y0), egui::pos2(x1, y1));
        let layer = LayerId::new(Order::Foreground, Id::unique("test-bar"));
        let other = Some(LayerId::new(Order::Foreground, Id::unique("test-dialog")));
        let mut state = UiState::default();
        // Hidden bar: nothing is special.
        assert!(!state.bar_passes_to_phone(egui::pos2(10.0, 10.0), Some(layer)));
        state.bar_zone = Some(BarZone {
            bar: r(0.0, 0.0, 400.0, 48.0),
            buttons: vec![r(300.0, 8.0, 380.0, 38.0)],
            layer,
        });
        assert!(state.bar_passes_to_phone(egui::pos2(10.0, 10.0), Some(layer)));
        assert!(!state.bar_passes_to_phone(egui::pos2(340.0, 20.0), Some(layer)));
        assert!(
            !state.bar_passes_to_phone(egui::pos2(10.0, 60.0), Some(layer)),
            "below the bar"
        );
        // Something drawn above the bar (or nothing of ours there) keeps it.
        assert!(
            !state.bar_passes_to_phone(egui::pos2(10.0, 10.0), other),
            "an overlay above the bar owns the press"
        );
        assert!(!state.bar_passes_to_phone(egui::pos2(10.0, 10.0), None));
    }

    /// Mirroring frames with the pointer near the top, `has_video` per
    /// stage; whether the UI state holds a bar zone after each stage.
    fn bar_zone_after(conn: &ConnState, stages: &[bool]) -> Vec<bool> {
        let ctx = egui::Context::default();
        apply_theme(&ctx);
        let mut state = UiState::default();
        let screen = egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(480.0, 900.0));
        let mut t = 0.0;
        stages
            .iter()
            .map(|&has_video| {
                let view = View {
                    conn,
                    has_video,
                    forwarding: false,
                    stats: None,
                    paired: &[],
                    now: Instant::now(),
                };
                for _ in 0..3 {
                    t += 0.1;
                    let mut out = ctx.run_ui(
                        egui::RawInput {
                            time: Some(t),
                            screen_rect: Some(screen),
                            events: vec![egui::Event::PointerMoved(egui::pos2(100.0, 10.0))],
                            ..Default::default()
                        },
                        |ui| {
                            draw(ui, &mut state, &view);
                        },
                    );
                    out.textures_delta.clear();
                }
                state.bar_zone.is_some()
            })
            .collect()
    }

    #[test]
    fn bar_zone_exists_only_while_the_bar_is_drawn() {
        let mut conn = ConnState::new();
        conn.connect(Target {
            host: "10.0.0.2".into(),
            port: 47800,
        });
        conn.phase = Phase::Mirroring {
            video: Some((1080, 2400)),
        };
        // Bar up while there is a picture; gone when the picture goes.
        assert_eq!(bar_zone_after(&conn, &[true, false]), [true, false]);
        // A stale zone from mirroring does not outlive the phase.
        let ctx = egui::Context::default();
        let mut state = UiState {
            bar_zone: Some(BarZone {
                bar: egui::Rect::EVERYTHING,
                buttons: vec![],
                layer: LayerId::background(),
            }),
            ..UiState::default()
        };
        let home = ConnState::new();
        let view = View {
            conn: &home,
            has_video: false,
            forwarding: false,
            stats: None,
            paired: &[],
            now: Instant::now(),
        };
        let mut out = ctx.run_ui(egui::RawInput::default(), |ui| {
            draw(ui, &mut state, &view);
        });
        out.textures_delta.clear();
        assert!(state.bar_zone.is_none());
    }

    /// The accessibility nodes of one frame (screen reader on), after a few
    /// warm-up frames with no pointer over the window.
    fn a11y_nodes(
        state: &mut UiState,
        conn: &ConnState,
        paired: &[PairedDevice],
    ) -> Vec<egui::accesskit::Node> {
        let ctx = egui::Context::default();
        apply_theme(&ctx);
        ctx.enable_accesskit();
        let view = View {
            conn,
            has_video: true,
            forwarding: false,
            stats: None,
            paired,
            now: Instant::now(),
        };
        let screen = egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(480.0, 900.0));
        let mut nodes = Vec::new();
        for i in 0..3 {
            let mut out = ctx.run_ui(
                egui::RawInput {
                    time: Some(10.0 + f64::from(i)),
                    screen_rect: Some(screen),
                    ..Default::default()
                },
                |ui| {
                    draw(ui, state, &view);
                },
            );
            out.textures_delta.clear();
            nodes = out
                .platform_output
                .accesskit_update
                .map(|u| u.nodes.into_iter().map(|(_, n)| n).collect())
                .unwrap_or_default();
        }
        nodes
    }

    fn labelled<'a>(
        nodes: &'a [egui::accesskit::Node],
        label: &str,
    ) -> Option<&'a egui::accesskit::Node> {
        nodes.iter().find(|n| n.label() == Some(label))
    }

    #[test]
    fn screen_reader_users_can_reach_the_bar_buttons_while_mirroring() {
        let conn = mirroring_conn();
        let mut state = UiState {
            screen_reader: true,
            ..UiState::default()
        };
        let nodes = a11y_nodes(&mut state, &conn, &[]);
        assert!(labelled(&nodes, "Disconnect").is_some(), "{nodes:?}");
        let stats = labelled(&nodes, "Stats").expect("Stats button");
        assert_eq!(stats.toggled(), Some(egui::accesskit::Toggled::False));
        state.show_stats = true;
        let nodes = a11y_nodes(&mut state, &conn, &[]);
        let stats = labelled(&nodes, "Stats").expect("Stats button");
        assert_eq!(stats.toggled(), Some(egui::accesskit::Toggled::True));
        // Without a screen reader the bar still hides with the pointer away.
        let mut state = UiState::default();
        let nodes = a11y_nodes(&mut state, &conn, &[]);
        assert!(labelled(&nodes, "Disconnect").is_none());
    }

    #[test]
    fn toasts_are_announced() {
        let conn = mirroring_conn();
        let mut state = UiState::default();
        state.show_toast("Paste interrupted");
        let nodes = a11y_nodes(&mut state, &conn, &[]);
        let toast = nodes
            .iter()
            .find(|n| n.value() == Some("Paste interrupted"))
            .expect("toast node");
        assert_eq!(toast.live(), Some(egui::accesskit::Live::Polite));
    }

    #[test]
    fn each_forget_button_names_its_phone() {
        let home = ConnState::new();
        let paired = [PairedDevice {
            device_id: "p1".into(),
            device_name: "Pixel 8".into(),
            key: mirror_protocol::auth::PairingKey::from_bytes([1; 32]),
            paired_at_ms: 0,
        }];
        let mut state = UiState::default();
        let nodes = a11y_nodes(&mut state, &home, &paired);
        assert!(labelled(&nodes, "Forget Pixel 8").is_some(), "{nodes:?}");
        assert!(labelled(&nodes, "Forget").is_none());
        state.confirm_forget = Some("p1".into());
        let nodes = a11y_nodes(&mut state, &home, &paired);
        assert!(labelled(&nodes, "Forget Pixel 8").is_some(), "{nodes:?}");
    }

    /// Press "s" in a mirroring UI whose phone said control is available.
    fn stats_after_s(forwarding: bool) -> bool {
        let ctx = egui::Context::default();
        apply_theme(&ctx);
        let mut conn = ConnState::new();
        conn.connect(Target {
            host: "10.0.0.2".into(),
            port: 47800,
        });
        conn.phase = Phase::Mirroring {
            video: Some((1080, 2400)),
        };
        conn.control_available = true; // the phone's STATUS said so
        let mut state = UiState::default();
        let view = View {
            conn: &conn,
            has_video: true,
            forwarding,
            stats: None,
            paired: &[],
            now: Instant::now(),
        };
        let screen = egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(480.0, 900.0));
        let key = |pressed| egui::Event::Key {
            key: Key::S,
            physical_key: None,
            pressed,
            repeat: false,
            modifiers: egui::Modifiers::NONE,
        };
        for (i, events) in [vec![], vec![key(true)], vec![key(false)]]
            .into_iter()
            .enumerate()
        {
            let mut out = ctx.run_ui(
                egui::RawInput {
                    time: Some(i as f64 * 0.016),
                    screen_rect: Some(screen),
                    events,
                    ..Default::default()
                },
                |ui| {
                    draw(ui, &mut state, &view);
                },
            );
            out.textures_delta.clear();
        }
        state.show_stats
    }

    #[test]
    fn stats_key_follows_the_apps_forwarding_gate_not_the_phones_flag() {
        // The phone offers control but the session refuses it: nothing is
        // forwarded, so S is the stats shortcut.
        assert!(stats_after_s(false));
        // Keys going to the phone: S is typed text.
        assert!(!stats_after_s(true));
    }

    fn mirroring_conn() -> ConnState {
        let mut conn = ConnState::new();
        conn.connect(Target {
            host: "10.0.0.2".into(),
            port: 47800,
        });
        conn.phase = Phase::Mirroring {
            video: Some((1080, 2400)),
        };
        conn
    }

    /// One UI frame `width` points wide at `now`, pointer near the top (so
    /// the bar shows), with the screen-reader tree on.
    fn frame_output(
        ctx: &egui::Context,
        state: &mut UiState,
        view: &View<'_>,
        width: f32,
        time: f64,
    ) -> egui::FullOutput {
        let screen = egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(width, 700.0));
        let mut out = ctx.run_ui(
            egui::RawInput {
                time: Some(time),
                screen_rect: Some(screen),
                events: vec![egui::Event::PointerMoved(egui::pos2(100.0, 10.0))],
                ..Default::default()
            },
            |ui| {
                draw(ui, state, view);
            },
        );
        out.textures_delta.clear();
        out
    }

    /// Every piece of text painted in `out`.
    fn painted_text(out: &egui::FullOutput) -> String {
        fn walk(shape: &egui::Shape, text: &mut String) {
            match shape {
                egui::Shape::Text(t) => {
                    text.push_str(t.galley.text());
                    text.push('\n');
                }
                egui::Shape::Vec(v) => v.iter().for_each(|s| walk(s, text)),
                _ => {}
            }
        }
        let mut text = String::new();
        out.shapes.iter().for_each(|c| walk(&c.shape, &mut text));
        text
    }

    #[test]
    fn compact_bar_buttons_have_names() {
        use egui::accesskit::Role;
        let ctx = egui::Context::default();
        apply_theme(&ctx);
        ctx.enable_accesskit();
        let conn = mirroring_conn();
        let mut state = UiState::default();
        let view = View {
            conn: &conn,
            has_video: true,
            forwarding: false,
            stats: None,
            paired: &[],
            now: Instant::now(),
        };
        let mut out = None;
        for i in 0..3 {
            out = Some(frame_output(
                &ctx,
                &mut state,
                &view,
                300.0,
                f64::from(i) * 0.1,
            ));
        }
        let out = out.unwrap();
        let tree = out.platform_output.accesskit_update.as_ref().expect("tree");
        let buttons: Vec<String> = tree
            .nodes
            .iter()
            .filter(|(_, n)| n.role() == Role::Button)
            .filter_map(|(_, n)| n.label().map(str::to_string))
            .collect();
        assert!(
            buttons.iter().any(|b| b == "Disconnect") && buttons.iter().any(|b| b == "Stats"),
            "{buttons:?}"
        );
        // Icon-only: the names are not painted at this width.
        let text = painted_text(&out);
        assert!(!text.contains("Disconnect"), "{text}");
    }

    #[test]
    fn text_fields_are_named_by_their_labels() {
        use crate::client::{ClientEvent, DisconnectReason};
        use egui::accesskit::Role;
        let mut pin = ConnState::new();
        pin.connect(Target {
            host: "10.0.0.2".into(),
            port: 47800,
        });
        pin.on_event(
            &ClientEvent::Stopped(DisconnectReason::WrongPin),
            Instant::now(),
        );
        for conn in [ConnState::new(), pin] {
            let ctx = egui::Context::default();
            apply_theme(&ctx);
            ctx.enable_accesskit();
            let mut state = UiState::default();
            let view = View {
                conn: &conn,
                has_video: false,
                forwarding: false,
                stats: None,
                paired: &[],
                now: Instant::now(),
            };
            frame_output(&ctx, &mut state, &view, 480.0, 0.0);
            let out = frame_output(&ctx, &mut state, &view, 480.0, 0.1);
            let tree = out.platform_output.accesskit_update.expect("tree");
            let field = tree
                .nodes
                .iter()
                .find(|(_, n)| n.role() == Role::TextInput)
                .unwrap_or_else(|| {
                    let roles: Vec<_> = tree.nodes.iter().map(|(_, n)| n.role()).collect();
                    panic!("no text field: {roles:?}")
                });
            assert!(!field.1.labelled_by().is_empty(), "{:?}", conn.phase);
        }
    }

    #[test]
    fn toast_shows_while_waiting_for_video_and_counts_from_first_draw() {
        let ctx = egui::Context::default();
        apply_theme(&ctx);
        let conn = mirroring_conn();
        let mut state = UiState::default();
        state.show_toast_for("Paired, but not saved", Duration::from_secs(10));
        let t0 = Instant::now();
        let mut text_at = |secs: u64| {
            let view = View {
                conn: &conn,
                has_video: false, // "Waiting for video…"
                forwarding: false,
                stats: None,
                paired: &[],
                now: t0 + Duration::from_secs(secs),
            };
            painted_text(&frame_output(&ctx, &mut state, &view, 480.0, secs as f64))
        };
        // First drawn long after it was raised (window hidden meanwhile);
        // a new area is laid out invisibly in its first frame.
        text_at(30);
        assert!(text_at(30).contains("Paired, but not saved"));
        assert!(text_at(39).contains("Paired, but not saved"));
        assert!(!text_at(41).contains("Paired, but not saved"));
    }

    /// Whether the bytes past the buffer's length (up to its capacity) are
    /// all zero.
    fn spare_is_zero(b: &mut PinBuffer) -> bool {
        // SAFETY: only reads the allocation as bytes, without changing it.
        let v = unsafe { b.0.as_mut_vec() };
        v.spare_capacity_mut()
            .iter()
            .all(|x| unsafe { x.assume_init() } == 0)
    }

    #[test]
    fn pin_buffer_takes_only_six_digits_and_never_regrows() {
        use egui::text::CharIndex;
        use egui::TextBuffer;
        let mut b = PinBuffer::default();
        let cap = b.0.capacity();
        assert_eq!(b.insert_text("12a3 4-5", CharIndex(0)), 5);
        assert_eq!(b.as_str(), "12345");
        assert_eq!(b.insert_text("6789", CharIndex(5)), 1, "room for one more");
        assert_eq!(b.as_str(), "123456");
        assert_eq!(b.insert_text("0", CharIndex(0)), 0, "full");
        b.delete_char_range(CharIndex(1)..CharIndex(3));
        assert_eq!(b.as_str(), "1456");
        b.delete_char_range(CharIndex(2)..CharIndex(99));
        assert_eq!(b.as_str(), "14");
        assert_eq!(b.0.capacity(), cap, "no realloc: one buffer to wipe");
        b.insert_text("0000", CharIndex(2));
        let taken = b.submit();
        assert_eq!(&**taken, "140000");
        assert_eq!(b.as_str(), "");
        assert_eq!(b.0.capacity(), cap);
        assert!(spare_is_zero(&mut b), "submit wipes");
        b.insert_text("987654", CharIndex(0));
        b.delete_char_range(CharIndex(0)..CharIndex(4));
        assert_eq!(b.as_str(), "54");
        assert!(spare_is_zero(&mut b), "delete wipes what it frees");
        b.clear();
        assert!(spare_is_zero(&mut b), "clear wipes");
        assert!(!format!("{b:?}").contains('1'));
    }

    /// Run a few UI frames in `conn`'s phase and return the repaint delay
    /// egui reports after the last one.
    fn repaint_delay(conn: &ConnState) -> Duration {
        let ctx = egui::Context::default();
        apply_theme(&ctx);
        let mut state = UiState::default();
        let view = View {
            conn,
            has_video: false,
            forwarding: false,
            stats: None,
            paired: &[],
            now: Instant::now(),
        };
        let mut delay = Duration::MAX;
        for i in 0..6 {
            let input = egui::RawInput {
                time: Some(f64::from(i) * 0.1),
                ..Default::default()
            };
            let mut out = ctx.run_ui(input, |ui| {
                draw(ui, &mut state, &view);
            });
            out.textures_delta.clear();
            delay = out.viewport_output[&egui::ViewportId::ROOT].repaint_delay;
        }
        delay
    }

    #[test]
    fn connecting_spinner_does_not_repaint_every_frame() {
        let mut conn = ConnState::new();
        conn.connect(Target {
            host: "10.0.0.2".into(),
            port: 47800,
        });
        let d = repaint_delay(&conn);
        assert!(d >= Duration::from_millis(30), "repaint every {d:?}");
        assert!(d < Duration::from_secs(1), "spinner must keep animating");
    }

    #[test]
    fn home_is_idle() {
        assert_eq!(repaint_delay(&ConnState::new()), Duration::MAX);
    }

    #[test]
    fn locked_out_dialog_keeps_counting_down() {
        use crate::client::{ClientEvent, DisconnectReason};
        let mut conn = ConnState::new();
        conn.connect(Target {
            host: "10.0.0.2".into(),
            port: 47800,
        });
        conn.on_event(
            &ClientEvent::Stopped(DisconnectReason::LockedOut {
                retry_after: Duration::from_secs(30),
            }),
            Instant::now(),
        );
        assert!(repaint_delay(&conn) < Duration::from_secs(1));
    }

    #[test]
    fn identity_dialog_is_idle_and_pin_field_only_blinks() {
        use crate::client::{ClientEvent, DisconnectReason};
        let delay = |reason| {
            let mut conn = ConnState::new();
            conn.connect(Target {
                host: "10.0.0.2".into(),
                port: 47800,
            });
            conn.on_event(&ClientEvent::Stopped(reason), Instant::now());
            repaint_delay(&conn)
        };
        let id = DisconnectReason::IdentityChanged {
            device_id: "d".into(),
        };
        assert_eq!(delay(id), Duration::MAX);
        // The focused PIN field repaints for the caret blink, not every frame.
        assert!(delay(DisconnectReason::WrongPin) >= Duration::from_millis(100));
    }
}
