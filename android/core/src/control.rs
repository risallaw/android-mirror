//! Pure mappings from [`ControlSink`](mirror_sender::ControlSink) calls to the
//! arguments of the Kotlin `CoreCallbacks.on*` control upcalls (JNI glue in
//! `callbacks.rs`). Host-testable.

use mirror_protocol::{GestureKind, GlobalAction, Key, TouchPhase};
use mirror_sender::PixelPoint;

/// `onGesture` kind codes.
pub const GESTURE_TAP: i32 = 1;
pub const GESTURE_LONG_PRESS: i32 = 2;
pub const GESTURE_PATH: i32 = 3;

/// Arguments of `onGesture(kind, xs, ys, durationMs)`.
#[derive(Debug, Clone, PartialEq)]
pub struct GestureArgs {
    pub kind: i32,
    pub xs: Vec<f32>,
    pub ys: Vec<f32>,
    /// Sum of `dt_ms` for paths; 0 for tap/long press ("use the default").
    pub duration_ms: i64,
}

/// Map a gesture to `onGesture` arguments; `None` for kinds this version does
/// not know or a gesture without points (nothing to inject).
pub fn gesture_args(kind: GestureKind, points: &[PixelPoint]) -> Option<GestureArgs> {
    if points.is_empty() {
        return None;
    }
    let (kind, duration_ms) = match kind {
        GestureKind::Tap => (GESTURE_TAP, 0),
        GestureKind::LongPress => (GESTURE_LONG_PRESS, 0),
        GestureKind::Path => (GESTURE_PATH, path_duration_ms(points)),
        GestureKind::Other(_) => return None,
    };
    Some(GestureArgs {
        kind,
        xs: points.iter().map(|p| p.x as f32).collect(),
        ys: points.iter().map(|p| p.y as f32).collect(),
        duration_ms,
    })
}

/// Total path duration: the sum of every point's `dt_ms` (the first is
/// normally 0). Cannot overflow: at most 255 points of ≤ 65535 ms.
pub fn path_duration_ms(points: &[PixelPoint]) -> i64 {
    points.iter().map(|p| i64::from(p.dt_ms)).sum()
}

/// `onGlobalAction` code: the wire value (1 back … 8 volume down); unknown
/// values pass through so Kotlin can log and ignore them.
pub fn global_action_code(a: GlobalAction) -> i32 {
    i32::from(a.to_u8())
}

/// `onKey` code: the wire value (1 backspace … 8 tab), unknown values pass through.
pub fn key_code(k: Key) -> i32 {
    i32::from(k.to_u8())
}

/// `onTouchLive` phase: 0 down, 1 move, 2 up, 3 cancel; unknown values pass through.
pub fn touch_phase_code(p: TouchPhase) -> i32 {
    i32::from(p.to_u8())
}

/// `onScroll(x, y, dx, dy)` arguments in display pixels.
pub fn scroll_args(x: u32, y: u32, dx: i32, dy: i32) -> [f32; 4] {
    [x as f32, y as f32, dx as f32, dy as f32]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pt(x: u32, y: u32, dt_ms: u16) -> PixelPoint {
        PixelPoint { x, y, dt_ms }
    }

    #[test]
    fn tap_and_long_press_have_zero_duration() {
        let a = gesture_args(GestureKind::Tap, &[pt(10, 20, 30)]).unwrap();
        assert_eq!(
            a,
            GestureArgs {
                kind: 1,
                xs: vec![10.0],
                ys: vec![20.0],
                duration_ms: 0
            }
        );
        let a = gesture_args(GestureKind::LongPress, &[pt(1, 2, 700)]).unwrap();
        assert_eq!((a.kind, a.duration_ms), (2, 0));
    }

    #[test]
    fn path_duration_is_sum_of_dt() {
        let pts = [pt(0, 0, 0), pt(5, 6, 16), pt(7, 8, 17), pt(1079, 2399, 100)];
        let a = gesture_args(GestureKind::Path, &pts).unwrap();
        assert_eq!(a.kind, 3);
        assert_eq!(a.duration_ms, 133);
        assert_eq!(a.xs, vec![0.0, 5.0, 7.0, 1079.0]);
        assert_eq!(a.ys, vec![0.0, 6.0, 8.0, 2399.0]);
    }

    #[test]
    fn path_duration_does_not_overflow() {
        let pts = vec![pt(0, 0, u16::MAX); 255];
        assert_eq!(path_duration_ms(&pts), 255 * 65535);
    }

    #[test]
    fn unknown_or_empty_gestures_are_dropped() {
        assert!(gesture_args(GestureKind::Other(9), &[pt(1, 1, 0)]).is_none());
        assert!(gesture_args(GestureKind::Tap, &[]).is_none());
    }

    #[test]
    fn action_key_phase_codes() {
        let actions = [
            (GlobalAction::Back, 1),
            (GlobalAction::Home, 2),
            (GlobalAction::Recents, 3),
            (GlobalAction::Notifications, 4),
            (GlobalAction::QuickSettings, 5),
            (GlobalAction::Lock, 6),
            (GlobalAction::VolumeUp, 7),
            (GlobalAction::VolumeDown, 8),
            (GlobalAction::Other(42), 42),
            (GlobalAction::Other(255), 255),
        ];
        for (a, c) in actions {
            assert_eq!(global_action_code(a), c, "{a:?}");
        }
        let keys = [
            (Key::Backspace, 1),
            (Key::Enter, 2),
            (Key::Left, 3),
            (Key::Right, 4),
            (Key::Up, 5),
            (Key::Down, 6),
            (Key::DeleteForward, 7),
            (Key::Tab, 8),
            (Key::Other(200), 200),
        ];
        for (k, c) in keys {
            assert_eq!(key_code(k), c, "{k:?}");
        }
        let phases = [
            (TouchPhase::Down, 0),
            (TouchPhase::Move, 1),
            (TouchPhase::Up, 2),
            (TouchPhase::Cancel, 3),
            (TouchPhase::Other(7), 7),
        ];
        for (p, c) in phases {
            assert_eq!(touch_phase_code(p), c, "{p:?}");
        }
    }

    #[test]
    fn scroll_is_signed_pixels() {
        assert_eq!(
            scroll_args(540, 1200, -300, 450),
            [540.0, 1200.0, -300.0, 450.0]
        );
    }
}
