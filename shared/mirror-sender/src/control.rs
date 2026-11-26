//! Mapping of receiver control messages onto a [`ControlSink`].

use mirror_protocol::geometry::norm_to_px;
use mirror_protocol::{Message, VideoConfig};

use crate::types::{ControlSink, PixelPoint};

/// True for receiver → phone input messages (Phase 2).
pub fn is_control(msg: &Message) -> bool {
    matches!(
        msg,
        Message::TouchGesture(_)
            | Message::GlobalAction(_)
            | Message::Text(_)
            | Message::Key(_)
            | Message::Scroll(_)
            | Message::TouchLive(_)
    )
}

/// Signed normalised distance -> display pixels, mapped like a coordinate
/// (`|d| × (size − 1) / 65535`, rounded) with the sign kept.
fn delta_to_px(d: i16, size: u32) -> i32 {
    let mag = norm_to_px(d.unsigned_abs(), size) as i32;
    if d < 0 {
        -mag
    } else {
        mag
    }
}

/// Deliver one control message to `sink`, mapping normalised coordinates to
/// display pixels with `cfg.display_width`/`display_height`.
///
/// Returns false (and calls nothing) when the message is not a control
/// message, or when it carries coordinates but no config is known yet or the
/// gesture has no points.
pub fn dispatch_control(msg: &Message, cfg: Option<&VideoConfig>, sink: &dyn ControlSink) -> bool {
    let dims = cfg.map(|c| (u32::from(c.display_width), u32::from(c.display_height)));
    let px = |x: u16, y: u16| dims.map(|(w, h)| (norm_to_px(x, w), norm_to_px(y, h)));
    match msg {
        Message::GlobalAction(a) => sink.global_action(*a),
        Message::Key(k) => sink.key(*k),
        Message::Text(t) => sink.text(t),
        Message::TouchGesture(g) => {
            let Some((w, h)) = dims else { return false };
            if g.points.is_empty() {
                return false;
            }
            let pts: Vec<PixelPoint> = g
                .points
                .iter()
                .map(|p| PixelPoint {
                    x: norm_to_px(p.x, w),
                    y: norm_to_px(p.y, h),
                    dt_ms: p.dt_ms,
                })
                .collect();
            sink.gesture(g.kind, &pts);
        }
        Message::Scroll(s) => {
            let (Some((x, y)), Some((w, h))) = (px(s.x, s.y), dims) else {
                return false;
            };
            sink.scroll(x, y, delta_to_px(s.dx, w), delta_to_px(s.dy, h));
        }
        Message::TouchLive(t) => {
            let Some((x, y)) = px(t.x, t.y) else {
                return false;
            };
            sink.touch_live(t.phase, x, y);
        }
        _ => return false,
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use mirror_protocol::{
        GestureKind, GesturePoint, GlobalAction, Key, Scroll, TouchGesture, TouchLive, TouchPhase,
    };
    use std::sync::Mutex;

    #[derive(Default)]
    struct Rec(Mutex<Vec<String>>);
    impl ControlSink for Rec {
        fn gesture(&self, k: GestureKind, p: &[PixelPoint]) {
            self.0.lock().unwrap().push(format!("g {k:?} {p:?}"));
        }
        fn touch_live(&self, ph: TouchPhase, x: u32, y: u32) {
            self.0.lock().unwrap().push(format!("t {ph:?} {x} {y}"));
        }
        fn scroll(&self, x: u32, y: u32, dx: i32, dy: i32) {
            self.0.lock().unwrap().push(format!("s {x} {y} {dx} {dy}"));
        }
        fn global_action(&self, a: GlobalAction) {
            self.0.lock().unwrap().push(format!("a {a:?}"));
        }
        fn text(&self, t: &str) {
            self.0.lock().unwrap().push(format!("x {t}"));
        }
        fn key(&self, k: Key) {
            self.0.lock().unwrap().push(format!("k {k:?}"));
        }
    }

    #[test]
    fn maps_to_display_pixels() {
        let cfg = VideoConfig {
            width: 864,
            height: 1920,
            display_width: 1080,
            display_height: 2400,
            rotation: 0,
            sps_pps: vec![],
        };
        let r = Rec::default();
        let msgs = [
            Message::TouchGesture(TouchGesture {
                kind: GestureKind::Tap,
                points: vec![
                    GesturePoint {
                        x: 0,
                        y: 65535,
                        dt_ms: 0,
                    },
                    GesturePoint {
                        x: 65535,
                        y: 0,
                        dt_ms: 16,
                    },
                ],
            }),
            Message::TouchLive(TouchLive {
                phase: TouchPhase::Down,
                x: 32768,
                y: 0,
            }),
            Message::Scroll(Scroll {
                x: 65535,
                y: 65535,
                dx: -32768,
                dy: 6554,
            }),
            Message::GlobalAction(GlobalAction::Home),
            Message::Text("hé".into()),
            Message::Key(Key::Enter),
        ];
        for m in &msgs {
            assert!(is_control(m));
            assert!(dispatch_control(m, Some(&cfg), &r), "{m:?}");
        }
        assert_eq!(
            *r.0.lock().unwrap(),
            vec![
                "g Tap [PixelPoint { x: 0, y: 2399, dt_ms: 0 }, PixelPoint { x: 1079, y: 0, dt_ms: 16 }]",
                "t Down 540 0",
                "s 1079 2399 -540 240",
                "a Home",
                "x hé",
                "k Enter",
            ]
        );
    }

    #[test]
    fn coordinates_need_config() {
        let r = Rec::default();
        let tl = Message::TouchLive(TouchLive {
            phase: TouchPhase::Up,
            x: 1,
            y: 1,
        });
        assert!(!dispatch_control(&tl, None, &r));
        let empty = Message::TouchGesture(TouchGesture {
            kind: GestureKind::Path,
            points: vec![],
        });
        assert!(!dispatch_control(&empty, None, &r));
        assert!(!dispatch_control(&Message::RequestKeyframe, None, &r));
        assert!(!is_control(&Message::Ping([0; 8])));
        // Non-coordinate controls work without a config.
        assert!(dispatch_control(&Message::Key(Key::Tab), None, &r));
        assert_eq!(*r.0.lock().unwrap(), vec!["k Tab"]);
    }
}
