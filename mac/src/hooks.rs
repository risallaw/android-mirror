//! macOS `PlatformHooks`: AppKit window sizing via `objc2-app-kit`.
//!
//! When a stream starts (or rotates) the window's content aspect ratio is
//! locked to the video, and the window is resized to the video's aspect,
//! keeping its long edge, clamped to 85% of the screen's visible height
//! (top-left corner kept, frame kept on screen). Back on home the lock is
//! released.

use mirror_receiver::state::window_size_for_video;
use mirror_receiver::{PlatformHooks, UserEvent};
use objc2::rc::Retained;
use objc2::MainThreadMarker;
use objc2_app_kit::{NSPasteboard, NSPasteboardTypeString, NSView, NSWindow, NSWorkspace};
use objc2_foundation::{NSPoint, NSRect, NSSize};
use raw_window_handle::{HasWindowHandle, RawWindowHandle};
use winit::event_loop::EventLoopBuilder;
use winit::platform::macos::EventLoopBuilderExtMacOS;
use winit::window::Window;

/// Largest share of the screen's visible height the content may take.
const MAX_HEIGHT_FRACTION: f64 = 0.85;
/// Largest share of the visible width.
const MAX_WIDTH_FRACTION: f64 = 0.95;

pub struct MacHooks;

/// The `NSWindow` behind a winit window, if it is an AppKit window.
fn ns_window(window: &Window) -> Option<Retained<NSWindow>> {
    // AppKit objects may only be touched on the main thread. Hooks are
    // called from winit's event loop (main thread); refuse anything else.
    MainThreadMarker::new()?;
    let handle = window.window_handle().ok()?;
    let RawWindowHandle::AppKit(h) = handle.as_raw() else {
        return None;
    };
    // SAFETY: winit guarantees `ns_view` is a valid NSView for as long as
    // the window (borrowed for this call) lives, and we checked above that
    // we are on the main thread. We only borrow it to ask for its
    // (retained) window.
    let view: &NSView = unsafe { h.ns_view.cast().as_ref() };
    view.window()
}

/// The general pasteboard's plain-text contents, if any. Main thread only
/// (returns `None` elsewhere).
fn clipboard_text() -> Option<String> {
    MainThreadMarker::new()?;
    // SAFETY: `NSPasteboardTypeString` is a valid constant NSString once
    // AppKit is loaded, and we are on the main thread.
    let ty = unsafe { NSPasteboardTypeString };
    NSPasteboard::generalPasteboard()
        .stringForType(ty)
        .map(|s| s.to_string())
}

impl PlatformHooks for MacHooks {
    fn configure_event_loop(&self, builder: &mut EventLoopBuilder<UserEvent>) {
        // winit's default menu has "Hide ⌘H", which would swallow ⌘H (Home
        // on the phone); `on_window_created` installs our own instead.
        builder.with_default_menu(false);
    }

    fn on_window_created(&self, _window: &Window) {
        // The app has finished launching by now (winit creates windows
        // from `resumed`), so this menu is not overwritten.
        crate::menu::install();
    }

    fn on_video_size(&self, window: &Window, width: u32, height: u32) {
        let Some(ns) = ns_window(window) else { return };
        if width == 0 || height == 0 {
            return;
        }
        ns.setContentAspectRatio(NSSize::new(f64::from(width), f64::from(height)));

        let frame = ns.frame();
        let content = ns.contentRectForFrameRect(frame);
        let visible = ns.screen().map(|s| s.visibleFrame());
        let max = visible.map_or((f64::MAX, f64::MAX), |v| {
            (
                v.size.width * MAX_WIDTH_FRACTION,
                v.size.height * MAX_HEIGHT_FRACTION,
            )
        });
        let (w, h) = window_size_for_video(
            (content.size.width, content.size.height),
            (width, height),
            max,
        );
        let mut new =
            ns.frameRectForContentRect(NSRect::new(NSPoint::new(0.0, 0.0), NSSize::new(w, h)));
        // Keep the top-left corner (AppKit's origin is bottom-left).
        new.origin.x = frame.origin.x;
        new.origin.y = frame.origin.y + frame.size.height - new.size.height;
        if let Some(v) = visible {
            let max_x = v.origin.x + v.size.width - new.size.width;
            let max_y = v.origin.y + v.size.height - new.size.height;
            new.origin.x = new.origin.x.min(max_x).max(v.origin.x);
            new.origin.y = new.origin.y.min(max_y).max(v.origin.y);
        }
        ns.setFrame_display(new, true);
    }

    fn clipboard_text(&self) -> Option<String> {
        clipboard_text()
    }

    fn screen_reader_on(&self) -> bool {
        // Not "an accessibility client asked for the tree": scripts and
        // Accessibility Inspector do that too, and never say they stopped.
        NSWorkspace::sharedWorkspace().isVoiceOverEnabled()
    }

    fn on_video_cleared(&self, window: &Window) {
        let Some(ns) = ns_window(window) else { return };
        // Setting resize increments clears the aspect-ratio constraint.
        ns.setContentResizeIncrements(NSSize::new(1.0, 1.0));
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn clipboard_is_none_off_main_thread() {
        // Test threads are not the main thread; AppKit must not be touched.
        assert_eq!(super::clipboard_text(), None);
    }
}
