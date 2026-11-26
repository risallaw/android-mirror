//! The app menu, installed instead of winit's default one.
//!
//! winit's default app menu has "Hide ⌘H", which AppKit matches as a key
//! equivalent before the window ever sees the key, so ⌘H could never reach
//! the phone (it is Home there). This menu keeps only items whose shortcuts
//! the phone does not use: About, Hide Others (⌥⌘H), Show All and Quit
//! (⌘Q), and a Window menu with Minimize (⌘M) and Close Window (⌘W), the
//! standard macOS window shortcuts (closing the only window ends the app,
//! after saying BYE to the phone). No ⌘H / ⌘B / ⌘R / ⌘N / ⌘V, and no Edit
//! menu (⌘V pastes to the phone).

use objc2::rc::Retained;
use objc2::runtime::Sel;
use objc2::{sel, MainThreadMarker};
use objc2_app_kit::{NSApplication, NSEventModifierFlags, NSMenu, NSMenuItem};
use objc2_foundation::{ns_string, NSString};

/// Key equivalents the menu claims (key, needs ⌥ besides ⌘). The phone
/// shortcuts must never appear here.
pub const SHORTCUTS: &[(&str, bool)] = &[("h", true), ("q", false), ("m", false), ("w", false)];

/// The app's name in the menu, as Finder shows it: `CFBundleName` in
/// `bundle/Info.plist` (the process name is the executable, "AndroidMirror").
pub const APP_NAME: &str = "Android Mirror";

/// Install the menu bar. Main thread only (no-op elsewhere).
pub fn install() {
    let Some(mtm) = MainThreadMarker::new() else {
        return;
    };
    let app = NSApplication::sharedApplication(mtm);
    let name = NSString::from_str(APP_NAME);

    let app_menu = NSMenu::new(mtm);
    let about = ns_string!("About ").stringByAppendingString(&name);
    app_menu.addItem(&item(
        mtm,
        &about,
        sel!(orderFrontStandardAboutPanel:),
        None,
    ));
    app_menu.addItem(&NSMenuItem::separatorItem(mtm));
    app_menu.addItem(&item(
        mtm,
        ns_string!("Hide Others"),
        sel!(hideOtherApplications:),
        Some(SHORTCUTS[0]),
    ));
    app_menu.addItem(&item(
        mtm,
        ns_string!("Show All"),
        sel!(unhideAllApplications:),
        None,
    ));
    app_menu.addItem(&NSMenuItem::separatorItem(mtm));
    let quit = ns_string!("Quit ").stringByAppendingString(&name);
    app_menu.addItem(&item(mtm, &quit, sel!(terminate:), Some(SHORTCUTS[1])));

    // AppKit sends these along the responder chain to the key window, whose
    // delegate (winit) turns Close into a close request.
    let window_menu = NSMenu::initWithTitle(mtm.alloc(), ns_string!("Window"));
    window_menu.addItem(&item(
        mtm,
        ns_string!("Minimize"),
        sel!(performMiniaturize:),
        Some(SHORTCUTS[2]),
    ));
    window_menu.addItem(&item(
        mtm,
        ns_string!("Close Window"),
        sel!(performClose:),
        Some(SHORTCUTS[3]),
    ));

    let app_item = NSMenuItem::new(mtm);
    app_item.setSubmenu(Some(&app_menu));
    let window_item = NSMenuItem::new(mtm);
    window_item.setSubmenu(Some(&window_menu));
    let menubar = NSMenu::new(mtm);
    menubar.addItem(&app_item);
    menubar.addItem(&window_item);
    app.setMainMenu(Some(&menubar));
    app.setWindowsMenu(Some(&window_menu));
}

fn item(
    mtm: MainThreadMarker,
    title: &NSString,
    action: Sel,
    shortcut: Option<(&str, bool)>,
) -> Retained<NSMenuItem> {
    let key = NSString::from_str(shortcut.map_or("", |(k, _)| k));
    // SAFETY: `action` is a standard NSApplication / NSWindow action selector;
    // the item's target is nil, so AppKit sends it along the responder chain
    // (key window, then NSApp), and the item disables itself if nothing
    // there implements it.
    let item = unsafe {
        NSMenuItem::initWithTitle_action_keyEquivalent(mtm.alloc(), title, Some(action), &key)
    };
    if let Some((_, true)) = shortcut {
        item.setKeyEquivalentModifierMask(
            NSEventModifierFlags::Command | NSEventModifierFlags::Option,
        );
    }
    item
}

#[cfg(test)]
mod tests {
    use super::{APP_NAME, SHORTCUTS};

    #[test]
    fn menu_names_the_app_as_its_bundle_does() {
        let plist = include_str!("../bundle/Info.plist");
        let want = format!("<key>CFBundleName</key>\n\t<string>{APP_NAME}</string>");
        assert!(
            plist.contains(&want),
            "Info.plist CFBundleName != {APP_NAME}"
        );
    }

    #[test]
    fn menu_leaves_phone_shortcuts_alone() {
        // ⌘B/⌘H/⌘R/⌘N/⌘V go to the phone; the menu may only claim ⌘Q and
        // shortcuts that need another modifier.
        for (key, extra_mod) in SHORTCUTS {
            assert!(
                *extra_mod || !["b", "h", "r", "v", "n"].contains(key),
                "menu claims ⌘{key}"
            );
        }
        assert!(SHORTCUTS.contains(&("q", false)), "⌘Q still quits");
        assert!(SHORTCUTS.contains(&("m", false)), "⌘M minimises");
        assert!(SHORTCUTS.contains(&("w", false)), "⌘W closes the window");
    }

    #[test]
    fn install_is_a_no_op_off_main_thread() {
        super::install(); // test threads are not the main thread
    }
}
