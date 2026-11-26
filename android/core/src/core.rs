//! The object behind a `NativeCore` handle: server + encoder + callbacks.

use std::sync::{Arc, Mutex};

use mirror_protocol::{ByeReason, StatusState};
use mirror_sender::{PairedClient, Server};
use zeroize::Zeroizing;

use crate::callbacks::{Callbacks, Control, Events};
use crate::config::HostConfig;
use crate::display::DisplayInfo;
use crate::encoder::Encoder;

pub struct Core {
    server: Arc<Server>,
    encoder: Arc<Encoder>,
    /// Last display passed to `set_display` (to decide on STATUS reconfiguring).
    display: Mutex<Option<DisplayInfo>>,
}

impl Core {
    /// Start the encoder thread and the listener.
    pub fn create(cfg: &HostConfig, cb: Arc<Callbacks>) -> Result<Core, String> {
        let encoder =
            Arc::new(Encoder::new(cb.clone()).map_err(|e| format!("spawn encoder thread: {e}"))?);
        let server_cfg = cfg.server_config();
        log::info!(
            "starting server: port {}, debug {} (no-auth {}, loopback {})",
            server_cfg.port,
            cfg.debug,
            server_cfg.allow_no_auth,
            server_cfg.allow_loopback
        );
        let server = Arc::new(
            Server::start(
                server_cfg,
                encoder.clone(),
                Arc::new(Events(cb.clone())),
                Arc::new(Control(cb.clone())),
            )
            .map_err(|e| format!("listen: {e}"))?,
        );
        // No `onPinChanged` for the first PIN: Kotlin reads it with
        // `nativeGetPin` after `nativeCreate`. An upcall here would run on the
        // caller's thread, and could land after (and undo) a rotation the
        // server already reported from its own thread.
        Ok(Core {
            server,
            encoder,
            display: Mutex::new(None),
        })
    }

    pub fn port(&self) -> u16 {
        self.server.port()
    }

    pub fn set_display(&self, d: DisplayInfo) {
        let prev = {
            let mut g = self.display.lock().unwrap_or_else(|e| e.into_inner());
            g.replace(d)
        };
        let geometry_changed = prev
            .is_some_and(|p| (p.width, p.height, p.rotation) != (d.width, d.height, d.rotation));
        if geometry_changed {
            self.server.send_status(StatusState::Reconfiguring);
        }
        self.encoder.set_display(d);
    }

    pub fn set_screen_state(&self, on: bool) {
        self.server.send_status(if on {
            StatusState::ScreenOn
        } else {
            StatusState::ScreenOff
        });
    }

    /// The phone's address changed: drop the client's connection without a
    /// BYE (which would tell the receiver to stop) so it reconnects.
    pub fn network_changed(&self) {
        if self.server.drop_client() {
            log::info!("network changed; client dropped");
        }
    }

    /// The system ended the MediaProjection ("Stop sharing", lock screen):
    /// BYE `projection_revoked` to the client. Call before `shutdown`, whose
    /// own BYE `stopped_by_user` is then not sent.
    pub fn projection_revoked(&self) {
        if self.server.disconnect(ByeReason::ProjectionRevoked) {
            log::info!("projection revoked; client told");
        }
    }

    /// Current pairing PIN (wiped when dropped).
    pub fn pin(&self) -> Zeroizing<String> {
        self.server.pin()
    }

    /// "New PIN": rotate the PIN and clear the PIN lockout; returns the new
    /// PIN (no `onPinChanged` upcall for it).
    pub fn new_pin(&self) -> Zeroizing<String> {
        self.server.new_pin()
    }

    /// How many times [`new_pin`](Self::new_pin) has run (only grows).
    pub fn pin_resets(&self) -> u64 {
        self.server.pin_resets()
    }

    /// Accessibility service on/off: control input is forwarded only when on.
    pub fn set_control_available(&self, available: bool) {
        self.server.set_control_available(available);
    }

    /// Paired receivers; `Err` if the pairing store could not be loaded.
    pub fn list_paired(&self) -> Result<Vec<PairedClient>, String> {
        self.server.try_list_paired()
    }

    /// Forget a paired client (disconnecting it if connected).
    pub fn revoke(&self, client_id: &str) -> bool {
        self.server.revoke(client_id)
    }

    /// BYE to the client, join all server threads, release the codec.
    pub fn shutdown(&self) {
        self.server.stop();
        self.encoder.shutdown();
    }
}
