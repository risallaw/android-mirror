//! Server configuration.

use std::fmt;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use mirror_protocol::DEFAULT_PORT;
use zeroize::Zeroize;

/// Upper bound for every duration in [`ServerConfig`] (one day): longer
/// values are clamped, so deadlines computed from them cannot overflow.
pub(crate) const MAX_DURATION: Duration = Duration::from_secs(24 * 60 * 60);

/// Upper bound for [`ServerConfig::max_pending_handshakes`]: choosing the
/// eviction victim is quadratic in the pending set, under its lock on the
/// accept thread.
pub const MAX_PENDING_HANDSHAKES: usize = 64;

/// Configuration for [`Server::start`](crate::Server::start).
///
/// Build with [`ServerConfig::new`] and override fields as needed; the
/// timing fields exist mainly so tests can use short values.
///
/// `Debug` redacts `fixed_pin`, and it is zeroized on drop.
#[derive(Clone)]
pub struct ServerConfig {
    /// SERVER_HELLO `deviceName` (user-visible, e.g. "Pixel 8").
    pub device_name: String,
    /// SERVER_HELLO `deviceId` (stable per install; enters the auth MAC).
    pub device_id: String,
    /// SERVER_HELLO `model` (`Build.MODEL`).
    pub model: String,
    /// SERVER_HELLO `sdkInt` (`Build.VERSION.SDK_INT`).
    pub sdk_int: u32,

    /// Preferred TCP port. Default [`DEFAULT_PORT`] (47800). If it is busy
    /// the server falls back to an ephemeral port; `0` asks for an ephemeral
    /// port directly. Read the result with [`Server::port`](crate::Server::port).
    pub port: u16,
    /// Address to listen on. `None` (default) = all interfaces, dual-stack
    /// IPv6 `[::]` when available, else `0.0.0.0`.
    pub bind_addr: Option<IpAddr>,

    /// Also offer and accept AUTH mode `none` (devtools/tests only; the
    /// Android app never enables it). Such sessions are encrypted but
    /// unauthenticated and never get control. Default `false`.
    pub allow_no_auth: bool,
    /// Pairing store file (`<filesDir>/pairings.json`): JSON, mode 0600,
    /// written atomically. `None` (default) keeps pairings in memory only.
    pub pairing_store: Option<PathBuf>,
    /// Devtools/tests only: use this 6-digit PIN and never rotate it (the
    /// lockout still applies). `None` (default) = random PIN, rotated after
    /// every pairing and every lockout. An invalid value is ignored.
    pub fixed_pin: Option<String>,
    /// Accept loopback peers (127.0.0.0/8, ::1) in addition to LAN peers.
    /// Default `true` (dev/tests). On a phone any local app can reach
    /// loopback, so a release build may want `false`.
    pub allow_loopback: bool,

    /// Time from accept until the handshake (including the PIN exchange)
    /// must be complete (default 5 s).
    pub handshake_timeout: Duration,
    /// Close an authenticated session after this long without receiving any
    /// byte (default 6 s; receivers PING every 2 s). Also used as the socket
    /// write timeout.
    pub liveness_timeout: Duration,
    /// Backpressure threshold: when the oldest queued video frame is older
    /// than this, queued video is dropped and a keyframe requested
    /// (default 250 ms).
    pub max_queue_age: Duration,
    /// Hard cap on queued video frames (default 120).
    pub max_queued_frames: usize,
    /// Hard cap on queued video bytes (default 16 MiB).
    pub max_queued_bytes: usize,
    /// Minimum interval between repeated keyframe requests while waiting for
    /// a keyframe (default 1 s).
    pub keyframe_retry: Duration,
    /// `SO_SNDBUF` for client sockets (default 256 KiB).
    pub send_buffer_size: usize,
    /// Maximum concurrent connections still in the handshake (default 4).
    /// When a new connection would exceed it, the oldest pending handshake
    /// of the busiest peer (IPv6: the busiest /64, then its busiest
    /// address; see `max_pending_handshakes_per_ip`) is closed to make
    /// room, so one flooding host cannot lock out the others. Clamped to
    /// 1..=[`MAX_PENDING_HANDSHAKES`] (the victim choice is quadratic).
    pub max_pending_handshakes: usize,
    /// Maximum concurrent connections still in the handshake from one peer
    /// IP address (default 2). A new connection over it closes that IP's
    /// oldest pending handshake. (For the global cap's victim choice IPv6
    /// peers count per /64, so one host cycling through its subnet's
    /// addresses still ends up the busiest.) Together with
    /// `max_pending_handshakes` this guarantees a client on another IP a
    /// handshake slot while a single host floods (as long as
    /// `max_pending_handshakes_per_ip < max_pending_handshakes`); a client
    /// inside the flooder's IPv6 /64 is only spared from eviction while the
    /// flooder reuses addresses.
    pub max_pending_handshakes_per_ip: usize,
    /// How long [`Server::stop`](crate::Server::stop) waits for the final
    /// BYE to be written before force-closing sockets (default 500 ms).
    pub bye_linger: Duration,
    /// Back-off after a failed `accept`, and the poll interval should the
    /// listener have to be polled (normally `accept` blocks and
    /// [`Server::stop`](crate::Server::stop) wakes it) (default 100 ms).
    ///
    /// Every duration above is clamped to one day.
    pub accept_poll_interval: Duration,
}

impl fmt::Debug for ServerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerConfig")
            .field("device_name", &self.device_name)
            .field("device_id", &self.device_id)
            .field("model", &self.model)
            .field("sdk_int", &self.sdk_int)
            .field("port", &self.port)
            .field("bind_addr", &self.bind_addr)
            .field("allow_no_auth", &self.allow_no_auth)
            .field("pairing_store", &self.pairing_store)
            .field("fixed_pin", &self.fixed_pin.as_ref().map(|_| "<redacted>"))
            .field("allow_loopback", &self.allow_loopback)
            .field("handshake_timeout", &self.handshake_timeout)
            .field("liveness_timeout", &self.liveness_timeout)
            .field("max_queue_age", &self.max_queue_age)
            .field("max_queued_frames", &self.max_queued_frames)
            .field("max_queued_bytes", &self.max_queued_bytes)
            .field("keyframe_retry", &self.keyframe_retry)
            .field("send_buffer_size", &self.send_buffer_size)
            .field("max_pending_handshakes", &self.max_pending_handshakes)
            .field(
                "max_pending_handshakes_per_ip",
                &self.max_pending_handshakes_per_ip,
            )
            .field("bye_linger", &self.bye_linger)
            .field("accept_poll_interval", &self.accept_poll_interval)
            .finish()
    }
}

impl Drop for ServerConfig {
    fn drop(&mut self) {
        self.fixed_pin.zeroize();
    }
}

impl ServerConfig {
    /// Config with the given device identity and all defaults.
    pub fn new(
        device_name: impl Into<String>,
        device_id: impl Into<String>,
        model: impl Into<String>,
        sdk_int: u32,
    ) -> Self {
        ServerConfig {
            device_name: device_name.into(),
            device_id: device_id.into(),
            model: model.into(),
            sdk_int,
            port: DEFAULT_PORT,
            bind_addr: None,
            allow_no_auth: false,
            pairing_store: None,
            fixed_pin: None,
            allow_loopback: true,
            handshake_timeout: Duration::from_secs(5),
            liveness_timeout: Duration::from_secs(6),
            max_queue_age: Duration::from_millis(250),
            max_queued_frames: 120,
            max_queued_bytes: 16 * 1024 * 1024,
            keyframe_retry: Duration::from_secs(1),
            send_buffer_size: 256 * 1024,
            max_pending_handshakes: 4,
            max_pending_handshakes_per_ip: 2,
            bye_linger: Duration::from_millis(500),
            accept_poll_interval: Duration::from_millis(100),
        }
    }

    /// Replace zero durations/limits (which would disable timeouts or make
    /// `set_read_timeout` fail) with the smallest sane values, and clamp
    /// durations to [`MAX_DURATION`] (`Instant + Duration::MAX` panics).
    pub(crate) fn sanitized(mut self) -> Self {
        let min = Duration::from_millis(1);
        for d in [
            &mut self.handshake_timeout,
            &mut self.liveness_timeout,
            &mut self.max_queue_age,
            &mut self.accept_poll_interval,
        ] {
            if *d < min {
                *d = min;
            }
        }
        for d in [
            &mut self.handshake_timeout,
            &mut self.liveness_timeout,
            &mut self.max_queue_age,
            &mut self.keyframe_retry,
            &mut self.bye_linger,
            &mut self.accept_poll_interval,
        ] {
            *d = (*d).min(MAX_DURATION);
        }
        self.max_queued_frames = self.max_queued_frames.max(1);
        self.max_pending_handshakes = self.max_pending_handshakes.clamp(1, MAX_PENDING_HANDSHAKES);
        self.max_pending_handshakes_per_ip = self.max_pending_handshakes_per_ip.max(1);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts_the_fixed_pin() {
        let mut c = ServerConfig::new("d", "i", "m", 1);
        c.fixed_pin = Some("482913".into());
        let dbg = format!("{c:?}");
        assert!(
            !dbg.contains("482913") && dbg.contains("<redacted>"),
            "{dbg}"
        );
        assert!(dbg.contains("handshake_timeout"));
    }

    #[test]
    fn durations_are_clamped() {
        let mut c = ServerConfig::new("d", "i", "m", 1);
        c.handshake_timeout = Duration::MAX;
        c.bye_linger = Duration::MAX;
        c.keyframe_retry = Duration::ZERO;
        let c = c.sanitized();
        assert_eq!(c.handshake_timeout, MAX_DURATION);
        assert_eq!(c.bye_linger, MAX_DURATION);
        assert_eq!(c.keyframe_retry, Duration::ZERO);
    }

    #[test]
    fn pending_handshake_cap_is_bounded() {
        let mut c = ServerConfig::new("d", "i", "m", 1);
        c.max_pending_handshakes = 100_000;
        assert_eq!(c.sanitized().max_pending_handshakes, MAX_PENDING_HANDSHAKES);
    }
}
