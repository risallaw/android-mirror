//! Integer codes for `CoreCallbacks.onClientState` (mirrored as constants in
//! Kotlin `CoreCallbacks`) and the pairing payloads (`nativeListPaired` JSON,
//! `onPairingFailed` arguments, "New PIN" counts). Pure so it is tested on the host.

use std::net::SocketAddr;
use std::time::Duration;

use mirror_sender::{ClientState, DisconnectReason, PairedClient};
use serde::Serialize;

pub const STATE_CONNECTING: i32 = 0;
pub const STATE_STREAMING: i32 = 1;
pub const STATE_DISCONNECTED: i32 = 2;

pub const REASON_NONE: i32 = 0;
pub const REASON_CLIENT_BYE: i32 = 1;
pub const REASON_REPLACED: i32 = 2;
pub const REASON_TIMEOUT: i32 = 3;
pub const REASON_CLOSED: i32 = 4;
pub const REASON_PROTOCOL_ERROR: i32 = 5;
pub const REASON_SERVER: i32 = 6;
pub const REASON_SOURCE_FAILED: i32 = 7;

/// `(state, reason)` codes for a client state change.
pub fn state_codes(state: ClientState) -> (i32, i32) {
    match state {
        ClientState::Connecting => (STATE_CONNECTING, REASON_NONE),
        ClientState::Streaming => (STATE_STREAMING, REASON_NONE),
        ClientState::Disconnected(r) => (
            STATE_DISCONNECTED,
            match r {
                DisconnectReason::ClientBye => REASON_CLIENT_BYE,
                DisconnectReason::Replaced => REASON_REPLACED,
                DisconnectReason::Timeout => REASON_TIMEOUT,
                DisconnectReason::Closed => REASON_CLOSED,
                DisconnectReason::ProtocolError => REASON_PROTOCOL_ERROR,
                DisconnectReason::Server => REASON_SERVER,
                DisconnectReason::SourceFailed => REASON_SOURCE_FAILED,
            },
        ),
    }
}

/// Peer address for display: IPv4-mapped IPv6 (dual-stack listener) shown
/// as plain IPv4.
pub fn peer_string(peer: &SocketAddr) -> String {
    SocketAddr::new(peer.ip().to_canonical(), peer.port()).to_string()
}

/// One element of the `nativeListPaired` JSON array.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PairedJson<'a> {
    client_id: &'a str,
    client_name: &'a str,
    paired_at_ms: u64,
}

/// `nativeListPaired` result: `[{"clientId":"…","clientName":"…","pairedAtMs":123}]`.
pub fn paired_json(list: &[PairedClient]) -> String {
    let items: Vec<PairedJson> = list
        .iter()
        .map(|p| PairedJson {
            client_id: &p.client_id,
            client_name: &p.client_name,
            paired_at_ms: p.paired_at_ms,
        })
        .collect();
    // Serialising plain strings and integers cannot fail.
    serde_json::to_string(&items).unwrap_or_else(|_| "[]".into())
}

/// `onPairingFailed` `(attemptsLeft, lockedForMs)`: saturating conversions;
/// `lockedForMs` is 0 when not locked out and at least 1 when locked out.
pub fn pairing_failed_args(attempts_left: u32, locked_for: Option<Duration>) -> (i32, i64) {
    let attempts = i32::try_from(attempts_left).unwrap_or(i32::MAX);
    let locked_ms = locked_for.map_or(0, |d| {
        i64::try_from(d.as_millis()).unwrap_or(i64::MAX).max(1)
    });
    (attempts, locked_ms)
}

/// A "New PIN" count (`onPairingFailed` `resets`, `nativePinResets`) as a
/// Java long. Saturating keeps the order Kotlin compares by (it never gets
/// near `i64::MAX` anyway).
pub fn pin_resets_arg(resets: u64) -> i64 {
    i64::try_from(resets).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paired_json_shape() {
        assert_eq!(paired_json(&[]), "[]");
        let list = vec![
            PairedClient {
                client_id: "mac-1".into(),
                client_name: "Ada's \"MacBook\"".into(),
                paired_at_ms: 1_700_000_000_123,
            },
            PairedClient {
                client_id: "mac-2".into(),
                client_name: String::new(),
                paired_at_ms: 0,
            },
        ];
        let json = paired_json(&list);
        assert_eq!(
            json,
            r#"[{"clientId":"mac-1","clientName":"Ada's \"MacBook\"","pairedAtMs":1700000000123},{"clientId":"mac-2","clientName":"","pairedAtMs":0}]"#
        );
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v[0]["clientName"], "Ada's \"MacBook\"");
    }

    #[test]
    fn pairing_failed_conversions() {
        assert_eq!(pairing_failed_args(4, None), (4, 0));
        assert_eq!(
            pairing_failed_args(0, Some(Duration::from_secs(30))),
            (0, 30_000)
        );
        assert_eq!(
            pairing_failed_args(0, Some(Duration::from_micros(10))),
            (0, 1)
        );
        assert_eq!(
            pairing_failed_args(u32::MAX, Some(Duration::MAX)),
            (i32::MAX, i64::MAX)
        );
    }

    #[test]
    fn pin_resets_conversion() {
        assert_eq!(pin_resets_arg(0), 0);
        assert_eq!(pin_resets_arg(7), 7);
        assert_eq!(pin_resets_arg(u64::MAX), i64::MAX);
    }

    #[test]
    fn codes() {
        assert_eq!(state_codes(ClientState::Connecting), (0, 0));
        assert_eq!(state_codes(ClientState::Streaming), (1, 0));
        assert_eq!(
            state_codes(ClientState::Disconnected(DisconnectReason::Replaced)),
            (2, 2)
        );
        assert_eq!(
            state_codes(ClientState::Disconnected(DisconnectReason::SourceFailed)),
            (2, 7)
        );
    }

    #[test]
    fn peer_is_canonical() {
        let p: SocketAddr = "[::ffff:192.168.1.5]:5000".parse().unwrap();
        assert_eq!(peer_string(&p), "192.168.1.5:5000");
        let p: SocketAddr = "[fe80::1]:5000".parse().unwrap();
        assert_eq!(peer_string(&p), "[fe80::1]:5000");
    }
}
