//! `nativeCreate` configuration JSON → [`ServerConfig`].

use std::path::PathBuf;

use mirror_protocol::DEFAULT_PORT;
use mirror_sender::ServerConfig;
use serde::Deserialize;

/// Host configuration passed from Kotlin as JSON, e.g.
/// `{"deviceName":"Pixel 7","deviceId":"…","model":"Pixel 7","sdkInt":35,
/// "filesDir":"/data/user/0/…/files","debug":true}`. Unknown keys are ignored.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostConfig {
    pub device_name: String,
    pub device_id: String,
    pub model: String,
    pub sdk_int: u32,
    #[serde(default = "default_port")]
    pub port: u16,
    /// `Context.filesDir`; the pairing store lives at `<filesDir>/pairings.json`.
    /// Required (an empty or missing value is rejected by [`HostConfig::parse`]).
    #[serde(default)]
    pub files_dir: String,
    /// `BuildConfig.DEBUG`. Debug builds accept loopback peers (adb-forwarded
    /// test connections arrive from 127.0.0.1). It no longer affects
    /// authentication: AUTH mode `none` is never accepted by the app.
    #[serde(default)]
    pub debug: bool,
}

/// File name of the pairing store inside `filesDir`.
pub const PAIRING_STORE_FILE: &str = "pairings.json";

/// `<filesDir>/pairings.json`, the one place the store path is derived.
pub fn pairing_store_path(files_dir: &str) -> PathBuf {
    PathBuf::from(files_dir).join(PAIRING_STORE_FILE)
}

fn default_port() -> u16 {
    DEFAULT_PORT
}

impl HostConfig {
    pub fn parse(json: &str) -> Result<Self, String> {
        let c: HostConfig =
            serde_json::from_str(json).map_err(|e| format!("bad config JSON: {e}"))?;
        if c.device_id.trim().is_empty() {
            return Err("deviceId must not be empty".into());
        }
        if c.files_dir.trim().is_empty() {
            return Err("filesDir must not be empty".into());
        }
        Ok(c)
    }

    /// `<filesDir>/pairings.json`.
    pub fn pairing_store(&self) -> PathBuf {
        pairing_store_path(&self.files_dir)
    }

    /// Server configuration. AUTH mode `none` is never allowed (debug or
    /// release): every session pairs with the PIN or a stored key, so control
    /// input is always authenticated. Release builds never allow loopback
    /// peers: any app on the phone could otherwise connect to 127.0.0.1.
    pub fn server_config(&self) -> ServerConfig {
        let name = if self.device_name.trim().is_empty() {
            &self.model
        } else {
            &self.device_name
        };
        let mut c = ServerConfig::new(
            name.clone(),
            self.device_id.clone(),
            self.model.clone(),
            self.sdk_int,
        );
        c.port = self.port;
        c.allow_no_auth = false;
        c.allow_loopback = self.debug;
        c.pairing_store = Some(self.pairing_store());
        c
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_defaults() {
        let c = HostConfig::parse(
            r#"{"deviceName":"Pixel","deviceId":"abc","model":"Pixel 7","sdkInt":35,"filesDir":"/x"}"#,
        )
        .unwrap();
        assert_eq!(c.port, 47800);
        assert!(!c.debug);
        let s = c.server_config();
        assert_eq!(s.port, 47800);
        assert!(!s.allow_no_auth);
        assert!(!s.allow_loopback);
        assert_eq!(s.device_name, "Pixel");
        assert_eq!(s.sdk_int, 35);
        assert_eq!(s.pairing_store, Some(PathBuf::from("/x/pairings.json")));
    }

    #[test]
    fn debug_enables_loopback_but_never_no_auth() {
        let c = HostConfig::parse(
            r#"{"deviceName":"","deviceId":"abc","model":"Pixel 7","sdkInt":35,"port":0,"debug":true,"filesDir":"/data/user/0/app/files/"}"#,
        )
        .unwrap();
        let s = c.server_config();
        assert!(s.allow_loopback);
        assert!(!s.allow_no_auth);
        assert_eq!(
            s.pairing_store,
            Some(PathBuf::from("/data/user/0/app/files/pairings.json"))
        );
        assert_eq!(s.port, 0);
        assert_eq!(s.device_name, "Pixel 7");
    }

    #[test]
    fn requires_files_dir() {
        let base = r#""deviceName":"a","deviceId":"d","model":"m","sdkInt":1"#;
        let missing = HostConfig::parse(&format!("{{{base}}}")).unwrap_err();
        assert!(missing.contains("filesDir"), "{missing}");
        assert!(HostConfig::parse(&format!(r#"{{{base},"filesDir":""}}"#)).is_err());
        assert!(HostConfig::parse(&format!(r#"{{{base},"filesDir":"  "}}"#)).is_err());
        assert!(HostConfig::parse(&format!(r#"{{{base},"filesDir":null}}"#)).is_err());
        assert!(HostConfig::parse(&format!(r#"{{{base},"filesDir":"/f"}}"#)).is_ok());
    }

    #[test]
    fn rejects_bad_input() {
        assert!(HostConfig::parse("{").is_err());
        assert!(HostConfig::parse(r#"{"deviceName":"a","model":"m","sdkInt":1}"#).is_err());
        assert!(
            HostConfig::parse(r#"{"deviceName":"a","deviceId":" ","model":"m","sdkInt":1}"#)
                .is_err()
        );
    }
}
