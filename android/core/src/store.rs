//! Pairing-store access while mirroring is not running
//! (`nativeListPairedIn` / `nativeRevokeIn`), so a lost or compromised
//! receiver can be reviewed and revoked without starting the listener it
//! could connect to. File handling is `mirror_sender`'s (same atomic write,
//! fsync, 0600 and never-overwrite-an-unreadable-store rules as the server).
//! Every `Err` here is already logged (by `mirror_sender` or below), so
//! callers must not log it again. Pure so it is tested on the host.

use std::path::PathBuf;

use crate::config::pairing_store_path;
use crate::events::paired_json;

fn store_in(files_dir: &str) -> Result<PathBuf, String> {
    // An empty filesDir would resolve against the process cwd.
    if files_dir.trim().is_empty() {
        let e = "filesDir must not be empty";
        log::error!("pairing store: {e}");
        return Err(e.into());
    }
    Ok(pairing_store_path(files_dir))
}

/// `nativeListPairedIn` result: the `nativeListPaired` JSON array for the
/// store in `files_dir`.
pub fn list_json_in(files_dir: &str) -> Result<String, String> {
    mirror_sender::list_paired_at(&store_in(files_dir)?).map(|l| paired_json(&l))
}

/// `nativeRevokeIn`: true only if `client_id` was paired and its removal is
/// persisted.
pub fn revoke_in(files_dir: &str, client_id: &str) -> Result<bool, String> {
    mirror_sender::revoke_at(&store_in(files_dir)?, client_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    struct Dir(PathBuf);
    impl Dir {
        fn new(tag: &str) -> Dir {
            let p = std::env::temp_dir()
                .join(format!("mirror-core-store-{tag}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&p);
            fs::create_dir_all(&p).unwrap();
            Dir(p)
        }
        fn s(&self) -> &str {
            self.0.to_str().unwrap()
        }
    }
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// A store as the server writes it (version 1, hex keys).
    fn write_store(d: &Dir, ids: &[&str]) {
        let entries: Vec<String> = ids
            .iter()
            .enumerate()
            .map(|(i, id)| {
                format!(
                    r#"{{"clientId":"{id}","clientName":"N {id}","key":"{}","pairedAtMs":{i}}}"#,
                    "ab".repeat(32)
                )
            })
            .collect();
        fs::write(
            d.0.join("pairings.json"),
            format!(r#"{{"version":1,"pairings":[{}]}}"#, entries.join(",")),
        )
        .unwrap();
    }

    #[test]
    fn lists_and_revokes_in_files_dir() {
        let d = Dir::new("ok");
        assert_eq!(list_json_in(d.s()).unwrap(), "[]", "no store yet");
        assert_eq!(revoke_in(d.s(), "a"), Ok(false));
        write_store(&d, &["a", "b"]);
        assert_eq!(
            list_json_in(d.s()).unwrap(),
            r#"[{"clientId":"a","clientName":"N a","pairedAtMs":0},{"clientId":"b","clientName":"N b","pairedAtMs":1}]"#
        );
        assert_eq!(revoke_in(d.s(), "a"), Ok(true));
        assert_eq!(revoke_in(d.s(), "a"), Ok(false));
        assert_eq!(
            list_json_in(d.s()).unwrap(),
            r#"[{"clientId":"b","clientName":"N b","pairedAtMs":1}]"#
        );
        // The key itself never appears in the listing.
        assert!(!list_json_in(d.s()).unwrap().contains("abab"));
    }

    #[test]
    fn rejects_empty_files_dir() {
        for dir in ["", "  "] {
            assert!(list_json_in(dir).is_err());
            assert!(revoke_in(dir, "a").is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn unreadable_store_is_an_error_and_untouched() {
        use std::os::unix::fs::PermissionsExt;
        let d = Dir::new("unreadable");
        write_store(&d, &["a"]);
        let p = d.0.join("pairings.json");
        let original = fs::read(&p).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o000)).unwrap();
        if fs::read(&p).is_ok() {
            return; // root
        }
        assert!(list_json_in(d.s()).is_err());
        assert!(revoke_in(d.s(), "a").is_err());
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(fs::read(&p).unwrap(), original);
    }
}
