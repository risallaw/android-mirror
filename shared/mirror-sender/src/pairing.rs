//! Pairing state (PLAN / spec §6): the PIN shown on the phone (rotation,
//! attempt counting, lockout) and the store of paired receivers' keys.
//!
//! Pure state, no locking and no host callbacks: [`Shared`](crate::server)
//! wraps both in one mutex and reports changes after releasing it. Keys and
//! the PIN are secrets: nothing here logs them, and `Debug` impls redact them.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use mirror_protocol::auth::{generate_pin, PairingKey, PIN_DIGITS};
use mirror_protocol::rand_core::UnwrapErr;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use zeroize::Zeroizing;

use crate::server::lock;
use crate::throttle::short;

/// Failed PIN attempts that trigger a lockout and a new PIN.
pub const MAX_PIN_FAILURES: u32 = 5;
/// How long PIN authentication is refused after the first
/// [`MAX_PIN_FAILURES`]; each further consecutive lockout doubles it, up to
/// [`PIN_LOCKOUT_MAX`]. Only a successful pairing resets the escalation.
pub const PIN_LOCKOUT: Duration = Duration::from_secs(30);
/// Cap of the escalating PIN lockout.
pub const PIN_LOCKOUT_MAX: Duration = Duration::from_secs(60 * 60);
/// Minimum interval between `pairing_failed` reports of refused attempts
/// (lockout / in-flight cap), so a flood of refused connections cannot spam
/// the phone's UI.
pub(crate) const REFUSAL_EVENT_INTERVAL: Duration = Duration::from_secs(5);
/// Maximum stored pairings; pairing one more evicts the oldest.
pub const MAX_PAIRINGS: usize = 32;

/// A paired receiver, as listed by [`Server::list_paired`](crate::Server::list_paired).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairedClient {
    /// `clientId` from CLIENT_HELLO (the key of the pairing).
    pub client_id: String,
    /// `clientName` at pairing time.
    pub client_name: String,
    /// Wall-clock pairing time, ms since the Unix epoch.
    pub paired_at_ms: u64,
}

/// True for exactly [`PIN_DIGITS`] ASCII digits.
pub fn is_valid_pin(pin: &str) -> bool {
    pin.len() == PIN_DIGITS && pin.bytes().all(|b| b.is_ascii_digit())
}

fn random_pin() -> Zeroizing<String> {
    Zeroizing::new(generate_pin(&mut UnwrapErr(getrandom::SysRng)))
}

pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

// ---------------------------------------------------------------------------
// PIN
// ---------------------------------------------------------------------------

/// Outcome of [`PinState::admit`].
pub(crate) enum PinAdmission {
    /// Run SPAKE2 against this PIN (a snapshot). `gen` identifies it: if
    /// the PIN rotates while the attempt is in flight, the attempt must not
    /// succeed ([`PinState::is_current`]).
    Attempt { pin: Zeroizing<String>, gen: u64 },
    /// Refuse with `locked_out`; PIN attempts may be accepted again after
    /// `retry_after`. `notify`: report it to the host (only during a
    /// lockout, rate-limited to one per [`REFUSAL_EVENT_INTERVAL`]).
    Refused { retry_after: Duration, notify: bool },
}

/// Result of a failed attempt, for [`HostEvents::pairing_failed`](crate::HostEvents::pairing_failed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PinFailure {
    pub attempts_left: u32,
    /// `Some` while PIN attempts are refused (this failure started the
    /// lockout, or the attempt was admitted before it started).
    pub locked_for: Option<Duration>,
    /// This failure started the lockout and rotated the PIN (never with a
    /// fixed PIN, which does not rotate).
    pub rotated: bool,
}

/// The current PIN and the server-wide online-guessing limit.
///
/// An attempt is counted when AUTH `pin` *arrives* ([`admit`](Self::admit)),
/// so a client that guesses and then disconnects (never learning the result)
/// still burns one. Counted attempts include ones still in flight, which
/// also bounds parallel guessing over several connections.
///
/// The state lives in memory only: restarting mirroring (a new
/// [`Server`](crate::Server)) starts with a fresh PIN, no lockout and no
/// escalation, as does the host's "New PIN" ([`reset`](Self::reset)). Both
/// need someone at the phone, which a LAN attacker is not.
pub(crate) struct PinState {
    pin: Zeroizing<String>,
    /// Bumped on every rotation.
    gen: u64,
    /// Bumped on every [`reset`](Self::reset) ("New PIN").
    resets: u64,
    /// Devtools/tests: never rotate (the lockout still applies).
    fixed: bool,
    /// Attempts counted since the last success or lockout.
    attempts: u32,
    locked_until: Option<Instant>,
    /// Lockouts since the last successful pairing (escalation level).
    lockouts: u32,
    /// Last refusal reported to the host.
    last_refusal_event: Option<Instant>,
}

impl fmt::Debug for PinState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PinState")
            .field("pin", &"<redacted>")
            .field("fixed", &self.fixed)
            .field("attempts", &self.attempts)
            .field("locked_until", &self.locked_until)
            .field("lockouts", &self.lockouts)
            .finish()
    }
}

impl PinState {
    /// Random PIN, or `fixed` (must be valid) that never rotates.
    pub fn new(fixed: Option<&str>) -> Self {
        let fixed = fixed.filter(|p| is_valid_pin(p));
        PinState {
            pin: fixed.map_or_else(random_pin, |p| Zeroizing::new(p.to_owned())),
            gen: 0,
            resets: 0,
            fixed: fixed.is_some(),
            attempts: 0,
            locked_until: None,
            lockouts: 0,
            last_refusal_event: None,
        }
    }

    pub fn pin(&self) -> &str {
        &self.pin
    }

    /// AUTH `pin` arrived: count it, or refuse while locked out or while
    /// every allowed attempt is in flight (then `in_flight_retry`, the
    /// handshake timeout, bounds how long until one resolves).
    pub fn admit(&mut self, now: Instant, in_flight_retry: Duration) -> PinAdmission {
        if let Some(until) = self.locked_until {
            if now < until {
                return self.refuse(now, until - now);
            }
            self.locked_until = None;
        }
        // Every allowed attempt is already in flight: refuse more until one
        // resolves, so concurrent connections cannot exceed the limit. Not
        // reported to the host: it is no lockout, and each attempt in
        // flight is reported when it resolves.
        if self.attempts >= MAX_PIN_FAILURES {
            return PinAdmission::Refused {
                retry_after: in_flight_retry,
                notify: false,
            };
        }
        self.attempts += 1;
        PinAdmission::Attempt {
            pin: self.pin.clone(),
            gen: self.gen,
        }
    }

    /// The PIN admitted as `gen` is still the current one.
    pub fn is_current(&self, gen: u64) -> bool {
        self.gen == gen
    }

    /// The current PIN generation (see [`is_current`](Self::is_current)).
    pub fn gen(&self) -> u64 {
        self.gen
    }

    /// How many times the host reset the PIN state ("New PIN").
    pub fn resets(&self) -> u64 {
        self.resets
    }

    /// A fixed (devtools) PIN: "New PIN" keeps it, so an attempt admitted
    /// before a reset still guesses the PIN in use.
    pub fn is_fixed(&self) -> bool {
        self.fixed
    }

    fn refuse(&mut self, now: Instant, retry_after: Duration) -> PinAdmission {
        let notify = self
            .last_refusal_event
            .is_none_or(|t| now.saturating_duration_since(t) >= REFUSAL_EVENT_INTERVAL);
        if notify {
            self.last_refusal_event = Some(now);
        }
        PinAdmission::Refused {
            retry_after,
            notify,
        }
    }

    /// A counted attempt failed (wrong PIN, or the client went away before
    /// confirming). The failure that reaches the limit starts the lockout
    /// and rotates the PIN, so the guessed-at PIN is gone for good.
    pub fn failed(&mut self, now: Instant) -> PinFailure {
        if let Some(until) = self.locked_until {
            // An attempt admitted before the lockout started: report the
            // lockout still running, or the fresh attempts after it.
            if now < until {
                return PinFailure {
                    attempts_left: 0,
                    locked_for: Some(until - now),
                    rotated: false,
                };
            }
            self.locked_until = None;
        } else if self.attempts >= MAX_PIN_FAILURES {
            let lockout = lockout_duration(self.lockouts);
            self.lockouts = self.lockouts.saturating_add(1);
            self.locked_until = Some(now + lockout);
            self.attempts = 0;
            self.rotate();
            return PinFailure {
                attempts_left: 0,
                locked_for: Some(lockout),
                rotated: !self.fixed,
            };
        }
        PinFailure {
            attempts_left: MAX_PIN_FAILURES - self.attempts,
            locked_for: None,
            rotated: false,
        }
    }

    /// [`failed`](Self::failed) for an attempt admitted before a
    /// [`reset`](Self::reset) on a fixed PIN: the reset dropped its slot
    /// from the count, but it guessed the PIN still in use, so it takes a
    /// slot of the fresh count (no free guesses per "New PIN").
    pub fn failed_after_reset(&mut self, now: Instant) -> PinFailure {
        self.attempts = self.attempts.saturating_add(1).min(MAX_PIN_FAILURES);
        self.failed(now)
    }

    /// A PIN pairing succeeded: reset the count and the lockout escalation,
    /// and rotate (a PIN pairs exactly one receiver).
    pub fn succeeded(&mut self) {
        self.attempts = 0;
        self.lockouts = 0;
        self.rotate();
    }

    /// The host asked for a new PIN ("New PIN" on the phone): rotate it
    /// (unless fixed; in-flight attempts on the old one then fail) and clear
    /// the lockout, the failure count and the escalation.
    pub fn reset(&mut self) {
        self.attempts = 0;
        self.lockouts = 0;
        self.locked_until = None;
        self.last_refusal_event = None;
        self.resets += 1;
        self.rotate();
    }

    /// New random PIN unless fixed.
    fn rotate(&mut self) {
        if !self.fixed {
            self.pin = random_pin();
            self.gen += 1;
        }
    }
}

/// `PIN_LOCKOUT × 2^n`, capped at [`PIN_LOCKOUT_MAX`]: the lockout after
/// `n` earlier consecutive ones.
fn lockout_duration(n: u32) -> Duration {
    let factor = 1u32.checked_shl(n).unwrap_or(u32::MAX);
    PIN_LOCKOUT.saturating_mul(factor).min(PIN_LOCKOUT_MAX)
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

struct Pairing {
    client_id: String,
    client_name: String,
    key: PairingKey,
    paired_at_ms: u64,
}

/// `{"version":1,"pairings":[{"clientId","clientName","key","pairedAtMs"}]}`.
#[derive(Serialize)]
struct StoreFile {
    version: u32,
    pairings: Vec<StoreEntry>,
}

/// The store as loaded: each entry is parsed on its own, so one bad entry
/// does not cost the others.
#[derive(Deserialize)]
struct LoadFile<'a> {
    version: u32,
    #[serde(borrow)]
    pairings: Vec<&'a RawValue>,
}

/// Just the version, read first: a newer store's other fields may not
/// parse as this version's.
#[derive(Deserialize)]
struct VersionOnly {
    version: u32,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoreEntry {
    client_id: String,
    client_name: String,
    /// Hex pairing key (secret; zeroized on drop).
    key: Zeroizing<String>,
    paired_at_ms: u64,
}

const STORE_VERSION: u32 = 1;

/// Pairing keys by `clientId`, persisted to a JSON file (or in memory only
/// when there is no path). Every change is written through atomically.
pub(crate) struct PairingStore {
    path: Option<PathBuf>,
    /// In pairing order (oldest first): [`trim_oldest`] relies on it.
    entries: Vec<Pairing>,
    /// The file exists but could not be loaded (unreadable, written by a
    /// newer version, or corrupt and could not be moved aside): never
    /// overwrite it, it may hold pairings.
    load_error: Option<String>,
    /// Sequence number of the last [`Snapshot`] taken.
    seq: u64,
}

impl fmt::Debug for PairingStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairingStore")
            .field("path", &self.path)
            .field("entries", &self.entries.len())
            .field("load_error", &self.load_error)
            .finish()
    }
}

/// A store change that still has to be written: `Ok(None)` when there is
/// nothing to write (in-memory store), `Err` (already logged) when the file
/// must not be written.
pub(crate) type Save = Result<Option<Snapshot>, String>;

/// The serialised store at one point in time, written by [`StoreWriter`]
/// (outside the lock that guards the [`PairingStore`]).
pub(crate) struct Snapshot {
    path: PathBuf,
    seq: u64,
    json: Zeroizing<Vec<u8>>,
}

impl Snapshot {
    fn write(&self) -> Result<(), String> {
        write_atomic(&self.path, &self.json).map_err(|e| {
            let e = format!("pairing store: cannot write {}: {e}", self.path.display());
            log::error!("{e}");
            e
        })
    }
}

/// Writes [`Snapshot`]s in order: one taken earlier than the last one
/// written is skipped (that newer one already holds its change).
#[derive(Default)]
pub(crate) struct StoreWriter {
    written: Mutex<u64>,
}

impl StoreWriter {
    pub fn write(&self, save: Save) -> Result<(), String> {
        let Some(snap) = save? else {
            return Ok(());
        };
        let mut written = lock(&self.written);
        if *written >= snap.seq {
            return Ok(());
        }
        snap.write()?;
        *written = snap.seq;
        Ok(())
    }
}

/// Write `save` at once (single-threaded users: tests, offline tools).
fn write_now(save: Save) -> Result<(), String> {
    save?.map_or(Ok(()), |s| s.write())
}

impl PairingStore {
    /// Load `path` (missing = empty; corrupt = moved aside to `<path>.bad`,
    /// then empty). `None` keeps pairings in memory only. A file that
    /// exists but cannot be read, was written by a newer version, or cannot
    /// be moved aside starts the store empty and read-only on disk: every
    /// save fails until a restart loads it.
    pub fn open(path: Option<PathBuf>) -> Self {
        Self::open_as(path, false)
    }

    /// `read_only`: change nothing on disk (no temp-file cleanup, a corrupt
    /// file is left in place and loads as empty).
    fn open_as(path: Option<PathBuf>, read_only: bool) -> Self {
        let (entries, load_error) = match path.as_deref() {
            None => (Vec::new(), None),
            Some(p) => {
                if !read_only {
                    remove_stale_tmps(p);
                }
                match load(p, read_only) {
                    Ok(v) => (v, None),
                    Err(e) => (Vec::new(), Some(e)),
                }
            }
        };
        PairingStore {
            path,
            entries,
            load_error,
            seq: 0,
        }
    }

    /// [`open_as`](Self::open_as) a store file; `Err` if it exists but
    /// could not be loaded (the store would be read-only and look empty).
    fn open_existing(path: &Path, read_only: bool) -> Result<Self, String> {
        let store = PairingStore::open_as(Some(path.to_path_buf()), read_only);
        if let Some(e) = &store.load_error {
            return Err(format!("pairing store {}: {e}", path.display()));
        }
        Ok(store)
    }

    pub fn key(&self, client_id: &str) -> Option<PairingKey> {
        self.find(client_id).map(|p| p.key.clone())
    }

    #[cfg(test)]
    pub fn contains(&self, client_id: &str) -> bool {
        self.find(client_id).is_some()
    }

    /// Store (or replace) the key for `client_id`, evicting the oldest
    /// pairing beyond [`MAX_PAIRINGS`]. The change holds in memory at once;
    /// the returned [`Save`] persists it.
    pub fn put_unsaved(
        &mut self,
        client_id: &str,
        client_name: &str,
        key: PairingKey,
        paired_at_ms: u64,
    ) -> Save {
        self.entries.retain(|p| p.client_id != client_id);
        self.entries.push(Pairing {
            client_id: client_id.to_owned(),
            client_name: client_name.to_owned(),
            key,
            paired_at_ms,
        });
        trim_oldest(&mut self.entries);
        self.snapshot()
    }

    /// Remove the pairing for `client_id` in memory. `None` if there was
    /// none; else the [`Save`] that persists the removal.
    pub fn remove_unsaved(&mut self, client_id: &str) -> Option<Save> {
        let before = self.entries.len();
        self.entries.retain(|p| p.client_id != client_id);
        (self.entries.len() != before).then(|| self.snapshot())
    }

    /// [`put_unsaved`](Self::put_unsaved) and write it. On `Err` (not
    /// persisted; already logged) the pairing still holds in memory.
    #[cfg(test)]
    pub fn put(
        &mut self,
        client_id: &str,
        client_name: &str,
        key: PairingKey,
        paired_at_ms: u64,
    ) -> Result<(), String> {
        write_now(self.put_unsaved(client_id, client_name, key, paired_at_ms))
    }

    /// Remove the pairing for `client_id` and write it. `Ok(false)` if
    /// there was none. On `Err` it is removed in memory but the removal is
    /// not persisted (already logged): the key would come back after a
    /// restart.
    pub fn remove(&mut self, client_id: &str) -> Result<bool, String> {
        self.remove_unsaved(client_id)
            .map_or(Ok(false), |s| write_now(s).map(|()| true))
    }

    /// Why the file could not be loaded at open (it is then never written).
    pub fn load_error(&self) -> Option<&str> {
        self.load_error.as_deref()
    }

    pub fn list(&self) -> Vec<PairedClient> {
        self.entries
            .iter()
            .map(|p| PairedClient {
                client_id: p.client_id.clone(),
                client_name: p.client_name.clone(),
                paired_at_ms: p.paired_at_ms,
            })
            .collect()
    }

    fn find(&self, client_id: &str) -> Option<&Pairing> {
        self.entries.iter().find(|p| p.client_id == client_id)
    }

    /// Serialise the current entries for writing.
    fn snapshot(&mut self) -> Save {
        let Some(path) = &self.path else {
            return Ok(None);
        };
        if let Some(e) = &self.load_error {
            let msg = format!(
                "pairing store {} was not loaded ({e}); not overwriting it \
                 (fix or remove it, then restart)",
                path.display()
            );
            log::error!("{msg}");
            return Err(msg);
        }
        let file = StoreFile {
            version: STORE_VERSION,
            pairings: self
                .entries
                .iter()
                .map(|p| StoreEntry {
                    client_id: p.client_id.clone(),
                    client_name: p.client_name.clone(),
                    key: Zeroizing::new(p.key.to_hex()),
                    paired_at_ms: p.paired_at_ms,
                })
                .collect(),
        };
        // Sized up front: a growing Vec would free un-wiped copies of the
        // keys on every reallocation.
        let mut json = Zeroizing::new(Vec::with_capacity(json_capacity(&file)));
        serde_json::to_writer_pretty(&mut *json, &file).map_err(|e| {
            let e = format!("pairing store: serialise: {e}");
            log::error!("{e}");
            e
        })?;
        self.seq += 1;
        Ok(Some(Snapshot {
            path: path.clone(),
            seq: self.seq,
            json,
        }))
    }

    #[cfg(test)]
    fn save(&mut self) -> Result<(), String> {
        write_now(self.snapshot())
    }
}

/// An upper bound on the pretty-printed size of `file`: every string byte
/// may become a 6-byte `\u00XX` escape; the rest (field names, indentation,
/// the 64-digit key, a `u64`) fits in 192 bytes per entry.
fn json_capacity(file: &StoreFile) -> usize {
    let strings: usize = file
        .pairings
        .iter()
        .map(|e| e.client_id.len() + e.client_name.len())
        .sum();
    64 + 6 * strings + 192 * file.pairings.len()
}

/// Drop the oldest entries beyond [`MAX_PAIRINGS`]. "Oldest" is insertion
/// order (`entries` is kept in pairing order, `put` appends), not
/// `paired_at_ms`: a wall clock set backwards must never evict the pairing
/// just made (that Mac would then loop on `auth_failed`).
fn trim_oldest(entries: &mut Vec<Pairing>) {
    let excess = entries.len().saturating_sub(MAX_PAIRINGS);
    for p in entries.drain(..excess) {
        log::info!(
            "pairing store full; evicted {:?} ({:?})",
            short(&p.client_name),
            short(&p.client_id)
        );
    }
}

/// Paired receivers in the store file at `path`, for a host that is not
/// running a [`Server`](crate::Server) (e.g. to review pairings before
/// mirroring starts). Read-only: a missing file lists as empty. `Err`
/// (logged) if the file is corrupt (it is moved aside only when a server
/// starts or a revoke runs), cannot be read, or was written by a newer
/// version, so a UI can say "couldn't read" instead of showing no pairings.
pub fn list_paired_at(path: &Path) -> Result<Vec<PairedClient>, String> {
    let store = PairingStore::open_existing(path, true)?;
    Ok(store.list())
}

/// Remove `client_id` from the store file at `path` without a running
/// [`Server`](crate::Server), so a lost or compromised receiver can be
/// revoked before mirroring (and its listener) starts. `Ok(true)` only if it
/// was present and the removal is written (atomic write, fsync, mode 0600);
/// `Ok(false)` if it was not paired. `Err` (logged) if the file could not be
/// loaded (it is then never overwritten) or the removal not written.
///
/// Must not run while a `Server` uses the same store: the server would
/// write its in-memory pairings (the revoked one included) back.
pub fn revoke_at(path: &Path, client_id: &str) -> Result<bool, String> {
    PairingStore::open_existing(path, false)?.remove(client_id)
}

/// Outcome of [`parse`].
enum Parsed {
    Ok(Vec<Pairing>),
    /// Not a store at all (bad JSON, no version, version 0).
    Corrupt,
    /// Written by a newer version of this code.
    Newer(u32),
}

/// `Err` if the file exists but must not be overwritten: unreadable,
/// written by a newer version, or corrupt and could not be moved aside.
fn load(path: &Path, read_only: bool) -> Result<Vec<Pairing>, String> {
    let bytes = match fs::read(path) {
        Ok(b) => Zeroizing::new(b),
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => {
            // Unreadable but maybe intact: leave it alone (no `.bad`).
            let msg = format!("cannot read: {e}");
            log::error!("pairing store {}: {msg}", path.display());
            return Err(msg);
        }
    };
    match parse(&bytes) {
        Parsed::Ok(v) => Ok(v),
        Parsed::Newer(v) => {
            // Its pairings are valid for the newer app: keep it intact.
            let msg = format!(
                "written by a newer version (store version {v}, this one reads \
                 {STORE_VERSION}); not loading it"
            );
            log::error!("pairing store {}: {msg}", path.display());
            Err(msg)
        }
        Parsed::Corrupt if read_only => {
            let msg = "corrupt; it is set aside when mirroring starts".to_string();
            log::warn!("pairing store {}: {msg}", path.display());
            Err(msg)
        }
        Parsed::Corrupt => {
            let moved = free_bad_name(path).and_then(|bad| fs::rename(path, &bad).map(|()| bad));
            match moved {
                Ok(bad) => {
                    log::warn!(
                        "pairing store {} is corrupt; moved to {} and starting empty",
                        path.display(),
                        bad.display()
                    );
                    Ok(Vec::new())
                }
                Err(e) => {
                    let msg = format!("corrupt, and cannot move it aside: {e}");
                    log::error!("pairing store {}: {msg}", path.display());
                    Err(msg)
                }
            }
        }
    }
}

/// Most `<path>.bad*` files kept; a further corrupt store stays in place.
const MAX_BAD_FILES: u32 = 10;

/// The first unused name of `<path>.bad`, `<path>.bad.1`, ...: an earlier
/// corrupt store is never overwritten.
fn free_bad_name(path: &Path) -> io::Result<PathBuf> {
    for i in 0..MAX_BAD_FILES {
        let name = if i == 0 {
            sibling(path, ".bad")
        } else {
            sibling(path, &format!(".bad.{i}"))
        };
        match fs::symlink_metadata(&name) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(name),
            Err(e) => return Err(e),
            Ok(_) => {}
        }
    }
    Err(io::Error::other(format!(
        "{MAX_BAD_FILES} earlier corrupt stores are already kept; remove them"
    )))
}

/// Parse a store file. A version-1 store loads every valid entry; invalid
/// ones (missing fields, a key that is not 64 hex digits) are skipped with
/// a warning. No length or emptiness rules here: anything `put` ever wrote
/// (older versions accepted an empty or a very long `clientId`) must load,
/// or it would be lost on the next start.
fn parse(bytes: &[u8]) -> Parsed {
    let Ok(VersionOnly { version }) = serde_json::from_slice(bytes) else {
        return Parsed::Corrupt;
    };
    if version > STORE_VERSION {
        return Parsed::Newer(version);
    }
    let Ok(file) = serde_json::from_slice::<LoadFile>(bytes) else {
        return Parsed::Corrupt;
    };
    if file.version != STORE_VERSION {
        return Parsed::Corrupt;
    }
    let mut out: Vec<Pairing> = Vec::with_capacity(file.pairings.len().min(MAX_PAIRINGS));
    for (i, raw) in file.pairings.iter().enumerate() {
        let entry = serde_json::from_str::<StoreEntry>(raw.get())
            .ok()
            .and_then(|e| Some((PairingKey::from_hex(&e.key)?, e)));
        let Some((key, e)) = entry else {
            log::warn!("pairing store: skipping invalid entry #{i}");
            continue;
        };
        // Duplicates cannot be written by us; keep the newest if present.
        if let Some(j) = out.iter().position(|p| p.client_id == e.client_id) {
            if out[j].paired_at_ms > e.paired_at_ms {
                continue;
            }
            out.remove(j);
        }
        out.push(Pairing {
            client_id: e.client_id,
            client_name: e.client_name,
            key,
            paired_at_ms: e.paired_at_ms,
        });
    }
    trim_oldest(&mut out);
    Parsed::Ok(out)
}

/// `<path><suffix>` in the same directory.
fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

/// Create `path` exclusively (O_EXCL: never follows or reuses an existing
/// file or symlink), owner read/write only.
fn create_private(path: &Path) -> io::Result<File> {
    let mut o = OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(path)
}

/// Prefix of the temp files [`write_atomic`] creates for `path`.
const TMP_SUFFIX: &str = ".tmp.";

/// `<path>.tmp.<pid>.<random>`: unique, so concurrent or crashed writers
/// never share (or truncate) a temp file.
fn tmp_path(path: &Path) -> io::Result<PathBuf> {
    let mut r = [0u8; 8];
    getrandom::fill(&mut r).map_err(|e| io::Error::other(e.to_string()))?;
    Ok(sibling(
        path,
        &format!(
            "{TMP_SUFFIX}{}.{:016x}",
            std::process::id(),
            u64::from_ne_bytes(r)
        ),
    ))
}

/// Delete temp files a crashed writer left next to `path` (they may hold
/// pairing keys). Best effort.
fn remove_stale_tmps(path: &Path) {
    let (Some(dir), Some(name)) = (parent_dir(path), path.file_name()) else {
        return;
    };
    let mut prefix = name.to_owned();
    prefix.push(TMP_SUFFIX);
    let prefix = prefix.to_string_lossy().into_owned();
    let Ok(rd) = fs::read_dir(&dir) else { return };
    for e in rd.flatten() {
        if e.file_name().to_string_lossy().starts_with(&prefix) {
            let _ = fs::remove_file(e.path());
        }
    }
}

/// The directory holding `path` (`.` for a bare file name).
fn parent_dir(path: &Path) -> Option<PathBuf> {
    match path.parent() {
        Some(p) if p.as_os_str().is_empty() => Some(PathBuf::from(".")),
        p => p.map(Path::to_path_buf),
    }
}

/// Write `data` to a temp file in the same directory and rename it over
/// `path`, then sync the directory, so a crash leaves either the old or the
/// new store, never half. `Ok` once the rename is done: the data is then
/// in the file, and a failed directory sync (the rename might not survive a
/// power loss) is only logged.
fn write_atomic(path: &Path, data: &[u8]) -> io::Result<()> {
    let tmp = tmp_path(path)?;
    let mut f = create_private(&tmp)?;
    let res = f
        .write_all(data)
        .and_then(|_| f.sync_all())
        .and_then(|_| fs::rename(&tmp, path));
    if res.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    res?;
    if let Err(e) = sync_dir(path) {
        log::warn!(
            "pairing store {} written, but syncing its directory failed: {e}; \
             the change may not survive a power loss",
            path.display()
        );
    }
    Ok(())
}

/// fsync the directory holding `path`, making a rename in it durable.
#[cfg(unix)]
fn sync_dir(path: &Path) -> io::Result<()> {
    match parent_dir(path) {
        Some(dir) => File::open(dir)?.sync_all(),
        None => Ok(()),
    }
}

#[cfg(not(unix))]
fn sync_dir(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t0() -> Instant {
        Instant::now()
    }

    const HS: Duration = Duration::from_secs(10);

    impl PinState {
        fn try_admit(&mut self, now: Instant) -> PinAdmission {
            self.admit(now, HS)
        }
    }

    fn is_attempt(a: &PinAdmission) -> bool {
        matches!(a, PinAdmission::Attempt { .. })
    }

    /// Run [`MAX_PIN_FAILURES`] failed attempts at `now`; the lockout the
    /// last one started.
    fn fail_all(s: &mut PinState, now: Instant) -> Duration {
        let mut locked = None;
        for _ in 0..MAX_PIN_FAILURES {
            assert!(is_attempt(&s.try_admit(now)));
            locked = s.failed(now).locked_for;
        }
        locked.expect("the fifth failure locks out")
    }

    #[test]
    fn pin_validation() {
        assert!(is_valid_pin("012345"));
        for p in ["12345", "1234567", "12345a", "", "١٢٣٤٥٦"] {
            assert!(!is_valid_pin(p), "{p}");
        }
        let s = PinState::new(None);
        assert!(is_valid_pin(s.pin()));
        // An invalid fixed PIN falls back to a random one.
        let s = PinState::new(Some("12"));
        assert!(is_valid_pin(s.pin()) && !s.fixed);
    }

    #[test]
    fn five_failures_lock_out_and_rotate() {
        let now = t0();
        let mut s = PinState::new(Some("111111"));
        s.fixed = false; // rotate like production, start from a known PIN
        for left in (1..MAX_PIN_FAILURES).rev() {
            assert!(
                matches!(s.try_admit(now), PinAdmission::Attempt { pin, .. } if *pin == "111111")
            );
            assert_eq!(
                s.failed(now),
                PinFailure {
                    attempts_left: left,
                    locked_for: None,
                    rotated: false,
                }
            );
        }
        assert!(is_attempt(&s.try_admit(now)));
        assert_eq!(
            s.failed(now),
            PinFailure {
                attempts_left: 0,
                locked_for: Some(PIN_LOCKOUT),
                rotated: true,
            }
        );
        assert_ne!(s.pin(), "111111", "rotated on lockout");
        match s.try_admit(now + Duration::from_secs(10)) {
            PinAdmission::Refused { retry_after, .. } => {
                assert_eq!(retry_after, Duration::from_secs(20))
            }
            PinAdmission::Attempt { .. } => panic!("must be locked"),
        }
        // After the lockout a fresh set of attempts is allowed.
        assert!(is_attempt(&s.try_admit(now + PIN_LOCKOUT)));
    }

    #[test]
    fn success_resets_and_rotates() {
        let now = t0();
        let mut s = PinState::new(None);
        for _ in 0..4 {
            let _ = s.try_admit(now);
            s.failed(now);
        }
        let PinAdmission::Attempt { gen, .. } = s.try_admit(now) else {
            panic!("admitted");
        };
        s.succeeded();
        assert_eq!(s.attempts, 0);
        // Rotated (the generation, not the digits: a new random PIN may
        // equal the old one).
        assert!(!s.is_current(gen));
    }

    #[test]
    fn in_flight_attempts_are_capped() {
        let now = t0();
        let mut s = PinState::new(None);
        for _ in 0..MAX_PIN_FAILURES {
            assert!(is_attempt(&s.try_admit(now)));
        }
        // No lockout started: retry once a handshake has timed out, not
        // after a full lockout, and the host is not told of a lockout.
        assert!(matches!(
            s.try_admit(now),
            PinAdmission::Refused { retry_after, notify: false } if retry_after == HS
        ));
        // The first failure reaches the limit and starts the lockout; the
        // other attempts in flight then fail *during* it, and say so.
        assert_eq!(s.failed(now).locked_for, Some(PIN_LOCKOUT));
        let later = now + Duration::from_secs(10);
        for _ in 1..MAX_PIN_FAILURES {
            assert_eq!(
                s.failed(later),
                PinFailure {
                    attempts_left: 0,
                    locked_for: Some(PIN_LOCKOUT - Duration::from_secs(10)),
                    rotated: false,
                }
            );
        }
        // One resolving after the lockout ended reports a fresh count.
        let s2_end = now + PIN_LOCKOUT;
        assert_eq!(
            s.failed(s2_end),
            PinFailure {
                attempts_left: MAX_PIN_FAILURES,
                locked_for: None,
                rotated: false,
            }
        );
        assert!(is_attempt(&s.try_admit(s2_end)));
    }

    #[test]
    fn consecutive_lockouts_escalate_until_a_success() {
        let mut s = PinState::new(None);
        let mut now = t0();
        let mut want = Vec::new();
        let mut got = Vec::new();
        for n in 0..10u32 {
            let d = fail_all(&mut s, now);
            got.push(d);
            want.push((PIN_LOCKOUT * 2u32.pow(n)).min(PIN_LOCKOUT_MAX));
            // Still locked just before the end, admitted right after.
            assert!(!is_attempt(
                &s.try_admit(now + d - Duration::from_millis(1))
            ));
            now += d;
        }
        assert_eq!(got, want);
        assert_eq!(got[..4], [30, 60, 120, 240].map(Duration::from_secs));
        assert_eq!(*got.last().unwrap(), PIN_LOCKOUT_MAX);
        // An expired lockout alone does not reset the escalation...
        assert_eq!(fail_all(&mut s, now), PIN_LOCKOUT_MAX);
        now += PIN_LOCKOUT_MAX;
        // ...only a successful pairing does.
        assert!(is_attempt(&s.try_admit(now)));
        s.succeeded();
        assert_eq!(fail_all(&mut s, now), PIN_LOCKOUT);
        assert_eq!(lockout_duration(u32::MAX), PIN_LOCKOUT_MAX);
    }

    #[test]
    fn refusal_reports_are_rate_limited() {
        let mut s = PinState::new(None);
        let now = t0();
        fail_all(&mut s, now);
        let notified = |a: PinAdmission| match a {
            PinAdmission::Refused { notify, .. } => notify,
            PinAdmission::Attempt { .. } => panic!("must be refused"),
        };
        assert!(notified(s.try_admit(now)));
        for ms in [0, 1, 100, 4_999] {
            assert!(!notified(s.try_admit(now + Duration::from_millis(ms))));
        }
        let later = now + REFUSAL_EVENT_INTERVAL;
        assert!(notified(s.try_admit(later)));
        assert!(!notified(s.try_admit(later + Duration::from_secs(1))));
    }

    #[test]
    fn fixed_pin_never_rotates() {
        let mut s = PinState::new(Some("424242"));
        s.succeeded();
        s.rotate();
        assert_eq!(s.pin(), "424242");
        // The lockout does not claim a rotation either (with every allowed
        // attempt in flight, the first failure starts it).
        for _ in 0..MAX_PIN_FAILURES {
            assert!(is_attempt(&s.try_admit(t0())));
        }
        assert_eq!(
            s.failed(t0()),
            PinFailure {
                attempts_left: 0,
                locked_for: Some(PIN_LOCKOUT),
                rotated: false,
            }
        );
        assert_eq!(s.pin(), "424242");
        assert!(
            !format!("{s:?}").contains("424242"),
            "Debug redacts the PIN"
        );
    }

    #[test]
    fn store_debug_and_parse_rules() {
        let k = "ab".repeat(32);
        let ok = format!(
            r#"{{"version":1,"pairings":[{{"clientId":"a","clientName":"A","key":"{k}","pairedAtMs":5}}]}}"#
        );
        let Parsed::Ok(v) = parse(ok.as_bytes()) else {
            panic!("valid store");
        };
        assert_eq!(v.len(), 1);
        for bad in [
            "{".to_string(),
            "[]".to_string(),
            ok.replace("\"version\":1", "\"version\":0"),
            ok.replace("\"version\":1", "\"version\":\"1\""),
        ] {
            assert!(matches!(parse(bad.as_bytes()), Parsed::Corrupt), "{bad}");
        }
        let store = PairingStore {
            path: None,
            entries: v,
            load_error: None,
            seq: 0,
        };
        assert!(!format!("{store:?}").contains(&k));
    }

    /// A unique, self-deleting temp directory.
    struct Dir(PathBuf);
    impl Dir {
        fn new(tag: &str) -> Dir {
            use std::sync::atomic::{AtomicUsize, Ordering};
            static N: AtomicUsize = AtomicUsize::new(0);
            let p = std::env::temp_dir().join(format!(
                "mirror-pairing-{tag}-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::SeqCst)
            ));
            let _ = fs::remove_dir_all(&p);
            fs::create_dir_all(&p).unwrap();
            Dir(p)
        }
        fn store(&self) -> PathBuf {
            self.0.join("pairings.json")
        }
        fn names(&self) -> Vec<String> {
            let mut v: Vec<String> = fs::read_dir(&self.0)
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            v.sort();
            v
        }
    }
    impl Drop for Dir {
        fn drop(&mut self) {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(0o700));
            }
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn key(b: u8) -> PairingKey {
        PairingKey::from_bytes([b; 32])
    }

    /// Every pairing `put` writes loads again: an empty or long `clientId`
    /// (older versions accepted both; the handshake now refuses them) must
    /// not make the next start treat the file as corrupt and move every
    /// pairing aside.
    #[test]
    fn empty_client_id_survives_a_restart() {
        let d = Dir::new("empty-id");
        let mut s = PairingStore::open(Some(d.store()));
        let long = "l".repeat(64 * 1024);
        s.put("a", "A", key(1), 1).unwrap();
        s.put("", "nameless", key(2), 2).unwrap();
        s.put(&long, &long, key(3), 3).unwrap();
        let s = PairingStore::open(Some(d.store()));
        assert!(s.load_error.is_none());
        assert!(s.contains("a") && s.contains("") && s.contains(&long));
        assert_eq!(d.names(), ["pairings.json"], "nothing moved aside");
    }

    /// The store JSON is serialised into a buffer sized up front, so no
    /// reallocation leaves un-wiped key copies behind, even for names that
    /// escape to six bytes per byte.
    #[test]
    fn store_json_never_outgrows_its_buffer() {
        let mut s = PairingStore::open(None);
        s.path = Some(PathBuf::from("unused"));
        for i in 0..MAX_PAIRINGS {
            let nasty = "\u{1}".repeat(i * 7);
            let _ = s.put_unsaved(&format!("{nasty}{i}"), &nasty, key(i as u8), u64::MAX);
        }
        let snap = s.snapshot().unwrap().unwrap();
        let file = StoreFile {
            version: STORE_VERSION,
            pairings: s
                .entries
                .iter()
                .map(|p| StoreEntry {
                    client_id: p.client_id.clone(),
                    client_name: p.client_name.clone(),
                    key: Zeroizing::new(p.key.to_hex()),
                    paired_at_ms: p.paired_at_ms,
                })
                .collect(),
        };
        assert!(snap.json.len() <= json_capacity(&file));
        assert_eq!(snap.json.capacity(), json_capacity(&file), "no realloc");
    }

    /// "New PIN" clears the lockout and its escalation and rotates; a fixed
    /// PIN is kept (only the lockout is cleared).
    #[test]
    fn reset_clears_lockout_and_escalation() {
        let mut s = PinState::new(None);
        let first = fail_all(&mut s, t0());
        let later = t0() + first + Duration::from_secs(1);
        let second = fail_all(&mut s, later);
        assert!(second > first, "escalated");
        let (old, gen) = (s.pin().to_owned(), s.gen);
        s.reset();
        assert_ne!(s.pin(), old);
        assert!(!s.is_current(gen), "in-flight attempts on the old PIN fail");
        // Not locked out any more, a full count (`fail_all` checks every
        // admission), and the escalation restarted.
        let again = fail_all(&mut s, later);
        assert_eq!(again, PIN_LOCKOUT);

        // A partial failure count is cleared too.
        let mut p = PinState::new(None);
        for _ in 0..2 {
            assert!(is_attempt(&p.try_admit(t0())));
            p.failed(t0());
        }
        p.reset();
        assert_eq!(fail_all(&mut p, t0()), PIN_LOCKOUT, "five fresh attempts");

        let mut f = PinState::new(Some("424242"));
        fail_all(&mut f, t0());
        assert!(!is_attempt(&f.try_admit(t0())), "locked out");
        f.reset();
        assert_eq!(f.pin(), "424242");
        assert!(is_attempt(&f.try_admit(t0())));
    }

    /// A store file that exists but cannot be read is never overwritten.
    #[cfg(unix)]
    #[test]
    fn unreadable_store_is_not_overwritten() {
        use std::os::unix::fs::PermissionsExt;
        let d = Dir::new("unreadable");
        let mut s = PairingStore::open(Some(d.store()));
        s.put("a", "A", key(1), 1).unwrap();
        let original = fs::read(d.store()).unwrap();
        fs::set_permissions(d.store(), fs::Permissions::from_mode(0o000)).unwrap();
        if fs::read(d.store()).is_ok() {
            return; // running as root: permissions cannot make it unreadable
        }
        let mut s = PairingStore::open(Some(d.store()));
        assert!(s.load_error.is_some());
        assert!(s.list().is_empty());
        // Pairings still work in memory, but are not written over the file.
        assert!(s.put("b", "B", key(2), 2).is_err());
        assert!(s.contains("b"));
        assert_eq!(s.remove("b"), Err(s.save().unwrap_err()));
        fs::set_permissions(d.store(), fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(fs::read(d.store()).unwrap(), original, "file untouched");
        assert_eq!(d.names(), ["pairings.json"]);
        // Once it loads again, saving works again.
        let mut s = PairingStore::open(Some(d.store()));
        assert!(s.contains("a"));
        s.put("b", "B", key(2), 2).unwrap();
    }

    /// Corrupt but impossible to move aside: also left alone.
    #[cfg(unix)]
    #[test]
    fn corrupt_store_that_cannot_be_moved_is_not_overwritten() {
        use std::os::unix::fs::PermissionsExt;
        let d = Dir::new("stuck");
        fs::write(d.store(), b"{").unwrap();
        fs::set_permissions(&d.0, fs::Permissions::from_mode(0o500)).unwrap();
        if fs::write(d.0.join("probe"), b"").is_ok() {
            return; // root
        }
        let mut s = PairingStore::open(Some(d.store()));
        assert!(s.load_error.is_some());
        assert!(s.put("a", "A", key(1), 1).is_err());
        fs::set_permissions(&d.0, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(fs::read(d.store()).unwrap(), b"{");
    }

    /// A removal that cannot be written reports an error (and stays removed
    /// in memory); the file still has the key.
    #[cfg(unix)]
    #[test]
    fn unpersisted_removal_is_an_error() {
        use std::os::unix::fs::PermissionsExt;
        let d = Dir::new("rm");
        let mut s = PairingStore::open(Some(d.store()));
        s.put("a", "A", key(1), 1).unwrap();
        fs::set_permissions(&d.0, fs::Permissions::from_mode(0o500)).unwrap();
        if fs::write(d.0.join("probe"), b"").is_ok() {
            return; // root
        }
        assert!(s.remove("a").is_err());
        assert!(!s.contains("a"), "removed in memory");
        assert_eq!(s.remove("a"), Ok(false));
        fs::set_permissions(&d.0, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(PairingStore::open(Some(d.store())).contains("a"));
    }

    /// Eviction follows pairing order, not the wall clock: a new pairing
    /// stamped earlier than every stored one (clock set backwards) is kept
    /// and the first-paired entry goes.
    #[test]
    fn full_store_evicts_the_first_paired_never_the_new_one() {
        let mut s = PairingStore::open(None);
        for i in 0..MAX_PAIRINGS as u64 {
            s.put(&format!("c{i}"), "C", key(1), 1_000 + i).unwrap();
        }
        s.put("new", "N", key(2), 0).unwrap();
        assert_eq!(s.list().len(), MAX_PAIRINGS);
        assert!(s.contains("new"), "the pairing just made survives");
        assert!(!s.contains("c0"), "the first-paired one is evicted");
        assert!(s.contains("c1"));
        // Re-pairing moves an entry to the newest position.
        s.put("c1", "C", key(3), 0).unwrap();
        s.put("new2", "N", key(4), 0).unwrap();
        assert!(s.contains("c1") && !s.contains("c2"));
        // Loading keeps file (pairing) order too.
        let mut v = s.entries;
        v.push(Pairing {
            client_id: "x".into(),
            client_name: "X".into(),
            key: key(5),
            paired_at_ms: 0,
        });
        trim_oldest(&mut v);
        assert_eq!(v.last().unwrap().client_id, "x");
        assert_eq!(v[0].client_id, "c4");
    }

    fn mode(p: &Path) -> u32 {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::metadata(p).unwrap().permissions().mode() & 0o777
        }
        #[cfg(not(unix))]
        {
            let _ = p;
            0o600
        }
    }

    /// Offline list/revoke: present, absent and missing-file cases; the
    /// removal is durable (a fresh load no longer has it) and keeps 0600.
    #[test]
    fn offline_list_and_revoke() {
        let d = Dir::new("offline");
        assert_eq!(list_paired_at(&d.store()), Ok(Vec::new()), "no file");
        assert_eq!(revoke_at(&d.store(), "a"), Ok(false));
        assert_eq!(d.names(), Vec::<String>::new(), "nothing created");

        let mut s = PairingStore::open(Some(d.store()));
        s.put("a", "A", key(1), 1).unwrap();
        s.put("b", "B", key(2), 2).unwrap();
        drop(s);
        let ids = |v: Vec<PairedClient>| v.into_iter().map(|p| p.client_id).collect::<Vec<_>>();
        assert_eq!(ids(list_paired_at(&d.store()).unwrap()), ["a", "b"]);
        let l = list_paired_at(&d.store()).unwrap();
        assert_eq!((l[1].client_name.as_str(), l[1].paired_at_ms), ("B", 2));

        assert_eq!(revoke_at(&d.store(), "zz"), Ok(false), "absent");
        assert_eq!(revoke_at(&d.store(), "a"), Ok(true));
        assert_eq!(mode(&d.store()), 0o600);
        // Durable: a server starting now does not know "a" any more.
        let s = PairingStore::open(Some(d.store()));
        assert!(!s.contains("a") && s.contains("b"));
        assert_eq!(s.key("b").unwrap().to_hex(), key(2).to_hex());
        assert_eq!(ids(list_paired_at(&d.store()).unwrap()), ["b"]);
        assert_eq!(revoke_at(&d.store(), "a"), Ok(false), "already gone");
        assert_eq!(d.names(), ["pairings.json"], "no temp files left");
    }

    /// Listing never changes the files (a corrupt store is an error and
    /// stays, temp files stay); a revoke moves a corrupt file aside like a
    /// server start (nothing to revoke); an unreadable one is an error and
    /// left untouched.
    #[cfg(unix)]
    #[test]
    fn offline_corrupt_and_unreadable_stores() {
        use std::os::unix::fs::PermissionsExt;
        let d = Dir::new("offline-bad");
        fs::write(d.store(), b"{").unwrap();
        fs::write(d.0.join("pairings.json.tmp.1.ab"), b"x").unwrap();
        assert!(list_paired_at(&d.store()).is_err(), "corrupt is not empty");
        assert_eq!(d.names(), ["pairings.json", "pairings.json.tmp.1.ab"]);
        assert_eq!(fs::read(d.store()).unwrap(), b"{");
        assert_eq!(revoke_at(&d.store(), "a"), Ok(false));
        assert_eq!(d.names(), ["pairings.json.bad"]);
        assert_eq!(list_paired_at(&d.store()), Ok(Vec::new()));

        let mut s = PairingStore::open(Some(d.store()));
        s.put("a", "A", key(1), 1).unwrap();
        let original = fs::read(d.store()).unwrap();
        fs::set_permissions(d.store(), fs::Permissions::from_mode(0o000)).unwrap();
        if fs::read(d.store()).is_ok() {
            return; // root
        }
        assert!(list_paired_at(&d.store()).is_err());
        assert!(revoke_at(&d.store(), "a").is_err());
        fs::set_permissions(d.store(), fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(fs::read(d.store()).unwrap(), original, "not overwritten");
        assert_eq!(d.names(), ["pairings.json", "pairings.json.bad"]);
    }

    /// A removal that cannot be written is an error, and the key stays.
    #[cfg(unix)]
    #[test]
    fn offline_revoke_that_cannot_be_written_is_an_error() {
        use std::os::unix::fs::PermissionsExt;
        let d = Dir::new("offline-ro");
        let mut s = PairingStore::open(Some(d.store()));
        s.put("a", "A", key(1), 1).unwrap();
        fs::set_permissions(&d.0, fs::Permissions::from_mode(0o500)).unwrap();
        if fs::write(d.0.join("probe"), b"").is_ok() {
            return; // root
        }
        assert!(revoke_at(&d.store(), "a").is_err());
        fs::set_permissions(&d.0, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(PairingStore::open(Some(d.store())).contains("a"));
    }

    fn store_json(entries: &str) -> String {
        format!(r#"{{"version":1,"pairings":[{entries}]}}"#)
    }

    fn entry(id: &str, key_hex: &str, at: u64) -> String {
        format!(r#"{{"clientId":"{id}","clientName":"N","key":"{key_hex}","pairedAtMs":{at}}}"#)
    }

    /// A second corrupt store does not overwrite the first one moved aside.
    #[test]
    fn corrupt_stores_moved_aside_are_all_kept() {
        let d = Dir::new("bad-twice");
        for (i, junk) in [&b"{"[..], b"[1", b"x"].into_iter().enumerate() {
            fs::write(d.store(), junk).unwrap();
            let s = PairingStore::open(Some(d.store()));
            assert!(s.load_error.is_none() && s.list().is_empty());
            let bad = if i == 0 {
                d.0.join("pairings.json.bad")
            } else {
                d.0.join(format!("pairings.json.bad.{i}"))
            };
            assert_eq!(fs::read(bad).unwrap(), junk);
        }
        // Once every slot is taken the store is left alone (read-only).
        for i in 3..MAX_BAD_FILES {
            fs::write(d.0.join(format!("pairings.json.bad.{i}")), b"").unwrap();
        }
        fs::write(d.store(), b"{").unwrap();
        let mut s = PairingStore::open(Some(d.store()));
        assert!(s.load_error.is_some());
        assert!(s.put("a", "A", key(1), 1).is_err());
        assert_eq!(fs::read(d.store()).unwrap(), b"{");
    }

    /// A store from a newer version is neither loaded, moved aside nor
    /// overwritten; listing it is an error.
    #[test]
    fn newer_store_version_is_left_alone() {
        let d = Dir::new("newer");
        let newer = r#"{"version":2,"pairings":{"a":"new format"}}"#;
        fs::write(d.store(), newer).unwrap();
        let mut s = PairingStore::open(Some(d.store()));
        assert!(s.load_error.as_deref().unwrap().contains("newer version"));
        assert!(s.put("a", "A", key(1), 1).is_err());
        assert!(list_paired_at(&d.store()).is_err());
        assert!(revoke_at(&d.store(), "a").is_err());
        assert_eq!(fs::read_to_string(d.store()).unwrap(), newer);
        assert_eq!(d.names(), ["pairings.json"]);
    }

    /// Invalid entries are skipped; the valid ones load and nothing is
    /// moved aside.
    #[test]
    fn one_bad_entry_does_not_cost_the_others() {
        let d = Dir::new("bad-entry");
        let good = key(7).to_hex();
        let json = store_json(
            &[
                entry("a", &good, 1),
                entry("b", "abcd", 2),                        // short key
                r#"{"clientId":"c","key":"00"}"#.to_string(), // missing fields
                "42".to_string(),
                entry("d", &good, 3),
            ]
            .join(","),
        );
        fs::write(d.store(), json).unwrap();
        let s = PairingStore::open(Some(d.store()));
        assert!(s.load_error.is_none());
        let ids: Vec<_> = s.list().into_iter().map(|p| p.client_id).collect();
        assert_eq!(ids, ["a", "d"]);
        assert_eq!(s.key("d").unwrap(), key(7));
        assert_eq!(d.names(), ["pairings.json"]);
    }

    /// Snapshots written out of order: the older one never replaces the
    /// newer one (it holds the older one's change too).
    #[test]
    fn older_snapshot_never_overwrites_a_newer_one() {
        let d = Dir::new("order");
        let mut s = PairingStore::open(Some(d.store()));
        let w = StoreWriter::default();
        let first = s.put_unsaved("a", "A", key(1), 1);
        let second = s.put_unsaved("b", "B", key(2), 2);
        w.write(second).unwrap();
        w.write(first).unwrap();
        let s = PairingStore::open(Some(d.store()));
        assert!(s.contains("a") && s.contains("b"));
    }

    /// The data is in place once the rename is done: a directory that
    /// cannot be synced (here: not readable, so it cannot be opened) is no
    /// failed save.
    #[cfg(unix)]
    #[test]
    fn failed_directory_sync_is_not_a_failed_save() {
        use std::os::unix::fs::PermissionsExt;
        let d = Dir::new("nosync");
        fs::set_permissions(&d.0, fs::Permissions::from_mode(0o300)).unwrap();
        if File::open(&d.0).is_ok() {
            return; // root
        }
        let mut s = PairingStore::open(Some(d.store()));
        assert_eq!(s.put("a", "A", key(1), 1), Ok(()));
        fs::set_permissions(&d.0, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(PairingStore::open(Some(d.store())).contains("a"));
    }

    #[test]
    fn temp_files_are_unique_and_cleaned_up() {
        let d = Dir::new("tmp");
        let (a, b) = (tmp_path(&d.store()).unwrap(), tmp_path(&d.store()).unwrap());
        assert_ne!(a, b);
        let name = a.file_name().unwrap().to_string_lossy().into_owned();
        let pid = format!("pairings.json.tmp.{}.", std::process::id());
        assert!(name.starts_with(&pid), "{name}");
        // Leftovers of a crashed writer are removed when the store opens;
        // other files are kept.
        fs::write(&a, b"secret").unwrap();
        fs::write(d.0.join("pairings.json.tmp.1.ab"), b"secret").unwrap();
        fs::write(d.0.join("other.tmp.1.ab"), b"x").unwrap();
        let mut s = PairingStore::open(Some(d.store()));
        assert_eq!(d.names(), ["other.tmp.1.ab"]);
        s.put("a", "A", key(1), 1).unwrap();
        assert_eq!(d.names(), ["other.tmp.1.ab", "pairings.json"]);
        assert_eq!(parent_dir(Path::new("x.json")), Some(PathBuf::from(".")));
    }

    /// Concurrent writers never share a temp file: every write succeeds and
    /// the result is always one complete version.
    #[test]
    fn concurrent_atomic_writes_do_not_collide() {
        let d = Dir::new("race");
        let path = d.store();
        std::thread::scope(|sc| {
            for t in 0..4u8 {
                let path = &path;
                sc.spawn(move || {
                    let data = vec![b'a' + t; 4096];
                    for _ in 0..50 {
                        write_atomic(path, &data).unwrap();
                    }
                });
            }
        });
        let got = fs::read(&path).unwrap();
        assert_eq!(got.len(), 4096);
        assert!(got.iter().all(|&b| b == got[0]));
        assert_eq!(d.names(), ["pairings.json"]);
    }
}
