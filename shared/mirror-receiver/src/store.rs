//! Small persisted settings (last address, stable client id, paired phones)
//! as JSON in the user's app data directory (`~/Library/Application Support/
//! dev.local.androidmirror/settings.json` on macOS). Every failure is
//! reported, never fatal: the app works with defaults when the file is
//! missing, unreadable or corrupt.
//!
//! The file holds pairing keys, so it is written owner-only (0600; a looser
//! file is tightened on load) and atomically (a uniquely named temp file,
//! fsync, rename, fsync of the directory). Keys are never logged:
//! [`PairingKey`]'s `Debug` is redacted, and so is everything that contains
//! one.
//!
//! Loading is lenient: a field or pairing entry that does not parse is
//! dropped (the original file is copied to `settings.json.bad` first) and
//! the rest is kept; fields this version does not know are kept and written
//! back. Only a file that is not a JSON object at all is quarantined.
//!
//! [`Store`] is the shared, thread-safe handle the app and the network client
//! use together: one in-memory copy, every change saved under one lock, so a
//! UI save (last address) can never overwrite a pairing the client just
//! stored (or the other way round). Across processes (two app instances) a
//! change is applied to the file's current contents under an advisory lock
//! on `settings.json.lock`, so neither instance overwrites the other's
//! changes.

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use mirror_protocol::auth::PairingKey;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

const FILE_NAME: &str = "settings.json";

/// At most this many paired phones are kept; pairing one more evicts the
/// oldest (`paired_at_ms`).
pub const MAX_PAIRINGS: usize = 32;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Settings {
    /// Last address the user connected to (as typed, normalised).
    pub last_address: Option<String>,
    /// Stable receiver id sent as `clientId` (the phone keys pairings by it).
    pub client_id: Option<String>,
    /// Phones paired by PIN, at most one entry per `device_id`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub pairings: Vec<PairedDevice>,
    /// Fields this version does not know (written by a newer one): kept and
    /// written back unchanged. Crate-private so nothing can change them:
    /// [`Change`] does not replay them (see [`Settings::extra`]).
    #[serde(flatten)]
    pub(crate) extra: Map<String, Value>,
}

/// One paired phone. `Debug` shows everything except the key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairedDevice {
    /// `deviceId` from SERVER_HELLO.
    pub device_id: String,
    /// `deviceName` at pairing time (for the "paired devices" list).
    pub device_name: String,
    /// The pairing key (64 lowercase hex digits in the file). Secret.
    #[serde(with = "key_hex")]
    pub key: PairingKey,
    /// Wall-clock pairing time, ms since the Unix epoch.
    pub paired_at_ms: u64,
}

/// Serde adapter: [`PairingKey`] as hex. A malformed key makes its pairing
/// entry unreadable (dropped on load, see [`Settings::from_json`]).
mod key_hex {
    use mirror_protocol::auth::PairingKey;
    use serde::{de, Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(k: &PairingKey, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&k.to_hex())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<PairingKey, D::Error> {
        let s = String::deserialize(d)?;
        // Never echo the value in the error: it is (part of) a secret.
        PairingKey::from_hex(&s)
            .ok_or_else(|| de::Error::custom("pairing key is not 64 hex digits"))
    }
}

impl Settings {
    /// Parse a settings file leniently. `Err` only when the text is not a
    /// JSON object; otherwise every field or pairing entry that does not
    /// parse is left out and described in the returned list (never with
    /// key material).
    pub fn from_json(bytes: &[u8]) -> Result<(Settings, Vec<String>), serde_json::Error> {
        let mut extra: Map<String, Value> = serde_json::from_slice(bytes)?;
        let mut problems = Vec::new();
        let mut text = |name: &str| match extra.remove(name) {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) => Some(s),
            Some(_) => {
                problems.push(format!("\"{name}\" is not a string"));
                None
            }
        };
        let last_address = text("lastAddress");
        let client_id = text("clientId");
        let mut pairings = Vec::new();
        match extra.remove("pairings") {
            None | Some(Value::Null) => {}
            Some(Value::Array(items)) => {
                for (i, item) in items.into_iter().enumerate() {
                    match serde_json::from_value::<PairedDevice>(item) {
                        Ok(p) => pairings.push(p),
                        Err(e) => problems.push(format!("pairing #{}: {e}", i + 1)),
                    }
                }
            }
            Some(_) => problems.push("\"pairings\" is not a list".into()),
        }
        let settings = Settings {
            last_address,
            client_id,
            pairings,
            extra,
        };
        Ok((settings, problems))
    }

    /// Fields this version does not know, as read from the file.
    pub fn extra(&self) -> &Map<String, Value> {
        &self.extra
    }

    /// The pairing for `device_id`, if any.
    pub fn pairing(&self, device_id: &str) -> Option<&PairedDevice> {
        self.pairings.iter().find(|p| p.device_id == device_id)
    }

    /// Add a pairing, replacing any previous one for the same device (a
    /// re-pair makes the old key useless on the phone anyway). Keeps at
    /// most [`MAX_PAIRINGS`] by evicting the oldest.
    pub fn put_pairing(&mut self, device: PairedDevice) {
        self.pairings.retain(|p| p.device_id != device.device_id);
        while self.pairings.len() >= MAX_PAIRINGS {
            let Some(oldest) = self
                .pairings
                .iter()
                .enumerate()
                .min_by_key(|(_, p)| p.paired_at_ms)
                .map(|(i, _)| i)
            else {
                break;
            };
            self.pairings.remove(oldest);
        }
        self.pairings.push(device);
    }

    /// Forget `device_id`. Returns whether a pairing was removed.
    pub fn remove_pairing(&mut self, device_id: &str) -> bool {
        let before = self.pairings.len();
        self.pairings.retain(|p| p.device_id != device_id);
        self.pairings.len() != before
    }
}

/// Why loading or saving settings failed.
#[derive(Debug)]
pub enum StoreError {
    /// No home/app-data directory could be determined.
    NoDataDir,
    Io(PathBuf, io::Error),
    Corrupt(PathBuf, serde_json::Error),
    /// The store is memory-only because the settings could not be loaded
    /// (the reason); nothing is written this run.
    NotSaving(String),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::NoDataDir => write!(f, "no app data directory available"),
            StoreError::Io(p, e) => write!(f, "{}: {e}", p.display()),
            StoreError::Corrupt(p, e) => write!(f, "{}: invalid settings: {e}", p.display()),
            StoreError::NotSaving(why) => write!(f, "not saving settings this run: {why}"),
        }
    }
}

impl std::error::Error for StoreError {}

/// Settings file location (`None` when there is no home directory).
pub fn default_path() -> Option<PathBuf> {
    directories::ProjectDirs::from("dev", "local", "androidmirror")
        .map(|d| d.data_dir().join(FILE_NAME))
}

/// Load settings from `path`. A missing file yields defaults; unreadable
/// fields and pairing entries are dropped (see [`Settings::from_json`]).
pub fn load(path: &Path) -> Result<Settings, StoreError> {
    Ok(read(path)?.map(|(s, _)| s).unwrap_or_default())
}

/// The file's settings and parse problems; `None` when it does not exist.
fn read(path: &Path) -> Result<Option<(Settings, Vec<String>)>, StoreError> {
    read_bytes(path)?
        .map(|b| Settings::from_json(&b))
        .transpose()
        .map_err(|e| StoreError::Corrupt(path.to_path_buf(), e))
}

/// The file's bytes; `None` when it does not exist. Tightens a
/// group/world-accessible file to 0600 (it holds keys).
fn read_bytes(path: &Path) -> Result<Option<Vec<u8>>, StoreError> {
    let io_err = |e| StoreError::Io(path.to_path_buf(), e);
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(io_err(e)),
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(path).map_err(io_err)?.permissions().mode();
        if mode & 0o077 != 0 {
            match fs::set_permissions(path, fs::Permissions::from_mode(0o600)) {
                Ok(()) => eprintln!(
                    "settings: {} was readable by others; made it owner-only",
                    path.display()
                ),
                Err(e) => eprintln!("settings: cannot make {} owner-only: {e}", path.display()),
            }
        }
    }
    Ok(Some(bytes))
}

/// Save settings atomically (unique temp file + rename), owner-only
/// permissions, then fsync the directory so the rename survives a crash.
pub fn save(path: &Path, settings: &Settings) -> Result<(), StoreError> {
    let io_err = |e| StoreError::Io(path.to_path_buf(), e);
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(io_err)?;
    }
    let json = serde_json::to_vec_pretty(settings)
        .map_err(|e| StoreError::Corrupt(path.to_path_buf(), e))?;
    // A per-save name: two writers (instances, threads) never share or
    // truncate each other's temp file, and `create_new` never reuses a
    // leftover with loose permissions.
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(format!(
        ".tmp-{}-{}",
        std::process::id(),
        &new_client_id()[..8]
    ));
    let tmp = PathBuf::from(tmp);
    if let Err(e) = write_private(&tmp, &json).and_then(|()| fs::rename(&tmp, path)) {
        let _ = fs::remove_file(&tmp);
        return Err(io_err(e));
    }
    // The new contents are in place; a failed directory fsync only means the
    // rename might not survive a power loss, so it is logged, not an error.
    #[cfg(unix)]
    if let Some(dir) = path.parent() {
        let dir = if dir.as_os_str().is_empty() {
            Path::new(".")
        } else {
            dir
        };
        if let Err(e) = fs::File::open(dir).and_then(|d| d.sync_all()) {
            eprintln!("settings: cannot sync {}: {e}", dir.display());
        }
    }
    Ok(())
}

fn write_private(path: &Path, data: &[u8]) -> io::Result<()> {
    use std::io::Write;
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(data)?;
    f.sync_all()
}

/// Hold the cross-process lock on `<path>.lock` (released on drop). `None`
/// when the lock file cannot be used; the save then goes ahead unlocked
/// (it will most likely fail for the same reason and say why).
fn lock_file(path: &Path) -> Option<fs::File> {
    let mut name = path.as_os_str().to_owned();
    name.push(".lock");
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let f = path
        .parent()
        .map_or(Ok(()), fs::create_dir_all)
        .and_then(|()| opts.open(&name))
        .and_then(|f| f.lock().map(|()| f));
    match f {
        Ok(f) => Some(f),
        Err(e) => {
            eprintln!("settings: cannot lock {}: {e}", Path::new(&name).display());
            None
        }
    }
}

/// Load settings for this run. Returns them plus the path later saves may
/// write to, or why there is none (saving could lose data, or there is no
/// place to save):
///
/// * not a JSON object: moved aside to `settings.json.bad` (or `.bad.1`,
///   `.bad.2`, … if that exists), then the path is reused; if the move
///   fails, nothing is written this run;
/// * some fields or pairings unreadable: the rest is used; the original is
///   copied to `.bad` the same way before a save would drop them (see
///   [`Store::update`]);
/// * unreadable file (I/O error): kept as is, settings live in memory only.
fn load_or_quarantine(path: Option<PathBuf>) -> (Settings, Result<PathBuf, String>) {
    let Some(path) = path else {
        eprintln!("settings: {}", StoreError::NoDataDir);
        return (Settings::default(), Err(StoreError::NoDataDir.to_string()));
    };
    match read(&path) {
        Ok(None) => (Settings::default(), Ok(path)),
        Ok(Some((s, problems))) if problems.is_empty() => (s, Ok(path)),
        Ok(Some((s, problems))) => {
            eprintln!(
                "settings: {}: skipped {}",
                path.display(),
                problems.join("; ")
            );
            (s, Ok(path))
        }
        Err(e @ StoreError::Corrupt(..)) => {
            // Keep the client id if it is still legible: a new one would
            // leave a stale entry for this Mac in every phone's paired list.
            let salvaged = Settings {
                client_id: fs::read(&path).ok().and_then(|b| salvage_client_id(&b)),
                ..Settings::default()
            };
            match set_aside(&path, |from, to| fs::rename(from, to)) {
                Ok(bad) => {
                    eprintln!(
                        "settings: {e}; moved it to {} and using defaults{}",
                        bad.display(),
                        if salvaged.client_id.is_some() {
                            " (client id kept)"
                        } else {
                            ""
                        }
                    );
                    (salvaged, Ok(path))
                }
                Err(re) => {
                    eprintln!("settings: {e}; cannot move it aside ({re}); not saving this run");
                    (salvaged, Err(format!("{e}; cannot move it aside ({re})")))
                }
            }
        }
        Err(e) => {
            eprintln!("settings: {e}; using defaults, not saving this run");
            (Settings::default(), Err(e.to_string()))
        }
    }
}

/// The `"clientId": "…"` value from a file that is not valid JSON, if it is
/// there and looks like an id (ASCII letters, digits, `-`, `_`).
fn salvage_client_id(bytes: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(bytes);
    let rest = &text[text.find("\"clientId\"")? + "\"clientId\"".len()..];
    let rest = rest.trim_start().strip_prefix(':')?.trim_start();
    let (id, _) = rest.strip_prefix('"')?.split_once('"')?;
    let ok = !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    ok.then(|| id.to_string())
}

/// Move or copy (`how`) a damaged settings file to `<name>.bad`, or the
/// first free `<name>.bad.<n>`: an earlier backup is never overwritten.
/// Returns the new path.
fn set_aside(path: &Path, how: impl FnOnce(&Path, &Path) -> io::Result<()>) -> io::Result<PathBuf> {
    const MAX_BACKUPS: u32 = 1000;
    for n in 0..MAX_BACKUPS {
        let mut bad = path.as_os_str().to_owned();
        bad.push(if n == 0 {
            ".bad".into()
        } else {
            format!(".bad.{n}")
        });
        let bad = PathBuf::from(bad);
        // Claim the name first (`create_new` is atomic), so a concurrent
        // set-aside cannot pick it too; `how` then replaces the placeholder.
        if let Err(e) = write_private(&bad, &[]) {
            if e.kind() == io::ErrorKind::AlreadyExists {
                continue;
            }
            return Err(e);
        }
        return match how(path, &bad) {
            Ok(()) => Ok(bad),
            Err(e) => {
                let _ = fs::remove_file(&bad);
                Err(e)
            }
        };
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "too many settings backups",
    ))
}

// ---------------------------------------------------------------------------
// Shared store
// ---------------------------------------------------------------------------

struct Inner {
    /// Where changes are saved; `None` = memory only (see [`Store::open`]).
    path: Option<PathBuf>,
    /// Why a store that should have a file is memory-only (loading failed,
    /// or no data directory): every update then reports that it was not
    /// saved. `None` for a file-backed or a deliberate in-memory store.
    not_saving: Option<String>,
    /// The client id once handed out by [`Store::ensure_client_id`]: kept
    /// for the whole run even if the file later says otherwise, because the
    /// phones paired this run know this Mac by it.
    client_id: OnceLock<String>,
    settings: Mutex<Settings>,
    /// Changes whose save failed, oldest first. Every update replays them
    /// onto the file's current contents (so another instance's changes are
    /// kept) until a save succeeds. Locked only while `settings` is.
    pending: Mutex<Vec<Change>>,
    /// The last save failed (memory holds changes the file lacks). A plain
    /// flag so the UI can read it without waiting for a save.
    unsaved: AtomicBool,
    /// File contents this process last copied to a `.bad` backup, and
    /// where: repeated failing saves do not pile up identical backups.
    backed_up: Mutex<Option<(Vec<u8>, PathBuf)>>,
}

/// Shared settings handle (cheap to clone; all clones see the same data).
/// Every change goes through [`update`](Store::update), which saves while
/// holding the lock, so concurrent writers never lose each other's changes.
#[derive(Clone)]
pub struct Store {
    inner: Arc<Inner>,
}

impl fmt::Debug for Store {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Store")
            .field("path", &self.inner.path)
            .field("pairings", &self.lock().pairings.len())
            .finish()
    }
}

impl Default for Store {
    /// An empty in-memory store.
    fn default() -> Self {
        Store::in_memory(Settings::default())
    }
}

impl Store {
    /// Load `path` (missing → defaults). A file that is not a JSON object is
    /// quarantined (renamed to `.bad`) and the store starts empty; unreadable
    /// entries are skipped (see [`Settings::from_json`]); an unreadable file is
    /// left alone and the store lives in memory only for this run. `None`
    /// (no data dir) is memory-only too. Problems are logged to stderr.
    pub fn open(path: Option<PathBuf>) -> Store {
        let (settings, path) = load_or_quarantine(path);
        let (path, not_saving) = match path {
            Ok(p) => (Some(p), None),
            Err(why) => (None, Some(why)),
        };
        Store {
            inner: Arc::new(Inner {
                path,
                not_saving,
                client_id: OnceLock::new(),
                settings: Mutex::new(settings),
                pending: Mutex::new(Vec::new()),
                unsaved: AtomicBool::new(false),
                backed_up: Mutex::new(None),
            }),
        }
    }

    /// A store that never touches the disk (tests, tools).
    pub fn in_memory(settings: Settings) -> Store {
        Store {
            inner: Arc::new(Inner {
                path: None,
                not_saving: None,
                client_id: OnceLock::new(),
                settings: Mutex::new(settings),
                pending: Mutex::new(Vec::new()),
                unsaved: AtomicBool::new(false),
                backed_up: Mutex::new(None),
            }),
        }
    }

    /// The file changes are saved to (`None` = memory only).
    pub fn path(&self) -> Option<&Path> {
        self.inner.path.as_deref()
    }

    fn lock(&self) -> MutexGuard<'_, Settings> {
        // A panic while holding the lock cannot leave Settings invalid.
        self.inner
            .settings
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }

    /// A copy of the current settings.
    pub fn get(&self) -> Settings {
        self.lock().clone()
    }

    /// Change the settings and save them. The change is kept in memory even
    /// when saving fails (the error says why it did not reach the disk),
    /// and is replayed by every later update until a save succeeds, so an
    /// unsaved pairing is never dropped by reloading the file.
    ///
    /// With a file, `f` is applied to the file's current contents (read
    /// under the cross-process lock), so changes another app instance saved
    /// meanwhile are kept rather than overwritten. A missing file leaves the
    /// in-memory copy as the base. A file that cannot be read (I/O error) is
    /// left alone, as on load: nothing is saved. A file that is not valid
    /// settings, or has entries this version cannot read (another version
    /// wrote them), would lose data to the save, so it is first copied to
    /// `.bad` as on load; if that copy fails, nothing is saved.
    ///
    /// A store that is memory-only because loading failed (see
    /// [`Store::open`]) applies `f` and returns [`StoreError::NotSaving`].
    pub fn update<R>(&self, f: impl FnOnce(&mut Settings) -> R) -> Result<R, StoreError> {
        let mut s = self.lock();
        let Some(path) = &self.inner.path else {
            let r = f(&mut s);
            return match &self.inner.not_saving {
                None => Ok(r),
                Some(why) => {
                    self.inner.unsaved.store(true, Ordering::Relaxed);
                    Err(StoreError::NotSaving(why.clone()))
                }
            };
        };
        let mut pending = self.inner.pending.lock().unwrap_or_else(|p| p.into_inner());
        let _lock = lock_file(path);
        let mut blocked = Ok(());
        let current = read_bytes(path);
        if let Ok(Some(bytes)) = current {
            let parsed = Settings::from_json(&bytes);
            let lost = match &parsed {
                Ok((_, problems)) if problems.is_empty() => None,
                Ok((_, problems)) => Some(problems.join("; ")),
                Err(e) => Some(format!("invalid settings ({e})")),
            };
            if let Some(lost) = lost {
                blocked = self
                    .back_up_once(path, bytes, &lost)
                    .map_err(|e| StoreError::Io(path.clone(), e));
            }
            if let Ok((disk, _)) = parsed {
                *s = disk;
                for change in pending.iter() {
                    change.apply(&mut s);
                }
            }
        } else if let Err(e) = current {
            // Saving would replace a file nobody could read (maybe full of
            // pairings) without a backup: keep the change pending instead.
            blocked = Err(e);
        }
        let before = s.clone();
        let r = f(&mut s);
        let saved = blocked.and_then(|()| save(path, &s));
        if saved.is_ok() {
            pending.clear();
        } else {
            pending.extend(Change::between(&before, &s));
        }
        self.inner.unsaved.store(saved.is_err(), Ordering::Relaxed);
        saved.map(|()| r)
    }

    /// Copy the file (`bytes`) to `.bad` before a save drops `lost`, unless
    /// this process already made a backup of exactly these contents that is
    /// still there.
    fn back_up_once(&self, path: &Path, bytes: Vec<u8>, lost: &str) -> io::Result<()> {
        let mut done = self
            .inner
            .backed_up
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if let Some((old, bad)) = done.as_ref() {
            if *old == bytes && fs::read(bad).is_ok_and(|b| b == bytes) {
                return Ok(());
            }
        }
        let bad = set_aside(path, |from, to| fs::copy(from, to).map(drop))?;
        eprintln!(
            "settings: {}: dropping {lost}; original copied to {}",
            path.display(),
            bad.display()
        );
        *done = Some((bytes, bad));
        Ok(())
    }

    /// Whether the last save failed, so memory holds changes the file lacks.
    pub fn unsaved(&self) -> bool {
        self.inner.unsaved.load(Ordering::Relaxed)
    }

    /// The stable client id, created and saved on first use (a save failure
    /// is logged; the id still holds for this run). Safe against two
    /// instances starting at once: an id already in the file wins.
    ///
    /// Once handed out, the same id is returned for the rest of the run,
    /// even if a later reload finds another instance's id in the file (only
    /// possible after this one failed to save its own): the phones paired
    /// this run know this Mac by the id it used. The file keeps the id that
    /// was saved first, so the next run uses that one.
    pub fn ensure_client_id(&self) -> String {
        self.inner
            .client_id
            .get_or_init(|| {
                if let Some(id) = self.lock().client_id.clone() {
                    return id;
                }
                match self.update(|s| s.client_id.get_or_insert_with(new_client_id).clone()) {
                    Ok(id) => id,
                    Err(e) => {
                        eprintln!("settings: {e}");
                        self.lock().client_id.clone().unwrap_or_else(new_client_id)
                    }
                }
            })
            .clone()
    }

    /// The stored pairing key for `device_id`.
    pub fn pairing_key(&self, device_id: &str) -> Option<PairingKey> {
        self.lock().pairing(device_id).map(|p| p.key.clone())
    }

    /// All paired phones (for a "paired devices" list).
    pub fn pairings(&self) -> Vec<PairedDevice> {
        self.lock().pairings.clone()
    }

    /// Store (or replace) a pairing and save.
    pub fn put_pairing(&self, device: PairedDevice) -> Result<(), StoreError> {
        self.update(|s| s.put_pairing(device))
    }

    /// Forget a phone ("Forget device", or the phone rejected our key) and
    /// save. Returns whether it was paired.
    pub fn remove_pairing(&self, device_id: &str) -> Result<bool, StoreError> {
        self.update(|s| s.remove_pairing(device_id))
    }
}

/// One change an update made, kept as data so it can be replayed onto the
/// file's current contents after a failed save.
#[derive(Debug, Clone)]
enum Change {
    LastAddress(Option<String>),
    /// Replayed only onto a file without an id: an id another instance
    /// already saved wins (see [`Store::ensure_client_id`]).
    ClientId(Option<String>),
    /// Replayed unless the file holds a newer pairing for that device.
    PutPairing(PairedDevice),
    /// Forget the pairing with this device id and key: replayed only while
    /// the file still has that key (a re-pair saved since then is kept).
    RemovePairing(String, PairingKey),
}

impl Change {
    /// The changes that turn `before` into `after` (unknown fields are only
    /// ever carried over, never changed, so they are not compared: `extra`
    /// is crate-private for that reason).
    fn between(before: &Settings, after: &Settings) -> Vec<Change> {
        let mut out = Vec::new();
        if before.last_address != after.last_address {
            out.push(Change::LastAddress(after.last_address.clone()));
        }
        if before.client_id != after.client_id {
            out.push(Change::ClientId(after.client_id.clone()));
        }
        for old in &before.pairings {
            if after.pairing(&old.device_id).is_none() {
                out.push(Change::RemovePairing(
                    old.device_id.clone(),
                    old.key.clone(),
                ));
            }
        }
        for new in &after.pairings {
            if before.pairing(&new.device_id) != Some(new) {
                out.push(Change::PutPairing(new.clone()));
            }
        }
        out
    }

    fn apply(&self, s: &mut Settings) {
        match self {
            Change::LastAddress(a) => s.last_address.clone_from(a),
            Change::ClientId(id) => {
                if s.client_id.is_none() {
                    s.client_id.clone_from(id);
                }
            }
            Change::PutPairing(p) => {
                if s.pairing(&p.device_id)
                    .is_none_or(|d| d.paired_at_ms <= p.paired_at_ms)
                {
                    s.put_pairing(p.clone());
                }
            }
            Change::RemovePairing(id, key) => {
                if s.pairing(id).is_some_and(|d| d.key == *key) {
                    s.remove_pairing(id);
                }
            }
        }
    }
}

/// A new random client id (32 hex chars).
pub fn new_client_id() -> String {
    let mut b = [0u8; 16];
    if getrandom::fill(&mut b).is_err() {
        // Extremely unlikely; fall back to something unique enough per host.
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        b = (t ^ u128::from(std::process::id())).to_le_bytes();
    }
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Milliseconds since the Unix epoch (0 if the clock is before 1970).
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("mirror-receiver-store-{name}-{}", new_client_id()));
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn paired(id: &str, byte: u8, at: u64) -> PairedDevice {
        PairedDevice {
            device_id: id.into(),
            device_name: format!("Phone {id}"),
            key: PairingKey::from_bytes([byte; 32]),
            paired_at_ms: at,
        }
    }

    #[test]
    fn missing_file_gives_defaults() {
        let d = temp_dir("missing");
        assert_eq!(load(&d.join("nope.json")).unwrap(), Settings::default());
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn round_trip_creates_dirs_and_is_private() {
        let d = temp_dir("rt");
        let p = d.join("sub/settings.json");
        let s = Settings {
            last_address: Some("192.168.1.42:47800".into()),
            client_id: Some("abc".into()),
            pairings: vec![paired("p1", 0xab, 5)],
            ..Default::default()
        };
        save(&p, &s).unwrap();
        assert_eq!(load(&p).unwrap(), s);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&p).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let names: Vec<_> = fs::read_dir(d.join("sub")).unwrap().collect();
        assert_eq!(names.len(), 1, "no temp file left: {names:?}");
        let text = fs::read_to_string(&p).unwrap();
        assert!(text.contains(r#""deviceId": "p1""#), "{text}");
        assert!(text.contains(&"ab".repeat(32)), "key stored as hex");
        assert!(text.contains(r#""pairedAtMs": 5"#), "{text}");
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn no_pairings_key_when_empty() {
        let json = serde_json::to_string(&Settings::default()).unwrap();
        assert!(!json.contains("pairings"), "{json}");
    }

    #[test]
    fn debug_never_shows_the_key() {
        let s = Settings {
            pairings: vec![paired("p1", 0xab, 5)],
            ..Default::default()
        };
        let store = Store::in_memory(s.clone());
        let text = format!("{s:?} {:?} {store:?} {:#?}", s.pairings[0], s);
        assert!(!text.contains("ab, ab") && !text.contains("abab"), "{text}");
        assert!(!text.contains("171"), "{text}"); // 0xab as decimal
        assert!(text.contains("p1"), "{text}");
    }

    #[test]
    fn bad_key_hex_drops_only_that_pairing_and_is_not_echoed() {
        let secretish = "cd".repeat(31); // 62 digits: wrong length
        let good = "ab".repeat(32);
        let json = format!(
            r#"{{"clientId":"keep","pairings":[
                {{"deviceId":"a","deviceName":"A","key":"{secretish}","pairedAtMs":1}},
                {{"deviceId":"b","deviceName":"B","key":"{good}","pairedAtMs":2}}]}}"#
        );
        let (s, problems) = Settings::from_json(json.as_bytes()).unwrap();
        assert_eq!(s.client_id.as_deref(), Some("keep"));
        assert_eq!(s.pairings.len(), 1);
        assert!(s.pairing("b").is_some());
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].contains("pairing #1"), "{problems:?}");
        assert!(!problems[0].contains(&secretish), "{problems:?}");
    }

    #[test]
    fn partly_bad_file_keeps_the_rest_and_backs_up_the_original() {
        let d = temp_dir("partly");
        let p = d.join("settings.json");
        let good = "ab".repeat(32);
        let original = format!(
            r#"{{"clientId":"keep-me","lastAddress":5,"pairings":[
                {{"deviceId":"ok","deviceName":"OK","key":"{good}","pairedAtMs":2}},
                {{"deviceId":"bad","deviceName":"Bad","pairedAtMs":3}}]}}"#
        );
        fs::write(&p, &original).unwrap();
        let store = Store::open(Some(p.clone()));
        let s = store.get();
        assert_eq!(s.client_id.as_deref(), Some("keep-me"), "id survives");
        assert_eq!(s.last_address, None);
        assert_eq!(s.pairings.len(), 1);
        assert!(store.pairing_key("ok").is_some());
        assert_eq!(store.path(), Some(p.as_path()));
        store.update(|s| s.last_address = Some("x".into())).unwrap();
        // Backed up once, before the save dropped the unreadable entries.
        assert_eq!(
            fs::read_to_string(d.join("settings.json.bad")).unwrap(),
            original
        );
        store.update(|s| s.last_address = Some("y".into())).unwrap();
        assert!(!d.join("settings.json.bad.1").exists());
        let on_disk = load(&p).unwrap();
        assert_eq!(on_disk.client_id.as_deref(), Some("keep-me"));
        assert!(on_disk.pairing("ok").is_some());
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn client_id_is_salvaged_only_when_legible() {
        let s = |b: &str| salvage_client_id(b.as_bytes());
        assert_eq!(
            s(r#"{"clientId" : "ab-12_c", oops"#),
            Some("ab-12_c".into())
        );
        assert_eq!(s(r#"{"clientId":"a b"}"#), None);
        assert_eq!(s(r#"{"clientId":""}"#), None);
        assert_eq!(s(r#"{"clientId":5}"#), None);
        assert_eq!(s(r#"{"clientId":"unterminated"#), None);
        assert_eq!(s("garbage"), None);
    }

    #[test]
    fn non_object_json_is_corrupt() {
        for bad in [&b"[]"[..], b"\"x\"", b"null", b"{"] {
            assert!(Settings::from_json(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn put_replaces_same_device_and_evicts_oldest() {
        let mut s = Settings::default();
        s.put_pairing(paired("a", 1, 10));
        s.put_pairing(paired("a", 2, 20));
        assert_eq!(s.pairings.len(), 1);
        assert_eq!(s.pairing("a").unwrap().key, PairingKey::from_bytes([2; 32]));

        for i in 0..MAX_PAIRINGS as u64 {
            s.put_pairing(paired(&format!("d{i}"), 3, 100 + i));
        }
        assert_eq!(s.pairings.len(), MAX_PAIRINGS);
        assert!(s.pairing("a").is_none(), "oldest (a @ 20) evicted");
        assert!(s.pairing("d0").is_some());
        assert!(s.remove_pairing("d0"));
        assert!(!s.remove_pairing("d0"));
        assert!(s.pairing("d0").is_none());
    }

    #[test]
    fn store_saves_every_change_and_shares_state() {
        let d = temp_dir("store");
        let p = d.join("settings.json");
        let a = Store::open(Some(p.clone()));
        let b = a.clone();
        a.update(|s| s.last_address = Some("x".into())).unwrap();
        b.put_pairing(paired("ph", 9, 1)).unwrap();
        // Neither write lost the other's change.
        let on_disk = load(&p).unwrap();
        assert_eq!(on_disk.last_address.as_deref(), Some("x"));
        assert_eq!(
            on_disk.pairing("ph").unwrap().key,
            PairingKey::from_bytes([9; 32])
        );
        assert_eq!(
            Store::open(Some(p.clone())).pairing_key("ph"),
            b.pairing_key("ph")
        );
        assert!(a.remove_pairing("ph").unwrap());
        assert!(load(&p).unwrap().pairings.is_empty());
        assert!(b.pairing_key("ph").is_none());
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn in_memory_store_never_writes() {
        let s = Store::default();
        assert_eq!(s.path(), None);
        s.put_pairing(paired("m", 1, 1)).unwrap();
        assert!(s.pairing_key("m").is_some());
        assert_eq!(s.pairings().len(), 1);
    }

    #[test]
    fn concurrent_saves_never_share_a_temp_file() {
        let d = temp_dir("race");
        let p = d.join("settings.json");
        let writers: Vec<_> = (0..4)
            .map(|i| {
                let p = p.clone();
                std::thread::spawn(move || {
                    let s = Settings {
                        client_id: Some(format!("w{i}")),
                        ..Default::default()
                    };
                    for _ in 0..30 {
                        save(&p, &s).unwrap();
                    }
                })
            })
            .collect();
        for w in writers {
            w.join().unwrap();
        }
        assert!(load(&p).unwrap().client_id.is_some());
        let n = fs::read_dir(&d).unwrap().count();
        assert_eq!(n, 1, "no temp files left behind");
        fs::remove_dir_all(d).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn loose_permissions_are_tightened_on_load() {
        use std::os::unix::fs::PermissionsExt;
        let d = temp_dir("perms");
        let p = d.join("settings.json");
        fs::write(&p, br#"{"clientId":"abc"}"#).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();
        let store = Store::open(Some(p.clone()));
        assert_eq!(store.get().client_id.as_deref(), Some("abc"));
        let mode = fs::metadata(&p).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn two_instances_keep_each_others_changes() {
        let d = temp_dir("instances");
        let p = d.join("settings.json");
        let a = Store::open(Some(p.clone()));
        let b = Store::open(Some(p.clone()));
        a.put_pairing(paired("pa", 1, 1)).unwrap();
        b.update(|s| s.last_address = Some("10.0.0.9:1".into()))
            .unwrap();
        b.put_pairing(paired("pb", 2, 2)).unwrap();
        a.remove_pairing("nope").unwrap();
        let on_disk = load(&p).unwrap();
        assert!(on_disk.pairing("pa").is_some(), "{on_disk:?}");
        assert!(on_disk.pairing("pb").is_some(), "{on_disk:?}");
        assert_eq!(on_disk.last_address.as_deref(), Some("10.0.0.9:1"));
        assert_eq!(a.get(), on_disk, "a picked up b's changes on its save");
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn ensure_client_id_creates_once_and_an_existing_id_wins() {
        let d = temp_dir("cid");
        let p = d.join("settings.json");
        let a = Store::open(Some(p.clone()));
        let b = Store::open(Some(p.clone()));
        let id = a.ensure_client_id();
        assert_eq!(id.len(), 32);
        assert_eq!(a.ensure_client_id(), id);
        assert_eq!(
            b.ensure_client_id(),
            id,
            "second instance adopts the saved id"
        );
        assert_eq!(load(&p).unwrap().client_id, Some(id));
        assert!(!Store::default().ensure_client_id().is_empty());
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn corrupt_file_is_an_error_and_unknown_fields_are_kept() {
        let d = temp_dir("corrupt");
        let p = d.join("settings.json");
        fs::write(&p, b"{not json").unwrap();
        assert!(matches!(load(&p), Err(StoreError::Corrupt(..))));
        fs::write(&p, br#"{"lastAddress":"x","future":{"a":[1]}}"#).unwrap();
        let store = Store::open(Some(p.clone()));
        assert_eq!(store.get().last_address.as_deref(), Some("x"));
        store.update(|s| s.last_address = Some("y".into())).unwrap();
        let v: Value = serde_json::from_slice(&fs::read(&p).unwrap()).unwrap();
        assert_eq!(v["future"], serde_json::json!({"a": [1]}), "{v}");
        assert_eq!(v["lastAddress"], "y");
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn corrupt_settings_are_moved_aside_not_overwritten() {
        let d = temp_dir("quarantine");
        let p = d.join("settings.json");
        let old = br#"{"clientId":"keep-me","lastAddress":"10.0.0.2:47800",}"#;
        fs::write(&p, old).unwrap();
        let store = Store::open(Some(p.clone()));
        let kept = Settings {
            client_id: Some("keep-me".into()),
            ..Settings::default()
        };
        assert_eq!(store.get(), kept, "only the legible client id survives");
        assert_eq!(store.path(), Some(p.as_path()));
        assert_eq!(fs::read(d.join("settings.json.bad")).unwrap(), old);
        assert!(!p.exists());
        store.update(|_| ()).unwrap();
        assert!(p.exists());
        // A second corrupt file does not clobber the first `.bad`.
        fs::write(&p, b"{").unwrap();
        let _ = Store::open(Some(p.clone()));
        assert_eq!(fs::read(d.join("settings.json.bad")).unwrap(), old);
        let n = fs::read_dir(&d)
            .unwrap()
            .filter(|e| {
                let name = e.as_ref().unwrap().file_name();
                name.to_string_lossy().starts_with("settings.json.bad")
            })
            .count();
        assert_eq!(n, 2, "settings.json.bad + settings.json.bad.1");
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn backups_never_overwrite_each_other() {
        let d = temp_dir("backups");
        let p = d.join("settings.json");
        let copy = |from: &Path, to: &Path| fs::copy(from, to).map(drop);
        let mut made = Vec::new();
        for i in 0..3 {
            fs::write(&p, format!("v{i}")).unwrap();
            made.push(set_aside(&p, copy).unwrap());
        }
        let got: Vec<String> = made
            .iter()
            .map(|b| fs::read_to_string(b).unwrap())
            .collect();
        assert_eq!(got, ["v0", "v1", "v2"], "{made:?}");
        // A failed move leaves no placeholder behind.
        let fail = |_: &Path, _: &Path| Err(io::Error::other("no"));
        assert!(set_aside(&p, fail).is_err());
        assert!(!d.join("settings.json.bad.3").exists());
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn a_save_backs_up_entries_this_version_cannot_read() {
        let d = temp_dir("newer");
        let p = d.join("settings.json");
        let store = Store::open(Some(p.clone()));
        store.update(|s| s.client_id = Some("me".into())).unwrap();
        // Another (newer) version adds a pairing this one cannot parse.
        let newer = r#"{"clientId":"me","pairings":[{"deviceId":"x","keyV2":"…"}]}"#;
        fs::write(&p, newer).unwrap();
        store.update(|s| s.last_address = Some("a".into())).unwrap();
        assert_eq!(
            fs::read_to_string(d.join("settings.json.bad")).unwrap(),
            newer
        );
        // If the backup cannot be made, the file is left alone.
        fs::write(&p, newer).unwrap();
        fs::remove_file(d.join("settings.json.bad")).unwrap();
        fs::create_dir(d.join("settings.json.bad")).unwrap();
        for n in 1..1000 {
            fs::write(d.join(format!("settings.json.bad.{n}")), "").unwrap();
        }
        assert!(store.update(|s| s.last_address = Some("b".into())).is_err());
        assert_eq!(fs::read_to_string(&p).unwrap(), newer);
        assert_eq!(
            store.get().last_address.as_deref(),
            Some("b"),
            "kept in memory"
        );
        fs::remove_dir_all(d).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn an_unsaved_pairing_survives_later_updates() {
        use std::os::unix::fs::PermissionsExt;
        let d = temp_dir("unsaved");
        let p = d.join("settings.json");
        let store = Store::open(Some(p.clone()));
        store.update(|s| s.client_id = Some("me".into())).unwrap();
        assert!(!store.unsaved());
        fs::set_permissions(&d, fs::Permissions::from_mode(0o500)).unwrap();
        assert!(store.put_pairing(paired("p1", 1, 1)).is_err());
        assert!(store.unsaved());
        // The file (without the pairing) must not replace memory.
        assert!(store.update(|s| s.last_address = Some("a".into())).is_err());
        assert!(store.pairing_key("p1").is_some(), "pairing kept in memory");
        fs::set_permissions(&d, fs::Permissions::from_mode(0o700)).unwrap();
        store.update(|s| s.last_address = Some("b".into())).unwrap();
        assert!(!store.unsaved());
        assert!(load(&p).unwrap().pairing("p1").is_some(), "saved at last");
        fs::remove_dir_all(d).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn unsaved_changes_never_overwrite_another_instances_changes() {
        use std::os::unix::fs::PermissionsExt;
        let d = temp_dir("unsaved-two");
        let p = d.join("settings.json");
        let a = Store::open(Some(p.clone()));
        let b = Store::open(Some(p.clone()));
        fs::set_permissions(&d, fs::Permissions::from_mode(0o500)).unwrap();
        let a_id = a.ensure_client_id();
        assert!(a.put_pairing(paired("pa", 1, 1)).is_err());
        assert!(a.unsaved());
        fs::set_permissions(&d, fs::Permissions::from_mode(0o700)).unwrap();
        // Meanwhile the other instance saves its own id and pairing.
        let b_id = b.ensure_client_id();
        assert_ne!(a_id, b_id);
        b.put_pairing(paired("pb", 2, 2)).unwrap();
        a.update(|s| s.last_address = Some("a".into())).unwrap();
        assert!(!a.unsaved());
        let on_disk = load(&p).unwrap();
        assert!(on_disk.pairing("pa").is_some(), "{on_disk:?}");
        assert!(on_disk.pairing("pb").is_some(), "{on_disk:?}");
        assert_eq!(on_disk.client_id, Some(b_id), "the saved id wins");
        assert_eq!(on_disk.last_address.as_deref(), Some("a"));
        assert_eq!(a.get(), on_disk);
        // Once saved, the change is not replayed again.
        assert!(b.remove_pairing("pa").unwrap());
        a.update(|_| ()).unwrap();
        assert!(load(&p).unwrap().pairing("pa").is_none());
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn a_file_corrupted_while_running_is_backed_up_before_a_save() {
        let d = temp_dir("hand-edit");
        let p = d.join("settings.json");
        let store = Store::open(Some(p.clone()));
        store.update(|s| s.client_id = Some("me".into())).unwrap();
        fs::write(&p, "{ hand edit").unwrap();
        store.update(|s| s.last_address = Some("a".into())).unwrap();
        assert_eq!(
            fs::read_to_string(d.join("settings.json.bad")).unwrap(),
            "{ hand edit"
        );
        assert_eq!(load(&p).unwrap().client_id.as_deref(), Some("me"));
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn the_same_contents_are_backed_up_only_once() {
        let d = temp_dir("once");
        let p = d.join("settings.json");
        let store = Store::open(Some(p.clone()));
        let newer = r#"{"clientId":"me","pairings":[{"deviceId":"x","keyV2":"…"}]}"#;
        for addr in ["a", "b", "c"] {
            fs::write(&p, newer).unwrap();
            store
                .update(|s| s.last_address = Some(addr.into()))
                .unwrap();
        }
        let backups: Vec<_> = fs::read_dir(&d)
            .unwrap()
            .filter_map(|e| e.ok()?.file_name().into_string().ok())
            .filter(|n| n.contains(".bad"))
            .collect();
        assert_eq!(backups, ["settings.json.bad"]);
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn unreadable_settings_are_never_written() {
        let d = temp_dir("io");
        // A directory where the file should be: read fails with an I/O error.
        let p = d.join("settings.json");
        fs::create_dir(&p).unwrap();
        let store = Store::open(Some(p.clone()));
        assert_eq!(store.get(), Settings::default());
        assert_eq!(store.path(), None, "no save target on an I/O error");
        // Kept in memory, but reported as not saved (the UI warns).
        let r = store.put_pairing(paired("p1", 1, 1));
        assert!(matches!(r, Err(StoreError::NotSaving(_))), "{r:?}");
        assert!(store.unsaved());
        assert!(store.pairing_key("p1").is_some());
        assert!(p.is_dir());
        // No data directory at all: the same.
        assert!(Store::open(None).put_pairing(paired("p1", 1, 1)).is_err());
        fs::remove_dir_all(d).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_file_that_becomes_unreadable_is_never_overwritten() {
        use std::os::unix::fs::PermissionsExt;
        let d = temp_dir("unreadable-later");
        let p = d.join("settings.json");
        let store = Store::open(Some(p.clone()));
        store.put_pairing(paired("old", 1, 1)).unwrap();
        let before = fs::read(&p).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o000)).unwrap();
        if fs::read(&p).is_ok() {
            // Running as root: permissions cannot make the file unreadable.
            fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
            fs::remove_dir_all(d).unwrap();
            return;
        }
        assert!(store.put_pairing(paired("new", 2, 2)).is_err());
        assert!(store.unsaved());
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(fs::read(&p).unwrap(), before, "left alone");
        // Readable again: the pending change is saved on the next update.
        store.update(|_| ()).unwrap();
        let on_disk = load(&p).unwrap();
        assert!(on_disk.pairing("old").is_some() && on_disk.pairing("new").is_some());
        fs::remove_dir_all(d).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_replayed_forget_keeps_another_instances_newer_pairing() {
        use std::os::unix::fs::PermissionsExt;
        let d = temp_dir("replay-forget");
        let p = d.join("settings.json");
        let a = Store::open(Some(p.clone()));
        let b = Store::open(Some(p.clone()));
        a.put_pairing(paired("ph", 1, 1)).unwrap();
        fs::set_permissions(&d, fs::Permissions::from_mode(0o500)).unwrap();
        assert!(a.remove_pairing("ph").is_err(), "forget not saved");
        fs::set_permissions(&d, fs::Permissions::from_mode(0o700)).unwrap();
        // The other instance pairs the phone again (a new key).
        b.put_pairing(paired("ph", 2, 2)).unwrap();
        a.update(|_| ()).unwrap();
        let key = load(&p).unwrap().pairing("ph").map(|d| d.key.clone());
        assert_eq!(key, Some(PairingKey::from_bytes([2; 32])), "re-pair kept");
        fs::remove_dir_all(d).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_replayed_pairing_never_replaces_a_newer_one() {
        use std::os::unix::fs::PermissionsExt;
        let d = temp_dir("replay-put");
        let p = d.join("settings.json");
        let a = Store::open(Some(p.clone()));
        let b = Store::open(Some(p.clone()));
        fs::set_permissions(&d, fs::Permissions::from_mode(0o500)).unwrap();
        assert!(a.put_pairing(paired("ph", 1, 1)).is_err());
        fs::set_permissions(&d, fs::Permissions::from_mode(0o700)).unwrap();
        b.put_pairing(paired("ph", 2, 2)).unwrap();
        a.update(|_| ()).unwrap();
        let key = load(&p).unwrap().pairing("ph").map(|d| d.key.clone());
        assert_eq!(key, Some(PairingKey::from_bytes([2; 32])));
        fs::remove_dir_all(d).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn the_client_id_handed_out_holds_for_the_whole_run() {
        use std::os::unix::fs::PermissionsExt;
        let d = temp_dir("cid-run");
        let p = d.join("settings.json");
        let a = Store::open(Some(p.clone()));
        let b = Store::open(Some(p.clone()));
        fs::set_permissions(&d, fs::Permissions::from_mode(0o500)).unwrap();
        let a_id = a.ensure_client_id();
        fs::set_permissions(&d, fs::Permissions::from_mode(0o700)).unwrap();
        let b_id = b.ensure_client_id();
        a.update(|_| ()).unwrap();
        assert_eq!(a.ensure_client_id(), a_id, "a keeps its id this run");
        assert_eq!(load(&p).unwrap().client_id, Some(b_id), "first saved wins");
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn good_settings_load_and_keep_their_path() {
        let d = temp_dir("ok");
        let p = d.join("settings.json");
        fs::write(&p, br#"{"clientId":"abc"}"#).unwrap();
        let store = Store::open(Some(p.clone()));
        assert_eq!(store.get().client_id.as_deref(), Some("abc"));
        assert_eq!(store.path(), Some(p.as_path()));
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn client_ids_are_hex_and_unique() {
        let a = new_client_id();
        assert_eq!(a.len(), 32);
        assert!(a.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_ne!(a, new_client_id());
    }
}
