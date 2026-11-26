//! Command-line behaviour of the bins (no ffmpeg needed): usage errors and
//! the protocol v2 flow between `fakeserver` and `rawclient` processes.

use std::io::{BufRead, BufReader, Read};
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

const T: Duration = Duration::from_secs(10);

#[test]
fn fakeserver_rejects_overflowing_rotate_every_with_usage_error() {
    let out = Command::new(env!("CARGO_BIN_EXE_fakeserver"))
        .args(["nonexistent.h264", "--rotate-every", "1e30"])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(2),
        "must be a usage error, not a panic"
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("too large"));
}

#[test]
fn fakeserver_rejects_a_malformed_pin() {
    for pin in ["12345", "1234567", "12345a"] {
        let out = Command::new(env!("CARGO_BIN_EXE_fakeserver"))
            .args(["nonexistent.h264", "--pin", pin])
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2), "{pin}");
        assert!(String::from_utf8_lossy(&out.stderr).contains("6 digits"));
    }
}

/// Kills and reaps the child on drop.
struct Proc(Child);
impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A unique, self-deleting temp directory.
struct TempDir(PathBuf);
impl TempDir {
    fn new(tag: &str) -> TempDir {
        let p = std::env::temp_dir().join(format!("mirror-cli-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// 1080p SPS + PPS + one IDR + one P slice.
fn write_clip(dir: &TempDir) -> PathBuf {
    let mut d = vec![0, 0, 0, 1];
    d.extend([
        0x67, 0x64, 0x00, 0x28, 0xAC, 0xD9, 0x40, 0x78, 0x02, 0x27, 0xE5, 0xC0, 0x44, 0x00, 0x00,
        0x03, 0x00, 0x04, 0x00, 0x00, 0x03, 0x00, 0xF0, 0x3C, 0x60, 0xC6, 0x58,
    ]);
    d.extend([0, 0, 0, 1, 0x68, 0xCE, 0x3C, 0x80]);
    d.extend([0, 0, 0, 1, 0x65, 0x88, 1, 2, 3]);
    d.extend([0, 0, 0, 1, 0x41, 0x80, 4, 5, 6]);
    let path = dir.0.join("clip.h264");
    std::fs::write(&path, d).unwrap();
    path
}

/// A running `fakeserver --port 0 --loop <extra>`; its stderr lines are
/// drained into `lines` (so the pipe never blocks it).
struct FakeServer {
    _proc: Proc,
    port: u16,
    lines: Receiver<String>,
}

impl FakeServer {
    fn start(clip: &PathBuf, extra: &[&str]) -> FakeServer {
        let mut child = Command::new(env!("CARGO_BIN_EXE_fakeserver"))
            .arg(clip)
            .args(["--port", "0", "--loop"])
            .args(extra)
            .env("MIRROR_LOG", "info")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let (tx, lines) = mpsc::channel();
        let err = child.stderr.take().unwrap();
        thread::spawn(move || {
            for l in BufReader::new(err).lines().map_while(Result::ok) {
                let _ = tx.send(l);
            }
        });
        let mut s = FakeServer {
            _proc: Proc(child),
            port: 0,
            lines,
        };
        let l = s.line_with("listening on ");
        s.port = l.rsplit(':').next().unwrap().trim().parse().unwrap();
        s
    }

    /// The next stderr line containing `pat`.
    fn line_with(&self, pat: &str) -> String {
        loop {
            let l = self
                .lines
                .recv_timeout(T)
                .unwrap_or_else(|_| panic!("fakeserver never printed {pat:?}"));
            if l.contains(pat) {
                return l;
            }
        }
    }

    fn pin(&self) -> String {
        let l = self.line_with("PIN: ");
        l.rsplit("PIN: ").next().unwrap().trim().to_string()
    }
}

/// rawclient with its own settings/pairings file in `dir` (never the
/// shared default).
fn rawclient(dir: &TempDir, port: u16, extra: &[&str]) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_rawclient"));
    c.arg(format!("127.0.0.1:{port}"))
        .arg("--store")
        .arg(dir.0.join("rawclient.json"))
        .args(extra);
    c
}

/// Run rawclient until it wrote the SPS/PPS of the first VIDEO_CONFIG to
/// stdout, then kill it.
fn assert_streams(mut cmd: Command) {
    let child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut p = Proc(child);
    let mut out = p.0.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut b = [0u8; 5];
        let _ = tx.send(out.read_exact(&mut b).map(|_| b));
    });
    let head = rx
        .recv_timeout(T)
        .expect("rawclient wrote nothing")
        .expect("rawclient stdout");
    assert_eq!(head, [0, 0, 0, 1, 0x67], "starts with the SPS");
}

/// Run rawclient to completion (bounded by the server's handshake).
fn run_to_end(mut cmd: Command) -> Output {
    let child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let _ = tx.send(child.wait_with_output());
    });
    rx.recv_timeout(T)
        .expect("rawclient did not exit")
        .expect("rawclient output")
}

#[test]
fn rawclient_pairs_with_the_pin_and_streams() {
    let dir = TempDir::new("pin");
    let clip = write_clip(&dir);
    let store = dir.0.join("pairings.json");
    let server = FakeServer::start(
        &clip,
        &[
            "--pin",
            "135790",
            "--pairing-store",
            store.to_str().unwrap(),
        ],
    );
    assert_eq!(server.pin(), "135790");

    // Pairing is required: without a PIN rawclient fails at once.
    let out = run_to_end(rawclient(&dir, server.port, &[]));
    assert_eq!(
        out.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    assert_streams(rawclient(&dir, server.port, &["--pin", "135790"]));
    server.line_with("paired");
    let saved = std::fs::read_to_string(&store).unwrap();
    assert!(saved.contains("rawclient"), "{saved}");

    // The stored key works without the PIN; a restarted fakeserver loads
    // the pairing from its store.
    assert_streams(rawclient(&dir, server.port, &[]));
    drop(server);
    let server = FakeServer::start(
        &clip,
        &[
            "--pin",
            "135790",
            "--pairing-store",
            store.to_str().unwrap(),
        ],
    );
    assert_streams(rawclient(&dir, server.port, &[]));
}

#[test]
fn random_pin_is_printed_and_no_auth_needs_both_flags() {
    let dir = TempDir::new("noauth");
    let clip = write_clip(&dir);

    // Default: a random PIN on stderr, `none` refused.
    let server = FakeServer::start(&clip, &[]);
    let pin = server.pin();
    assert!(
        pin.len() == 6 && pin.bytes().all(|b| b.is_ascii_digit()),
        "{pin}"
    );
    let out = run_to_end(rawclient(&dir, server.port, &["--allow-no-auth"]));
    assert_eq!(out.status.code(), Some(1));
    assert_streams(rawclient(&dir, server.port, &["--pin", &pin]));
    drop(server);

    // `--no-auth` + `--allow-no-auth`: the old devtools flow (fresh
    // rawclient settings: a new fakeserver process forgot the pairing).
    let fresh = TempDir::new("noauth-client");
    let server = FakeServer::start(&clip, &["--no-auth"]);
    assert_streams(rawclient(&fresh, server.port, &["--allow-no-auth"]));
}

/// The default settings dir lives in the (maybe shared) temp dir: rawclient
/// creates it 0700 and refuses a symlink or a directory others can access.
#[cfg(unix)]
#[test]
fn rawclient_default_store_dir_must_be_private() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = TempDir::new("private");
    let dir = tmp.0.join("androidmirror-rawclient");
    // Nothing listens on port 1: past the store check it fails to connect (1).
    let run = || {
        Command::new(env!("CARGO_BIN_EXE_rawclient"))
            .arg("127.0.0.1:1")
            .env("TMPDIR", &tmp.0)
            .output()
            .unwrap()
    };
    let out = run();
    assert_eq!(
        out.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700);

    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    let out = run();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("other users"));

    std::fs::remove_dir_all(&dir).unwrap();
    let elsewhere = tmp.0.join("attacker");
    std::fs::create_dir(&elsewhere).unwrap();
    std::os::unix::fs::symlink(&elsewhere, &dir).unwrap();
    let out = run();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("not a directory"));
    assert_eq!(
        std::fs::read_dir(&elsewhere).unwrap().count(),
        0,
        "nothing written"
    );
}
