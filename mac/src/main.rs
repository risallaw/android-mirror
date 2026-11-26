//! AndroidMirror.app entry point (macOS receiver).
//!
//! Usage: `AndroidMirror [--connect host[:port]] [--pin NNNNNN | --pin - |
//! --pin-env VAR] [--settings PATH]`
//! (development flags: `--connect` connects right away, `--pin` is the
//! pairing PIN for that first connect, `--settings` uses another settings
//! file instead of the user's). A PIN given as an argument is visible in
//! `ps` to every user on the machine; `--pin -` reads it from stdin and
//! `--pin-env VAR` from that environment variable instead.

mod hooks;
mod menu;
mod vt_decoder;

use std::ffi::OsString;
use std::io::{BufRead, IsTerminal, Read};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{mpsc, Arc};
use std::time::Duration;

use mirror_receiver::{RunOptions, VideoDecoder};
use zeroize::Zeroizing;

/// Where the PIN for the first connect comes from.
#[derive(PartialEq, Eq)]
enum PinSource {
    /// `--pin 123456`: visible in the process list.
    Literal(String),
    /// `--pin -`: first line of stdin.
    Stdin,
    /// `--pin-env VAR`.
    Env(String),
}

// Manual: a derived Debug would print the PIN.
impl std::fmt::Debug for PinSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PinSource::Literal(_) => f.write_str("Literal(<redacted>)"),
            PinSource::Stdin => f.write_str("Stdin"),
            PinSource::Env(v) => write!(f, "Env({v})"),
        }
    }
}

/// Command-line options (dev/scripting; the app needs none).
#[derive(Debug, Default, PartialEq, Eq)]
struct Args {
    connect: Option<String>,
    pin: Option<PinSource>,
    settings: Option<PathBuf>,
}

const PIN_HELP: &str = "a 6-digit PIN, or - to read it from stdin";

const LITERAL_PIN_WARNING: &str =
    "AndroidMirror: warning: --pin on the command line is visible to \
     other users in `ps`; use `--pin -` (stdin) or `--pin-env VAR` instead";

/// The PIN `source` names, checked, or why there is none. `stdin` and `env`
/// are the process's, passed in so tests need neither. Warns on stderr about
/// the literal form.
fn resolve_pin(
    source: &PinSource,
    stdin: impl FnOnce() -> std::io::Result<String>,
    env: impl Fn(&str) -> Option<OsString>,
) -> Result<Zeroizing<String>, String> {
    let raw = match source {
        PinSource::Literal(p) => {
            eprintln!("{LITERAL_PIN_WARNING}");
            Zeroizing::new(p.clone())
        }
        PinSource::Stdin => Zeroizing::new(stdin().map_err(|e| format!("reading the PIN: {e}"))?),
        PinSource::Env(var) => Zeroizing::new(
            env(var)
                .ok_or(format!("{var} is not set"))?
                .into_string()
                .map_err(|_| format!("{var} is not valid UTF-8"))?,
        ),
    };
    let pin = Zeroizing::new(raw.trim().to_string());
    if mirror_receiver::is_valid_pin(&pin) {
        Ok(pin)
    } else {
        Err("the PIN must be exactly 6 digits".into())
    }
}

/// First line of stdin, at most a few bytes (a PIN is 6). Prompts when
/// stdin is a terminal, so the app does not seem to hang, and does not echo
/// what is typed there (the PIN is a secret).
fn read_stdin_line() -> std::io::Result<String> {
    use std::os::fd::AsRawFd;
    let _quiet = std::io::stdin().is_terminal().then(|| {
        eprint!("PIN: ");
        NoEcho::on(std::io::stdin().as_raw_fd())
    });
    let mut line = String::new();
    std::io::stdin().lock().take(64).read_line(&mut line)?;
    Ok(line)
}

/// Terminal echo turned off on a tty until dropped. The typed newline is
/// still echoed, so the next output starts on its own line. Ctrl-C or a
/// SIGTERM at the prompt restores echo too (see [`restore_and_reraise`]),
/// so the shell is not left typing blind.
struct NoEcho {
    fd: libc::c_int,
    saved: libc::termios,
    /// The SIGINT/SIGTERM handlers to put back on drop (`None`: that signal
    /// was ignored, so no handler was installed for it).
    old_handlers: [(libc::c_int, Option<libc::sigaction>); 2],
}

/// The terminal settings [`restore_and_reraise`] puts back, for the fd in
/// [`SIGNAL_FD`]. Written only while `SIGNAL_FD` is -1 (no handler reads it
/// then); the handler reads it only after seeing the fd (acquire).
struct SignalTermios(std::cell::UnsafeCell<std::mem::MaybeUninit<libc::termios>>);
// SAFETY: access is ordered through `SIGNAL_FD` as described above.
unsafe impl Sync for SignalTermios {}
static SIGNAL_TERMIOS: SignalTermios =
    SignalTermios(std::cell::UnsafeCell::new(std::mem::MaybeUninit::uninit()));
/// The terminal to restore on a signal, or -1 for none.
static SIGNAL_FD: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);

/// SIGINT/SIGTERM handler while echo is off: put the terminal back, then
/// die of the same signal (the handler was installed with `SA_RESETHAND`,
/// so the default action runs once this returns). Only async-signal-safe
/// calls: an atomic load, `tcsetattr`, `raise`.
extern "C" fn restore_and_reraise(sig: libc::c_int) {
    let fd = SIGNAL_FD.load(std::sync::atomic::Ordering::Acquire);
    if fd >= 0 {
        // SAFETY: the termios was fully written before `fd` was published.
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, SIGNAL_TERMIOS.0.get().cast()) };
    }
    // SAFETY: re-raising the signal being handled; it is blocked until this
    // handler returns, then takes its default action.
    unsafe { libc::raise(sig) };
}

/// Install [`restore_and_reraise`] for `sig` unless the signal is ignored.
/// Returns the previous action to put back (`None`: left alone).
fn install_restore_handler(sig: libc::c_int) -> Option<libc::sigaction> {
    // SAFETY: plain sigaction calls with valid (zeroed, then filled) structs.
    unsafe {
        let mut old: libc::sigaction = std::mem::zeroed();
        if libc::sigaction(sig, std::ptr::null(), &mut old) != 0
            || old.sa_sigaction == libc::SIG_IGN
        {
            // Ignored (e.g. started with nohup): must stay ignored.
            return None;
        }
        let mut new: libc::sigaction = std::mem::zeroed();
        new.sa_sigaction = restore_and_reraise as extern "C" fn(libc::c_int) as libc::sighandler_t;
        new.sa_flags = libc::SA_RESETHAND;
        libc::sigemptyset(&mut new.sa_mask);
        (libc::sigaction(sig, &new, &mut old) == 0).then_some(old)
    }
}

impl NoEcho {
    /// `None` (echo left as is) when `fd` is not a terminal.
    fn on(fd: libc::c_int) -> Option<NoEcho> {
        let mut t = std::mem::MaybeUninit::<libc::termios>::uninit();
        // SAFETY: `tcgetattr` fills the struct on success (checked) and only
        // reads `fd`, which the caller keeps open while `NoEcho` lives.
        let saved = unsafe {
            if libc::tcgetattr(fd, t.as_mut_ptr()) != 0 {
                return None;
            }
            t.assume_init()
        };
        let mut quiet = saved;
        quiet.c_lflag &= !libc::ECHO;
        quiet.c_lflag |= libc::ECHONL;
        // Publish what a signal must restore before echo goes off. Only one
        // NoEcho lives at a time (one PIN prompt), so nothing else writes it.
        // SAFETY: `SIGNAL_FD` is -1, so no handler reads the termios now.
        unsafe { (*SIGNAL_TERMIOS.0.get()).write(saved) };
        SIGNAL_FD.store(fd, std::sync::atomic::Ordering::Release);
        let old_handlers = [libc::SIGINT, libc::SIGTERM].map(|s| (s, install_restore_handler(s)));
        let on = NoEcho {
            fd,
            saved,
            old_handlers,
        };
        // SAFETY: `quiet` is a valid termios read from this same fd.
        // On failure `on` is dropped, which undoes the steps above.
        (unsafe { libc::tcsetattr(fd, libc::TCSANOW, &quiet) } == 0).then_some(on)
    }
}

impl Drop for NoEcho {
    fn drop(&mut self) {
        for (sig, old) in &self.old_handlers {
            if let Some(old) = old {
                // SAFETY: puts back the action `sigaction` returned in `on`.
                unsafe { libc::sigaction(*sig, old, std::ptr::null_mut()) };
            }
        }
        SIGNAL_FD.store(-1, std::sync::atomic::Ordering::Release);
        // SAFETY: restores the settings read from this fd in `on`.
        unsafe { libc::tcsetattr(self.fd, libc::TCSANOW, &self.saved) };
    }
}

/// The value of `var`, removed from the environment so child processes
/// (`scutil`) do not inherit the PIN. Call before any thread starts:
/// changing the environment races with other threads reading it. `var`
/// must be a valid name (see [`valid_env_name`]); std panics otherwise.
fn take_env(var: &str) -> Option<OsString> {
    let value = std::env::var_os(var);
    std::env::remove_var(var);
    value
}

/// A name `std::env` accepts: not empty, no `=` and no NUL.
fn valid_env_name(name: &str) -> bool {
    !name.is_empty() && !name.contains(['=', '\0'])
}

/// Parse command-line arguments (without the program name).
fn parse_args(args: impl IntoIterator<Item = String>) -> Result<Args, String> {
    let mut out = Args::default();
    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        // `--flag value` or `--flag=value`.
        let (flag, inline) = match a.split_once('=') {
            Some((f, v)) if f.starts_with("--") => (f.to_string(), Some(v.to_string())),
            _ => (a.clone(), None),
        };
        let mut value = |what: &str| {
            inline
                .clone()
                .or_else(|| it.next())
                .ok_or(format!("{flag} needs {what}"))
        };
        match flag.as_str() {
            "--connect" => out.connect = Some(value("host[:port]")?),
            "--pin" => {
                let pin = value(PIN_HELP)?;
                out.pin = Some(if pin == "-" {
                    PinSource::Stdin
                } else if mirror_receiver::is_valid_pin(&pin) {
                    PinSource::Literal(pin)
                } else {
                    return Err("--pin must be exactly 6 digits (or - for stdin)".into());
                });
            }
            "--pin-env" => {
                let var = value("an environment variable name")?;
                if !valid_env_name(&var) {
                    return Err(format!("--pin-env: {var:?} is not a variable name"));
                }
                out.pin = Some(PinSource::Env(var));
            }
            "--settings" => out.settings = Some(PathBuf::from(value("a file path")?)),
            // Process serial number added by older Finder launches.
            _ if a.starts_with("-psn_") => {}
            _ => return Err(format!("unknown argument: {a}")),
        }
    }
    Ok(out)
}

/// How long app start may wait for the computer name.
const NAME_TIMEOUT: Duration = Duration::from_secs(2);

/// `clientName` shown on the phone: the Mac's computer name.
fn client_name() -> String {
    let mut cmd = Command::new("scutil");
    cmd.args(["--get", "ComputerName"]);
    name_from(cmd, NAME_TIMEOUT)
}

/// Trimmed stdout of `cmd`, or "Mac" when it fails, prints nothing or takes
/// longer than `timeout` (a stuck helper must not block app start; it is
/// left to finish on its own thread).
fn name_from(mut cmd: Command, timeout: Duration) -> String {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let name = cmd
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .ok()
            .filter(|o| o.status.success())
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let _ = tx.send(name);
    });
    rx.recv_timeout(timeout)
        .ok()
        .flatten()
        .unwrap_or_else(|| "Mac".to_string())
}

fn main() {
    let args = match parse_args(std::env::args().skip(1)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("AndroidMirror: {e}\nusage: AndroidMirror [--connect host[:port]] [--pin NNNNNN | --pin - | --pin-env VAR] [--settings PATH]");
            std::process::exit(2);
        }
    };
    let pin = args.pin.as_ref().map(|source| {
        // Still single-threaded here (see `take_env`).
        resolve_pin(source, read_stdin_line, take_env).unwrap_or_else(|e| {
            eprintln!("AndroidMirror: {e}");
            std::process::exit(2);
        })
    });
    let factory: mirror_receiver::DecoderFactory =
        Arc::new(|out| Box::new(vt_decoder::VtDecoder::new(out)) as Box<dyn VideoDecoder>);
    let options = RunOptions {
        client_name: client_name(),
        auto_connect: args.connect,
        settings_path: args.settings,
        pin,
    };
    if let Err(e) = mirror_receiver::run(Box::new(hooks::MacHooks), factory, options) {
        eprintln!("AndroidMirror: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn literal_pin_warning_reads_as_one_sentence() {
        let w = super::LITERAL_PIN_WARNING;
        assert!(
            !w.contains("  ") && w.contains("to other users in `ps`"),
            "{w}"
        );
    }

    use super::{name_from, parse_args, resolve_pin, take_env, Args, NoEcho, PinSource};
    use std::ffi::OsString;
    use std::path::PathBuf;
    use std::process::Command;
    use std::time::{Duration, Instant};

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn flag_forms() {
        assert_eq!(parse_args(args(&[])), Ok(Args::default()));
        let a = parse_args(args(&["--connect", "127.0.0.1:47800", "--pin=246810"])).unwrap();
        assert_eq!(a.connect.as_deref(), Some("127.0.0.1:47800"));
        assert_eq!(a.pin, Some(PinSource::Literal("246810".into())));
        let a = parse_args(args(&["--connect=10.0.0.2", "--settings", "/tmp/s.json"])).unwrap();
        assert_eq!(a.connect.as_deref(), Some("10.0.0.2"));
        assert_eq!(a.settings, Some(PathBuf::from("/tmp/s.json")));
        assert!(parse_args(args(&["--connect"])).is_err());
        assert!(parse_args(args(&["--pin", "12345"])).is_err());
        let a = parse_args(args(&["--pin", "-"])).unwrap();
        assert_eq!(a.pin, Some(PinSource::Stdin));
        let a = parse_args(args(&["--pin-env", "MIRROR_PIN"])).unwrap();
        assert_eq!(a.pin, Some(PinSource::Env("MIRROR_PIN".into())));
        assert!(parse_args(args(&["--pin-env"])).is_err());
        for bad in ["", "A=B", "A\0B"] {
            assert!(parse_args(args(&["--pin-env", bad])).is_err(), "{bad:?}");
        }
        assert!(parse_args(args(&["--pin-env=A=B"])).is_err());
        assert!(parse_args(args(&["--bogus"])).is_err());
        assert_eq!(parse_args(args(&["-psn_0_12345"])), Ok(Args::default()));
    }

    #[test]
    fn pin_from_stdin_or_env_is_trimmed_and_checked() {
        let no_env = |_: &str| None;
        let ok = |s: &str| Ok(s.to_string());
        let pin = |src, stdin: std::io::Result<String>, env: Option<&str>| {
            resolve_pin(&src, || stdin, |_| env.map(OsString::from)).map(|p| p.to_string())
        };
        assert_eq!(
            pin(PinSource::Stdin, ok("123456\n"), None),
            Ok("123456".into())
        );
        assert_eq!(
            pin(PinSource::Stdin, ok(" 012345 \r\n"), None),
            Ok("012345".into())
        );
        assert!(pin(PinSource::Stdin, ok(""), None).is_err(), "empty stdin");
        assert!(pin(PinSource::Stdin, ok("12345\n"), None).is_err());
        assert!(pin(PinSource::Stdin, ok("1234567\n"), None).is_err());
        assert!(pin(
            PinSource::Stdin,
            Err(std::io::ErrorKind::BrokenPipe.into()),
            None
        )
        .is_err());
        let env = PinSource::Env("P".into());
        assert_eq!(pin(env, ok(""), Some("654321")), Ok("654321".into()));
        assert!(
            pin(PinSource::Env("P".into()), ok(""), None).is_err(),
            "unset"
        );
        assert!(pin(PinSource::Env("P".into()), ok(""), Some("abcdef")).is_err());
        {
            use std::os::unix::ffi::OsStringExt;
            let not_utf8 = |_: &str| Some(OsString::from_vec(vec![b'1', 0xff]));
            let err = resolve_pin(&PinSource::Env("P".into()), || ok(""), not_utf8).unwrap_err();
            assert!(err.contains("UTF-8"), "{err}");
        }
        assert_eq!(
            resolve_pin(&PinSource::Literal("246810".into()), || ok(""), no_env)
                .map(|p| p.to_string()),
            Ok("246810".into())
        );
        assert!(!format!("{:?}", PinSource::Literal("246810".into())).contains("246810"));
    }

    #[test]
    fn a_pin_from_the_environment_is_not_inherited() {
        let var = "MIRROR_MAC_TEST_TAKE_ENV";
        std::env::set_var(var, "123456");
        assert_eq!(take_env(var), Some("123456".into()));
        assert!(std::env::var_os(var).is_none(), "removed");
        assert_eq!(take_env(var), None);
    }

    #[test]
    fn echo_is_off_while_reading_the_pin_and_restored_after() {
        let (mut leader, mut follower) = (0, 0);
        // SAFETY: openpty writes two fds; the null pointers are optional.
        let r = unsafe {
            libc::openpty(
                &mut leader,
                &mut follower,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(r, 0, "openpty");
        let lflag = |fd| {
            let mut t = std::mem::MaybeUninit::<libc::termios>::uninit();
            // SAFETY: as in `NoEcho::on`.
            unsafe {
                assert_eq!(libc::tcgetattr(fd, t.as_mut_ptr()), 0);
                t.assume_init().c_lflag
            }
        };
        let before = lflag(follower);
        assert_ne!(before & libc::ECHO, 0, "a new pty echoes");
        let handler_before = sigint_handler();
        let quiet = NoEcho::on(follower).expect("a tty");
        assert_eq!(lflag(follower) & libc::ECHO, 0);
        drop(quiet);
        assert_eq!(lflag(follower), before, "restored");
        assert_eq!(sigint_handler(), handler_before, "Ctrl-C handler put back");
        // SAFETY: closing the fds openpty gave us.
        unsafe {
            libc::close(leader);
            libc::close(follower);
        }
        let devnull = std::fs::File::open("/dev/null").unwrap();
        use std::os::fd::AsRawFd;
        assert!(NoEcho::on(devnull.as_raw_fd()).is_none(), "not a tty");
    }

    fn sigint_handler() -> libc::sighandler_t {
        // SAFETY: reads the current action into a zeroed struct.
        unsafe {
            let mut cur: libc::sigaction = std::mem::zeroed();
            assert_eq!(libc::sigaction(libc::SIGINT, std::ptr::null(), &mut cur), 0);
            cur.sa_sigaction
        }
    }

    fn lflag_of(fd: libc::c_int) -> libc::tcflag_t {
        let mut t = std::mem::MaybeUninit::<libc::termios>::uninit();
        // SAFETY: as in `NoEcho::on`.
        unsafe {
            assert_eq!(libc::tcgetattr(fd, t.as_mut_ptr()), 0);
            t.assume_init().c_lflag
        }
    }

    const NOECHO_CHILD: &str = "MIRROR_MAC_NOECHO_CHILD";
    const NOECHO_READY: &str = "NOECHO-READY";

    /// Child half of `a_signal_at_the_pin_prompt_restores_echo` (does
    /// nothing in a normal test run): echo off on stdin, a pty, then wait
    /// for the signal.
    #[test]
    fn noecho_child() {
        if std::env::var_os(NOECHO_CHILD).is_none() {
            return;
        }
        // Like a fresh app, whatever this test run inherited (a background
        // shell job ignores SIGINT).
        // SAFETY: resetting two signals to their default action.
        unsafe {
            libc::signal(libc::SIGINT, libc::SIG_DFL);
            libc::signal(libc::SIGTERM, libc::SIG_DFL);
        }
        let _quiet = NoEcho::on(0).expect("stdin is a pty");
        println!("{NOECHO_READY}");
        std::thread::sleep(Duration::from_secs(30));
    }

    #[test]
    fn a_signal_at_the_pin_prompt_restores_echo() {
        use std::io::BufRead;
        use std::os::fd::{FromRawFd, OwnedFd};
        use std::os::unix::process::ExitStatusExt;
        for sig in [libc::SIGINT, libc::SIGTERM] {
            let (mut leader, mut follower) = (0, 0);
            // SAFETY: openpty writes two fds; the null pointers are optional.
            let r = unsafe {
                libc::openpty(
                    &mut leader,
                    &mut follower,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            assert_eq!(r, 0, "openpty");
            let before = lflag_of(follower);
            // SAFETY: a fresh duplicate, owned by the child's stdin.
            let stdin = unsafe { OwnedFd::from_raw_fd(libc::dup(follower)) };
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "tests::noecho_child", "--nocapture"])
                .env(NOECHO_CHILD, "1")
                .stdin(stdin)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap();
            let out = std::io::BufReader::new(child.stdout.take().unwrap());
            let ready = out
                .lines()
                .map_while(Result::ok)
                .any(|l| l.contains(NOECHO_READY));
            assert!(ready, "child reached the prompt");
            assert_eq!(lflag_of(follower) & libc::ECHO, 0, "echo off in the child");
            // SAFETY: signalling our own child.
            unsafe { libc::kill(child.id() as libc::pid_t, sig) };
            let status = child.wait().unwrap();
            assert_eq!(status.signal(), Some(sig), "died of the signal");
            assert_eq!(lflag_of(follower), before, "echo restored ({sig})");
            // SAFETY: closing the fds openpty gave us.
            unsafe {
                libc::close(leader);
                libc::close(follower);
            }
        }
    }

    fn sh(script: &str) -> Command {
        let mut c = Command::new("/bin/sh");
        c.args(["-c", script]);
        c
    }

    #[test]
    fn computer_name_falls_back_and_never_blocks() {
        let t = Duration::from_secs(5);
        assert_eq!(name_from(sh("echo '  Studio Mac  '"), t), "Studio Mac");
        assert_eq!(name_from(sh("echo '   '"), t), "Mac");
        assert_eq!(name_from(sh("echo name; exit 1"), t), "Mac");
        assert_eq!(name_from(Command::new("/nonexistent/scutil"), t), "Mac");
        let start = Instant::now();
        assert_eq!(
            name_from(sh("sleep 3; echo late"), Duration::from_millis(100)),
            "Mac"
        );
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "timed out promptly"
        );
    }
}
