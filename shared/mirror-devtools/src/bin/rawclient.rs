//! `rawclient <host[:port]> [--pin NNNNNN] [--allow-no-auth] [--store PATH]
//!  [--max-long-edge N] [--fps N]`
//!
//! Connects with protocol v2 (`--pin` if given, else the stored pairing key,
//! else `none` when `--allow-no-auth`), and writes the received video as a raw Annex-B
//! stream to stdout (SPS/PPS on every config, frames from the first keyframe
//! after a config). Status goes to stderr. Example:
//! `rawclient 127.0.0.1 --pin 123456 | ffplay -f h264 -fflags nobuffer -`.
//!
//! The settings/pairings file (`--store`) keeps this tool's client id and
//! pairing keys between runs (same format as the Mac app's settings.json,
//! mode 0600). Default: `<temp dir>/androidmirror-rawclient/settings.json`;
//! on Unix that directory must be private (0700, not a symlink; created so),
//! since the temp dir may be shared (`/tmp`).
//!
//! Strings from the phone (names, errors) are printed with terminal control
//! characters replaced.
//!
//! Exit codes: 0 clean end (server BYE, Ctrl-C, stdout closed), 1 connect or
//! handshake failure (including auth: pairing required, wrong PIN, ...) or a
//! stdout write error, 2 usage, 3 connection lost.

use std::io::{self, Write};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use mirror_devtools::{init_logger, printable};
use mirror_protocol::DEFAULT_PORT;
use mirror_receiver::store::Store;
use mirror_receiver::{
    is_valid_pin, Client, ClientConfig, ClientEvent, DisconnectReason, FrameGate, GateAction,
};

const USAGE: &str = "\
usage: rawclient <host[:port]> [options]

  --pin NNNNNN       pair using the 6-digit PIN shown on the phone
                     (takes precedence over a stored pairing key; the new
                     key replaces it)
  --allow-no-auth    permit auth mode `none` (unauthenticated, still encrypted;
                     devtools servers only)
  --store PATH       settings/pairings file (client id + pairing keys, 0600)
                     [default: <temp dir>/androidmirror-rawclient/settings.json]
  --max-long-edge N  ask the sender to scale the long edge to at most N
  --fps N            ask the sender for at most N fps

Writes raw H.264 Annex-B to stdout; status goes to stderr.";

/// `<temp dir>/androidmirror-rawclient/settings.json`, its directory made
/// private: in a shared temp dir another user could otherwise plant a
/// symlink there (and read or redirect our pairing keys).
fn default_store_path() -> Result<PathBuf, String> {
    let dir = std::env::temp_dir().join("androidmirror-rawclient");
    private_dir(&dir).map_err(|e| format!("{}: {e} (or pass --store PATH)", dir.display()))?;
    Ok(dir.join("settings.json"))
}

/// Create `dir` with mode 0700, or check an existing one is a real
/// directory (not a symlink) that only its owner can access. (An attacker's
/// own 0700 directory is not accessible to us, so writing into it fails.)
#[cfg(unix)]
fn private_dir(dir: &std::path::Path) -> io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    match std::fs::DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => return Ok(()),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    let m = std::fs::symlink_metadata(dir)?;
    if !m.file_type().is_dir() {
        return Err(io::Error::other("exists and is not a directory (symlink?)"));
    }
    if m.permissions().mode() & 0o077 != 0 {
        return Err(io::Error::other(
            "is accessible to other users (needs mode 0700)",
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn private_dir(dir: &std::path::Path) -> io::Result<()> {
    std::fs::create_dir_all(dir)
}

fn resolve(s: &str) -> Result<SocketAddr, String> {
    if let Ok(a) = s.parse::<SocketAddr>() {
        return Ok(a);
    }
    if let Ok(ip) = s.trim_matches(['[', ']']).parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, DEFAULT_PORT));
    }
    let with_port = if s.contains(':') {
        s.to_string()
    } else {
        format!("{s}:{DEFAULT_PORT}")
    };
    with_port
        .to_socket_addrs()
        .map_err(|e| format!("cannot resolve {s}: {e}"))?
        .next()
        .ok_or(format!("cannot resolve {s}"))
}

fn parse() -> Result<(SocketAddr, ClientConfig), String> {
    let mut args = std::env::args().skip(1);
    let mut host = None;
    let mut store_path = None;
    // The client id is filled in from the store below.
    let mut cfg = ClientConfig::new("rawclient", "");
    while let Some(a) = args.next() {
        let mut val = |n: &str| args.next().ok_or(format!("{n} needs a value"));
        match a.as_str() {
            "--pin" => {
                let pin = val("--pin")?;
                if !is_valid_pin(&pin) {
                    return Err("--pin: expected 6 digits".into());
                }
                cfg.pin = Some(pin.into());
            }
            "--allow-no-auth" => cfg.allow_no_auth = true,
            "--store" => store_path = Some(PathBuf::from(val("--store")?)),
            "--max-long-edge" => {
                cfg.start.max_long_edge = Some(
                    val("--max-long-edge")?
                        .parse()
                        .map_err(|e| format!("--max-long-edge: {e}"))?,
                )
            }
            "--fps" => {
                cfg.start.max_fps = Some(val("--fps")?.parse().map_err(|e| format!("--fps: {e}"))?)
            }
            "-h" | "--help" => return Err(String::new()),
            s if s.starts_with("--") => return Err(format!("unknown option {s}")),
            s if host.is_none() => host = Some(s.to_string()),
            s => return Err(format!("unexpected argument {s}")),
        }
    }
    let addr = resolve(&host.ok_or("missing <host[:port]>")?)?;

    // A stable client id per store: the phone keys our pairing by it.
    let store_path = match store_path {
        Some(p) => p,
        None => default_store_path()?,
    };
    let store = Store::open(Some(store_path));
    cfg.client_id = store.ensure_client_id();
    cfg.store = store;
    Ok((addr, cfg))
}

fn main() -> ExitCode {
    init_logger();
    let (addr, cfg) = match parse() {
        Ok(v) => v,
        Err(e) => {
            if !e.is_empty() {
                eprintln!("error: {e}");
            }
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    // Until the handler is installed (after connecting), Ctrl-C ends the
    // process at once, also during a slow connect or handshake.
    let mut client = match Client::connect(addr, cfg) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {addr}: {}", printable(&e.to_string()));
            match e {
                DisconnectReason::NeedsPin { .. } | DisconnectReason::PairingRemoved { .. } => {
                    eprintln!("hint: rerun with --pin <the PIN shown on the phone>")
                }
                DisconnectReason::AuthUnsupported { .. } => {
                    eprintln!("hint: a devtools server without auth needs --allow-no-auth")
                }
                _ => {}
            }
            return ExitCode::from(1);
        }
    };
    let quit = Arc::new(AtomicBool::new(false));
    let q = quit.clone();
    if let Err(e) = ctrlc::set_handler(move || q.store(true, Ordering::SeqCst)) {
        // Ctrl-C still works (the default handler kills us), just without
        // the clean BYE to the phone.
        eprintln!("warning: cannot install Ctrl-C handler: {e}");
    }
    let events = client.events();
    let mut out = io::stdout().lock();
    let mut gate = FrameGate::new();
    let (mut frames, mut bytes) = (0u64, 0u64);
    let code = loop {
        if quit.load(Ordering::SeqCst) {
            break 0;
        }
        let ev = match events.recv_timeout(Duration::from_millis(100)) {
            Ok(ev) => ev,
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => continue,
            Err(_) => break 3,
        };
        let res: io::Result<()> = match ev {
            ClientEvent::Connected { addr, server, auth } => {
                eprintln!(
                    "connected to {} ({}) at {addr}, auth {}",
                    printable(&server.device_name),
                    printable(&server.model),
                    auth.as_str().unwrap_or("?")
                );
                Ok(())
            }
            ClientEvent::Paired { device_name, .. } => {
                eprintln!(
                    "paired with {}; the key is stored for next time",
                    printable(&device_name)
                );
                Ok(())
            }
            ClientEvent::VideoConfig(c) => {
                eprintln!(
                    "config {}x{} display {}x{} rotation {}",
                    c.width, c.height, c.display_width, c.display_height, c.rotation
                );
                gate.on_config();
                out.write_all(&c.sps_pps).and_then(|_| out.flush())
            }
            ClientEvent::VideoFrame(f) => {
                let key = f.is_keyframe();
                let disc = f.is_discontinuity();
                match gate.on_frame(key, disc, Instant::now()) {
                    GateAction::Decode => {
                        frames += 1;
                        bytes += f.data.len() as u64;
                        out.write_all(&f.data).and_then(|_| out.flush())
                    }
                    GateAction::Drop => Ok(()),
                    GateAction::DropAndRequestKeyframe => {
                        let _ = client.request_keyframe();
                        Ok(())
                    }
                }
            }
            ClientEvent::Status(s) => {
                eprintln!("status: {s:?}");
                Ok(())
            }
            ClientEvent::Rtt(r) => {
                eprintln!(
                    "rtt {:.1} ms ({frames} frames, {bytes} bytes)",
                    r.as_secs_f64() * 1e3
                );
                Ok(())
            }
            ClientEvent::Disconnected(r) => {
                eprintln!("disconnected: {}", printable(&r.to_string()));
                break match r {
                    DisconnectReason::Closed | DisconnectReason::Bye(_) => 0,
                    _ => 3,
                };
            }
            // Supervisor-only events; not produced by a bare Client.
            _ => Ok(()),
        };
        if let Err(e) = res {
            if e.kind() != io::ErrorKind::BrokenPipe {
                eprintln!("error: writing stdout: {e}");
                client.close();
                return ExitCode::from(1);
            }
            eprintln!("stdout closed, exiting");
            break 0;
        }
    };
    client.close();
    ExitCode::from(code)
}
