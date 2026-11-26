//! `fakeserver <file.h264> [--port 47800] [--fps 60] [--loop] [--rotate-every SECS]
//!             [--pin NNNNNN] [--no-auth] [--pairing-store PATH] [--control]`
//!
//! Serves an Annex-B H.264 file over the mirror protocol (protocol v2,
//! loopback allowed). With `--rotate-every` it periodically sends a new
//! VIDEO_CONFIG with width/height swapped to simulate rotation; the video
//! content itself stays the same.
//!
//! Pairing is required by default, as on the phone: the PIN is random,
//! printed to stderr (`PIN: NNNNNN`, again after every change) and rotated
//! like the app does. `--pin` fixes it (tests; never rotated),
//! `--pairing-store` persists pairings (default: in memory), `--no-auth`
//! also accepts auth mode `none`. `--control` reports control as available
//! and logs received input (only paired sessions get control).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use mirror_devtools::{init_logger, printable, FakeOptions, FileSource, H264Stream};
use mirror_sender::mirror_protocol::{GestureKind, GlobalAction, Key, TouchPhase};
use mirror_sender::{
    is_valid_pin, ClientInfo, ClientState, ControlSink, HostError, HostEvents, NoControl,
    PairedClient, PixelPoint, Server, ServerConfig,
};

const USAGE: &str = "usage: fakeserver <file.h264> [--port 47800] [--fps 60] [--loop] \
[--rotate-every SECS] [--pin NNNNNN] [--no-auth] [--pairing-store PATH] [--control]";

struct LogEvents;
impl HostEvents for LogEvents {
    fn client_state(&self, state: ClientState, c: &ClientInfo) {
        log::info!(
            "client {} ({}, auth {:?}) {:?}",
            printable(&c.name),
            c.peer,
            c.auth,
            state
        );
    }
    fn error(&self, e: &HostError) {
        log::error!("{e}");
    }
    fn pin_changed(&self, pin: &str) {
        // The fake "phone screen": print the PIN for the user / test.
        eprintln!("PIN: {pin}");
    }
    // The server already logs pairings and failed attempts at info/warn;
    // these only show the host-event view, for debugging.
    fn paired(&self, c: &PairedClient) {
        log::debug!(
            "event: paired {} ({})",
            printable(&c.client_name),
            printable(&c.client_id)
        );
    }
    fn pairing_failed(&self, peer: SocketAddr, attempts_left: u32, locked: Option<Duration>) {
        log::debug!(
            "event: PIN attempt from {peer} failed; {attempts_left} left, locked {locked:?}"
        );
    }
}

/// Logs input from paired receivers (`--control`).
struct LogControl;
impl ControlSink for LogControl {
    fn gesture(&self, kind: GestureKind, points: &[PixelPoint]) {
        log::info!("control: gesture {kind:?} {points:?}");
    }
    fn touch_live(&self, phase: TouchPhase, x: u32, y: u32) {
        log::info!("control: touch {phase:?} ({x}, {y})");
    }
    fn scroll(&self, x: u32, y: u32, dx: i32, dy: i32) {
        log::info!("control: scroll at ({x}, {y}) by ({dx}, {dy})");
    }
    fn global_action(&self, action: GlobalAction) {
        log::info!("control: global action {action:?}");
    }
    fn text(&self, text: &str) {
        log::info!("control: text ({} chars)", text.chars().count());
    }
    fn key(&self, key: Key) {
        log::info!("control: key {key:?}");
    }
}

struct Args {
    file: String,
    port: u16,
    opts: FakeOptions,
    pin: Option<String>,
    no_auth: bool,
    pairing_store: Option<PathBuf>,
    control: bool,
}

fn parse() -> Result<Args, String> {
    let mut args = std::env::args().skip(1);
    let (mut file, mut port) = (None, mirror_sender::mirror_protocol::DEFAULT_PORT);
    let mut opts = FakeOptions::default();
    let (mut pin, mut no_auth, mut pairing_store, mut control) = (None, false, None, false);
    while let Some(a) = args.next() {
        let mut val = |name: &str| args.next().ok_or(format!("{name} needs a value"));
        match a.as_str() {
            "--port" => port = val("--port")?.parse().map_err(|e| format!("--port: {e}"))?,
            "--pin" => {
                let p = val("--pin")?;
                if !is_valid_pin(&p) {
                    return Err("--pin must be exactly 6 digits".into());
                }
                pin = Some(p);
            }
            "--no-auth" => no_auth = true,
            "--pairing-store" => pairing_store = Some(PathBuf::from(val("--pairing-store")?)),
            "--control" => control = true,
            "--fps" => opts.fps = val("--fps")?.parse().map_err(|e| format!("--fps: {e}"))?,
            "--loop" => opts.looping = true,
            "--rotate-every" => {
                let s: f64 = val("--rotate-every")?
                    .parse()
                    .map_err(|e| format!("--rotate-every: {e}"))?;
                if !(s.is_finite() && s > 0.0) {
                    return Err("--rotate-every must be > 0".into());
                }
                opts.rotate_every = Some(
                    Duration::try_from_secs_f64(s)
                        .map_err(|_| "--rotate-every is too large".to_string())?,
                );
            }
            "-h" | "--help" => return Err(String::new()),
            s if s.starts_with("--") => return Err(format!("unknown option {s}")),
            s if file.is_none() => file = Some(s.to_string()),
            s => return Err(format!("unexpected argument {s}")),
        }
    }
    Ok(Args {
        file: file.ok_or("missing <file.h264>")?,
        port,
        opts,
        pin,
        no_auth,
        pairing_store,
        control,
    })
}

fn main() -> ExitCode {
    init_logger();
    let args = match parse() {
        Ok(v) => v,
        Err(e) => {
            if !e.is_empty() {
                eprintln!("error: {e}");
            }
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    let file = &args.file;
    let stream = match H264Stream::from_file(file) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            eprintln!("error: {file}: {e}");
            return ExitCode::from(1);
        }
    };
    log::info!(
        "{file}: {}x{}, {} access units, {} bytes",
        stream.info.width,
        stream.info.height,
        stream.aus.len(),
        stream.data.len()
    );
    let mut cfg = ServerConfig::new("fakeserver", "fakeserver-0001", "FakeServer", 34);
    cfg.port = args.port;
    cfg.allow_no_auth = args.no_auth;
    cfg.allow_loopback = true;
    cfg.fixed_pin = args.pin;
    cfg.pairing_store = args.pairing_store;
    let control: Arc<dyn ControlSink> = if args.control {
        Arc::new(LogControl)
    } else {
        Arc::new(NoControl)
    };
    let server = match Server::start(
        cfg,
        Arc::new(FileSource::new(stream, args.opts)),
        Arc::new(LogEvents),
        control,
    ) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: cannot listen: {e}");
            return ExitCode::from(1);
        }
    };
    server.set_control_available(args.control);
    // Machine-readable lines so scripts can learn the actual port and PIN.
    eprintln!("listening on {}", server.local_addr());
    eprintln!("PIN: {}", server.pin().as_str());
    let (tx, rx) = std::sync::mpsc::channel();
    if let Err(e) = ctrlc::set_handler(move || {
        let _ = tx.send(());
    }) {
        // The dropped sender would make recv() return at once and stop the
        // server silently, so fail loudly instead.
        eprintln!("error: cannot install Ctrl-C handler: {e}");
        server.stop();
        return ExitCode::from(1);
    }
    let _ = rx.recv();
    log::info!("stopping");
    server.stop();
    ExitCode::SUCCESS
}
