//! Loopback integration tests: FileSource -> Server -> Client (protocol v2).
//! The ffmpeg-based ones are skipped (printing `SKIPPED <test name>`) when
//! ffmpeg is not on PATH, unless `MIRROR_REQUIRE_FFMPEG` is set.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use mirror_devtools::{split_access_units, FakeOptions, FileSource, H264Stream};
use mirror_protocol::{AuthMode, ByeReason, GlobalAction, Message, StatusState};
use mirror_receiver::{Client, ClientConfig, ClientEvent, DisconnectReason};
use mirror_sender::{ControlSink, NoControl, NoEvents, Server, ServerConfig};

/// Fixed PIN of the test servers.
const PIN: &str = "246810";

struct TempDir(PathBuf);
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Encode a clip; None (after printing a skip notice) if ffmpeg or its
/// libx264 encoder is missing.
fn make_clip(tag: &str, size: &str, secs: u32, gop: u32) -> Option<(TempDir, PathBuf)> {
    let encoders = Command::new("ffmpeg")
        .args(["-hide_banner", "-encoders"])
        .stdin(Stdio::null())
        .output();
    let missing = match encoders {
        Err(_) => Some("ffmpeg not found on PATH"),
        Ok(o) if !String::from_utf8_lossy(&o.stdout).contains("libx264") => {
            Some("ffmpeg has no libx264 encoder")
        }
        Ok(_) => None,
    };
    if let Some(why) = missing {
        // CI can insist, so a missing ffmpeg fails instead of skipping.
        assert!(
            std::env::var_os("MIRROR_REQUIRE_FFMPEG").is_none(),
            "ffmpeg required: {why}"
        );
        // Named, so the skipped tests can be told apart in the output
        // (`cargo test -- --nocapture`).
        let test = std::thread::current().name().unwrap_or(tag).to_owned();
        eprintln!("SKIPPED {test}: {why}");
        return None;
    }
    let dir =
        TempDir(std::env::temp_dir().join(format!("mirror-devtools-{tag}-{}", std::process::id())));
    std::fs::create_dir_all(&dir.0).unwrap();
    let out = dir.0.join("clip.h264");
    let status = Command::new("ffmpeg")
        .args(["-y", "-loglevel", "error", "-f", "lavfi", "-i"])
        .arg(format!("testsrc2=size={size}:rate=60"))
        .args([
            "-t",
            &secs.to_string(),
            "-c:v",
            "libx264",
            "-preset",
            "ultrafast",
        ])
        .args(["-profile:v", "high", "-bf", "0", "-g", &gop.to_string()])
        .args([
            "-pix_fmt",
            "yuv420p",
            "-bsf:v",
            "h264_mp4toannexb",
            "-f",
            "h264",
        ])
        .arg(&out)
        .stdin(Stdio::null())
        .status()
        .expect("ffmpeg ran a moment ago");
    assert!(status.success(), "ffmpeg failed: {status}");
    Some((dir, out))
}

fn server_config() -> ServerConfig {
    let mut cfg = ServerConfig::new("test", "test-id", "Test", 34);
    cfg.port = 0;
    cfg.bind_addr = Some(IpAddr::V4(Ipv4Addr::LOCALHOST));
    cfg.allow_loopback = true;
    cfg.fixed_pin = Some(PIN.into());
    cfg
}

/// Accepts PIN pairing (fixed [`PIN`]) and, for the devtools flow, `none`.
fn start_server(stream: Arc<H264Stream>, opts: FakeOptions) -> Server {
    let mut cfg = server_config();
    cfg.allow_no_auth = true;
    Server::start(
        cfg,
        Arc::new(FileSource::new(stream, opts)),
        Arc::new(NoEvents),
        Arc::new(NoControl),
    )
    .unwrap()
}

/// A devtools-style client: auth `none` explicitly allowed.
fn no_auth_client() -> ClientConfig {
    let mut c = ClientConfig::new("test-client", "cid");
    c.allow_no_auth = true;
    c
}

/// Next event, skipping RTT and STATUS reports.
fn next(rx: &crossbeam_channel::Receiver<ClientEvent>) -> ClientEvent {
    loop {
        match rx
            .recv_timeout(Duration::from_secs(5))
            .expect("event timeout")
        {
            ClientEvent::Rtt(_) | ClientEvent::Status(_) => continue,
            ev => return ev,
        }
    }
}

/// Wait for STATUS `want`, skipping everything else.
fn wait_status(rx: &crossbeam_channel::Receiver<ClientEvent>, want: StatusState) {
    loop {
        match rx
            .recv_timeout(Duration::from_secs(5))
            .expect("event timeout")
        {
            ClientEvent::Status(s) if s == want => return,
            ClientEvent::Disconnected(r) => panic!("disconnected: {r}"),
            _ => {}
        }
    }
}

fn wait_disconnected(rx: &crossbeam_channel::Receiver<ClientEvent>) -> DisconnectReason {
    loop {
        if let ClientEvent::Disconnected(r) = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("no disconnect")
        {
            return r;
        }
    }
}

#[test]
fn split_is_lossless_and_finds_keyframes() {
    let Some((_d, path)) = make_clip("split", "320x568", 2, 30) else {
        return;
    };
    let data = std::fs::read(&path).unwrap();
    let aus = split_access_units(&data);
    assert_eq!(aus.len(), 120, "2 s at 60 fps");
    assert!(aus[0].keyframe);
    let keys: Vec<usize> = (0..aus.len()).filter(|&i| aus[i].keyframe).collect();
    assert_eq!(keys, vec![0, 30, 60, 90]);
    let mut cat = Vec::new();
    let mut end = 0;
    for a in &aus {
        assert_eq!(a.range.start, end, "contiguous");
        end = a.range.end;
        cat.extend_from_slice(&data[a.range.clone()]);
    }
    assert_eq!(cat, data);
    // 568 is not a multiple of 16: exercises frame cropping.
    let s = H264Stream::parse(data).unwrap();
    assert_eq!((s.info.width, s.info.height), (320, 568));
}

#[test]
fn stream_to_client_and_keyframe_request() {
    let Some((_d, path)) = make_clip("e2e", "1088x2400", 3, 100) else {
        return;
    };
    let stream = Arc::new(H264Stream::from_file(&path).unwrap());
    assert_eq!((stream.info.width, stream.info.height), (1088, 2400));
    let server = start_server(stream.clone(), FakeOptions::default());
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server.port());
    // Pair with the PIN: the whole stream runs over the encrypted records.
    let mut cfg = ClientConfig::new("test-client", "cid");
    cfg.pin = Some(PIN.to_string().into());
    let mut client = Client::connect(addr, cfg).unwrap();
    let rx = client.events();

    assert!(matches!(
        next(&rx),
        ClientEvent::Connected {
            auth: AuthMode::Pin,
            ..
        }
    ));
    assert!(matches!(next(&rx), ClientEvent::Paired { .. }));
    match next(&rx) {
        ClientEvent::VideoConfig(c) => {
            assert_eq!((c.width, c.height), (1088, 2400));
            assert_eq!(
                (c.display_width, c.display_height, c.rotation),
                (1088, 2400, 0)
            );
            assert_eq!(c.sps_pps, stream.sps_pps_annexb());
        }
        e => panic!("expected config, got {e:?}"),
    }
    let mut frames = 0;
    let mut requested_at = None;
    let mut keys_after_request = 0;
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline && (frames < 30 || keys_after_request == 0) {
        let ClientEvent::VideoFrame(f) = next(&rx) else {
            panic!("unexpected event");
        };
        if frames == 0 {
            assert!(f.is_keyframe(), "first frame must be a keyframe");
        }
        frames += 1;
        if frames == 5 {
            client.request_keyframe().unwrap();
            requested_at = Some(frames);
        }
        if let Some(at) = requested_at {
            if f.is_keyframe() && frames > at && keys_after_request == 0 {
                keys_after_request += 1;
                // Natural next IDR would be 95 frames later.
                assert!(frames - at < 60, "keyframe came late: {}", frames - at);
            }
        }
    }
    assert!(frames >= 30, "only {frames} frames");
    assert_eq!(keys_after_request, 1, "no keyframe after request");

    client.close();
    loop {
        match rx
            .recv_timeout(Duration::from_secs(5))
            .expect("no disconnect")
        {
            ClientEvent::Disconnected(r) => {
                assert_eq!(r, DisconnectReason::Closed);
                break;
            }
            _ => continue,
        }
    }
    server.stop();
}

#[test]
fn rotation_sends_swapped_config_then_keyframe() {
    let Some((_d, path)) = make_clip("rot", "320x568", 2, 30) else {
        return;
    };
    let stream = Arc::new(H264Stream::from_file(&path).unwrap());
    let server = start_server(
        stream,
        FakeOptions {
            looping: true,
            rotate_every: Some(Duration::from_millis(300)),
            ..FakeOptions::default()
        },
    );
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server.port());
    let mut client = Client::connect(addr, no_auth_client()).unwrap();
    let rx = client.events();
    let mut dims = Vec::new();
    let mut key_after_config = false;
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && dims.len() < 3 {
        match next(&rx) {
            ClientEvent::VideoConfig(c) => {
                dims.push((c.width, c.height, c.rotation));
                key_after_config = false;
            }
            ClientEvent::VideoFrame(f) if !dims.is_empty() && !key_after_config => {
                assert!(f.is_keyframe(), "frame after config must be IDR");
                key_after_config = true;
            }
            _ => {}
        }
    }
    assert_eq!(dims, vec![(320, 568, 0), (568, 320, 1), (320, 568, 0)]);
    client.close();
    server.stop();
}

/// 1080p SPS + PPS + one IDR + one P slice, no ffmpeg needed.
fn synthetic_stream() -> Arc<H264Stream> {
    let mut d = Vec::new();
    d.extend([0, 0, 0, 1]);
    d.extend([
        0x67, 0x64, 0x00, 0x28, 0xAC, 0xD9, 0x40, 0x78, 0x02, 0x27, 0xE5, 0xC0, 0x44, 0x00, 0x00,
        0x03, 0x00, 0x04, 0x00, 0x00, 0x03, 0x00, 0xF0, 0x3C, 0x60, 0xC6, 0x58,
    ]);
    d.extend([0, 0, 0, 1, 0x68, 0xCE, 0x3C, 0x80]);
    d.extend([0, 0, 0, 1, 0x65, 0x88, 1, 2, 3]);
    d.extend([0, 0, 0, 1, 0x41, 0x80, 4, 5, 6]);
    Arc::new(H264Stream::parse(d).unwrap())
}

/// A keyframe request while the next frame due is an IDR sends that IDR,
/// not the one after it.
#[test]
fn keyframe_request_does_not_skip_the_next_idr() {
    let mut d = Vec::new();
    let mut nal = |n: &[u8]| {
        d.extend([0, 0, 0, 1]);
        d.extend(n);
    };
    nal(&[
        0x67, 0x64, 0x00, 0x28, 0xAC, 0xD9, 0x40, 0x78, 0x02, 0x27, 0xE5, 0xC0, 0x44, 0x00, 0x00,
        0x03, 0x00, 0x04, 0x00, 0x00, 0x03, 0x00, 0xF0, 0x3C, 0x60, 0xC6, 0x58,
    ]);
    nal(&[0x68, 0xCE, 0x3C, 0x80]);
    nal(&[0x65, 0x88, 0xA1]); // IDR a
    nal(&[0x65, 0x88, 0xB2]); // IDR b
    nal(&[0x41, 0x80, 0x03]);
    nal(&[0x65, 0x88, 0xC3]); // IDR c
    let stream = Arc::new(H264Stream::parse(d).unwrap());
    let server = start_server(
        stream,
        FakeOptions {
            fps: 2,
            ..FakeOptions::default()
        },
    );
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server.port());
    let mut client = Client::connect(addr, no_auth_client()).unwrap();
    let rx = client.events();
    let frame = || loop {
        if let ClientEvent::VideoFrame(f) = next(&rx) {
            return *f.data.last().unwrap();
        }
    };
    assert_eq!(frame(), 0xA1);
    client.request_keyframe().unwrap();
    assert_eq!(frame(), 0xB2, "the IDR due next, not a later one");
    client.close();
    server.stop();
}

#[test]
fn huge_rotate_interval_streams_instead_of_panicking() {
    let server = start_server(
        synthetic_stream(),
        FakeOptions {
            looping: true,
            rotate_every: Some(Duration::MAX),
            ..FakeOptions::default()
        },
    );
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server.port());
    let mut client = Client::connect(addr, no_auth_client()).unwrap();
    let rx = client.events();
    let mut frames = 0;
    while frames < 5 {
        if let ClientEvent::VideoFrame(_) = next(&rx) {
            frames += 1;
        }
    }
    client.close();
    server.stop();
}

#[derive(Default)]
struct CountingControl(AtomicUsize);
impl ControlSink for CountingControl {
    fn global_action(&self, _a: GlobalAction) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

/// The receiver and sender cores agree on the whole v2 flow: PIN pairing,
/// token reconnect, control gating, NeedsPin, revoke.
#[test]
fn pairing_token_control_and_revoke() {
    let control = Arc::new(CountingControl::default());
    let server = Server::start(
        server_config(), // pairing required
        Arc::new(FileSource::new(synthetic_stream(), FakeOptions::default())),
        Arc::new(NoEvents),
        control.clone(),
    )
    .unwrap();
    server.set_control_available(true);
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server.port());

    // No key, no PIN: the client asks for one instead of guessing.
    match Client::connect(addr, ClientConfig::new("mac", "mac-id")) {
        Err(DisconnectReason::NeedsPin { device_id, .. }) => assert_eq!(device_id, "test-id"),
        r => panic!("expected NeedsPin, got {:?}", r.map(|_| ())),
    }
    // `none` is refused unless the server allows it.
    let mut c = ClientConfig::new("mac", "mac-id");
    c.allow_no_auth = true;
    assert!(Client::connect(addr, c).is_err());

    // Pair; the key lands in the (shared, in-memory) store.
    let mut cfg = ClientConfig::new("mac", "mac-id");
    cfg.pin = Some(PIN.to_string().into());
    let mut client = Client::connect(addr, cfg.clone()).unwrap();
    assert_eq!(client.auth_mode(), AuthMode::Pin);
    let rx = client.events();
    wait_status(&rx, StatusState::ControlAvailable);
    client
        .send_control(Message::GlobalAction(GlobalAction::Home))
        .unwrap();
    let t0 = Instant::now();
    while control.0.load(Ordering::SeqCst) == 0 {
        assert!(
            t0.elapsed() < Duration::from_secs(5),
            "control not delivered"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    client.close();
    assert_eq!(server.list_paired().len(), 1);

    // Reconnect with the stored key.
    cfg.pin = None;
    let client = Client::connect(addr, cfg.clone()).unwrap();
    assert_eq!(client.auth_mode(), AuthMode::Token);
    let rx = client.events();

    // Revoke on the phone: the session ends with BYE auth_failed and the
    // key is refused afterwards (the receiver keeps it until re-paired).
    assert!(server.revoke("mac-id"));
    assert_eq!(
        wait_disconnected(&rx),
        DisconnectReason::Bye(ByeReason::AuthFailed)
    );
    drop(client);
    match Client::connect(addr, cfg.clone()) {
        Err(DisconnectReason::PairingRemoved { device_id }) => assert_eq!(device_id, "test-id"),
        r => panic!("expected PairingRemoved, got {:?}", r.map(|_| ())),
    }
    // Kept: the refusal is unauthenticated and must not unpair us.
    assert!(cfg.store.pairing_key("test-id").is_some());
    server.stop();
}
