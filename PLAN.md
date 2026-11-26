# Android → Mac LAN screen mirror: plan (Rust core on both sides)

No adb, no Developer Options. Mac + Android now; Windows receiver later. Built so far: M0–M4, M6, M7 with 7b (protocol v2: X25519 + SPAKE2/token auth, encrypted records), M9 and M10. Not built yet: M5 discovery (receivers connect by IP), most of M8, M11. This plan is the original design: where it and the code disagree, the code and `shared/mirror-protocol/PROTOCOL.md` (the wire authority) win. Items marked "verify" are from memory and need checking during implementation.

## 0. Tooling on this Mac

| Item | Found | Consequence |
|---|---|---|
| Rust | `rustc`/`cargo` 1.97.0 via rustup, host `aarch64-apple-darwin` | Ready. |
| Rust Android targets | `aarch64-linux-android`, `armv7-linux-androideabi`, `i686-linux-android`, `x86_64-linux-android` | Nothing to add. |
| Android NDK | r27c at `~/Library/Android/sdk/ndk/27.2.12479018` | Ready. `ANDROID_NDK_HOME` unset; the Gradle task sets it. |
| `cargo-ndk` | **Not installed** | `cargo install cargo-ndk` (the one mandatory install). |
| Xcode | Command Line Tools only, macOS SDK 27.2 | Fine for Rust. No Swift is used. |
| Signing identities | 0 | Ad-hoc signing (`codesign -s -`); see R2. |
| JDK | `JAVA_HOME` is JDK 17; `java` on PATH is OpenJDK 27 | Gradle uses 17 via `JAVA_HOME`. |
| Android SDK | Platforms 35, 36; build-tools 35.0.0, 36.0.0 | Write `android/local.properties` with `sdk.dir`. |
| Gradle | 9.6.1 and 8.14.3 cached in `~/.gradle/wrapper/dists`; AGP 9.3.1 and 8.11.0 cached | Bootstrap wrapper with `~/.gradle/wrapper/dists/gradle-9.6.1-bin/4ticwg1pgcbps2hj28r8so764/gradle-9.6.1/bin/gradle wrapper --gradle-version 9.6.1`. |
| Other | `ffmpeg`, `ffplay` | Test clips and raw-stream viewing. |

Not cached (first build needs network): `winit`, `wgpu`, `egui`, `mdns-sd`, `objc2-video-toolbox`, `objc2-core-media`, `objc2-core-video`.

## 1. Layout and builds

Root Cargo workspace; shared crates in root `shared/` (a library folder, not a third project). Keeps a future `windows/` from depending on `../mac/...`.

```
android-mirror/
  Cargo.toml               # [workspace] members: shared/*, mac, android/core
  Cargo.lock  rust-toolchain.toml  .cargo/config.toml  .gitignore  README.md  PLAN.md
  shared/
    mirror-protocol/       # wire format, sans-IO codec, auth, geometry, Annex-B utils; PROTOCOL.md
    mirror-sender/         # platform-neutral server: listener, session, pairing, backpressure; VideoSource/ControlSink/HostEvents traits
    mirror-receiver/       # platform-neutral receiver: discovery, client, reconnect, input mapping, winit+wgpu+egui shell; VideoDecoder trait
    mirror-devtools/       # bins: fakeserver (file-backed sender), rawclient (headless receiver → stdout)
  mac/                     # crate mirror-mac (bin): VideoToolbox decoder, AppKit hooks, bundling
    Cargo.toml  src/{main.rs, vt_decoder.rs, hooks.rs}
    bundle/Info.plist  scripts/build-app.sh
  android/                 # Gradle root
    settings.gradle.kts  build.gradle.kts  gradle/libs.versions.toml  gradlew  local.properties (gitignored)
    core/                  # crate mirror-android-core (cdylib): JNI + NDK encoder
      Cargo.toml  src/{lib.rs, jni_api.rs, callbacks.rs, encoder.rs}
    app/build.gradle.kts
    app/src/main/{AndroidManifest.xml, res/..., java/dev/local/androidmirror/...}
```

- Platform deps under `[target.'cfg(target_os = ...)'.dependencies]`, modules cfg-gated, so `cargo test --workspace` works on the host.
- `.cargo/config.toml`: `-C link-arg=-Wl,-z,max-page-size=16384` for Android targets (16 KB pages; verify), and `--cfg chacha20_force_neon` for aarch64 (macOS, Android, glibc Linux) so chacha20 uses NEON (~30% faster records; a `RUSTFLAGS`/`CARGO_ENCODED_RUSTFLAGS` env var replaces these flags).

**Mac build**
- Dev: `cargo run -p mirror-mac` (uses Terminal's Local Network permission).
- App: `mac/scripts/build-app.sh` → `cargo build --release -p mirror-mac`, assemble `mac/build/AndroidMirror.app/Contents/{MacOS,Resources}`, copy binary + `bundle/Info.plist`, `codesign --force --sign "${SIGN_ID:--}"`. Launch with `open`.
- Info.plist: `CFBundleIdentifier=dev.local.androidmirror`, `CFBundleExecutable`, `CFBundlePackageType=APPL`, `LSMinimumSystemVersion=13.0`, `NSHighResolutionCapable`, `NSLocalNetworkUsageDescription`, `NSBonjourServices=[_androidmirror._tcp]`. No sandbox.

**Android build**
- `cd android && ./gradlew assembleDebug` → `app/build/outputs/apk/debug/app-debug.apk`.
- Rust via a Gradle `Exec` task `cargoNdkBuild` (not rust-android-gradle plugin, which lags AGP): runs in repo root with `ANDROID_NDK_HOME = android.ndkDirectory`, executes `cargo ndk -t arm64-v8a --platform 29 -o android/app/build/rustJniLibs build --release -p mirror-android-core`, registers that dir as `jniLibs`, `preBuild` depends on it.
- `ndkVersion = "27.2.12479018"`, AGP 9.3.1 + Gradle 9.6.1, `compileSdk 36`, `targetSdk 36`, `minSdk 29`. Fallback: AGP 8.11.0 + Gradle 8.14.3 + Kotlin 2.2.10.
- Kotlin deps: `androidx.core:core-ktx`, `androidx.activity:activity-ktx`. One Activity, XML layout.
- Back up `~/.android/debug.keystore` after first build (key change forces uninstall → loses accessibility grant and pairings).

## 2. Wire protocol (defined once in `mirror-protocol`)

This section is the original v1 sketch. The protocol actually implemented is **v2** (`PROTO_VERSION = 2`): the hellos also carry `kx` (X25519 public keys), AUTH carries `pake` in PIN mode, PAKE_REPLY (0x0A) and AUTH_CONFIRM (0x16) were added, BYE gained `unknown`, AUTH_RESULT gained `retryAfterMs`, and every frame after AUTH_RESULT travels in a ChaCha20-Poly1305 record. `shared/mirror-protocol/PROTOCOL.md` is the authority for every byte.

- One TCP connection; phone is the server. Port **47800**, ephemeral fallback. Big-endian. `TCP_NODELAY` both ends.
- Each side first sends magic `41 4D 52 31` ("AMR1").

**Header, 16 bytes**

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | u8 | `type` | below |
| 1 | u8 | `flags` | bit0 KEYFRAME, bit1 CONFIG, bit2 DISCONTINUITY |
| 2 | u16 | reserved | 0 |
| 4 | u32 | `length` | payload bytes; reject > 8 MiB; JSON types and every receiver → phone frame ≤ 64 KiB (see PROTOCOL.md, the authority) |
| 8 | u64 | `pts_us` | media timestamp; 0 otherwise |

**Phone → receiver**

| Type | Name | Payload |
|---|---|---|
| 0x01 | SERVER_HELLO | JSON `{proto, deviceName, deviceId, model, sdkInt, codecs:["h264"], caps, authModes, nonceS}` |
| 0x02 | AUTH_RESULT | JSON `{ok, serverProof?, reason?}` |
| 0x03 | VIDEO_CONFIG | `u16 width, u16 height, u16 displayWidth, u16 displayHeight, u8 rotation, u8[3] reserved`, then SPS+PPS Annex-B |
| 0x04 | VIDEO_FRAME | One Annex-B access unit |
| 0x05 | STATUS | JSON `{state}`: `streaming`, `screen_off`, `screen_on`, `reconfiguring`, `control_available`, `control_unavailable` |
| 0x06 | PONG | Echo of 8-byte PING payload |
| 0x07 | BYE | JSON `{reason}`: `stopped_by_user`, `projection_revoked`, `replaced`, `auth_failed`, `proto_mismatch` |
| 0x08, 0x09 | AUDIO_CONFIG, AUDIO_FRAME | Reserved, Phase 3 |

**Receiver → phone**

| Type | Name | Payload |
|---|---|---|
| 0x10 | CLIENT_HELLO | JSON `{proto, clientName, clientId, nonceC}` |
| 0x11 | AUTH | JSON `{mode:"pin"\|"token"\|"none", proof}` |
| 0x12 | START | JSON `{maxLongEdge, maxFps, bitrate}`; required to start streaming, fields optional |
| 0x13 | REQUEST_KEYFRAME | empty |
| 0x14 | PING | 8 opaque bytes |
| 0x15 | BYE | JSON `{reason}` |
| 0x20 | TOUCH_GESTURE | `u8 kind(1 tap, 2 longpress, 3 path), u8 count, u16 reserved`, then `count` × `{u16 x, u16 y, u16 dt_ms}` |
| 0x21 | GLOBAL_ACTION | `u8`: 1 back, 2 home, 3 recents, 4 notifications, 5 quick settings, 6 lock, 7 vol up, 8 vol down |
| 0x22 | TEXT | UTF-8 to commit at cursor (≤ 64 KiB per message) |
| 0x23 | KEY | `u8`: 1 backspace, 2 enter, 3 left, 4 right, 5 up, 6 down, 7 delete-forward, 8 tab |
| 0x24 | SCROLL | `u16 x, u16 y, i16 dx, i16 dy` |
| 0x25 | TOUCH_LIVE (2.1) | `u8 phase(0 down, 1 move, 2 up, 3 cancel), u8 reserved, u16 x, u16 y` |

- Coordinates normalised 0..65535 over the video frame; sender maps to display pixels.
- Order: magic → CLIENT_HELLO → SERVER_HELLO → AUTH (→ PAKE_REPLY → AUTH_CONFIRM in PIN mode) → AUTH_RESULT → records: START (required; the phone sends no video before it) → VIDEO_CONFIG → frames.
- Unknown types skipped by `length`.
- Discovery (M5, not built): `_androidmirror._tcp`, name `Mirror-<model>`, TXT `v=2`, `id`, `name`.

`mirror-protocol` modules: `wire.rs`, `codec.rs` (`encode(&Message)`, incremental `Decoder::push(&[u8])`), `messages.rs`, `auth.rs`, `handshake.rs` (sans-IO v2 handshake), `secure.rs` (record `Sealer`/`Opener`), `geometry.rs`, `annexb.rs`. Deps: `serde`, `serde_json`, `hmac`, `sha2`, `hkdf`, `x25519-dalek`, `spake2`, `chacha20poly1305`, `zeroize`, `getrandom`, `rand_core`.

## 3. Crate choices

| Concern | Choice | Why |
|---|---|---|
| I/O | std threads + blocking sockets, `crossbeam-channel`, `socket2` | One connection; no async runtime in a JNI lib; channels feed winit `EventLoopProxy`. |
| Discovery (receivers) | `mdns-sd` | Pure Rust, reusable on Windows (verify macOS Local Network prompt behaviour). |
| Discovery (Android) | Kotlin `NsdManager` | System daemon handles multicast/power; avoids MulticastLock. ~40 lines. |
| Decode (Mac) | VideoToolbox `VTDecompressionSession` via `objc2-video-toolbox`/`-core-media`/`-core-video` | Hardware, no C deps. |
| Display | winit + wgpu, NV12 as two textures | Renderer shared with Windows. |
| UI chrome | egui (`egui-winit`, `egui-wgpu`) | Device list, PIN, settings, diagnostics, overlays. |
| JNI | `jni` 0.21 | Cached, standard. |
| NDK | `ndk` 0.9 (`media` feature), `ndk-sys` where needed | Cached. |
| Pairing store | JSON file, mode 0600 | Keychain re-prompts for ad-hoc-signed rebuilds. |

Rejected: `ffmpeg-next` (bundling/re-signing dylibs), `openh264` (CPU/latency; kept as optional feature for tests and day-one Windows), `AVSampleBufferDisplayLayer` (fallback only; macOS-only). Zero-copy IOSurface→Metal deferred (copy is <1 ms). No Swift/ObjC needed; unsafe FFI confined to `mac/src/vt_decoder.rs` and `mac/src/hooks.rs`. Pick egui release first and take its winit/wgpu versions.

## 4. Android: thin Kotlin shell + Rust core

**Kotlin only:** consent Activity + permissions + UI; foreground service + notification; `MediaProjection` / `VirtualDisplay`; `AccessibilityService`; `NsdManager`; display rotation listener + screen on/off receiver; network callback + low-latency `WifiLock`. (MulticastLock not needed.)

**Rust:** encoder, drain loop, TCP server, framing, handshake, PIN/pairing, backpressure, liveness, geometry, control parsing and coordinate mapping.

- `mirror-sender`: `server.rs`, `session.rs`, `pairing.rs`; traits `VideoSource { start, request_keyframe, stop }`, `ControlSink { gesture, touch_live, global_action, text, key, scroll }`, `HostEvents`.
- `mirror-android-core` (`libmirror_core.so`): `encoder.rs` (VideoSource on AMediaCodec), `callbacks.rs` (ControlSink/HostEvents → Kotlin), `jni_api.rs`.

**Encoder (`ndk::media`)**
1. `MediaCodec::from_encoder_type("video/avc")`, configure.
2. `create_input_surface()` → `NativeWindow`.
3. `ANativeWindow_toSurface` → `jobject` → Kotlin `onSurfaceReady` (verify crate fn name).
4. `start()`; drain thread loops `dequeue_output_buffer` with 10 ms timeout.
5. Codec-config buffer (flag 2) = SPS+PPS → VIDEO_CONFIG; else `csd-0`/`csd-1` from output format.
6. Keyframe: `AMediaCodec_setParameters` with `request-sync = 0` (via `ndk-sys` if needed).

| Format key | Value |
|---|---|
| `color-format` | `0x7F000789` (surface) |
| `bitrate` | 8 Mbps @1920 long edge; 4 Mbps @1280; 2–20 via START |
| `bitrate-mode` | 1 (VBR) |
| `frame-rate` | 60 (ladder → 30) |
| `max-fps-to-encoder` (float) | 60 |
| `i-frame-interval` | 10 |
| `repeat-previous-frame-after` (i64) | 100000 µs — **required** |
| `max-bframes` | 0 |
| `priority` | 0 |
| `operating-rate` | 60 |
| `latency` | 1 |
| `color-standard`, `color-range` | 1 (BT.709), 2 (limited) |

- Configure ladder: full → drop optional keys → 30 fps → 1280 cap. Log rung.
- Size: `scale = min(1, 1920/long_edge)`, round then floor each dim to multiple of 16.
- Encoder lifetime = client connection × geometry; no client → no codec, null VirtualDisplay surface → new client always starts on IDR.

**JNI boundary** — Kotlin `class NativeCore(cb: CoreCallbacks) : Closeable`, `@Volatile handle: Long`, no-op when 0. Only `start`/`close` lock (create once, destroy once); other calls need no lock because the handle is a key into the native handle table, so a call racing `close` finds it gone and returns its fallback.

Kotlin → Rust (`Java_dev_local_androidmirror_core_NativeCore_*`):

| Function | Purpose |
|---|---|
| `nativeCreate(configJson, cb): Long` | Device name, model, sdkInt, filesDir, port, debug. Starts listener. 0 on failure. `debug` only lets loopback peers connect, and Kotlin sets it only in a debug build with the opt-in file `files/allow_loopback`; AUTH `none` is never accepted. |
| `nativeGetPort(h)`, `nativeGetPin(h)` | UI (and NSD once M5 lands). |
| `nativeNewPin(h): String?` | "New PIN": rotate the PIN and clear the PIN lockout and its escalation; returns the new PIN (no `onPinChanged` for it), null for a closed handle. |
| `nativePinResets(h): Long` | How many "New PIN"s so far (only grows; -1 for a closed handle). Read right after `nativeNewPin` on the same thread; Kotlin drops `onPairingFailed` events counted under an older value. |
| `nativeSetDisplay(h, w, h, rotation, dpi)` | Start and every display change; reconfigures if streaming. |
| `nativeSetScreenState(h, on)` | STATUS. |
| `nativeSetControlAvailable(h, available)` | Accessibility bound/unbound. |
| `nativeNetworkChanged(h)` | Drops client. |
| `nativeProjectionRevoked(h)` | Projection ended: BYE `projection_revoked`. |
| `nativeListPaired(h)`, `nativeRevoke(h, clientId)` | Pairing management while running (`nativeListPaired` is null if the store could not be read); `nativeListPairedIn(filesDir)`, `nativeRevokeIn(filesDir, clientId)` while idle. |
| `nativeDestroy(h)` | BYE, join threads, release codec, drop global refs, free handle. |

Rust → Kotlin (`interface CoreCallbacks`, method IDs cached):

| Callback | Kotlin action |
|---|---|
| `onSurfaceReady(surface, w, h)` | `virtualDisplay.resize(w, h, dpi)`; `virtualDisplay.surface = surface` |
| `onSurfaceGone()` | `surface = null`, `surface.release()`; returns when done |
| `onClientState(state, sessionId, name?, peer?, reason)` | UI, notification, WifiLock |
| `onPinChanged(pin)`, `onPairingFailed(peer, attemptsLeft, lockedForMs, resets)` | UI |
| `onGesture(kind, xs, ys, durationMs)` | Accessibility (pixels) |
| `onScroll`, `onTouchLive`, `onGlobalAction`, `onText`, `onKey` | Accessibility |
| `onSurfaceRefresh()`, `onStreamInfo(w, h, fps, encoder)`, `onPaired(id, name)` | Keyframe nudge; UI |
| `onError(msg)` | Non-fatal error, shown in the UI. There is no fatal upcall: a session that fails ends with `onClientState(DISCONNECTED, reason)` (e.g. `SOURCE_FAILED`) and the service keeps running |

Rules: handle = a key into a handle table (`handles.rs`: ids from 1, never reused) mapping to `Arc<Core>`; removed once in `nativeDestroy`, so a destroyed or bogus handle is a logged error, never a dangling pointer. Rust threads (accept, reader, writer, drain) attach once/detach on exit; `JavaVM` stored in `JNI_OnLoad`. No class lookups from native threads — only the `GlobalRef` callbacks. Rust never calls Kotlin holding its core mutex; Kotlin never calls native holding its projection lock; `resize`/`setSurface` called directly on the Rust thread. `onSurfaceGone()` returns before codec release. Every export in `catch_unwind` (`panic = "unwind"`); clear pending Java exceptions after upcalls. Kotlin posts UI updates to main handler.

## 5. Receiver

**`mirror-receiver` (platform-neutral):** `discovery.rs` (mdns-sd, permission-denied detection), `client.rs` (handshake, auth, reader/writer, PING 2 s), `reconnect.rs` (0.5/1/2/4/5 s for 30 s, token auth), `decoder.rs` (`trait VideoDecoder { configure, decode }` → `Nv12Frame { width, height, y, y_stride, uv, uv_stride, pts_us }`), `render.rs` (wgpu `R8Unorm` + `Rg8Unorm`, BT.709 limited shader, aspect-fit, latest-frame-wins, low-latency present mode — verify Metal options), `ui.rs` (egui), `input.rs`, `app.rs` (winit `ApplicationHandler`, decoder factory + `PlatformHooks`), `store.rs`, `diagnostics.rs`.

**`mirror-mac`:**
- `vt_decoder.rs`: SPS/PPS → `CMVideoFormatDescriptionCreateFromH264ParameterSets` (NAL len 4); session with `kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange`, `kVTDecompressionPropertyKey_RealTime`; Annex-B→AVCC → `CMBlockBuffer`/`CMSampleBuffer` → sync `VTDecompressionSessionDecodeFrame`; callback copies both planes with strides into pooled buffers; on error recreate, REQUEST_KEYFRAME, drop until keyframe.
- `hooks.rs`: `NSWindow.setContentAspectRatio` via `objc2-app-kit`; initial size ≤ 85% of visible screen height.

```rust
/// Byte ranges of NAL payloads (start codes excluded).
pub fn nal_ranges(d: &[u8]) -> Vec<std::ops::Range<usize>> {
    let (mut out, mut i, mut start) = (Vec::new(), 0usize, None);
    while i + 3 <= d.len() {
        let sc = if d[i..].starts_with(&[0, 0, 1]) { 3 }
                 else if d[i..].starts_with(&[0, 0, 0, 1]) { 4 } else { 0 };
        if sc > 0 { if let Some(s) = start { out.push(s..i); } start = Some(i + sc); i += sc; }
        else { i += 1; }
    }
    if let Some(s) = start { out.push(s..d.len()); }
    out
}
// AVCC: per range write u32 BE length + bytes; skip NAL types 7, 8, 9.
```

**Phase 2 input (winit):** click → tap; hold 500 ms still → long press; drag → path ≤64 points on release; right/middle click → back/home; wheel → SCROLL; text / `Ime::Commit` → TEXT; Backspace/Enter/arrows/Tab/Delete → KEY; Cmd+B/H/R → back/home/recents; Cmd+N → notifications, Cmd+Shift+N → quick settings; Cmd+V → clipboard as TEXT (split into ≤ 64 KiB messages). Map window → aspect-fit rect → normalised u16; ignore letterbox; don't forward while egui wants input (except presses on the top bar background, which go to the phone so the status bar can be pulled down).

## 6. Lifecycle, edge cases, security

**Session start (Android 14+)**
1. Request `POST_NOTIFICATIONS` (33+).
2. `createScreenCaptureIntent()`; on 34+ with `MediaProjectionConfig.createConfigForDefaultDisplay()`.
3. On `RESULT_OK` start `MirrorService`.
4. `startForeground(..., MEDIA_PROJECTION)` first → `getMediaProjection` → `registerCallback` → `createVirtualDisplay` **once, null surface**.
5. Create `NativeCore`, `nativeSetDisplay`, show `IP:port` from `nativeGetPort` (NSD registration comes with M5).
- Never reuse consent intent. Receiver reconnects reuse the session.
- Manifest: `INTERNET`, `ACCESS_NETWORK_STATE`, `FOREGROUND_SERVICE`, `FOREGROUND_SERVICE_MEDIA_PROJECTION`, `POST_NOTIFICATIONS`, `WAKE_LOCK`.

**Rotation:** `DisplayWatcher` (listener + `onCapturedContentResize`, 150 ms debounce) → `nativeSetDisplay` → Rust: STATUS reconfiguring → `onSurfaceGone()` → release codec → new codec/surface → `onSurfaceReady` → VIDEO_CONFIG + IDR. Never `createVirtualDisplay` twice.

| Case | Behaviour |
|---|---|
| Single client | Newest authenticated wins; old gets BYE `replaced`. |
| Liveness | PING 2 s; close after 6 s silence. |
| Backpressure | Oldest queued > 250 ms → clear, sync frame, drop until key, DISCONTINUITY. Send buffer ~256 KB. |
| Screen off | STATUS; receiver dims last frame. |
| Device lock | Android 15 QPR1+ ends projection (verify) → BYE `projection_revoked`. Same for "Stop sharing" chip. |
| Wi-Fi change | `nativeNetworkChanged` (drops the client so it reconnects), refresh IP (and re-register NSD once M5 lands). |
| FLAG_SECURE | Black frames, not an error. |
| mDNS blocked | Connect by IP; phone shows `IP:47800`. |
| Local Network denied (Mac) | Banner → System Settings > Privacy & Security > Local Network. |

Diagnostics (3 s TCP probe): works but no discovery → mDNS filtered; timeout → isolation/guest/VLAN; refused → no session on phone; different subnet → different networks. Fallback: phone hotspot or USB tethering.

**Security**
- LAN-only: close unless peer is site-local IPv4, IPv6 link-local or ULA.
- Protocol v2 (7b, built; details and test vectors in PROTOCOL.md): ephemeral X25519 per connection; first pairing by 6-digit PIN through SPAKE2 (no offline guessing: a sniffer learns nothing, an active attacker gets one guess per connection), which yields a stored 32-byte pairing key; later connections prove that key with HMAC over the transcript hash of both hellos and the mode. Session keys come from HKDF over the DH result, the auth key and the transcript; every frame after AUTH_RESULT is a ChaCha20-Poly1305 record, in every mode.
- PIN policy: 5 failures → new PIN + lockout, escalating 30 s, 60 s, … capped at 1 h; at most 5 attempts in flight. The PIN state is in memory only: "New PIN" on the phone (`nativeNewPin`) and restarting mirroring both clear the lockout and its escalation. Revoke on phone (also while idle).
- Control (input) only after START, only for `pin`/`token` sessions; `none` is accepted only with `allow_no_auth` (devtools/tests; the Android app never enables it).

## 7. Implementation order

Install without adb (M4+): `python3 -m http.server 8000 --bind <Mac LAN IP>` in the APK dir, open in phone browser, allow "Install unknown apps".

- **M0 Scaffolding** — workspace, toolchain, empty crates, `git init`, `cargo install cargo-ndk`, Gradle + wrapper + `cargoNdkBuild` + `NativeCore.nativeVersion()` stub; blank winit window + bundle script. *Verify:* `cargo build --workspace`; APK contains `lib/arm64-v8a/libmirror_core.so`; phone shows Rust version; `open mac/build/AndroidMirror.app` shows a window.
- **M1 `mirror-protocol`** — *Verify:* round-trips, byte-at-a-time decoding, oversize rejection, 3/4-byte start codes, geometry, HMAC vectors.
- **M2 Sender/receiver cores on loopback** — `mirror-sender` (auth `none`), `mirror-receiver` client/reconnect, devtools `fakeserver` + `rawclient`. Test clip: `ffmpeg -f lavfi -i testsrc2=size=1088x2400:rate=60 -t 20 -c:v libx264 -bf 0 -g 120 -bsf:v h264_mp4toannexb -f h264 test.h264`. *Verify:* integration test; `rawclient 127.0.0.1 | ffplay -f h264 -fflags nobuffer -`.
- **M3 Mac app vs fake server** — decoder, render, app, minimal UI; `vt_decoder.rs`, `hooks.rs`. *Verify:* smooth pattern, rotation resizes window, reconnect works.
- **M4 Android capture/encode** — Rust `encoder.rs`, `callbacks.rs`, `jni_api.rs`; Kotlin `MainActivity`, `service/MirrorService`, `service/Notifications`, `capture/ProjectionSession`, `core/NativeCore`, `core/CoreCallbacks`. *Verify:* `cargo run -p mirror-devtools --bin rawclient -- <phone-ip> | ffplay -f h264 -fflags nobuffer -flags low_delay -`; rerun needs no new consent; Mac app by IP; clean Stop.
- **M5 Discovery** — `NsdAdvertiser.kt`, `discovery.rs`, device list. *Verify:* `dns-sd -B _androidmirror._tcp`; Local Network prompt; phone listed in ~2 s.
- **M6 Lifecycle hardening** — `DisplayWatcher.kt`, `NetworkWatcher.kt`, reconfigure, backpressure, overlays, decoder recovery. *Verify:* rotate ×5; Mac Wi-Fi off 5 s; screen off/on; lock; FLAG_SECURE app; `replaced`; 2 min fast motion; 30 min memory; start/stop ×10.
- **M7 Pairing** — `pairing.rs`, `store.rs`, PIN UI both sides, `rawclient --pin`; remove `none` in release. 7b (protocol v2: SPAKE2/token auth, encrypted records) is built.
- **M8 v1 polish** — diagnostics UI, settings, stats overlay, quality presets. *Verify latency:* stopwatch photo test, ≤100 ms on 5 GHz.
- **M9 Phase 2 control** — `session.rs` control parsing, `input.rs`; Kotlin `MirrorAccessibilityService` + `accessibility_config.xml`, `ControlBridge`, `GestureInjector`, `GlobalActions`, onboarding incl. "Allow restricted settings". Queue gestures; next only after `onCompleted`/`onCancelled`. 2.1: TOUCH_LIVE via `continueStroke`.
- **M10 Phase 2 text** — `TextInjector.kt`: API 33+ `flagInputMethodEditor` + `currentInputConnection`; 29–32 `ACTION_SET_TEXT`/`ACTION_SET_SELECTION`, `ACTION_IME_ENTER`, clipboard fallback.
- **M11 Phase 3 (optional)** — audio (Kotlin `AudioPlaybackCapture` → direct ByteBuffers → Rust Opus/AAC via AMediaCodec → receiver `cpal`, 40–60 ms jitter buffer), HEVC. (Encryption, once planned here, is built as 7b.)

```kotlin
fun dispatchPath(xs: FloatArray, ys: FloatArray, durationMs: Long) {
    val path = Path().apply { moveTo(xs[0], ys[0]); for (i in 1 until xs.size) lineTo(xs[i], ys[i]) }
    val stroke = GestureDescription.StrokeDescription(path, 0, durationMs.coerceIn(1, 10_000))
    service.dispatchGesture(GestureDescription.Builder().addStroke(stroke).build(), callback, mainHandler)
}
// tap: one point ~50 ms; long press: one point ≥600 ms.
```

## 8. Windows later (not in scope)

| Reused | New in `windows/` |
|---|---|
| `mirror-protocol` | `VideoDecoder` via Media Foundation (`windows` crate), NV12 to system memory, D3D11 later |
| `mirror-receiver` (discovery, client, reconnect, input, wgpu renderer, egui UI, store, diagnostics) | `PlatformHooks` impl |
| `mirror-devtools` | Packaging, firewall prompt for UDP 5353 |
| optional `openh264` feature | `mdns-sd` check alongside Windows mDNS |

Rules now: no Apple types in `mirror-receiver` public API; frames cross as plain NV12; platform code cfg-gated.

## 9. Risks

| # | Item |
|---|---|
| R1 | Toolchain pairings untested (AGP 9.3.1/Gradle 9.6.1/JDK 17, cargo-ndk + r27c, winit/wgpu/egui trio). M0 settles. |
| R2 | Ad-hoc signing may re-trigger Local Network prompt per rebuild; use self-signed cert as `SIGN_ID`, or `cargo run` in dev. |
| R3 | `mdns-sd` bypasses Bonjour on macOS; prompt/denial behaviour unverified. Manual IP safety net; `dns-sd` FFI fallback. |
| R4 | Native crashes kill the service; strict JNI rules + start/stop ×10 test. |
| R5 | `ndk` 0.9 coverage gaps → `ndk-sys`. |
| R6 | Unsafe VideoToolbox FFI; fallback `AVSampleBufferDisplayLayer`. |
| R7 | Consent every session; Android 15 QPR1+ lock ends session. |
| R8 | Mac can't wake/unlock phone. |
| R9 | Protected content is black. |
| R10 | Accessibility gestures ≠ real touch (no pinch at first; some apps block). |
| R11 | OEM power managers; document battery exemption. |
| R12 | Encoder variance; ladder + logging. |
| R13 | TCP head-of-line blocking; 250 ms resync. |
| R14 | Network isolation/enterprise/VPN; diagnostics + hotspot/tethering. |
| R15 | Future Android local-network permission at higher targetSdk (verify). |
| R16 | Security rests on the PIN (one online guess per connection, escalating lockout) and the stored pairing key; done in 7b. |
| R17 | wgpu/egui compile time and binary size. |
| R18 | Battery/heat at 1080p60; 720p30 preset. |
