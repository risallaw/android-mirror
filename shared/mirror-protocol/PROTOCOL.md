# Android Mirror wire protocol v2

Implemented by the `mirror-protocol` crate (`wire.rs`, `messages.rs`, `codec.rs`, `auth.rs`, `handshake.rs`, `secure.rs`, `geometry.rs`, `annexb.rs`). When this document and the code disagree, fix one of them; the tests in `tests/protocol.rs`, `tests/handshake.rs` and `tests/secure.rs` pin the byte layout and the test vectors below.

v2 adds an authenticated key exchange (X25519 + stored pairing key, or SPAKE2 PIN pairing) and encrypts every frame after authentication. v1 is not supported: a peer with `proto != 2` gets BYE `proto_mismatch`.

## Transport

- One TCP connection. The phone is the server; the receiver (Mac) connects.
- Default port **47800** (`DEFAULT_PORT`); the phone falls back to an ephemeral port and advertises it.
- Both ends set `TCP_NODELAY`.
- All integers are **big-endian**.
- Discovery (planned, milestone M5; not implemented yet, so receivers connect by IP): DNS-SD `_androidmirror._tcp` (`SERVICE_TYPE`), instance name `Mirror-<model>`, TXT `v=2` (the `proto` version), `id=<deviceId>`, `name=<deviceName>`. Connecting by IP always works too.

## Preamble

Each side first sends the 4-byte magic `41 4D 52 31` (`"AMR1"`). A peer that receives anything else closes the connection. The decoder (`Decoder::new(true)`) rejects a wrong byte as soon as it arrives.

## Frame header (16 bytes)

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | u8 | `type` | see tables below |
| 1 | u8 | `flags` | bit0 `KEYFRAME`, bit1 `CONFIG`, bit2 `DISCONTINUITY` |
| 2 | u16 | reserved | send 0; ignored on receive |
| 4 | u32 | `length` | payload bytes; **> 8 MiB (8 388 608) is rejected** and the connection closed; for JSON types (0x01, 0x02, 0x05, 0x07, 0x0A, 0x10, 0x11, 0x12, 0x15, 0x16) the limit is **64 KiB** (`MAX_JSON_PAYLOAD`). **The phone accepts at most 64 KiB for every receiver → phone frame, whatever its type** (`MAX_CLIENT_PAYLOAD`, TEXT included); a larger frame is a protocol error and ends the session |
| 8 | u64 | `pts_us` | media timestamp in µs for VIDEO_FRAME; 0 otherwise |

The payload of `length` bytes follows immediately. **Unknown types are skipped by `length`** (the crate surfaces them as `Message::Unknown { ty, flags, payload }`).

Before authentication completes, frames travel as plain header + payload. After it, every frame is wrapped in a record (see [Record layer](#record-layer)); the frame format inside is unchanged.

Flags in use: VIDEO_CONFIG is sent with `CONFIG`; VIDEO_FRAME carries `KEYFRAME` for IDR access units and `DISCONTINUITY` on the first frame after frames were dropped (backpressure resync).

## Phone → receiver

| Type | Name | Payload |
|---|---|---|
| 0x01 | SERVER_HELLO | JSON `{proto, deviceName, deviceId, model, sdkInt, codecs:["h264"], caps, authModes, nonceS, kx}` |
| 0x02 | AUTH_RESULT | JSON `{ok, serverProof?, reason?, retryAfterMs?}` |
| 0x03 | VIDEO_CONFIG | `u16 width, u16 height, u16 displayWidth, u16 displayHeight, u8 rotation, u8[3] reserved`, then SPS+PPS Annex-B |
| 0x04 | VIDEO_FRAME | One Annex-B access unit |
| 0x05 | STATUS | JSON `{state}`: `screen_off`, `screen_on`, `reconfiguring`, `control_available`, `control_unavailable`; `streaming` is reserved (defined, never sent by the phone). Right after AUTH_RESULT the phone always sends `control_available` or `control_unavailable` first, then `screen_off` if the phone screen is off (see [Session sequence](#session-sequence)) |
| 0x06 | PONG | Echo of the 8-byte PING payload |
| 0x07 | BYE | JSON `{reason}`: `stopped_by_user`, `projection_revoked`, `replaced`, `auth_failed`, `proto_mismatch`, `unknown` (phone-side failure such as the encoder failing to start; final, don't auto-reconnect). A connection closed **without** a BYE (e.g. the phone changed network) is a connection loss the receiver may retry |
| 0x08, 0x09 | AUDIO_CONFIG, AUDIO_FRAME | Reserved (Phase 3) |
| 0x0A | PAKE_REPLY | JSON `{pake, serverProof}` — PIN mode only: SPAKE2 message B and `serverConfirm` |

## Receiver → phone

| Type | Name | Payload |
|---|---|---|
| 0x10 | CLIENT_HELLO | JSON `{proto, clientName, clientId, nonceC, kx}`. The phone requires a non-empty `clientId` of at most 256 bytes (UTF-8); otherwise it closes without SERVER_HELLO. A longer `clientName` is accepted: the phone stores and shows it cut to 256 bytes (on a character boundary), while the transcript binds it as sent. Receivers should still keep it short |
| 0x11 | AUTH | JSON `{mode:"pin"\|"token"\|"none", proof, pake?}` |
| 0x12 | START | JSON `{maxLongEdge, maxFps, bitrate}`. **Required to begin streaming** (the phone sends no video until it arrives); every field is optional and an empty payload means defaults |
| 0x13 | REQUEST_KEYFRAME | empty. The phone passes at most one to its encoder per 250 ms; one arriving sooner is deferred to the end of that interval, not dropped, and several within it count as one. A receiver still waiting for an IDR after its request should ask again (the IDR may have been lost to backpressure) |
| 0x14 | PING | 8 opaque bytes |
| 0x15 | BYE | JSON `{reason}` (same reasons as 0x07) |
| 0x16 | AUTH_CONFIRM | JSON `{proof}` — PIN mode only: `clientConfirm` |
| 0x20 | TOUCH_GESTURE | `u8 kind (1 tap, 2 longpress, 3 path), u8 count, u16 reserved`, then `count` × `{u16 x, u16 y, u16 dt_ms}` |
| 0x21 | GLOBAL_ACTION | `u8`: 1 back, 2 home, 3 recents, 4 notifications, 5 quick settings, 6 lock, 7 vol up, 8 vol down |
| 0x22 | TEXT | UTF-8 text to commit at the cursor (no terminator); at most 64 KiB per message, so split longer pastes |
| 0x23 | KEY | `u8`: 1 backspace, 2 enter, 3 left, 4 right, 5 up, 6 down, 7 delete-forward, 8 tab |
| 0x24 | SCROLL | `u16 x, u16 y, i16 dx, i16 dy` (see [Coordinates](#coordinates)) |
| 0x25 | TOUCH_LIVE (2.1) | `u8 phase (0 down, 1 move, 2 up, 3 cancel), u8 reserved, u16 x, u16 y` |

### Field details

- `proto`: protocol version, currently `2` (`PROTO_VERSION`). A mismatch is answered with BYE `proto_mismatch`. A `proto` that is missing or not a `u32` (`"3"`, `3.0`, `-1`, …) decodes as `0`, i.e. a mismatch, never a decode error. `kx` decodes as `""` when absent, so a v1 hello still parses and gets the BYE rather than a decode error.
- `sdkInt`: Android API level. `codecs`: currently `["h264"]`. `caps`: capability strings, reserved for future use; the phone currently always sends `[]` (control availability is signalled with STATUS instead). It is still bound into the transcript (see [Key schedule](#key-schedule)). `authModes`: subset of `"pin"`, `"token"`, `"none"`.
- `nonceS`, `nonceC`: 32 random bytes, lowercase hex (64 chars).
- `kx`: the sender's ephemeral X25519 public key, 32 bytes, lowercase hex (64 chars). Fresh per connection.
- `proof` (AUTH): token mode `clientProof`, 32 bytes hex; `""` for `pin` and `none`. `pake` (AUTH): PIN mode only, SPAKE2 message A hex (33 bytes → 66 chars).
- `serverProof` (AUTH_RESULT): token mode only, 32 bytes hex. PAKE_REPLY `pake`: SPAKE2 message B hex; `serverProof`: `serverConfirm` hex. AUTH_CONFIRM `proof`: `clientConfirm` hex.
- `reason` (AUTH_RESULT, when `ok:false`): `unknown_client` (token mode, no key stored for this `clientId` — never paired or revoked), `bad_proof` (proof / PAKE did not verify), `locked_out` (PIN attempts refused, see [Phone-side PIN policy](#phone-side-pin-policy); `retryAfterMs` = ms until a PIN attempt may be accepted again), `mode_unsupported` (mode not offered, e.g. `none` when not allowed). Unknown strings decode as `unknown`.
- START fields and the phone's defaults when a field is absent:
  - `maxLongEdge`: cap on the encoded long edge, pixels. Default `1920`; `0` = no cap (native size); other values below `320` are raised to `320` (`MIN_LONG_EDGE`).
  - `maxFps`: frames per second. Default `60`; clamped to `1`–`120`.
  - `bitrate`: bits per second. Default 8 Mbps when the long-edge cap is above 1280 or `0`, else 4 Mbps; clamped to 2–20 Mbps.
  - The phone may still lower these when its encoder cannot do them (it retries at 30 fps, then with a 1280 cap); the VIDEO_CONFIG it sends describes what it actually encodes.
  - Every field present must be a JSON integer in `u32` range (`1920.0`, `-1` or `"1920"` are not). A START that cannot be parsed, before streaming started, ends the session: the phone sends BYE `unknown` and closes (skipping it would leave the receiver waiting for video forever). A malformed repeated START is ignored like any repeated START.
- `rotation`: display rotation in quarter turns (`Surface.ROTATION_*`, 0–3).
- `width`/`height` are the encoded video size; `displayWidth`/`displayHeight` the real display size in pixels.
- `dt_ms` in TOUCH_GESTURE is the delay since the previous point (0 for the first).
- Unknown JSON fields are ignored; unknown enum strings (state, reason, auth mode) decode as "unknown". Unknown `u8` codes in binary messages are preserved (`Other(n)`).
- Fixed-layout binary payloads may be followed by extra bytes, which are ignored (room for extension). PING/PONG must be exactly 8 bytes.
- A known type whose payload cannot be parsed is reported as `Malformed`; the frame is consumed and the stream stays in sync. The receiver of such a frame may close the connection.

### Coordinates

All `x`, `y` are **normalised `u16` over the video frame**: 0 is the first pixel (left/top), 65535 the last (right/bottom). The sender maps them to display pixels using `displayWidth`/`displayHeight`:

```
pixel = round(n × (size − 1) / 65535)        n = round(pixel × 65535 / (size − 1))
```

Receivers map window points through the aspect-fit (letterboxed) video rectangle; clicks in the letterbox bars are not sent.

**SCROLL**: `x`,`y` is where the finger goes down; `dx`,`dy` is the finger-drag distance, signed, in the same normalised units (65535 = the full video width / height). Positive `dy` = the finger moves **down** (content scrolls up, like dragging a page down), positive `dx` = right. The sender maps `dx`,`dy` to display pixels exactly like coordinates (`d × (size − 1) / 65535`), keeping the sign, and performs a short swipe from (x, y) by (dx, dy).

## Session sequence

```
Receiver (client)                                          Phone (server)
  ── "AMR1" ───────────────────────────────────────────────▶
  ◀─────────────────────────────────────────────── "AMR1" ──
  ── CLIENT_HELLO {proto:2, clientName, clientId, nonceC, kx} ─▶
  ◀── SERVER_HELLO {proto:2, …, authModes, nonceS, kx} ─────────
  │
  ├─ token: ── AUTH {mode:"token", proof:clientProof} ─────▶   verify clientProof
  │         ◀──────── AUTH_RESULT {ok:true, serverProof} ──
  │         verify serverProof
  │
  ├─ pin:   ── AUTH {mode:"pin", proof:"", pake:msgA} ─────▶   count attempt; SPAKE2 B
  │         ◀── PAKE_REPLY {pake:msgB, serverProof:serverConfirm} ──
  │         verify serverConfirm (else "wrong PIN", close)
  │         ── AUTH_CONFIRM {proof:clientConfirm} ─────────▶   verify clientConfirm
  │         ◀────────────────────── AUTH_RESULT {ok:true} ──   both store the new PK
  │
  └─ none:  ── AUTH {mode:"none", proof:""} ───────────────▶   only if allow_no_auth
            ◀────────────────────── AUTH_RESULT {ok:true} ──

  failure:  ◀── AUTH_RESULT {ok:false, reason, retryAfterMs?} ── then BYE auth_failed, close

  ═══════════════ every later frame, both directions, is an encrypted record ═══════════════
  ◀── STATUS control_available | control_unavailable ──   always the phone's first record
  ◀── STATUS screen_off ──                                 next, only if the screen is off
  ── START {maxLongEdge, maxFps, bitrate} ─────────────────▶   (required; first client record)
  ◀──────── VIDEO_CONFIG (flags=CONFIG) ──
  ◀──────── VIDEO_FRAME (flags=KEYFRAME) ──    first frame is always an IDR
  ◀──────── VIDEO_FRAME ... ──
  ── PING (every 2 s) ─────────────────────▶
  ◀─────────────────────────────── PONG ──
  ── REQUEST_KEYFRAME / input messages ───▶
  ◀── STATUS / VIDEO_CONFIG (on rotation) ──
  ── BYE / ◀── BYE                              then close
```

- The **server's last plaintext frame is AUTH_RESULT**; the **client's last plaintext frame is AUTH** (token / none) **or AUTH_CONFIRM** (pin). Bytes received after that frame are records (`Decoder::take_buffered` hands any already-buffered bytes to the `Opener`).
- Each side closes after 6 s without receiving anything.
- On rotation: STATUS `reconfiguring`, then a new VIDEO_CONFIG followed by an IDR frame.
- Newest authenticated client wins; the old one gets BYE `replaced`.
- The phone's first record is always STATUS `control_available` or `control_unavailable` (always `control_unavailable` for `none`), then the sticky STATUS `screen_off` if the screen is off. Both are sent without waiting for START.
- START must be the client's first record. Before it the phone answers PING and honours BYE, ignores REQUEST_KEYFRAME, and **drops control messages**; after it, a repeated START is ignored.
- A handshake message (CLIENT_HELLO, AUTH, AUTH_CONFIRM) inside a record is a protocol error: the phone closes the connection.
- Control messages are accepted only after START, only on sessions authenticated with `pin` or `token`, and only while the phone says `control_available`.

## Authentication

### Choosing a mode (client)

- Use `pin` if offered and the user has supplied the PIN for this attempt (an explicit PIN wins over a stored key, so the user can re-pair after the phone refused that key); else `token` if a pairing key is stored for the SERVER_HELLO `deviceId`. If a PIN is needed but not at hand, close and ask the user (`NeedsPin`), then reconnect with it — the phone's handshake timeout is far shorter than a human typing.
- Send `none` only when the client's config explicitly allows it (devtools/tests). The phone accepts `none` only with `allow_no_auth`, otherwise it answers `mode_unsupported`.
- Token mode, `unknown_client` or `bad_proof`: report "pairing required" and ask for a PIN, but **keep** the stored key: AUTH_RESULT is unauthenticated plaintext, so deleting the key on its say-so would let anyone at the phone's address unpair the receiver. A successful PIN pairing replaces it. Server proof mismatch: close, report "device identity changed", also keeping the key.
- PIN mode, `serverConfirm` mismatch: close without sending AUTH_CONFIRM, report "wrong PIN".

### Phone-side PIN policy

6-digit PIN (`generate_pin`), shown on the phone. An attempt is counted when AUTH `pin` arrives (so a client that just disconnects still burns one) and the count resets on success. After 5 failures the phone rotates the PIN and refuses PIN auth (`locked_out` + `retryAfterMs`); the lockout is server-wide. Consecutive lockouts escalate: 30 s, 60 s, 120 s, … doubling each time, capped at 1 h. An expired lockout does not reset the escalation; a successful PIN pairing does. The PIN state lives in memory only: tapping "New PIN" on the phone (`Server::new_pin`) rotates the PIN and clears the lockout, the failure count and the escalation, and so does restarting mirroring (a fresh PIN, no lockout). Both need someone at the phone, which the LAN attacker the lockout guards against is not. (Without escalation a LAN attacker would get 5 guesses every 30 s, about 14 000 a day against 10⁶ PINs.) The PIN is also rotated after every successful pairing.

At most 5 attempts are counted at once, including ones still in flight (an AUTH `pin` whose handshake has not finished), so parallel connections cannot exceed the limit. "New PIN" resets the count, so right after it up to 5 more attempts can be admitted while ones on the old PIN are still in flight; those fail when they resolve (the old PIN no longer pairs) and are neither counted against the new 5 (so they cannot start a lockout, even with 5 new attempts in flight) nor reported to the phone's UI. With a fixed devtools PIN, which "New PIN" does not rotate, an old attempt can still succeed. A 6th counted attempt while 5 are in flight is refused with `locked_out` and `retryAfterMs` = the phone's handshake timeout (by then an in-flight attempt has resolved), without starting a lockout. The phone reports refused attempts to its UI at most once every 5 s.

### Key schedule

```
lp(x)  = u16_be(len(x)) || x
ls(xs) = lp(x1) || lp(x2) || … || lp(xn)                   empty list → empty string
ctx    = lp("amr2") || lp(nonceC) || lp(nonceS) || lp(kxC) || lp(kxS) || lp(clientId) || lp(deviceId) || lp(mode)
         || lp(clientName) || lp(deviceName) || lp(model) || lp(ls(authModes)) || lp(ls(caps))
th     = SHA-256(ctx)
dh     = X25519(own_secret, peer_kx)                       all-zero result → abort

token: K = PK (stored 32-byte pairing key)
       clientProof = HMAC-SHA256(K, lp("C") || lp(th))
       serverProof = HMAC-SHA256(K, lp("S") || lp(th))
       thF = th

pin:   SPAKE2 (Ed25519 group, asymmetric: client = A, phone = B)
         password = "androidmirror-pin" || PIN,  idA = clientId,  idB = deviceId
       Kp  = SPAKE2 shared key (32 bytes)
       thP = SHA-256(ctx || lp(msgA) || lp(msgB))
       serverConfirm = HMAC-SHA256(Kp, lp("S") || lp(thP))
       clientConfirm = HMAC-SHA256(Kp, lp("C") || lp(thP))
       K = Kp;  thF = thP
       new PK = HKDF-SHA256(salt = thP, ikm = Kp, info = "amr2 pairing key", L = 32)

none:  K = 32 zero bytes;  thF = th

session: PRK = HKDF-Extract(salt = K, ikm = dh)               (HKDF-SHA256)
         OKM = HKDF-Expand(PRK, info = "amr2 session keys" || thF, L = 64)
         key_c2s = OKM[0..32]      receiver → phone
         key_s2c = OKM[32..64]     phone → receiver
```

- `||` is byte concatenation. Nonces, `kx` keys and SPAKE2 messages enter as their **raw bytes** (hex-decoded; nonces and `kx` must be exactly 32 bytes); `clientId`, `deviceId`, `clientName`, `deviceName`, `model` and each `caps` item as UTF-8 (the JSON string values, unescaped); `mode` and each `authModes` item as the ASCII wire string (`"pin"`, `"token"`, `"none"`); labels as ASCII.
- Lists (`authModes`, `caps`) are encoded with `ls()`: every item length-prefixed, in the order sent, and the whole encoding wrapped in one more `lp()`. Items may contain any characters (commas included); `["a","b"]`, `["ab"]` and `["a,b"]` all encode differently. `authModes` items that are not one of the three v2 modes are skipped by both sides (the client cannot know their spelling); `proto`, `sdkInt` and `codecs` are not bound.
- Any `lp()` field (an id, a name, `model`, or an `ls()` encoding) longer than 65535 bytes fails the handshake (never truncated).
- `mode` and the rest of both hellos are part of `th`, so every proof and key is bound to the mode actually used and to what each side said: a relay that rewrites AUTH's mode, a nonce, a `kx`, an id, a name, the model, the offered modes or the caps produces mismatching proofs and keys (downgrade protection).
- The X25519 secret is fresh per connection (forward secrecy); `K` makes the session keys depend on the authentication secret.
- SPAKE2 never exposes the PIN to a passive observer, and an active attacker gets one guess per connection. The client verifies `serverConfirm` before sending `clientConfirm`.
- All proof comparisons are constant time.
- After a successful `pin` auth both sides store the new `PK` (phone keyed by `clientId`, receiver keyed by `deviceId`) and use `token` next time. Re-pairing replaces the entry.

## Record layer

Every frame after authentication — in both directions and for **every** mode, including `none` (unauthenticated but still encrypted) — is sent as a record:

```
record    = u32_be len || ciphertext || tag         len = ciphertext length + 16 (tag)
plaintext = exactly one frame (16-byte header + payload), as above
AEAD      = ChaCha20-Poly1305 (RFC 8439)
key       = key_c2s (receiver → phone) / key_s2c (phone → receiver)
nonce     = 00 00 00 00 || u64_be seq               seq = 0, 1, 2, … per direction, +1 per record
aad       = the 4 length bytes
```

- Limits: phone → receiver `len ≤ 16 + 8 MiB + 16`; receiver → phone `len ≤ 16 + 64 KiB + 16`. `len < 32` (header + tag) is invalid. Both are checked from the 4 length bytes alone, before buffering the body. Inside the record the usual frame limits still apply (64 KiB for JSON types).
- Over the limit, a decryption failure (wrong key, tampered, reordered, replayed or dropped record), a plaintext that is not exactly one frame, or sequence exhaustion → close the connection **without BYE** (it could not be authenticated).
- `mirror_protocol::secure`: `Sealer` (frame → record) and the incremental `Opener` (push bytes → decrypted `Message`s), symmetrical to `Decoder`.

## Test vectors

Computed independently (pure-Python RFC 7748 X25519, RFC 8439 ChaCha20-Poly1305, `hashlib`/`hmac`), pinned in `tests/handshake.rs` and `tests/secure.rs`.

Inputs: `nonceC = 00 01 … 1f`, `nonceS = 20 21 … 3f`, client X25519 secret `40 41 … 5f`, server X25519 secret `60 61 … 7f`, `clientId = "mac-client-1"`, `clientName = "Mac"`, `deviceId = "pixel-8-abc"`, `deviceName = "Pixel"`, `model = "Pixel 8"`, `authModes = ["pin","token","none"]`, `caps = ["control"]`, `PK = 80 81 … 9f`.

So the hello tail of `ctx` is `0003 "Mac" 0005 "Pixel" 0007 "Pixel 8" 0012 (0003 "pin" 0005 "token" 0004 "none") 0009 (0007 "control")`.

### Token mode

| Value | Hex |
|---|---|
| kxC | `79a631eede1bf9c98f12032cdeadd0e7a079398fc786b88cc846ec89af85a51a` |
| kxS | `675dd574ed7789310b3d2e7681f3790b466c773b1521fecf36577958371ea52f` |
| dh | `d6fb939511b2381bc8599b4b8edc5968829450dfd7a87aebe78a703cd04cd54e` |
| th | `7a11c3c950adcfcbdb632a10228a67cec2091ef60702af0dac1403f894bb353d` |
| clientProof | `2b93c9dd914f20a4687c0522e999746c0eb670ec75949e91d17ddf824c8a6342` |
| serverProof | `b37320d4a45f706b5e2e8ee747d397ed7e18dde27e5f732e7ba573c7aa3b25b8` |
| key_c2s | `cda68a732e33f6741d17ab1a16ec36d47b4769eacf97661bf620570330c619ab` |
| key_s2c | `7c1576301d7901f27d8b7e18fb538d0624f623c86d311067bb3545e56a5a77c5` |

### Mode `none` (same inputs, K = 32 zero bytes)

| Value | Hex |
|---|---|
| th | `9fb9364fae0219e59698ca322d527a6db19e170f322a06c679355e1e7b66b657` |
| key_c2s | `aab2a0688bf0c61bae92bc8f4a07a08bb026d2efd9d32c237bf337783f044981` |
| key_s2c | `d4054938d4b7a616512bb6792e00ed5c9ba36972336e17c113e4e7ab86c86ee8` |

### Records (token-mode `key_c2s`)

| Record | Hex |
|---|---|
| seq 0: REQUEST_KEYFRAME | `00000020fb5b75dbd30c66073ed891805848b72aa576431a7ec3b3680c3047af6db6cded` |
| seq 1: PING `01 02 … 08` | `00000028479470c3dfdcecd54637bd01dc0db1a3f6108f95c765795417e4e7b5c0346818715c0c72adf4d1c1` |

PIN mode is randomized (SPAKE2), so it is pinned by full round trips instead: both sides derive identical session keys and an identical new `PK`, a wrong PIN fails the client's `serverConfirm` check, and a hand-rolled client following the formulas above is accepted by the server with the right PIN and refused with a wrong one.

## Video

- H.264 Annex-B, 3- or 4-byte start codes. VIDEO_CONFIG carries SPS and PPS; VIDEO_FRAME carries one access unit (it may also repeat SPS/PPS/AUD, which AVCC conversion drops).
- Encode size: `scale = min(1, maxLongEdge / longEdge)`; each dimension is scaled, rounded, then floored to a multiple of 16 (minimum 16). Example: 1080×2400 at 1920 → 864×1920.
