#!/usr/bin/env bash
# Build mac/build/AndroidMirror.app (release) and sign it.
# SIGN_ID: codesign identity; defaults to "-" (ad-hoc).
#
# The bundle is assembled and signed next to its final place and swapped in
# only once it verifies, so a failed build never destroys the previous app.
set -euo pipefail

MAC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT_DIR="$(cd "$MAC_DIR/.." && pwd)"
APP="$MAC_DIR/build/AndroidMirror.app"
STAGE="$MAC_DIR/build/.AndroidMirror.app.new"
OLD="$MAC_DIR/build/.AndroidMirror.app.old"

# A previous run that could neither install the new app nor put the old one
# back left the old one at $OLD: restore it before anything can delete it.
if [[ -e "$OLD" && ! -e "$APP" ]]; then
    mv "$OLD" "$APP"
    echo "build-app.sh: restored the previous app from $OLD" >&2
fi

cd "$ROOT_DIR"
# Build for this Mac's own architecture, named explicitly so that
# CARGO_BUILD_TARGET or a build.target setting cannot move the binary
# somewhere this script does not look.
HOST="$(rustc -vV | sed -n 's/^host: //p')"
[[ -n "$HOST" ]] || { echo "build-app.sh: cannot tell the host target from rustc -vV" >&2; exit 1; }
cargo build --release -p mirror-mac --target "$HOST"

# Ask cargo where it built: honours CARGO_TARGET_DIR, build.target-dir in any
# .cargo/config.toml, and relative paths, which guessing "$ROOT_DIR/target"
# does not. plutil reads JSON and ships with macOS (python3 may not).
TARGET_DIR="$(cargo metadata --format-version 1 --no-deps |
    plutil -extract target_directory raw -o - -)"
BIN="$TARGET_DIR/$HOST/release/AndroidMirror"
[[ -x "$BIN" ]] || { echo "build-app.sh: $BIN not found" >&2; exit 1; }
plutil -lint "$MAC_DIR/bundle/Info.plist" >/dev/null
[[ -f "$MAC_DIR/bundle/AppIcon.icns" ]] || { echo "build-app.sh: bundle/AppIcon.icns missing" >&2; exit 1; }

rm -rf "$STAGE" "$OLD"
trap 'rm -rf "$STAGE" "$OLD"' EXIT
mkdir -p "$STAGE/Contents/MacOS" "$STAGE/Contents/Resources"
cp "$BIN" "$STAGE/Contents/MacOS/AndroidMirror"
cp "$MAC_DIR/bundle/Info.plist" "$STAGE/Contents/Info.plist"
cp "$MAC_DIR/bundle/AppIcon.icns" "$STAGE/Contents/Resources/AppIcon.icns"

codesign --force --sign "${SIGN_ID:--}" "$STAGE"
codesign --verify --strict "$STAGE"

# Swap: the old app is only moved aside until the new one is in place, and
# put back if that fails.
if [[ -e "$APP" ]]; then
    mv "$APP" "$OLD"
fi
if ! mv "$STAGE" "$APP"; then
    if [[ -e "$OLD" ]] && ! mv "$OLD" "$APP"; then
        # Never let the EXIT trap delete the only copy of the old app.
        trap 'rm -rf "$STAGE"' EXIT
        echo "build-app.sh: cannot put the old app back; it is at $OLD" >&2
    fi
    echo "build-app.sh: cannot move the new app into place" >&2
    exit 1
fi
rm -rf "$OLD"
echo "Built $APP"
if [[ "${SIGN_ID:--}" == "-" ]]; then
    # An ad-hoc signature's identity is the binary's hash, which changes with
    # every build: macOS then forgets the Local Network permission and asks
    # again each time. A stable identity keeps the grant.
    echo "build-app.sh: signed ad-hoc; macOS will ask for Local Network access again after each rebuild." >&2
    echo "build-app.sh: set SIGN_ID to a stable codesigning identity (see: security find-identity -p codesigning) to keep the permission." >&2
fi
