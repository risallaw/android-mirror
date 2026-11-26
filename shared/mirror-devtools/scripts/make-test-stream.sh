#!/usr/bin/env bash
# Generate a 20 s 1088x2400@60 Annex-B H.264 test stream for fakeserver.
# Usage: make-test-stream.sh [out.h264]   (default: <repo>/target/test.h264)
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="${1:-$here/../../../target/test.h264}"

command -v ffmpeg >/dev/null 2>&1 || {
    echo "error: ffmpeg not found on PATH" >&2
    exit 1
}
mkdir -p "$(dirname "$out")"
# Encode next to the target and rename on success, so a failed or
# interrupted run never leaves a truncated stream at "$out".
tmp="$(mktemp "$out.XXXXXX")"
trap 'rm -f "$tmp"' EXIT
ffmpeg -y -loglevel error -f lavfi -i testsrc2=size=1088x2400:rate=60 -t 20 \
    -c:v libx264 -profile:v high -bf 0 -g 120 -pix_fmt yuv420p \
    -bsf:v h264_mp4toannexb -f h264 "$tmp"
# mktemp creates 0600; a test stream is not private.
chmod 644 "$tmp"
mv -f "$tmp" "$out"
trap - EXIT
echo "$out"
