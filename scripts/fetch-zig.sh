#!/usr/bin/env bash
# fetch-zig.sh — provision the vendored Zig toolchain used by .local-tools/cc
# with verified provenance (audit 2026-07 L10).
#
# The .local-tools/ directory is gitignored local-dev convenience only (it is not
# tracked and never reaches release artifacts, which build with musl-tools in
# CI). Previously the Zig build was trust-on-first-placement: no fetch script, no
# checksum. This script downloads a pinned Zig release and verifies its SHA-256
# against the value published in Zig's signed download index before extracting.
set -euo pipefail

# Pinned version + official SHA-256 (from https://ziglang.org/download/index.json).
ZIG_VERSION="${ZIG_VERSION:-0.14.1}"
ZIG_TARBALL="zig-x86_64-linux-${ZIG_VERSION}.tar.xz"
ZIG_SHA256="${ZIG_SHA256:-24aeeec8af16c381934a6cd7d95c807a8cb2cf7df9fa40d359aa884195c4716c}"
ZIG_URL="https://ziglang.org/download/${ZIG_VERSION}/${ZIG_TARBALL}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="$ROOT/.local-tools"
mkdir -p "$DEST"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "Fetching Zig ${ZIG_VERSION}…"
curl -fsSL "$ZIG_URL" -o "$TMP/$ZIG_TARBALL"

echo "Verifying SHA-256…"
GOT="$(sha256sum "$TMP/$ZIG_TARBALL" | cut -d' ' -f1)"
if [ "$GOT" != "$ZIG_SHA256" ]; then
  echo "zig SHA-256 mismatch:" >&2
  echo "  expected $ZIG_SHA256" >&2
  echo "  got      $GOT" >&2
  exit 1
fi

echo "Extracting to $DEST…"
tar -C "$DEST" -xf "$TMP/$ZIG_TARBALL"
echo "Zig ${ZIG_VERSION} verified and installed under .local-tools/. Point the"
echo "cc/c++ wrappers at .local-tools/zig-x86_64-linux-${ZIG_VERSION}/zig if needed."
