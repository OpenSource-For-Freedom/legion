#!/usr/bin/env bash
# Build a Legion AppImage — a single, double-clickable Linux app.
#
# Usage:
#   scripts/build-appimage.sh <legion-web-binary> <output.AppImage> [arch]
#
# Example:
#   scripts/build-appimage.sh \
#     target/x86_64-unknown-linux-musl/release/legion-web \
#     dist/Legion-v1.0.0-x86_64.AppImage
#
# Bundles the binary together with packaging/appimage/{AppRun,legion.desktop}
# and the icon into an AppDir, then packs it with appimagetool using the static
# type2 runtime. The static runtime means the resulting AppImage needs NO
# libfuse2 installed on the user's machine — modern Debian/Ubuntu ship only
# fuse3, so a default-runtime AppImage would fail to launch on them.
set -euo pipefail

BIN="${1:?usage: build-appimage.sh <legion-web binary> <output.AppImage> [arch]}"
OUT="${2:?usage: build-appimage.sh <legion-web binary> <output.AppImage> [arch]}"
ARCH="${3:-x86_64}"

ROOT="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
APPDIR="$WORK/AppDir"

# ── assemble the AppDir ──────────────────────────────────────────────────────
mkdir -p "$APPDIR/usr/bin" "$APPDIR/usr/share/applications" \
         "$APPDIR/usr/share/icons/hicolor/256x256/apps"

install -m755 "$BIN"                                    "$APPDIR/usr/bin/legion-web"
install -m755 "$ROOT/packaging/appimage/AppRun"        "$APPDIR/AppRun"
install -m644 "$ROOT/packaging/appimage/legion.desktop" "$APPDIR/legion.desktop"
install -m644 "$ROOT/packaging/appimage/legion.desktop" "$APPDIR/usr/share/applications/legion.desktop"
install -m644 "$ROOT/assets/legion-icon.png"           "$APPDIR/legion-icon.png"
install -m644 "$ROOT/assets/legion-icon.png"           "$APPDIR/usr/share/icons/hicolor/256x256/apps/legion-icon.png"

# Catch desktop-entry mistakes early (non-fatal if the validator is absent).
command -v desktop-file-validate >/dev/null 2>&1 && \
  desktop-file-validate "$APPDIR/legion.desktop"

# ── fetch tooling ────────────────────────────────────────────────────────────
# appimagetool is itself an AppImage; run it via --appimage-extract-and-run so it
# does not need libfuse2 to mount on the CI runner.
TOOL="$WORK/appimagetool"
RUNTIME="$WORK/runtime-$ARCH"
curl -fsSL "https://github.com/AppImage/AppImageKit/releases/download/continuous/appimagetool-${ARCH}.AppImage" -o "$TOOL"
curl -fsSL "https://github.com/AppImage/type2-runtime/releases/download/continuous/runtime-${ARCH}" -o "$RUNTIME"
chmod +x "$TOOL" "$RUNTIME"

# ── pack ─────────────────────────────────────────────────────────────────────
mkdir -p "$(dirname "$OUT")"
ARCH="$ARCH" "$TOOL" --appimage-extract-and-run --runtime-file "$RUNTIME" "$APPDIR" "$OUT"
echo "Built $OUT"
