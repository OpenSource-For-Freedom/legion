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
#
# M7 (audit 2026-07): these come from the mutable `continuous` tag, so we verify
# a pinned SHA-256 and abort on mismatch — a silently-mutated or MITM'd tool must
# not be baked into the shipped AppImage. Bump the hashes deliberately when
# updating the tooling. Only x86_64 is pinned (the only shipped release arch);
# other arches abort rather than run unverified.
TOOL="$WORK/appimagetool"
RUNTIME="$WORK/runtime-$ARCH"

case "$ARCH" in
  x86_64)
    TOOL_SHA256="b90f4a8b18967545fda78a445b27680a1642f1ef9488ced28b65398f2be7add2"
    RUNTIME_SHA256="1cc49bcf1e2ccd593c379adb17c9f85a36d619088296504de95b1d06215aebbf"
    ;;
  *)
    echo "build-appimage: no pinned tool hashes for arch '$ARCH'; refusing to run unverified tooling" >&2
    exit 1
    ;;
esac

verify_sha256() {
  local file="$1" expected="$2" got
  got="$(sha256sum "$file" | cut -d' ' -f1)"
  if [ "$got" != "$expected" ]; then
    echo "build-appimage: SHA-256 mismatch for $file" >&2
    echo "  expected $expected" >&2
    echo "  got      $got" >&2
    exit 1
  fi
}

curl -fsSL "https://github.com/AppImage/AppImageKit/releases/download/continuous/appimagetool-${ARCH}.AppImage" -o "$TOOL"
curl -fsSL "https://github.com/AppImage/type2-runtime/releases/download/continuous/runtime-${ARCH}" -o "$RUNTIME"
verify_sha256 "$TOOL" "$TOOL_SHA256"
verify_sha256 "$RUNTIME" "$RUNTIME_SHA256"
chmod +x "$TOOL" "$RUNTIME"

# ── pack ─────────────────────────────────────────────────────────────────────
mkdir -p "$(dirname "$OUT")"
# Pack to a temporary file, then move it into place.
#
# Writing $OUT directly fails with "Text file busy" whenever the previous
# AppImage is still running (a FUSE-mounted AppImage holds its own file open),
# and appimagetool exits 0 even when mksquashfs fails underneath it. The build
# therefore reported success and silently left the OLD AppImage on disk — which
# is how a stale binary ends up looking freshly built. rename(2) over a running
# executable is permitted, so packing aside and moving is both atomic and immune
# to ETXTBSY.
TMP_OUT="${OUT}.tmp.$$"
rm -f "$TMP_OUT"
ARCH="$ARCH" "$TOOL" --appimage-extract-and-run --runtime-file "$RUNTIME" "$APPDIR" "$TMP_OUT" || true

# appimagetool's exit status is not trustworthy here, so check the artifact.
if [ ! -s "$TMP_OUT" ]; then
  rm -f "$TMP_OUT"
  echo "error: packaging produced no AppImage." >&2
  echo "       If the previous AppImage is still running, stop it first:" >&2
  echo "         pkill -x legion-web   # add sudo if it self-elevated" >&2
  exit 1
fi
mv -f "$TMP_OUT" "$OUT"
chmod +x "$OUT"
echo "Built $OUT ($(stat -c%s "$OUT") bytes)"
