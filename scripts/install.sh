#!/usr/bin/env bash
# Legion SIEM – Linux/macOS install script
# Usage: curl -fsSL https://raw.githubusercontent.com/tbgor/legion/main/scripts/install.sh | bash
set -e

REPO="tbgor/legion"
BIN_DIR="${LEGION_BIN_DIR:-$HOME/.local/bin}"
DATA_DIR="${LEGION_DATA_DIR:-$HOME/.local/share/legion}"

# ── Detect platform ─────────────────────────────────────────────────────────
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
    Linux)
        case "$ARCH" in
            x86_64)  TARGET="x86_64-unknown-linux-musl" ;;
            aarch64) TARGET="aarch64-unknown-linux-musl" ;;
            *)       echo "Unsupported arch: $ARCH"; exit 1 ;;
        esac
        ;;
    Darwin)
        case "$ARCH" in
            x86_64)  TARGET="x86_64-apple-darwin" ;;
            arm64)   TARGET="aarch64-apple-darwin" ;;
            *)       echo "Unsupported arch: $ARCH"; exit 1 ;;
        esac
        ;;
    *)
        echo "Unsupported OS: $OS"
        echo "For Windows, use install.ps1"
        exit 1
        ;;
esac

# ── Get latest release tag ───────────────────────────────────────────────────
echo "Fetching latest Legion release..."
LATEST=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
         | grep '"tag_name"' | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')

if [ -z "$LATEST" ]; then
    echo "Could not determine latest version. Check https://github.com/${REPO}/releases"
    exit 1
fi

echo "Installing Legion ${LATEST} for ${TARGET}..."

# ── Download & extract ───────────────────────────────────────────────────────
ARCHIVE="legion-${LATEST}-${TARGET}.tar.gz"
URL="https://github.com/${REPO}/releases/download/${LATEST}/${ARCHIVE}"
TMP="$(mktemp -d)"
trap "rm -rf $TMP" EXIT

curl -fsSL "$URL" -o "$TMP/$ARCHIVE"
tar -xzf "$TMP/$ARCHIVE" -C "$TMP"
EXTRACTED="$TMP/legion-${LATEST}-${TARGET}"

# ── Install binaries ─────────────────────────────────────────────────────────
mkdir -p "$BIN_DIR"
cp "$EXTRACTED/legion"     "$BIN_DIR/legion"
cp "$EXTRACTED/legion-tui" "$BIN_DIR/legion-tui"
cp "$EXTRACTED/legion-web" "$BIN_DIR/legion-web"
chmod +x "$BIN_DIR/legion" "$BIN_DIR/legion-tui" "$BIN_DIR/legion-web"

# ── Create data dir ──────────────────────────────────────────────────────────
mkdir -p "$DATA_DIR"

echo ""
echo "Legion ${LATEST} installed!"
echo "  CLI:      $BIN_DIR/legion"
echo "  TUI:      $BIN_DIR/legion-tui"
echo "  Web:      $BIN_DIR/legion-web"
echo "  Data dir: $DATA_DIR"
echo ""

# ── PATH check ───────────────────────────────────────────────────────────────
if ! echo "$PATH" | tr ':' '\n' | grep -q "^${BIN_DIR}$"; then
    echo "  Add to PATH: export PATH=\"\$PATH:${BIN_DIR}\""
    echo "  (add this to ~/.bashrc or ~/.zshrc)"
fi

echo ""
echo "Quick start:"
echo "  legion feeds refresh   # pull latest threat feeds"
echo "  legion scan .          # scan current directory"
echo "  legion alerts          # view active alerts"
echo "  legion-tui             # launch terminal dashboard"
echo "  legion-web             # launch browser dashboard (http://localhost:3000)"
