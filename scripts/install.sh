#!/usr/bin/env bash
# Legion SIEM – Linux/macOS install script
# Usage: curl -fsSL https://raw.githubusercontent.com/tbgor/legion/main/scripts/install.sh | bash
set -e

REPO="tbgor/legion"
SKIP_OLLAMA_INSTALL="${LEGION_SKIP_OLLAMA_INSTALL:-0}"

# ── Detect platform ─────────────────────────────────────────────────────────
OS="$(uname -s)"
ARCH="$(uname -m)"

require_sudo() {
    if [ "$(id -u)" -eq 0 ]; then
        SUDO_CMD=""
        return
    fi
    if command -v sudo >/dev/null 2>&1; then
        echo "Requesting admin elevation via sudo..."
        sudo -v
        SUDO_CMD="sudo"
        return
    fi
    echo "This installer needs administrator privileges. Re-run as root."
    exit 1
}

add_path_if_missing() {
    local line="$1"
    local profile="$2"
    touch "$profile"
    if ! grep -Fq "$line" "$profile"; then
        printf '\n%s\n' "$line" >> "$profile"
        echo "Updated PATH in $profile"
    fi
}

install_ollama() {
    if [ "$SKIP_OLLAMA_INSTALL" = "1" ]; then
        echo "Skipping Ollama install (LEGION_SKIP_OLLAMA_INSTALL=1)."
        return
    fi

    if command -v ollama >/dev/null 2>&1; then
        echo "Ollama already installed."
        return
    fi

    echo "Installing Ollama..."
    # Supply-chain note (CIS 2/7): this runs a remote installer script directly.
    # To skip and install Ollama yourself, re-run with LEGION_SKIP_OLLAMA_INSTALL=1.
    echo "  -> running the official Ollama installer from https://ollama.com (set LEGION_SKIP_OLLAMA_INSTALL=1 to skip)."
    if [ "$OS" = "Linux" ]; then
        curl -fsSL https://ollama.com/install.sh | sh
        if command -v systemctl >/dev/null 2>&1; then
            systemctl enable --now ollama >/dev/null 2>&1 || true
        fi
    elif [ "$OS" = "Darwin" ]; then
        if command -v brew >/dev/null 2>&1; then
            brew install --cask ollama
        else
            echo "Homebrew not found; installing Homebrew first..."
            NONINTERACTIVE=1 /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
            eval "$(/opt/homebrew/bin/brew shellenv 2>/dev/null || /usr/local/bin/brew shellenv)"
            brew install --cask ollama
        fi
    fi

    if command -v ollama >/dev/null 2>&1; then
        echo "Ollama installed successfully."
    else
        echo "Ollama install completed but command is not available yet; open a new terminal session."
    fi
}

require_sudo "$@"

if [ "$OS" = "Linux" ]; then
    BIN_DIR="${LEGION_BIN_DIR:-/usr/local/bin}"
    DATA_DIR="${LEGION_DATA_DIR:-/var/lib/legion}"
else
    BIN_DIR="${LEGION_BIN_DIR:-/usr/local/bin}"
    DATA_DIR="${LEGION_DATA_DIR:-/usr/local/var/legion}"
fi

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
$SUDO_CMD mkdir -p "$BIN_DIR"
$SUDO_CMD cp "$EXTRACTED/legion"     "$BIN_DIR/legion"
$SUDO_CMD cp "$EXTRACTED/legion-tui" "$BIN_DIR/legion-tui"
$SUDO_CMD cp "$EXTRACTED/legion-web" "$BIN_DIR/legion-web"
$SUDO_CMD chmod +x "$BIN_DIR/legion" "$BIN_DIR/legion-tui" "$BIN_DIR/legion-web"

# ── Create data dir ──────────────────────────────────────────────────────────
$SUDO_CMD mkdir -p "$DATA_DIR"
# Owner-only (CIS Control 3): the data dir holds the SIEM database and cached
# rules; keep it off-limits to group/other regardless of the system umask.
$SUDO_CMD chmod 700 "$DATA_DIR" >/dev/null 2>&1 || true

if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_CMD" = "" ]; then
    $SUDO_CMD chown -R "$SUDO_USER":"$SUDO_USER" "$DATA_DIR" >/dev/null 2>&1 || true
fi

echo ""
echo "Legion ${LATEST} installed!"
echo "  CLI:      $BIN_DIR/legion"
echo "  TUI:      $BIN_DIR/legion-tui"
echo "  Web:      $BIN_DIR/legion-web"
echo "  Data dir: $DATA_DIR"
echo ""

# ── PATH persistence ─────────────────────────────────────────────────────────
if ! echo "$PATH" | tr ':' '\n' | grep -q "^${BIN_DIR}$"; then
    export PATH="$PATH:$BIN_DIR"
fi

if [ -n "${SUDO_USER:-}" ]; then
    TARGET_USER="$SUDO_USER"
    USER_HOME=$(getent passwd "$TARGET_USER" 2>/dev/null | cut -d: -f6 || true)
    if [ -z "$USER_HOME" ] && [ "$OS" = "Darwin" ]; then
        USER_HOME=$(dscl . -read "/Users/$TARGET_USER" NFSHomeDirectory 2>/dev/null | awk '{print $2}')
    fi
else
    TARGET_USER="$USER"
    USER_HOME="$HOME"
fi

if [ -z "$USER_HOME" ]; then
    USER_HOME="$HOME"
fi

PATH_LINE="export PATH=\"\$PATH:${BIN_DIR}\""
add_path_if_missing "$PATH_LINE" "$USER_HOME/.profile"
add_path_if_missing "$PATH_LINE" "$USER_HOME/.bashrc"
add_path_if_missing "$PATH_LINE" "$USER_HOME/.zshrc"

# ── Ollama auto-install ──────────────────────────────────────────────────────
install_ollama

echo ""
echo "Quick start:"
echo "  legion feeds refresh   # pull latest threat feeds"
echo "  legion scan .          # scan current directory"
echo "  legion alerts          # view active alerts"
echo "  legion-tui             # launch terminal dashboard"
echo "  legion-web             # launch browser dashboard (http://localhost:3000)"
