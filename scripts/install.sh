#!/usr/bin/env bash
# Legion SIEM – Linux install script
# Usage: curl -fsSL https://raw.githubusercontent.com/OpenSource-For-Freedom/legion/main/scripts/install.sh | bash
set -e

REPO="OpenSource-For-Freedom/legion"
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

    # L8 (audit 2026-07): piping a remote installer to a root shell is now
    # opt-in. The default runtime is the OpenAI-compatible local server, so
    # Ollama (legacy) is not installed unless the operator asks for it with
    # LEGION_INSTALL_OLLAMA=1.
    if [ "${LEGION_INSTALL_OLLAMA:-0}" != "1" ]; then
        echo "Skipping Ollama install (legacy runtime). Set LEGION_INSTALL_OLLAMA=1 to install it."
        return
    fi

    echo "Installing Ollama..."
    # Supply-chain note (CIS 2/7): this runs a remote installer script directly.
    echo "  -> running the official Ollama installer from https://ollama.com."
    if [ "$OS" = "Linux" ]; then
        curl -fsSL https://ollama.com/install.sh | sh
        if command -v systemctl >/dev/null 2>&1; then
            systemctl enable --now ollama >/dev/null 2>&1 || true
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

# ── Integrity check ──────────────────────────────────────────────────────────
# Verify the published SHA-256 before extracting (supply-chain, CIS 2/7).
# Override with LEGION_SKIP_CHECKSUM=1 (not recommended).
if [ "${LEGION_SKIP_CHECKSUM:-0}" != "1" ]; then
    if curl -fsSL "${URL}.sha256" -o "$TMP/${ARCHIVE}.sha256"; then
        if ( cd "$TMP" && sha256sum -c "${ARCHIVE}.sha256" >/dev/null 2>&1 ); then
            echo "Checksum verified."
        else
            echo "Checksum verification FAILED for ${ARCHIVE}. Aborting." >&2
            exit 1
        fi
    else
        echo "No published checksum for ${ARCHIVE}. Set LEGION_SKIP_CHECKSUM=1 to install anyway." >&2
        exit 1
    fi
fi

tar -xzf "$TMP/$ARCHIVE" -C "$TMP"
EXTRACTED="$TMP/legion-${LATEST}-${TARGET}"

# ── Install binaries ─────────────────────────────────────────────────────────
$SUDO_CMD mkdir -p "$BIN_DIR"
$SUDO_CMD cp "$EXTRACTED/legion-web" "$BIN_DIR/legion-web"
$SUDO_CMD chmod +x "$BIN_DIR/legion-web"

# ── Create data dir ──────────────────────────────────────────────────────────
$SUDO_CMD mkdir -p "$DATA_DIR"
# Owner-only (CIS Control 3): the data dir holds the SIEM database and cached
# rules; keep it off-limits to group/other regardless of the system umask.
$SUDO_CMD chmod 700 "$DATA_DIR" >/dev/null 2>&1 || true

# One-prompt mode: after installer elevation, suppress runtime re-prompts.
$SUDO_CMD mkdir -p /etc/legion
$SUDO_CMD sh -c 'printf "installed=%s\n" "$(date -u +%FT%TZ)" > /etc/legion/one_prompt_mode'
$SUDO_CMD chmod 644 /etc/legion/one_prompt_mode >/dev/null 2>&1 || true

if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_CMD" = "" ]; then
    $SUDO_CMD chown -R "$SUDO_USER":"$SUDO_USER" "$DATA_DIR" >/dev/null 2>&1 || true
fi

echo ""
echo "Legion ${LATEST} installed!"
echo "  App:      $BIN_DIR/legion-web"
echo "  Data dir: $DATA_DIR"
echo "  Mode:     one admin prompt at install (runtime elevation prompts disabled)"
echo ""

# ── PATH persistence ─────────────────────────────────────────────────────────
if ! echo "$PATH" | tr ':' '\n' | grep -q "^${BIN_DIR}$"; then
    export PATH="$PATH:$BIN_DIR"
fi

if [ -n "${SUDO_USER:-}" ]; then
    TARGET_USER="$SUDO_USER"
    USER_HOME=$(getent passwd "$TARGET_USER" 2>/dev/null | cut -d: -f6 || true)
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
echo "  legion-web             # launch the dashboard (http://localhost:3000)"
