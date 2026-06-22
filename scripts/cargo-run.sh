#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 1 ]; then
  echo "usage: cargo-run.sh <cargo-args...>" >&2
  exit 2
fi

resolve_home() {
  local user="$1"
  local home=""
  home="$(getent passwd "$user" 2>/dev/null | cut -d: -f6 || true)"
  if [ -z "$home" ]; then
    home="$(eval echo "~$user" 2>/dev/null || true)"
  fi
  printf '%s' "$home"
}

CARGO_BIN=""
RUSTUP_BIN=""

# Under sudo, prefer the invoking user's Rust toolchain so cargo/rustup metadata aligns.
if [ -n "${SUDO_USER:-}" ]; then
  SUDO_HOME="$(resolve_home "$SUDO_USER")"
  if [ -n "$SUDO_HOME" ] && [ -x "$SUDO_HOME/.cargo/bin/cargo" ]; then
    export CARGO_HOME="$SUDO_HOME/.cargo"
    export RUSTUP_HOME="$SUDO_HOME/.rustup"
    CARGO_BIN="$CARGO_HOME/bin/cargo"
    if [ -x "$CARGO_HOME/bin/rustup" ]; then
      RUSTUP_BIN="$CARGO_HOME/bin/rustup"
    fi
  fi
fi

if [ -z "$CARGO_BIN" ] && [ -x "$HOME/.cargo/bin/cargo" ]; then
  export CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
  export RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"
  CARGO_BIN="$HOME/.cargo/bin/cargo"
  if [ -x "$HOME/.cargo/bin/rustup" ]; then
    RUSTUP_BIN="$HOME/.cargo/bin/rustup"
  fi
fi

if [ -z "$CARGO_BIN" ]; then
  CARGO_BIN="$(command -v cargo 2>/dev/null || true)"
fi

if [ -z "$RUSTUP_BIN" ]; then
  RUSTUP_BIN="$(command -v rustup 2>/dev/null || true)"
fi

if [ -z "$CARGO_BIN" ]; then
  echo "cargo not found. Install Rust: https://rustup.rs" >&2
  exit 127
fi

# If rustup is present but no default toolchain is configured in the active home,
# auto-bootstrap stable so first sudo launch works without manual intervention.
if ! "$CARGO_BIN" -V >/dev/null 2>&1; then
  if [ -n "$RUSTUP_BIN" ]; then
    "$RUSTUP_BIN" default stable >/dev/null 2>&1 || true
  fi
fi

exec "$CARGO_BIN" "$@"
