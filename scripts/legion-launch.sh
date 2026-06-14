#!/usr/bin/env bash
# Legion dashboard launcher for the Linux desktop (clickable .desktop target).
#
# Flow when you click the Legion icon:
#   1. Locate the legion-web binary (installed copy, else this repo's build).
#   2. If the dashboard is already up, just open the browser.
#   3. Otherwise launch legion-web, which self-elevates through the OS-native
#      polkit admin dialog and serves the dashboard as root for its lifetime.
#   4. --no-open is passed because the elevated (root) process cannot reach this
#      user's browser session — so we open http://localhost:3000 here, as you.
set -u

URL="http://localhost:3000/"
RUN_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/legion"
LOG="$RUN_DIR/legion-web.log"
mkdir -p "$RUN_DIR"

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"

# Resolve the legion-web binary: a copy next to this script (extracted release),
# then installed copies, then this repo's build.
BIN=""
for c in \
    "$SCRIPT_DIR/legion-web" \
    "$(command -v legion-web 2>/dev/null || true)" \
    "/usr/local/bin/legion-web" \
    "$SCRIPT_DIR/../target/release/legion-web" \
    "$SCRIPT_DIR/../target/debug/legion-web"; do
  if [ -n "$c" ] && [ -x "$c" ]; then BIN="$c"; break; fi
done

up()     { curl -fsS -o /dev/null --max-time 2 "$URL" 2>/dev/null; }
notify() { command -v notify-send >/dev/null 2>&1 && notify-send "Legion" "$1" || echo "Legion: $1" >&2; }
open_ui(){ command -v xdg-open >/dev/null 2>&1 && xdg-open "$URL" >/dev/null 2>&1 & }

# Already running? Just surface the dashboard.
if up; then
  open_ui
  exit 0
fi

if [ -z "$BIN" ]; then
  notify "legion-web binary not found. Build it with 'make release' in the repo."
  exit 1
fi

# Launch detached so the server outlives this launcher and its desktop scope.
if command -v setsid >/dev/null 2>&1; then
  setsid "$BIN" --scan-root "$HOME" --no-open >"$LOG" 2>&1 < /dev/null &
else
  nohup  "$BIN" --scan-root "$HOME" --no-open >"$LOG" 2>&1 < /dev/null &
  disown || true
fi

# Wait up to ~40s for the admin prompt to be approved and the port to bind.
for _ in $(seq 1 80); do
  up && break
  sleep 0.5
done

if up; then
  open_ui
else
  notify "Dashboard did not start (admin prompt cancelled?). See $LOG"
  exit 1
fi
