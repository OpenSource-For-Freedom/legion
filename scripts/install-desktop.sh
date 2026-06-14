#!/usr/bin/env bash
# Legion — Linux desktop integration installer (bash; no PowerShell).
#
# Run this from an extracted Legion release directory (the one containing
# legion-web, legion-launch.sh and legion-icon.svg) to add a clickable "Legion"
# entry to your applications menu (and optionally the desktop). Clicking it
# self-elevates via the polkit admin dialog, starts the dashboard, and opens the
# browser at http://localhost:3000.
#
#   ./install-desktop.sh            # apps menu only
#   ./install-desktop.sh --desktop  # also drop a desktop icon
#   ./install-desktop.sh --uninstall
set -eu

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
APPS="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
ICONS="${XDG_DATA_HOME:-$HOME/.local/share}/icons"
DESKTOP_DIR="${XDG_DESKTOP_DIR:-$HOME/Desktop}"
ENTRY="legion.desktop"

if [ "${1:-}" = "--uninstall" ]; then
  rm -f "$APPS/$ENTRY" "$DESKTOP_DIR/$ENTRY" "$ICONS/legion-icon.svg" "$ICONS/legion-icon.png"
  command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "$APPS" 2>/dev/null || true
  echo "Legion desktop entry removed."
  exit 0
fi

LAUNCHER="$SCRIPT_DIR/legion-launch.sh"
[ -f "$LAUNCHER" ] || { echo "error: legion-launch.sh not found next to this installer ($SCRIPT_DIR)." >&2; exit 1; }
chmod +x "$LAUNCHER" 2>/dev/null || true

# Pick an icon shipped alongside (svg preferred, png fallback).
ICON_SRC=""
for cand in "$SCRIPT_DIR/legion-icon.svg" "$SCRIPT_DIR/legion-icon.png"; do
  [ -f "$cand" ] && { ICON_SRC="$cand"; break; }
done
mkdir -p "$APPS" "$ICONS"
ICON_PATH=""
if [ -n "$ICON_SRC" ]; then
  cp "$ICON_SRC" "$ICONS/$(basename "$ICON_SRC")"
  ICON_PATH="$ICONS/$(basename "$ICON_SRC")"
fi

write_entry() {
  local dest="$1"
  cat > "$dest" <<EOF
[Desktop Entry]
Type=Application
Version=1.0
Name=Legion
GenericName=Security Monitor
Comment=Local SIEM/SOAR security dashboard (http://localhost:3000)
Exec=$LAUNCHER
Icon=${ICON_PATH:-utilities-system-monitor}
Terminal=false
Categories=System;Security;Monitor;
Keywords=SIEM;security;CVE;threat;monitor;legion;poncho;
StartupNotify=true
StartupWMClass=legion-web
EOF
  chmod +x "$dest"
}

write_entry "$APPS/$ENTRY"
command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "$APPS" 2>/dev/null || true
echo "Installed: $APPS/$ENTRY"

if [ "${1:-}" = "--desktop" ]; then
  mkdir -p "$DESKTOP_DIR"
  write_entry "$DESKTOP_DIR/$ENTRY"
  command -v gio >/dev/null 2>&1 && gio set "$DESKTOP_DIR/$ENTRY" metadata::trusted true 2>/dev/null || true
  echo "Installed: $DESKTOP_DIR/$ENTRY (you may need to right-click → Allow Launching on first use)"
fi

echo "Done. Find 'Legion' in your applications menu."
