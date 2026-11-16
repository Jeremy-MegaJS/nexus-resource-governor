#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
DATA_DIR="${XDG_DATA_HOME:-$HOME/.local/share}"
APP_DIR="$DATA_DIR/applications"
ICON_DIR="$DATA_DIR/icons/hicolor/scalable/apps"
mkdir -p "$APP_DIR" "$ICON_DIR"
install -m 644 "$ROOT/packaging/icons/nrg.svg" "$ICON_DIR/nrg.svg"
sed -e "s|@NRG_DESKTOP_SCRIPT@|$ROOT/desktop/nrg_desktop.py|g" \
    -e "s|@NRG_PROJECT_ROOT@|$ROOT|g" \
    "$ROOT/packaging/nrg-desktop.desktop" > "$APP_DIR/nrg-desktop.desktop"
chmod 644 "$APP_DIR/nrg-desktop.desktop"
if command -v desktop-file-validate >/dev/null 2>&1; then
    desktop-file-validate "$APP_DIR/nrg-desktop.desktop"
fi
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache -f "$DATA_DIR/icons/hicolor" >/dev/null 2>&1 || true
fi
printf 'Installed NRG Desktop launcher: %s\n' "$APP_DIR/nrg-desktop.desktop"
printf 'Project path: %s\n' "$ROOT"
