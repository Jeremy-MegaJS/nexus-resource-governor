#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
APP_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
mkdir -p "$APP_DIR"
sed -e "s|@NRG_DESKTOP_SCRIPT@|$ROOT/desktop/nrg_desktop.py|g" \
    -e "s|@NRG_PROJECT_ROOT@|$ROOT|g" \
    "$ROOT/packaging/nrg-desktop.desktop" > "$APP_DIR/nrg-desktop.desktop"
chmod 644 "$APP_DIR/nrg-desktop.desktop"
if command -v desktop-file-validate >/dev/null 2>&1; then
    desktop-file-validate "$APP_DIR/nrg-desktop.desktop"
fi
printf 'Installed NRG Desktop launcher: %s\n' "$APP_DIR/nrg-desktop.desktop"
printf 'Project path: %s\n' "$ROOT"
