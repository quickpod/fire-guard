#!/usr/bin/env bash
# FireGuard local installer (Linux). Installs to /opt/quickopen/fire-guard,
# adds the menu entry + icon. Uninstall: sudo rm -rf /opt/quickopen/fire-guard
# /usr/share/applications/quickopen-fire-guard.desktop
# /usr/share/icons/hicolor/*/apps/quickopen-fire-guard.png
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
[ "$(id -u)" = 0 ] || { echo "run with sudo: sudo $0"; exit 1; }
install -d /opt/quickopen/fire-guard
install -m755 "$HERE/FireGuard" /opt/quickopen/fire-guard/FireGuard
install -m644 "$HERE/quickopen-fire-guard.desktop" /usr/share/applications/
for sz in 256 128 64 48 32; do
  d="/usr/share/icons/hicolor/${sz}x${sz}/apps"; install -d "$d"
  install -m644 "$HERE/fire-guard.png" "$d/quickopen-fire-guard.png"
done
command -v update-desktop-database >/dev/null && update-desktop-database -q || true
command -v gtk-update-icon-cache >/dev/null && gtk-update-icon-cache -q /usr/share/icons/hicolor || true
echo "FireGuard installed — find it in the menu, or run /opt/quickopen/fire-guard/FireGuard"
