#!/usr/bin/env bash
set -euo pipefail

PLUGIN_ID="rmarchei.openvpn"
PLUGIN_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/omarchy/plugins/$PLUGIN_ID"

echo "This removes the widget only. NetworkManager profiles and keyring entries are kept."
omarchy plugin disable "$PLUGIN_ID" 2>/dev/null || true
rm -rf -- "$PLUGIN_DIR"
omarchy-shell shell rescanPlugins 2>/dev/null || true

echo "OpenVPN Profiles removed."
