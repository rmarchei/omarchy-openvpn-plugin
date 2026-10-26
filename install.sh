#!/usr/bin/env bash
set -euo pipefail

REPLACE=0
for argument in "$@"; do
  case "$argument" in
    --replace) REPLACE=1 ;;
    -h|--help)
      echo "Usage: ./install.sh [--replace]"
      echo "--replace explicitly allows backing up and replacing an existing plugin."
      exit 0
      ;;
    *) echo "install.sh: unknown option: $argument" >&2; exit 1 ;;
  esac
done

PLUGIN_ID="rmarchei.openvpn"
SOURCE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
DESTINATION="${XDG_CONFIG_HOME:-$HOME/.config}/omarchy/plugins/$PLUGIN_ID"

omarchy plugin validate "$SOURCE_DIR"
COPY_PLUGIN=0
if [[ "$SOURCE_DIR" != "$(readlink -f -- "$DESTINATION")" ]]; then
  COPY_PLUGIN=1
  if [[ -e "$DESTINATION" || -L "$DESTINATION" ]] && (( ! REPLACE )); then
    echo "install.sh: $DESTINATION already exists; leave it untouched or rerun with --replace to back it up first" >&2
    exit 1
  fi
fi

echo "Installing OpenVPN and NetworkManager integration..."
omarchy pkg add python openvpn networkmanager networkmanager-openvpn libsecret gnome-keyring

if (( COPY_PLUGIN )); then
  mkdir -p -- "$(dirname -- "$DESTINATION")"
  if [[ -e "$DESTINATION" || -L "$DESTINATION" ]]; then
    backup=$(mktemp -d "$(dirname -- "$DESTINATION")/.${PLUGIN_ID}.backup.XXXXXX")
    mv -- "$DESTINATION" "$backup/plugin"
    echo "Existing plugin backed up to $backup/plugin"
  fi
  mkdir -p -- "$DESTINATION/scripts"
  cp -- "$SOURCE_DIR/manifest.json" "$SOURCE_DIR/Panel.qml" "$SOURCE_DIR/LICENSE" "$DESTINATION/"
  cp -- "$SOURCE_DIR/scripts/openvpn-plugin" "$DESTINATION/scripts/"
fi

chmod +x "$DESTINATION/scripts/openvpn-plugin"
omarchy plugin validate "$DESTINATION"
omarchy-shell shell rescanPlugins
omarchy plugin enable "$PLUGIN_ID" --section right

echo "OpenVPN Profiles installed. Configure its directory from the Omarchy bar settings."
