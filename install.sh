#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: ./install.sh [--replace | --update] [--restart]"
  echo "--replace  back up an existing installation, then install it again from scratch."
  echo "--update   refresh the files of an existing installation in place: no packages,"
  echo "           no backup, and the widget stays where it is on the bar."
  echo "--restart  restart the Omarchy shell afterwards so it loads the new version."
}

MODE=install
RESTART=0
for argument in "$@"; do
  case "$argument" in
    --replace|--update)
      if [[ $MODE != install ]]; then
        echo "install.sh: use only one of --replace or --update" >&2
        exit 1
      fi
      MODE=${argument#--}
      ;;
    --restart) RESTART=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "install.sh: unknown option: $argument" >&2; exit 1 ;;
  esac
done

PLUGIN_ID="rmarchei.openvpn"
PACKAGES=(python openvpn networkmanager networkmanager-openvpn libsecret gnome-keyring)
PLUGIN_FILES=(manifest.json Panel.qml LICENSE scripts/openvpn-plugin)
SOURCE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
DESTINATION="${XDG_CONFIG_HOME:-$HOME/.config}/omarchy/plugins/$PLUGIN_ID"

copy_plugin_files() {
  local file
  mkdir -p -- "$DESTINATION/scripts"
  for file in "${PLUGIN_FILES[@]}"; do
    # Replace each file with a rename so the shell's hot reload never sees a partial write.
    cp -- "$SOURCE_DIR/$file" "$DESTINATION/$file.new"
    mv -f -- "$DESTINATION/$file.new" "$DESTINATION/$file"
  done
  chmod +x "$DESTINATION/scripts/openvpn-plugin"
}

# The shell's hot reload keeps serving an already loaded plugin's old QML (it
# cannot clear Qt's component cache), so changed files only show after a restart.
finish() {
  if (( RESTART )); then
    echo "Restarting the Omarchy shell..."
    omarchy restart shell
  elif [[ $MODE != install ]]; then
    echo "Restart the shell to load the new version: omarchy restart shell (or rerun with --restart)"
  fi
}

omarchy plugin validate "$SOURCE_DIR"
SAME_DIR=0
if [[ "$SOURCE_DIR" == "$(readlink -f -- "$DESTINATION")" ]]; then
  SAME_DIR=1
fi

if [[ $MODE == update ]]; then
  if [[ ! -d "$DESTINATION" ]]; then
    echo "install.sh: $PLUGIN_ID is not installed yet; run ./install.sh first" >&2
    exit 1
  fi
  if [[ -e "$DESTINATION/.git" ]] && (( ! SAME_DIR )); then
    echo "install.sh: $DESTINATION is managed by the Omarchy plugin manager; run: omarchy plugin update $PLUGIN_ID" >&2
    exit 1
  fi
  if (( ! SAME_DIR )); then
    copy_plugin_files
  fi
  omarchy plugin validate "$DESTINATION"
  omarchy-shell shell rescanPlugins 2>/dev/null || true
  if omarchy-pkg-missing "${PACKAGES[@]}"; then
    echo "Some dependencies are missing; install them with: omarchy pkg add ${PACKAGES[*]}"
  fi
  echo "OpenVPN Profiles updated in place."
  finish
  exit 0
fi

if (( ! SAME_DIR )) && [[ -e "$DESTINATION" || -L "$DESTINATION" ]] && [[ $MODE != replace ]]; then
  echo "install.sh: $DESTINATION already exists; rerun with --update to refresh it in place, or --replace to back it up and reinstall" >&2
  exit 1
fi

echo "Installing OpenVPN and NetworkManager integration..."
omarchy pkg add "${PACKAGES[@]}"

if (( ! SAME_DIR )); then
  mkdir -p -- "$(dirname -- "$DESTINATION")"
  if [[ -e "$DESTINATION" || -L "$DESTINATION" ]]; then
    backup=$(mktemp -d "$(dirname -- "$DESTINATION")/.${PLUGIN_ID}.backup.XXXXXX")
    mv -- "$DESTINATION" "$backup/plugin"
    echo "Existing plugin backed up to $backup/plugin"
  fi
  copy_plugin_files
fi

chmod +x "$DESTINATION/scripts/openvpn-plugin"
omarchy plugin validate "$DESTINATION"
omarchy-shell shell rescanPlugins
omarchy plugin enable "$PLUGIN_ID" --section right

echo "OpenVPN Profiles installed. Configure its directory from the Omarchy bar settings."
finish
