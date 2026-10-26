# OpenVPN Profiles for Omarchy

An [Omarchy](https://omarchy.org/) bar widget that manages multiple OpenVPN profiles through NetworkManager. It supports username/password, client certificates (PEM or PKCS#12, including encrypted keys), and both together. All secrets stay in the system keyring.

Inspired by and based on [debba/omarchy-openvpn-widget](https://github.com/debba/omarchy-openvpn-widget).

## Highlights

- **Multiple profiles.** Discovers `.ovpn` and `.conf` files in a directory and in its immediate subfolders (`~/.config/openvpn/office/client.ovpn`). A profile named generically, like `client.ovpn`, takes its folder's name.
- **Several connections at once, or one at a time.** By default, connecting a profile disconnects the others. Turn off **One connection at a time** to keep several connected. The panel header lists every active profile and offers **Disconnect all**.
- **Certificate authentication.** Each profile's auth type is detected from its file:

  | Profile contains | Asks for |
  | --- | --- |
  | `auth-user-pass` | username + password |
  | `cert`/`key` with an unencrypted key | nothing, connects directly |
  | `cert`/`key` with an encrypted key | private key passphrase |
  | `pkcs12` | private key passphrase |
  | `auth-user-pass` + certificate | username + password (+ passphrase if the key is encrypted) |

  Certificates may be referenced by path (relative to the profile file) or inlined as `<ca>`, `<cert>`, `<key>`, `<pkcs12>`, and similar blocks. Missing certificate files are reported on the profile before NetworkManager is involved.
- **Safe inline certificate imports.** NetworkManager writes inline certificates to `~/.local/share/networkmanagement/certificates/nm-openvpn/<file name>-<tag>.pem` and overwrites what is already there, so two profiles both named `client.ovpn` would end up sharing one key. This plugin imports such profiles under a unique name, and **Delete** removes the extracted key files.
- **Add profiles from the panel.** Pick an `.ovpn`/`.conf` file or a `.zip` bundle in the desktop file chooser and the plugin copies it into your profile directory, along with any certificate files the profile references.
- Imports a profile into NetworkManager only when you first use it.
- Custom display names, keyring-backed credentials, and themed Omarchy UI.

## Security

Secrets are never stored in `shell.json`, the plugin state file, NetworkManager profiles, or command-line arguments.

- Usernames, passwords, and private key passphrases are Secret Service items (`secret-tool`, attribute `service=omarchy-openvpn-plugin`).
- On connect, secrets go to NetworkManager through a temporary `0600` `passwd-file`, which is deleted immediately afterwards. Values are escaped for nmcli, so passwords with spaces or backslashes work.
- Each secret's flag is set to "not saved", so NetworkManager never writes it to `/etc/NetworkManager/system-connections`. The username is set only for the duration of the activation.
- Refreshing only reads keyring item *attributes*, so a locked keyring does not prompt until you actually connect.
- The profile directory is created automatically (`0700`). On every refresh, the directory, each profile, the certificate and key files it references inside the directory, and the folders holding them lose group and other access. Owner permissions are kept, so helper scripts stay executable. Files you don't own, symlinks, and anything outside the directory are left alone.

The local state file is `~/.local/state/omarchy-openvpn-plugin/profiles.json`. It holds profile paths, NetworkManager UUIDs, custom display names, and the paths of certificate files NetworkManager extracted.

## What you need

- Omarchy 4.x (Quickshell plugin API)
- The system Python, `/usr/bin/python3` 3.10+. The backend uses it explicitly, so mise, pyenv or Homebrew Pythons earlier on your `PATH` don't matter.
- NetworkManager, running (`systemctl is-active NetworkManager`)
- `openvpn` and `networkmanager-openvpn`
- `libsecret` (for `secret-tool`) and a running Secret Service provider such as GNOME Keyring. Only needed for profiles that use a password or an encrypted key.
- `python-gobject` and `xdg-desktop-portal-gtk`, for the **Add profile** file chooser. Both ship with Omarchy.

On Omarchy:

```bash
omarchy pkg add openvpn networkmanager networkmanager-openvpn libsecret gnome-keyring python-gobject xdg-desktop-portal-gtk
```

## Installation

### Omarchy plugin manager

```bash
omarchy plugin add https://github.com/rmarchei/omarchy-openvpn-plugin.git --enable
```

### From a clone

```bash
git clone https://github.com/rmarchei/omarchy-openvpn-plugin.git
cd omarchy-openvpn-plugin
./install.sh
```

The installer validates the plugin, installs the packages above, copies the plugin to `~/.config/omarchy/plugins/rmarchei.openvpn`, and enables it in the right section of the bar. It refuses to touch an existing installation unless you pass a mode:

| Command | Packages | Existing install | Bar position |
| --- | --- | --- | --- |
| `./install.sh --update` | not touched (warns if missing) | files refreshed in place | kept |
| `./install.sh --replace` | installed if missing | moved to a hidden `.rmarchei.openvpn.backup.*` folder, then reinstalled | reset to the right section, after the tray |

After `git pull`, run `./install.sh --update --restart`. A copy installed with `omarchy plugin add` is a git checkout; update that one with `omarchy plugin update rmarchei.openvpn` instead.

The shell notices changed plugin files and rebuilds the widget, but it rebuilds it from Qt's cached copy of the old QML, so panel changes only appear after `omarchy restart shell`. `--restart` (accepted with any mode) runs that for you. Backend changes in `scripts/openvpn-plugin` apply immediately, because the panel starts the backend fresh on every call.

## Usage

1. Click the shield icon in the bar, then **Add profile…** (or **+** next to PROFILES, or press `a`). Choose an `.ovpn`/`.conf` file or a `.zip` bundle:

   - A self-contained profile (inline certificates, or none) is copied as is.
   - A profile that references certificate files next to it (`cert client.crt`) gets its own folder with those files. References outside the profile's folder (`../ca.crt`) are refused; copy such folders by hand.
   - A `.zip` bundle is extracted into its own folder, with a single wrapping folder removed. Profiles must sit at the top of the bundle. Unsafe paths and oversized archives are refused.

   Copied files are `0600` and folders `0700`.

   Alternatively, copy your provider's files into `~/.config/openvpn` yourself, either flat or one folder per profile:

   ```text
   ~/.config/openvpn/
   ├── provider-nl.ovpn          # inline <ca>, auth-user-pass
   ├── office/
   │   ├── client.ovpn           # cert client.crt / key client.key
   │   ├── ca.crt
   │   ├── client.crt
   │   └── client.key
   └── lab/
       ├── lab.ovpn              # pkcs12 lab.p12 + auth-user-pass
       └── lab.p12
   ```

   You can choose a different directory in the Omarchy bar settings; it is created if it does not exist.
2. Each profile in the panel shows its auth type and whether it is ready.
3. Click a profile, or its connect icon. If secrets are missing, the panel asks for exactly the fields that profile needs and saves them to the keyring before connecting.

Middle-click the bar icon, or press `r` in the panel, to refresh.

### Profile actions

| Action | When |
| --- | --- |
| Add profile (`+`, `a`) | always |
| Connect | profile is disconnected and has no problems |
| Rename | profile is disconnected |
| Edit credentials / key passphrase | profile needs secrets |
| Delete (click twice) | profile is disconnected |
| Disconnect | profile is connected or connecting |

**Delete** removes the NetworkManager connection, the profile's keyring secrets, its custom name, the certificate files NetworkManager extracted for it, and the profile file itself. It also removes the certificate and key files the profile references from its own folder, unless another profile in that folder still uses them, and then the folder if that leaves it empty. Unrelated files in the folder and anything outside the profile directory are never touched.

### IPC

```bash
omarchy-shell rmarchei.openvpn toggle
omarchy-shell rmarchei.openvpn refresh
omarchy-shell rmarchei.openvpn disconnectAll
```

## Widget settings

| Setting | Default | Description |
| --- | --- | --- |
| `configDirectory` | `~/.config/openvpn` | Directory containing OpenVPN profiles (scanned one folder deep) |
| `refreshIntervalSec` | `10` | Connection-state refresh interval in seconds |
| `singleConnection` | `true` | Disconnect other profiles before connecting a new one |

## Development

```bash
python -m unittest discover -s tests -v
omarchy plugin validate .
```

The backend can be run on its own:

```bash
scripts/openvpn-plugin list --config-dir ~/.config/openvpn
```

For live development, install once, then push each change into the user plugin directory. Add `--restart` whenever `Panel.qml` changed:

```bash
./install.sh --update            # backend-only changes
./install.sh --update --restart  # Panel.qml changes
```

## Uninstallation

```bash
omarchy plugin remove rmarchei.openvpn   # plugin manager install
./uninstall.sh                           # install.sh install
```

Both keep imported NetworkManager profiles, keyring entries, local state, and system packages. To remove them, use **Delete** on each profile before uninstalling.

## License

[MIT](LICENSE)
