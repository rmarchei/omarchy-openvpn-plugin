"""Unit tests for backend functions; NetworkManager and Secret Service are mocked."""

from importlib.machinery import SourceFileLoader
from importlib.util import find_spec, module_from_spec, spec_from_loader
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import call, patch

BACKEND = Path(__file__).parents[1] / "scripts" / "openvpn-plugin"
loader = SourceFileLoader("openvpn_plugin", str(BACKEND))
module = module_from_spec(spec_from_loader(loader.name, loader))
# dataclasses resolves annotations through sys.modules.
sys.modules[loader.name] = module
loader.exec_module(module)

CLIENT = "client\nremote vpn.example.com 1194\n"
ENCRYPTED_PEM = "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIF\n-----END ENCRYPTED PRIVATE KEY-----\n"
PLAIN_PEM = "-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----\n"


def connection(uuid, name, state="", connection_type="vpn"):
    return {uuid: {"uuid": uuid, "name": name, "type": connection_type, "state": state}}


class TempDirTestCase(unittest.TestCase):
    def setUp(self):
        self._directory = tempfile.TemporaryDirectory()
        self.root = Path(self._directory.name).resolve()

    def tearDown(self):
        self._directory.cleanup()

    def write(self, relative, text=""):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path


class ParsingTests(unittest.TestCase):
    def test_parse_terse_line_unescapes_colons_and_backslashes(self):
        self.assertEqual(
            module.parse_terse_line(r"uuid:Name\: office:vpn\\type:activated"),
            ["uuid", "Name: office", "vpn\\type", "activated"],
        )

    def test_escape_secret_survives_nmcli_unescaping(self):
        self.assertEqual(module.escape_secret("plain"), "plain")
        self.assertEqual(module.escape_secret(" a\\b "), "\\040a\\134b\\040")
        self.assertEqual(module.escape_secret("tab\there"), "tab\\011here")
        # Octal escapes produce single bytes, so non-ASCII text must pass through untouched (the no-break spaces are deliberate).
        self.assertEqual(module.escape_secret("pässwörd "), "pässwörd ")  # noqa: RUF001

    def test_vpn_data_parsing_unescapes_values(self):
        output = (
            "ca = /home/u/.local/share/networkmanagement/certificates/nm-openvpn/.office-12345678-ca.pem, "
            "connection-type = tls, remote = a\\:1194\n"
        )
        with patch.object(module, "run") as run:
            run.return_value.stdout = output
            self.assertEqual(
                module.nm_vpn_data("uuid"),
                {
                    "ca": "/home/u/.local/share/networkmanagement/certificates/nm-openvpn/.office-12345678-ca.pem",
                    "connection-type": "tls",
                    "remote": "a:1194",
                },
            )


class InspectConfigTests(TempDirTestCase):
    def test_password_profile(self):
        info = module.inspect_config(self.write("p.ovpn", CLIENT + "auth-user-pass\n<ca>\nX\n</ca>\n"))
        self.assertEqual(info.auth, "password")
        self.assertEqual(info.required_secrets, ["username", "password"])
        self.assertTrue(info.inline)
        self.assertEqual(info.problems, [])

    def test_certificate_with_plain_key_needs_no_secrets(self):
        self.write("certs/client.crt", "CERT")
        self.write("certs/client.key", PLAIN_PEM)
        info = module.inspect_config(self.write("c.ovpn", CLIENT + "cert certs/client.crt\nkey certs/client.key\n"))
        self.assertEqual(info.auth, "certificate")
        self.assertEqual(info.required_secrets, [])
        self.assertFalse(info.inline)

    def test_encrypted_key_file_needs_passphrase(self):
        self.write("client.key", ENCRYPTED_PEM)
        info = module.inspect_config(self.write("c.ovpn", CLIENT + "cert [inline]\nkey 'client.key'\n<cert>\nC\n</cert>\n"))
        self.assertTrue(info.key_encrypted)
        self.assertEqual(info.required_secrets, ["cert-pass"])

    def test_legacy_encrypted_inline_key(self):
        key = "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES\n-----END RSA PRIVATE KEY-----"
        info = module.inspect_config(self.write("c.ovpn", f"{CLIENT}<cert>\nC\n</cert>\n<key>\n{key}\n</key>\n"))
        self.assertTrue(info.key_encrypted)

    def test_certificate_and_password_with_pkcs12(self):
        self.write("bundle.p12", "P12")
        info = module.inspect_config(self.write("both.ovpn", CLIENT + "--auth-user-pass\npkcs12 bundle.p12\n"))
        self.assertEqual(info.auth, "password-certificate")
        self.assertTrue(info.pkcs12)
        self.assertEqual(info.required_secrets, ["username", "password", "cert-pass"])

    def test_reports_missing_files_and_non_client_configs(self):
        info = module.inspect_config(self.write("bad.conf", "# server\n;remote ignored\nca missing-ca.crt\n"))
        self.assertEqual(
            info.problems,
            ["Missing ca file: missing-ca.crt", "Not an OpenVPN client configuration", "No remote server defined"],
        )

    def test_remote_inside_connection_block(self):
        info = module.inspect_config(self.write("c.ovpn", "client\n<connection>\nremote a 1194 udp\n</connection>\n"))
        self.assertTrue(info.remote)


class DiscoveryTests(TempDirTestCase):
    def test_discover_scans_one_folder_deep_and_skips_hidden(self):
        self.write("Zurich.ovpn")
        self.write("amsterdam.conf")
        self.write("ignore.txt")
        self.write(".hidden.ovpn")
        self.write("office/client.ovpn")
        self.write("office/nested/too-deep.ovpn")
        self.write(".secret/hidden.ovpn")
        self.assertEqual(
            [str(item.relative_to(self.root)) for item in module.discover(self.root)],
            ["amsterdam.conf", "office/client.ovpn", "Zurich.ovpn"],
        )

    def test_generic_file_names_use_their_folder_name(self):
        self.assertEqual(module.default_name(self.root / "office" / "client.ovpn", self.root), "office")
        self.assertEqual(module.default_name(self.root / "client.ovpn", self.root), "client")
        self.assertEqual(module.default_name(self.root / "office" / "berlin.ovpn", self.root), "berlin")

    def run_list(self, directory):
        with (
            patch.object(module, "load_state", return_value={}),
            patch.object(module, "nm_connections", return_value={}),
            patch.object(module, "stored_secret_index", return_value={}),
            patch("sys.stdout", io.StringIO()) as output,
            self.assertRaises(SystemExit),
        ):
            module.command_list(type("Args", (), {"config_dir": str(directory)})())
        return json.loads(output.getvalue())

    def test_list_creates_a_missing_directory_privately(self):
        target = self.root / "config" / "openvpn"
        for _attempt in range(2):
            self.assertEqual(self.run_list(target)["profiles"], [])
        self.assertEqual(target.stat().st_mode & 0o777, 0o700)

    def test_list_refuses_a_file_where_the_directory_should_be(self):
        target = self.write("openvpn")
        with self.assertRaisesRegex(module.WidgetError, "is not a directory"):
            module.command_list(type("Args", (), {"config_dir": str(target)})())

    def test_list_makes_profiles_and_their_files_owner_only(self):
        profiles = self.root / "profiles"
        key = self.write("profiles/office/certs/client.key", PLAIN_PEM)
        notes = self.write("profiles/office/notes.txt", "keep my mode")
        outside = self.write("shared-ca.crt", "CA")
        profile = self.write("profiles/office/client.ovpn", CLIENT + f"key certs/client.key\nca {outside}\n")
        flat = self.write("profiles/home.ovpn", CLIENT)
        (profiles / "link.ovpn").symlink_to(outside)
        for path, mode in (
            (profiles, 0o755),
            (profiles / "office", 0o755),
            (key.parent, 0o755),
            (key, 0o644),
            (notes, 0o644),
            (outside, 0o644),
            (profile, 0o755),
            (flat, 0o664),
        ):
            path.chmod(mode)

        self.run_list(profiles)

        def mode(path):
            return path.stat().st_mode & 0o777

        self.assertEqual(
            [mode(path) for path in (profiles, profiles / "office", key.parent, key, profile, flat)],
            [0o700, 0o700, 0o700, 0o600, 0o700, 0o600],
        )
        # Unreferenced files, files outside the directory and symlink targets keep their modes.
        self.assertEqual([mode(notes), mode(outside)], [0o644, 0o644])

    def test_config_key_is_stable(self):
        path = self.write("vpn.ovpn")
        self.assertEqual(module.config_key(path), module.config_key(path.resolve()))
        self.assertEqual(len(module.config_key(path)), 64)

    def test_list_reports_auth_and_secret_state(self):
        self.write("home.ovpn", CLIENT + "auth-user-pass\n")
        office = self.write("office/client.ovpn", CLIENT + "<cert>\nC\n</cert>\n<key>\n" + ENCRYPTED_PEM + "</key>\n")
        state = {str(office): {"uuid": "office-uuid", "blobs": ["/x"]}}
        secrets = {"username": set(), "password": set(), "cert-pass": {module.config_key(office)}}
        output = io.StringIO()

        with (
            patch.object(module, "load_state", return_value=state),
            patch.object(module, "nm_connections", return_value=connection("office-uuid", "OpenVPN · office", "activated")),
            patch.object(module, "stored_secret_index", return_value=secrets),
            patch.object(module, "interface_addresses", return_value={"10.8.0.2": "tun0"}) as addresses,
            patch.object(module, "connection_details", return_value={"device": "tun0"}) as details,
            patch.object(module, "save_state") as save_state,
            patch("sys.stdout", output),
            self.assertRaises(SystemExit),
        ):
            module.command_list(type("Args", (), {"config_dir": str(self.root)})())

        profiles = json.loads(output.getvalue())["profiles"]
        self.assertEqual([profile["name"] for profile in profiles], ["home", "office"])
        home, office_profile = profiles
        self.assertEqual((home["auth"], home["hasSecrets"], home["active"]), ("password", False, False))
        self.assertEqual(office_profile["relativePath"], "office/client.ovpn")
        self.assertEqual(office_profile["requiredSecrets"], ["cert-pass"])
        self.assertTrue(office_profile["hasSecrets"])
        self.assertTrue(office_profile["active"])
        # Live details are gathered for connected profiles only, with one address lookup.
        self.assertEqual((home["details"], office_profile["details"]), (None, {"device": "tun0"}))
        details.assert_called_once_with("office-uuid", {"10.8.0.2": "tun0"})
        addresses.assert_called_once_with()
        save_state.assert_not_called()


class ImportTests(TempDirTestCase):
    def test_import_uses_name_assigned_before_first_connection(self):
        path = self.write("office.ovpn", CLIENT)
        state = {str(path): {"name": "Main office"}}
        imported = connection("vpn-uuid", "office")

        with (
            patch.object(module, "nm_connections", side_effect=[{}, {}, imported]),
            patch.object(module, "run") as run,
            patch.object(module, "save_state") as save_state,
        ):
            record = module.ensure_imported(path, state, module.inspect_config(path), "office")

        self.assertEqual(record, {"name": "Main office", "uuid": "vpn-uuid", "blobs": []})
        self.assertEqual(
            run.call_args_list,
            [
                call(["nmcli", "connection", "import", "type", "openvpn", "file", str(path)]),
                call(["nmcli", "connection", "modify", "uuid", "vpn-uuid", "connection.id", "Main office"]),
            ],
        )
        save_state.assert_called_once_with(state)

    def test_inline_profiles_import_through_a_unique_link(self):
        path = self.write("office/client.ovpn", CLIENT + "<key>\n" + PLAIN_PEM + "</key>\n")
        alias = module.import_alias(path)
        blob = f"/home/u/.local/share/networkmanagement/certificates/nm-openvpn/{alias.stem}-key.pem"
        seen = {}

        def fake_run(command, **_kwargs):
            if command[:3] == ["nmcli", "connection", "import"]:
                source = Path(command[-1])
                seen["source"] = source
                seen["target"] = source.resolve()
            return type("Result", (), {"stdout": "", "returncode": 0})()

        with (
            patch.object(module, "nm_connections", side_effect=[{}, connection("u1", "x")]),
            patch.object(module, "nm_vpn_data", return_value={"key": blob, "ca": "/etc/ssl/shared-ca.pem"}),
            patch.object(module, "run", side_effect=fake_run),
        ):
            uuid, blobs = module.import_profile(path, module.inspect_config(path))

        self.assertEqual(uuid, "u1")
        self.assertEqual(seen["source"], alias)
        self.assertEqual(seen["target"], path)
        self.assertEqual(blobs, [blob])
        self.assertFalse(alias.exists() or alias.is_symlink())

    def test_blob_cleanup_only_removes_files_written_for_this_profile(self):
        path = self.write("office/client.ovpn", CLIENT)
        prefix = module.import_alias(path).stem
        own = self.write(f"certs/{prefix}-key.pem", "KEY")
        foreign = self.write("certs/client-key.pem", "KEY")
        module.remove_blobs({"blobs": [str(own), str(foreign)]}, path)
        self.assertFalse(own.exists())
        self.assertTrue(foreign.exists())


class ConnectTests(TempDirTestCase):
    def connect(self, path, state, secrets, exclusive=False):
        written = {}

        def fake_run(command, **_kwargs):
            if "passwd-file" in command:
                written["lines"] = Path(command[command.index("passwd-file") + 1]).read_text()
            return type("Result", (), {"stdout": "", "returncode": 0})()

        args = type("Args", (), {"config": str(path), "config_dir": str(self.root), "exclusive": exclusive})()
        with (
            patch.object(module, "secret_lookup", side_effect=lambda _path, name: secrets.get(name, "")),
            patch.object(module, "load_state", return_value=state),
            patch.object(
                module, "nm_connections", return_value={**connection("u1", "OpenVPN · c"), **connection("u2", "Other", "activated")}
            ),
            patch.object(module, "run", side_effect=fake_run) as run,
            patch("sys.stdout", io.StringIO()) as output,
            self.assertRaises(SystemExit),
        ):
            module.command_connect(args)
        return run, written, json.loads(output.getvalue())

    def test_certificate_without_secrets_connects_without_passwd_file(self):
        path = self.write("c.ovpn", CLIENT + "<cert>\nC\n</cert>\n<key>\n" + PLAIN_PEM + "</key>\n")
        run, written, result = self.connect(path, {str(path): {"uuid": "u1"}}, {})
        self.assertTrue(result["ok"])
        self.assertEqual(run.call_args_list, [call(["nmcli", "connection", "up", "uuid", "u1"])])
        self.assertEqual(written, {})

    def test_password_and_passphrase_are_passed_through_passwd_file(self):
        path = self.write("c.ovpn", CLIENT + "auth-user-pass\n<cert>\nC\n</cert>\n<key>\n" + ENCRYPTED_PEM + "</key>\n")
        secrets = {"username": "alice", "password": "p w\\", "cert-pass": "key pass"}
        run, written, result = self.connect(path, {str(path): {"uuid": "u1"}}, secrets)
        self.assertTrue(result["ok"])
        self.assertEqual(written["lines"], "vpn.secrets.password:p\\040w\\134\nvpn.secrets.cert-pass:key\\040pass\n")
        commands = [entry.args[0] for entry in run.call_args_list]
        self.assertEqual(
            commands[0],
            ["nmcli", "connection", "modify", "uuid", "u1", "vpn.user-name", "alice", "+vpn.data", "password-flags=2, cert-pass-flags=2"],
        )
        self.assertEqual(commands[-1], ["nmcli", "connection", "modify", "uuid", "u1", "vpn.user-name", ""])

    def test_exclusive_connect_stops_other_managed_profiles_first(self):
        path = self.write("c.ovpn", CLIENT + "<cert>\nC\n</cert>\n<key>\n" + PLAIN_PEM + "</key>\n")
        other = str(self.root / "other.ovpn")
        run, _written, result = self.connect(path, {str(path): {"uuid": "u1"}, other: {"uuid": "u2"}}, {}, exclusive=True)
        commands = [entry.args[0] for entry in run.call_args_list]
        self.assertEqual(commands, [["nmcli", "connection", "down", "uuid", "u2"], ["nmcli", "connection", "up", "uuid", "u1"]])
        self.assertIn("disconnected Other", result["message"])

    def test_problems_and_missing_secrets_stop_before_networkmanager(self):
        missing_file = self.write("a.ovpn", CLIENT + "pkcs12 missing.p12\n")
        self.write("bundle.p12", "P12")
        no_passphrase = self.write("b.ovpn", CLIENT + "pkcs12 bundle.p12\n")
        for path, error in (
            (missing_file, "Missing pkcs12 file: missing.p12"),
            (no_passphrase, "Save the private key passphrase before connecting"),
        ):
            args = type("Args", (), {"config": str(path), "config_dir": None, "exclusive": False})()
            with (
                patch.object(module, "secret_lookup", return_value=""),
                patch.object(module, "run") as run,
                self.assertRaisesRegex(module.WidgetError, error),
            ):
                module.command_connect(args)
            run.assert_not_called()


class LiveDetailsTests(TempDirTestCase):
    def test_active_properties_keep_only_live_fields(self):
        output = (
            "connection.id:Office\nvpn.data:remote = a\nIP4.ADDRESS[1]:10.8.0.2/24\n"
            "VPN.GATEWAY:vpn.example:443:tcp\nGENERAL.STATE:activated\n"
        )
        with patch.object(module, "run") as run:
            run.return_value.stdout = output
            self.assertEqual(
                module.active_properties("u1"),
                {"IP4.ADDRESS[1]": "10.8.0.2/24", "VPN.GATEWAY": "vpn.example:443:tcp", "GENERAL.STATE": "activated"},
            )

    def test_interface_addresses_map_addresses_to_devices(self):
        payload = [
            {"ifname": "lo", "addr_info": [{"local": "127.0.0.1"}]},
            {"ifname": "tun0", "addr_info": [{"local": "10.8.0.2"}, {"local": "fd00::2"}]},
            {"ifname": "eth0", "addr_info": []},
        ]
        with patch.object(module, "run") as run:
            run.return_value.stdout = json.dumps(payload)
            self.assertEqual(module.interface_addresses(), {"127.0.0.1": "lo", "10.8.0.2": "tun0", "fd00::2": "tun0"})
            run.return_value.stdout = "not json"
            self.assertEqual(module.interface_addresses(), {})

    def test_format_server(self):
        self.assertEqual(module.format_server("vpn-eu.example.com:443:tcp"), "vpn-eu.example.com:443 TCP")
        self.assertEqual(module.format_server("[2001:db8::1]:1194:udp"), "[2001:db8::1]:1194 UDP")
        self.assertEqual(module.format_server("203.0.113.7"), "203.0.113.7")
        self.assertEqual(module.format_server(""), "")

    def test_openvpn_start_time_comes_from_its_process(self):
        proc = self.root / "proc"
        self.write("proc/stat", "cpu 1 2 3\nbtime 1700000000\n")
        ticks = os.sysconf("SC_CLK_TCK")
        stat_tail = " ".join(["S"] + ["0"] * 18 + [str(ticks * 90)] + ["0"] * 5)
        for pid, comm, cmdline in (
            ("10", "nm-openvpn-serv", "--management\0/run/NetworkManager/nm-openvpn-u1\0"),
            ("11", "openvpn", "/usr/sbin/openvpn\0--management\0/run/NetworkManager/nm-openvpn-u2\0"),
            ("12", "openvpn", "/usr/sbin/openvpn\0--management\0/run/NetworkManager/nm-openvpn-u1\0"),
        ):
            self.write(f"proc/{pid}/comm", comm + "\n")
            self.write(f"proc/{pid}/cmdline", cmdline)
            self.write(f"proc/{pid}/stat", f"{pid} (open vpn) {stat_tail}\n")
        self.write("proc/self/comm", "python")
        self.assertEqual(module.openvpn_started_at("u1", proc), 1700000090)
        self.assertIsNone(module.openvpn_started_at("u3", proc))


class DeleteTests(TempDirTestCase):
    def setUp(self):
        super().setUp()
        self.profiles = self.root / "profiles"
        self.profiles.mkdir()

    def delete(self, path, state=None, config_dir="default"):
        state = state if state is not None else {}
        config_dir = str(self.profiles) if config_dir == "default" else config_dir
        args = type("Args", (), {"config": str(path), "config_dir": config_dir})()
        with (
            patch.object(module, "load_state", return_value=state),
            patch.object(module, "save_state") as save_state,
            patch.object(module, "run") as run,
            patch.object(module, "secret_clear") as secret_clear,
            patch("sys.stdout", io.StringIO()) as output,
            self.assertRaises(SystemExit),
        ):
            module.command_delete(args)
        return json.loads(output.getvalue()), run, secret_clear, save_state

    def files(self):
        return sorted(str(p.relative_to(self.profiles)) for p in self.profiles.rglob("*"))

    def test_flat_profile_is_removed_with_its_connection_and_secrets(self):
        path = self.write("profiles/home.ovpn", CLIENT)
        self.write("profiles/other.ovpn", CLIENT)
        (self.profiles / "empty-unrelated").mkdir()
        state = {str(path): {"uuid": "u1", "name": "Home"}, "/elsewhere.ovpn": {"uuid": "u2"}}
        result, run, secret_clear, save_state = self.delete(path, state)
        self.assertEqual(result, {"ok": True, "message": "Deleted Home"})
        run.assert_called_once_with(["nmcli", "connection", "delete", "uuid", "u1"], check=False)
        secret_clear.assert_called_once_with(path)
        save_state.assert_called_once_with({"/elsewhere.ovpn": {"uuid": "u2"}})
        self.assertEqual(self.files(), ["empty-unrelated", "other.ovpn"])

    def test_bundle_folder_goes_away_but_unrelated_files_stay(self):
        self.write("profiles/office/certs/client.crt", "CERT")
        self.write("profiles/office/client.key", PLAIN_PEM)
        office = self.write("profiles/office/client.ovpn", CLIENT + "cert certs/client.crt\nkey client.key\n")
        self.write("profiles/lab/lab.key", PLAIN_PEM)
        self.write("profiles/lab/README.txt", "notes")
        lab = self.write("profiles/lab/lab.ovpn", CLIENT + "key lab.key\n")
        self.delete(office)
        self.delete(lab)
        self.assertEqual(self.files(), ["lab", "lab/README.txt"])

    def test_files_shared_with_another_profile_or_outside_the_folder_are_kept(self):
        self.write("profiles/ca.crt", "CA")
        self.write("profiles/site/shared.key", PLAIN_PEM)
        first = self.write("profiles/site/a.ovpn", CLIENT + "key shared.key\nca ../ca.crt\n")
        self.write("profiles/site/b.ovpn", CLIENT + "key shared.key\n")
        self.delete(first)
        self.assertEqual(self.files(), ["ca.crt", "site", "site/b.ovpn", "site/shared.key"])

    def test_files_used_by_profiles_in_other_folders_are_kept(self):
        self.write("profiles/ca.crt", "CA")
        self.write("profiles/ta.key", "TA")
        top = self.write("profiles/top.ovpn", CLIENT + "ca ca.crt\ntls-auth ta.key\n")
        self.write("profiles/site/a.ovpn", CLIENT + "ca ../ca.crt\n")
        self.write("profiles/lab/b.ovpn", CLIENT + f"tls-auth {self.profiles / 'ta.key'}\n")
        self.delete(top)
        self.assertEqual(self.files(), ["ca.crt", "lab", "lab/b.ovpn", "site", "site/a.ovpn", "ta.key"])

    def test_refuses_profiles_outside_the_profiles_directory(self):
        outside = self.write("Downloads/vpn.ovpn", CLIENT)
        deep = self.write("profiles/a/b/vpn.ovpn", CLIENT)
        for path, config_dir in ((outside, "default"), (deep, "default"), (self.write("profiles/x.ovpn", CLIENT), None)):
            args = type("Args", (), {"config": str(path), "config_dir": str(self.profiles) if config_dir else None})()
            with self.subTest(path=path.name), patch.object(module, "run") as run, self.assertRaises(module.WidgetError):
                module.command_delete(args)
            run.assert_not_called()
            self.assertTrue(path.exists())


class AddProfileTests(TempDirTestCase):
    def setUp(self):
        super().setUp()
        self.profiles = self.root / "profiles"

    def add(self, source):
        args = type("Args", (), {"source": str(source), "config_dir": str(self.profiles)})()
        with patch("sys.stdout", io.StringIO()) as output, self.assertRaises(SystemExit):
            module.command_add_profile(args)
        return json.loads(output.getvalue())

    def mode(self, path):
        return path.stat().st_mode & 0o777

    def test_self_contained_profile_is_copied_privately_and_creates_the_directory(self):
        source = self.write("Downloads/home.ovpn", CLIENT + "auth-user-pass\n<ca>\nX\n</ca>\n")
        result = self.add(source)
        target = self.profiles / "home.ovpn"
        self.assertEqual(result["message"], "Added home")
        self.assertEqual(target.read_text(), source.read_text())
        self.assertEqual((self.mode(self.profiles), self.mode(target)), (0o700, 0o600))

    def test_profile_with_certificate_files_gets_its_own_folder(self):
        self.write("Downloads/office/certs/client.crt", "CERT")
        self.write("Downloads/office/client.key", PLAIN_PEM)
        source = self.write("Downloads/office/client.ovpn", CLIENT + "cert certs/client.crt\nkey client.key\n")
        self.write("Downloads/office/unrelated.txt", "not copied")
        result = self.add(source)
        folder = self.profiles / "office"
        self.assertEqual(result["added"], [str(folder / "client.ovpn")])
        self.assertEqual(
            sorted(str(p.relative_to(folder)) for p in folder.rglob("*") if p.is_file()), ["certs/client.crt", "client.key", "client.ovpn"]
        )
        self.assertEqual(module.inspect_config(folder / "client.ovpn").problems, [])
        self.assertEqual(self.mode(folder / "client.key"), 0o600)
        self.assertEqual(list(self.profiles.glob(".import-*")), [])

    def test_duplicates_are_refused_and_name_clashes_get_a_suffix(self):
        source = self.write("Downloads/vpn.ovpn", CLIENT)
        self.add(source)
        with self.assertRaisesRegex(module.WidgetError, "already in your profiles"):
            self.add(source)
        other = self.write("Elsewhere/vpn.ovpn", CLIENT + "remote second.example 1194\n")
        self.assertEqual(self.add(other)["added"], [str(self.profiles / "vpn-2.ovpn")])

    def test_unsafe_or_incomplete_profiles_are_refused(self):
        self.write("Downloads/shared-ca.crt", "CA")
        cases = (
            (self.write("Downloads/sub/up.ovpn", CLIENT + "ca ../shared-ca.crt\n"), "outside its folder"),
            (self.write("Downloads/missing.ovpn", CLIENT + "cert nope.crt\n"), "not found next to it"),
            (self.write("Downloads/server.conf", "port 1194\ndev tun\n"), "Not an OpenVPN client configuration"),
            (self.write("Downloads/notes.txt", "hello"), "Choose an .ovpn"),
        )
        for source, error in cases:
            with self.subTest(source=source.name), self.assertRaisesRegex(module.WidgetError, error):
                self.add(source)
        self.assertEqual(list(self.profiles.iterdir()), [])

    def test_zip_bundle_is_unwrapped_into_its_own_folder(self):
        bundle = self.root / "pfsense-alice.zip"
        with module.zipfile.ZipFile(bundle, "w") as archive:
            archive.writestr("pfsense-alice/alice.ovpn", CLIENT + "pkcs12 alice.p12\n")
            archive.writestr("pfsense-alice/alice.p12", "P12")
            archive.writestr("__MACOSX/pfsense-alice/._alice.ovpn", "junk")
        result = self.add(bundle)
        folder = self.profiles / "pfsense-alice"
        self.assertEqual(result["added"], [str(folder / "alice.ovpn")])
        self.assertEqual(sorted(p.name for p in folder.iterdir()), ["alice.ovpn", "alice.p12"])
        self.assertEqual(module.inspect_config(folder / "alice.ovpn").required_secrets, ["cert-pass"])

    def test_zip_with_unsafe_paths_or_no_profiles_is_refused(self):
        cases = {"evil.zip": ("../../escape.ovpn", CLIENT), "empty.zip": ("deep/er/x.ovpn", CLIENT)}
        for name, (member, text) in cases.items():
            bundle = self.root / name
            with module.zipfile.ZipFile(bundle, "w") as archive:
                archive.writestr(member, text)
                archive.writestr("readme.txt", "x")
            with self.subTest(name=name), self.assertRaisesRegex(module.WidgetError, "unsafe path|no .ovpn"):
                self.add(bundle)
        self.assertFalse((self.root / "escape.ovpn").exists())
        self.assertEqual([p.name for p in self.profiles.iterdir()], [])

    def test_portal_uris_become_paths(self):
        self.assertEqual(module.uri_to_path("file:///home/u/My%20VPN.ovpn"), "/home/u/My VPN.ovpn")
        with self.assertRaises(module.WidgetError):
            module.uri_to_path("sftp://host/vpn.ovpn")

    @unittest.skipUnless(find_spec("gi"), "python-gobject not installed")
    def test_file_chooser_options_match_the_portal_signature(self):
        options = module.file_chooser_options("token_1", self.root)
        self.assertEqual(options.get_type_string(), "(ssa{sv})")
        parent, title, values = options.unpack()
        self.assertEqual((parent, title, values["handle_token"]), ("", "Add OpenVPN profile", "token_1"))
        self.assertEqual(bytes(values["current_folder"]), bytes(self.root) + b"\0")


if __name__ == "__main__":
    unittest.main()
