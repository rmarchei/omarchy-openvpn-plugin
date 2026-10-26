"""Unit tests for backend functions; NetworkManager and Secret Service are mocked."""

from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader
import io
import json
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
        # Octal escapes produce single bytes, so non-ASCII text must pass through untouched.
        self.assertEqual(module.escape_secret("pässwörd "), "pässwörd ")

    def test_vpn_data_parsing_unescapes_values(self):
        output = "ca = /home/u/.local/share/networkmanagement/certificates/nm-openvpn/.office-12345678-ca.pem, connection-type = tls, remote = a\\:1194\n"
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

    def test_forget_only_removes_files_written_for_this_profile(self):
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
            patch.object(module, "nm_connections", return_value={**connection("u1", "OpenVPN · c"), **connection("u2", "Other", "activated")}),
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


if __name__ == "__main__":
    unittest.main()
