"""End-to-end tests for tvault.

Everything runs against a throwaway TVAULT_HOME so a developer's real vault
is never touched. The native-host tests speak the actual framed protocol to
a real subprocess, rather than calling the handler directly.
"""

from __future__ import annotations

import base64
import json
import os
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tvault import agent, otpauth  # noqa: E402
from tvault.crypto import VaultCryptoError, gen_password  # noqa: E402
from tvault.install import extension_id, host_manifest, write_launchers  # noqa: E402
from tvault.vault import (  # noqa: E402
    Entry,
    Vault,
    VaultError,
    derive_from_header,
    host_matches,
    normalize_host,
    read_header,
)

PASSWORD = "correct horse battery staple"
SECRET = "JBSWY3DPEHPK3PXP"


class TempHome(unittest.TestCase):
    """Base class giving each test an isolated TVAULT_HOME."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="tvault-test-")
        self.home = Path(self.tmp.name)
        self.vault_path = self.home / "vault.json"
        self.env = {
            **os.environ,
            "TVAULT_HOME": str(self.home),
            "TVAULT_VAULT": str(self.vault_path),
            "PYTHONPATH": str(ROOT),
        }
        self._saved = {k: os.environ.get(k) for k in ("TVAULT_HOME", "TVAULT_VAULT")}
        os.environ["TVAULT_HOME"] = str(self.home)
        os.environ["TVAULT_VAULT"] = str(self.vault_path)

    def tearDown(self) -> None:
        try:
            agent.lock()
        except Exception:
            pass
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        self.tmp.cleanup()

    def make_vault(self) -> tuple[Vault, bytes]:
        vault, key = Vault.create(self.vault_path, PASSWORD)
        vault.add(Entry(
            name="GitHub", issuer="GitHub", username="me@example.com",
            secret=SECRET, password="hunter2", urls=["github.com"],
        ))
        vault.add(Entry(name="Bank", issuer="Bank", username="acct", password="s3cret", urls=["bank.example"]))
        vault.save(key)
        return vault, key


class TestVaultFile(TempHome):
    def test_roundtrip(self):
        _, key = self.make_vault()
        loaded = Vault.load(self.vault_path, key)
        self.assertEqual(len(loaded.entries), 2)
        self.assertEqual(loaded.resolve("GitHub").password, "hunter2")
        self.assertEqual(loaded.resolve("GitHub").code(at=0), "282760")

    def test_file_permissions_are_owner_only(self):
        self.make_vault()
        self.assertEqual(self.vault_path.stat().st_mode & 0o777, 0o600)

    def test_ciphertext_contains_no_plaintext(self):
        self.make_vault()
        blob = self.vault_path.read_bytes()
        for needle in (b"hunter2", b"me@example.com", SECRET.encode(), b"GitHub"):
            self.assertNotIn(needle, blob, f"{needle!r} leaked into the vault file")

    def test_wrong_password_rejected(self):
        self.make_vault()
        bad = derive_from_header("wrong password", read_header(self.vault_path))
        with self.assertRaises(VaultCryptoError):
            Vault.load(self.vault_path, bad)

    def test_header_tampering_is_detected(self):
        """KDF params are bound in as AAD, so editing them must break auth."""
        _, key = self.make_vault()
        document = json.loads(self.vault_path.read_text())
        document["kdf"]["n"] = 1024  # try to downgrade the KDF
        self.vault_path.write_text(json.dumps(document))
        with self.assertRaises(VaultCryptoError):
            Vault.load(self.vault_path, key)

    def test_ciphertext_tampering_is_detected(self):
        _, key = self.make_vault()
        document = json.loads(self.vault_path.read_text())
        raw = bytearray(base64.b64decode(document["ciphertext"]))
        raw[len(raw) // 2] ^= 0x01
        document["ciphertext"] = base64.b64encode(bytes(raw)).decode()
        self.vault_path.write_text(json.dumps(document))
        with self.assertRaises(VaultCryptoError):
            Vault.load(self.vault_path, key)

    def test_change_master_password(self):
        vault, key = self.make_vault()
        new_key = vault.rekey("a brand new password")
        vault.save(new_key)
        self.assertEqual(len(Vault.load(self.vault_path, new_key).entries), 2)
        with self.assertRaises(VaultCryptoError):
            Vault.load(self.vault_path, key)

    def test_save_is_atomic_leaves_no_temp_file(self):
        vault, key = self.make_vault()
        vault.save(key)
        leftovers = list(self.home.glob("*.tmp"))
        self.assertEqual(leftovers, [])

    def test_duplicate_name_requires_force(self):
        vault, key = self.make_vault()
        with self.assertRaises(VaultError):
            vault.add(Entry(name="GitHub"))
        vault.add(Entry(name="GitHub", username="second"), replace=True)
        self.assertEqual(len(vault.entries), 2)


class TestLookup(TempHome):
    def test_resolve_prefers_exact_name(self):
        vault, _ = self.make_vault()
        vault.add(Entry(name="GitHub Enterprise"))
        self.assertEqual(vault.resolve("GitHub").name, "GitHub")

    def test_ambiguous_query_raises(self):
        vault, _ = self.make_vault()
        vault.add(Entry(name="GitHub Enterprise"))
        with self.assertRaises(VaultError):
            vault.resolve("git")

    def test_host_matching(self):
        self.assertTrue(host_matches("github.com", "github.com"))
        self.assertTrue(host_matches("github.com", "gist.github.com"))
        self.assertTrue(host_matches("github.com", "https://www.github.com/login"))
        self.assertFalse(host_matches("github.com", "github.com.evil.tld"))
        self.assertFalse(host_matches("github.com", "notgithub.com"))
        self.assertFalse(host_matches("", "github.com"))

    def test_normalize_host_strips_noise(self):
        self.assertEqual(normalize_host("https://user:pw@www.Example.com:8443/x?y=1"), "example.com")

    def test_for_host(self):
        vault, _ = self.make_vault()
        names = {e.name for e in vault.for_host("gist.github.com")}
        self.assertIn("GitHub", names)
        self.assertNotIn("Bank", names)


class TestOtpAuth(unittest.TestCase):
    def test_parse_uri(self):
        parsed = otpauth.parse_uri(
            f"otpauth://totp/GitHub:me@example.com?secret={SECRET}&issuer=GitHub&digits=8&period=60&algorithm=SHA256"
        )
        self.assertEqual(parsed["issuer"], "GitHub")
        self.assertEqual(parsed["username"], "me@example.com")
        self.assertEqual((parsed["digits"], parsed["period"], parsed["algorithm"]), (8, 60, "SHA256"))

    def test_uri_roundtrip(self):
        original = f"otpauth://totp/GitHub:me?secret={SECRET}&issuer=GitHub"
        rebuilt = otpauth.build_uri(otpauth.parse_uri(original))
        self.assertEqual(otpauth.parse_uri(rebuilt)["secret"], SECRET)

    def test_rejects_junk(self):
        for bad in ["https://example.com", "otpauth://totp/x", "otpauth://xxx/y?secret=AA"]:
            with self.assertRaises(otpauth.OtpAuthError):
                otpauth.parse_uri(bad)

    def test_rejects_invalid_base32(self):
        with self.assertRaises(Exception):
            otpauth.parse_uri("otpauth://totp/x?secret=1111111")  # 1 is not base32

    def test_google_authenticator_migration(self):
        """Build a real migration payload by hand, then parse it back."""
        def varint(value: int) -> bytes:
            out = bytearray()
            while True:
                byte = value & 0x7F
                value >>= 7
                out.append(byte | (0x80 if value else 0))
                if not value:
                    return bytes(out)

        def field(num: int, wire: int, payload: bytes) -> bytes:
            return varint((num << 3) | wire) + payload

        def delim(num: int, payload: bytes) -> bytes:
            return field(num, 2, varint(len(payload)) + payload)

        secret_raw = base64.b32decode(SECRET)
        account = (
            delim(1, secret_raw)
            + delim(2, b"me@example.com")
            + delim(3, b"GitHub")
            + field(4, 0, varint(1))   # SHA1
            + field(5, 0, varint(1))   # six digits
            + field(6, 0, varint(2))   # TOTP
        )
        payload = delim(1, account) + field(2, 0, varint(1))
        uri = "otpauth-migration://offline?data=" + base64.b64encode(payload).decode()

        entries = otpauth.parse_migration(uri)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["issuer"], "GitHub")
        self.assertEqual(entries[0]["username"], "me@example.com")
        self.assertEqual(entries[0]["secret"], SECRET)
        self.assertEqual(entries[0]["digits"], 6)

    def test_parse_any_handles_mixed_text(self):
        text = f"# a comment\n\notpauth://totp/A?secret={SECRET}\notpauth://totp/B?secret={SECRET}\n"
        self.assertEqual(len(otpauth.parse_any(text)), 2)


class TestPasswordGeneration(unittest.TestCase):
    def test_length_and_classes(self):
        for _ in range(50):
            pw = gen_password(20)
            self.assertEqual(len(pw), 20)
            self.assertTrue(any(c.islower() for c in pw))
            self.assertTrue(any(c.isupper() for c in pw))
            self.assertTrue(any(c.isdigit() for c in pw))

    def test_unambiguous_excludes_lookalikes(self):
        for _ in range(50):
            self.assertFalse(set(gen_password(24, unambiguous=True)) & set("lI1O0"))

    def test_values_differ(self):
        self.assertEqual(len({gen_password(16) for _ in range(100)}), 100)


class TestAgent(TempHome):
    def test_cache_and_retrieve(self):
        _, key = self.make_vault()
        self.assertTrue(agent.cache_key(key, self.vault_path, ttl=60))
        self.assertEqual(agent.get_key(self.vault_path), key)
        self.assertTrue(agent.status()["unlocked"])

    def test_lock_forgets_key(self):
        _, key = self.make_vault()
        agent.cache_key(key, self.vault_path, ttl=60)
        agent.lock()
        time.sleep(0.2)
        self.assertIsNone(agent.get_key(self.vault_path))

    def test_socket_is_owner_only(self):
        _, key = self.make_vault()
        agent.cache_key(key, self.vault_path, ttl=60)
        mode = agent.socket_path().stat().st_mode & 0o777
        self.assertEqual(mode, 0o600, "agent socket must not be reachable by other users")

    def test_key_never_written_to_disk(self):
        _, key = self.make_vault()
        agent.cache_key(key, self.vault_path, ttl=60)
        for path in self.home.rglob("*"):
            if path.is_file():
                self.assertNotIn(key, path.read_bytes(), f"key leaked into {path}")


class NativeHostSession:
    """Speaks Chrome's framed native-messaging protocol to a real subprocess."""

    LEN = struct.Struct("=I")

    def __init__(self, env: dict):
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "tvault.nativehost"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=str(ROOT), env=env,
        )

    def call(self, message: dict) -> dict:
        body = json.dumps(message).encode()
        self.proc.stdin.write(self.LEN.pack(len(body)) + body)
        self.proc.stdin.flush()
        header = self.proc.stdout.read(self.LEN.size)
        assert len(header) == self.LEN.size, "native host closed the connection"
        (length,) = self.LEN.unpack(header)
        return json.loads(self.proc.stdout.read(length).decode())

    def close(self):
        try:
            self.proc.stdin.close()
            self.proc.wait(timeout=5)
        except Exception:
            self.proc.kill()
            self.proc.wait(timeout=5)
        finally:
            for stream in (self.proc.stdout, self.proc.stderr):
                if stream and not stream.closed:
                    stream.close()


class TestNativeHost(TempHome):
    def setUp(self):
        super().setUp()
        self.vault, self.key = self.make_vault()
        self.session = NativeHostSession(self.env)

    def tearDown(self):
        self.session.close()
        super().tearDown()

    def test_status_reports_locked_before_unlock(self):
        reply = self.session.call({"type": "status"})
        self.assertTrue(reply["ok"])
        self.assertTrue(reply["vault_exists"])
        self.assertFalse(reply["unlocked"])

    def test_wrong_password_rejected(self):
        reply = self.session.call({"type": "unlock", "password": "nope"})
        self.assertFalse(reply["ok"])
        self.assertIn("wrong master password", reply["error"])

    def test_locked_requests_are_refused(self):
        reply = self.session.call({"type": "list", "domain": "github.com"})
        self.assertFalse(reply["ok"])
        self.assertTrue(reply.get("locked"))

    def test_full_flow(self):
        self.assertTrue(self.session.call({"type": "unlock", "password": PASSWORD})["ok"])
        self.assertTrue(self.session.call({"type": "status"})["unlocked"])

        listing = self.session.call({"type": "list", "domain": "github.com"})
        self.assertTrue(listing["ok"])
        github = next(e for e in listing["entries"] if e["name"] == "GitHub")
        self.assertTrue(github["matches_site"])
        self.assertEqual(listing["entries"][0]["name"], "GitHub", "site matches must sort first")

        codes = self.session.call({"type": "codes", "ids": [github["id"]]})
        self.assertTrue(codes["ok"])
        self.assertRegex(codes["codes"][github["id"]]["code"], r"^\d{6}$")

        creds = self.session.call({"type": "credentials", "id": github["id"], "include_code": True})
        self.assertEqual(creds["username"], "me@example.com")
        self.assertEqual(creds["password"], "hunter2")
        self.assertRegex(creds["code"], r"^\d{6}$")

        self.assertTrue(self.session.call({"type": "lock"})["ok"])
        self.assertFalse(self.session.call({"type": "status"})["unlocked"])

    def test_list_never_returns_secrets(self):
        self.session.call({"type": "unlock", "password": PASSWORD})
        listing = self.session.call({"type": "list", "domain": "github.com"})
        blob = json.dumps(listing)
        self.assertNotIn("hunter2", blob)
        self.assertNotIn(SECRET, blob)
        for entry in listing["entries"]:
            self.assertNotIn("password", entry)
            self.assertNotIn("secret", entry)

    def test_unknown_request_is_an_error_not_a_crash(self):
        reply = self.session.call({"type": "nonsense"})
        self.assertFalse(reply["ok"])
        self.assertIn("unknown request", reply["error"])

    def test_malformed_request_does_not_kill_the_host(self):
        self.session.call({"type": "unlock", "password": PASSWORD})
        self.assertFalse(self.session.call({"type": "code", "id": "does-not-exist"})["ok"])
        self.assertTrue(self.session.call({"type": "status"})["ok"], "host should still be alive")


class TestInstall(unittest.TestCase):
    def test_extension_id_is_stable_and_well_formed(self):
        ext_id = extension_id()
        self.assertEqual(len(ext_id), 32)
        self.assertTrue(all("a" <= c <= "p" for c in ext_id))
        self.assertEqual(ext_id, extension_id(), "extension ID must be deterministic")

    def test_host_manifest_locks_to_our_extension(self):
        manifest = host_manifest(Path("/tmp/tvault-host"), extension_id())
        self.assertEqual(manifest["allowed_origins"], [f"chrome-extension://{extension_id()}/"])
        self.assertEqual(manifest["type"], "stdio")


class TestLaunchers(TempHome):
    """Regression cover for the generated CLI and native-host launchers."""

    def test_launcher_keeps_the_venv_interpreter(self):
        """sys.executable must not be symlink-resolved.

        Inside a virtualenv, <venv>/bin/python is a symlink to the base
        interpreter. Resolving it produces a launcher that runs the base
        interpreter, which silently loses every package installed in the venv
        — the vault still opened, but optional extras such as the QR decoder
        vanished with a misleading "not installed" message.
        """
        cli, host = write_launchers()
        expected = os.path.abspath(sys.executable)

        for launcher in (cli, host):
            text = launcher.read_text()
            self.assertIn(f'"{expected}"', text, f"{launcher.name} lost the running interpreter")
            resolved = str(Path(sys.executable).resolve())
            if resolved != expected:
                self.assertNotIn(
                    f'"{resolved}"', text,
                    f"{launcher.name} resolved the symlink and escaped the venv",
                )

    def test_launcher_interpreter_lives_in_the_current_prefix(self):
        """Whatever prefix is running the tests must be the one baked in."""
        cli, _ = write_launchers()
        interpreter = None
        for line in cli.read_text().splitlines():
            if "exec " in line:
                interpreter = [p for p in line.split('"') if "python" in p][0]
        self.assertIsNotNone(interpreter)
        self.assertTrue(
            Path(interpreter).is_relative_to(Path(sys.prefix))
            or Path(interpreter) == Path(os.path.abspath(sys.executable)),
            f"{interpreter} is outside the running prefix {sys.prefix}",
        )

    def test_launchers_are_executable_and_owner_only_dir(self):
        cli, host = write_launchers()
        for launcher in (cli, host):
            self.assertTrue(os.access(launcher, os.X_OK), f"{launcher.name} is not executable")
        self.assertEqual(cli.parent.parent.stat().st_mode & 0o777, 0o700)


if __name__ == "__main__":
    unittest.main(verbosity=2)
