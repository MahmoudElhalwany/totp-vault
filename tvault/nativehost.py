"""Chrome native messaging host.

Chrome launches this process and speaks a simple framed protocol over
stdin/stdout: a 4-byte native-order length, then that many bytes of UTF-8
JSON. Nothing else may ever be written to stdout, so every failure path
returns a framed error object instead of raising.

Design notes:
  * Secrets are only ever returned for a single entry, in response to an
    explicit user action in the popup. `list` returns metadata only.
  * The master password is never stored here; unlocking hands the derived
    key to the agent, which holds it in memory with an idle timeout.
"""

from __future__ import annotations

import json
import struct
import sys
import traceback
from pathlib import Path

from . import agent, crypto
from .crypto import VaultCryptoError
from .vault import Vault, VaultError, default_vault_path, derive_from_header, read_header

_LEN = struct.Struct("=I")
MAX_INCOMING = 1 << 20   # Chrome caps messages to the host at 1 MB anyway
PROTOCOL_VERSION = 1


def read_message() -> dict | None:
    raw = sys.stdin.buffer.read(_LEN.size)
    if len(raw) < _LEN.size:
        return None
    (length,) = _LEN.unpack(raw)
    if length == 0 or length > MAX_INCOMING:
        return None
    body = sys.stdin.buffer.read(length)
    if len(body) < length:
        return None
    return json.loads(body.decode("utf-8"))


def write_message(payload: dict) -> None:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    sys.stdout.buffer.write(_LEN.pack(len(body)))
    sys.stdout.buffer.write(body)
    sys.stdout.buffer.flush()


# -- request handlers -----------------------------------------------------


def _open(path: Path) -> Vault:
    key = agent.get_key(path)
    if key is None:
        raise Locked()
    return Vault.load(path, key)


class Locked(Exception):
    pass


def handle(message: dict) -> dict:
    kind = message.get("type")
    path = Path(message.get("vault") or default_vault_path())

    if kind == "status":
        state = agent.status()
        return {
            "ok": True,
            "protocol": PROTOCOL_VERSION,
            "vault": str(path),
            "vault_exists": path.exists(),
            "unlocked": bool(state.get("unlocked")),
            "expires_in": state.get("expires_in", 0),
        }

    if kind == "unlock":
        password = message.get("password") or ""
        if not password:
            return {"ok": False, "error": "no password supplied"}
        if not path.exists():
            return {"ok": False, "error": f"no vault at {path} — run 'tvault init'"}
        try:
            header = read_header(path)
            key = derive_from_header(password, header)
            vault = Vault.load(path, key)
        except VaultCryptoError:
            return {"ok": False, "error": "wrong master password"}
        agent.cache_key(key, path, int(message.get("ttl") or agent.DEFAULT_TTL))
        return {"ok": True, "count": len(vault.entries)}

    if kind == "lock":
        agent.lock()
        return {"ok": True}

    if kind == "list":
        vault = _open(path)
        domain = message.get("domain") or ""
        matched = {e.id for e in vault.for_host(domain)} if domain else set()
        entries = []
        for entry in vault.sorted_entries():
            public = entry.public()
            public["matches_site"] = entry.id in matched
            entries.append(public)
        entries.sort(key=lambda e: (not e["matches_site"], e["label"].lower()))
        return {"ok": True, "entries": entries, "domain": domain}

    if kind == "code":
        vault = _open(path)
        entry = vault.by_id(message.get("id", ""))
        if entry is None:
            return {"ok": False, "error": "no such entry"}
        if not entry.has_totp:
            return {"ok": False, "error": "entry has no TOTP secret"}
        code = entry.code()
        remaining = entry.remaining()
        if entry.type == "hotp":
            entry.counter += 1
            key = agent.get_key(path)
            if key:
                vault.save(key)
        return {
            "ok": True,
            "code": code,
            "remaining": round(remaining, 2),
            "period": entry.period,
        }

    if kind == "codes":
        # One call for every visible code: Chrome spawns a fresh host process
        # per message, so per-entry requests would be painfully slow.
        vault = _open(path)
        wanted = message.get("ids")
        entries = vault.entries if wanted is None else [
            e for e in (vault.by_id(i) for i in wanted) if e is not None
        ]
        codes = {}
        for entry in entries:
            if not entry.has_totp or entry.type != "totp":
                continue
            try:
                codes[entry.id] = {
                    "code": entry.code(),
                    "remaining": round(entry.remaining(), 2),
                    "period": entry.period,
                }
            except Exception as exc:
                codes[entry.id] = {"error": str(exc)}
        return {"ok": True, "codes": codes}

    if kind == "credentials":
        vault = _open(path)
        entry = vault.by_id(message.get("id", ""))
        if entry is None:
            return {"ok": False, "error": "no such entry"}
        payload = {
            "ok": True,
            "username": entry.username,
            "password": entry.password,
            "has_totp": entry.has_totp,
        }
        if entry.has_totp and message.get("include_code"):
            payload["code"] = entry.code()
        return payload

    if kind == "generate":
        length = int(message.get("length") or 24)
        length = max(8, min(128, length))
        return {"ok": True, "password": crypto.gen_password(length, symbols=not message.get("no_symbols"))}

    return {"ok": False, "error": f"unknown request type: {kind!r}"}


def main() -> int:
    while True:
        try:
            message = read_message()
        except (json.JSONDecodeError, struct.error):
            return 1
        if message is None:
            return 0

        try:
            reply = handle(message)
        except Locked:
            reply = {"ok": False, "error": "locked", "locked": True}
        except (VaultError, VaultCryptoError) as exc:
            reply = {"ok": False, "error": str(exc)}
        except Exception as exc:  # never let a traceback reach stdout
            print(traceback.format_exc(), file=sys.stderr)
            reply = {"ok": False, "error": f"internal error: {exc.__class__.__name__}"}

        try:
            write_message(reply)
        except OSError:
            return 0


if __name__ == "__main__":
    raise SystemExit(main())
