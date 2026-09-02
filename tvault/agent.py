"""In-memory key cache, in the spirit of ssh-agent.

Deriving a key costs ~0.3s and needs the master password, which is fine once
but intolerable for every `tvault code` or every popup refresh in Chrome. The
agent holds the derived key in the memory of a detached process and hands it
back to same-user clients over a unix socket, then exits after an idle timeout.

Access control is filesystem-based: the socket lives inside a 0700 directory
and is itself 0600, so only this uid can connect. The key never touches disk.
"""

from __future__ import annotations

import json
import os
import socket
import struct
import sys
import time
from pathlib import Path

from .vault import ensure_home, home

DEFAULT_TTL = 900  # 15 minutes idle
_LEN = struct.Struct("<I")
MAX_MESSAGE = 1 << 20


def socket_path() -> Path:
    return Path(os.environ.get("TVAULT_AGENT_SOCK", home() / "agent.sock"))


# -- framing --------------------------------------------------------------


def _send(conn: socket.socket, obj: dict) -> None:
    body = json.dumps(obj).encode("utf-8")
    conn.sendall(_LEN.pack(len(body)) + body)


def _recv(conn: socket.socket) -> dict | None:
    header = _recv_exactly(conn, _LEN.size)
    if not header:
        return None
    (length,) = _LEN.unpack(header)
    if length > MAX_MESSAGE:
        raise ValueError("agent message too large")
    body = _recv_exactly(conn, length)
    if not body:
        return None
    return json.loads(body.decode("utf-8"))


def _recv_exactly(conn: socket.socket, count: int) -> bytes | None:
    chunks = bytearray()
    while len(chunks) < count:
        chunk = conn.recv(count - len(chunks))
        if not chunk:
            return None
        chunks.extend(chunk)
    return bytes(chunks)


# -- client ---------------------------------------------------------------


def request(payload: dict, timeout: float = 5.0) -> dict | None:
    """Send one request to a running agent. Returns None if no agent is up."""
    path = socket_path()
    if not path.exists():
        return None
    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    conn.settimeout(timeout)
    try:
        conn.connect(str(path))
    except (ConnectionRefusedError, FileNotFoundError, OSError):
        # Socket file left behind by a crashed agent.
        try:
            path.unlink()
        except OSError:
            pass
        return None
    finally_close = True
    try:
        _send(conn, payload)
        return _recv(conn)
    except (OSError, ValueError, json.JSONDecodeError):
        return None
    finally:
        if finally_close:
            conn.close()


def get_key(vault_path: Path) -> bytes | None:
    """Fetch the cached key for a vault, refreshing its idle timer."""
    reply = request({"op": "key", "vault": str(vault_path)})
    if not reply or not reply.get("ok"):
        return None
    return bytes.fromhex(reply["key"])


def status() -> dict:
    reply = request({"op": "status"})
    if not reply:
        return {"unlocked": False, "running": False}
    reply["running"] = True
    return reply


def lock() -> bool:
    reply = request({"op": "lock"})
    return bool(reply and reply.get("ok"))


def cache_key(key: bytes, vault_path: Path, ttl: int = DEFAULT_TTL) -> bool:
    """Hand a derived key to the agent, starting one if needed."""
    payload = {"op": "set", "key": key.hex(), "vault": str(vault_path), "ttl": ttl}
    reply = request(payload)
    if reply and reply.get("ok"):
        return True
    return _spawn(payload)


def _spawn(payload: dict) -> bool:
    """Start a detached agent, passing the key over a pipe rather than argv.

    Uses posix_spawn with setsid instead of subprocess.Popen: the agent is
    meant to outlive this process, and a Popen handle for a child we never
    reap would leak a zombie and warn at interpreter shutdown.
    """
    ensure_home()
    path = socket_path()
    try:
        path.unlink()
    except FileNotFoundError:
        pass
    except OSError:
        return False

    root = str(Path(__file__).resolve().parent.parent)
    env = dict(os.environ)
    env["PYTHONPATH"] = root + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")

    read_fd, write_fd = os.pipe()
    devnull = os.open(os.devnull, os.O_RDWR)
    try:
        os.posix_spawn(
            sys.executable,
            [sys.executable, "-m", "tvault.agent"],
            env,
            file_actions=[
                (os.POSIX_SPAWN_DUP2, read_fd, 0),
                (os.POSIX_SPAWN_DUP2, devnull, 1),
                (os.POSIX_SPAWN_DUP2, devnull, 2),
            ],
            setsid=True,
        )
    except (OSError, ValueError):
        os.close(read_fd)
        os.close(write_fd)
        os.close(devnull)
        return False
    finally:
        os.close(read_fd)
        os.close(devnull)

    try:
        os.write(write_fd, (json.dumps(payload) + "\n").encode("utf-8"))
    except OSError:
        return False
    finally:
        os.close(write_fd)

    # Wait briefly for the socket to appear.
    for _ in range(100):
        if path.exists():
            return True
        time.sleep(0.02)
    return path.exists()


# -- server ---------------------------------------------------------------


class _State:
    def __init__(self) -> None:
        self.key: bytes | None = None
        self.vault: str = ""
        self.ttl: int = DEFAULT_TTL
        self.expires: float = 0.0

    def set(self, key: bytes, vault: str, ttl: int) -> None:
        self.key = key
        self.vault = vault
        self.ttl = max(30, int(ttl))
        self.touch()

    def touch(self) -> None:
        self.expires = time.time() + self.ttl

    def clear(self) -> None:
        self.key = None
        self.vault = ""
        self.expires = 0.0

    @property
    def unlocked(self) -> bool:
        return self.key is not None and time.time() < self.expires


def serve() -> int:
    """Run the agent. The initial {"op":"set",...} arrives on stdin."""
    try:
        first = json.loads(sys.stdin.readline() or "{}")
    except json.JSONDecodeError:
        return 2
    if first.get("op") != "set" or not first.get("key"):
        return 2

    state = _State()
    state.set(bytes.fromhex(first["key"]), first.get("vault", ""), first.get("ttl", DEFAULT_TTL))

    ensure_home()
    path = socket_path()
    try:
        path.unlink()
    except FileNotFoundError:
        pass

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    old_umask = os.umask(0o177)  # socket becomes 0600
    try:
        server.bind(str(path))
    finally:
        os.umask(old_umask)
    os.chmod(path, 0o600)
    server.listen(8)
    server.settimeout(5.0)

    try:
        while True:
            if not state.unlocked:
                break
            try:
                conn, _ = server.accept()
            except socket.timeout:
                continue
            with conn:
                conn.settimeout(5.0)
                try:
                    message = _recv(conn)
                except (OSError, ValueError, json.JSONDecodeError):
                    continue
                if message is None:
                    continue
                reply, keep_going = _handle(state, message)
                try:
                    _send(conn, reply)
                except OSError:
                    pass
                if not keep_going:
                    break
    finally:
        state.clear()
        server.close()
        try:
            path.unlink()
        except OSError:
            pass
    return 0


def _handle(state: _State, message: dict) -> tuple[dict, bool]:
    op = message.get("op")

    if op == "status":
        return (
            {
                "ok": True,
                "unlocked": state.unlocked,
                "vault": state.vault,
                "expires_in": max(0, int(state.expires - time.time())) if state.unlocked else 0,
                "ttl": state.ttl,
            },
            True,
        )

    if op == "key":
        wanted = message.get("vault") or state.vault
        if not state.unlocked:
            return {"ok": False, "error": "locked"}, False
        if state.vault and wanted != state.vault:
            return {"ok": False, "error": "a different vault is unlocked"}, True
        state.touch()
        return {"ok": True, "key": state.key.hex(), "expires_in": int(state.expires - time.time())}, True

    if op == "set":
        try:
            state.set(bytes.fromhex(message["key"]), message.get("vault", ""), message.get("ttl", DEFAULT_TTL))
        except (KeyError, ValueError):
            return {"ok": False, "error": "bad key"}, True
        return {"ok": True, "expires_in": state.ttl}, True

    if op == "lock":
        state.clear()
        return {"ok": True}, False

    return {"ok": False, "error": f"unknown op {op!r}"}, True


if __name__ == "__main__":
    raise SystemExit(serve())
