"""Encrypted vault file: format, entry model, and load/save."""

from __future__ import annotations

import base64
import json
import os
import re
import stat
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path

from . import crypto
from . import totp as totp_mod

FORMAT_VERSION = 1


def home() -> Path:
    """Directory holding the vault, agent socket, and generated launchers."""
    return Path(os.environ.get("TVAULT_HOME", Path.home() / ".tvault"))


def default_vault_path() -> Path:
    return Path(os.environ.get("TVAULT_VAULT", home() / "vault.json"))


def ensure_home() -> Path:
    d = home()
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(d, 0o700)
    return d


class VaultError(Exception):
    """Raised for vault-level problems (missing file, bad format, duplicates)."""


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text)


def _now() -> int:
    return int(time.time())


@dataclass
class Entry:
    """One vault record. May carry a login, a TOTP secret, or both."""

    name: str
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    issuer: str = ""
    username: str = ""
    password: str = ""
    secret: str = ""          # base32 TOTP/HOTP shared secret
    type: str = "totp"        # "totp" | "hotp"
    algorithm: str = "SHA1"
    digits: int = 6
    period: int = 30
    counter: int = 0          # HOTP only
    urls: list[str] = field(default_factory=list)
    notes: str = ""
    created: int = field(default_factory=_now)
    updated: int = field(default_factory=_now)

    @property
    def has_totp(self) -> bool:
        return bool(self.secret)

    @property
    def has_password(self) -> bool:
        return bool(self.password)

    @property
    def label(self) -> str:
        """Human-facing identity: 'Issuer (account)'."""
        base = self.issuer or self.name
        if self.username and self.username.lower() != base.lower():
            return f"{base} ({self.username})"
        return base

    def code(self, at: float | None = None) -> str:
        if not self.secret:
            raise VaultError(f"entry {self.name!r} has no TOTP secret")
        raw = totp_mod.decode_secret(self.secret)
        if self.type == "hotp":
            return totp_mod.hotp(raw, self.counter, self.digits, self.algorithm)
        return totp_mod.totp(raw, self.period, self.digits, self.algorithm, at)

    def remaining(self, at: float | None = None) -> float:
        return totp_mod.remaining(self.period, at)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "Entry":
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in data.items() if k in known})

    def public(self) -> dict:
        """Metadata safe to hand to the browser extension — no secrets."""
        return {
            "id": self.id,
            "name": self.name,
            "issuer": self.issuer,
            "username": self.username,
            "label": self.label,
            "urls": self.urls,
            "has_password": self.has_password,
            "has_totp": self.has_totp,
            "digits": self.digits,
            "period": self.period,
        }


def normalize_host(value: str) -> str:
    """Reduce a URL or hostname to a bare lowercase host."""
    value = (value or "").strip().lower()
    if not value:
        return ""
    if "://" in value:
        value = value.split("://", 1)[1]
    value = value.split("/", 1)[0].split("?", 1)[0]
    value = value.rsplit("@", 1)[-1]          # strip userinfo
    value = value.split(":", 1)[0]            # strip port
    if value.startswith("www."):
        value = value[4:]
    return value


def host_matches(entry_host: str, page_host: str) -> bool:
    """True when a page host equals, or is a subdomain of, an entry host."""
    a, b = normalize_host(entry_host), normalize_host(page_host)
    if not a or not b:
        return False
    return a == b or b.endswith("." + a) or a.endswith("." + b)


@dataclass
class Vault:
    """A decrypted vault held in memory, plus the header needed to re-encrypt it."""

    path: Path
    header: dict
    entries: list[Entry] = field(default_factory=list)

    # -- construction -----------------------------------------------------

    @staticmethod
    def new_header() -> dict:
        return {
            "version": FORMAT_VERSION,
            "cipher": crypto.CIPHER_NAME,
            "kdf": {
                "name": crypto.KDF_NAME,
                "n": crypto.KDF_N,
                "r": crypto.KDF_R,
                "p": crypto.KDF_P,
                "dklen": crypto.KDF_DKLEN,
                "salt": _b64e(crypto.new_salt()),
            },
        }

    @classmethod
    def create(cls, path: Path, password: str) -> tuple["Vault", bytes]:
        if path.exists():
            raise VaultError(f"vault already exists at {path}")
        header = cls.new_header()
        key = derive_from_header(password, header)
        vault = cls(path=path, header=header, entries=[])
        vault.save(key)
        return vault, key

    # -- persistence ------------------------------------------------------

    @classmethod
    def load(cls, path: Path, key: bytes) -> "Vault":
        header, nonce, ciphertext = read_file(path)
        plaintext = crypto.decrypt(key, nonce, ciphertext, aad_for(header))
        payload = json.loads(plaintext.decode("utf-8"))
        entries = [Entry.from_dict(e) for e in payload.get("entries", [])]
        return cls(path=path, header=header, entries=entries)

    def save(self, key: bytes) -> None:
        payload = json.dumps(
            {"entries": [e.to_dict() for e in self.entries]},
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")

        aad = aad_for(self.header)
        nonce, ciphertext = crypto.encrypt(key, payload, aad)
        document = dict(self.header)
        document["nonce"] = _b64e(nonce)
        document["ciphertext"] = _b64e(ciphertext)

        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(document, fh, indent=2, sort_keys=True)
                fh.write("\n")
                fh.flush()
                os.fsync(fh.fileno())
        except Exception:
            tmp.unlink(missing_ok=True)
            raise
        os.replace(tmp, self.path)
        os.chmod(self.path, 0o600)

    def rekey(self, new_password: str) -> bytes:
        """Re-derive from a fresh salt. Caller must save() with the returned key."""
        self.header = self.new_header()
        return derive_from_header(new_password, self.header)

    # -- lookup -----------------------------------------------------------

    def add(self, entry: Entry, replace: bool = False) -> Entry:
        existing = self.by_exact_name(entry.name)
        if existing and not replace:
            raise VaultError(
                f"an entry named {entry.name!r} already exists (use --force to replace)"
            )
        if existing:
            entry.id = existing.id
            entry.created = existing.created
            entry.updated = _now()
            self.entries[self.entries.index(existing)] = entry
        else:
            self.entries.append(entry)
        return entry

    def remove(self, entry: Entry) -> None:
        self.entries.remove(entry)

    def by_id(self, entry_id: str) -> Entry | None:
        return next((e for e in self.entries if e.id == entry_id), None)

    def by_exact_name(self, name: str) -> Entry | None:
        needle = (name or "").strip().lower()
        return next((e for e in self.entries if e.name.lower() == needle), None)

    def search(self, query: str) -> list[Entry]:
        """Case-insensitive substring match over name, issuer, username and URLs."""
        needle = (query or "").strip().lower()
        if not needle:
            return list(self.entries)
        hits = []
        for e in self.entries:
            haystack = " ".join([e.name, e.issuer, e.username, " ".join(e.urls)]).lower()
            if needle in haystack:
                hits.append(e)
        return hits

    def resolve(self, query: str) -> Entry:
        """Find exactly one entry, preferring an exact name match."""
        exact = self.by_exact_name(query)
        if exact:
            return exact
        by_id = self.by_id(query)
        if by_id:
            return by_id
        hits = self.search(query)
        if not hits:
            raise VaultError(f"no entry matching {query!r}")
        if len(hits) > 1:
            names = ", ".join(sorted(e.name for e in hits[:8]))
            raise VaultError(f"{query!r} matches {len(hits)} entries: {names}")
        return hits[0]

    def for_host(self, page_host: str) -> list[Entry]:
        """Entries whose URLs, issuer or name plausibly belong to a page host."""
        host = normalize_host(page_host)
        if not host:
            return []
        matches = []
        for e in self.entries:
            if any(host_matches(u, host) for u in e.urls):
                matches.append(e)
                continue
            # Fall back to name/issuer against the registrable-ish label,
            # so a "GitHub" entry still surfaces on github.com.
            label = host.split(".")[0]
            if len(label) >= 3 and label in re.sub(r"\s+", "", (e.issuer or e.name)).lower():
                matches.append(e)
        return matches

    def sorted_entries(self) -> list[Entry]:
        return sorted(self.entries, key=lambda e: (e.issuer or e.name).lower())


# -- module-level file helpers -------------------------------------------


def aad_for(header: dict) -> bytes:
    """Canonical header bytes, bound into GCM so parameters can't be tampered with."""
    return json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")


def read_file(path: Path) -> tuple[dict, bytes, bytes]:
    if not path.exists():
        raise VaultError(f"no vault at {path} — run 'tvault init' first")
    warn_if_world_readable(path)
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise VaultError(f"vault file is not valid JSON: {exc}") from exc

    if document.get("version") != FORMAT_VERSION:
        raise VaultError(f"unsupported vault version: {document.get('version')!r}")
    for key in ("kdf", "cipher", "nonce", "ciphertext"):
        if key not in document:
            raise VaultError(f"vault file is missing the {key!r} field")
    if document["cipher"] != crypto.CIPHER_NAME:
        raise VaultError(f"unsupported cipher: {document['cipher']!r}")

    header = {k: v for k, v in document.items() if k not in ("nonce", "ciphertext")}
    return header, _b64d(document["nonce"]), _b64d(document["ciphertext"])


def read_header(path: Path) -> dict:
    return read_file(path)[0]


def derive_from_header(password: str, header: dict) -> bytes:
    kdf = header["kdf"]
    if kdf.get("name") != crypto.KDF_NAME:
        raise VaultError(f"unsupported KDF: {kdf.get('name')!r}")
    return crypto.derive_key(
        password,
        salt=_b64d(kdf["salt"]),
        n=int(kdf["n"]),
        r=int(kdf["r"]),
        p=int(kdf["p"]),
        dklen=int(kdf["dklen"]),
    )


def warn_if_world_readable(path: Path) -> None:
    try:
        mode = path.stat().st_mode
    except OSError:
        return
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        os.chmod(path, 0o600)
