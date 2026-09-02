"""Parsing and generation of otpauth:// URIs and Google Authenticator exports.

Google Authenticator's "Export accounts" QR encodes an
`otpauth-migration://offline?data=<base64 protobuf>` payload. Rather than
pull in a protobuf runtime, this module walks the wire format directly —
the schema is small and stable:

    MigrationPayload { repeated OtpParameters otp_parameters = 1; ... }
    OtpParameters {
        bytes  secret    = 1;  string name   = 2;  string issuer = 3;
        enum   algorithm = 4;  enum   digits = 5;  enum   type   = 6;
        int64  counter   = 7;
    }
"""

from __future__ import annotations

import base64
import binascii
from urllib.parse import parse_qs, quote, unquote, urlparse

from . import totp as totp_mod

_MIG_ALGORITHM = {0: "SHA1", 1: "SHA1", 2: "SHA256", 3: "SHA512", 4: "MD5"}
_MIG_DIGITS = {0: 6, 1: 6, 2: 8}
_MIG_TYPE = {0: "totp", 1: "hotp", 2: "totp"}


class OtpAuthError(ValueError):
    """Raised when an otpauth URI or migration payload cannot be parsed."""


def parse_uri(uri: str) -> dict:
    """Parse a single otpauth:// URI into a normalized dict."""
    uri = uri.strip()
    parsed = urlparse(uri)
    if parsed.scheme.lower() != "otpauth":
        raise OtpAuthError(f"not an otpauth:// URI: {uri[:40]!r}")

    kind = parsed.netloc.lower()
    if kind not in ("totp", "hotp"):
        raise OtpAuthError(f"unsupported otpauth type: {kind!r}")

    label = unquote(parsed.path.lstrip("/"))
    issuer_label, _, account = label.rpartition(":")
    issuer_label = issuer_label.strip()
    account = account.strip()

    params = {k.lower(): v[0] for k, v in parse_qs(parsed.query).items()}
    secret = params.get("secret")
    if not secret:
        raise OtpAuthError("otpauth URI has no secret parameter")
    totp_mod.decode_secret(secret)  # validate early

    issuer = params.get("issuer", "").strip() or issuer_label
    digits = int(params.get("digits", 6))
    if digits not in (6, 7, 8):
        raise OtpAuthError(f"unsupported digit count: {digits}")

    entry = {
        "type": kind,
        "name": issuer or account or "unnamed",
        "issuer": issuer,
        "username": account,
        "secret": secret.replace(" ", "").upper(),
        "algorithm": totp_mod.normalize_algorithm(params.get("algorithm")),
        "digits": digits,
        "period": int(params.get("period", 30)),
        "counter": int(params.get("counter", 0)),
    }
    return entry


def build_uri(entry: dict) -> str:
    """Render an entry back to an otpauth:// URI (for export / phone transfer)."""
    kind = entry.get("type", "totp")
    issuer = entry.get("issuer") or entry.get("name") or ""
    account = entry.get("username") or entry.get("name") or "account"
    label = f"{issuer}:{account}" if issuer else account

    query = [f"secret={entry['secret']}"]
    if issuer:
        query.append(f"issuer={quote(issuer, safe='')}")
    if entry.get("algorithm", "SHA1") != "SHA1":
        query.append(f"algorithm={entry['algorithm']}")
    if int(entry.get("digits", 6)) != 6:
        query.append(f"digits={entry['digits']}")
    if kind == "totp" and int(entry.get("period", 30)) != 30:
        query.append(f"period={entry['period']}")
    if kind == "hotp":
        query.append(f"counter={entry.get('counter', 0)}")
    return f"otpauth://{kind}/{quote(label, safe=':')}?" + "&".join(query)


def _read_varint(buf: bytes, i: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        if i >= len(buf):
            raise OtpAuthError("truncated varint in migration payload")
        byte = buf[i]
        i += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, i
        shift += 7
        if shift > 63:
            raise OtpAuthError("oversized varint in migration payload")


def _iter_fields(buf: bytes):
    """Yield (field_number, wire_type, value) for a protobuf message."""
    i = 0
    while i < len(buf):
        key, i = _read_varint(buf, i)
        field, wire = key >> 3, key & 0x07
        if wire == 0:
            value, i = _read_varint(buf, i)
        elif wire == 2:
            length, i = _read_varint(buf, i)
            value = buf[i : i + length]
            if len(value) != length:
                raise OtpAuthError("truncated length-delimited field")
            i += length
        elif wire == 5:
            value, i = buf[i : i + 4], i + 4
        elif wire == 1:
            value, i = buf[i : i + 8], i + 8
        else:
            raise OtpAuthError(f"unsupported protobuf wire type {wire}")
        yield field, wire, value


def parse_migration(uri: str) -> list[dict]:
    """Parse an otpauth-migration://offline?data=... payload into entries."""
    parsed = urlparse(uri.strip())
    if parsed.scheme.lower() != "otpauth-migration":
        raise OtpAuthError("not an otpauth-migration:// URI")

    data = parse_qs(parsed.query).get("data", [None])[0]
    if not data:
        raise OtpAuthError("migration URI has no data parameter")

    raw_b64 = unquote(data)
    raw_b64 += "=" * (-len(raw_b64) % 4)
    try:
        payload = base64.b64decode(raw_b64)
    except (binascii.Error, ValueError) as exc:
        raise OtpAuthError(f"migration data is not valid base64: {exc}") from exc

    entries = []
    for field, wire, value in _iter_fields(payload):
        if field != 1 or wire != 2:
            continue  # version / batch metadata
        entries.append(_parse_otp_parameters(value))
    if not entries:
        raise OtpAuthError("migration payload contained no accounts")
    return entries


def _parse_otp_parameters(buf: bytes) -> dict:
    secret = b""
    name = issuer = ""
    algorithm = digits = kind = 0
    counter = 0

    for field, wire, value in _iter_fields(buf):
        if field == 1 and wire == 2:
            secret = value
        elif field == 2 and wire == 2:
            name = value.decode("utf-8", "replace")
        elif field == 3 and wire == 2:
            issuer = value.decode("utf-8", "replace")
        elif field == 4 and wire == 0:
            algorithm = value
        elif field == 5 and wire == 0:
            digits = value
        elif field == 6 and wire == 0:
            kind = value
        elif field == 7 and wire == 0:
            counter = value

    if not secret:
        raise OtpAuthError("migration account has no secret")

    # Google puts "Issuer:account" in name when issuer is not set separately.
    account = name
    if not issuer and ":" in name:
        issuer, _, account = name.partition(":")
        issuer, account = issuer.strip(), account.strip()

    return {
        "type": _MIG_TYPE.get(kind, "totp"),
        "name": issuer or account or "unnamed",
        "issuer": issuer,
        "username": account,
        "secret": totp_mod.encode_secret(secret),
        "algorithm": _MIG_ALGORITHM.get(algorithm, "SHA1"),
        "digits": _MIG_DIGITS.get(digits, 6),
        "period": 30,
        "counter": counter,
    }


def parse_any(text: str) -> list[dict]:
    """Parse one or more otpauth / otpauth-migration URIs from arbitrary text."""
    found = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        low = line.lower()
        if low.startswith("otpauth-migration://"):
            found.extend(parse_migration(line))
        elif low.startswith("otpauth://"):
            found.append(parse_uri(line))
    if not found:
        raise OtpAuthError("no otpauth:// or otpauth-migration:// URI found in input")
    return found
