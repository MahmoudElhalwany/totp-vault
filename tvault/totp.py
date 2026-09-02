"""RFC 4226 (HOTP) and RFC 6238 (TOTP) code generation."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import re
import time

ALGORITHMS = {
    "SHA1": hashlib.sha1,
    "SHA256": hashlib.sha256,
    "SHA512": hashlib.sha512,
    "MD5": hashlib.md5,
}


class InvalidSecret(ValueError):
    """Raised when a shared secret is not valid base32."""


def normalize_algorithm(name: str | None) -> str:
    if not name:
        return "SHA1"
    key = name.strip().upper().replace("-", "")
    if key not in ALGORITHMS:
        raise ValueError(f"unsupported algorithm: {name}")
    return key


def decode_secret(secret: str) -> bytes:
    """Decode a base32 shared secret, tolerating lowercase, spaces and missing padding."""
    cleaned = re.sub(r"[\s\-_]", "", secret).upper()
    if not cleaned:
        raise InvalidSecret("empty secret")
    cleaned += "=" * (-len(cleaned) % 8)
    try:
        raw = base64.b32decode(cleaned, casefold=True)
    except (binascii.Error, ValueError) as exc:
        raise InvalidSecret(f"not valid base32: {exc}") from exc
    if not raw:
        raise InvalidSecret("secret decoded to zero bytes")
    return raw


def encode_secret(raw: bytes) -> str:
    """Encode raw secret bytes as unpadded base32, the otpauth:// convention."""
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def hotp(secret: bytes, counter: int, digits: int = 6, algorithm: str = "SHA1") -> str:
    digest = hmac.new(secret, counter.to_bytes(8, "big"), ALGORITHMS[algorithm]).digest()
    offset = digest[-1] & 0x0F
    truncated = int.from_bytes(digest[offset : offset + 4], "big") & 0x7FFFFFFF
    return str(truncated % (10**digits)).zfill(digits)


def totp(
    secret: bytes,
    period: int = 30,
    digits: int = 6,
    algorithm: str = "SHA1",
    at: float | None = None,
) -> str:
    now = time.time() if at is None else at
    return hotp(secret, int(now) // period, digits, algorithm)


def remaining(period: int = 30, at: float | None = None) -> float:
    """Seconds until the current TOTP step expires."""
    now = time.time() if at is None else at
    return period - (now % period)
