"""Vault encryption primitives.

Key derivation: scrypt (stdlib hashlib), N=2^17, r=8, p=1 -> 32-byte key.
Encryption:     AES-256-GCM, with the vault header bound in as additional
                authenticated data so KDF parameters cannot be downgraded
                by editing the file.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import string

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KDF_NAME = "scrypt"
KDF_N = 1 << 17
KDF_R = 8
KDF_P = 1
KDF_DKLEN = 32
# 128 * N * r bytes are needed; give scrypt headroom above that.
KDF_MAXMEM = 320 * 1024 * 1024

SALT_LEN = 16
NONCE_LEN = 12
CIPHER_NAME = "AES-256-GCM"


class VaultCryptoError(Exception):
    """Raised when a vault cannot be decrypted or authenticated."""


def new_salt() -> bytes:
    return os.urandom(SALT_LEN)


def derive_key(
    password: str,
    salt: bytes,
    n: int = KDF_N,
    r: int = KDF_R,
    p: int = KDF_P,
    dklen: int = KDF_DKLEN,
) -> bytes:
    """Stretch a master password into a symmetric key."""
    return hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=n,
        r=r,
        p=p,
        dklen=dklen,
        maxmem=KDF_MAXMEM,
    )


def encrypt(key: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    nonce = os.urandom(NONCE_LEN)
    return nonce, AESGCM(key).encrypt(nonce, plaintext, aad)


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise VaultCryptoError(
            "decryption failed — wrong master password, or the vault file was modified"
        ) from exc


def constant_time_eq(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)


_AMBIGUOUS = "lI1O0"


def gen_password(length: int = 24, symbols: bool = True, unambiguous: bool = False) -> str:
    """Generate a password from a cryptographically secure source.

    Retries until the result contains at least one character from each
    enabled class, so callers get the character diversity they asked for.
    """
    lower = string.ascii_lowercase
    upper = string.ascii_uppercase
    digits = string.digits
    syms = "!@#$%^&*()-_=+[]{};:,.?" if symbols else ""

    classes = [lower, upper, digits] + ([syms] if syms else [])
    if unambiguous:
        classes = ["".join(c for c in cls if c not in _AMBIGUOUS) for cls in classes]

    alphabet = "".join(classes)
    if length < len(classes):
        raise ValueError(f"length must be at least {len(classes)}")

    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if all(any(ch in cls for ch in pw) for cls in classes):
            return pw


def gen_passphrase(words: int = 5, sep: str = "-") -> str:
    """Generate a passphrase from the system word list, with a digit appended."""
    try:
        with open("/usr/share/dict/words", "r", encoding="utf-8", errors="ignore") as fh:
            pool = [
                w.strip().lower()
                for w in fh
                if 4 <= len(w.strip()) <= 9 and w.strip().isalpha()
            ]
    except OSError:
        pool = []
    if len(pool) < 2048:
        # No usable word list; fall back to a random password of similar strength.
        return gen_password(length=max(16, words * 4), symbols=False)
    return sep.join(secrets.choice(pool) for _ in range(words)) + sep + str(secrets.randbelow(100))
