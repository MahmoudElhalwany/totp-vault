#!/usr/bin/env python3
"""One-time: generate the extension's identity key and stamp it into the manifest.

Run again only if you want a *new* extension ID (you would then have to
reload the extension in Chrome and re-run `tvault install-chrome`).
"""

import base64
import json
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tvault.install import extension_id  # noqa: E402
from tvault.vault import ensure_home, home  # noqa: E402

MANIFEST = ROOT / "extension" / "manifest.json"


def main() -> int:
    if "--force" not in sys.argv:
        manifest = json.loads(MANIFEST.read_text())
        if manifest.get("key"):
            print(f"manifest already has a key; extension ID = {extension_id()}")
            print("pass --force to generate a new identity (changes the ID)")
            return 0

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    spki = key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    manifest = json.loads(MANIFEST.read_text())
    manifest["key"] = base64.b64encode(spki).decode("ascii")
    MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n")

    # Keep the private half only so a .crx can be packed later; Chrome does
    # not need it to load an unpacked extension.
    ensure_home()
    priv = home() / "extension_key.pem"
    fd = os.open(priv, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    print(f"extension ID: {extension_id()}")
    print(f"private key:  {priv} (mode 0600)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
