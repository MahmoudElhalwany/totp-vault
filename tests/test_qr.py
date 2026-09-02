"""QR decoding tests.

Where a QR *encoder* is available (CoreImage on macOS) these render a real
Google Authenticator export and read it back, which exercises the decoder
against a genuine image rather than a fixture. Without a decoder backend the
whole module skips, so Linux CI stays green.
"""

from __future__ import annotations

import base64
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_tvault import PASSWORD, NativeHostSession, TempHome  # noqa: E402
from tvault import otpauth, qr  # noqa: E402

HAVE_DECODER = qr.backend_name() is not None


def _varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def _delim(num: int, payload: bytes) -> bytes:
    return _varint((num << 3) | 2) + _varint(len(payload)) + payload


def _vfield(num: int, value: int) -> bytes:
    return _varint(num << 3) + _varint(value)


def migration_uri(accounts) -> str:
    payload = b""
    for secret, name, issuer in accounts:
        payload += _delim(
            1,
            _delim(1, secret) + _delim(2, name) + _delim(3, issuer)
            + _vfield(4, 1) + _vfield(5, 1) + _vfield(6, 2),
        )
    payload += _vfield(2, 1) + _vfield(3, 1) + _vfield(4, 0) + _vfield(5, 42)
    return "otpauth-migration://offline?data=" + base64.b64encode(payload).decode()


def can_encode() -> bool:
    try:
        import Quartz

        return Quartz.CIFilter.filterWithName_("CIQRCodeGenerator") is not None
    except Exception:
        return False


def render_qr(text: str, path: Path, scale: int = 8) -> Path:
    """Render `text` as a real QR image using CoreImage."""
    import Quartz
    from Foundation import NSData, NSURL

    data = NSData.dataWithBytes_length_(text.encode(), len(text.encode()))
    generator = Quartz.CIFilter.filterWithName_("CIQRCodeGenerator")
    generator.setValue_forKey_(data, "inputMessage")
    generator.setValue_forKey_("M", "inputCorrectionLevel")
    image = generator.outputImage().imageByApplyingTransform_(
        Quartz.CGAffineTransformMakeScale(scale, scale)
    )
    cg = Quartz.CIContext.context().createCGImage_fromRect_(image, image.extent())
    dest = Quartz.CGImageDestinationCreateWithURL(
        NSURL.fileURLWithPath_(str(path)), "public.png", 1, None
    )
    Quartz.CGImageDestinationAddImage(dest, cg, None)
    Quartz.CGImageDestinationFinalize(dest)
    return path


@unittest.skipUnless(HAVE_DECODER, "no local QR decoder available")
class TestDecoder(unittest.TestCase):
    def test_backend_reported(self):
        self.assertIn(qr.backend_name(), {"Apple Vision", "zbarimg", "OpenCV"})

    def test_missing_file_raises(self):
        with self.assertRaises(qr.QRError):
            qr.decode_file("/nonexistent/definitely-not-here.png")

    def test_non_image_raises(self):
        with tempfile.NamedTemporaryFile(suffix=".png") as fh:
            fh.write(b"this is not a PNG")
            fh.flush()
            with self.assertRaises(qr.QRError):
                qr.decode_file(fh.name)


@unittest.skipUnless(HAVE_DECODER and can_encode(), "needs both a QR encoder and decoder")
class TestRoundTrip(unittest.TestCase):
    """Render a real export QR, decode it, and confirm the seeds survive."""

    ACCOUNTS = [
        (base64.b32decode("JBSWY3DPEHPK3PXP"), b"me@example.com", b"GitHub"),
        (base64.b32decode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"), b"work@corp.com", b"Okta"),
        (base64.b32decode("KRSXG5CTMVRXEZLU"), b"root", b"AWS"),
    ]

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="tvault-qr-")
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_google_authenticator_export_round_trip(self):
        uri = migration_uri(self.ACCOUNTS)
        image = render_qr(uri, self.dir / "export.png")

        payloads = qr.decode_file(image)
        self.assertEqual(payloads, [uri], "decoded payload must match byte for byte")

        entries = otpauth.parse_any(payloads[0])
        self.assertEqual(len(entries), len(self.ACCOUNTS))

        from tvault.totp import decode_secret

        for (secret, name, issuer), entry in zip(self.ACCOUNTS, entries):
            self.assertEqual(entry["issuer"], issuer.decode())
            self.assertEqual(entry["username"], name.decode())
            self.assertEqual(decode_secret(entry["secret"]), secret)

    def test_plain_otpauth_qr(self):
        """A single-account QR from a website's 2FA setup page."""
        uri = "otpauth://totp/GitHub:me@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"
        payloads = qr.decode_file(render_qr(uri, self.dir / "single.png"))
        self.assertEqual(payloads, [uri])
        self.assertEqual(otpauth.parse_any(payloads[0])[0]["issuer"], "GitHub")

    def test_image_without_a_qr_returns_nothing(self):
        blank = self.dir / "blank.png"
        import Quartz
        from Foundation import NSURL

        image = Quartz.CIImage.imageWithColor_(
            Quartz.CIColor.colorWithRed_green_blue_(1.0, 1.0, 1.0)
        ).imageByCroppingToRect_(Quartz.CGRectMake(0, 0, 200, 200))
        cg = Quartz.CIContext.context().createCGImage_fromRect_(image, image.extent())
        dest = Quartz.CGImageDestinationCreateWithURL(
            NSURL.fileURLWithPath_(str(blank)), "public.png", 1, None
        )
        Quartz.CGImageDestinationAddImage(dest, cg, None)
        Quartz.CGImageDestinationFinalize(dest)
        self.assertEqual(qr.decode_file(blank), [])


@unittest.skipUnless(HAVE_DECODER and can_encode(), "needs both a QR encoder and decoder")
class TestExtensionScan(TempHome):
    """The browser extension screenshots the tab and posts it to the host."""

    def setUp(self):
        super().setUp()
        self.make_vault()
        self.dir = self.home / "images"
        self.dir.mkdir()
        self.session = NativeHostSession(self.env)
        self.assertTrue(self.session.call({"type": "unlock", "password": PASSWORD})["ok"])

    def tearDown(self):
        self.session.close()
        super().tearDown()

    def _screenshot(self, uri: str) -> str:
        image = render_qr(uri, self.dir / "page.png")
        return base64.b64encode(image.read_bytes()).decode()

    def test_preview_then_save(self):
        uri = "otpauth://totp/Stripe:ops@example.com?secret=KRSXG5CTMVRXEZLU&issuer=Stripe"
        image = self._screenshot(uri)

        preview = self.session.call({"type": "scan_qr", "image": image, "save": False})
        self.assertTrue(preview["ok"])
        self.assertFalse(preview["saved"])
        self.assertEqual(preview["found"][0]["issuer"], "Stripe")
        self.assertNotIn("KRSXG5CTMVRXEZLU", json.dumps(preview),
                         "a preview must not carry the secret into the browser")

        saved = self.session.call(
            {"type": "scan_qr", "image": image, "save": True, "domain": "stripe.com"}
        )
        self.assertTrue(saved["ok"])
        self.assertEqual(saved["added"], ["Stripe (ops@example.com)"])

        listing = self.session.call({"type": "list", "domain": "stripe.com"})
        stripe = next(e for e in listing["entries"] if e["issuer"] == "Stripe")
        self.assertTrue(stripe["has_totp"])
        self.assertTrue(stripe["matches_site"], "the scanned entry should match the site")

    def test_rescanning_does_not_duplicate(self):
        uri = "otpauth://totp/Stripe:ops@example.com?secret=KRSXG5CTMVRXEZLU&issuer=Stripe"
        image = self._screenshot(uri)
        self.session.call({"type": "scan_qr", "image": image, "save": True})
        again = self.session.call({"type": "scan_qr", "image": image, "save": True})
        self.assertEqual(again["added"], [])
        self.assertEqual(again["skipped"], ["Stripe (ops@example.com)"])

    def test_multi_account_export_qr(self):
        accounts = [
            (base64.b32decode("JBSWY3DPEHPK3PXP"), b"a@example.com", b"Alpha"),
            (base64.b32decode("KRSXG5CTMVRXEZLU"), b"b@example.com", b"Beta"),
        ]
        image = self._screenshot(migration_uri(accounts))
        saved = self.session.call({"type": "scan_qr", "image": image, "save": True})
        self.assertEqual(sorted(saved["added"]), ["Alpha (a@example.com)", "Beta (b@example.com)"])

    def test_page_without_a_qr(self):
        blank = self.dir / "blank.png"
        import Quartz
        from Foundation import NSURL

        image = Quartz.CIImage.imageWithColor_(
            Quartz.CIColor.colorWithRed_green_blue_(1.0, 1.0, 1.0)
        ).imageByCroppingToRect_(Quartz.CGRectMake(0, 0, 300, 300))
        cg = Quartz.CIContext.context().createCGImage_fromRect_(image, image.extent())
        dest = Quartz.CGImageDestinationCreateWithURL(
            NSURL.fileURLWithPath_(str(blank)), "public.png", 1, None
        )
        Quartz.CGImageDestinationAddImage(dest, cg, None)
        Quartz.CGImageDestinationFinalize(dest)

        reply = self.session.call({
            "type": "scan_qr",
            "image": base64.b64encode(blank.read_bytes()).decode(),
            "save": False,
        })
        self.assertFalse(reply["ok"])
        self.assertIn("no QR code found", reply["error"])

    def test_rejects_junk_image_data(self):
        reply = self.session.call({"type": "scan_qr", "image": "not base64!!", "save": False})
        self.assertFalse(reply["ok"])
        self.assertIn("base64", reply["error"])

    def test_scan_requires_unlock_to_save(self):
        uri = "otpauth://totp/Stripe:ops@example.com?secret=KRSXG5CTMVRXEZLU&issuer=Stripe"
        image = self._screenshot(uri)
        self.session.call({"type": "lock"})
        reply = self.session.call({"type": "scan_qr", "image": image, "save": True})
        self.assertFalse(reply["ok"])
        self.assertTrue(reply.get("locked"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
