"""Static checks on the extension.

The popup can only be exercised inside Chrome, so these tests guard the
contracts that break silently: element IDs referenced by the script must
exist in the HTML, the manifest must stay minimal and correctly wired, and
the popup must never persist secrets.
"""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

EXT = Path(__file__).resolve().parent.parent / "extension"
MANIFEST = json.loads((EXT / "manifest.json").read_text())
POPUP_JS = (EXT / "popup.js").read_text()
POPUP_HTML = (EXT / "popup.html").read_text()
POPUP_CSS = (EXT / "popup.css").read_text()


def strip_comments(source: str) -> str:
    """Crude but sufficient: drop /* */ and // so prose about the code
    is not mistaken for the code itself."""
    source = re.sub(r"/\*.*?\*/", "", source, flags=re.S)
    return re.sub(r"^\s*//.*$", "", source, flags=re.M)


POPUP_CODE = strip_comments(POPUP_JS)


class TestManifest(unittest.TestCase):
    def test_manifest_v3(self):
        self.assertEqual(MANIFEST["manifest_version"], 3)

    def test_permissions_are_minimal(self):
        allowed = {"nativeMessaging", "activeTab", "scripting", "clipboardWrite"}
        self.assertEqual(set(MANIFEST["permissions"]), allowed)

    def test_no_broad_host_permissions(self):
        """<all_urls> would let the extension read every page unprompted."""
        self.assertNotIn("host_permissions", MANIFEST)
        self.assertNotIn("content_scripts", MANIFEST)

    def test_has_identity_key(self):
        self.assertIn("key", MANIFEST)
        self.assertGreater(len(MANIFEST["key"]), 300)

    def test_referenced_files_exist(self):
        self.assertTrue((EXT / MANIFEST["action"]["default_popup"]).exists())
        for _, rel in MANIFEST["icons"].items():
            self.assertTrue((EXT / rel).exists(), f"missing icon {rel}")


class TestPopupContract(unittest.TestCase):
    def test_every_referenced_id_exists_in_html(self):
        referenced = set(re.findall(r'\bel\("([\w-]+)"\)', POPUP_JS))
        referenced |= set(re.findall(r'view-(\w+)"', POPUP_JS))
        html_ids = set(re.findall(r'id="([\w-]+)"', POPUP_HTML))
        # `views` are expanded as view-<name> at runtime.
        for name in ("loading", "error", "locked", "list"):
            self.assertIn(f"view-{name}", html_ids)
        missing = {r for r in referenced if not r.startswith("view-")} - html_ids
        self.assertEqual(missing, set(), f"popup.js references missing IDs: {missing}")

    def test_html_scripts_are_local(self):
        """MV3 forbids remote code; every script must ship with the extension."""
        for src in re.findall(r'<script[^>]*src="([^"]+)"', POPUP_HTML):
            self.assertFalse(src.startswith(("http:", "https:", "//")), f"remote script: {src}")
            self.assertTrue((EXT / src).exists())

    def test_no_inline_event_handlers(self):
        self.assertNotRegex(POPUP_HTML, r"\son\w+\s*=", "inline handlers violate the MV3 CSP")

    def test_never_persists_secrets(self):
        for api in ("chrome.storage", "localStorage", "sessionStorage", "indexedDB"):
            self.assertFalse(
                api in POPUP_CODE,
                f"popup.js uses {api}; secrets must not outlive the popup",
            )

    def test_uses_bulk_codes_endpoint(self):
        """Per-entry code calls would spawn one host process per entry."""
        self.assertIn('type: "codes"', POPUP_CODE)

    def test_host_name_matches_installer(self):
        from tvault.install import HOST_NAME

        self.assertIn(f'HOST = "{HOST_NAME}"', POPUP_CODE)

    def test_injected_filler_is_self_contained(self):
        """executeScript serialises the function; it can close over nothing."""
        body = POPUP_CODE[POPUP_CODE.index("function fillForm("):]
        body = body[: body.index("\nstart();")]
        for leaked in ("send(", "el(", "toast(", "entries", "codes["):
            self.assertNotIn(leaked, body, f"fillForm references outer scope: {leaked}")

    def test_theme_defined_for_light_and_dark(self):
        self.assertIn(":root", POPUP_CSS)
        self.assertIn("prefers-color-scheme: light", POPUP_CSS)


if __name__ == "__main__":
    unittest.main(verbosity=2)
