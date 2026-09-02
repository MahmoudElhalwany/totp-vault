"""Decode QR codes locally.

Reading a 2FA QR is the one step where people are routinely tempted to paste
a payload into a website. An `otpauth-migration://` export contains every
seed in your Google Authenticator, so that would hand over the lot. Everything
here runs offline.

Backends, in order of preference:
  1. Apple's Vision framework (macOS, via PyObjC) — no extra binaries.
  2. `zbarimg` from the zbar package, if it is on PATH.
  3. OpenCV's QRCodeDetector, if the module happens to be installed.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
from pathlib import Path

INSTALL_HINT = (
    "no local QR decoder available. Install one:\n"
    "  macOS   pip install 'pyobjc-framework-Vision' 'pyobjc-framework-Quartz'\n"
    "  Linux   sudo apt install zbar-tools     (or: pip install opencv-python-headless)"
)


class QRError(Exception):
    """Raised when an image cannot be read or holds no QR code."""


# -- backend 1: Apple Vision ---------------------------------------------


def _have(module: str) -> bool:
    """Probe for an optional module without importing it."""
    try:
        return importlib.util.find_spec(module) is not None
    except (ImportError, ValueError):
        return False


def _vision_available() -> bool:
    return _have("Vision") and _have("Quartz")


def _vision_decode(image) -> list[str]:
    """`image` is a CIImage. Returns every QR payload found."""
    import Vision

    handler = Vision.VNImageRequestHandler.alloc().initWithCIImage_options_(image, {})
    request = Vision.VNDetectBarcodesRequest.alloc().init()
    try:
        request.setSymbologies_([Vision.VNBarcodeSymbologyQR])
    except (AttributeError, ValueError):
        pass  # older SDKs: fall back to detecting every symbology

    ok, error = handler.performRequests_error_([request], None)
    if not ok:
        raise QRError(f"Vision could not process the image: {error}")

    payloads = []
    for observation in request.results() or []:
        value = observation.payloadStringValue()
        if value:
            payloads.append(str(value))
    return payloads


def _vision_from_bytes(data: bytes) -> list[str]:
    import Quartz
    from Foundation import NSData

    payload = NSData.dataWithBytes_length_(data, len(data))
    image = Quartz.CIImage.imageWithData_(payload)
    if image is None:
        raise QRError("the image data could not be decoded")
    return _vision_decode(image)


def _vision_from_path(path: Path) -> list[str]:
    import Quartz
    from Foundation import NSURL

    url = NSURL.fileURLWithPath_(str(path))
    image = Quartz.CIImage.imageWithContentsOfURL_(url)
    if image is None:
        raise QRError(f"could not read {path} as an image")
    return _vision_decode(image)


# -- backend 2: zbarimg ---------------------------------------------------


def _zbar_decode(path: Path) -> list[str]:
    result = subprocess.run(
        ["zbarimg", "-q", "--raw", "-Sdisable", "-Sqrcode.enable", str(path)],
        capture_output=True,
    )
    if result.returncode not in (0, 4):  # 4 = nothing found
        raise QRError(result.stderr.decode("utf-8", "replace").strip() or "zbarimg failed")
    return [line for line in result.stdout.decode("utf-8", "replace").splitlines() if line.strip()]


# -- backend 3: OpenCV ----------------------------------------------------


def _opencv_decode(path: Path) -> list[str]:
    import cv2  # type: ignore

    image = cv2.imread(str(path))
    if image is None:
        raise QRError(f"could not read {path} as an image")
    detector = cv2.QRCodeDetector()
    ok, payloads, _, _ = detector.detectAndDecodeMulti(image)
    if not ok:
        return []
    return [p for p in payloads if p]


# -- public API -----------------------------------------------------------


def backend_name() -> str | None:
    if _vision_available():
        return "Apple Vision"
    if shutil.which("zbarimg"):
        return "zbarimg"
    if _have("cv2"):
        return "OpenCV"
    return None


def decode_file(path: str | Path) -> list[str]:
    """Return every QR payload in an image file."""
    path = Path(path).expanduser()
    if not path.exists():
        raise QRError(f"no such file: {path}")

    if _vision_available():
        return _vision_from_path(path)
    if shutil.which("zbarimg"):
        return _zbar_decode(path)
    if _have("cv2"):
        return _opencv_decode(path)
    raise QRError(INSTALL_HINT)


def decode_bytes(data: bytes) -> list[str]:
    """Return every QR payload in an in-memory image.

    Used by the browser extension, which sends a screenshot of the current
    tab rather than writing it to disk.
    """
    if not data:
        raise QRError("empty image data")

    if _vision_available():
        return _vision_from_bytes(data)

    # The other backends are file-oriented; stage the bytes in a temp file
    # with owner-only permissions and remove it immediately afterwards.
    import tempfile

    suffix = ".png" if data[:8] == b"\x89PNG\r\n\x1a\n" else ".jpg"
    fd, name = tempfile.mkstemp(suffix=suffix)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        return decode_file(name)
    finally:
        try:
            os.unlink(name)
        except OSError:
            pass


def decode_clipboard() -> list[str]:
    """Decode a QR from an image sitting on the clipboard (macOS)."""
    if not _vision_available():
        raise QRError(
            "reading the clipboard needs the macOS Vision bridge.\n"
            "Save the QR to a file and pass its path instead, or:\n"
            "  pip install 'pyobjc-framework-Vision' 'pyobjc-framework-Quartz'"
        )

    import Quartz
    from AppKit import NSPasteboard

    board = NSPasteboard.generalPasteboard()
    data = None
    for kind in ("public.png", "public.tiff", "public.jpeg"):
        data = board.dataForType_(kind)
        if data:
            break

    if data is None:
        # A screenshot saved to disk may be on the clipboard as a file URL.
        names = board.propertyListForType_("NSFilenamesPboardType")
        if names:
            payloads = []
            for name in names:
                payloads.extend(decode_file(str(name)))
            return payloads
        raise QRError(
            "no image on the clipboard.\n"
            "On macOS, Cmd-Ctrl-Shift-4 copies a screen selection to the clipboard."
        )

    image = Quartz.CIImage.imageWithData_(data)
    if image is None:
        raise QRError("the clipboard image could not be decoded")
    return _vision_decode(image)
