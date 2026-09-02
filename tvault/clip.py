"""Clipboard integration, with an optional auto-clear timer."""

from __future__ import annotations

import shutil
import subprocess
import sys


class ClipboardUnavailable(RuntimeError):
    """Raised when no clipboard helper exists on this system."""


def _copier() -> list[str]:
    if sys.platform == "darwin":
        return ["pbcopy"]
    if shutil.which("wl-copy"):
        return ["wl-copy"]
    if shutil.which("xclip"):
        return ["xclip", "-selection", "clipboard"]
    if shutil.which("xsel"):
        return ["xsel", "--clipboard", "--input"]
    raise ClipboardUnavailable(
        "no clipboard tool found (install xclip or wl-clipboard on Linux)"
    )


def _paster() -> list[str] | None:
    if sys.platform == "darwin":
        return ["pbpaste"]
    if shutil.which("wl-paste"):
        return ["wl-paste", "--no-newline"]
    if shutil.which("xclip"):
        return ["xclip", "-selection", "clipboard", "-o"]
    return None


def copy(text: str) -> None:
    subprocess.run(_copier(), input=text.encode("utf-8"), check=True)


def copy_with_clear(text: str, seconds: int = 30) -> None:
    """Copy, then wipe the clipboard later — but only if it still holds our value.

    The clearing runs in a detached child so the CLI can exit immediately.
    """
    copy(text)
    if seconds <= 0:
        return

    paste = _paster()
    if paste is None:
        return

    script = (
        "import subprocess,sys,time\n"
        "time.sleep(float(sys.argv[1]))\n"
        "want=sys.argv[2]\n"
        "paste=sys.argv[3:sys.argv.index('--')]\n"
        "copy=sys.argv[sys.argv.index('--')+1:]\n"
        "try:\n"
        "    cur=subprocess.run(paste,capture_output=True).stdout.decode('utf-8','replace')\n"
        "except Exception:\n"
        "    sys.exit(0)\n"
        "if cur.strip()==want:\n"
        "    subprocess.run(copy,input=b'')\n"
    )
    subprocess.Popen(
        [sys.executable, "-c", script, str(seconds), text.strip(), *paste, "--", *_copier()],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
