"""Terminal presentation helpers: colour, tables, and the live code view."""

from __future__ import annotations

import os
import shutil
import sys
import time

_ENABLED = sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def _c(code: str) -> str:
    return code if _ENABLED else ""


RESET = _c("\033[0m")
BOLD = _c("\033[1m")
DIM = _c("\033[2m")
RED = _c("\033[31m")
GREEN = _c("\033[32m")
YELLOW = _c("\033[33m")
BLUE = _c("\033[34m")
CYAN = _c("\033[36m")
GREY = _c("\033[90m")

HIDE_CURSOR = _c("\033[?25l")
SHOW_CURSOR = _c("\033[?25h")
CLEAR = _c("\033[2J\033[H")
HOME = _c("\033[H")
CLEAR_LINE = _c("\033[K")


def err(message: str) -> None:
    print(f"{RED}error{RESET}: {message}", file=sys.stderr)


def warn(message: str) -> None:
    print(f"{YELLOW}warning{RESET}: {message}", file=sys.stderr)


def ok(message: str) -> None:
    print(f"{GREEN}✓{RESET} {message}")


def info(message: str) -> None:
    print(f"{DIM}{message}{RESET}")


def group_code(code: str) -> str:
    """Split a code in half for readability: 123456 -> '123 456'."""
    if len(code) == 6:
        return f"{code[:3]} {code[3:]}"
    if len(code) == 8:
        return f"{code[:4]} {code[4:]}"
    return code


def bar(fraction: float, width: int = 12) -> str:
    """A horizontal meter; colour shifts as a TOTP step runs out."""
    fraction = max(0.0, min(1.0, fraction))
    filled = int(round(fraction * width))
    if fraction > 0.5:
        colour = GREEN
    elif fraction > 0.2:
        colour = YELLOW
    else:
        colour = RED
    return f"{colour}{'█' * filled}{GREY}{'░' * (width - filled)}{RESET}"


def table(rows: list[list[str]], headers: list[str] | None = None) -> str:
    """Render a left-aligned table, ignoring ANSI codes when measuring width."""
    if not rows:
        return ""
    all_rows = ([headers] if headers else []) + rows
    columns = max(len(r) for r in all_rows)
    widths = [0] * columns
    for row in all_rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], _visible_len(str(cell)))

    lines = []
    if headers:
        lines.append(
            BOLD + "  ".join(str(h).ljust(widths[i]) for i, h in enumerate(headers)).rstrip() + RESET
        )
    for row in rows:
        parts = []
        for i in range(columns):
            cell = str(row[i]) if i < len(row) else ""
            pad = widths[i] - _visible_len(cell)
            parts.append(cell + " " * max(0, pad))
        lines.append("  ".join(parts).rstrip())
    return "\n".join(lines)


def _visible_len(text: str) -> int:
    out, i = 0, 0
    while i < len(text):
        if text[i] == "\033":
            end = text.find("m", i)
            if end == -1:
                break
            i = end + 1
            continue
        out += 1
        i += 1
    return out


def truncate(text: str, limit: int) -> str:
    text = text or ""
    return text if len(text) <= limit else text[: limit - 1] + "…"


def watch(entries, interval: float = 0.25) -> None:
    """Live-refreshing view of every TOTP code, until interrupted."""
    if not entries:
        info("no entries with a TOTP secret")
        return

    width = shutil.get_terminal_size((80, 24)).columns
    name_width = max(12, min(32, max(len(e.label) for e in entries)))

    sys.stdout.write(HIDE_CURSOR + CLEAR)
    try:
        while True:
            now = time.time()
            lines = [
                f"{BOLD}tvault{RESET} {DIM}— live codes, Ctrl-C to exit{RESET}",
                "",
            ]
            for entry in entries:
                try:
                    code = entry.code(at=now)
                except Exception as exc:  # a single bad secret shouldn't kill the view
                    lines.append(f"{truncate(entry.label, name_width).ljust(name_width)}  {RED}{exc}{RESET}")
                    continue
                left = entry.remaining(at=now)
                meter = bar(left / entry.period)
                colour = RED if left <= 5 else CYAN
                lines.append(
                    f"{truncate(entry.label, name_width).ljust(name_width)}  "
                    f"{colour}{BOLD}{group_code(code).rjust(9)}{RESET}  "
                    f"{meter} {GREY}{int(left):2d}s{RESET}"
                )
            sys.stdout.write(HOME)
            sys.stdout.write("\n".join(line[: width + 200] + CLEAR_LINE for line in lines))
            sys.stdout.write("\033[J")
            sys.stdout.flush()
            time.sleep(interval)
    except KeyboardInterrupt:
        pass
    finally:
        sys.stdout.write(SHOW_CURSOR + "\n")
        sys.stdout.flush()
