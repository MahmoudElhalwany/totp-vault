#!/usr/bin/env python3
"""Generate the extension's PNG icons — a keyhole on a rounded indigo tile.

Written with zlib + struct so the repo carries no opaque binary assets:
every pixel here is reproducible by re-running this script.
"""

import struct
import zlib
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "extension" / "icons"
SIZES = (16, 32, 48, 128)
SS = 4  # supersampling factor, for antialiased edges

TOP = (99, 102, 241)      # indigo-500
BOTTOM = (67, 56, 202)    # indigo-700
GLYPH = (255, 255, 255)


def rounded_rect(x, y, radius):
    """Signed coverage test for a rounded unit square."""
    cx = min(max(x, radius), 1 - radius)
    cy = min(max(y, radius), 1 - radius)
    dx, dy = x - cx, y - cy
    return (dx * dx + dy * dy) <= radius * radius


def keyhole(x, y):
    """Circle head plus a tapered stem."""
    if (x - 0.5) ** 2 + (y - 0.40) ** 2 <= 0.155**2:
        return True
    if 0.40 <= y <= 0.76:
        t = (y - 0.40) / 0.36
        half = 0.055 + 0.075 * t * t
        return abs(x - 0.5) <= half
    return False


def render(size: int) -> bytes:
    rows = []
    n = size * SS
    for py in range(size):
        row = bytearray()
        for px in range(size):
            r_acc = g_acc = b_acc = a_acc = 0.0
            for sy in range(SS):
                for sx in range(SS):
                    x = (px * SS + sx + 0.5) / n
                    y = (py * SS + sy + 0.5) / n
                    if not rounded_rect(x, y, 0.22):
                        continue
                    if keyhole(x, y):
                        r, g, b = GLYPH
                    else:
                        r = TOP[0] + (BOTTOM[0] - TOP[0]) * y
                        g = TOP[1] + (BOTTOM[1] - TOP[1]) * y
                        b = TOP[2] + (BOTTOM[2] - TOP[2]) * y
                    r_acc += r
                    g_acc += g
                    b_acc += b
                    a_acc += 1.0
            samples = SS * SS
            if a_acc == 0:
                row += bytes((0, 0, 0, 0))
            else:
                row += bytes(
                    (
                        int(round(r_acc / a_acc)),
                        int(round(g_acc / a_acc)),
                        int(round(b_acc / a_acc)),
                        int(round(255 * a_acc / samples)),
                    )
                )
        rows.append(bytes(row))
    return png(size, size, rows)


def png(width: int, height: int, rows: list[bytes]) -> bytes:
    raw = b"".join(b"\x00" + row for row in rows)

    def chunk(tag: bytes, data: bytes) -> bytes:
        body = tag + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)

    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(raw, 9))
        + chunk(b"IEND", b"")
    )


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    for size in SIZES:
        path = OUT / f"icon{size}.png"
        path.write_bytes(render(size))
        print(f"  {path.name}  {path.stat().st_size} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
