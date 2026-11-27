#!/usr/bin/env python3
"""Generate packaging/windows/assets/pktpath-studio.ico from assets/logo.svg.

Produces a standard Windows ICO with 16, 32, 48 (32-bit BMP/DIB) and
256 (PNG) frames. Prefers rsvg-convert when available so the official
SVG is rendered faithfully; falls back to a built-in rasterizer that
mirrors assets/logo.svg geometry and colours (stdlib only).
"""

from __future__ import annotations

import argparse
import io
import math
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import zlib
from pathlib import Path


SIZES = (16, 32, 48, 256)


def repo_root_from_here() -> Path:
    here = Path(__file__).resolve()
    # packaging/windows/tools/gen_icon.py -> repo root
    return here.parents[3]


def find_logo_svg(root: Path) -> Path:
    candidates = [
        root / "assets" / "logo.svg",
        root / "studio-cordis" / "web" / "favicon.svg",
    ]
    for p in candidates:
        if p.is_file():
            return p
    raise FileNotFoundError("assets/logo.svg not found")


# ---------------------------------------------------------------------------
# PNG encoder (stdlib)
# ---------------------------------------------------------------------------

def write_png(width: int, height: int, rgba: bytes) -> bytes:
    if len(rgba) != width * height * 4:
        raise ValueError("rgba buffer size mismatch")

    def chunk(tag: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(tag + data) & 0xFFFFFFFF
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", crc)

    raw = b"".join(b"\x00" + rgba[y * width * 4 : (y + 1) * width * 4] for y in range(height))
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b"")


def write_dib32(width: int, height: int, rgba: bytes) -> bytes:
    """32-bit BI_RGB DIB for ICO: BITMAPINFOHEADER + bottom-up BGRA XOR + AND mask."""
    header = struct.pack(
        "<IIIHHIIIIII",
        40,  # biSize
        width,
        height * 2,  # XOR + AND
        1,  # planes
        32,  # bitcount
        0,  # BI_RGB
        0,
        0,
        0,
        0,
        0,
    )
    xor = bytearray(width * height * 4)
    # bottom-up BGRA
    for y in range(height):
        src_y = height - 1 - y
        for x in range(width):
            i = (src_y * width + x) * 4
            o = (y * width + x) * 4
            r, g, b, a = rgba[i], rgba[i + 1], rgba[i + 2], rgba[i + 3]
            xor[o : o + 4] = bytes((b, g, r, a))
    # 1-bit AND mask, rows padded to 32 bits, bottom-up. Use 0 (opaque) and
    # let the alpha channel in the XOR bitmap do the work on modern Windows.
    row_bytes = ((width + 31) // 32) * 4
    and_mask = bytes(row_bytes * height)
    return header + bytes(xor) + and_mask


# ---------------------------------------------------------------------------
# Built-in logo rasterizer (mirrors assets/logo.svg viewBox 0 0 128 128)
# ---------------------------------------------------------------------------

def _lerp(a: float, b: float, t: float) -> float:
    return a + (b - a) * t


def _hex(c: str) -> tuple[float, float, float]:
    c = c.lstrip("#")
    return int(c[0:2], 16) / 255.0, int(c[2:4], 16) / 255.0, int(c[4:6], 16) / 255.0


def _sd_round_rect(px: float, py: float, x: float, y: float, w: float, h: float, r: float) -> float:
    cx = x + w * 0.5
    cy = y + h * 0.5
    hx = w * 0.5
    hy = h * 0.5
    r = min(r, hx, hy)
    dx = abs(px - cx) - (hx - r)
    dy = abs(py - cy) - (hy - r)
    ox = max(dx, 0.0)
    oy = max(dy, 0.0)
    return math.hypot(ox, oy) + min(max(dx, dy), 0.0) - r


def _sd_circle(px: float, py: float, cx: float, cy: float, r: float) -> float:
    return math.hypot(px - cx, py - cy) - r


def _dist_seg(px: float, py: float, ax: float, ay: float, bx: float, by: float) -> float:
    vx, vy = bx - ax, by - ay
    length2 = vx * vx + vy * vy
    if length2 <= 1e-12:
        return math.hypot(px - ax, py - ay)
    t = max(0.0, min(1.0, ((px - ax) * vx + (py - ay) * vy) / length2))
    return math.hypot(px - (ax + t * vx), py - (ay + t * vy))


def _cubic_points(p0, p1, p2, p3, n: int):
    pts = []
    for i in range(n + 1):
        t = i / n
        u = 1.0 - t
        x = u * u * u * p0[0] + 3 * u * u * t * p1[0] + 3 * u * t * t * p2[0] + t * t * t * p3[0]
        y = u * u * u * p0[1] + 3 * u * u * t * p1[1] + 3 * u * t * t * p2[1] + t * t * t * p3[1]
        pts.append((x, y))
    return pts


def _polyline_dist(px: float, py: float, pts) -> float:
    d = 1e9
    for i in range(len(pts) - 1):
        d = min(d, _dist_seg(px, py, pts[i][0], pts[i][1], pts[i + 1][0], pts[i + 1][1]))
    return d


def _coverage(sd: float, aa: float = 0.6) -> float:
    # 0 inside (negative sd), 1 outside. Return fill coverage 0..1.
    if sd >= aa:
        return 0.0
    if sd <= -aa:
        return 1.0
    # smooth step across the edge
    t = 0.5 - sd / (2.0 * aa)
    return max(0.0, min(1.0, t))


def _stroke_cov(dist: float, width: float, aa: float = 0.6) -> float:
    return _coverage(dist - width * 0.5, aa)


def _blend(dst, r, g, b, a, cov):
    alpha = max(0.0, min(1.0, a * cov))
    if alpha <= 0.0:
        return
    ia = 1.0 - alpha
    dst[0] = dst[0] * ia + r * alpha
    dst[1] = dst[1] * ia + g * alpha
    dst[2] = dst[2] * ia + b * alpha
    dst[3] = dst[3] * ia + alpha


def _bg_color(x: float, y: float) -> tuple[float, float, float]:
    # linear gradient 0,0 -> 100%,100% : #2563EB -> #0F172A
    t = max(0.0, min(1.0, ((x - 6) + (y - 6)) / (116 * 2)))
    c0 = _hex("2563EB")
    c1 = _hex("0F172A")
    return _lerp(c0[0], c1[0], t), _lerp(c0[1], c1[1], t), _lerp(c0[2], c1[2], t)


def _flow_color(t: float) -> tuple[float, float, float]:
    # #60A5FA -> #38BDF8 @55% -> #34D399
    t = max(0.0, min(1.0, t))
    c0 = _hex("60A5FA")
    c1 = _hex("38BDF8")
    c2 = _hex("34D399")
    if t <= 0.55:
        u = t / 0.55
        return _lerp(c0[0], c1[0], u), _lerp(c0[1], c1[1], u), _lerp(c0[2], c1[2], u)
    u = (t - 0.55) / 0.45
    return _lerp(c1[0], c2[0], u), _lerp(c1[1], c2[1], u), _lerp(c1[2], c2[2], u)


def render_logo_builtin(size: int) -> bytes:
    """Render the official logo at `size`x`size` into RGBA bytes."""
    # Super-sample small sizes for crisp edges.
    ssaa = 4 if size <= 48 else 2
    dim = size * ssaa
    scale = dim / 128.0
    # Precompute path polylines in pixel space (viewBox 128).
    def S(x, y=None):
        if y is None:
            return x * scale
        return (x * scale, y * scale)

    path_top_l = _cubic_points(S(30, 64), S(40, 64), S(42, 39), S(52, 39), 48)
    path_bot_l = _cubic_points(S(30, 64), S(40, 64), S(42, 89), S(52, 89), 48)
    path_mid_l = [S(30, 64), S(52, 64)]
    path_top_r = _cubic_points(S(76, 39), S(86, 39), S(88, 64), S(98, 64), 48)
    path_bot_r = _cubic_points(S(76, 89), S(86, 89), S(88, 64), S(98, 64), 48)
    path_mid_r = [S(76, 64), S(98, 64)]
    check = [S(96.8, 64), S(99.1, 66.4), S(103.6, 61.5)]

    # For 16px, slightly thicken strokes so the mark stays legible.
    stroke_boost = 1.15 if size <= 16 else 1.0

    px = [0.0, 0.0, 0.0, 0.0]
    out = bytearray(dim * dim * 4)
    aa = 0.7 * ssaa * (0.6 if size <= 16 else 0.75)

    for yi in range(dim):
        py = yi + 0.5
        # map back to viewBox for the badge gradient
        for xi in range(dim):
            pxv = xi + 0.5
            vx, vy = pxv / scale, py / scale
            px[0] = px[1] = px[2] = px[3] = 0.0

            # Badge fill
            sd = _sd_round_rect(pxv, py, S(6), S(6), S(116), S(116), S(28))
            cov = _coverage(sd, aa)
            if cov > 0:
                r, g, b = _bg_color(vx, vy)
                _blend(px, r, g, b, 1.0, cov)

            # Badge inner stroke
            inner = abs(_sd_round_rect(pxv, py, S(6.75), S(6.75), S(114.5), S(114.5), S(27.25))) - S(1.5) * 0.5
            cov = _coverage(inner, aa)
            if cov > 0:
                r, g, b = _hex("93C5FD")
                _blend(px, r, g, b, 0.22, cov)

            # Queue lane bars
            bars = (
                (52, 32, 0.14, "93C5FD", 0.45),
                (57, 57, 0.22, "38BDF8", 0.85),
                (82, 82, 0.14, "93C5FD", 0.45),
            )
            # Wait, y positions are 32, 57, 82 - I used first field wrong.
            for (by, fill_a, stroke_hex, stroke_a) in (
                (32, 0.14, "93C5FD", 0.45),
                (57, 0.22, "38BDF8", 0.85),
                (82, 0.14, "93C5FD", 0.45),
            ):
                sd = _sd_round_rect(pxv, py, S(52), S(by), S(24), S(14), S(4))
                cov = _coverage(sd, aa)
                if cov > 0:
                    _blend(px, 1.0, 1.0, 1.0, fill_a, cov)
                ring = abs(sd) - S(1.5) * 0.5
                cov = _coverage(ring, aa)
                if cov > 0:
                    r, g, b = _hex(stroke_hex)
                    _blend(px, r, g, b, stroke_a, cov)

            # Branch strokes (behind nodes)
            for pts, hexcol, width, alpha in (
                (path_top_l, "93C5FD", 3.2, 0.7),
                (path_bot_l, "93C5FD", 3.2, 0.7),
                (path_top_r, "6EE7B7", 3.2, 0.75),
                (path_bot_r, "6EE7B7", 3.2, 0.75),
            ):
                d = _polyline_dist(pxv, py, pts)
                cov = _stroke_cov(d, S(width) * stroke_boost, aa)
                if cov > 0:
                    r, g, b = _hex(hexcol)
                    _blend(px, r, g, b, alpha, cov)

            # Flow mid lines with gradient along x
            for pts, x0, x1, width in (
                (path_mid_l, 30.0, 52.0, 4.2),
                (path_mid_r, 76.0, 98.0, 4.2),
            ):
                d = _polyline_dist(pxv, py, pts)
                cov = _stroke_cov(d, S(width) * stroke_boost, aa)
                if cov > 0:
                    t = max(0.0, min(1.0, (vx - x0) / (x1 - x0)))
                    # map overall 0..1 across full left-to-right flow
                    if x0 < 60:
                        gt = t * 0.5
                    else:
                        gt = 0.5 + t * 0.5
                    r, g, b = _flow_color(gt)
                    _blend(px, r, g, b, 1.0, cov)

            # Entry packet node
            cov = _coverage(_sd_circle(pxv, py, S(28, 64)[0], S(28, 64)[1], S(7.5)), aa)
            if cov > 0:
                _blend(px, 1.0, 1.0, 1.0, 1.0, cov)
            cov = _coverage(_sd_circle(pxv, py, S(28, 64)[0], S(28, 64)[1], S(3.5)), aa)
            if cov > 0:
                r, g, b = _hex("2563EB")
                _blend(px, r, g, b, 1.0, cov)

            # Egress verified node
            cov = _coverage(_sd_circle(pxv, py, S(100, 64)[0], S(100, 64)[1], S(7.5)), aa)
            if cov > 0:
                r, g, b = _hex("34D399")
                _blend(px, r, g, b, 1.0, cov)
            d = _polyline_dist(pxv, py, check)
            cov = _stroke_cov(d, S(2.4) * stroke_boost, aa)
            if cov > 0:
                r, g, b = _hex("064E3B")
                _blend(px, r, g, b, 1.0, cov)

            o = (yi * dim + xi) * 4
            a = max(0.0, min(1.0, px[3]))
            if a > 0:
                # un-premultiply is not needed; we stored straight alpha via over
                out[o] = int(max(0.0, min(1.0, px[0])) * 255 + 0.5)
                out[o + 1] = int(max(0.0, min(1.0, px[1])) * 255 + 0.5)
                out[o + 2] = int(max(0.0, min(1.0, px[2])) * 255 + 0.5)
                out[o + 3] = int(a * 255 + 0.5)
            else:
                out[o : o + 4] = b"\x00\x00\x00\x00"

    if ssaa == 1:
        return bytes(out)

    # Box-filter downsample.
    dst = bytearray(size * size * 4)
    inv = 1.0 / (ssaa * ssaa)
    for y in range(size):
        for x in range(size):
            r = g = b = a = 0.0
            for dy in range(ssaa):
                for dx in range(ssaa):
                    i = ((y * ssaa + dy) * dim + (x * ssaa + dx)) * 4
                    r += out[i]
                    g += out[i + 1]
                    b += out[i + 2]
                    a += out[i + 3]
            o = (y * size + x) * 4
            dst[o] = int(r * inv + 0.5)
            dst[o + 1] = int(g * inv + 0.5)
            dst[o + 2] = int(b * inv + 0.5)
            dst[o + 3] = int(a * inv + 0.5)
    return bytes(dst)


def render_with_rsvg(svg_path: Path, size: int) -> bytes:
    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp:
        tmp_path = tmp.name
    try:
        cmd = [
            "rsvg-convert",
            "--width",
            str(size),
            "--height",
            str(size),
            "--keep-aspect-ratio",
            "--background-color",
            "none",
            "--output",
            tmp_path,
            str(svg_path),
        ]
        subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return _decode_png(Path(tmp_path).read_bytes())
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def _decode_png(data: bytes) -> bytes:
    """Minimal 8-bit RGBA PNG decoder (no interlacing)."""
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        raise ValueError("not a PNG")
    pos = 8
    width = height = None
    bit_depth = color_type = None
    idat = b""
    while pos + 8 <= len(data):
        length, = struct.unpack(">I", data[pos : pos + 4])
        tag = data[pos + 4 : pos + 8]
        chunk = data[pos + 8 : pos + 8 + length]
        pos += 12 + length
        if tag == b"IHDR":
            width, height, bit_depth, color_type, comp, filt, inter = struct.unpack(">IIBBBBB", chunk)
            if bit_depth != 8 or inter != 0 or comp != 0:
                raise ValueError("unsupported PNG")
        elif tag == b"IDAT":
            idat += chunk
        elif tag == b"IEND":
            break
    if width is None:
        raise ValueError("missing IHDR")
    raw = zlib.decompress(idat)
    # color types: 2=RGB, 6=RGBA, 3=indexed (reject), 4=gray+alpha
    if color_type == 6:
        bpp = 4
    elif color_type == 2:
        bpp = 3
    elif color_type == 4:
        bpp = 2
    elif color_type == 0:
        bpp = 1
    else:
        raise ValueError(f"unsupported PNG color type {color_type}")
    stride = width * bpp
    rows = []
    i = 0
    prev = bytes(stride)
    for _ in range(height):
        ftype = raw[i]
        row = bytearray(raw[i + 1 : i + 1 + stride])
        i += 1 + stride
        if ftype == 1:  # sub
            for x in range(stride):
                row[x] = (row[x] + (row[x - bpp] if x >= bpp else 0)) & 255
        elif ftype == 2:  # up
            for x in range(stride):
                row[x] = (row[x] + prev[x]) & 255
        elif ftype == 3:  # average
            for x in range(stride):
                a = row[x - bpp] if x >= bpp else 0
                row[x] = (row[x] + ((a + prev[x]) // 2)) & 255
        elif ftype == 4:  # paeth
            for x in range(stride):
                a = row[x - bpp] if x >= bpp else 0
                b = prev[x]
                c = prev[x - bpp] if x >= bpp else 0
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                pr = a if pa <= pb and pa <= pc else (b if pb <= pc else c)
                row[x] = (row[x] + pr) & 255
        elif ftype != 0:
            raise ValueError(f"unsupported PNG filter {ftype}")
        rows.append(bytes(row))
        prev = bytes(row)
    rgba = bytearray(width * height * 4)
    for y, row in enumerate(rows):
        for x in range(width):
            o = (y * width + x) * 4
            if color_type == 6:
                rgba[o : o + 4] = row[x * 4 : x * 4 + 4]
            elif color_type == 2:
                rgba[o : o + 3] = row[x * 3 : x * 3 + 3]
                rgba[o + 3] = 255
            elif color_type == 4:
                g = row[x * 2]
                a = row[x * 2 + 1]
                rgba[o : o + 4] = bytes((g, g, g, a))
            else:
                g = row[x]
                rgba[o : o + 4] = bytes((g, g, g, 255))
    return bytes(rgba)


def render_size(svg_path: Path, size: int, force_builtin: bool = False) -> bytes:
    if not force_builtin and shutil.which("rsvg-convert"):
        try:
            return render_with_rsvg(svg_path, size)
        except (subprocess.CalledProcessError, ValueError, OSError) as exc:
            print(f"warning: rsvg-convert failed for {size}px ({exc}); using built-in renderer", file=sys.stderr)
    return render_logo_builtin(size)


# ---------------------------------------------------------------------------
# ICO writer
# ---------------------------------------------------------------------------

def build_ico(frames: dict[int, bytes]) -> bytes:
    # 16/32/48 -> 32-bit DIB; 256 -> PNG (required, DIB 256 is poorly supported)
    encoded: list[tuple[int, int, int, bytes]] = []
    for size in SIZES:
        rgba = frames[size]
        if size == 256:
            blob = write_png(size, size, rgba)
            bpp = 32
        else:
            blob = write_dib32(size, size, rgba)
            bpp = 32
        encoded.append((size, bpp, 1, blob))

    count = len(encoded)
    header = struct.pack("<HHH", 0, 1, count)
    offset = 6 + 16 * count
    entries = b""
    blobs = b""
    for size, bpp, planes, blob in encoded:
        w = 0 if size >= 256 else size
        h = 0 if size >= 256 else size
        entries += struct.pack("<BBBBHHII", w, h, 0, 0, planes, bpp, len(blob), offset)
        blobs += blob
        offset += len(blob)
    return header + entries + blobs


def parse_ico(data: bytes) -> list[dict]:
    if len(data) < 6:
        raise ValueError("ICO too short")
    reserved, typ, count = struct.unpack("<HHH", data[:6])
    if reserved != 0 or typ != 1 or count == 0:
        raise ValueError(f"invalid ICO header reserved={reserved} type={typ} count={count}")
    frames = []
    for i in range(count):
        off = 6 + 16 * i
        w, h, colors, reserved2, planes, bpp, size, image_off = struct.unpack("<BBBBHHII", data[off : off + 16])
        if reserved2 != 0:
            raise ValueError("invalid ICONDIRENTRY reserved")
        if image_off + size > len(data):
            raise ValueError("ICONDIRENTRY points past end of file")
        blob = data[image_off : image_off + size]
        kind = "png" if blob.startswith(b"\x89PNG") else "dib"
        width = 256 if w == 0 else w
        height = 256 if h == 0 else h
        if kind == "dib":
            bi_size, bi_w, bi_h, bi_planes, bi_bpp = struct.unpack("<IIIHH", blob[:16])
            if bi_size < 40 or bi_w <= 0:
                raise ValueError("invalid DIB in ICO")
            width = bi_w
            height = bi_h // 2 if bi_h >= 2 else bi_h
            planes, bpp = bi_planes, bi_bpp
        frames.append(
            {
                "width": width,
                "height": height,
                "bpp": bpp,
                "planes": planes,
                "bytes": size,
                "kind": kind,
            }
        )
    return frames


def verify_ico(path: Path) -> list[dict]:
    data = path.read_bytes()
    frames = parse_ico(data)
    sizes = {(f["width"], f["height"]) for f in frames}
    needed = {(16, 16), (32, 32), (48, 48), (256, 256)}
    missing = needed - sizes
    if missing:
        raise ValueError(f"ICO missing sizes: {sorted(missing)}")
    if not any(f["kind"] == "png" and f["width"] == 256 for f in frames):
        raise ValueError("256x256 frame must be PNG")
    return frames


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate PktPath Studio .ico")
    parser.add_argument("--root", type=Path, default=None, help="repository root")
    parser.add_argument("--output", type=Path, default=None, help="output .ico path")
    parser.add_argument("--builtin-only", action="store_true", help="do not call rsvg-convert")
    parser.add_argument("--verify", type=Path, default=None, help="only verify an existing .ico")
    args = parser.parse_args()

    if args.verify:
        frames = verify_ico(args.verify)
        for f in frames:
            print(f"  {f['width']}x{f['height']} {f['kind']} {f['bpp']}bpp {f['bytes']} bytes")
        print(f"OK: {args.verify} ({len(frames)} frames)")
        return 0

    root = args.root.resolve() if args.root else repo_root_from_here()
    svg = find_logo_svg(root)
    out = args.output if args.output else root / "packaging" / "windows" / "assets" / "pktpath-studio.ico"
    out.parent.mkdir(parents=True, exist_ok=True)

    frames = {}
    for size in SIZES:
        print(f"rendering {size}x{size} from {svg}...")
        frames[size] = render_size(svg, size, force_builtin=args.builtin_only)
        if len(frames[size]) != size * size * 4:
            raise RuntimeError(f"bad frame buffer for {size}")

    data = build_ico(frames)
    out.write_bytes(data)
    parsed = verify_ico(out)
    print(f"wrote {out} ({len(data)} bytes)")
    for f in parsed:
        print(f"  {f['width']}x{f['height']} {f['kind']} {f['bpp']}bpp {f['bytes']} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
