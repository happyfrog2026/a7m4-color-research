"""Portable, offline synthetic previews for the four ST-based research slots.

This module neither reads Sony image banks nor edits firmware. It creates its
own numbered frame, star and bitmap lettering. Geometry and mapping facts come
from the local research references listed in ``SOURCE_REFERENCES``; none of
their image pixels, fonts, compression code or executable adapters are copied.
The new code and primitive bitmap glyphs are covered by the repository MIT
license. Pillow is loaded only for a caller's PNG or explicitly supplied font.

``build_icons`` accepts ``{"schema": "a7m4-icons/1", "slots": [
{"slot": 1, "text": "po"}]}``. Slots are unique integers 1..4; a subset is
allowed. A slot may instead supply ``png`` and an optional descriptive ``name``.
PNG artwork is fitted inside a 26x17 glyph box, retaining its color/alpha except
that selected-list artwork is tinted orange. An optional top-level ``font`` is
``{"path": "owned.ttf", "size": 16}``; the chosen text must fit the glyph box.
Relative input paths resolve against ``config_dir`` (or the current directory).
Inputs and all rendered files are checked before a new output folder is made.
"""

from __future__ import annotations

import hashlib
import html
import json
import os
from pathlib import Path
import struct
from typing import Any
import zlib

WIDTH, HEIGHT, STRIDE = 70, 35, 80
VARIANTS = ("23", "32")
NORMAL_INDICES = (0x6C5, 0x6C6, 0x6C7, 0x6C8)
SELECTED_INDICES = (0x8EF, 0x8FC, 0x909, 0x916)
INSTALLED_NAMES = ("po", "po", "po", "m9")
ORANGE = (0xDD, 0x66, 0x33, 255)  # Native selected foreground nibble palette D63.
SOURCE_REFERENCES = (
    "reports/m4-internal-packaging-handoff-20261026.html",
    "local/m4-look-names-20261026/menu-icons-assets/build_assets.py",
    "local/m4-look-names-20261025/playback-display-port/build_images.py",
    "local/m4-look-names-20261025/playback-display-port/playback.S",
    "local/m4-look-names-20261025/ap-port/build_candidate.py",
)

# Original 5x7 bitmap letters, expressed as rows rather than a bundled font file.
_ROWS = {
    "A": "01110/10001/10001/11111/10001/10001/10001",
    "B": "11110/10001/10001/11110/10001/10001/11110",
    "C": "01111/10000/10000/10000/10000/10000/01111",
    "D": "11110/10001/10001/10001/10001/10001/11110",
    "E": "11111/10000/10000/11110/10000/10000/11111",
    "F": "11111/10000/10000/11110/10000/10000/10000",
    "G": "01111/10000/10000/10111/10001/10001/01110",
    "H": "10001/10001/10001/11111/10001/10001/10001",
    "I": "11111/00100/00100/00100/00100/00100/11111",
    "J": "00111/00010/00010/00010/10010/10010/01100",
    "K": "10001/10010/10100/11000/10100/10010/10001",
    "L": "10000/10000/10000/10000/10000/10000/11111",
    "M": "10001/11011/10101/10101/10001/10001/10001",
    "N": "10001/11001/11001/10101/10011/10011/10001",
    "O": "01110/10001/10001/10001/10001/10001/01110",
    "P": "11110/10001/10001/11110/10000/10000/10000",
    "Q": "01110/10001/10001/10001/10101/10010/01101",
    "R": "11110/10001/10001/11110/10100/10010/10001",
    "S": "01111/10000/10000/01110/00001/00001/11110",
    "T": "11111/00100/00100/00100/00100/00100/00100",
    "U": "10001/10001/10001/10001/10001/10001/01110",
    "V": "10001/10001/10001/10001/10001/01010/00100",
    "W": "10001/10001/10001/10101/10101/10101/01010",
    "X": "10001/10001/01010/00100/01010/10001/10001",
    "Y": "10001/10001/01010/00100/00100/00100/00100",
    "Z": "11111/00001/00010/00100/01000/10000/11111",
    "a": "00000/00000/01110/00001/01111/10001/01111",
    "b": "10000/10000/11110/10001/10001/10001/11110",
    "c": "00000/00000/01111/10000/10000/10000/01111",
    "d": "00001/00001/01111/10001/10001/10001/01111",
    "e": "00000/00000/01110/10001/11111/10000/01111",
    "f": "00110/01001/01000/11100/01000/01000/01000",
    "g": "00000/01111/10001/10001/01111/00001/11110",
    "h": "10000/10000/11110/10001/10001/10001/10001",
    "i": "00100/00000/01100/00100/00100/00100/01110",
    "j": "00010/00000/00110/00010/00010/10010/01100",
    "k": "10000/10000/10010/10100/11000/10100/10010",
    "l": "01100/00100/00100/00100/00100/00100/01110",
    "m": "00000/00000/11010/10101/10101/10101/10101",
    "n": "00000/00000/11110/10001/10001/10001/10001",
    "o": "00000/00000/01110/10001/10001/10001/01110",
    "p": "00000/11110/10001/10001/11110/10000/10000",
    "q": "00000/01111/10001/10001/01111/00001/00001",
    "r": "00000/00000/10110/11001/10000/10000/10000",
    "s": "00000/00000/01111/10000/01110/00001/11110",
    "t": "01000/01000/11100/01000/01000/01001/00110",
    "u": "00000/00000/10001/10001/10001/10011/01101",
    "v": "00000/00000/10001/10001/10001/01010/00100",
    "w": "00000/00000/10001/10001/10101/10101/01010",
    "x": "00000/00000/10001/01010/00100/01010/10001",
    "y": "00000/10001/10001/10001/01111/00001/11110",
    "z": "00000/00000/11111/00010/00100/01000/11111",
    "0": "01110/10001/10011/10101/11001/10001/01110",
    "1": "00100/01100/00100/00100/00100/00100/01110",
    "2": "01110/10001/00001/00010/00100/01000/11111",
    "3": "11110/00001/00001/01110/00001/00001/11110",
    "4": "00010/00110/01010/10010/11111/00010/00010",
    "5": "11111/10000/10000/11110/00001/00001/11110",
    "6": "01110/10000/10000/11110/10001/10001/01110",
    "7": "11111/00001/00010/00100/00100/00100/00100",
    "8": "01110/10001/10001/01110/10001/10001/01110",
    "9": "01110/10001/10001/01111/00001/00001/01110",
    "-": "00000/00000/00000/11111/00000/00000/00000",
    "_": "00000/00000/00000/00000/00000/00000/11111",
    ".": "00000/00000/00000/00000/00000/00110/00110",
    "+": "00000/00100/00100/11111/00100/00100/00000",
    " ": "00000/00000/00000/00000/00000/00000/00000",
}


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def encode_rgba4444(rgba: bytes, *, width: int = WIDTH, height: int = HEIGHT,
                    stride: int = STRIDE) -> bytes:
    """Quantize visible RGBA8 pixels to little-endian RGBA4444, zero padding.

    Each word has R in bits 15..12, G 11..8, B 7..4 and A 3..0. Row stride is
    measured in pixels; the 70x35/80 layout occupies exactly 5,600 bytes.
    """
    if any(type(v) is not int or v < 1 for v in (width, height, stride)) or stride < width:
        raise ValueError("Positive dimensions and stride >= width are required")
    if not isinstance(rgba, bytes) or len(rgba) != width * height * 4:
        raise ValueError("RGBA8 byte length differs from visible dimensions")
    result = bytearray(stride * height * 2)
    for y in range(height):
        for x in range(width):
            offset = (y * width + x) * 4
            r, g, b, a = ((c * 15 + 127) // 255 for c in rgba[offset:offset + 4])
            struct.pack_into("<H", result, (y * stride + x) * 2,
                             r << 12 | g << 8 | b << 4 | a)
    return bytes(result)


def decode_rgba4444(raw: bytes, *, width: int = WIDTH, height: int = HEIGHT,
                    stride: int = STRIDE) -> bytes:
    """Return visible RGBA8 pixels; discard stride padding."""
    if any(type(v) is not int or v < 1 for v in (width, height, stride)) or stride < width:
        raise ValueError("Positive dimensions and stride >= width are required")
    if not isinstance(raw, bytes) or len(raw) != stride * height * 2:
        raise ValueError("RGBA4444 byte length differs from stride/dimensions")
    pixels = bytearray()
    for y in range(height):
        for x in range(width):
            word = struct.unpack_from("<H", raw, (y * stride + x) * 2)[0]
            pixels.extend(((word >> 12) * 17, (word >> 8 & 15) * 17,
                           (word >> 4 & 15) * 17, (word & 15) * 17))
    return bytes(pixels)


def _png(rgba: bytes) -> bytes:
    def chunk(kind: bytes, payload: bytes) -> bytes:
        return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", zlib.crc32(kind + payload))
    scanlines = b"".join(b"\0" + rgba[y * WIDTH * 4:(y + 1) * WIDTH * 4] for y in range(HEIGHT))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", WIDTH, HEIGHT, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(scanlines, 9)) + chunk(b"IEND", b""))


def _pillow():
    try:
        from PIL import Image, ImageDraw, ImageFont
    except ImportError as exc:
        raise ValueError("PNG/font input requires Pillow; install the optional image dependency") from exc
    return Image, ImageDraw, ImageFont


def _keys(value: Any, allowed: set[str], required: set[str], what: str) -> None:
    if not isinstance(value, dict) or set(value) - allowed or required - set(value):
        raise ValueError(f"Invalid {what} keys; allowed: {', '.join(sorted(allowed))}")


def _label(value: Any, what: str) -> str:
    if (not isinstance(value, str) or not value.strip() or len(value.encode("utf-8")) > 63
            or any(not c.isprintable() for c in value)):
        raise ValueError(f"{what} must be 1..63 UTF-8 bytes of printable text")
    return value


def _input_path(value: Any, base: Path, what: str) -> Path:
    if not isinstance(value, str) or not value or "\0" in value:
        raise ValueError(f"{what} requires a file path")
    path = Path(value)
    if not path.is_absolute():
        path = base / path
    if not path.is_file():
        raise ValueError(f"{what} is not a readable regular file: {path}")
    return path


def _bitmap(text: str) -> bytes:
    if len(text) > 4 or any(c not in _ROWS for c in text):
        raise ValueError("Built-in glyphs support 1..4 ASCII letters, digits, space or -_.+; supply an explicit font or PNG")
    scale = min(2, 26 // (6 * len(text) - 1), 17 // 7)
    width, height = (6 * len(text) - 1) * scale, 7 * scale
    pixels = bytearray(26 * 17 * 4)
    x0, y0 = (26 - width) // 2, (17 - height) // 2
    for i, char in enumerate(text):
        for y, row in enumerate(_ROWS[char].split("/")):
            for x, bit in enumerate(row):
                if bit == "1":
                    for sy in range(scale):
                        for sx in range(scale):
                            at = ((y0 + y * scale + sy) * 26 + x0 + (i * 6 + x) * scale + sx) * 4
                            pixels[at:at + 4] = b"\xff\xff\xff\xff"
    return bytes(pixels)


def _font_glyph(text: str, path: Path, size: int) -> bytes:
    Image, ImageDraw, ImageFont = _pillow()
    try:
        font = ImageFont.truetype(str(path), size * 4)
        missing = font.getmask(chr(0x10FFFF))
        missing_signature = (missing.size, bytes(missing))
        for char in text:
            mask = font.getmask(char)
            if not char.isspace() and (mask.size, bytes(mask)) == missing_signature:
                raise ValueError(f"The supplied font has no glyph for {char!r}")
        box = font.getbbox(text)
        width, height = box[2] - box[0], box[3] - box[1]
        if not width or not height or width > 26 * 4 or height > 17 * 4:
            raise ValueError("Text at the explicit font size does not fit the 26x17 glyph box")
        image = Image.new("RGBA", (26 * 4, 17 * 4))
        ImageDraw.Draw(image).text(((26 * 4 - width) // 2 - box[0], (17 * 4 - height) // 2 - box[1]),
                                  text, font=font, fill=(255, 255, 255, 255))
        return image.resize((26, 17), Image.Resampling.LANCZOS).tobytes()
    except (OSError, TypeError) as exc:
        raise ValueError(f"Cannot render the supplied font: {path.name}") from exc


def _png_glyph(path: Path) -> bytes:
    Image, _, _ = _pillow()
    try:
        with Image.open(path) as opened:
            if opened.format != "PNG" or getattr(opened, "n_frames", 1) != 1:
                raise ValueError("Artwork must be a single-frame PNG")
            if not (1 <= opened.width <= 2048 and 1 <= opened.height <= 2048):
                raise ValueError("PNG dimensions must be within 1..2048 pixels")
            image = opened.convert("RGBA")
        image.thumbnail((26, 17), Image.Resampling.LANCZOS)
        canvas = Image.new("RGBA", (26, 17))
        canvas.paste(image, ((26 - image.width) // 2, (17 - image.height) // 2))
        return canvas.tobytes()
    except OSError as exc:
        raise ValueError(f"Cannot decode supplied PNG: {path.name}") from exc


def _render(slot: int, glyph: bytes, *, selected: bool, menu: bool) -> bytes:
    pixels = bytearray(WIDTH * HEIGHT * 4)
    foreground = ORANGE if selected else (255, 255, 255, 255)

    def dot(x: int, y: int, color: tuple[int, int, int, int]) -> None:
        if 0 <= x < WIDTH and 0 <= y < HEIGHT:
            at = (y * WIDTH + x) * 4
            pixels[at:at + 4] = bytes(color)

    for x in range(3, 67):
        dot(x, 4, foreground)
        dot(x, 31, foreground)
    for y in range(5, 31):
        dot(2, y, foreground)
        dot(67, y, foreground)
    for y, row in enumerate(_ROWS[str(slot)].split("/")):
        for x, bit in enumerate(row):
            if bit == "1":
                dot(6 + x, 14 + y, foreground)
    for dx, dy in ((0, -2), (0, -1), (-2, 0), (-1, 0), (0, 0), (1, 0), (2, 0), (0, 1), (0, 2)):
        dot(59 + dx, 9 + dy, foreground)
    x0 = 27 if menu else 22
    for y in range(17):
        for x in range(26):
            at = (y * 26 + x) * 4
            r, g, b, a = glyph[at:at + 4]
            if a:
                if selected:
                    # Match the source rule for grayscale; colored PNGs use luminance.
                    gray = (r * 299 + g * 587 + b * 114 + 500) // 1000
                    r, g, b = ((gray * c + 127) // 255 for c in foreground[:3])
                dot(x0 + x, 11 + y, (r, g, b, a))
    return bytes(pixels)


def mapping_reference(slot: int) -> dict[str, Any]:
    """Describe the observed adapter; this does not allocate a new image ID."""
    if type(slot) is not int or slot not in range(1, 5):
        raise ValueError("Only ST-based slots 1..4 have a recorded mapping")
    playback = 0x1E98 if slot < 4 else 0x1E99
    return {
        "slot": slot, "menu_normal_index": NORMAL_INDICES[slot - 1],
        "menu_selected_index": SELECTED_INDICES[slot - 1],
        "title_resource_id": 0x0200ABE2 + slot - 1,
        "photo_identity": 248 + slot,
        "installed_playback_asset_index": playback,
        "installed_playback_public_image_id": 0x02000000 + playback,
        "installed_label": INSTALLED_NAMES[slot - 1],
        "planned_playback_asset_index": None,
        "mapping_is_reference_only": True,
    }


def build_icons(config: dict, output: Path, config_dir: Path | None = None) -> dict:
    """Create raw/PNG previews, a manifest and a gallery in a new directory.

    The returned manifest explicitly distinguishes current adapter references
    from requested synthetic content. It is never a bank mutation or install
    plan. No device/network code is imported or called. Existing output paths,
    including empty folders and symlinks, are rejected.
    """
    _keys(config, {"schema", "slots", "font"}, {"schema", "slots"}, "icon configuration")
    if config["schema"] != "a7m4-icons/1":
        raise ValueError("Expected icon configuration schema a7m4-icons/1")
    slots = config["slots"]
    if not isinstance(slots, list) or not 1 <= len(slots) <= 4:
        raise ValueError("slots must contain 1..4 unique slot entries")
    output = Path(output)
    if output.exists() or output.is_symlink():
        raise ValueError("A new output directory is required; refusing to overwrite")
    if not output.parent.is_dir():
        raise ValueError("The output parent directory must already exist")
    base = Path(config_dir) if config_dir is not None else Path.cwd()
    font_path, font_size, font_record = None, None, None
    if "font" in config:
        font = config["font"]
        _keys(font, {"path", "size"}, {"path", "size"}, "font")
        if type(font["size"]) is not int or not 1 <= font["size"] <= 64:
            raise ValueError("font size must be an integer in 1..64")
        font_path, font_size = _input_path(font["path"], base, "font"), font["size"]
        font_record = {"name": font_path.name, "sha256": _sha(font_path.read_bytes()),
                       "size": font_size, "font_file_distributed": False}
    prepared, seen = [], set()
    for row in slots:
        _keys(row, {"slot", "text", "png", "name"}, {"slot"}, "slot")
        slot = row["slot"]
        if type(slot) is not int or slot not in range(1, 5) or slot in seen:
            raise ValueError("Slots must be unique integers 1..4")
        seen.add(slot)
        if ("text" in row) == ("png" in row) or ("name" in row and "png" not in row):
            raise ValueError("Each slot needs either text or png; name is only valid with png")
        if "text" in row:
            name = _label(row["text"], "text")
            glyph = _font_glyph(name, font_path, font_size) if font_path else _bitmap(name)
            source = {"kind": "text", "text": name,
                      "renderer": "explicit-font" if font_path else "original-bitmap-5x7"}
        else:
            path = _input_path(row["png"], base, "PNG")
            name = _label(row.get("name", f"PNG {slot}"), "name")
            glyph = _png_glyph(path)
            source = {"kind": "user-png", "name": path.name,
                      "sha256": _sha(path.read_bytes()), "source_file_distributed": False}
        prepared.append((slot, name, glyph, source))
    prepared.sort(key=lambda item: item[0])
    artifacts: dict[str, bytes] = {}
    assets, slot_records = [], []
    for slot, name, glyph, source in prepared:
        slot_records.append({"slot": slot, "name": name, "input": source,
                             "reference": mapping_reference(slot),
                             "requested_content_requires_adapter_review": True})
        for variant in VARIANTS:
            for route in ("title", "list-normal", "list-selected", "playback"):
                rgba = _render(slot, glyph, selected=route == "list-selected", menu=route.startswith("list-"))
                raw = encode_rgba4444(rgba)
                # The PNG shows the quantized bytes, so preview and raw agree.
                png = _png(decode_rgba4444(raw))
                stem = f"bank-{variant}-slot-{slot}-{route}"
                raw_name, png_name = stem + ".rgba4444.bin", stem + ".png"
                artifacts[raw_name], artifacts[png_name] = raw, png
                assets.append({"slot": slot, "name": name, "bank_variant": variant,
                               "route": route, "png": png_name, "raw": raw_name,
                               "raw_bytes": len(raw), "raw_sha256": _sha(raw),
                               "png_sha256": _sha(png), "synthetic_preview": True})
    manifest = {
        "schema": "a7m4-icons-preview/1", "status": "SYNTHETIC_PREVIEW_NOT_INSTALLABLE",
        "model_scope": "ILCE-7M4 / 6.02 / ST-based slots 1..4",
        "camera_IO": False, "network_IO": False, "bank_modification": False,
        "generated_assets_are_installed": False,
        "geometry": {"width": WIDTH, "height": HEIGHT, "stride_pixels": STRIDE,
                     "format": "RGBA4444-le", "padding": "transparent zero words"},
        "bank_variants": list(VARIANTS), "font": font_record,
        "slots": slot_records, "assets": assets, "gallery": "gallery.html",
        "source_references": list(SOURCE_REFERENCES),
        "artwork_origin": "Original synthetic frame, slot digits, star and bitmap glyphs; no Sony pixels",
        "license": "Repository MIT for generated synthetic artwork/code; supplied PNG/font retains its owner's license",
        "limitations": [
            "Title rendering is a schematic text preview: real titles use language resources and the AP title getter, not an image bank icon.",
            "Variants 23/32 are separately named; runtime bank selection is not proven and they must not be called horizontal/vertical.",
            "The installed AP maps photo identities 249..251 to shared po asset 0x1e98 and identity 252 to m9 asset 0x1e99. Different desired content needs a separately reviewed allocation/translator adapter.",
            "Existing/new-photo identity propagation, AP routing, both banks and multilingual strings must be adapted together; old photos cannot reliably identify new slots.",
            "No compressed payload, Sony bank bytes, executable patch, apply action or inverse installation plan is generated.",
        ],
    }
    routes = (("title", "标题"), ("list-normal", "普通"),
              ("list-selected", "橙色选中"), ("playback", "照片回放"))
    by_asset = {(asset["bank_variant"], asset["slot"], asset["route"]): asset for asset in assets}

    def preview_table(variant: str) -> str:
        rows = []
        for record in slot_records:
            slot, name = record["slot"], record["name"]
            cells = []
            for route, label in routes:
                asset = by_asset[variant, slot, route]
                description = html.escape(f"自定义 {slot} · {name} · {label}", quote=True)
                cells.append('<td><img width="140" height="70" alt="' + description
                             + '" src="' + asset["png"] + '"></td>')
            rows.append('<tr><th scope="row">自定义 ' + str(slot) + '<span class="slot-name">'
                        + html.escape(name) + '</span></th>' + ''.join(cells) + '</tr>')
        headings = ''.join('<th scope="col">' + label + '</th>' for _, label in routes)
        return ('<div class="table-wrap"><table><thead><tr><th scope="col">槽位</th>'
                + headings + '</tr></thead><tbody>' + ''.join(rows) + '</tbody></table></div>')

    technical_limits = ''.join('<li>' + html.escape(limit) + '</li>' for limit in manifest["limitations"])
    gallery = ('<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
               '<title>合成图标预览</title><style>body{background:#25282c;color:#eee;font:14px/1.5 system-ui,-apple-system,sans-serif;margin:16px}'
               'h1{font-size:22px;line-height:1.3;margin:0 0 4px}.intro{color:#bdc3cc;margin:0 0 12px}'
               '.table-wrap{overflow-x:auto}table{border-collapse:separate;border-spacing:6px;width:100%;min-width:590px;table-layout:fixed}'
               'thead th{font-size:12px;font-weight:500;color:#bdc3cc;padding:0 0 3px}'
               'th:first-child{width:70px;text-align:left}tbody th{font-size:12px;font-weight:500}'
               '.slot-name{display:block;color:#fff;font-size:15px;font-weight:600;overflow-wrap:anywhere}'
               'td{background:#33373d;border-radius:7px;padding:7px 0;text-align:center}'
               'img{image-rendering:pixelated;display:block;max-width:100%;height:auto;margin:auto}'
               'details{margin-top:12px;border-top:1px solid #464b53;padding-top:10px;color:#bdc3cc}'
               'summary{cursor:pointer;color:#d6dce5}details p,details li{font-size:12px}details h2{font-size:14px;margin:16px 0 8px}'
               'details li{margin:6px 0}a{color:#aee}</style>'
               '<h1>合成图标预览</h1><p class="intro">仅供预览，尚未安装到相机</p>'
               + preview_table("23")
               + '<details><summary>开发者映射与限制</summary>'
               '<p>SYNTHETIC PREVIEW — not installed. Original artwork; no Sony pixels or installation plan.</p>'
               '<p>主预览对应图形库 23，下方为图形库 32；两库的实际运行选择条件尚未证明。</p>'
               '<ul>' + technical_limits + '</ul>'
               '<p><a href="manifest.json">查看完整清单、映射与限制（JSON）</a></p>'
               '<h2>图形库 32</h2>' + preview_table("32") + '</details></html>')
    artifacts["gallery.html"] = gallery.encode("utf-8")
    artifacts["manifest.json"] = (json.dumps(manifest, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode("utf-8")
    try:
        output.mkdir(mode=0o700)
    except FileExistsError as exc:
        raise ValueError("A new output directory is required; refusing to overwrite") from exc
    for name, data in artifacts.items():
        fd = os.open(output / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
    return manifest
