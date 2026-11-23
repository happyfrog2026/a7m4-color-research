"""Native M4 bitmap assets and exact local two-bank replacement plans.

PNG files are decoded previews. The import material is RGBA4444-le encoded by
the native F0 codec and, for lists, registered in an exact source-bound UXC
bank. No device, network or deployment module is imported. Playback assets are
generated but their four independent routes remain HELD.

The F0 compressor and UXC layout handling adapt MIT-licensed C2 research code.
Its complete notice is retained in native-icon-templates.json. The 18 small
glyph-cleared Sony frames have separate, explicitly internal-only rights there.
Pillow is imported lazily; fonts are read locally and never copied to outputs.
"""
from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import re
import struct
from typing import Any
import zlib

from .offline import _regular_reader, load_manifest

WIDTH, HEIGHT, STRIDE, RAW_BYTES = 70, 35, 80, 5600
ROUTES = ("list-normal", "list-selected", "playback")
VARIANTS = ("23", "32")
NORMAL = (0x6C5, 0x6C6, 0x6C7, 0x6C8)
SELECTED = (0x8EF, 0x8FC, 0x909, 0x916)
_LENGTHS = tuple(range(3, 17)) + (32, 64)


def _need(condition: Any, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _keys(value: Any, allowed: set[str], required: set[str], what: str) -> None:
    _need(isinstance(value, dict) and required <= set(value) <= allowed, f"Invalid {what} fields")


def _read(path: Path, limit: int) -> bytes:
    with _regular_reader(path) as (stream, info):
        _need(0 < info.st_size <= limit, f"Local file size outside supported bounds: {path.name}")
        raw = stream.read(limit + 1)
        _need(len(raw) == info.st_size, "Local input size changed while reading")
    return raw


def _local_path(value: Any, base: Path) -> Path:
    _need(isinstance(value, (str, os.PathLike)), "A local file path is required")
    value = os.fspath(value)
    _need(isinstance(value, str) and value and "\0" not in value and "://" not in value,
          "A local file path without NUL or URL is required")
    path = Path(value)
    return path if path.is_absolute() else base / path


def _new_output(value: Any) -> Path:
    path = Path(value).absolute()
    _need(not path.exists() and not path.is_symlink(), "Output already exists; choose a new directory")
    _need(path.parent.is_dir(), "Output parent directory does not exist")
    return path


def _write(path: Path, raw: bytes | dict) -> None:
    if isinstance(raw, dict):
        raw = (json.dumps(raw, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)


def _template_data() -> dict:
    path = Path(__file__).with_name("data") / "native-icon-templates.json"
    return json.loads(_read(path, 256 * 1024))


def _unpack_templates(data: dict) -> dict[tuple[str, int | None, str], bytes]:
    _need(data.get("schema") == "a7m4-native-icon-templates/1", "Unknown native template schema")
    _need(data.get("rights", {}).get("holder") == "Sony" and
          data["rights"].get("status") == "internal-only", "Native template rights metadata differs")
    geometry = data.get("geometry", {})
    _need(all(geometry.get(k) == v for k, v in {
        "width": WIDTH, "height": HEIGHT, "stride": STRIDE,
        "format": "RGBA4444-le", "raw_bytes": RAW_BYTES,
        "glyph_width": 26, "glyph_height": 17}.items()), "Native template geometry differs")
    _need("Copyright (c) 2026 A7C II FL2/FL3 preview contributors" in
          data.get("codec_attribution", {}).get("license_text", ""), "C2 attribution is missing")
    result = {}
    for row in data.get("templates", []):
        key = (row.get("bank_variant"), row.get("slot"), row.get("route"))
        _need(key not in result and row.get("encoding") == "zlib-base64", "Duplicate or unsupported template")
        try:
            encoded = base64.b64decode(row["payload"], validate=True)
            decoder = zlib.decompressobj()
            raw = decoder.decompress(encoded, RAW_BYTES + 1)
            _need(decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail,
                  "Native template compressed bounds differ")
        except (KeyError, ValueError, zlib.error) as exc:
            raise ValueError("Invalid native template payload") from exc
        _need(len(raw) == row.get("raw_bytes") == RAW_BYTES and _sha(raw) == row.get("raw_sha256"),
              "Native template length or SHA-256 differs")
        result[key] = raw
    expected = {(v, s, r) for v in VARIANTS for s in range(1, 5) for r in ROUTES[:2]}
    expected |= {(v, None, "playback") for v in VARIANTS}
    _need(set(result) == expected, "Exactly sixteen list and two playback templates are required")
    return result


def check_templates() -> dict:
    """Verify the small local template payloads without fonts, banks or Pillow."""
    data = _template_data()
    templates = _unpack_templates(data)
    return {"schema": "a7m4-native-icon-template-check/1", "status": "PASS", "verified": True,
            "version": data["version"], "template_count": len(templates),
            "rights": deepcopy(data["rights"]), "geometry": deepcopy(data["geometry"]),
            "offline_only": True, "device_IO": False, "network_IO": False,
            "camera_io": False, "network_io": False, "device_execution_ready": False, "camera_tests": "HELD"}


def compress_native(raw: bytes) -> bytes:
    """Encode one 70x35/stride80 RGBA4444 bitmap using native F0 pages."""
    _need(isinstance(raw, bytes) and len(raw) == RAW_BYTES, "Native bitmap must contain exactly 5600 bytes")
    output = bytearray()
    for base in range(0, len(raw), 4096):
        data = raw[base:base + 4096]
        history: dict[bytes, int] = {}
        tokens = []
        at = 0
        while at < len(data):
            key = data[at:at + 3]
            prior = history.get(key)
            size = 0
            if len(key) == 3 and prior is not None and 0 < at - prior <= 4095:
                matched = 0
                while matched < min(64, len(data) - at) and data[prior + matched] == data[at + matched]:
                    matched += 1
                size = max((n for n in _LENGTHS if n <= matched), default=0)
            if size:
                distance = at - prior
                tokens.append((1, bytes([(_LENGTHS.index(size) << 4) | (distance >> 8), distance & 255])))
            else:
                size = 1
                tokens.append((0, data[at:at + 1]))
            for index in range(at, at + size):
                history[data[index:index + 3]] = index
            at += size
        tokens.append((1, b"\0\0"))
        output.append(0xF0)
        for start in range(0, len(tokens), 8):
            group = tokens[start:start + 8]
            output.append(sum(flag << bit for bit, (flag, _) in enumerate(group)))
            for _, payload in group:
                output.extend(payload)
    return bytes(output)


def decompress_native(encoded: bytes) -> bytes:
    """Decode exactly one bounded native bitmap; reject malformed/trailing pages."""
    _need(isinstance(encoded, bytes) and 0 < len(encoded) <= RAW_BYTES * 2, "Invalid native compressed length")
    output = bytearray()
    at = 0
    for expected in (4096, RAW_BYTES - 4096):
        _need(at < len(encoded) and encoded[at] == 0xF0, "Missing native F0 page header")
        at += 1
        page = bytearray()
        done = False
        while not done:
            _need(at < len(encoded), "Truncated native flags")
            flags = encoded[at]
            at += 1
            for bit in range(8):
                if flags >> bit & 1:
                    _need(at + 2 <= len(encoded), "Truncated native back-reference")
                    a, b = encoded[at:at + 2]
                    at += 2
                    if not (a or b):
                        _need(flags >> (bit + 1) == 0, "Nonzero unused native flag bits")
                        done = True
                        break
                    distance, count = (a & 15) * 256 + b, _LENGTHS[a >> 4]
                    _need(0 < distance <= len(page) and len(page) + count <= expected,
                          "Invalid native back-reference or page bounds")
                    for _ in range(count):
                        page.append(page[-distance])
                else:
                    _need(at < len(encoded) and len(page) < expected, "Truncated native literal or page overflow")
                    page.append(encoded[at])
                    at += 1
        _need(len(page) == expected, "Native decoded page length differs")
        output.extend(page)
    _need(at == len(encoded), "Trailing native compressed data")
    return bytes(output)


def _rgba(raw: bytes) -> bytes:
    return bytes(c for y in range(HEIGHT) for word in
                 struct.unpack_from("<80H", raw, y * STRIDE * 2)[:WIDTH]
                 for c in ((word >> 12) * 17, (word >> 8 & 15) * 17, (word >> 4 & 15) * 17, (word & 15) * 17))


def _png(raw: bytes) -> bytes:
    rgba = _rgba(raw)
    def chunk(kind: bytes, payload: bytes) -> bytes:
        return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", zlib.crc32(kind + payload))
    scan = b"".join(b"\0" + rgba[y * WIDTH * 4:(y + 1) * WIDTH * 4] for y in range(HEIGHT))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", WIDTH, HEIGHT, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(scan, 9)) + chunk(b"IEND", b""))


def _pillow():
    try:
        from PIL import Image, ImageDraw, ImageFilter, ImageFont
    except ImportError as exc:
        raise ValueError("Native text/PNG generation requires Pillow") from exc
    return Image, ImageDraw, ImageFilter, ImageFont


def _is_han(text: str) -> bool:
    return len(text) == 1 and any(lo <= ord(text) <= hi for lo, hi in
        ((0x3400, 0x4DBF), (0x4E00, 0x9FFF), (0x20000, 0x2EE5F), (0x30000, 0x323AF)))


def _text(text: Any) -> str:
    _need(isinstance(text, str) and (re.fullmatch(r"[A-Za-z0-9]{1,3}", text) is not None or _is_han(text)),
          "Text must be 1–3 ASCII letters/digits, preserving case, or one Han character")
    return text


def _font_path(explicit: Any, base: Path, han: bool) -> Path:
    if explicit is not None:
        return _local_path(explicit, base)
    names = (["STHeiti Medium.ttc", "STHeiti Light.ttc", "PingFang.ttc"] if han else
             ["Supplemental/Arial Narrow.ttf", "Supplemental/Arial.ttf", "Helvetica.ttc", "HelveticaNeue.ttc"])
    for name in names:
        path = Path("/System/Library/Fonts") / name
        if path.is_file():
            return path.resolve()
    raise ValueError("No suitable system font found; supply an explicit local font path")


def _text_glyph(text: str, path: Path) -> tuple[bytes, bytes, dict]:
    Image, ImageDraw, ImageFilter, ImageFont = _pillow()
    # Read/hash the actual font, but do not retain or copy its contents.
    digest = hashlib.sha256()
    with _regular_reader(path) as (stream, info):
        _need(0 < info.st_size <= 256 * 1024 * 1024, "Font file size outside supported bounds")
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    target = 17 if _is_han(text) else {1: 17, 2: 14, 3: 11}[len(text)]
    try:
        lo, hi = 1, 512
        chosen = None
        while lo <= hi:
            size = (lo + hi) // 2
            font = ImageFont.truetype(str(path), size)
            box = font.getbbox(text)
            if box[2] - box[0] <= 26 * 4 and box[3] - box[1] <= target * 4:
                chosen = (font, box, size)
                lo = size + 1
            else:
                hi = size - 1
        _need(chosen is not None, "Text cannot fit the native glyph box")
        font, box, size = chosen
        missing = font.getmask(chr(0x10FFFF))
        signature = missing.size, bytes(missing)
        for char in text:
            mask = font.getmask(char)
            _need((mask.size, bytes(mask)) != signature and any(bytes(mask)),
                  f"The selected font has no glyph for {char!r}")
        width, height = box[2] - box[0], box[3] - box[1]
        _need(width > 0 and height > 0, "Selected font produced an empty glyph")
        image = Image.new("L", (26 * 4, 17 * 4))
        ImageDraw.Draw(image).text(((26 * 4 - width) // 2 - box[0], (17 * 4 - height) // 2 - box[1]),
                                  text, font=font, fill=255)
        image = image.resize((26, 17), Image.Resampling.LANCZOS)
        outline = image.filter(ImageFilter.MaxFilter(3))
    except (OSError, TypeError) as exc:
        raise ValueError(f"Cannot render selected font: {path.name}") from exc
    return image.tobytes(), outline.tobytes(), {
        "name": path.name, "sha256": digest.hexdigest(), "face_index": 0,
        "high_resolution_size": size, "target_height": target,
        "high_resolution_bbox": list(box), "font_distributed": False}


def _paint(template: bytes, mask: bytes, outline: bytes, route: str) -> bytes:
    result = bytearray(template)
    origin = 22 if route == "playback" else 27
    palette = (13, 6, 3) if route == "list-selected" else (15, 15, 15)
    for y in range(17):
        for x in range(26):
            at = y * 26 + x
            a, white = min(15, (outline[at] + 8) // 17), min(15, (mask[at] + 8) // 17)
            if a:
                r, g, b = ((white * c + 7) // 15 for c in palette)
                word = r << 12 | g << 8 | b << 4 | max(a, white)
                struct.pack_into("<H", result, ((y + 11) * STRIDE + x + origin) * 2, word)
    return bytes(result)


def _caller_png(path: Path) -> tuple[bytes, dict]:
    Image, _, _, _ = _pillow()
    raw_file = _read(path, 20 * 1024 * 1024)
    import io
    try:
        with Image.open(io.BytesIO(raw_file)) as image:
            _need(image.format == "PNG" and image.size == (WIDTH, HEIGHT),
                  "Route PNG must be exactly 70×35 pixels; resize it explicitly before import")
            rgba = image.convert("RGBA").tobytes()
    except (OSError, Image.DecompressionBombError) as exc:
        raise ValueError("Cannot decode caller PNG") from exc
    result = bytearray(RAW_BYTES)
    for y in range(HEIGHT):
        for x in range(WIDTH):
            channels = [(c * 15 + 127) // 255 for c in rgba[(y * WIDTH + x) * 4:(y * WIDTH + x + 1) * 4]]
            r, g, b, a = channels
            struct.pack_into("<H", result, (y * STRIDE + x) * 2, r << 12 | g << 8 | b << 4 | a)
    return bytes(result), {"name": path.name, "sha256": _sha(raw_file)}


def generate_native_icons(config: dict, output: Path, config_dir: Path | None = None) -> dict:
    """Generate native payloads and previews from the same quantized pixels.

    Schema a7m4-native-icons/1: slots [{slot:1,text:'Po',pngs?:{route:path}}],
    optional font:path. Slots may be a subset of 1..4. Routes are list-normal,
    list-selected, playback. An override PNG is an exact 70x35 full canvas.
    """
    _keys(config, {"schema", "slots", "font"}, {"schema", "slots"}, "native icon config")
    _need(config["schema"] == "a7m4-native-icons/1", "Unknown native icon config schema")
    _need(isinstance(config["slots"], list) and 1 <= len(config["slots"]) <= 4, "Select one to four slots")
    base = Path(config_dir) if config_dir is not None else Path.cwd()
    out = _new_output(output)
    data = _template_data()
    templates = _unpack_templates(data)
    selected = set()
    rendered = []
    slots = []
    for row in config["slots"]:
        _keys(row, {"slot", "text", "pngs"}, {"slot", "text"}, "slot")
        slot, text = row["slot"], _text(row["text"])
        _need(type(slot) is int and 1 <= slot <= 4 and slot not in selected, "Slots must be unique integers 1..4")
        selected.add(slot)
        pngs = row.get("pngs", {})
        _keys(pngs, set(ROUTES), set(), "route PNG overrides")
        overrides = {route: _caller_png(_local_path(value, base)) for route, value in pngs.items()}
        if len(overrides) < len(ROUTES):
            mask, outline, font = _text_glyph(text, _font_path(config.get("font"), base, _is_han(text)))
        else:
            mask, outline, font = b"", b"", None
        slots.append({"slot": slot, "text": text, "font": font})
        for variant in VARIANTS:
            for route in ROUTES:
                caller = route in overrides
                if caller:
                    raw, source_png = overrides[route]
                else:
                    raw = _paint(templates[(variant, None if route == "playback" else slot, route)], mask, outline, route)
                    source_png = None
                compressed = compress_native(raw)
                decoded = decompress_native(compressed)
                _need(decoded == raw, "Native codec round-trip differs")
                png = _png(decoded)
                prefix = f"bank{variant}-slot{slot}-{route}"
                asset = {"slot": slot, "text": text, "bank_variant": variant, "route": route,
                         "png": prefix + ".png", "raw": prefix + ".rgba4444", "compressed": prefix + ".f0",
                         "png_sha256": _sha(png), "raw_sha256": _sha(raw), "compressed_sha256": _sha(compressed),
                         "compressed_bytes": len(compressed), "geometry": deepcopy(data["geometry"]),
                         "artwork_source": "caller-artwork" if caller else "native-frame-with-rendered-text",
                         "native_frame_preserved": not caller, "caller_png": source_png,
                         "preview_origin": "decoded-final-native-compressed-payload",
                         "codec_round_trip_exact": True,
                         "status": "HELD_FOUR_INDEPENDENT_PLAYBACK_ROUTES" if route == "playback" else "NATIVE_ASSET_GENERATED"}
                rendered.append((asset, raw, compressed, png))
    manifest = {"schema": "a7m4-native-icons-result/1", "status": "GENERATED_OFFLINE",
                "output_dir": str(out), "offline_only": True, "deployment_authorized": False,
                "device_execution_ready": False, "camera_io": False, "network_io": False,
                "camera_tests": "HELD", "template_version": data["version"],
                "rights": deepcopy(data["rights"]), "slots": sorted(slots, key=lambda r: r["slot"]),
                "assets": [r[0] for r in rendered], "font_files_distributed": False,
                "playback": {"status": "HELD", "reason": "Four independent playback asset registrations and AP routes are not implemented.",
                             "recorded_mapping": {"249": "0x1e98", "250": "0x1e98", "251": "0x1e98", "252": "0x1e99"}},
                "import_boundary": "PNG is preview only. F0/raw assets need registered bank records. Build a source-bound list bank plan separately; no device operation is provided."}
    out.mkdir(mode=0o700)
    for asset, raw, compressed, png in rendered:
        for key, value in (("raw", raw), ("compressed", compressed), ("png", png)):
            _write(out / asset[key], value)
    _write(out / "manifest.json", manifest)
    return manifest


def _inspect_bank(source: bytes) -> dict:
    _need(len(source) >= 16 and source[:8] == b"uxd\x07\0\0\0\0", "Unsupported UXC image bank header")
    kind, group, descriptor = struct.unpack_from("<HHI", source, 8)
    count = descriptor & 8191
    _need(kind == 8 and group == 0 and count == 7844 and
          descriptor == count | (((count + 1) & ~1) << 12), "Unsupported UXC image bank layout")
    base = 16 + ((descriptor >> 11) & 0x7FFC)
    _need(16 + 2 * count <= base < len(source), "UXC index outside bank")
    records = {}
    for index in range(count):
        pointer = struct.unpack_from("<H", source, 16 + 2 * index)[0]
        if pointer == 65535:
            continue
        at = base + 4 * pointer
        _need(base <= at and at + 12 <= len(source), "UXC metadata outside bank")
        rid, flags, width, height = struct.unpack_from("<IIHH", source, at)
        field = 32 if flags & 0x08000000 else 12
        _need(at + field + 8 <= len(source), "UXC payload reference outside bank")
        size, offset = struct.unpack_from("<II", source, at + field)
        start = at + 4 + offset
        _need(rid == 0x1A000000 + index and size > 0 and
              at + field + 8 <= start <= start + size <= len(source), "Invalid UXC record identity or payload bounds")
        records[index] = {"at": at, "field": field, "width": width, "height": height,
                          "flags": flags, "start": start, "size": size}
    return {"base": base, "count": count, "records": records}


def _profile_data() -> list[dict]:
    return _template_data()["profiles"]


def _project(value: Any) -> tuple[dict, Path]:
    if isinstance(value, dict):
        manifest = deepcopy(value)
        _need(isinstance(manifest.get("output_dir"), str), "Manifest dict requires its generated output_dir")
        base = Path(manifest["output_dir"])
    else:
        path = Path(value)
        _need(not path.is_symlink(), "Project input must not be a symbolic link")
        if path.is_dir():
            if not (path / "manifest.json").exists() and (path / "native-icons" / "manifest.json").is_file():
                path = path / "native-icons"
            _need(not path.is_symlink(), "Native icon project directory must not be a symbolic link")
            path = path / "manifest.json"
        manifest = load_manifest(path)
        base = path.parent
    _need(not base.is_symlink(), "Native icon project directory must not be a symbolic link")
    _need(manifest.get("schema") == "a7m4-native-icons-result/1", "Unsupported native icon project manifest")
    _need(isinstance(manifest.get("assets"), list) and 1 <= len(manifest["assets"]) <= 24,
          "Native icon project has no bounded assets")
    return manifest, base


def _asset_file(base: Path, value: Any) -> Path:
    _need(isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", value) is not None,
          "Asset paths must be simple project-relative filenames")
    return base / value


def _bank_delta(source: bytes, target: bytes, windows: list[dict], path: Path) -> dict:
    windows.sort(key=lambda w: w["offset"])
    end = 0
    ranges = []
    complement = hashlib.sha256()
    restored = bytearray(target)
    for row in windows:
        at = row["offset"]
        before, after = bytes.fromhex(row["before_hex"]), bytes.fromhex(row["after_hex"])
        _need(at >= end and len(before) == len(after) == 8 and source[at:at + 8] == before and
              target[at:at + 8] == after and source[end:at] == target[end:at], "Exact UXC windows or complement differ")
        if at > end:
            segment = source[end:at]
            ranges.append({"offset": end, "size": len(segment), "sha256": _sha(segment)})
            complement.update(segment)
        restored[at:at + 8] = before
        end = at + 8
    _need(source[end:] == target[end:len(source)], "Bank trailing complement differs")
    if end < len(source):
        segment = source[end:]
        ranges.append({"offset": end, "size": len(segment), "sha256": _sha(segment)})
        complement.update(segment)
    tail = target[len(source):]
    _need(restored[:len(source)] == source and restored[len(source):] == tail, "Retained-tail inverse differs")
    return {"schema": "a7m4-native-bank-content-plan/1", "offline_only": True,
            "deployment_authorized": False, "device_execution_ready": False,
            "source": {"path": str(path), "kind": "resource", "size": len(source), "sha256": _sha(source)},
            "target": {"size": len(target), "sha256": _sha(target)}, "windows": windows,
            "append": {"offset": len(source), "size": len(tail), "after_hex": tail.hex(), "sha256": _sha(tail)},
            "complement": {"verification": "whole-source-and-materialized-target-compared", "ranges": ranges,
                           "size": len(source) - sum(w["size"] for w in windows),
                           "sha256_concatenated_ranges": complement.hexdigest(), "coverage_bytes": len(source)},
            "inverse": {"source": {"size": len(target), "sha256": _sha(target)},
                        "windows": [{"offset": w["offset"], "before_hex": w["after_hex"], "after_hex": w["before_hex"]} for w in windows],
                        "truncate": False, "retain_tail": True,
                        "tail_identity": {"offset": len(source), "size": len(tail), "sha256": _sha(tail)},
                        "target": {"size": len(restored), "sha256": _sha(restored)},
                        "restored_original_prefix": {"size": len(source), "sha256": _sha(source)},
                        "full_original_file_restored": False,
                        "order": "Verify complete target and tail, restore only the exact 8-byte references, retain the entire appended tail. Never truncate the bank."},
            "original_encoded_payload_bytes_retained": True, "unselected_records_and_payloads_exact": True,
            "playback_records_and_payloads_exact": True}


def build_native_bank_plan(bank23: Path, bank32: Path, project_manifest_or_dir: Any, output: Path) -> dict:
    """Materialize two exact local UXC targets, changing selected list records.

    Both complete banks must form one registered stock/current pair. Playback
    is held. The inverse restores references while retaining every appended
    byte, and explicitly does not claim the original whole-file identity.
    """
    out = _new_output(output)
    trusted_rights = check_templates()["rights"]
    paths = {"23": _local_path(bank23, Path.cwd()), "32": _local_path(bank32, Path.cwd())}
    sources = {v: _read(paths[v], 16 * 1024 * 1024) for v in VARIANTS}
    identities = {v: {"size": len(b), "sha256": _sha(b)} for v, b in sources.items()}
    matches = [p for p in _profile_data() if p["banks"] == identities]
    _need(len(matches) == 1, "Both complete UXC banks must match one registered stock/current SHA-256 pair")
    manifest, project_dir = _project(project_manifest_or_dir)
    assets = {}
    for item in manifest["assets"]:
        _need(isinstance(item, dict), "Invalid native icon asset")
        slot, variant, route = item.get("slot"), item.get("bank_variant"), item.get("route")
        _need(type(slot) is int and 1 <= slot <= 4 and variant in VARIANTS and route in ROUTES,
              "Native icon asset mapping differs")
        key = variant, slot, route
        _need(key not in assets, "Duplicate native icon asset mapping")
        raw = _read(_asset_file(project_dir, item.get("raw")), RAW_BYTES)
        encoded = _read(_asset_file(project_dir, item.get("compressed")), RAW_BYTES * 2)
        png = _read(_asset_file(project_dir, item.get("png")), 1024 * 1024)
        _need(len(raw) == RAW_BYTES and _sha(raw) == item.get("raw_sha256") and
              _sha(encoded) == item.get("compressed_sha256") and _sha(png) == item.get("png_sha256"),
              "Native icon asset complete SHA-256 differs")
        _need(decompress_native(encoded) == raw and png == _png(raw), "Native compressed bitmap and PNG preview differ")
        assets[key] = encoded
    slots = {key[1] for key in assets}
    _need(set(assets) == {(v, s, r) for v in VARIANTS for s in slots for r in ROUTES},
          "Every selected slot requires both banks and all three native route assets")
    components, targets, appends = {}, {}, {}
    materialized = []
    for variant in VARIANTS:
        source = sources[variant]
        bank = _inspect_bank(source)
        target = bytearray(source)
        windows = []
        edited = set()
        for slot in sorted(slots):
            for route, indices in (("list-normal", NORMAL), ("list-selected", SELECTED)):
                index = indices[slot - 1]
                _need(index in bank["records"], "Native list image index is not registered")
                record = bank["records"][index]
                _need((record["width"], record["height"], record["flags"], record["field"]) == (70, 35, 0xC0000000, 12),
                      "Native list record geometry differs")
                encoded = assets[(variant, slot, route)]
                target.extend(bytes((-len(target)) % 4))
                at = len(target)
                target.extend(encoded)
                field = record["at"] + record["field"]
                before = source[field:field + 8]
                after = struct.pack("<II", len(encoded), at - record["at"] - 4)
                _need(before != after, "Native list reference unexpectedly unchanged")
                target[field:field + 8] = after
                windows.append({"offset": field, "size": 8, "before_hex": before.hex(), "after_hex": after.hex(),
                                "image_index": index, "slot": slot, "route": route,
                                "changed_bytes": sum(a != b for a, b in zip(before, after))})
                edited.add(index)
        target.extend(bytes((-len(target)) % 4))
        result = bytes(target)
        after_bank = _inspect_bank(result)
        _need(set(after_bank["records"]) == set(bank["records"]), "Native image registrations changed")
        for index, old in bank["records"].items():
            current = after_bank["records"][index]
            _need(source[old["start"]:old["start"] + old["size"]] == result[old["start"]:old["start"] + old["size"]],
                  "An original native payload was overwritten")
            if index not in edited:
                _need(old == current, "An unselected or playback record changed")
        name = f"image_00_{variant}_IPSX.uxc"
        plan = _bank_delta(source, result, windows, paths[variant])
        plan["changed_existing_bytes"] = sum(w["changed_bytes"] for w in windows)
        components[name] = plan
        targets[name] = f"image_00_{variant}_IPSX.target.uxc"
        appends[name] = f"image_00_{variant}_IPSX.append.bin"
        materialized.append((name, result))
    report = {"schema": "a7m4-native-bank-plan-result/1", "status": "PLANNED_OFFLINE_LISTS_ONLY",
              "output_dir": str(out), "matched_profile": matches[0]["id"], "selected_slots": sorted(slots),
              "offline_only": True, "deployment_authorized": False, "device_execution_ready": False,
              "camera_io": False, "network_io": False, "camera_tests": "HELD",
              "components": components, "target_paths": targets, "append_paths": appends,
              "rights": trusted_rights,
              "scope": "Only registered ST-base slot1–4 list-normal/list-selected payload references; AP/CP, ordinary ST, slots5/6, all old payload bytes and playback are preserved.",
              "playback": {"status": "HELD", "assets_generated": True, "bank_modified": False,
                           "reason": "Four independent playback registrations and AP routes are not implemented."},
              "inverse_policy": "Restore exact original references, retain appended tails; bank truncation is forbidden.",
              "space_budget": {"status": "PENDING_TRANSPORT_PREFLIGHT", "evaluated": False},
              "device_IO": False, "network_IO": False}
    out.mkdir(mode=0o700)
    for name, raw in materialized:
        _write(out / targets[name], raw)
        _write(out / appends[name], bytes.fromhex(components[name]["append"]["after_hex"]))
    _write(out / "bank-plan.json", report)
    return report
