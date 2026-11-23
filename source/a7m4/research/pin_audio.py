"""Offline PIN sound projects; independent of the legacy audio schema.

24 kHz is the production-domain assumption, not a measured camera rate. R066's
fixed PIN route has recorded acceptance; arbitrary new audio, the 80 ms layout
and a new 1/50 cutoff remain independent, untested camera candidates. This
module opens local regular WAV/project files only and has no deployment API.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import struct
from typing import Any

from .native_audio_codec import HEADROOM, decode_filter0, encode_filter0, encoded_size
from .offline import PlanError, _regular_reader, load_manifest

RATE = 24000
MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_INPUT_SECONDS = 10
MAX_SHUTTER_SECONDS = 3600
ROLES = ("ka", "sha", "kasha")
CAPACITY = {"ka": 256, "sha": 15424, "kasha": 17600}
OFFSETS = {"ka": 0, "sha": 77504, "kasha": 92928}
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")


def _need(condition: Any, message: str) -> None:
    if not condition:
        raise PlanError(message)


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _keys(value: Any, allowed: set[str], required: set[str], name: str) -> dict:
    _need(isinstance(value, dict) and required <= set(value) <= allowed, f"Invalid {name} fields")
    return value


def _number(value: Any, name: str, low: float, high: float) -> float:
    _need(type(value) in (int, float) and low <= value <= high and math.isfinite(value),
          f"{name} must be finite and within {low}..{high}")
    return float(value)


def _frames(seconds: float) -> int:
    return math.floor(seconds * RATE + .5)


def _path(value: Any, base: Path) -> Path:
    _need(isinstance(value, (str, os.PathLike)), "A local filesystem path is required")
    value = os.fspath(value)
    _need(isinstance(value, str) and value and "\0" not in value and "://" not in value,
          "A local path without NUL or URL is required")
    p = Path(value)
    return p if p.is_absolute() else base / p


def _read(path: Path, maximum: int) -> bytes:
    with _regular_reader(path) as (stream, info):
        _need(0 < info.st_size <= maximum, f"Local file exceeds its size limit or is empty: {path.name}")
        raw = stream.read(maximum + 1)
        _need(len(raw) == info.st_size, "Local file changed size while reading")
    return raw


def _new_directory(value: Any) -> Path:
    path = _path(value, Path.cwd()).absolute()
    _need(not path.exists() and not path.is_symlink(), "Choose a new sound project directory; existing outputs are preserved")
    _need(path.parent.is_dir(), "Sound project parent directory does not exist")
    return path


def _json(value: dict) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def _write_new(path: Path, raw: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    _need(_read(path, max(1, len(raw))) == raw, "Durable local sound output differs")


def _publish(directory: Path, files: dict[str, bytes]) -> None:
    # All signal/schema/budget checks finish before a directory is created.
    # Manifest is last. Failed writes remove only the newly created directory.
    try:
        directory.mkdir(mode=0o700)
    except FileExistsError as exc:
        raise PlanError("Sound output appeared during preparation; refusing to overwrite") from exc
    identity = directory.stat()
    try:
        for name, raw in files.items():
            _write_new(directory / name, raw)
    except BaseException:
        current = directory.lstat()
        if not directory.is_symlink() and (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino):
            shutil.rmtree(directory)
        raise


def _wav(samples: list[int]) -> bytes:
    pcm = struct.pack("<" + "h" * len(samples), *samples)
    return (b"RIFF" + struct.pack("<I", 36 + len(pcm)) + b"WAVEfmt " +
            struct.pack("<IHHIIHH", 16, 1, 1, RATE, RATE * 2, 2, 16) + b"data" + struct.pack("<I", len(pcm)) + pcm)


def _source_wav(raw: bytes) -> tuple[dict, list[float]]:
    _need(len(raw) >= 44 and raw[:4] == b"RIFF" and raw[8:12] == b"WAVE" and
          struct.unpack_from("<I", raw, 4)[0] + 8 == len(raw), "Use a complete little-endian RIFF/WAVE file")
    at, fmt, payload, chunks = 12, None, None, 0
    while at < len(raw):
        _need(at + 8 <= len(raw) and chunks < 4096, "Truncated or excessive WAV chunks")
        kind, size = struct.unpack_from("<4sI", raw, at)
        start, end = at + 8, at + 8 + size
        _need(end + (size & 1) <= len(raw), "WAV chunk exceeds the complete input")
        if kind == b"fmt ":
            _need(fmt is None and payload is None and size in (16, 18), "Use one ordinary WAV fmt chunk before data")
            if size == 18:
                _need(struct.unpack_from("<H", raw, start + 16)[0] == 0, "WAV format extensions are unsupported")
            fmt = struct.unpack_from("<HHIIHH", raw, start)
        elif kind == b"data":
            _need(fmt is not None and payload is None and size > 0, "Use one nonempty WAV data chunk after fmt")
            payload = memoryview(raw)[start:end]
        at, chunks = end + (size & 1), chunks + 1
    _need(fmt is not None and payload is not None, "WAV fmt/data pair is missing")
    encoding, channels, rate, byte_rate, align, bits = fmt
    _need(channels in (1, 2) and 8000 <= rate <= 192000, "WAV must have 1–2 channels at 8–192 kHz")
    _need((encoding == 1 and bits in (8, 16, 24, 32)) or (encoding == 3 and bits in (32, 64)),
          "Use PCM8/16/24/32 or finite IEEE float32/64 WAV; compressed/extensible WAV is unsupported")
    width = bits // 8
    _need(align == channels * width and byte_rate == rate * align and len(payload) % align == 0,
          "WAV frame alignment or byte rate differs")
    frames = len(payload) // align
    _need(0 < frames <= rate * MAX_INPUT_SECONDS, "Each source WAV must be nonempty and at most 10 seconds")
    mono = []
    for at in range(0, len(payload), align):
        value = 0.0
        for channel in range(channels):
            offset = at + channel * width
            if encoding == 3:
                sample = struct.unpack_from("<f" if bits == 32 else "<d", payload, offset)[0] * 32768
            else:
                sample = ((payload[offset] - 128) if width == 1 else
                          int.from_bytes(payload[offset:offset + width], "little", signed=True)) * (32768 / (1 << (bits - 1)))
            _need(math.isfinite(sample), "Source WAV contains a non-finite sample")
            value += sample / channels
        _need(math.isfinite(value), "WAV downmix overflowed")
        mono.append(value)
    return {"sample_rate": rate, "channels": channels, "bits_per_sample": bits,
            "encoding": "PCM" if encoding == 1 else "IEEE_FLOAT", "frames": frames,
            "duration_seconds": frames / rate}, mono


def _clip(config: Any, role: str, base: Path) -> tuple[list[float], dict]:
    cfg = _keys(config, {"path", "start_seconds", "end_seconds", "fade_in_ms", "fade_out_ms"}, {"path"}, role)
    path = _path(cfg["path"], base)
    raw = _read(path, MAX_INPUT_BYTES)
    meta, samples = _source_wav(raw)
    start = _number(cfg.get("start_seconds", 0), f"{role}.start_seconds", 0, meta["duration_seconds"])
    end = _number(cfg.get("end_seconds", meta["duration_seconds"]), f"{role}.end_seconds", 0, meta["duration_seconds"])
    first = math.floor(start * meta["sample_rate"] + .5)
    last = math.floor(end * meta["sample_rate"] + .5)
    _need(0 <= first < last <= len(samples), f"{role} trim must retain at least one complete source frame")
    samples = samples[first:last]
    count = max(1, math.floor(len(samples) * RATE / meta["sample_rate"] + .5))
    converted = []
    for index in range(count):
        lower, remainder = divmod(index * meta["sample_rate"], RATE)
        lower = min(lower, len(samples) - 1)
        upper = min(lower + 1, len(samples) - 1)
        converted.append(samples[lower] + (samples[upper] - samples[lower]) * remainder / RATE)
    fade_in = _frames(_number(cfg.get("fade_in_ms", 0), f"{role}.fade_in_ms", 0, 20) / 1000)
    fade_out = _frames(_number(cfg.get("fade_out_ms", 0), f"{role}.fade_out_ms", 0, 20) / 1000)
    _need(fade_in + fade_out <= count, f"{role} short fades must fit without overlapping or shortening the clip")
    for index in range(fade_in):
        converted[index] *= index / (fade_in - 1) if fade_in > 1 else 0
    for index in range(fade_out):
        converted[count - fade_out + index] *= (fade_out - 1 - index) / (fade_out - 1) if fade_out > 1 else 0
    return converted, {"source": {"filename": path.name, "bytes": len(raw), "sha256": _sha(raw), **meta},
                       "source_preserved": True, "trim_source_frames": [first, last], "trim_seconds": [start, end],
                       "prepared_samples": count, "fade_in_samples": fade_in, "fade_out_samples": fade_out,
                       "rights": "Original source rights retained; preparation grants no redistribution license"}


def _controls(config: dict) -> dict:
    recock = _keys(config.get("recock", {}), {"enabled", "gap_ms"}, set(), "recock")
    enabled = recock.get("enabled", "recock" in config["clips"])
    _need(type(enabled) is bool, "recock.enabled must be boolean")
    _need(not enabled or "recock" in config["clips"], "Enabled recock requires a local recock clip")
    gap = _number(recock.get("gap_ms", 40), "recock.gap_ms", 0, 80)
    cutoff = _keys(config.get("hybrid_cutoff", {}), {"denominator"}, set(), "hybrid_cutoff")
    denominator = _number(cutoff.get("denominator", 50), "hybrid_cutoff.denominator", 1, 1000000)
    synthesis = _keys(config.get("kasha_synthesis", {}),
                      {"link_pair_delay_to_cutoff", "pair_delay_seconds", "preserve_tails"}, set(), "kasha_synthesis")
    linked = synthesis.get("link_pair_delay_to_cutoff", True)
    _need(type(linked) is bool and synthesis.get("preserve_tails", True) is True,
          "Kasha linkage must be boolean and complete tails must be preserved")
    if linked:
        delay = 1 / denominator
        if "pair_delay_seconds" in synthesis:
            supplied = _number(synthesis["pair_delay_seconds"], "pair_delay_seconds", 0, 10)
            _need(abs(supplied - delay) <= 1e-12, "Linked pair delay must equal the requested cutoff")
    else:
        _need("pair_delay_seconds" in synthesis, "Unlinked Kasha synthesis requires pair_delay_seconds")
        delay = _number(synthesis["pair_delay_seconds"], "pair_delay_seconds", 0, 10)
    return {"gain_db": _number(config.get("gain_db", 0), "gain_db", -96, 24),
            "ka_playback_descriptor_bytes": CAPACITY["ka"],
            "recock_enabled": enabled, "recock_gap_ms": gap,
            "recock_gap_samples": _frames(gap / 1000) if enabled else 0,
            "cutoff_denominator": denominator, "cutoff_seconds": 1 / denominator,
            "kasha_pair_delay_seconds": delay, "kasha_pair_delay_samples": _frames(delay),
            "link_pair_delay_to_cutoff": linked, "preserve_tails": True}


def _budgets(controls: dict) -> dict:
    extra = _frames(max(0, controls["recock_gap_ms"] - 40) / 1000) if controls["recock_enabled"] else 0
    maximum = {"ka": 248, "sha": 13950 + extra, "kasha": 16058 + extra}
    return {role: {"max_source_samples": count, "max_actual_bytes": min(CAPACITY[role], encoded_size(count)),
                   "slot_capacity": CAPACITY[role], "offset": OFFSETS[role]} for role, count in maximum.items()}


def prepare_sound_project(config: dict, output_dir: Path, config_dir: Path | None = None) -> dict:
    """Trim/resample/fade, synthesize, apply one common gain, encode and verify.

    New schema a7m4-pin-sound-project/1. Concrete clips are local descriptor
    objects for ka/sha_dry/optional recock. Presets are resolved lazily by the
    separate registry. No clipping, normalization, time stretching or implicit
    truncation is performed to satisfy the final aligned native limits.
    """
    _need(isinstance(config, dict), "Sound configuration must be an object")
    if "preset" in config or (isinstance(config.get("clips"), dict) and
                              any(isinstance(v, dict) and "preset_asset" in v for v in config["clips"].values())):
        from .pin_presets import resolve_sound_project_presets
        config = resolve_sound_project_presets(config, config_dir)
    cfg = _keys(config, {"schema", "clips", "gain_db", "recock", "hybrid_cutoff", "kasha_synthesis", "model", "firmware"},
                {"schema", "clips"}, "PIN sound project")
    _need(cfg["schema"] == "a7m4-pin-sound-project/1", "Unsupported PIN sound project schema")
    _need(cfg.get("model", "ILCE-7M4") == "ILCE-7M4" and cfg.get("firmware", "6.02") == "6.02", "Unsupported model/firmware")
    clips = _keys(cfg["clips"], {"ka", "sha_dry", "recock", "kasha"}, {"ka", "sha_dry"}, "clips")
    if "kasha" in clips:
        _need(clips["kasha"] == {"mode": "synthesize_from_ka_and_sha"}, "Only explicit Kasha synthesis is supported")
    controls = _controls(cfg)
    budgets = _budgets(controls)
    directory = _new_directory(output_dir)
    base = Path(config_dir) if config_dir is not None else Path.cwd()
    material, sources = {}, {}
    for role in ("ka", "sha_dry", "recock"):
        if role in clips:
            material[role], sources[role] = _clip(clips[role], role, base)
    ka = material["ka"]
    _need(len(ka) <= 248, "Ka exceeds its hard 248-sample/256-byte limit; trim it explicitly, never accelerate it")
    sha = list(material["sha_dry"])
    if controls["recock_enabled"]:
        sha += [0.0] * controls["recock_gap_samples"] + material["recock"]
    delay = controls["kasha_pair_delay_samples"]
    kasha_count = max(len(ka), delay + len(sha))
    _need(len(sha) <= budgets["sha"]["max_source_samples"], "Sha plus recock exceeds the final sample/byte budget; trim source audio explicitly")
    _need(kasha_count <= budgets["kasha"]["max_source_samples"], "Kasha pair delay/tails exceed the final sample/byte budget; adjust the explicit inputs")
    kasha = [0.0] * kasha_count
    for index, value in enumerate(ka):
        kasha[index] = value
    for index, value in enumerate(sha):
        kasha[delay + index] += value
    gain = 10 ** (controls["gain_db"] / 20)
    raw_roles = {"ka": ka, "sha": sha, "kasha": kasha}
    files, native, decoded_records = {}, {}, {}
    for role in ROLES:
        gained = [sample * gain for sample in raw_roles[role]]
        _need(all(math.isfinite(x) and abs(x) <= HEADROOM for x in gained),
              f"{role} exceeds +/-32512 headroom after the common gain; lower gain_db and prepare again")
        pcm = [round(x) for x in gained]
        encoded = encode_filter0(pcm)
        minimum_encoded_bytes = len(encoded)
        # The admitted AP edits change only Sha/Kasha descriptors. KA playback
        # remains fixed at 256 bytes, so its actual payload/preview must include
        # that complete legal filter0 silence even when the source is shorter.
        if role == "ka":
            _need(len(encoded) <= CAPACITY["ka"], "Ka encoding exceeds its fixed playback descriptor")
            encoded += bytes(CAPACITY["ka"] - len(encoded))
        budget = budgets[role]
        _need(len(encoded) <= budget["max_actual_bytes"] <= CAPACITY[role], f"Final aligned {role} encoding exceeds its admitted budget")
        decoded = decode_filter0(encoded)
        wave = _wav(decoded)
        slot = encoded + bytes(CAPACITY[role] - len(encoded))
        # Every unused slot byte is a legitimate zero filter0 block; descriptor
        # lengths refer to encoded, never to the complete reserved slot.
        decode_filter0(slot)
        name, preview, slot_name = role + ".native.bin", role + ".decoded.wav", role + ".slot.bin"
        files[name], files[preview], files[slot_name] = encoded, wave, slot
        native[role] = {"file": name, "sha256": _sha(encoded), "actual_bytes": len(encoded),
                        "minimum_encoded_bytes": minimum_encoded_bytes, "playback_descriptor_bytes": len(encoded),
                        "source_samples": len(pcm), "decoded_samples": len(decoded), "padding_samples": len(decoded) - len(pcm),
                        "codec_alignment_padding_samples": minimum_encoded_bytes // 32 * 31 - len(pcm),
                        "fixed_descriptor_padding_samples": (len(encoded) - minimum_encoded_bytes) // 32 * 31,
                        "preview_file": preview, "preview_sha256": _sha(wave), "preview_bytes": len(wave),
                        "slot_file": slot_name, "slot_sha256": _sha(slot), "slot_capacity": CAPACITY[role],
                        "offset": OFFSETS[role], "max_allowed_actual_bytes": budget["max_actual_bytes"],
                        "max_source_samples": budget["max_source_samples"], "peak_before_encoding_pcm16": max(map(abs, pcm)),
                        "peak_decoded_pcm16": max(map(abs, decoded)),
                        "software_max_abs_error_pcm16": max(abs(a - b) for a, b in zip(pcm, decoded))}
        decoded_records[role] = {"file": preview, "sha256": _sha(wave), "samples": len(decoded), "bytes": len(wave)}
    manifest = {"schema": "a7m4-prepared-pin-sound-pack/1", "status": "PREPARED_OFFLINE_CANDIDATE",
                "model": "ILCE-7M4", "firmware": "6.02", "output_dir": str(directory),
                "camera_io": False, "network_io": False, "camera_applied": False,
                "deployment_authorized": False, "device_execution_ready": False, "camera_tests": "HELD",
                "controls": controls, "source_clips": sources, "native": native, "decoded": decoded_records,
                "format": {"sample_rate": RATE, "channels": 1, "pcm_bits": 16, "native_filter": 0,
                           "block_bytes": 32, "samples_per_block": 31, "alignment_bytes": 64,
                           "encoded_size_formula": "64*ceil(source_samples/62)", "headroom_abs_max": HEADROOM,
                           "encoded_size_formula_scope": "minimum filter0 encoding; prepared Ka playback is fixed at 256 bytes",
                           "camera_rate_measured": False},
                "conversion": {"resampling": "deterministic linear interpolation; no time stretching; no bandlimited anti-alias claim",
                               "gain": "one common PCM multiplier before one native encode; no normalization or saturation",
                               "gain_multiplier": gain, "player_volume": 1.0, "player_applies_gain_again": False,
                               "preview": "software decode of the exact playback native bytes, including Ka fixed-descriptor and codec alignment silence"},
                "layout": {"status": "PROPOSED_NOT_DEPLOYED", "bank_bytes": 110528,
                           "protected_prefix": [256, 77504], "preload_reserved_bytes": 131072,
                           "preload_remaining_bytes": 20544, "ka_playback_descriptor_bytes": CAPACITY["ka"],
                           "length_policy": "ka fixed 256 bytes; sha/kasha actual native bytes, not slot capacity",
                           "ka_length_change_requires": "separate AP descriptor adaptation and validation"},
                "acceptance": {"recorded_fixed_route": "R065/R066 PIN route accepted, including recorded R066 ordinary OFF/ON regression",
                               "dynamic_audio": "NOT_CAMERA_VALIDATED", "expanded_80ms_layout": "NOT_CAMERA_VALIDATED",
                               "requested_cutoff": "OFFLINE_ONLY_NOT_CAMERA_APPLIED", "installed_cutoff_approx_seconds": 0.125,
                               "fixed_R066_kasha_is_this_new_pair": False},
                "codec_source": {"url": "https://github.com/QAQLeonard/a7c2-fl23-research", "file": "src/shutter_sound/native_codec.py",
                                 "license": "MIT; complete author notice retained in native_audio_codec.py"}}
    raw_manifest = _json(manifest)
    files["manifest.sha256"] = (_sha(raw_manifest) + "\n").encode()
    files["manifest.json"] = raw_manifest
    _publish(directory, files)
    try:
        return validate_prepared_pack(directory)
    except BaseException:
        shutil.rmtree(directory)
        raise


def _asset_path(base: Path, name: Any) -> Path:
    _need(isinstance(name, str) and _NAME.fullmatch(name) is not None, "Prepared assets must use simple project-relative filenames")
    return base / name


def _pack_input(value: Any) -> tuple[dict, Path]:
    supplied = None
    if isinstance(value, dict):
        supplied = value
        _need(isinstance(value.get("output_dir"), str), "Manifest dict requires its prepared output_dir")
        path = Path(value["output_dir"]) / "manifest.json"
    else:
        path = _path(value, Path.cwd())
        _need(not path.is_symlink(), "Prepared project input must not be a symbolic link")
        if path.is_dir():
            path = path / "manifest.json"
    _need(not path.parent.is_symlink(), "Prepared project directory must not be a symbolic link")
    raw = _read(path, 1024 * 1024)
    checksum = _read(path.parent / "manifest.sha256", 65)
    _need(checksum == (_sha(raw) + "\n").encode(), "Prepared manifest SHA-256 differs")
    manifest = load_manifest(path)
    if supplied is not None:
        old, new = deepcopy(supplied), deepcopy(manifest)
        old.pop("output_dir", None)
        new.pop("output_dir", None)
        _need(old == new, "Supplied manifest does not match the complete saved prepared pack")
    return manifest, path.parent


def validate_prepared_pack(pack_manifest_or_dir: Any) -> dict:
    """Verify the saved manifest identity and every native/slot/decoded file.

    Relative files resolve against the actual manifest parent, so a copied pack
    is portable. No original input or device is reopened. Returned output_dir
    points at that actual parent, irrespective of the old saved absolute path.
    """
    manifest, base = _pack_input(pack_manifest_or_dir)
    fields = {"schema", "status", "model", "firmware", "output_dir", "camera_io", "network_io", "camera_applied",
              "deployment_authorized", "device_execution_ready", "camera_tests", "controls", "source_clips", "native",
              "decoded", "format", "conversion", "layout", "acceptance", "codec_source"}
    _keys(manifest, fields, fields, "prepared manifest")
    _need(manifest.get("schema") == "a7m4-prepared-pin-sound-pack/1" and
          manifest.get("status") == "PREPARED_OFFLINE_CANDIDATE", "Unsupported prepared PIN sound pack")
    _need(manifest.get("model") == "ILCE-7M4" and manifest.get("firmware") == "6.02", "Unsupported prepared model/firmware")
    _need(manifest.get("format") == {"sample_rate": RATE, "channels": 1, "pcm_bits": 16, "native_filter": 0,
          "block_bytes": 32, "samples_per_block": 31, "alignment_bytes": 64,
          "encoded_size_formula": "64*ceil(source_samples/62)", "headroom_abs_max": HEADROOM,
          "encoded_size_formula_scope": "minimum filter0 encoding; prepared Ka playback is fixed at 256 bytes",
          "camera_rate_measured": False}, "Prepared format metadata differs")
    controls = manifest.get("controls")
    _keys(controls, {"gain_db", "ka_playback_descriptor_bytes", "recock_enabled", "recock_gap_ms", "recock_gap_samples", "cutoff_denominator", "cutoff_seconds",
                     "kasha_pair_delay_seconds", "kasha_pair_delay_samples", "link_pair_delay_to_cutoff", "preserve_tails"},
          {"gain_db", "ka_playback_descriptor_bytes", "recock_enabled", "recock_gap_ms", "recock_gap_samples", "cutoff_denominator", "cutoff_seconds",
           "kasha_pair_delay_seconds", "kasha_pair_delay_samples", "link_pair_delay_to_cutoff", "preserve_tails"}, "prepared controls")
    normalized = _controls({"clips": {"recock": {}}, "gain_db": controls["gain_db"],
        "recock": {"enabled": controls["recock_enabled"], "gap_ms": controls["recock_gap_ms"]},
        "hybrid_cutoff": {"denominator": controls["cutoff_denominator"]},
        "kasha_synthesis": {"link_pair_delay_to_cutoff": controls["link_pair_delay_to_cutoff"],
                            "pair_delay_seconds": controls["kasha_pair_delay_seconds"], "preserve_tails": controls["preserve_tails"]}})
    _need(controls == normalized, "Prepared timing controls are inconsistent")
    conversion = manifest.get("conversion", {})
    _need(conversion.get("gain_multiplier") == 10 ** (controls["gain_db"] / 20) and
          conversion.get("player_volume") == 1.0 and conversion.get("player_applies_gain_again") is False,
          "Prepared gain/player controls are inconsistent")
    _need(manifest.get("layout") == {"status": "PROPOSED_NOT_DEPLOYED", "bank_bytes": 110528,
          "protected_prefix": [256, 77504], "preload_reserved_bytes": 131072, "preload_remaining_bytes": 20544,
          "ka_playback_descriptor_bytes": CAPACITY["ka"],
          "length_policy": "ka fixed 256 bytes; sha/kasha actual native bytes, not slot capacity",
          "ka_length_change_requires": "separate AP descriptor adaptation and validation"}, "Prepared PIN layout differs")
    budgets = _budgets(controls)
    _need(isinstance(manifest.get("native"), dict) and set(manifest["native"]) == set(ROLES) and
          isinstance(manifest.get("decoded"), dict) and set(manifest["decoded"]) == set(ROLES), "Prepared roles differ")
    sources = _keys(manifest.get("source_clips"), {"ka", "sha_dry", "recock"}, {"ka", "sha_dry"}, "prepared source clips")
    source_counts = {}
    for role, source in sources.items():
        _need(isinstance(source, dict) and type(source.get("prepared_samples")) is int and
              1 <= source["prepared_samples"] <= RATE * MAX_INPUT_SECONDS, "Prepared source sample count differs")
        source_counts[role] = source["prepared_samples"]
    _need(not controls["recock_enabled"] or "recock" in source_counts, "Prepared recock source is missing")
    sha_count = source_counts["sha_dry"] + (controls["recock_gap_samples"] + source_counts.get("recock", 0)
                                          if controls["recock_enabled"] else 0)
    expected_counts = {"ka": source_counts["ka"], "sha": sha_count,
                       "kasha": max(source_counts["ka"], controls["kasha_pair_delay_samples"] + sha_count)}
    names = set()
    for role in ROLES:
        item = manifest["native"][role]
        _need(isinstance(item, dict), "Invalid native role record")
        actual, count = item.get("actual_bytes"), item.get("source_samples")
        _need(type(actual) is int and type(count) is int and 1 <= count <= budgets[role]["max_source_samples"] and
              count == expected_counts[role],
              "Native actual length/sample budget differs")
        minimum = encoded_size(count)
        expected_actual = CAPACITY["ka"] if role == "ka" else minimum
        _need(actual == expected_actual <= budgets[role]["max_actual_bytes"] <= CAPACITY[role] and
              item.get("minimum_encoded_bytes") == minimum and item.get("playback_descriptor_bytes") == actual,
              "Native actual length differs from its admitted playback descriptor")
        _need(item.get("slot_capacity") == CAPACITY[role] and item.get("offset") == OFFSETS[role] and
              item.get("max_allowed_actual_bytes") == budgets[role]["max_actual_bytes"] and
              item.get("max_source_samples") == budgets[role]["max_source_samples"], "Native slot capacity/offset differs")
        for key in ("file", "preview_file", "slot_file"):
            name = item.get(key)
            _asset_path(base, name)
            _need(name not in names, "Prepared asset filenames must be unique")
            names.add(name)
        native = _read(_asset_path(base, item["file"]), CAPACITY[role])
        slot = _read(_asset_path(base, item["slot_file"]), CAPACITY[role])
        wave = _read(_asset_path(base, item["preview_file"]), 128 * 1024)
        _need(len(native) == actual and _sha(native) == item.get("sha256") and
              len(slot) == CAPACITY[role] and _sha(slot) == item.get("slot_sha256") and
              _sha(wave) == item.get("preview_sha256"), "Prepared native/slot/decoded complete SHA-256 differs")
        _need(slot == native + bytes(CAPACITY[role] - actual), "Reserved slot is not native plus valid zero filter0 blocks")
        _need(native[minimum:] == bytes(actual - minimum), "Fixed descriptor padding must contain canonical zero filter0 blocks")
        decoded = decode_filter0(native)
        decode_filter0(slot)
        _need(len(decoded) == item.get("decoded_samples") and len(decoded) - count == item.get("padding_samples") and
              item.get("codec_alignment_padding_samples") == minimum // 32 * 31 - count and
              item.get("fixed_descriptor_padding_samples") == (actual - minimum) // 32 * 31 and
              not any(decoded[count:]) and wave == _wav(decoded) and len(wave) == item.get("preview_bytes"),
              "Prepared decoded preview does not match the exact actual native bytes")
        _need(manifest["decoded"][role] == {"file": item["preview_file"], "sha256": item["preview_sha256"],
              "samples": len(decoded), "bytes": len(wave)}, "Prepared decoded role index differs")
    _need(manifest.get("camera_applied") is False and manifest.get("device_execution_ready") is False and
          manifest.get("deployment_authorized") is False and manifest.get("camera_io") is False and
          manifest.get("network_io") is False, "Offline preparation cannot claim camera execution")
    result = deepcopy(manifest)
    result["output_dir"] = str(base.absolute())
    return result


def preview_sound(pack_manifest_or_dir: Any, shutter_seconds: float, output: Path) -> dict:
    """Write an exact native-decoded audition timeline, with no second gain."""
    manifest = validate_prepared_pack(pack_manifest_or_dir)
    shutter = _number(shutter_seconds, "shutter_seconds", 1e-9, MAX_SHUTTER_SECONDS)
    target = _path(output, Path.cwd()).absolute()
    _need(not target.exists() and not target.is_symlink(), "Preview output already exists; choose a new WAV")
    _need(target.parent.is_dir(), "Preview output parent directory does not exist")
    base = Path(manifest["output_dir"])
    fast = shutter <= manifest["controls"]["cutoff_seconds"]
    scheduled = [("kasha", 0)] if fast else [("ka", 0), ("sha", _frames(shutter))]
    events = []
    for role, start in scheduled:
        item = manifest["native"][role]
        raw = _read(_asset_path(base, item["file"]), CAPACITY[role])
        _need(_sha(raw) == item["sha256"], "Native payload changed after validation")
        events.append((role, start, decode_filter0(raw)))
    frames = max(start + len(samples) for _, start, samples in events)
    _need(frames * 2 + 44 < 2**32, "Preview WAV duration exceeds RIFF capacity")
    if len(events) == 2:
        _, first_start, first = events[0]
        _, second_start, second = events[1]
        for at in range(max(first_start, second_start), min(first_start + len(first), second_start + len(second))):
            _need(abs(first[at - first_start] + second[at - second_start]) <= HEADROOM,
                  "Scheduled decoded KA/SHA overlap exceeds headroom; lower project gain_db and prepare again")
    created = False
    try:
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        created = True
        with os.fdopen(fd, "wb") as stream:
            stream.write(b"RIFF" + struct.pack("<I", 36 + frames * 2) + b"WAVEfmt " +
                         struct.pack("<IHHIIHH", 16, 1, 1, RATE, RATE * 2, 2, 16) + b"data" + struct.pack("<I", frames * 2))
            for start in range(0, frames, 16384):
                end = min(frames, start + 16384)
                chunk = [0] * (end - start)
                for _, offset, samples in events:
                    a, b = max(start, offset), min(end, offset + len(samples))
                    for at in range(a, b):
                        chunk[at - start] += samples[at - offset]
                stream.write(struct.pack("<" + "h" * len(chunk), *chunk))
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        if created:
            target.unlink(missing_ok=True)
        raise
    digest = hashlib.sha256()
    with _regular_reader(target) as (stream, info):
        while data := stream.read(1024 * 1024):
            digest.update(data)
    return {"schema": "a7m4-pin-sound-preview/1", "status": "PREVIEW_ONLY", "camera_io": False,
            "network_io": False, "camera_applied": False, "gain_applied_again": False, "player_volume": 1.0,
            "shutter_seconds": shutter, "cutoff_seconds": manifest["controls"]["cutoff_seconds"],
            "mode": "fixed-kasha" if fast else "separate-ka-sha", "sample_rate": RATE, "frames": frames,
            "output": {"path": str(target), "bytes": info.st_size, "sha256": digest.hexdigest()},
            "events": [{"role": role, "offset_samples": start, "decoded_samples": len(samples),
                        "native_sha256": manifest["native"][role]["sha256"]} for role, start, samples in events],
            "camera_tests": "HELD"}
