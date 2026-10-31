"""Local KA/SHA/KASHA PCM projects; no native codec or camera execution.

Accepts bounded little-endian integer PCM WAV (8/16/24/32-bit, mono/stereo),
strips ancillary metadata and converts to 24 kHz mono PCM16. Resampling uses
deterministic linear interpolation. It is an audition/preparation format, not
an admitted camera payload. A fast exposure (<=1/8 s) always uses the fixed
KASHA clip; longer exposures schedule KA at start and SHA at exposure end.
"""

from __future__ import annotations

from collections.abc import Mapping
from functools import lru_cache
import hashlib
import json
import math
import os
from pathlib import Path
import struct
from typing import Any

from .offline import PlanError, _object, _path, _regular_reader


TARGET_RATE = 24000
FAST_SHUTTER_SECONDS = .125
MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_CLIP_SECONDS = 10.
MAX_SHUTTER_SECONDS = 3600.
CLIP_NAMES = ("ka", "sha", "kasha")


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _number(value: Any, name: str, low: float, high: float, *, exclusive_low: bool = False) -> float:
    if (type(value) not in (int, float) or value > high or
            (value <= low if exclusive_low else value < low) or not math.isfinite(value)):
        bracket = "greater than" if exclusive_low else "at least"
        raise PlanError(f"{name} must be finite, {bracket} {low}, and at most {high}")
    return float(value)


def _parse_wav(raw: bytes) -> tuple[dict[str, Any], memoryview]:
    if len(raw) < 12 or raw[:4] != b"RIFF" or raw[8:12] != b"WAVE":
        raise PlanError("Only little-endian RIFF/WAVE integer PCM files are supported")
    if struct.unpack_from("<I", raw, 4)[0] + 8 != len(raw):
        raise PlanError("WAV RIFF size does not match the complete local file")
    position, fmt, data, extras = 12, None, None, []
    while position < len(raw):
        if position + 8 > len(raw):
            raise PlanError("WAV has a truncated RIFF chunk header")
        kind, size = struct.unpack_from("<4sI", raw, position)
        start, end = position + 8, position + 8 + size
        if end + (size & 1) > len(raw):
            raise PlanError("WAV chunk or alignment pad is outside the RIFF file")
        if kind == b"fmt ":
            if fmt is not None or data is not None or size not in (16, 18):
                raise PlanError("WAV requires one PCM fmt chunk before data, of 16 bytes or 18 bytes with no extension")
            if size == 18 and struct.unpack_from("<H", raw, start + 16)[0] != 0:
                raise PlanError("Extended/compressed WAV formats are unsupported")
            fmt = struct.unpack_from("<HHIIHH", raw, start)
        elif kind == b"data":
            if fmt is None or data is not None:
                raise PlanError("WAV requires exactly one data chunk after fmt")
            data = (start, size)
        else:
            extras.append(kind.hex())
        position = end + (size & 1)
    if position != len(raw) or fmt is None or data is None:
        raise PlanError("WAV is missing a complete fmt/data pair")
    encoding, channels, rate, byte_rate, align, bits = fmt
    if encoding != 1:
        raise PlanError("WAV must be integer PCM format 1; float, extensible and compressed audio are unsupported")
    if channels not in (1, 2) or bits not in (8, 16, 24, 32):
        raise PlanError("PCM WAV must be mono/stereo with 8, 16, 24 or 32 integer bits")
    if not 8000 <= rate <= 192000:
        raise PlanError("PCM WAV sample rate must be 8000..192000 Hz")
    if align != channels * (bits // 8) or byte_rate != rate * align:
        raise PlanError("WAV byte rate/block alignment do not match PCM channel/bit/rate fields")
    data_start, data_size = data
    if data_size == 0 or data_size % align:
        raise PlanError("WAV audio must contain nonempty complete PCM frames")
    frames = data_size // align
    if frames > rate * MAX_CLIP_SECONDS:
        raise PlanError("Each local audio clip must be at most 10 seconds")
    pcm = memoryview(raw)[data_start:data_start + data_size]
    return {
        "format": "PCM_INTEGER_LE", "sample_rate": rate, "channels": channels,
        "bits_per_sample": bits, "frames": frames, "duration_seconds": frames / rate,
        "block_align": align, "pcm_bytes": data_size, "pcm_sha256": _sha(pcm),
        "ancillary_chunk_ids_hex": extras,
    }, pcm


def _decode(meta: Mapping[str, Any], pcm: memoryview, *, keep_mono: bool) -> tuple[list[float], float]:
    width, channels = meta["bits_per_sample"] // 8, meta["channels"]
    denominator = float(1 << (meta["bits_per_sample"] - 1))
    mono, peak = [], 0.
    for offset in range(0, len(pcm), width * channels):
        total = 0.
        for channel in range(channels):
            start = offset + channel * width
            value = ((pcm[start] - 128) if width == 1 else
                     int.from_bytes(pcm[start:start + width], "little", signed=True)) / denominator
            total += value
            peak = max(peak, abs(value))
        if keep_mono:
            mono.append(total / channels)
    return mono, peak


def _load_wav(path: str | os.PathLike[str], base: Path | None = None) -> tuple[dict[str, Any], memoryview]:
    local = _path(path, base)
    with _regular_reader(local) as (stream, info):
        if info.st_size > MAX_INPUT_BYTES:
            raise PlanError("Each WAV input must be at most 16 MiB")
        raw = stream.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise PlanError("Each WAV input must be at most 16 MiB")
    meta, pcm = _parse_wav(raw)
    return {"path": str(local), "filename": local.name, "bytes": len(raw), "sha256": _sha(raw), **meta}, pcm


def inspect_wav(path: str | os.PathLike[str]) -> dict[str, Any]:
    """Validate a complete regular local PCM WAV and return bounded metadata."""
    meta, pcm = _load_wav(path)
    _, peak = _decode(meta, pcm, keep_mono=False)
    return {"schema": "a7m4-local-wav-inspection/1", **meta, "peak_normalized": peak,
            "convertible_to_local_pcm24k_mono16": True,
            "camera_codec_compatible": None, "camera_validation": "NOT_PERFORMED",
            "camera_io": False, "network_io": False}


def _pcm16(mono: list[float], source_rate: int, gain: float) -> bytes:
    frames = max(1, (2 * len(mono) * TARGET_RATE + source_rate) // (2 * source_rate))
    output = bytearray(frames * 2)
    for index in range(frames):
        numerator = index * source_rate
        lower, remainder = divmod(numerator, TARGET_RATE)
        lower = min(lower, len(mono) - 1)
        upper = min(lower + 1, len(mono) - 1)
        value = (mono[lower] + (mono[upper] - mono[lower]) * remainder / TARGET_RATE) * gain * 32768
        sample = math.floor(value + .5) if value >= 0 else math.ceil(value - .5)
        struct.pack_into("<h", output, index * 2, min(32767, max(-32768, sample)))
    return bytes(output)


def _wav_bytes(pcm: bytes) -> bytes:
    return (b"RIFF" + struct.pack("<I", 36 + len(pcm)) + b"WAVEfmt " +
            struct.pack("<IHHIIHH", 16, 1, 1, TARGET_RATE, TARGET_RATE * 2, 2, 16) +
            b"data" + struct.pack("<I", len(pcm)) + pcm)


@lru_cache(maxsize=1)
def _asset_rights() -> dict[str, dict[str, Any]]:
    path = Path(__file__).with_name("data") / "assets/manifest.json"
    if not path.is_file():
        return {}
    manifest = json.loads(path.read_text(encoding="utf-8"))
    return {record["sha256"]: {"origin": record["origin"], "rights": record["rights"],
                               "known_asset": record["path"],
                               "internal_distribution_only": record["path"].startswith("factory-")}
            for record in manifest["files"] if record["path"].endswith(".wav")}


def _rights(meta: Mapping[str, Any]) -> dict[str, Any]:
    known = _asset_rights().get(meta["sha256"])
    if known is not None:
        return dict(known)
    return {"origin": "User-supplied local audio", "rights": "Owner's original rights retained; this conversion grants no redistribution license",
            "known_asset": None, "internal_distribution_only": None}


def _write_new(path: Path, raw: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    if path.read_bytes() != raw:
        raise PlanError("Prepared audio output differs after durable local write")


def prepare_audio(config: Mapping[str, Any], output: str | os.PathLike[str],
                  config_dir: str | os.PathLike[str] | None = None) -> dict[str, Any]:
    """Prepare three local audition WAVs and a timeline in a new private folder.

    Schema ``a7m4-audio-project/1`` requires ``clips`` with exactly ka/sha/kasha
    local paths, ``shutter_seconds`` (>0, <=3600), and ``gain`` (0..1). Paths
    resolve against config_dir or cwd. All inputs and conversions are checked
    before the output directory is created. Originals are never copied or
    modified; ancillary source metadata is stripped from the new WAVs.
    """
    config = _object(config, "audio project", required={"schema", "clips", "shutter_seconds", "gain"})
    if config["schema"] != "a7m4-audio-project/1":
        raise PlanError("Unsupported audio project schema")
    clips = _object(config["clips"], "clips", required=set(CLIP_NAMES))
    shutter = _number(config["shutter_seconds"], "shutter_seconds", 0., MAX_SHUTTER_SECONDS, exclusive_low=True)
    gain = _number(config["gain"], "gain", 0., 1.)
    directory = _path(output)
    if directory.exists() or directory.is_symlink():
        raise PlanError("Audio preparation requires a new output directory; existing paths are preserved")
    if not directory.parent.is_dir():
        raise PlanError("Audio output parent directory must already exist")
    base = Path(config_dir) if config_dir is not None else Path.cwd()
    prepared, records = {}, {}
    for name in CLIP_NAMES:
        source, pcm = _load_wav(clips[name], base)
        mono, peak = _decode(source, pcm, keep_mono=True)
        converted = _wav_bytes(_pcm16(mono, source["sample_rate"], gain))
        actual, converted_pcm = _parse_wav(converted)
        _, output_peak = _decode(actual, converted_pcm, keep_mono=False)
        prepared[name] = converted
        records[name] = {
            "source": {**source, "peak_normalized": peak}, "source_preserved": True,
            "file": name + ".wav", "bytes": len(converted), "sha256": _sha(converted),
            **actual, "peak_normalized": output_peak, "rights": _rights(source),
        }
    fast = shutter <= FAST_SHUTTER_SECONDS
    events = ([{"clip": "kasha", "at_seconds": 0., "role": "fixed-fast-exposure-sound"}] if fast else
              [{"clip": "ka", "at_seconds": 0., "role": "exposure-start"},
               {"clip": "sha", "at_seconds": shutter, "role": "exposure-end"}])
    for event in events:
        event["duration_seconds"] = records[event["clip"]]["duration_seconds"]
        event["end_seconds"] = event["at_seconds"] + event["duration_seconds"]
    manifest = {
        "schema": "a7m4-prepared-audio-project/1", "status": "PREPARED_LOCAL_ONLY",
        "camera_io": False, "network_io": False, "device_execution_state": "HELD",
        "camera_applied": False, "deployment_authorized": False, "native_codec_generated": False,
        "camera_playback_compatible": None, "camera_limits_verified": False,
        "output": str(directory.absolute()), "gain": gain, "shutter_seconds": shutter,
        "clips": records, "format": {"container": "WAV", "encoding": "PCM_INTEGER_LE", "sample_rate": TARGET_RATE,
                                      "channels": 1, "bits_per_sample": 16},
        "conversion": {"downmix": "arithmetic channel mean", "resampling": "linear interpolation; no bandlimited anti-alias claim",
                       "gain": "linear multiplier before PCM16 quantization; no peak normalization",
                       "ancillary_metadata": "stripped", "rounding": "nearest integer, ties away from zero, saturated signed16"},
        "timeline": {"fast_threshold_seconds": FAST_SHUTTER_SECONDS, "fast_includes_boundary": True,
                     "mode": "fixed-kasha" if fast else "separate-ka-sha", "events": events,
                     "preview_end_seconds": max(event["end_seconds"] for event in events),
                     "ka_sha_overlap": False if fast else records["ka"]["duration_seconds"] > shutter,
                     "rule": "Exposure <=1/8s uses the fixed KASHA recording without trimming/stretching to exposure length; longer exposure starts KA at 0 and starts SHA at exposure end."},
        "limits": {"maximum_source_file_bytes": MAX_INPUT_BYTES, "maximum_clip_seconds": MAX_CLIP_SECONDS,
                   "source_rate_range": [8000, 192000], "source_channels": [1, 2], "source_pcm_bits": [8, 16, 24, 32],
                   "maximum_local_shutter_seconds": MAX_SHUTTER_SECONDS,
                   "camera_encoding_duration_and_upload_limits": "NOT_ADMITTED_BY_LOCAL_WAV_CONVERSION"},
        "source_files_copied": False,
        "internal_distribution_only": any(record["rights"]["internal_distribution_only"] is True for record in records.values()),
        "rights_boundary": "Source rights remain unchanged. Known factory clips are Sony audio for the requested internal personal-study audition only, never relicensed as MIT or cleared for public publication.",
        "application": {"status": "HELD", "reason": "Only local file preparation and audition are implemented; camera scheduling, native encoding, settings, transaction and validation remain separate."},
    }
    raw_manifest = (json.dumps(manifest, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode("utf-8")
    try:
        directory.mkdir(mode=0o700)
    except FileExistsError as exc:
        raise PlanError("Audio output appeared during preparation; refusing to overwrite") from exc
    for name, raw in prepared.items():
        _write_new(directory / (name + ".wav"), raw)
    _write_new(directory / "manifest.json", raw_manifest)
    return manifest
