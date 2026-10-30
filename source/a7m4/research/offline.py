"""Read local files and describe exact byte changes without materializing images.

This module uses only the standard library. It neither imports live deployment
modules nor opens network/device connections. A plan is an offline calculation,
never an installation authorization. Offsets are zero-based byte offsets.

``plan_changes`` accepts schema ``a7m4-offline-plan/1``. Required fields are
``source`` (path/kind/size/sha256), ``windows`` (offset/before_hex/after_hex),
and ``space``. Optional ``append_hex`` adds a tail. Existing windows must be
nonempty, equally sized and disjoint. There are no insert/delete operations in
the existing body. ``space`` requires an explicit user-supplied offline free
space value and declares the prospective upload files by name and size; it does
not measure a camera, discover uploads, or inherit historical free space.

The unchanged complement is streamed in full into the virtual target. Its
range hashes describe an identity verified by construction, not a comparison
with a physical candidate or a camera readback. The inverse has exact swapped
windows and the exact appended tail to check before truncation.
"""

from __future__ import annotations

from collections.abc import Mapping
from contextlib import contextmanager
from copy import deepcopy
from functools import lru_cache
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, BinaryIO, Iterator


CHUNK_BYTES = 1024 * 1024
MAX_MANIFEST_BYTES = 8 * 1024 * 1024
MAX_PAYLOAD_BYTES = 8 * 1024 * 1024
MAX_WINDOW_BYTES = 1024 * 1024
MAX_WINDOWS = 4096
MAX_INTEGER = (1 << 63) - 1
UPLOAD_LIMIT_EXCLUSIVE = 65536
MINIMUM_FREE_BYTES = 8 * 1024 * 1024
_KINDS = frozenset(("ap", "cp", "synthetic"))
_HEX = re.compile(r"[0-9a-fA-F]*\Z")
_SHA256 = re.compile(r"[0-9a-fA-F]{64}\Z")
_UPLOAD_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")


class PlanError(ValueError):
    """A local input does not satisfy the offline planning contract."""


@lru_cache(maxsize=1)
def _baseline() -> dict[str, Any]:
    path = Path(__file__).with_name("data") / "baseline-r051c.json"
    return json.loads(path.read_text(encoding="utf-8"))


def baseline_metadata() -> dict[str, Any]:
    """Return public recorded evidence without private image paths or secrets."""
    result = deepcopy(_baseline())
    result["deployment_readiness"] = deployment_readiness()
    return result


def deployment_readiness() -> dict[str, Any]:
    """Keep live readiness separate from immutable historical component pins."""
    path = Path(__file__).with_name("data") / "known-issues.json"
    issues = json.loads(path.read_text(encoding="utf-8"))
    if issues.get("schema") != "a7m4-known-issues/1" or issues.get("device_writes_allowed") is not False:
        raise PlanError("Known-issue device gate is missing or invalid")
    return deepcopy(issues)


def _integer(value: Any, field: str, *, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= MAX_INTEGER:
        raise PlanError(f"{field} must be an integer from {minimum} to {MAX_INTEGER}")
    return value


def _object(value: Any, field: str, *, required: set[str], optional: set[str] | None = None) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise PlanError(f"{field} must be an object with string keys")
    keys = set(value)
    missing = required - keys
    extra = keys - required - (optional or set())
    if missing or extra:
        raise PlanError(f"{field} fields invalid: missing={sorted(missing)}, unknown={sorted(extra)}")
    return value


def _sha256(value: Any, field: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise PlanError(f"{field} must be exactly 64 hexadecimal characters")
    return value.lower()


def _hex_bytes(value: Any, field: str, *, allow_empty: bool = False, limit: int = MAX_WINDOW_BYTES) -> bytes:
    if not isinstance(value, str) or len(value) > limit * 2:
        raise PlanError(f"{field} must be a hexadecimal string of at most {limit} bytes")
    if len(value) % 2 or _HEX.fullmatch(value) is None or (not value and not allow_empty):
        raise PlanError(f"{field} must contain complete hex byte pairs without whitespace")
    return bytes.fromhex(value)


def _kind(value: Any) -> str:
    if not isinstance(value, str) or value not in _KINDS:
        raise PlanError("kind must be ap, cp, or synthetic")
    return value


def _path(value: Any, base_dir: Path | None = None) -> Path:
    if not isinstance(value, (str, os.PathLike)):
        raise PlanError("source path must be a local filesystem path")
    value = os.fspath(value)
    if not isinstance(value, str) or not value or "\0" in value:
        raise PlanError("source path must be a nonempty local path without NUL")
    if "://" in value:
        raise PlanError("source path must be local; URLs are not supported")
    path = Path(value)
    return base_dir / path if base_dir is not None and not path.is_absolute() else path


def _signature(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


@contextmanager
def _regular_reader(path: Path) -> Iterator[tuple[BinaryIO, os.stat_result]]:
    """Reject symlinks and special files before opening, then check the fd."""
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode):
            raise PlanError(f"source must be a regular file, not a symlink or device: {path}")
        flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened.st_mode) or _signature(before) != _signature(opened):
                raise PlanError("source changed while opening it")
            yield stream, opened
            if _signature(os.fstat(stream.fileno())) != _signature(opened):
                raise PlanError("source changed while reading it")
    except OSError as exc:
        raise PlanError(f"cannot read local source {path}: {exc.strerror or exc}") from exc


def _identification(kind: str, size: int, digest: str) -> dict[str, Any]:
    baseline = _baseline()
    expected = baseline["components"].get(kind)
    matched = expected is not None and expected["size"] == size and expected["sha256"] == digest
    stock = baseline["official602_components"].get(kind)
    stock_matched = stock is not None and stock["size"] == size and stock["sha256"] == digest
    profile = "r051c" if matched else "official602" if stock_matched else "unknown"
    return {
        "status": "exact-profile-component" if profile != "unknown" else "unknown",
        "matched_profile": profile,
        "baseline_match": matched,
        "baseline_id": baseline["baseline_id"] if matched else None,
        "component_feature_state": (
            "recorded-accepted-combination-component" if matched else
            "stock-component-research-customizations-absent" if stock_matched else "unknown"
        ),
        "features_inferred": [],
        "combined_feature_state": "requires-matching-component-pair",
        "boundary": baseline["recognition_boundary"],
    }


def inspect_image(path: str | os.PathLike[str], kind: str) -> dict[str, Any]:
    """Stream a complete local file and recognize fixed stock 6.02/R051c identities.

    ``synthetic`` permits arbitrary local fixtures. Unknown AP/CP bytes remain
    unknown: filenames, strings and partial signatures are not feature evidence.
    No source data is copied to the output.
    """
    kind = _kind(kind)
    local_path = _path(path)
    digest = hashlib.sha256()
    size = 0
    with _regular_reader(local_path) as (stream, info):
        while chunk := stream.read(CHUNK_BYTES):
            digest.update(chunk)
            size += len(chunk)
        if size != info.st_size:
            raise PlanError("source size changed while reading it")
    hexdigest = digest.hexdigest()
    return {
        "schema": "a7m4-offline-inspection/1",
        "offline_only": True,
        "deployment_authorized": False,
        "source": {"path": str(local_path), "kind": kind, "size": size, "sha256": hexdigest},
        "identification": _identification(kind, size, hexdigest),
    }


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PlanError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_manifest(path: str | os.PathLike[str]) -> dict[str, Any]:
    """Read bounded JSON, rejecting duplicate keys and nonstandard constants.

    Resolve its source with ``plan_changes(load_manifest(p), base_dir=p.parent)``.
    """
    local_path = _path(path)
    with _regular_reader(local_path) as (stream, info):
        if info.st_size > MAX_MANIFEST_BYTES:
            raise PlanError("manifest exceeds the 8 MiB input limit")
        raw = stream.read(MAX_MANIFEST_BYTES + 1)
    if len(raw) > MAX_MANIFEST_BYTES:
        raise PlanError("manifest exceeds the 8 MiB input limit")
    def reject_constant(value: str) -> Any:
        raise PlanError(f"nonstandard JSON constant: {value}")
    try:
        result = json.loads(raw, object_pairs_hook=_unique_object, parse_constant=reject_constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise PlanError(f"invalid manifest JSON: {exc}") from exc
    if not isinstance(result, dict):
        raise PlanError("manifest must be a JSON object")
    return result


def _space_budget(value: Any, kind: str) -> dict[str, Any]:
    space = _object(value, "space", required={"explicit_user_offline_measurement", "measured_free_bytes", "uploads"},
                    optional={"measurement_is_synthetic", "reserved_bytes"})
    if space["explicit_user_offline_measurement"] is not True:
        raise PlanError("space requires an explicit user-supplied offline measurement; historical free space is not a measurement")
    synthetic = space.get("measurement_is_synthetic", False)
    if type(synthetic) is not bool:
        raise PlanError("space.measurement_is_synthetic must be a boolean")
    if synthetic and kind != "synthetic":
        raise PlanError("a synthetic space measurement is allowed only for a synthetic source")
    free = _integer(space["measured_free_bytes"], "space.measured_free_bytes")
    reserved = _integer(space.get("reserved_bytes", 0), "space.reserved_bytes")
    uploads = space["uploads"]
    if not isinstance(uploads, list) or len(uploads) > MAX_WINDOWS:
        raise PlanError("space.uploads must be a list of at most 4096 files")
    names: set[str] = set()
    normalized = []
    for index, item in enumerate(uploads):
        item = _object(item, f"space.uploads[{index}]", required={"name", "size"})
        name = item["name"]
        if not isinstance(name, str) or _UPLOAD_NAME.fullmatch(name) is None or name in names:
            raise PlanError("upload names must be unique simple filenames of at most 128 ASCII characters")
        names.add(name)
        size = _integer(item["size"], f"space.uploads[{index}].size", minimum=1)
        if size >= UPLOAD_LIMIT_EXCLUSIVE:
            raise PlanError("each declared upload must be smaller than 65536 bytes")
        normalized.append({"name": name, "size": size})
    total = sum(item["size"] for item in normalized)
    remaining = free - total - reserved
    if remaining < MINIMUM_FREE_BYTES:
        raise PlanError("declared uploads and reserve must leave at least 8 MiB free")
    return {
        "measurement_origin": "explicit-user-supplied-offline-value",
        "measurement_is_synthetic": synthetic,
        "measurement_reverified": False,
        "measured_free_bytes": free,
        "uploads": normalized,
        "total_upload_bytes": total,
        "reserved_bytes": reserved,
        "projected_remaining_free_bytes": remaining,
        "minimum_remaining_free_bytes": MINIMUM_FREE_BYTES,
        "each_upload_bytes_exclusive": UPLOAD_LIMIT_EXCLUSIVE,
        "scope": "Only the declared prospective uploads and reserve; no transport artifacts were generated or measured.",
        "execution_requirement": "Remeasure actual free space and account for every actual upload before any separate deployment.",
        "deployment_authorized": False,
    }


def plan_changes(manifest: Mapping[str, Any], *, base_dir: str | os.PathLike[str] | None = None) -> dict[str, Any]:
    """Validate exact patches and return virtual target, complement and inverse.

    A source must match both the declared complete size and SHA-256. It need
    not match R051c: unknown inputs are explicitly reported as unknown, allowing
    synthetic testing without suggesting firmware compatibility. No images or
    payload files are written. Exceptions are ``PlanError`` for invalid inputs.
    """
    return _calculate_plan(manifest, base_dir=base_dir, content_only=False)


def plan_content_changes(manifest: Mapping[str, Any], *, base_dir: str | os.PathLike[str] | None = None) -> dict[str, Any]:
    """Calculate exact local content without requesting device space values.

    Uses schema ``a7m4-offline-content-plan/1`` with source, windows and optional
    append_hex. The same complete-source, window, complement and inverse checks
    apply as in ``plan_changes``. Transport artifacts and capacity are explicitly
    pending: this report cannot satisfy any deployment preflight or authorize
    execution. It is useful before a device session exists.
    """
    return _calculate_plan(manifest, base_dir=base_dir, content_only=True)


def _calculate_plan(manifest: Mapping[str, Any], *, base_dir: str | os.PathLike[str] | None,
                    content_only: bool) -> dict[str, Any]:
    required = {"schema", "source", "windows"} | (set() if content_only else {"space"})
    manifest = _object(manifest, "manifest", required=required, optional={"append_hex"})
    input_schema = "a7m4-offline-content-plan/1" if content_only else "a7m4-offline-plan/1"
    if manifest["schema"] != input_schema:
        raise PlanError("unsupported manifest schema")
    source = _object(manifest["source"], "source", required={"path", "kind", "size", "sha256"})
    kind = _kind(source["kind"])
    expected_size = _integer(source["size"], "source.size")
    expected_hash = _sha256(source["sha256"], "source.sha256")
    directory = Path(base_dir) if base_dir is not None else None
    local_path = _path(source["path"], directory)
    budget = ({
        "status": "PENDING_TRANSPORT_PREFLIGHT",
        "evaluated": False,
        "deployment_authorized": False,
        "each_upload_bytes_exclusive": UPLOAD_LIMIT_EXCLUSIVE,
        "minimum_remaining_free_bytes": MINIMUM_FREE_BYTES,
        "execution_requirement": "Generate and measure every actual upload, account for reserve, and measure fresh device free space before execution.",
    } if content_only else _space_budget(manifest["space"], kind))
    raw_windows = manifest["windows"]
    if not isinstance(raw_windows, list) or len(raw_windows) > MAX_WINDOWS:
        raise PlanError("windows must be a list of at most 4096 exact replacement windows")
    windows: list[tuple[int, bytes, bytes]] = []
    payload_bytes = 0
    for index, value in enumerate(raw_windows):
        window = _object(value, f"windows[{index}]", required={"offset", "before_hex", "after_hex"})
        offset = _integer(window["offset"], f"windows[{index}].offset")
        before = _hex_bytes(window["before_hex"], f"windows[{index}].before_hex")
        after = _hex_bytes(window["after_hex"], f"windows[{index}].after_hex")
        if len(before) != len(after):
            raise PlanError("existing replacement windows must have equal before/after lengths")
        if before == after:
            raise PlanError("replacement windows must change at least one byte")
        if offset + len(before) > expected_size:
            raise PlanError("replacement window extends outside the declared source")
        payload_bytes += len(before) + len(after)
        if payload_bytes > MAX_PAYLOAD_BYTES:
            raise PlanError("total exact window data exceeds the 8 MiB limit")
        windows.append((offset, before, after))
    windows.sort(key=lambda item: item[0])
    for previous, current in zip(windows, windows[1:]):
        if previous[0] + len(previous[1]) > current[0]:
            raise PlanError("replacement windows overlap")
    append = _hex_bytes(manifest.get("append_hex", ""), "append_hex", allow_empty=True, limit=MAX_PAYLOAD_BYTES)
    if payload_bytes + len(append) > MAX_PAYLOAD_BYTES:
        raise PlanError("total patch data exceeds the 8 MiB limit")
    if not windows and not append:
        raise PlanError("a plan must contain a replacement window or appended bytes")
    if expected_size + len(append) > MAX_INTEGER:
        raise PlanError("target size exceeds the supported integer range")

    original_digest = hashlib.sha256()
    target_digest = hashlib.sha256()
    complement_digest = hashlib.sha256()
    complement_ranges: list[dict[str, Any]] = []
    position = 0
    with _regular_reader(local_path) as (stream, info):
        if info.st_size != expected_size:
            raise PlanError(f"source size mismatch: expected {expected_size}, found {info.st_size}")

        def copy_complement(end: int) -> None:
            nonlocal position
            start = position
            segment_digest = hashlib.sha256()
            while position < end:
                chunk = stream.read(min(CHUNK_BYTES, end - position))
                if not chunk:
                    raise PlanError("source was truncated while reading it")
                position += len(chunk)
                original_digest.update(chunk)
                target_digest.update(chunk)
                complement_digest.update(chunk)
                segment_digest.update(chunk)
            if end > start:
                complement_ranges.append({"offset": start, "size": end - start, "sha256": segment_digest.hexdigest()})

        for offset, before, after in windows:
            copy_complement(offset)
            actual = stream.read(len(before))
            if actual != before:
                raise PlanError(f"exact before image mismatch at byte offset {offset}")
            original_digest.update(actual)
            target_digest.update(after)
            position += len(actual)
        copy_complement(expected_size)
        if stream.read(1):
            raise PlanError("source grew while reading it")
    original_hash = original_digest.hexdigest()
    if original_hash != expected_hash:
        raise PlanError(f"complete source SHA-256 mismatch: expected {expected_hash}, found {original_hash}")
    target_digest.update(append)
    target_hash = target_digest.hexdigest()
    target_size = expected_size + len(append)
    normalized_windows = [
        {"offset": offset, "size": len(before), "before_hex": before.hex(), "after_hex": after.hex(),
         "changed_bytes": sum(left != right for left, right in zip(before, after))}
        for offset, before, after in windows
    ]
    complement_size = sum(item["size"] for item in complement_ranges)
    inverse = {
        "source": {"kind": kind, "size": target_size, "sha256": target_hash},
        "windows": [{"offset": offset, "before_hex": after.hex(), "after_hex": before.hex()} for offset, before, after in windows],
        "truncate_to": expected_size,
        "tail_before_truncate": {"offset": expected_size, "size": len(append), "before_hex": append.hex(), "sha256": hashlib.sha256(append).hexdigest()},
        "target": {"size": expected_size, "sha256": original_hash},
        "order": "Verify complete source identity and exact windows/tail, replace windows, then truncate; separately verify the complete restored identity.",
    }
    return {
        "schema": "a7m4-offline-content-plan-result/1" if content_only else "a7m4-offline-plan-result/1",
        "offline_only": True,
        "deployment_authorized": False,
        "images_written": False,
        "device_execution_ready": False,
        "source": {"path": str(local_path), "kind": kind, "size": expected_size, "sha256": original_hash},
        "identification": _identification(kind, expected_size, original_hash),
        "target": {"size": target_size, "sha256": target_hash, "materialized": False},
        "windows": normalized_windows,
        "append": {"offset": expected_size, "size": len(append), "after_hex": append.hex(), "sha256": hashlib.sha256(append).hexdigest()},
        "changed_existing_bytes": sum(item["changed_bytes"] for item in normalized_windows),
        "complement": {
            "verification": "complete-identity-by-construction",
            "physical_candidate_compared": False,
            "size": complement_size,
            "sha256_concatenated_ranges": complement_digest.hexdigest(),
            "ranges": complement_ranges,
            "coverage_bytes": complement_size + sum(len(before) for _, before, _ in windows),
            "boundary": "Every source byte outside the listed windows was streamed unchanged into the virtual target; no camera or materialized target was compared.",
        },
        "inverse": inverse,
        "space_budget": budget,
        "baseline_context": baseline_metadata(),
    }
