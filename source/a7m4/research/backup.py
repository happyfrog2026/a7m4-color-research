"""Complete local-import backup containers; never discover or contact a device.

Default snapshot layout is appFw.so, CPAPP-B.BIN and resources/<70 filenames>.
Optional inventory.json adds explicit present/absent objects under extras/.
The .a7backup container is a ZIP with one schema-bound manifest and complete
objects. It is not a whole-chip dump, proof of device origin, or permission to
restore. Unknown firmware bytes may be preserved; all restore execution is held.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct
from typing import Any, BinaryIO, Iterator
import zipfile
import zlib

from .. import resource_profile as device_scope


SCHEMA = "a7m4-backup/1"
SCOPE_ID = "m4-602-app-cp-resources/1"
INVENTORY_SCHEMA = "a7m4-snapshot-inventory/1"
LANGUAGES = (
    "arabic", "brazilianportuguese", "bulgarian", "canadianfrench", "croatian",
    "czech", "danish", "dutch", "english", "finnish", "french", "german",
    "greek", "hindi", "hungarian", "indonesia", "italian", "japanese",
    "korean", "malay", "norwegian", "persian", "polish", "portuguese",
    "romanian", "russian", "simplifiedchinese", "spanish", "swedish", "thai",
    "traditionalchinese", "turkish", "ukrainian", "vietnamese",
)
RESOURCE_FILENAMES = tuple(sorted(
    [f"string_{language}_{direction}.uxc" for language in LANGUAGES
     for direction in ("horizontal", "vertical")]
    + ["image_00_23_IPSX.uxc", "image_00_32_IPSX.uxc"]))
REQUIRED_OBJECTS = {
    "appFw.so": {"target_path": "/usr/lib/appFw.so", "kind": "ap"},
    "CPAPP-B.BIN": {"target_path": "/cp/CPAPP-B.BIN", "kind": "cp"},
    **{f"resources/{name}": {"target_path": f"/usr/share/app/{name}", "kind": "resource"}
       for name in RESOURCE_FILENAMES},
}
CHUNK_BYTES = 1024 * 1024
MAX_OBJECT_BYTES = 512 * 1024 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_OBJECTS = 1024
MAX_COMPRESSION_RATIO = 200
MAX_CENTRAL_DIRECTORY_BYTES = 2 * 1024 * 1024
_RELATIVE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]*\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_NOT_COVERED = [
    "whole_emmc_chip_boot_partitions_nor_other_mcus_calibration_and_settings",
    "future_custom_audio_and_loader_objects_unless_explicitly_in_inventory",
]


class BackupError(ValueError):
    """A local snapshot/container cannot support the stated complete scope."""


def _path(value: Any, what: str = "path") -> str:
    if (not isinstance(value, str) or len(value) > 512 or not _RELATIVE.fullmatch(value)
            or "\\" in value or any(part in ("", ".", "..") for part in value.split("/"))):
        raise BackupError(f"Invalid canonical relative {what}: {value!r}")
    if str(PurePosixPath(value)) != value:
        raise BackupError(f"Invalid canonical relative {what}: {value!r}")
    return value


def _target(value: Any) -> str:
    if not isinstance(value, str) or not value.startswith(("/usr/", "/cp/")):
        raise BackupError("Explicit target_path must be an absolute /usr/ or /cp/ file path")
    _path(value[1:], "target_path")
    return value


def _add_target(target: str, targets: set[str]) -> None:
    """Require disjoint file targets, including explicit absence records.

    A file cannot contain another target file. Likewise an absent directory-like
    target cannot be restored by removing a parent of a protected object. Compare
    components rather than string prefixes: /usr/share/app2 is not below app.
    """
    parts = PurePosixPath(target.casefold()).parts
    for existing in targets:
        other = PurePosixPath(existing.casefold()).parts
        if parts[:len(other)] == other or other[:len(parts)] == parts:
            raise BackupError(f"Target path ancestor/descendant conflict: {target} and {existing}")
    targets.add(target)


def _strict_object(value: Any, keys: set[str], what: str) -> dict:
    if not isinstance(value, dict) or set(value) != keys:
        raise BackupError(f"Invalid {what} fields; expected {sorted(keys)}")
    return value


def _integer(value: Any, what: str, maximum: int, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise BackupError(f"{what} must be an integer in {minimum}..{maximum}")
    return value


def _signature(info: os.stat_result) -> tuple:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _root(value: str | os.PathLike) -> Path:
    path = Path(value)
    try:
        if path.is_symlink() or not path.is_dir():
            raise BackupError("snapshot_dir must be a real directory, not a symlink")
        return path.resolve(strict=True)
    except OSError as exc:
        raise BackupError(f"Cannot open snapshot directory: {exc}") from exc


def _local(root: Path, relative: str) -> Path:
    _path(relative)
    path = root
    for part in relative.split("/"):
        path = path / part
        if path.is_symlink():
            raise BackupError(f"Snapshot symlink is not allowed: {relative}")
    return path


@contextmanager
def _reader(path: Path) -> Iterator[tuple[BinaryIO, os.stat_result]]:
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode):
            raise BackupError(f"Only regular files can be backed up: {path.name}")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        with os.fdopen(os.open(path, flags), "rb") as stream:
            opened = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened.st_mode) or _signature(before) != _signature(opened):
                raise BackupError(f"Local input changed while opening: {path.name}")
            yield stream, opened
            if _signature(os.fstat(stream.fileno())) != _signature(opened):
                raise BackupError(f"Local input changed while reading: {path.name}")
    except OSError as exc:
        raise BackupError(f"Cannot read local file {path.name}: {exc.strerror or exc}") from exc


def _hash(stream: BinaryIO, limit: int = MAX_OBJECT_BYTES) -> tuple[int, str]:
    digest, size = hashlib.sha256(), 0
    while chunk := stream.read(CHUNK_BYTES):
        size += len(chunk)
        if size > limit:
            raise BackupError("Local input exceeds the size limit")
        digest.update(chunk)
    return size, digest.hexdigest()


def _unique(pairs: list[tuple[str, Any]]) -> dict:
    value = {}
    for key, item in pairs:
        if key in value:
            raise BackupError(f"Duplicate JSON key: {key}")
        value[key] = item
    return value


def _json(raw: bytes) -> dict:
    if len(raw) > MAX_MANIFEST_BYTES:
        raise BackupError("Manifest exceeds the 2 MiB limit")
    try:
        def reject(value):
            raise BackupError(f"Nonstandard JSON value: {value}")
        value = json.loads(raw, object_pairs_hook=_unique, parse_constant=reject)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise BackupError(f"Invalid manifest JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise BackupError("Manifest must be a JSON object")
    return value


def _inventory(root: Path, required=None) -> list[dict]:
    required = REQUIRED_OBJECTS if required is None else required
    path = _local(root, "inventory.json")
    if not path.exists():
        return []
    with _reader(path) as (stream, info):
        if info.st_size > MAX_MANIFEST_BYTES:
            raise BackupError("Inventory exceeds the 2 MiB limit")
        inventory = _json(stream.read(MAX_MANIFEST_BYTES + 1))
    _strict_object(inventory, {"schema", "extra_objects"}, "snapshot inventory")
    if inventory["schema"] != INVENTORY_SCHEMA:
        raise BackupError("Unsupported snapshot inventory schema")
    rows = inventory["extra_objects"]
    if not isinstance(rows, list) or len(rows) > MAX_OBJECTS - len(required):
        raise BackupError("Invalid extra_objects inventory count")
    seen, result = set(), []
    targets = {row["target_path"] for row in required.values()}
    for item in rows:
        _strict_object(item, {"path", "target_path", "state", "kind"}, "extra object")
        relative = _path(item["path"])
        target = _target(item["target_path"])
        if not relative.startswith("extras/") or relative.casefold() in seen:
            raise BackupError("Extra paths must be unique under extras/ and have distinct targets")
        if item["state"] not in ("present", "absent") or item["kind"] not in ("audio", "loader", "extra"):
            raise BackupError("Extra object requires present/absent state and audio/loader/extra kind")
        _add_target(target, targets)
        seen.add(relative.casefold())
        result.append(dict(item))
    return sorted(result, key=lambda row: row["path"])


def _snapshot(root: Path, extras: list[dict], required=None) -> list[dict]:
    required = REQUIRED_OBJECTS if required is None else required
    definitions = [{"path": path, "state": "present", **spec} for path, spec in required.items()] + extras
    missing = [row["path"] for row in definitions
               if row["state"] == "present" and not _local(root, row["path"]).exists()]
    if missing:
        raise BackupError("Incomplete snapshot; missing files: " + ", ".join(sorted(missing)))
    result, total = [], 0
    for definition in sorted(definitions, key=lambda row: row["path"]):
        relative = definition["path"]
        path = _local(root, relative)
        row = dict(definition)
        if row["state"] == "absent":
            if path.exists():
                raise BackupError(f"Inventory says absent but local object exists: {relative}")
            row.update(size=0, sha256=None, mode=None, archive_path=None)
        else:
            with _reader(path) as (stream, info):
                if info.st_size > MAX_OBJECT_BYTES or (relative in required and not info.st_size):
                    raise BackupError(f"Empty or oversized required snapshot object: {relative}")
                size, digest = _hash(stream)
            total += size
            if total > MAX_TOTAL_BYTES:
                raise BackupError("Snapshot exceeds the 2 GiB total limit")
            row.update(size=size, sha256=digest, mode=stat.S_IMODE(info.st_mode), archive_path="objects/" + relative)
        result.append(row)
    return result


def _zip_info(name: str, mode: int = 0o600) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.create_system = 3
    info.external_attr = (stat.S_IFREG | mode) << 16
    info.compress_type = zipfile.ZIP_STORED
    return info


def _known_identity(objects: list[dict]) -> dict:
    # Recognition is metadata only; unknown complete bytes remain preservable.
    from .offline import baseline_metadata
    baseline = baseline_metadata()
    identities = {}
    for relative, kind in (("appFw.so", "ap"), ("CPAPP-B.BIN", "cp")):
        row = next(obj for obj in objects if obj["path"] == relative)
        expected = baseline.get("components", {}).get(kind, {})
        match = (row["size"], row["sha256"]) == (expected.get("size"), expected.get("sha256"))
        identities[kind] = {"status": "recorded-r051c-component" if match else "unrecognized-preserved",
                            "device_state_proven": False}
    return identities


def _scope_definition(profile):
    if profile is None or profile == SCOPE_ID:
        return REQUIRED_OBJECTS, SCHEMA, SCOPE_ID
    if profile == device_scope.ID:
        return device_scope.OBJECTS, device_scope.ARCHIVE_SCHEMA, device_scope.ARCHIVE_SCOPE
    raise BackupError('Unknown explicit archive scope')


def _manifest(objects: list[dict], *, profile=None) -> dict:
    required, schema, scope_id = _scope_definition(profile)
    return {
        "schema": schema, "created_at": datetime.now(timezone.utc).isoformat(),
        "sourceOrigin": "local-import", "complete": True,
        "scope": {"id": scope_id, "required_paths": sorted(required),
                  "base_object_count": len(required), "not_covered": list(_NOT_COVERED)},
        "mode_origin": "local-snapshot-file-stat-not-device-stat",
        "objects": objects, "camera_io": False, "device_execution_ready": False,
    }


def create_backup(snapshot_dir: str | os.PathLike, output_archive: str | os.PathLike, *, profile=None) -> dict:
    """Store all 72 required local files plus explicit inventory extras.

    Missing files are reported together before output creation. Existing output
    is never overwritten. No profile pinning, second copy, hardware access,
    network access, or extraction occurs. The returned archive verifies itself.
    """
    root, output = _root(snapshot_dir), Path(output_archive)
    required, _, _ = _scope_definition(profile)
    objects = _snapshot(root, _inventory(root, required), required)
    raw_manifest = (json.dumps(_manifest(objects, profile=profile), ensure_ascii=False, sort_keys=True,
                               indent=2, allow_nan=False) + "\n").encode("utf-8")
    if len(raw_manifest) > MAX_MANIFEST_BYTES:
        raise BackupError("Manifest exceeds the 2 MiB limit")
    created = False
    try:
        with output.open("xb") as destination:
            created = True
            os.fchmod(destination.fileno(), 0o600)
            with zipfile.ZipFile(destination, "w", allowZip64=True) as archive:
                for row in objects:
                    if row["state"] == "absent":
                        continue
                    digest, size = hashlib.sha256(), 0
                    with _reader(_local(root, row["path"])) as (stream, info):
                        if stat.S_IMODE(info.st_mode) != row["mode"]:
                            raise BackupError(f"Mode changed while creating backup: {row['path']}")
                        with archive.open(_zip_info(row["archive_path"], row["mode"]), "w", force_zip64=True) as member:
                            while chunk := stream.read(CHUNK_BYTES):
                                size += len(chunk)
                                if size > row["size"]:
                                    raise BackupError(f"Source grew while creating backup: {row['path']}")
                                digest.update(chunk); member.write(chunk)
                    if (size, digest.hexdigest()) != (row["size"], row["sha256"]):
                        raise BackupError(f"Source changed while creating backup: {row['path']}")
                archive.writestr(_zip_info("manifest.json"), raw_manifest)
            destination.flush()
            os.fsync(destination.fileno())
        result = verify_backup(output)
        result["snapshot_dir"] = str(root)
        return result
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        if created:
            output.unlink(missing_ok=True)
        raise BackupError(f"Backup creation failed: {exc}") from exc
    except Exception:
        if created:
            output.unlink(missing_ok=True)
        raise


def _validate_manifest(manifest: dict) -> list[dict]:
    _strict_object(manifest, {"schema", "created_at", "sourceOrigin", "complete", "scope", "mode_origin",
                              "objects", "camera_io", "device_execution_ready"}, "backup manifest")
    required, schema, scope_id = _scope_definition(device_scope.ID if manifest["schema"] == device_scope.ARCHIVE_SCHEMA else None)
    if (manifest["schema"] != schema or manifest["sourceOrigin"] != "local-import"
            or manifest["complete"] is not True or manifest["camera_io"] is not False
            or manifest["device_execution_ready"] is not False
            or manifest["mode_origin"] != "local-snapshot-file-stat-not-device-stat"
            or not isinstance(manifest["created_at"], str)):
        raise BackupError("Unsupported or incomplete local-import backup manifest")
    scope = _strict_object(manifest["scope"], {"id", "required_paths", "base_object_count", "not_covered"}, "scope")
    if (scope["id"] != scope_id or scope["required_paths"] != sorted(required)
            or scope["base_object_count"] != len(required) or scope["not_covered"] != _NOT_COVERED):
        raise BackupError("Backup required scope differs; partial snapshots are not complete backups")
    objects = manifest["objects"]
    if not isinstance(objects, list) or not len(required) <= len(objects) <= MAX_OBJECTS:
        raise BackupError("Backup object count is incomplete or exceeds the limit")
    paths, targets, bases, total = set(), set(), set(), 0
    for row in objects:
        _strict_object(row, {"path", "target_path", "kind", "state", "size", "sha256", "mode", "archive_path"}, "backup object")
        relative, target = _path(row["path"]), _target(row["target_path"])
        if relative.casefold() in paths:
            raise BackupError("Duplicate or case-colliding object path/target")
        _add_target(target, targets)
        paths.add(relative.casefold())
        if relative in required:
            base = required[relative]
            if row["kind"] != base["kind"] or target != base["target_path"] or row["state"] != "present":
                raise BackupError("Required object cannot be remapped or absent")
            bases.add(relative)
        elif (not relative.startswith("extras/") or row["kind"] not in ("audio", "loader", "extra")
              or row["state"] not in ("present", "absent")):
            raise BackupError("Unsupported extra object scope")
        _integer(row["size"], "object size", MAX_OBJECT_BYTES)
        if row["state"] == "absent":
            if any(row[name] is not None for name in ("sha256", "mode", "archive_path")) or row["size"] != 0:
                raise BackupError("Absent object must have no payload, mode or hash")
        else:
            if (not isinstance(row["sha256"], str) or not _SHA.fullmatch(row["sha256"])
                    or row["archive_path"] != "objects/" + relative
                    or (relative in required and row["size"] == 0)):
                raise BackupError("Invalid complete object identity or archive path")
            _integer(row["mode"], "object mode", 0o7777)
            total += row["size"]
    if bases != set(required) or total > MAX_TOTAL_BYTES:
        raise BackupError("Backup is incomplete or exceeds the 2 GiB limit")
    return objects


def _check_zip_envelope(stream: BinaryIO, size: int) -> None:
    """Bound the central directory before ZipFile allocates and parses it.

    This schema is capped below 4 GiB, so a multi-volume/ZIP64 end directory is
    unnecessary and rejected. ZIP64 local headers used by streaming writers
    remain supported. Comments are allowed; executable/SFX prefixes are not.
    """
    if not 22 <= size <= MAX_TOTAL_BYTES + 16 * MAX_MANIFEST_BYTES:
        raise BackupError("Archive file size is outside the supported limits")
    stream.seek(0)
    if stream.read(4) != b"PK\x03\x04":
        raise BackupError("Backup must start with a ZIP local file header")
    stream.seek(max(0, size - 65557))
    tail = stream.read(65557)
    position = tail.rfind(b"PK\x05\x06")
    if position < 0 or position + 22 > len(tail):
        raise BackupError("Invalid or truncated ZIP end directory")
    disk, directory_disk, disk_count, count, directory_size, directory_offset, comment_size = struct.unpack_from("<4H2IH", tail, position + 4)
    eocd_offset = size - len(tail) + position
    if (disk or directory_disk or disk_count != count or not 1 <= count <= MAX_OBJECTS + 1
            or not count * 46 <= directory_size <= MAX_CENTRAL_DIRECTORY_BYTES
            or directory_offset + directory_size != eocd_offset
            or position + 22 + comment_size != len(tail)):
        raise BackupError("Unsupported ZIP directory count, size, volume or trailing data")
    stream.seek(0)


@contextmanager
def _verified(archive_path: Path) -> Iterator[tuple[zipfile.ZipFile, dict, list[dict], dict]]:
    try:
        with _reader(archive_path) as (stream, archive_info):
            _check_zip_envelope(stream, archive_info.st_size)
            with zipfile.ZipFile(stream, "r") as archive:
                infos = archive.infolist()
                if not 1 <= len(infos) <= MAX_OBJECTS + 1:
                    raise BackupError("Invalid archive entry count")
                names, total = set(), 0
                for info in infos:
                    name = _path(info.filename, "archive member")
                    if name.casefold() in names:
                        raise BackupError("Duplicate or case-colliding archive member")
                    names.add(name.casefold())
                    mode = info.external_attr >> 16
                    if (info.is_dir() or info.flag_bits & 1 or info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                            or info.create_system != 3 or stat.S_IFMT(mode) not in (0, stat.S_IFREG)):
                        raise BackupError("Archive directories, symlinks, special or encrypted entries are not allowed")
                    limit = MAX_MANIFEST_BYTES if name == "manifest.json" else MAX_OBJECT_BYTES
                    if (info.file_size > limit or info.file_size > max(1, info.compress_size) * MAX_COMPRESSION_RATIO):
                        raise BackupError("Archive entry exceeds size/compression-ratio limits")
                    total += info.file_size
                    if total > MAX_TOTAL_BYTES + MAX_MANIFEST_BYTES:
                        raise BackupError("Archive exceeds the uncompressed total size limit")
                if "manifest.json" not in archive.namelist():
                    raise BackupError("Archive manifest is missing")
                raw = archive.read("manifest.json")
                manifest = _json(raw)
                objects = _validate_manifest(manifest)
                expected = {"manifest.json"} | {row["archive_path"] for row in objects if row["state"] == "present"}
                if set(archive.namelist()) != expected:
                    raise BackupError("Archive members differ from the complete manifest")
                for row in objects:
                    if row["state"] == "absent":
                        continue
                    info = archive.getinfo(row["archive_path"])
                    if info.file_size != row["size"] or (info.external_attr >> 16) & 0o7777 != row["mode"]:
                        raise BackupError(f"Archive object size/mode differs: {row['path']}")
                    with archive.open(info) as member:
                        size, digest = _hash(member)
                    if (size, digest) != (row["size"], row["sha256"]):
                        raise BackupError(f"Archive SHA-256 differs: {row['path']}")
                # Hash this same fd, not a second path lookup that could change.
                stream.seek(0)
                archive_size, archive_digest = _hash(stream, MAX_TOTAL_BYTES + 16 * MAX_MANIFEST_BYTES)
                receipt = {
                    "schema": "a7m4-backup-verification/1", "status": "VERIFIED_COMPLETE_LOCAL",
                    "verified": True, "complete": True, "restore_ready_local": True,
                    "device_execution_ready": False, "camera_io": False, "network_io": False,
                    "sourceOrigin": "local-import", "archive": str(archive_path.absolute()),
                    "archive_size": archive_size, "archive_sha256": archive_digest,
                    "manifest_sha256": hashlib.sha256(raw).hexdigest(),
                    "scope_id": manifest["scope"]["id"], "required_object_count": manifest["scope"]["base_object_count"],
                    "object_count": len(objects), "present_object_count": sum(row["state"] == "present" for row in objects),
                    "absent_object_count": sum(row["state"] == "absent" for row in objects),
                    "total_object_bytes": sum(row["size"] for row in objects),
                    "not_covered": list(_NOT_COVERED), "identification": _known_identity(objects),
                    "authentication": "none-unsigned-self-consistent-local-container",
                    "boundary": "Complete local originals for the declared file scope only; not proof of camera origin, compatible firmware, whole-chip backup or live restore readiness.",
                }
                yield archive, manifest, objects, receipt
    except BackupError:
        raise
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile, RuntimeError, EOFError, NotImplementedError, KeyError, zlib.error) as exc:
        raise BackupError(f"Invalid backup archive: {exc}") from exc


def verify_backup(archive: str | os.PathLike) -> dict:
    """Hash every complete payload and verify the fixed inventory without extraction."""
    with _verified(Path(archive)) as (_, _, _, receipt):
        return receipt


def _current_state(root: Path, row: dict) -> dict:
    path = _local(root, row["path"])
    if not path.exists():
        return {"state": "absent", "path": row["path"], "size": 0, "sha256": None, "mode": None}
    with _reader(path) as (stream, info):
        size, digest = _hash(stream)
    return {"state": "present", "path": row["path"], "size": size,
            "sha256": digest, "mode": stat.S_IMODE(info.st_mode)}


def _differences(archive: zipfile.ZipFile, row: dict, root: Path, current: dict) -> dict:
    if row["state"] == "absent" or current["state"] == "absent":
        return {"comparison": "presence-change" if row["state"] != current["state"] else "both-absent",
                "restore_size_delta": row["size"] - current["size"]}
    changed, ranges, active, offset = 0, [], None, 0
    current_digest = hashlib.sha256()
    with _reader(_local(root, row["path"])) as (source, _), archive.open(row["archive_path"]) as target:
        while True:
            left, right = source.read(CHUNK_BYTES), target.read(CHUNK_BYTES)
            if not left and not right:
                break
            current_digest.update(left)
            if left == right:
                if active is not None:
                    if len(ranges) < 4096:
                        ranges.append({"offset": active, "size": offset - active})
                    active = None
                offset += len(left)
                continue
            for index in range(max(len(left), len(right))):
                differs = index >= len(left) or index >= len(right) or left[index] != right[index]
                if differs:
                    changed += 1
                    if active is None:
                        active = offset + index
                elif active is not None:
                    if len(ranges) < 4096:
                        ranges.append({"offset": active, "size": offset + index - active})
                    active = None
            offset += max(len(left), len(right))
    if active is not None and len(ranges) < 4096:
        ranges.append({"offset": active, "size": offset - active})
    if current_digest.hexdigest() != current["sha256"]:
        raise BackupError(f"Current snapshot changed during diff: {row['path']}")
    return {"comparison": "complete-byte-comparison", "different_bytes": changed,
            "restore_size_delta": row["size"] - current["size"], "ranges": ranges,
            "range_list_may_be_truncated": len(ranges) == 4096,
            "current_mode": current["mode"], "restore_mode": row["mode"]}


def plan_restore(archive: str | os.PathLike, current_snapshot: str | os.PathLike) -> dict:
    """Describe exact full-object restoration against a complete local snapshot.

    Returns local source/target hashes, object presence, complete byte diffs and
    archive-member origins. No files are extracted or changed. An absence record
    restores absence only with an exact current identity, never wildcard removal.
    Device application/order/reload are explicitly not implemented here.
    """
    root = _root(current_snapshot)
    with _verified(Path(archive)) as (container, manifest, objects, receipt):
        required, _, _ = _scope_definition(device_scope.ID if manifest['schema'] == device_scope.ARCHIVE_SCHEMA else None)
        current_extras = _inventory(root, required)
        _snapshot(root, current_extras, required)
        archived_extras = {row["path"]: row for row in objects if row["path"] not in required}
        for row in current_extras:
            if row["path"] not in archived_extras or any(row[key] != archived_extras[row["path"]][key] for key in ("target_path", "kind")):
                raise BackupError(f"Current extra scope is not covered by this backup: {row['path']}")
        components = {}
        for row in objects:
            current = _current_state(root, row)
            if row["path"] in required and current["state"] != "present":
                raise BackupError(f"Current required object is absent: {row['path']}")
            if row["state"] == "absent":
                operation = "remove-exact-object" if current["state"] == "present" else "keep-absent"
            elif current["state"] == "absent":
                operation = "create-complete-object"
            else:
                operation = "unchanged" if (current["size"], current["sha256"], current["mode"]) == (row["size"], row["sha256"], row["mode"]) else "replace-complete-object"
            components[row["path"]] = {
                "target_path": row["target_path"], "kind": row["kind"], "operation": operation,
                "current": current,
                "restore": {"state": row["state"], "archive_member": row["archive_path"],
                            "size": row["size"], "sha256": row["sha256"], "mode": row["mode"]},
                "difference": _differences(container, row, root, current),
                "execution_requires_fresh_current_identity": True,
            }
        return {"schema": "a7m4-local-restore-plan/1", "status": "READY_LOCAL_RESTORE_PLAN",
                "verified": True, "complete": True, "restore_ready_local": True,
                "device_execution_ready": False, "camera_io": False, "network_io": False,
                "sourceOrigin": "local-import", "archive": receipt["archive"],
                "archive_sha256": receipt["archive_sha256"], "scope_id": receipt["scope_id"],
                "current_snapshot": str(root), "components": components,
                "changed_object_count": sum(row["operation"] not in ("unchanged", "keep-absent") for row in components.values()),
                "not_covered": manifest["scope"]["not_covered"],
                "execution": {"gate": "HELD", "apply_implemented": False,
                              "application_order_validated": False, "reload_validated": False,
                              "reason": "Local exact restoration description only; live transport, transaction order and device regression have not been authorized or run."}}
