"""Source-bound R066 PIN audio planning. All public operations are local only.

An accepted historical R066 endpoint is not an authorization to execute a new
dynamic plan. No transport, session, device discovery or network is imported.
"""
from __future__ import annotations

import copy
import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
from typing import Any, Mapping

from .offline import PlanError


SCHEMA = "a7m4-pin-install-plan/1"
ROLES = ("ap", "cp_program", "bank")
BASELINE = {
    "ap": {"size": 98212632, "sha256": "53fc8b67ecccce8ee8efe63c7d1d14e9db3e2e973ff45a60391b28346bc0a82f"},
    "cp_program": {"size": 16236816, "sha256": "43df121d66892f902bf5979992d3aa6741272bbf297c96ddfa41ae4d8054669e"},
    "bank": {"size": 108480, "sha256": "d8d7ce8eae9442c0c51c2f5bec608bc228d2acdf8bc5b69b484620b9c94bbe06"},
}
TARGET_PATHS = {"ap": "/usr/lib/appFw.so", "cp_program": "/cp/CPAPP-B.BIN", "bank": "/cp/SysSound.bin"}
AP_OFFSETS = (0x317C5F0, 0x317C5F4, 0x317C5F8, 0x317C5FC, 0x317C628, 0x317C62C, 0x317C630)
AP_BEFORE = tuple(bytes.fromhex(h) for h in (
    "08d885d2", "150887d2", "2800a0f2", "e80700f9", "00e08cd2", "2000a0f2", "151888d2"))
CUTOFF_OFFSET = 3182020
CUTOFF_BEFORE = bytes.fromhex("41ea0221")
CUTOFF_AFTER = bytes.fromhex("41f2a551")
CUTOFF_TARGET_SHA256 = "c0952e9d725d829df81058df21001a147e61268a2b3688e92b77666b7c4ebd1e"
SLOTS = {"ka": (0, 256), "sha": (77504, 15424), "kasha": (92928, 17600)}
OWNED_START = 77504
BANK_TARGET_SIZE = 110528
UPLOAD_LIMIT = 65536
MINIMUM_RESERVE = 8 * 1024 * 1024
SOURCE_OWNED_SHA256 = "e3f087c93181e38805ffd99bfe3cac709b2a4ee10d705be47137441245af11c6"
NATIVE_SOURCE_SHA256 = "4461e92ad1b683bc9e623e4e12892a177c6c83b5430e46de7ee06ef15ee07355"
# Offline hashes of every unchanged R066 range, independently pinned so a
# re-sealed, edited JSON plan cannot redefine the meaning of "complement".
ADMITTED_COMPLEMENTS = {
    "ap": [
        {"offset": 0, "size": 51889648, "sha256": "7af0feadca8f6547bdfd0f1e294e0402210fdbc12041f8784b140b644251a1a4"},
        {"offset": 51889664, "size": 40, "sha256": "74b70b3de815a502de0a90115a5e5c4cf09cf91bca0c94697529c78ee552e902"},
        {"offset": 51889716, "size": 46322916, "sha256": "84310206f7625552cd05136703dd2d8c36a4f3f2ea2631152f9dc7efa69effb5"}],
    "bank": [{"offset": 256, "size": 77248, "sha256": "618ba84677894adf2df99522c19e8464aa76b8ce8f45824d4cc4784b4f22dbdb"}],
    "cp_program": [
        {"offset": 0, "size": 3182020, "sha256": "8e07973bcb9657dd6c9197018d41e3a60ba8c5c5d0d4bb856617d92478a421cf"},
        {"offset": 3182024, "size": 13054792, "sha256": "da0bc5b091ff7b22feb72c0c74c235f287e8a5eaef68668adcabbfc62583fc7d"}],
}
PACK_HEADER = struct.Struct("<8s32sII")
REQUEST = struct.Struct("<8sII16s32s")


class PinPlanError(PlanError):
    """Invalid, unsupported or incomplete local PIN inputs."""


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise PinPlanError(message)


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    except (ValueError, TypeError, OverflowError) as exc:
        raise PinPlanError("plan must contain finite JSON values") from exc


def _read(value: Any, maximum: int, label: str) -> bytes:
    if type(value) is bytes:
        _need(len(value) <= maximum, label + " exceeds its size bound")
        return value
    _need(isinstance(value, (str, os.PathLike)), label + " must be complete bytes or a local path")
    path = Path(value)
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            _need(stat.S_ISREG(before.st_mode) and before.st_size <= maximum, label + " must be a bounded regular file")
            raw = stream.read(maximum + 1)
            after = os.fstat(stream.fileno())
            _need((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                  (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), label + " changed while reading")
            _need(len(raw) == before.st_size, label + " is incomplete")
            return raw
    except (OSError, ValueError) as exc:
        raise PinPlanError(label + ": " + str(exc)) from exc


def _identity(raw: bytes) -> dict[str, Any]:
    return {"size": len(raw), "sha256": _sha(raw)}


def _images(images: Mapping[str, Any]) -> dict[str, bytes]:
    _need(isinstance(images, Mapping) and set(images) == set(ROLES), "complete ap, cp_program and bank images are required")
    return {role: _read(images[role], max(BASELINE[role]["size"], BANK_TARGET_SIZE), role) for role in ROLES}


def _fresh(images: Mapping[str, Any]) -> dict[str, bytes]:
    raw = _images(images)
    for role in ROLES:
        _need(_identity(raw[role]) == BASELINE[role], "unsupported complete R066 identity: " + role)
    return raw


def _pack(prepared: Any) -> tuple[dict[str, Any], dict[str, bytes]]:
    if isinstance(prepared, (str, os.PathLike)):
        path = Path(prepared)
        path = path / "manifest.json" if path.is_dir() else path
        try:
            manifest = json.loads(_read(path, 2 * 1024 * 1024, "prepared manifest"))
        except (ValueError, UnicodeError) as exc:
            raise PinPlanError("invalid prepared manifest JSON") from exc
        base = path.absolute().parent
    else:
        _need(isinstance(prepared, Mapping), "prepared pack must be a manifest path or mapping")
        manifest = dict(prepared)
        _need(isinstance(manifest.get("output_dir"), str), "in-memory prepared manifest requires output_dir")
        base = Path(manifest["output_dir"]).absolute()
    _need(manifest.get("schema") == "a7m4-prepared-pin-sound-pack/1", "unsupported prepared PIN pack schema")
    native = manifest.get("native")
    _need(isinstance(native, dict) and set(native) == {"ka", "sha", "kasha"}, "three complete native clips required")
    data: dict[str, bytes] = {}
    for role, (offset, capacity) in SLOTS.items():
        entry = native[role]
        _need(isinstance(entry, dict), "invalid native clip entry: " + role)
        name = entry.get("file")
        _need(isinstance(name, str) and name and not Path(name).is_absolute() and "\\" not in name and
              all(part not in ("", ".", "..") for part in name.split("/")), "native file must be a safe relative path")
        # Resolve every parent before opening, preventing a symlinked directory escape.
        path = base / name
        _need(path.resolve().is_relative_to(base.resolve()), "native file escapes prepared pack")
        value = _read(path, capacity, role + " native data")
        actual = entry.get("actual_bytes")
        _need(type(actual) is int and 0 < actual <= capacity and actual % 64 == 0 and len(value) == actual,
              role + " actual encoded length must be positive, 64-byte aligned and fit its reserved slot")
        _need(entry.get("sha256") == _sha(value), role + " native SHA-256 mismatch")
        _need(entry.get("offset", offset) == offset and entry.get("slot_capacity", capacity) == capacity,
              role + " reserved slot differs from the admitted layout")
        # Filter0 has no predictor bit; its low nibble is exponent 0..8.
        _need(all(value[index] <= 8 for index in range(0, len(value), 32)), role + " is not filter0 native audio")
        data[role] = value
    return manifest, data


def _movz(register: int, immediate: int) -> bytes:
    _need(0 <= immediate <= 65535, "AArch64 immediate outside admitted 16-bit range")
    return struct.pack("<I", 0xD2800000 | (immediate << 5) | register)


def _ap_after(lengths: Mapping[str, int]) -> tuple[bytes, ...]:
    return (_movz(8, 77504 & 65535), _movz(21, lengths["sha"]), AP_BEFORE[2], AP_BEFORE[3],
            _movz(0, 92928 & 65535), AP_BEFORE[5], _movz(21, lengths["kasha"]))


def _component(role: str, before: bytes, after: bytes, ranges: list[tuple[int, int]]) -> dict[str, Any]:
    windows = []
    complement = []
    cursor = 0
    for offset, size in sorted(ranges):
        _need(cursor <= offset and size > 0 and offset + size <= min(len(before), len(after)), "invalid exact window")
        if offset > cursor:
            complement.append({"offset": cursor, "size": offset - cursor, "sha256": _sha(before[cursor:offset])})
            _need(before[cursor:offset] == after[cursor:offset], "undeclared complement changed")
        windows.append({"offset": offset, "size": size, "before_hex": before[offset:offset + size].hex(),
                        "after_hex": after[offset:offset + size].hex()})
        cursor = offset + size
    common = min(len(before), len(after))
    if cursor < common:
        complement.append({"offset": cursor, "size": common - cursor, "sha256": _sha(before[cursor:common])})
        _need(before[cursor:common] == after[cursor:common], "undeclared complement changed")
    return {"path": TARGET_PATHS[role], "source": _identity(before), "target": _identity(after), "windows": windows,
            "append_hex": after[len(before):].hex(), "truncate_to": len(after),
            "tail_before_truncate_hex": before[len(after):].hex(), "complement": complement}


def _seal(plan: dict[str, Any]) -> dict[str, Any]:
    plan["plan_id"] = _sha(_canonical({k: v for k, v in plan.items() if k != "plan_id"}))
    return plan


def plan_pin_install(fresh_images: Mapping[str, Any], prepared_pack: Any, requested_cutoff: Any = None) -> dict[str, Any]:
    """Plan only from the complete accepted R066 AP, CP-program and sound bank.

    requested_cutoff is None (leave current near-1/8 logic unchanged), 50, or
    exactly 1/50 (0.02). Other firmware cutoff values are unsupported. The pack's
    Mac pair delay never implicitly requests a CP-program write.
    """
    source = _fresh(fresh_images)
    manifest, clips = _pack(prepared_pack)
    change_cutoff = requested_cutoff is not None
    if change_cutoff:
        _need(type(requested_cutoff) in (int, float) and requested_cutoff in (50, 0.02),
              "only the separately requested exact 1/50 cutoff candidate is supported")
    lengths = {role: len(raw) for role, raw in clips.items()}
    controls = manifest.get("controls", {})
    _need(isinstance(controls, dict), "prepared pack controls must be an object")
    preview_cutoff = controls.get("cutoff_seconds")
    if preview_cutoff is not None:
        _need(type(preview_cutoff) in (int, float) and 0 < preview_cutoff <= 3600 and math.isfinite(preview_cutoff),
              "prepared preview cutoff must be positive and finite")
    planned_nominal = 0.02 if change_cutoff else 0.125
    preview_matches = None if preview_cutoff is None else preview_cutoff == planned_nominal
    ap = bytearray(source["ap"])
    for offset, before, after in zip(AP_OFFSETS, AP_BEFORE, _ap_after(lengths)):
        _need(ap[offset:offset + 4] == before, "R066 AP descriptor preimage differs")
        ap[offset:offset + 4] = after
    bank = bytearray(source["bank"][:OWNED_START])
    bank.extend(bytes(BANK_TARGET_SIZE - OWNED_START))
    for role, (offset, capacity) in SLOTS.items():
        bank[offset:offset + capacity] = clips[role] + bytes(capacity - len(clips[role]))
    cp = bytearray(source["cp_program"])
    if change_cutoff:
        _need(cp[CUTOFF_OFFSET:CUTOFF_OFFSET + 4] == CUTOFF_BEFORE, "CP cutoff preimage differs")
        cp[CUTOFF_OFFSET:CUTOFF_OFFSET + 4] = CUTOFF_AFTER
        _need(_sha(cp) == CUTOFF_TARGET_SHA256, "CP cutoff target differs from the admitted complete candidate")
    target = {"ap": bytes(ap), "cp_program": bytes(cp), "bank": bytes(bank)}
    ranges = {"ap": [(offset, 4) for offset in AP_OFFSETS],
              "cp_program": [(CUTOFF_OFFSET, 4)] if change_cutoff else [],
              "bank": [(0, 256), (OWNED_START, len(source["bank"]) - OWNED_START)]}
    plan = {"schema": SCHEMA, "profile": "ILCE-7M4-6.02-R066-PIN", "direction": "forward",
            "status": "PLANNED_OFFLINE", "source_origin": "local-import", "camera_io": False,
            "network_io": False, "device_execution_ready": False, "deployment_authorized": False,
            "device_execution_state": "HELD", "dynamic_layout_device_validated": False,
            "historical_R066_physical_acceptance": True,
            "components": {role: _component(role, source[role], target[role], ranges[role]) for role in ROLES},
            "native": {role: {"actual_bytes": lengths[role], "sha256": _sha(clips[role]),
                              "offset": SLOTS[role][0], "slot_capacity": SLOTS[role][1],
                              "playback_descriptor_bytes": 256 if role == "ka" else lengths[role]} for role in clips},
            "prepared_pack_sha256": _sha(_canonical(manifest)),
            "cutoff": {"requested": "1/50" if change_cutoff else None,
                       "source_installed": "approximately-1/8", "camera_changed": False,
                       "planned_target": "1/50-offline-candidate" if change_cutoff else "unchanged-approximately-1/8",
                       "planned_cutoff_nominal_seconds": planned_nominal,
                       "preview_cutoff_seconds": preview_cutoff,
                       "preview_matches_planned_installed_cutoff": preview_matches,
                       "requires_cutoff_difference_notice": preview_matches is not True,
                       "candidate_actual_threshold_seconds": 0.019990643867276083 if change_cutoff else None,
                       "installed_cutoff_observed_this_run": False,
                       "candidate_device_validated": False, "independent_of_pair_delay": True},
            "protected_bank": {"offset": 256, "size": OWNED_START - 256,
                               "sha256": _sha(source["bank"][256:OWNED_START])},
            "helper_contract": _helper_contract(change_cutoff),
            "space_budget": {"evaluated": False, "fresh_jiritsu_measurement_required": True,
                             "each_upload_strictly_less_than_bytes": UPLOAD_LIMIT,
                             "minimum_jiritsu_remaining_bytes": MINIMUM_RESERVE,
                             "cp_growth_bytes": BANK_TARGET_SIZE - len(source["bank"]),
                             "cp_capacity_rule": "fresh VFAT bavail >= growth clusters + 2 reserve clusters",
                             "whole_images_staged_in_jiritsu": False},
            "limits": ["Ka AP descriptor stays at its admitted 256 bytes; shorter Ka is padded with legal zero blocks.",
                       "The new 110528-byte layout and arbitrary dynamic clips have not been deployed or physically accepted.",
                       "Complete AP/CP/bank SHA and complements are verified on the Mac; a worker receipt is insufficient."]}
    return _seal(plan)


def _helper_contract(cutoff: bool) -> dict[str, Any]:
    return {"schema": "a7m4-pin-helper-contract/1", "source_identical_AP_private_COW": True,
            "AP_COW_offsets": list(AP_OFFSETS), "semantic_runtime_memory_change": False,
            "CP_program_cutoff_write": cutoff, "persistent_targets": list(TARGET_PATHS.values()),
            "forward_phases": ["inspect-source", "verify-unique-nonce-and-plan", "fresh-space-and-FD-identity",
                               "source-identical-AP-private-COW", "write-bank-owned-ranges", "bank-fsync",
                               "bank-exact-readback", "patch-AP-descriptors", "AP-fsync-readback",
                               "optional-independent-CP-cutoff", "full-Mac-readback", "exact-owned-cleanup"],
            "inverse_phases": ["inspect-exact-target", "new-unique-nonce-and-plan", "source-identical-AP-private-COW",
                               "restore-AP-descriptors", "AP-fsync-readback", "restore-CP-cutoff-if-selected",
                               "restore-owned-bank-data", "truncate-to-exact-source-size", "bank-fsync-readback",
                               "full-Mac-readback", "exact-owned-cleanup"],
            "nonce_bytes": 16, "request_bytes": REQUEST.size, "request_binds_full_plan_id": True,
            "nonce_policy": "fresh nonzero nonce per exact phase; no reuse within a session",
            "unknown_result": "STOP_UNKNOWN; no automatic retry, replay, inverse or success",
            "failure_policy": "only known complete native outcomes may enter an explicitly bound inverse; unknown is held",
            "fresh_runtime_prerequisites": ["AP55 exactly 02 (read only)", "/usr/share/avsystemsound/custom.txt absent",
                                           "exact model/version and new complete source readback", "private AP mappings match open AP dev/inode",
                                           "fresh /tmp/jiritsu free reserve >=8MiB after all uploads", "fresh /cp growth capacity"],
            "full_readback_location": "Mac", "CSV_writes": False, "settings_writes": False,
            "AP55_writes": False, "NOR_writes": False, "WBI_writes": False, "device_executor_included": False}


def _validate_plan(plan: Any) -> None:
    try:
        _validate_plan_structure(plan)
    except PinPlanError:
        raise
    except (KeyError, ValueError, TypeError, IndexError, OverflowError) as exc:
        raise PinPlanError("malformed exact PIN plan") from exc


def _validate_plan_structure(plan: Any) -> None:
    _need(isinstance(plan, dict) and plan.get("schema") == SCHEMA, "invalid PIN plan schema")
    _need(plan.get("plan_id") == _sha(_canonical({k: v for k, v in plan.items() if k != "plan_id"})), "PIN plan identity changed")
    _need(plan.get("direction") in ("forward", "inverse"), "invalid PIN direction")
    _need(plan.get("camera_io") is False and plan.get("network_io") is False and
          plan.get("deployment_authorized") is False and plan.get("device_execution_ready") is False and
          plan.get("device_execution_state") == "HELD", "PIN plan escaped local HELD scope")
    _need(plan.get("dynamic_layout_device_validated") is False, "dynamic device acceptance is not established")
    _need(set(plan.get("components", {})) == set(ROLES), "complete three-component plan required")
    forward = plan["direction"] == "forward"
    for role, component in plan["components"].items():
        _need(component.get("path") == TARGET_PATHS[role], "foreign persistent target")
        _need(component["source" if forward else "target"] == BASELINE[role], "PIN plan does not bind the admitted complete R066 source")
        if role != "bank":
            _need(component["source"]["size"] == component["target"]["size"] == BASELINE[role]["size"] and
                  component["append_hex"] == component["tail_before_truncate_hex"] == "",
                  "AP/CP program append or truncation is forbidden")
    windows = plan["components"]["ap"]["windows"]
    _need(len(windows) == 7, "all seven admitted AP descriptor words required")
    lengths = {role: plan["native"][role]["actual_bytes"] for role in SLOTS}
    for role, length in lengths.items():
        _need(type(length) is int and 0 < length <= SLOTS[role][1] and length % 64 == 0, "invalid native actual length")
    for window, offset, before, after in zip(windows, AP_OFFSETS, AP_BEFORE, _ap_after(lengths)):
        _need(window == {"offset": offset, "size": 4, "before_hex": (before if forward else after).hex(),
                         "after_hex": (after if forward else before).hex()}, "AP window escaped the reviewed descriptor whitelist")
    cp_windows = plan["components"]["cp_program"]["windows"]
    selected = plan["cutoff"]["requested"] == "1/50"
    _need(plan["helper_contract"] == _helper_contract(selected), "helper contract differs from the fixed safety scope")
    _need(plan["cutoff"]["requested"] in (None, "1/50"), "unsupported firmware cutoff")
    nominal = 0.02 if selected and forward else 0.125
    preview = plan["cutoff"]["preview_cutoff_seconds"]
    _need(preview is None or type(preview) in (int, float) and 0 < preview <= 3600 and math.isfinite(preview), "invalid preview cutoff")
    match = None if preview is None else preview == nominal
    _need(plan["cutoff"]["planned_cutoff_nominal_seconds"] == nominal and
          plan["cutoff"]["preview_matches_planned_installed_cutoff"] is match and
          plan["cutoff"]["requires_cutoff_difference_notice"] is (match is not True) and
          plan["cutoff"]["source_installed"] == "approximately-1/8" and
          plan["cutoff"]["camera_changed"] is False and plan["cutoff"]["candidate_device_validated"] is False and
          plan["cutoff"]["installed_cutoff_observed_this_run"] is False, "cutoff preview/installed-state boundary changed")
    expected = [{"offset": CUTOFF_OFFSET, "size": 4,
                 "before_hex": (CUTOFF_BEFORE if forward else CUTOFF_AFTER).hex(),
                 "after_hex": (CUTOFF_AFTER if forward else CUTOFF_BEFORE).hex()}] if selected else []
    _need(cp_windows == expected, "CP windows escaped the independent cutoff candidate")
    if selected:
        _need(plan["components"]["cp_program"]["target" if forward else "source"]["sha256"] == CUTOFF_TARGET_SHA256,
              "foreign complete cutoff target")
    else:
        _need(plan["components"]["cp_program"]["target"] == BASELINE["cp_program"], "unselected CP program must remain exactly unchanged")
    for role in ROLES:
        expected_complement = ADMITTED_COMPLEMENTS[role]
        if role == "cp_program" and not selected:
            expected_complement = [{"offset": 0, **BASELINE[role]}]
        _need(plan["components"][role]["complement"] == expected_complement, "complement differs from admitted complete R066 ranges: " + role)
    bank = plan["components"]["bank"]
    _need(plan["protected_bank"] == ADMITTED_COMPLEMENTS["bank"][0], "protected bank metadata changed")
    _need(bank["target" if forward else "source"]["size"] == BANK_TARGET_SIZE, "bank escaped its fixed owned-tail layout")
    _need([(w["offset"], w["size"]) for w in bank["windows"]] ==
          [(0, 256), (OWNED_START, BASELINE["bank"]["size"] - OWNED_START)], "bank write touches a protected range")
    for role, component in plan["components"].items():
        for window in component["windows"]:
            _need(len(bytes.fromhex(window["before_hex"])) == len(bytes.fromhex(window["after_hex"])) == window["size"], "invalid exact preimage length")
        _need(component["truncate_to"] == component["target"]["size"], "wrong final file size")
    bank_growth = BANK_TARGET_SIZE - BASELINE["bank"]["size"]
    _need(len(bytes.fromhex(bank["append_hex" if forward else "tail_before_truncate_hex"])) == bank_growth and
          bank["tail_before_truncate_hex" if forward else "append_hex"] == "", "invalid exact owned-tail growth/inverse")
    target_owned = b"".join(bytes.fromhex(w["after_hex" if forward else "before_hex"]) for w in bank["windows"])
    target_owned += bytes.fromhex(bank["append_hex" if forward else "tail_before_truncate_hex"])
    source_owned = b"".join(bytes.fromhex(w["before_hex" if forward else "after_hex"]) for w in bank["windows"])
    _need(_sha(source_owned) == SOURCE_OWNED_SHA256, "original R066 owned preimage changed; inverse would not restore the admitted source")
    for role, (offset, capacity) in SLOTS.items():
        at = 0 if role == "ka" else 256 + offset - OWNED_START
        slot = target_owned[at:at + capacity]
        actual = lengths[role]
        _need(len(slot) == capacity and _sha(slot[:actual]) == plan["native"][role]["sha256"] and
              slot[actual:] == bytes(capacity - actual) and all(slot[i] <= 8 for i in range(0, actual, 32)),
              "bank payload no longer matches validated filter0 clip or zero-padded slot: " + role)
        _need(plan["native"][role]["offset"] == offset and plan["native"][role]["slot_capacity"] == capacity and
              plan["native"][role]["playback_descriptor_bytes"] == (256 if role == "ka" else actual), "native descriptor metadata changed")


def verify_full_readback(plan: dict[str, Any], fresh_after_images: Mapping[str, Any], direction: str = "forward") -> dict[str, Any]:
    """Require every full SHA and every unchanged complement, including CP code."""
    _validate_plan(plan)
    _need(direction in ("forward", "source", "inverse"), "readback direction must be forward, source or inverse")
    endpoint = "target" if direction == "forward" else "source"
    images = _images(fresh_after_images)
    identities = {}
    for role in ROLES:
        component = plan["components"][role]
        _need(_identity(images[role]) == component[endpoint], "complete readback identity differs: " + role)
        for window in component["windows"]:
            start, size = window["offset"], window["size"]
            expected = bytes.fromhex(window["after_hex" if endpoint == "target" else "before_hex"])
            _need(images[role][start:start + size] == expected, "exact readback window differs: " + role)
        if endpoint == "target" and component["append_hex"]:
            _need(images[role][component["source"]["size"]:] == bytes.fromhex(component["append_hex"]), "exact appended readback differs: " + role)
        if endpoint == "source" and component["tail_before_truncate_hex"]:
            _need(images[role][component["target"]["size"]:] == bytes.fromhex(component["tail_before_truncate_hex"]), "exact inverse source tail differs: " + role)
        for region in component["complement"]:
            start, size = region["offset"], region["size"]
            _need(_sha(images[role][start:start + size]) == region["sha256"], "readback complement differs: " + role)
        identities[role] = _identity(images[role])
    return {"schema": "a7m4-pin-full-readback/1", "verified": True, "complete": True,
            "plan_id": plan["plan_id"], "endpoint": endpoint, "images": identities,
            "complement_verified": True, "verification_origin": "local-import-full-images",
            "camera_io": False, "network_io": False, "device_execution_ready": False,
            "device_execution_state": "HELD", "physical_acceptance_claimed": False}


def materialize_pin_plan(plan: dict[str, Any], fresh_images: Mapping[str, Any]) -> dict[str, bytes]:
    """Return full local bytes without writing any image or accessing a camera."""
    verify_full_readback(plan, fresh_images, "source")
    source = _images(fresh_images)
    result = {}
    for role in ROLES:
        component = plan["components"][role]
        target = bytearray(source[role])
        for window in component["windows"]:
            offset, size = window["offset"], window["size"]
            _need(target[offset:offset + size] == bytes.fromhex(window["before_hex"]), "exact source preimage differs")
            target[offset:offset + size] = bytes.fromhex(window["after_hex"])
        target.extend(bytes.fromhex(component["append_hex"]))
        if len(target) > component["truncate_to"]:
            _need(target[component["truncate_to"]:] == bytes.fromhex(component["tail_before_truncate_hex"]), "exact truncated tail differs")
            del target[component["truncate_to"]:]
        result[role] = bytes(target)
    verify_full_readback(plan, result)
    return result


def plan_pin_inverse(plan: dict[str, Any], fresh_current_images: Mapping[str, Any]) -> dict[str, Any]:
    """Bind an exact inverse to newly imported complete target images."""
    _validate_plan(plan)
    _need(plan["direction"] == "forward", "inverse requires the original forward plan")
    verify_full_readback(plan, fresh_current_images)
    inverse = copy.deepcopy(plan)
    inverse["direction"] = "inverse"
    inverse["inverse_of"] = plan["plan_id"]
    for component in inverse["components"].values():
        component["source"], component["target"] = component["target"], component["source"]
        for window in component["windows"]:
            window["before_hex"], window["after_hex"] = window["after_hex"], window["before_hex"]
        component["append_hex"], component["tail_before_truncate_hex"] = component["tail_before_truncate_hex"], component["append_hex"]
        component["truncate_to"] = component["target"]["size"]
    inverse["space_budget"]["cp_growth_bytes"] = 0
    inverse["cutoff"]["planned_target"] = "restore-approximately-1/8"
    inverse["cutoff"]["planned_cutoff_nominal_seconds"] = 0.125
    inverse["cutoff"]["candidate_actual_threshold_seconds"] = None
    preview = inverse["cutoff"]["preview_cutoff_seconds"]
    match = None if preview is None else preview == 0.125
    inverse["cutoff"]["preview_matches_planned_installed_cutoff"] = match
    inverse["cutoff"]["requires_cutoff_difference_notice"] = match is not True
    return _seal(inverse)


def make_pin_request(plan: dict[str, Any], mode: int, nonce: bytes) -> bytes:
    _validate_plan(plan)
    _need(type(mode) is int and mode in (0, 1, 2, 3), "mode must be inspect-source/apply/inverse/inspect-target")
    _need(type(nonce) is bytes and len(nonce) == 16 and any(nonce), "fresh nonzero 16-byte nonce required")
    return REQUEST.pack(b"M4PIN001", mode, 0, nonce, bytes.fromhex(plan["plan_id"]))


def _save(path: Path, raw: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def build_pin_workers(plan: dict[str, Any], output_dir: Any = None, *, compiler: Any = None) -> dict[str, Any]:
    """Build bounded owned-data packets; a missing adapter/compiler is blocked.

    No worker is claimed deployable without a real native binary and ABI check.
    All output is private local material. This function never uploads anything.
    """
    _validate_plan(plan)
    _need(plan["direction"] == "forward", "build from the forward plan; bundle contains both directions")
    bank = plan["components"]["bank"]
    source_data = b"".join(bytes.fromhex(w["before_hex"]) for w in bank["windows"])
    target_data = b"".join(bytes.fromhex(w["after_hex"]) for w in bank["windows"]) + bytes.fromhex(bank["append_hex"])
    packets = {}
    prefix = "m4.pin." + plan["plan_id"][:16]
    for index, (name, data) in enumerate((("source", source_data), ("target", target_data))):
        raw = PACK_HEADER.pack(b"M4PIND01", bytes.fromhex(plan["plan_id"]), index, len(data)) + data
        _need(0 < len(raw) < UPLOAD_LIMIT, "owned-data packet exceeds the strict upload limit")
        filename = prefix + "." + name + ".bin"
        packets[name] = {"file": filename, "upload_path": "/tmp/jiritsu/" + filename,
                         "size": len(raw), "sha256": _sha(raw), "data": raw}
    result = {"schema": "a7m4-pin-worker-bundle/1", "plan_id": plan["plan_id"],
              "status": "BLOCKED_DYNAMIC_NATIVE_ADAPTER", "worker_built": False,
              "camera_io": False, "network_io": False, "device_execution_ready": False,
              "deployment_authorized": False, "device_execution_state": "HELD", "dynamic_device_validation": "NOT_PERFORMED",
              "packets": {k: {n: v for n, v in row.items() if n != "data"} for k, row in packets.items()},
              "helper_contract": plan["helper_contract"], "blockers": [],
              "each_upload_strictly_less_than_bytes": UPLOAD_LIMIT, "minimum_jiritsu_remaining_bytes": MINIMUM_RESERVE,
              "fresh_budget_verified": False, "unknown_result_policy": "STOP_UNKNOWN_NO_REPLAY"}
    if output_dir is None:
        result["blockers"] = ["new private output directory and offline compiler are required to build artifacts"]
        return result
    directory = Path(output_dir).absolute()
    _need(not directory.exists() and directory.parent.is_dir() and not any(p.is_symlink() for p in (directory, *directory.parents)), "new non-symlink output directory required")
    directory.mkdir(mode=0o700)
    for packet in packets.values():
        _save(directory / packet["file"], packet["data"])
    result["output_dir"] = str(directory)
    source_path = Path(__file__).with_name("data") / "pin-sound-dynamic.c"
    canonical_source = Path(__file__).resolve().parents[2] / "native" / "pin-sound-dynamic" / "program.c"
    if not source_path.is_file():
        source_path = canonical_source
    if not source_path.is_file():
        result["blockers"] = ["dynamic native worker source is not yet available; fixed R066 worker cannot accept arbitrary packets"]
    elif _sha(source_path.read_bytes()) != NATIVE_SOURCE_SHA256 or (canonical_source.is_file() and _sha(canonical_source.read_bytes()) != NATIVE_SOURCE_SHA256):
        result["status"] = "BLOCKED_NATIVE_SOURCE_BINDING"
        result["blockers"] = ["packaged/canonical native source differs from the reviewed request/ABI/source contract"]
    elif plan["cutoff"]["requested"] is not None:
        result["status"] = "BLOCKED_INDEPENDENT_CUTOFF_WORKER"
        result["blockers"] = ["sound worker does not write CP-program; optional 1/50 requires a separate reviewed adapter"]
    else:
        _compile_worker(plan, packets, directory, source_path, compiler, result)
    _save(directory / "bundle.json", _canonical(result) + b"\n")
    return result


def _compile_worker(plan: dict[str, Any], packets: dict[str, Any], directory: Path,
                    source_path: Path, compiler: Any, result: dict[str, Any]) -> None:
    if compiler is None:
        compiler = shutil.which("zig")
    if compiler is None:
        result["status"] = "BLOCKED_COMPILER_UNAVAILABLE"
        result["blockers"] = ["offline Zig 0.13.0 is required; no download is attempted"]
        return
    command = [os.fspath(compiler)] if isinstance(compiler, (str, os.PathLike)) else list(compiler)
    _need(command and all(isinstance(item, str) and item for item in command), "explicit compiler command required")
    source = source_path.read_bytes()
    _need(_sha(source) == NATIVE_SOURCE_SHA256, "native source no longer matches the reviewed contract")
    def array(raw: bytes) -> str:
        return "{" + ",".join(str(value) for value in raw) + "}"
    lines = ["/* Generated from an exact local R066 plan. No device authorization. */",
             "struct Window {u64 offset;u32 length,chip;const u8 *before,*after;};"]
    for index, window in enumerate(plan["components"]["ap"]["windows"]):
        for side in ("before", "after"):
            lines.append("static const u8 %s_%d[]=%s;" % (side, index, array(bytes.fromhex(window[side + "_hex"]))))
    lines.append("static const struct Window windows[]={" + ",".join(
        "{%dUL,4,0,before_%d,after_%d}" % (offset, index, index) for index, offset in enumerate(AP_OFFSETS)) + "};")
    lines.extend(["static const u32 window_count=7;",
                  "static const u64 file_sizes[]={98212632UL,108480UL};",
                  "static const u8 plan_id[32]=" + array(bytes.fromhex(plan["plan_id"])) + ";",
                  "static const u8 protected_bank_sha[32]=" + array(bytes.fromhex(ADMITTED_COMPLEMENTS["bank"][0]["sha256"])) + ";"])
    for name, packet in packets.items():
        lines.extend(["static const u32 %s_packet_bytes=%d;" % (name, packet["size"]),
                      "static const u8 %s_packet_sha[32]=%s;" % (name, array(bytes.fromhex(packet["sha256"]))),
                      'static const char %s_packet_path[]="/tmp/jiritsu/%s";' % (name, packet["file"])])
    header = ("\n".join(lines) + "\n").encode()
    _save(directory / "patch_manifest.h", header)
    environment = dict(os.environ, ZIG_GLOBAL_CACHE_DIR=str(directory / "zig-cache-global"),
                       ZIG_LOCAL_CACHE_DIR=str(directory / "zig-cache-local"))
    try:
        version = subprocess.run(command + ["version"], capture_output=True, text=True, check=True, timeout=30, env=environment).stdout.strip()
        _need(version == "0.13.0", "offline native build requires reviewed Zig 0.13.0")
        common = command + ["cc", "-target", "aarch64-linux-gnu", "-std=c11", "-O2", "-ffreestanding", "-fno-builtin", "-I", str(directory)]
        abi = directory / "target-abi.o"
        subprocess.run(common + ["-DM4_FL23_TARGET_ABI_CHECK", "-c", str(source_path), "-o", str(abi)],
                       capture_output=True, check=True, timeout=180, env=environment)
        abi.chmod(0o600)
        flags = ["-Wall", "-Wextra", "-Werror", "-shared", "-fPIC", "-fno-stack-protector", "-fno-unwind-tables",
                 "-fno-asynchronous-unwind-tables", "-nostdlib", "-g0", "-Wl,--strip-debug", "-Wl,--no-undefined",
                 "-Wl,--build-id=none", "-Wl,-Bsymbolic", "-Wl,-z,noexecstack"]
        binaries = []
        for filename in ("pin-worker.so", "pin-worker-repeat.so"):
            output = directory / filename
            subprocess.run(common + flags + [str(source_path), "-o", str(output)], capture_output=True,
                           check=True, timeout=180, env=environment)
            output.chmod(0o600)
            raw = output.read_bytes()
            _need(0 < len(raw) < UPLOAD_LIMIT, "native worker exceeds the strict upload bound")
            _validate_elf(raw)
            binaries.append(raw)
        _need(binaries[0] == binaries[1] and source_path.read_bytes() == source, "native double build/source reproducibility failed")
    except (OSError, subprocess.SubprocessError, PinPlanError) as exc:
        result["status"] = "BLOCKED_NATIVE_BUILD"
        detail = getattr(exc, "stderr", "") or str(exc)
        if isinstance(detail, bytes):
            detail = detail.decode(errors="replace")
        result["blockers"] = [str(detail)[-3000:]]
        return
    result.update(status="BUILT_OFFLINE_NOT_DEVICE_VALIDATED", worker_built=True, blockers=[],
                  worker={"file": "pin-worker.so", "size": len(binaries[0]), "sha256": _sha(binaries[0]),
                          "upload_path": "/tmp/jiritsu/libJit.so",
                          "source_sha256": _sha(source), "header_sha256": _sha(header),
                          "target_abi_sha256": _sha(abi.read_bytes()), "compiler": "Zig 0.13.0",
                          "double_build_identical": True, "elf": _validate_elf(binaries[0])},
                  request={"file": "/tmp/jiritsu/m4.pin-dynamic.request", "bytes": REQUEST.size},
                  report={"file": "/tmp/jiritsu/m4.pin-dynamic.result", "bytes": 184},
                  native_failure_policy="no automatic failure inverse; preserve partial evidence and STOP_UNKNOWN",
                  forward_modes=[0, 1, 3], inverse_modes=[3, 2, 0],
                  total_staged_upload_bytes=sum(row["size"] for row in packets.values()) + len(binaries[0]) + REQUEST.size,
                  minimum_jiritsu_preupload_free_bytes=MINIMUM_RESERVE + sum(
                      ((size + 65535) // 65536) * 65536 for size in
                      [*(row["size"] for row in packets.values()), len(binaries[0]), REQUEST.size, 184]),
                  allocation_budget={"allocation_unit_assumed_upper_bound": 65536,
                                     "each_staged_file_rounded_independently": True,
                                     "includes_final_report_allocation": True,
                                     "fresh_actual_statfs_and_existing_owned_files_required": True})


def _validate_elf(raw: bytes) -> dict[str, Any]:
    _need(len(raw) >= 64 and raw[:6] == b"\x7fELF\x02\x01", "worker must be ELF64 little endian")
    fields = struct.unpack_from("<16sHHIQQQIHHHHHH", raw)
    _need(fields[1] == 3 and fields[2] == 183 and fields[9] == 56, "worker must be an AArch64 shared ELF")
    offset, count = fields[5], fields[10]
    _need(0 < count < 128 and offset + count * 56 <= len(raw), "invalid ELF program headers")
    stack_seen = False
    for index in range(count):
        kind, flags, start, _, _, size, _, _ = struct.unpack_from("<IIQQQQQQ", raw, offset + index * 56)
        _need(start + size <= len(raw), "ELF segment extends outside the file")
        _need(not (kind == 1 and flags & 3 == 3), "worker contains a writable executable load segment")
        if kind == 0x6474E551:
            _need(not flags & 1, "worker requests an executable stack")
            stack_seen = True
        if kind == 2:
            _need(size % 16 == 0, "invalid ELF dynamic table")
            for at in range(start, start + size, 16):
                tag, _ = struct.unpack_from("<qQ", raw, at)
                _need(tag != 1, "worker has an external dynamic dependency")
    _need(stack_seen, "worker lacks explicit non-executable-stack metadata")
    return {"class": "ELF64", "machine": "AArch64", "type": "shared", "external_dependencies": False, "executable_stack": False}


class PinWorkerProtocol:
    """Finite request/receipt guard with no channel or device methods.

    A receipt checks only native completion. Full Mac readback remains mandatory
    before ``confirm_readback`` can finish this local protocol record.
    """
    def __init__(self, plan: dict[str, Any], *, inverse: bool = False):
        _validate_plan(plan)
        _need(plan["direction"] == "forward" and type(inverse) is bool, "protocol requires original forward plan")
        self.plan = copy.deepcopy(plan)
        self.sequence = [3, 2, 0] if inverse else [0, 1, 3]
        self.step = 0
        self.nonces: set[bytes] = set()
        self.pending: tuple[int, bytes] | None = None
        self.failed = False
        self.finished = False
        self.file_identities: tuple[int, ...] | None = None

    def request(self, mode: int, nonce: bytes) -> bytes:
        _need(not self.failed and not self.finished and self.pending is None and self.step < 3, "protocol is held, pending, or ended")
        _need(type(nonce) is bytes, "fresh nonzero 16-byte nonce required")
        _need(mode == self.sequence[self.step] and nonce not in self.nonces, "phase order or nonce replay rejected")
        raw = make_pin_request(self.plan, mode, nonce)
        self.pending = (mode, nonce)
        self.nonces.add(nonce)
        return raw

    def unknown(self) -> None:
        self.failed = True
        self.pending = None

    def accept_report(self, raw: bytes) -> dict[str, Any]:
        _need(not self.failed and self.pending is not None, "no pending exact native request")
        mode, nonce = self.pending
        try:
            _need(type(raw) is bytes and len(raw) == 184, "missing/partial native result; no replay")
            fields = struct.unpack("<8sIIII7q6Q32s16sq", raw)
            _need(fields[:2] == (b"M4PINR01", 1) and fields[2] == mode and fields[3] == 9,
                  "foreign mode or incomplete native phase")
            _need(all(fields[index] == 0 for index in (5, 6, 7, 8, 9, 20)), "native operation or cleanup failed")
            _need(fields[10] == 0 and fields[11] > 0 and fields[4] == (8 if mode in (1, 2) else 0), "unexpected native identity or operation count")
            _need(fields[13] > 0 and fields[14] == BASELINE["ap"]["size"] and fields[16] > 0 and
                  fields[17] == (BANK_TARGET_SIZE if mode in (1, 3) else BASELINE["bank"]["size"]), "native file identity/size mismatch")
            _need(fields[18] == bytes.fromhex(self.plan["plan_id"]) and fields[19] == nonce, "foreign plan or stale nonce")
            identities = (fields[12], fields[13], fields[15], fields[16], fields[11])
            _need(self.file_identities is None or self.file_identities == identities,
                  "AP/bank dev/inode or process changed between phases; unknown outcome")
        except (PinPlanError, struct.error):
            self.unknown()
            raise
        self.pending = None
        if self.file_identities is None:
            self.file_identities = identities
        self.step += 1
        return {"mode": mode, "phase": 9, "native_completed": True, "full_readback_verified": False, "device_execution_state": "HELD"}

    def confirm_readback(self, images: Mapping[str, Any]) -> dict[str, Any]:
        _need(not self.failed and not self.finished and self.pending is None and self.step == 3, "terminal inspect sequence required before full readback")
        try:
            result = verify_full_readback(self.plan, images, "forward" if self.sequence[-1] == 3 else "inverse")
        except PinPlanError:
            self.unknown()
            raise
        self.finished = True
        return result

