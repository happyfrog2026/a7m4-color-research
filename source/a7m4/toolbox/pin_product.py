"""Fixed stock602/R066 PIN content planning with complete source witnesses.

The reviewed research module is unchanged. This product adapter revalidates
complete source files plus receipt-bound fixed overlays whenever a plan is
materialized, inverted or built. It never treats a caller's sealed JSON as an
admission token. No transport or device module is imported.
"""
from copy import deepcopy
from contextvars import ContextVar
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import struct

from ..research import pin_audio, pin_plan as reference
from . import pin_sources as sources

SCHEMA = "a7m4-toolbox-pin-content-plan/1"
ROLES = reference.ROLES
TARGET_PATHS = reference.TARGET_PATHS
AP_OFFSETS = reference.AP_OFFSETS
BANK_TARGET_SIZE = reference.BANK_TARGET_SIZE
BASELINE = reference.BASELINE  # Read limits only; never source admission.
_VALIDATING = ContextVar("pin_product_composition_validation", default=())


def _need(value, message):
    if not value:
        raise ValueError(message)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _seal(value):
    value["plan_id"] = sha256(_canonical({key: item for key, item in value.items() if key != "plan_id"})).hexdigest()
    return value


def _clips(plan):
    component = plan["components"]["bank"]
    owned = b"".join(bytes.fromhex(row["after_hex"]) for row in component["windows"])
    owned += bytes.fromhex(component["append_hex"])
    result = {}
    for role, (offset, capacity) in reference.SLOTS.items():
        start = 0 if role == "ka" else 256 + offset - reference.OWNED_START
        length = plan["native"][role]["actual_bytes"]
        _need(type(length) is int and 0 < length <= capacity and length % 64 == 0, "Invalid native clip length")
        result[role] = owned[start:start + length]
    return result


def _construct(raw, clips, controls, admission):
    _need(set(clips) == set(reference.SLOTS), "Three native clips required")
    for role, value in clips.items():
        capacity = reference.SLOTS[role][1]
        _need(type(value) is bytes and 0 < len(value) <= capacity and len(value) % 64 == 0
              and all(value[at] <= 8 for at in range(0, len(value), 32)), "Invalid bounded filter0 clip: " + role)
    # Ka is always the admitted fixed 256-byte descriptor. Short input is
    # padded with codec-valid zero blocks; metadata still records actual bytes.
    before = sources.STOCK_WORDS if admission["family"] == "stock602" else reference.AP_BEFORE
    lengths = {role: len(value) for role, value in clips.items()}
    after = reference._ap_after(lengths)
    target = dict(raw)
    ap = bytearray(raw["ap"])
    for at, old, new in zip(reference.AP_OFFSETS, before, after):
        _need(ap[at:at + 4] == old, "Source descriptor preimage differs")
        ap[at:at + 4] = new
    target["ap"] = bytes(ap)
    bank = bytearray(raw["bank"][:reference.OWNED_START])
    bank.extend(bytes(reference.BANK_TARGET_SIZE - len(bank)))
    for role, (at, capacity) in reference.SLOTS.items():
        bank[at:at + capacity] = clips[role] + bytes(capacity - len(clips[role]))
    target["bank"] = bytes(bank)
    source_size = len(raw["bank"])
    bank_ranges = [(0, 256)]
    if source_size > reference.OWNED_START:
        bank_ranges.append((reference.OWNED_START, source_size - reference.OWNED_START))
    ranges = {"ap": [(at, 4) for at in reference.AP_OFFSETS], "cp_program": [], "bank": bank_ranges}
    preview = controls.get("cutoff_seconds")
    _need(preview is None or type(preview) in (int, float) and math.isfinite(preview) and 0 < preview <= 3600,
          "Preview cutoff must be finite positive seconds")
    return _seal({"schema": SCHEMA, "direction": "forward", "status": "PLANNED_OFFLINE",
        "camera_io": False, "network_io": False, "device_execution_ready": False,
        "deployment_authorized": False, "device_execution_state": "HELD",
        "dynamic_layout_device_validated": False, "source_admission": deepcopy(admission),
        "source_layout": {"family": admission["family"], "original_source_bank_bytes": len(raw["bank"]),
            "preserved_bank_range": [256, 77504], "old_sha_kasha_allocations_preserved": True,
            "fixed_R066_endpoint_reproduced": False, "historical_R066_acceptance_extended": False,
            "stock_adapter_physical_acceptance": "NOT_PERFORMED"},
        "components": {role: reference._component(role, raw[role], target[role], ranges[role]) for role in ROLES},
        "native": {role: {"actual_bytes": len(clips[role]), "sha256": sha256(clips[role]).hexdigest(),
            "offset": at, "slot_capacity": capacity, "playback_descriptor_bytes": 256 if role == "ka" else len(clips[role])}
            for role, (at, capacity) in reference.SLOTS.items()},
        "protected_bank": {"offset": 256, "size": 77248, "sha256": sha256(raw["bank"][256:77504]).hexdigest()},
        "controls": deepcopy(controls), "cutoff": {"requested": None,
            "source_installed": "approximately-1/8", "planned_cutoff_nominal_seconds": 0.125,
            "preview_cutoff_seconds": preview, "camera_changed": False,
            "preview_matches_planned_installed_cutoff": None if preview is None else preview == 0.125},
        "space_budget": {"cp_growth_bytes": reference.BANK_TARGET_SIZE - source_size,
            "minimum_jiritsu_remaining_bytes": 8388608, "each_upload_strictly_less_than_bytes": 65536,
            "fresh_budget_verified": False, "whole_images_staged_in_jiritsu": False},
        "limitations": ["New stock602/dynamic layout is not physically camera-accepted.",
            "AP55=02 and absent retired custom.txt must be freshly proved; no settings write.",
            "24k is a software production assumption, not a measured hardware playback rate.",
            "KA remains a 256-byte descriptor; arbitrary extended KA is unsupported.",
            "The installed near-1/8 cutoff is preserved; GUI1/50 remains preview only."]})


def plan_product_pin(values, prepared_pack, *, body_binding=None, program_jobs=(), requested_cutoff=None):
    """Local complete stock/current admission; no generic manifest input."""
    _need(requested_cutoff is None, "PIN does not change body cutoff; 1/50 is preview only")
    _need(isinstance(prepared_pack, (str, os.PathLike)), "A validated local prepared pack path is required")
    prepared = pin_audio.validate_prepared_pack(prepared_pack)
    manifest, clips = reference._pack(prepared)
    raw = sources.images(values)
    admission = sources.admit_pin_source(raw, body_binding=body_binding, program_jobs=program_jobs)
    return _construct(raw, clips, manifest.get("controls", {}), admission)


def _composed_admission(capture_path, context):
    info = context["admission"]
    return dict(schema="a7m4-toolbox-pin-composed-source/1", family=info["family"],
        body_binding=deepcopy(context["body_binding"]), images=deepcopy(info["projected_images"]),
        canonical_images=deepcopy(info["canonical_images"]),
        source_capture_receipt=str(Path(capture_path).absolute()), sound_job=deepcopy(info["sound_job"]),
        program_jobs=deepcopy(info["program_jobs"]), projection_admission=deepcopy(info),
        camera_io=False, device_execution_ready=False)


def plan_composed_pin(capture_path, prepared_pack, *, previous_job, program_jobs=()):
    from .pin_composition import product_source_context
    context = product_source_context(capture_path, previous_job=previous_job, program_jobs=program_jobs)
    prepared = pin_audio.validate_prepared_pack(prepared_pack)
    manifest, clips = reference._pack(prepared)
    return _construct(context["pin_normalized_bytes"], clips, manifest.get("controls", {}),
                      _composed_admission(capture_path, context))


def transpose_previous_pin(previous_plan, capture_path, context):
    """Preserve completed later fixed programs while exactly removing old audio."""
    result = _construct(context["pin_normalized_bytes"], _clips(previous_plan), previous_plan["controls"],
                        _composed_admission(capture_path, context))
    validate_product_pin(result, context["pin_normalized_bytes"])
    verify_product_readback(result, context["actual_bytes"], context["pin_normalized_bytes"])
    return result


def _admit_from_proof(raw, proof):
    if proof.get("schema") == "a7m4-toolbox-pin-source/1":
        return sources.admit_pin_source(raw, body_binding=proof["body_binding"],
            program_jobs=[row["receipt"] for row in proof["program_lineage"]])
    _need(proof.get("schema") == "a7m4-toolbox-pin-composed-source/1", "Unknown complete source witness schema")
    from .pin_composition import product_source_context
    key = (proof["source_capture_receipt"], proof["sound_job"]["receipt"])
    stack = _VALIDATING.get()
    _need(key not in stack and len(stack) < 16, "Cyclic or excessive composed sound lineage")
    token = _VALIDATING.set(stack + (key,))
    try:
        context = product_source_context(key[0], previous_job=key[1], program_jobs=proof["program_jobs"])
        _need(raw == context["pin_normalized_bytes"], "Complete transposed source differs from independently projected capture")
        admission = _composed_admission(key[0], context)
        _need(admission == proof, "Composed source receipt/lineage binding changed")
        return admission
    finally:
        _VALIDATING.reset(token)


def validate_product_pin(plan, source_images):
    """Require actual complete source witnesses, not a caller-sealed digest."""
    try:
        _need(type(plan) is dict and plan.get("schema") == SCHEMA and plan.get("direction") == "forward",
              "Original product forward plan required")
        raw = sources.images(source_images)
        proof = plan["source_admission"]
        admission = _admit_from_proof(raw, proof)
        expected = _construct(raw, _clips(plan), plan["controls"], admission)
        _need(expected == plan, "PIN plan differs from exact independently admitted source/clip/windows/complement")
        return plan
    except (KeyError, TypeError, IndexError, OverflowError) as error:
        raise ValueError("Malformed product PIN plan") from error


def verify_product_readback(plan, fresh_images, source_images, direction="forward"):
    validate_product_pin(plan, source_images)
    _need(direction in ("forward", "source", "inverse"), "Explicit readback direction required")
    raw = sources.images(fresh_images)
    side = "target" if direction == "forward" else "source"
    for role in ROLES:
        component = plan["components"][role]
        _need(sources.identity(raw[role]) == component[side], "Full product PIN readback differs: " + role)
        for window in component["windows"]:
            at, size = window["offset"], window["size"]
            _need(raw[role][at:at + size] == bytes.fromhex(window["after_hex" if side == "target" else "before_hex"]),
                  "Product PIN readback window differs")
        for row in component["complement"]:
            at, size = row["offset"], row["size"]
            _need(sha256(raw[role][at:at + size]).hexdigest() == row["sha256"], "Protected complement differs")
    return {"schema": "a7m4-toolbox-pin-full-readback/1", "verified": True, "complete": True,
        "plan_id": plan["plan_id"], "endpoint": side, "images": {role: sources.identity(raw[role]) for role in ROLES},
        "complement_verified": True, "camera_io": False, "physical_acceptance_claimed": False}


def materialize_product_pin(plan, fresh_images, source_images=None, *, inverse=False):
    _need(type(inverse) is bool, "Explicit inverse boolean required")
    witnesses = fresh_images if source_images is None else source_images
    verify_product_readback(plan, fresh_images, witnesses, "forward" if inverse else "source")
    raw = sources.images(fresh_images)
    result = {}
    for role in ROLES:
        component = plan["components"][role]
        target = bytearray(raw[role])
        for row in component["windows"]:
            at, size = row["offset"], row["size"]
            target[at:at + size] = bytes.fromhex(row["before_hex" if inverse else "after_hex"])
        if inverse:
            del target[component["source"]["size"]:]
        else:
            target.extend(bytes.fromhex(component["append_hex"]))
        result[role] = bytes(target)
    verify_product_readback(plan, result, witnesses, "source" if inverse else "forward")
    return result


def plan_product_inverse(plan, current_images, source_images):
    verify_product_readback(plan, current_images, source_images)
    result = {"schema": "a7m4-toolbox-pin-inverse/1", "direction": "inverse", "forward_plan": deepcopy(plan),
        "inverse_of": plan["plan_id"], "components": deepcopy(plan["components"]),
        "camera_io": False, "device_execution_ready": False, "device_execution_state": "HELD"}
    for row in result["components"].values():
        row["source"], row["target"] = row["target"], row["source"]
        for window in row["windows"]:
            window["before_hex"], window["after_hex"] = window["after_hex"], window["before_hex"]
        row["tail_before_truncate_hex"], row["append_hex"] = row["append_hex"], ""
        row["truncate_to"] = row["target"]["size"]
    return _seal(result)
