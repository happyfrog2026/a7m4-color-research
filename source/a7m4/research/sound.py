"""Portable, local-only factory shutter sound plans for exact 6.02 pairs.

No legacy session, device, transport, compiler or emulation modules are imported.
The profile contains two small gate replacements, never the native audio files.
"""

from __future__ import annotations

from functools import lru_cache
import json
import os
from pathlib import Path
from typing import Any

from .offline import PlanError, inspect_image, plan_content_changes


@lru_cache(maxsize=1)
def _profile_data() -> dict[str, Any]:
    return json.loads((Path(__file__).with_name("data") / "native-sound.json").read_text(encoding="utf-8"))


def native_sound_plan(ap_path: str | os.PathLike[str], cp_path: str | os.PathLike[str],
                      desired_state: str) -> dict[str, Any]:
    """Identify an exact AP/CP pair and calculate enable/disable or no change.

    Both inputs are fully read as regular local files, even for a no-op. Only
    fixed complete identities are supported; partial signatures never qualify.
    Disabling restores this track's exact pre-gate CP, preserving every other
    feature. No images or upload artifacts are produced. Capacity, native sound
    registry, live policy and device execution remain separate pending checks.
    """
    if not isinstance(desired_state, str) or desired_state not in ("enabled", "disabled"):
        raise PlanError("desired_state must be enabled or disabled")
    profile = _profile_data()
    ap = inspect_image(ap_path, "ap")["source"]
    cp = inspect_image(cp_path, "cp")["source"]
    track = None
    current_state = None
    for candidate in profile["tracks"]:
        if ap["size"] != profile["ap_size"] or ap["sha256"] != candidate["ap_sha256"]:
            continue
        for state in ("disabled", "enabled"):
            if cp["size"] == profile["cp_size"] and cp["sha256"] == candidate[state + "_cp_sha256"]:
                track, current_state = candidate, state
                break
        if track is not None:
            break
    if track is None:
        raise PlanError("unsupported AP/CP pair for native sound; complete registered component identities are required")

    cp_plan = None
    target_hash = track[desired_state + "_cp_sha256"]
    if current_state != desired_state:
        enabling = desired_state == "enabled"
        windows = [{
            "offset": window["offset"],
            "before_hex": window["before_hex" if enabling else "after_hex"],
            "after_hex": window["after_hex" if enabling else "before_hex"],
        } for window in profile["windows"]]
        cp_plan = plan_content_changes({
            "schema": "a7m4-offline-content-plan/1",
            "source": cp,
            "windows": windows,
        })
        if cp_plan["target"]["size"] != profile["cp_size"] or cp_plan["target"]["sha256"] != target_hash:
            raise PlanError("computed native sound target does not match the registered complete CP identity")

    unchanged_ap = {key: ap[key] for key in ("kind", "size", "sha256")}
    return {
        "schema": "a7m4-native-sound-plan/1",
        "feature_id": profile["feature_id"],
        "model": profile["model"],
        "firmware": profile["firmware"],
        "offline_only": True,
        "camera_io": False,
        "network_io": False,
        "images_written": False,
        "deployment_authorized": False,
        "device_execution_ready": False,
        "status": "NO_CHANGE_REQUIRED" if cp_plan is None else "PLANNED_OFFLINE",
        "profile_id": track["id"],
        "current_state": current_state,
        "desired_state": desired_state,
        "source": {"ap": ap, "cp": cp},
        "target": {
            "ap": dict(unchanged_ap, materialized=False),
            "cp": {"kind": "cp", "size": profile["cp_size"], "sha256": target_hash, "materialized": False},
        },
        "cp_plan": cp_plan,
        "inverse": None if cp_plan is None else {"ap_unchanged": unchanged_ap, "cp": cp_plan["inverse"]},
        "scope": {
            "ap_changed": False,
            "cp_window_bytes": 0 if cp_plan is None else sum(window["size"] for window in cp_plan["windows"]),
            "cp_changed_bytes": 0 if cp_plan is None else cp_plan["changed_existing_bytes"],
            "other_cp_bytes": "unchanged-by-construction; no physical readback performed",
            "native_audio_files_changed": False,
            "settings_changed": False,
            "effect_boundary": "Gate state only. Live sound settings and native registry are unknown; existing early suppression, skip and kind1 counter branches remain. Not all capture modes are covered.",
        },
        "evidence": {
            "enabled_pair": track["enabled_evidence"],
            "historical_device_acceptance_recorded": track["device_acceptance_recorded"],
            "historical_acceptance_scope": profile["evidence"]["historical_acceptance_scope"] if track["device_acceptance_recorded"] else None,
            "this_planner_device_validation": "not-performed",
            "recipe_record_sha256": profile["evidence"]["recipe_record_sha256"],
        },
        "space_budget": {
            "status": "PENDING_TRANSPORT_PREFLIGHT", "evaluated": False,
            "each_upload_bytes_exclusive": 65536, "minimum_remaining_free_bytes": 8388608,
            "reason": "Content planning generates no transport files and does not measure a camera.",
        },
        "pending_runtime_checks": [
            "fresh model, firmware, complete pair and exact preimages",
            "native audio registry and actual sound policy",
            "all actual uploads individually below 65536 bytes; fresh free-space budget with at least 8 MiB remaining",
            "bounded write, complete readback/complement, exact inverse and cleanup",
            "reload, electronic/mechanical single capture and normal photo/playback acceptance",
        ],
    }
