"""Offline, receipt-bound PIN source families. Never imports device backends.

Completed local receipts are evidence bindings, not signatures or deployment
permission. Only fixed sound-gate / Custom1 program overlays are accepted;
complete reversed source bytes must match a pinned stock602 or R066 family.
"""
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path

from .capture_inputs import read_private
from . import program_worker
from .selection_ref import resolve_selection,read_selection
from ..research import pin_plan as pin

ROLES = ("ap", "cp_program", "bank")
MAXIMUM = {"ap": 98212632, "cp_program": 16236816, "bank": 131072}
STOCK_WORDS = tuple(bytes.fromhex(h) for h in (
    "f5ff00a9", "157081d2", "ff1b00b9", "f41300f9", "ff0b00f9", "009081d2", "ff1b00b9"))
PROFILES = {
    "stock602": {
        "ap": {"size": 98212632, "sha256": "1e1b9202eaa69198f20df03dbfdab2f103b206cc4ebcd2e7bd817e6a710018a2"},
        "cp_program": {"size": 16236816, "sha256": "7b9b137d696e5972d20db7f9119076172ed8e0730805d7f0b4c31b87689e2c2b"},
        "bank": {"size": 77504, "sha256": "dae3d18d37b85a22398573f04090a4a95a97052380f4b2b4402a374516399dfb"}},
    "r066": deepcopy(pin.BASELINE),
}
GATE_WINDOWS = ((3181912, "12021e02", "02120202"),
    (3181948, "94f897090321002845f2685018bf002121502044", "4cf29950c0f2a01000780128e8d10ee000bf00bf"))
GATE_ENABLED_CP = {
    "stock602": "9528bfcc2a1fd4a3d04a48e59cc3e1ae063e7e820092fa0cea97360f8d61b6d8",
    "r066": PROFILES["r066"]["cp_program"]["sha256"],
}
GATE_DISABLED_CP = {"stock602": PROFILES["stock602"]["cp_program"]["sha256"],
                    "r066": "a452e5eb130f1275463beaba0041667a195b571ef56e859d6e9e5fef891b0b5d"}


def need(value, message):
    if not value:
        raise ValueError(message)


def identity(raw):
    return {"size": len(raw), "sha256": sha256(raw).hexdigest()}


def images(values):
    need(isinstance(values, dict) and set(values) == set(ROLES), "Complete AP, CP program and sound bank required")
    result = {}
    for role in ROLES:
        value = values[role]
        raw = value if type(value) is bytes else read_private(value, MAXIMUM[role])
        need(0 < len(raw) <= MAXIMUM[role], "Bounded complete image required: " + role)
        result[role] = raw
    return result


def record(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result, "Duplicate key in completed program receipt")
            result[key] = value
        return result
    def finite(value):
        raise ValueError("Nonfinite completed program receipt")
    raw = read_private(path, 4 * 1024 * 1024)
    result = json.loads(raw, object_pairs_hook=unique, parse_constant=finite)
    need(type(result) is dict, "Completed program receipt must be an object")
    return result, sha256(raw).hexdigest()


def _endpoint(plan, data, side):
    program_worker.validate_plan(plan)
    need(all(identity(data[role]) == plan["components"][key][side]
             for role, key in (("ap", "ap"), ("cp_program", "cp"))), "Program lineage whole endpoint differs")


def _reverse(stages, current):
    data = dict(current)
    for plan in reversed(stages):
        _endpoint(plan, data, "target")
        for role, key in (("ap", "ap"), ("cp_program", "cp")):
            raw = bytearray(data[role])
            for row in plan["components"][key]["windows"]:
                at = row["offset"]
                before, after = bytes.fromhex(row["before_hex"]), bytes.fromhex(row["after_hex"])
                need(raw[at:at + len(after)] == after, "Program lineage target window differs")
                raw[at:at + len(before)] = before
            data[role] = bytes(raw)
        _endpoint(plan, data, "source")
    return data


def _gate_expected(plan, before):
    need(plan.get("feature_id") == "electronic-sound-gate", "Foreign program feature")
    raw = before["cp_program"]
    candidates = []
    for enabled in (False, True):
        target = bytearray(raw)
        windows = []
        for at, off, on in GATE_WINDOWS:
            old, new = bytes.fromhex(on if enabled else off), bytes.fromhex(off if enabled else on)
            if raw[at:at + len(old)] != old:
                break
            target[at:at + len(old)] = new
            windows.append({"offset": at, "before_hex": old.hex(), "after_hex": new.hex()})
        else:
            components = {"ap": {"source": identity(before["ap"]), "target": identity(before["ap"]), "windows": []},
                          "cp": {"source": identity(raw), "target": identity(bytes(target)), "windows": windows}}
            candidates.append(program_worker.program_plan(components, feature_id="electronic-sound-gate"))
    need(plan in candidates, "Program lineage is not the fixed two-window electronic-sound gate")


def _completed(path, body):
    path = Path(path).absolute()
    if path.is_dir():
        path /= "job.private.json"
    need(path.name == "job.private.json", "Completed program job filename differs")
    result, digest = record(path)
    flags = ("camera_io", "complete", "verified", "full_readback_verified", "stop_safe",
             "normal_return_verified", "service_exit_confirmed")
    need(result.get("schema") == "a7m4-toolbox-device-job/1" and result.get("status") in ("VERIFIED_APPLIED", "VERIFIED_NO_CHANGE")
         and result.get("camera_applied") is (result.get("status") == "VERIFIED_APPLIED")
         and all(result.get(key) is True for key in flags) and result.get("simulation", False) is False,
         "Only a real complete program terminal receipt may establish a source descendant")
    need(result.get("body_binding") == body and result.get("receipt") == str(path), "Program receipt/body binding differs")
    normal = result.get("normal_return", {})
    need(type(normal) is dict and normal.get("normal_msc_verified") is True and normal.get("same_body_and_port") is True,
         "Completed program job lacks normal same-body return")
    selection = resolve_selection(result,path.parent)
    need(type(selection) is dict and selection.get("body_binding", body) == body, "Program selection/body binding differs")
    feature = result.get("feature")
    new_gate = feature == "electronic-sound-gate" and selection.get("schema") == "a7m4-toolbox-gate-selection/1"
    if feature == "electronic-sound-gate":
        if new_gate:
            need(result.get("native_sequence_complete") is True, "Completed gate native sequence missing")
            stored = read_selection(path.parent)
            need(stored == selection, "Gate stored selection differs from completed receipt")
            from .gate_scope import verify_ticket_binding
            verify_ticket_binding(selection,path.parent)
            plan = selection.get("gate", {}).get("program")
            stages = selection.get("program_stages")
            need(stages == ([plan] if plan is not None else []) and result.get("program_stages") == stages, "Gate stage bindings differ")
        else:
            plan = selection.get("program")
            stored, _ = record(path.parent / "plan.json")
            need(stored == plan, "Gate stored plan differs from completed receipt")
            stages = [plan]
    elif feature == "looks-install":
        need(result.get("native_sequence_complete") is True, "Completed looks sequence missing")
        stored = read_selection(path.parent)
        need(stored == selection, "Looks stored selection differs from completed receipt")
        plan = selection
        need(type(plan) is dict and plan.get("schema") == "a7m4-toolbox-looks-plan/2", "Completed looks selection missing")
        stages = plan.get("program_stages") or ([plan["program"]] if plan.get("program") else [])
        need(result.get("program_stages") == stages, "Completed looks stage bindings differ")
    else:
        raise ValueError("Unsupported completed program lineage feature")
    need(type(stages) is list and 0 <= len(stages) <= 2, "Bounded fixed program stages required")
    need(result["status"] != "VERIFIED_NO_CHANGE" or not stages, "No-change receipt cannot contain program mutations")
    for plan in stages:
        program_worker.validate_plan(plan)
    # Retained whole readback is independent of the JSON's success words.
    folder = path.parent / ("inspect-3" if feature == "electronic-sound-gate" and not new_gate else "post")
    retained = {"ap": read_private(folder / "ap.bin", MAXIMUM["ap"]),
                "cp_program": read_private(folder / ("cp.bin" if feature == "electronic-sound-gate" and not new_gate else "cp_program.bin"), MAXIMUM["cp_program"])}
    scoped_observed=new_gate and selection.get('source_basis')=='gate-current-CDEF/2'
    if scoped_observed:
        from .gate_scope import observed_normalization
        ref=result.get('gate_observations_ref',{})
        need(ref.get('path')=='gate-forward-observations.json' and type(ref.get('size')) is int,
             'Fixed Gate observation reference missing')
        observed_raw=read_private(path.parent/'gate-forward-observations.json',2*1024*1024)
        need(len(observed_raw)==ref['size'] and sha256(observed_raw).hexdigest()==ref.get('sha256'),
             'Gate observation reference changed')
        observation=json.loads(observed_raw)
        normalized=observed_normalization(selection,retained['ap'],retained['cp_program'])
        need(observation.get('schema')=='gate-forward-observations/1'
             and observation.get('E_F_gate_execution') is False
             and observation.get('source_normalization_stages')==normalized
             and observation.get('normalization_is_native_execution_claim') is False,
             'Gate observed C normalization differs')
        stages=normalized
    if stages:
        _endpoint(stages[-1], retained, "target")
    elif not scoped_observed:
        need(feature == "looks-install" or new_gate, "Legacy empty program receipts are not admitted")
        if feature == "looks-install":
            for role, name, remote in (("ap", "appFw.so", "/usr/lib/appFw.so"), ("cp_program", "CPAPP-B.BIN", "/cp/CPAPP-B.BIN")):
                component = selection["components"][name]
                expected = identity(retained[role])
                need({k:component["source"][k] for k in ("size", "sha256")} == component["target"] == expected
                     and component.get("windows") == [] and component.get("append", {}).get("size") == 0
                     and component.get("target_path") == remote, "Resource-only receipt changed a program")
        else:
            # Current gate-selection/1 stores the exact complete objects in
            # components; its small gate dict only states desired/current.
            # Compatibility with the earlier full native-sound shape remains
            # explicit, never inferred from a missing source or target.
            components = selection.get("components")
            if type(components) is dict:
                for role, name, remote in (("ap", "appFw.so", "/usr/lib/appFw.so"), ("cp_program", "CPAPP-B.BIN", "/cp/CPAPP-B.BIN")):
                    component = components.get(name, {})
                    expected = identity(retained[role])
                    need({k:component.get("source", {}).get(k) for k in ("size", "sha256")} == component.get("target") == expected
                         and component.get("windows") == [] and component.get("append", {}).get("size") == 0
                         and component.get("append", {}).get("after_hex") == ""
                         and component.get("target_path") == remote, "No-op gate changed a complete program")
                state = selection.get("gate", {}).get("gate", {})
                need(state.get("desired_state") == state.get("current_state")
                     and state.get("current_state") in ("enabled", "disabled"), "No-op gate state differs")
            else:
                gate = selection["gate"]["gate"]
                need(gate.get("status") == "NO_CHANGE_REQUIRED" and all(
                    {k:gate["source"][key][k] for k in ("size", "sha256")} == {k:gate["target"][key][k] for k in ("size", "sha256")} for key in ("ap", "cp")), "No-op gate changed programs")
                need(all({k:gate["target"][key][k] for k in ("size", "sha256")} == identity(retained[role])
                     for role,key in (("ap","ap"),("cp_program","cp"))), "No-op gate retained programs differ")
    if feature == "electronic-sound-gate" and not new_gate:
        expected = {"status": "FULL_READBACK_VERIFIED", "endpoint": "target",
            "files": {"ap": identity(retained["ap"]), "cp": identity(retained["cp_program"])},
            "plan_id": stages[-1]["plan_id"], "camera_validation_claimed": False}
        need(result.get("readback") == expected, "Gate full-readback record differs")
    else:
        if scoped_observed:
            from .gate_scope import read_observed_file
            bank=read_observed_file(folder/'bank.bin',MAXIMUM['bank'])
        else:bank = read_private(folder / "bank.bin", MAXIMUM["bank"])
        expected_files = {"ap": identity(retained["ap"]), "cp_program": identity(retained["cp_program"]), "bank": identity(bank)}
        readback = result.get("readback", {})
        if scoped_observed:
            need(readback.get('validation_scope')=='C-D-only-E-F-observations/1'
                 and ((readback.get('scoped_objects_read') is True and readback.get('object_count') == 11) or readback.get('objects73_read') is True) and readback.get('C_D_verified') is True
                 and readback.get('settings_C_D_verified') is True and readback.get('F_gate_execution') is False
                 and readback.get('files')==expected_files,'Completed observed Gate C/D receipt differs')
        else:
            need((readback.get("scoped_objects_verified") is True or readback.get("objects73_verified") is True) and readback.get("settings_full_verified") is True
                 and readback.get("files") == expected_files, "Completed 73-object/settings/full-program receipt differs")
        objects = result.get("verified_objects", [])
        for role in ROLES:
            matches = [row for row in objects if row.get("path") == "post/" + role + ".bin"]
            need(matches == [{"path": "post/" + role + ".bin", **expected_files[role]}], "Completed retained object identity differs")
        if not scoped_observed and (not new_gate or type(selection.get("components")) is dict):
            audio = selection["components"]["extras/SysSound.bin"]
            need(identity(bank) == {key: audio["target"][key] for key in ("size", "sha256")}
                 == {key: audio["source"][key] for key in ("size", "sha256")}
                 and audio.get("windows") == [] and audio.get("append", {}).get("size") == 0,
                 "Fixed program jobs must retain the complete sound bank unchanged")
    return {"stage_role": "observed-C-normalization-not-native-execution" if scoped_observed else "native-program-stage", "receipt": str(path), "receipt_sha256": digest, "feature": feature, "stages": stages,
            "bank": identity(bank) if new_gate or feature == "looks-install" else None,
            "program_endpoint": {role:identity(retained[role]) for role in ("ap", "cp_program")}}


def program_lineage(path, body):
    """Explicit separate read-only proof; ordinary completion rules stay exact."""
    path=Path(path).absolute()
    if path.name=='program-reconciliation.private.json':
        from .program_reconciliation import verify_reconciliation
        return verify_reconciliation(path,body)
    return _completed(path,body)


def admit_pin_source(values, *, body_binding=None, program_jobs=()):
    """Prove the complete source family by reversing exact completed overlays.

    program_jobs is chronological. Each reverse is complete-hash bound, then
    the independent feature validator recomputes the permitted fixed overlay.
    No caller generic manifest or arbitrary known-hash descendant is admitted.
    The returned private source bytes are deliberately separate from JSON.
    """
    need(type(program_jobs) in (list, tuple) and len(program_jobs) <= 8, "At most eight explicit completed program jobs")
    need(not program_jobs or type(body_binding) is dict, "Same-body binding required for composed source")
    current = images(values)
    proofs = [program_lineage(path, body_binding) for path in program_jobs]
    need(len({row["receipt"] for row in proofs}) == len(proofs), "Program lineage receipt repeated")
    base, reversed_rows = dict(current), []
    for row in reversed(proofs):
        need(all(identity(base[role]) == row["program_endpoint"][role] for role in ("ap", "cp_program")), "Completed program endpoint differs from source lineage")
        need(row["bank"] is None or row["bank"] == identity(base["bank"]), "Completed program bank differs from current source")
        before = _reverse(row["stages"], base)
        reversed_rows.append((row, before, base))
        base = before
    families = []
    for family, profile in PROFILES.items():
        if identity(base["ap"]) != profile["ap"] or identity(base["bank"]) != profile["bank"]:
            continue
        if identity(base["cp_program"])["size"] != profile["cp_program"]["size"]:
            continue
        cp_sha = identity(base["cp_program"])["sha256"]
        if cp_sha in {GATE_ENABLED_CP[family], GATE_DISABLED_CP[family]}:
            families.append(family)
    need(len(families) == 1, "Unknown/mixed complete PIN source; stock602 or R066 canonical provenance required")
    family = families[0]
    words = STOCK_WORDS if family == "stock602" else pin.AP_BEFORE
    need(all(base["ap"][at:at + 4] == word for at, word in zip(pin.AP_OFFSETS, words)), "Canonical descriptor preimages differ")
    for row, before, after in reversed(reversed_rows):
        if not row["stages"]:
            continue  # Fully checked program NOOP adds no source mutation.
        if row["feature"] == "electronic-sound-gate":
            need(len(row["stages"]) == 1, "Gate has extra program stages")
            _gate_expected(row["stages"][0], before)
        else:
            from .looks import validate_program_overlay
            checked = validate_program_overlay(row["stages"], before["ap"], before["cp_program"],
                canonical_ap_bytes=base["ap"], canonical_cp_bytes=base["cp_program"])
            need(checked.get("verified") is True, "Fixed looks program overlay was not independently verified")
        # PIN descriptor and bank ranges must survive every non-audio overlay.
        need(after["bank"] == before["bank"] and all(after["ap"][at:at + 4] == word
             for at, word in zip(pin.AP_OFFSETS, words)), "Program overlay overlaps PIN descriptors/bank")
    description = {"schema": "a7m4-toolbox-pin-source/1", "family": family,
        "canonical_images": {role: identity(base[role]) for role in ROLES},
        "images": {role: identity(current[role]) for role in ROLES},
        "body_binding": deepcopy(body_binding), "program_lineage": deepcopy(proofs),
        "canonical_full_hash_verified": True, "exact_overlay_and_complement_verified": True,
        "camera_io": False, "device_execution_ready": False}
    return description
