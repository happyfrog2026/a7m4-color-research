"""Exact local Custom1 M9/display planning; no transport or device imports.

The UXC string algorithm adapts the original M4 resources-port/resources.py
(MIT; source SHA in looks-r066.json) and C2's MIT resource layout. Native
bitmap parsing/codec is reused from research.native_icons, which retains its
complete C2 notice and Sony internal-only template rights. The one fixed M9
record/basis has separate GPL-3.0-or-later source attribution and license.
No full firmware, native string data, calibration template or historical PO
recipe is embedded. Stock composition is an offline plan; settings admission,
physical execution and Custom1 camera acceptance remain separate checks.
"""
from __future__ import annotations

import base64
from .. import resource_profile as device_scope
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import struct

from ..research import native_icons as icons
from ..research.offline import _regular_reader, load_manifest
from .policy import filter_selection
from .selection_ref import resolve_selection

_DATA = Path(__file__).with_name("data")
_NAMED_COUNT = 3048
_LABELS = tuple(range(0x0200ABE2, 0x0200ABE8))
_BANK_LIMIT = 16 * 1024 * 1024


def _need(value, message):
    if not value:
        raise ValueError(message)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _profile_data():
    data = load_manifest(_DATA / "looks-r066.json")
    _need(data.get("schema") == "a7m4-toolbox-looks-data/1", "Unknown looks dependency schema")
    return data


def _playback_data():
    info = load_manifest(_DATA / "looks-playback-custom1.json")
    _need(info.get("schema") == "a7m4-custom1-playback-code/1", "Unknown Custom1 playback schema")
    for name, key in (("looks-playback-custom1.S", "assembly_sha256"),
                      ("looks-playback-custom1.ld", "linker_sha256"),
                      ("looks-playback-stock-custom1.S", "stock_assembly_sha256"),
                      ("looks-playback-stock-custom1.ld", "stock_linker_sha256")):
        _need(_sha(_read(_DATA / name, 16384)) == info[key], "Custom1 playback source identity differs")
    _need(_sha(bytes.fromhex(info["helper_hex"])) == info["helper_sha256"], "Custom1 playback code identity differs")
    _need(_sha(bytes.fromhex(info["stock_helper_hex"])) == info["stock_helper_sha256"], "Stock Custom1 playback code identity differs")
    return info


def _metadata_data():
    info = load_manifest(_DATA / "looks-metadata-custom1.json")
    _need(info.get("schema") == "a7m4-custom1-photo-metadata-code/1", "Unknown Custom1 metadata schema")
    for name, key in (("looks-metadata-custom1.S", "assembly_sha256"),
                      ("looks-metadata-custom1.ld", "linker_sha256")):
        _need(_sha(_read(_DATA / name, 16384)) == info[key], "Custom1 metadata source identity differs")
    for row in info["sections"]:
        _need(_sha(bytes.fromhex(row["after_hex"])) == row["sha256"], "Custom1 metadata code identity differs")
    return info


def _root(value):
    path = Path(value).absolute()
    _need(path.is_dir() and not any(p.is_symlink() for p in (path, *path.parents)),
          "Input root must be an existing real directory without symbolic links")
    return path


def _file(root, relative):
    _need(isinstance(relative, str) and relative and not relative.startswith("/")
          and "\\" not in relative and ":" not in relative
          and all(p not in ("", ".", "..") for p in relative.split("/")), "Unsafe project-relative path")
    path = root
    for part in relative.split("/"):
        path /= part
        _need(not path.is_symlink(), "Input file must not cross a symbolic link")
    return path


def _read(path, maximum):
    with _regular_reader(path) as (stream, info):
        _need(0 < info.st_size <= maximum, "Input file exceeds bounded size")
        raw = stream.read(maximum + 1)
        _need(len(raw) == info.st_size, "Input changed during read")
    return raw


def _identity(path, kind):
    _need(kind in ("ap", "cp", "audio", "resource"), "Unknown exact object kind")
    limit = _BANK_LIMIT if kind == "resource" else 160 * 1024 * 1024
    with _regular_reader(path) as (stream, info):
        _need(0 < info.st_size <= limit, "Exact source exceeds bounded size")
        digest, size = hashlib.sha256(), 0
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
        _need(size == info.st_size, "Complete local source changed while hashing")
    return {"size": size, "sha256": digest.hexdigest()}


def _admit(root, data):
    ap = _identity(_file(root, "appFw.so"), "ap")
    cp = _identity(_file(root, "CPAPP-B.BIN"), "cp")
    matches = [p for p in data["profiles"] if all(
        p["files"][name][key] == value[key] for name, value in (("appFw.so", ap), ("CPAPP-B.BIN", cp))
        for key in ("size", "sha256"))]
    if not matches:
        stock = [p for p in data.get("recognized_unimplemented", [])
                 if p["ap_sha256"] == ap["sha256"] and p["cp_sha256"] == cp["sha256"]]
        if stock:
            raise ValueError("Recognized stock 6.02; installation prerequisites unavailable: " + stock[0]["reason"])
        raise ValueError("Unknown or mixed complete AP/CP identities; no looks profile admitted")
    _need(len(matches) == 1, "Ambiguous complete looks profile")
    profile = deepcopy(matches[0])
    _need(len(profile["files"]) == 73, "Legacy local profile must retain its original inventory")
    profile["files"]={name:row for name,row in profile["files"].items() if name in device_scope.OBJECTS}
    profile["resource_profile"]=device_scope.ID
    _need(len(profile["files"]) == device_scope.COUNT, "Current device profile must bind eleven objects")
    observed, retained = {}, {}
    for name, spec in profile["files"].items():
        actual = ap if name == "appFw.so" else cp if name == "CPAPP-B.BIN" else _identity(_file(root, name), spec["kind"])
        canonical = {k: spec[k] for k in ("size", "sha256")}
        if actual != canonical:
            _need(spec["kind"] == "resource" and actual["size"] > spec["size"] and actual["size"] % 4 == 0,
                  "Complete source identity differs: " + name)
            raw = _read(_file(root, name), _BANK_LIMIT)
            prefix, tail = raw[:spec["size"]], raw[spec["size"]:]
            _need(_sha(raw) == actual["sha256"] and _sha(prefix) == spec["sha256"],
                  "Complete source/canonical prefix identity differs: " + name)
            # Parsing only the complete canonical prefix proves every indexed
            # record and payload resolves inside it; extra bytes are unreachable.
            if Path(name).name.startswith("string_"):
                _strings(prefix)
            else:
                icons._inspect_bank(prefix)
            retained[name] = {"canonical_prefix": canonical, "actual_complete": actual,
                              "tail": {"offset": len(prefix), "size": len(tail), "sha256": _sha(tail)},
                              "all_index_references_within_canonical_prefix": True,
                              "physical_tail_action": "PRESERVE_NEVER_TRUNCATE"}
            spec.update(actual)
        observed[name] = actual
    profile["retained_tail_admission"] = retained
    return profile, observed


def _capture(path):
    from .capture_inputs import verified_device_capture as verified_capture
    return verified_capture(path)


def _source_context(capture, sound_job, previous_jobs):
    from .pin_composition import product_source_context
    return product_source_context(capture, previous_job=sound_job, program_jobs=previous_jobs)


def _resource_baseline(root, profile, previous=None):
    specs = {n: s for n, s in profile["files"].items() if s["kind"] == "resource"}
    _need(len(specs) == len(device_scope.RESOURCES), "Complete resource scope must contain current 8 objects")
    observed = {n: _identity(_file(root, n), "resource") for n in specs}
    if previous is not None and observed == previous:
        return observed, {}, True
    retained = {}
    for name, spec in specs.items():
        actual = observed[name]
        canonical = {k: spec[k] for k in ("size", "sha256")}
        if actual == canonical:
            continue
        _need(actual["size"] > spec["size"] and actual["size"] % 4 == 0,
              "Resource is neither a proved completed endpoint nor a canonical retained-tail endpoint: " + name)
        raw = _read(_file(root, name), _BANK_LIMIT)
        prefix, tail = raw[:spec["size"]], raw[spec["size"]:]
        _need(_sha(raw) == actual["sha256"] and _sha(prefix) == spec["sha256"],
              "Resource complete/canonical prefix identity differs: " + name)
        _strings(prefix) if Path(name).name.startswith("string_") else icons._inspect_bank(prefix)
        retained[name] = {"canonical_prefix": canonical, "actual_complete": actual,
                          "tail": {"offset": len(prefix), "size": len(tail), "sha256": _sha(tail)},
                          "all_index_references_within_canonical_prefix": True,
                          "physical_tail_action": "PRESERVE_NEVER_TRUNCATE"}
    return observed, retained, False


def _job_path(path):
    value = Path(path).absolute()
    if value.is_dir():
        value /= "job.private.json"
    _need(value.name == "job.private.json" and not any(p.is_symlink() for p in (value, *value.parents)),
          "Completed job must be a real job.private.json without symbolic links")
    return value


def _program_job_path(path):
    """Only the separately verified gate sidecar extends program history paths."""
    value=Path(path).absolute()
    if value.name=='program-reconciliation.private.json':
        _need(value.is_file() and not any(p.is_symlink() for p in (value,*value.parents)),
              'Gate reconciliation must be a real explicit proof without symbolic links')
        return value
    return _job_path(value)


def _resource_history(previous_jobs, profile, body):
    """Rebuild each completed resource transform from its retained originals.

    Success words alone do not establish ownership of 1E9A. The complete source
    archive, frozen native artwork, independently regenerated transform and all
    73 complete post files must agree, including each physical inverse prefix.
    """
    _need(type(previous_jobs) in (tuple, list) and len(previous_jobs) <= 8, "At most eight chronological completed jobs")
    paths = [_program_job_path(p) for p in previous_jobs]
    _need(len(set(paths)) == len(paths), "Completed job lineage is repeated")
    previous, summaries = None, []
    for path in paths:
        if path.name=='program-reconciliation.private.json':
            from .pin_sources import program_lineage
            proof=program_lineage(path,body)
            _need(proof['feature']=='electronic-sound-gate','Only the fixed gate proof has no resource ownership')
            continue
        job = load_manifest(path)
        if job.get("feature") != "looks-install":
            # Gate jobs have no resource ownership; their complete fixed program
            # proof is independently enforced by product_source_context.
            continue
        flags = ("camera_io", "complete", "verified", "full_readback_verified", "stop_safe",
                 "normal_return_verified", "service_exit_confirmed", "native_sequence_complete")
        _need(job.get("schema") == "a7m4-toolbox-device-job/1"
              and job.get("status") in ("VERIFIED_APPLIED", "VERIFIED_NO_CHANGE")
              and all(job.get(k) is True for k in flags) and job.get("simulation") is False
              and job.get("network_io") is False and job.get("receipt") == str(path)
              and job.get("body_binding") == body,
              "Resource ownership requires a real complete same-body job, never a plan or simulation")
        _need(job.get("normal_return", {}).get("normal_msc_verified") is True
              and job.get("normal_return", {}).get("same_body_and_port") is True,
              "Completed resource job lacks same-body normal return")
        planned = load_manifest(_file(path.parent, "selection.json"))
        _need(planned == resolve_selection(job,path.parent) and planned.get("schema") == "a7m4-toolbox-looks-plan/2"
              and planned.get("body_binding") == body, "Completed stored looks selection differs")
        capture = _capture(planned.get("capture_receipt"))
        _need(capture["body_binding"] == body, "Completed source archive belongs to another body")
        _need(type(capture.get("archive_sha256")) is str and len(capture["archive_sha256"]) == 64
              and job.get("backup_archive_sha256") == capture["archive_sha256"],
              "Completed job/source archive SHA-256 binding differs")
        root = _root(capture["snapshot_dir"])
        observed, retained, owned = _resource_baseline(root, profile, previous)
        choice = filter_selection(planned.get("selection"))
        chosen = [r for r in choice["slots"] if r["selected"]]
        _need(all(r["slot"] == 1 for r in chosen), "Completed selection modified another custom slot")
        assets = _assets(path.parent / "native-project", chosen[0]["icon_text"]) if chosen else None
        components = planned.get("components", {})
        _need(type(components) is dict and set(components) == set(profile["files"]), "Completed scope must contain current 11 objects")
        stages = planned.get("program_stages")
        _need(type(stages) is list and len(stages) <= 2 and stages == job.get("program_stages"),
              "Completed program stage binding differs")
        programs = {role: _read(_file(root, name), 160 * 1024 * 1024)
                    for role, name in (("ap", "appFw.so"), ("cp", "CPAPP-B.BIN"))}
        program_targets = dict(programs)
        from .program_worker import validate_plan
        for stage in stages:
            validate_plan(stage)
            for role, raw in tuple(program_targets.items()):
                component = stage["components"][role]
                _need(_program_identity(raw) == component["source"], "Completed stage source differs from its full capture")
                target = bytearray(raw)
                for window in component["windows"]:
                    offset, before, after = window["offset"], bytes.fromhex(window["before_hex"]), bytes.fromhex(window["after_hex"])
                    _need(target[offset:offset + len(before)] == before, "Completed stage source window differs")
                    target[offset:offset + len(after)] = after
                program_targets[role] = bytes(target)
                _need(_program_identity(target) == component["target"], "Completed stage target/complement differs")
        target_ids = {}
        for name, base_spec in profile["files"].items():
            spec = dict(base_spec)
            local = _file(root, name)
            raw = _read(local, _BANK_LIMIT if spec["kind"] == "resource" else 160 * 1024 * 1024)
            observed_id = _program_identity(raw)
            _need(observed_id == {k: capture["objects"][name][k] for k in ("size", "sha256")},
                  "Completed source snapshot changed: " + name)
            spec.update(observed_id)
            if spec["kind"] == "resource":
                _need(observed_id == observed[name], "Completed source resource changed during proof")
                if chosen:
                    target, windows = (_rename_m9(raw, chosen[0]["name"]) if Path(name).name.startswith("string_")
                                       else _bank(raw, assets, "23" if "_23_" in name else "32", owned_playback=owned))
                    expected = _delta(local, spec, raw, target, windows)
                else:
                    expected = _unchanged(local, spec)
                _need(components[name] == expected, "Completed resource transform differs from independent regeneration: " + name)
                target_ids[name] = expected["target"]
            elif spec["kind"] == "audio":
                _need(components[name] == _unchanged(local, spec), "Looks job changed the sound bank")
            else:
                # Whole program semantics are checked separately by the fixed
                # program validator in product_source_context. Bind the source
                # and its complete independently retained post image here too.
                role = spec["kind"]
                spans = [(w["offset"], len(bytes.fromhex(w["before_hex"]))) for stage in stages
                         for w in stage["components"][role]["windows"]]
                expected = (_delta(local, spec, raw, program_targets[role],
                                   _program_rows(raw, program_targets[role], spans)) if stages else _unchanged(local, spec))
                _need(components[name] == expected, "Completed program component/source/complement differs")
            _need(components[name].get("target_path") == spec["target_path"], "Completed remote object path differs")
        rows = job.get("verified_objects")
        post_names = {name: "post/" + ({"appFw.so": "ap.bin", "CPAPP-B.BIN": "cp_program.bin",
                        "extras/SysSound.bin": "bank.bin"}.get(name, name)) for name in components}
        _need(type(rows) is list and len(rows) == device_scope.COUNT and all(type(r) is dict for r in rows)
              and {r.get("path") for r in rows} == set(post_names.values()), "Completed 73-object readback inventory differs")
        expected_rows = []
        for name, relative in post_names.items():
            kind = profile["files"][name]["kind"]
            actual = _identity(_file(path.parent, relative), kind)
            _need(actual == components[name]["target"], "Completed full post-readback differs: " + name)
            expected_rows.append({"path": relative, **actual})
        _need(sorted(rows, key=lambda r: r["path"]) == sorted(expected_rows, key=lambda r: r["path"]),
              "Completed retained readback identities differ")
        readback = job.get("readback", {})
        _need(readback.get("scoped_objects_verified") is True and readback.get("settings_full_verified") is True
              and readback.get("files") == {role: components[name]["target"] for role, name in
                  (("ap", "appFw.so"), ("cp_program", "CPAPP-B.BIN"), ("bank", "extras/SysSound.bin"))},
              "Completed full readback/settings evidence differs")
        mutated = bool(stages) or any(c["source"]["sha256"] != c["target"]["sha256"] for c in components.values())
        _need((job["status"] == "VERIFIED_APPLIED" and job.get("camera_applied") is True)
              or (not mutated and job["status"] == "VERIFIED_NO_CHANGE" and job.get("camera_applied") is False),
              "Completed mutation/status evidence differs")
        previous = target_ids
        summaries.append({"receipt": str(path), "receipt_sha256": _identity(path, "resource")["sha256"],
                          "source_capture_receipt": planned["capture_receipt"], "resource_count": len(device_scope.RESOURCES),
                          "complete_post_objects_verified": device_scope.COUNT, "independent_resource_regeneration": True,
                          "source_retained_tail_admission": retained})
    return previous, summaries


def _projected_admission(root, data, capture_path, previous_jobs, sound_job):
    _need(capture_path is not None, "Receipt-bound sources require the fresh complete capture receipt")
    capture = _capture(capture_path)
    _need(Path(capture["snapshot_dir"]).absolute() == root, "Fresh capture does not bind this snapshot directory")
    context = _source_context(capture_path, sound_job, previous_jobs)
    _need(context["body_binding"] == capture["body_binding"], "Projected source body differs")
    canonical = {"ap": context["canonical_bytes"]["ap"], "cp": context["canonical_bytes"]["cp_program"]}
    profile = deepcopy(_canonical_program_profile(canonical, data))
    profile["files"] = {name:row for name,row in profile["files"].items() if name in device_scope.OBJECTS}
    profile["resource_profile"] = device_scope.ID
    sound_spec = profile["files"]["extras/SysSound.bin"]
    _need(_program_identity(context["canonical_bytes"]["bank"]) == {k: sound_spec[k] for k in ("size", "sha256")},
          "Projected sound bank is not the complete canonical family")
    previous, summaries = _resource_history(previous_jobs, profile, capture["body_binding"])
    resources, retained, owned = _resource_baseline(root, profile, previous)
    observed = dict(resources)
    for name, role in (("appFw.so", "ap"), ("CPAPP-B.BIN", "cp_program"), ("extras/SysSound.bin", "bank")):
        actual = _identity(_file(root, name), profile["files"][name]["kind"])
        _need(actual == _program_identity(context["actual_bytes"][role])
              == {k: capture["objects"][name][k] for k in ("size", "sha256")}, "Actual projected capture changed: " + name)
        observed[name] = actual
    for name, identity in observed.items():
        profile["files"][name].update(identity)
    profile["retained_tail_admission"] = retained
    profile["resource_history"] = summaries
    return profile, observed, context, owned


def _m9_payloads(data):
    pair = data["m9"]
    license_raw = _read(_DATA / "looks-M9-LICENSE.txt", 128 * 1024)
    _need(pair["license_file"] == "looks-M9-LICENSE.txt" and _sha(license_raw) == pair["license_sha256"],
          "Fixed M9 GPL license text is missing or changed")
    expected = {}
    for name in ("record", "basis"):
        try:
            raw = base64.b64decode(pair[name + "_base64"], validate=True)
        except (ValueError, TypeError) as exc:
            raise ValueError("Invalid fixed M9 payload") from exc
        _need(len(raw) == pair[name + "_size"] and _sha(raw) == pair[name + "_sha256"], "Fixed M9 dependency identity differs")
        expected[name] = raw
    record = expected["record"]
    table = record[8:8 + 1215]
    h = 0x811C9DC5
    for value in table:
        h = ((h ^ value) * 0x01000193) & 0xFFFFFFFF
    _need(record == b"M4L1" + struct.pack("<I", h) + table + bytes(25)
          and _sha(table) == pair["correction_table_sha256"] and len(expected["basis"]) == 108,
          "Fixed M9 table/basis packing differs")
    return expected


def _m9_pair(root, data):
    pair, expected = data["m9"], _m9_payloads(data)
    with _regular_reader(_file(root, "CPAPP-B.BIN")) as (stream, info):
        for name, raw in expected.items():
            offset = pair[name + "_offset"]
            _need(type(offset) is int and 0 <= offset <= info.st_size - len(raw), "M9 pair outside CP program")
            stream.seek(offset)
            _need(stream.read(len(raw)) == raw, "Existing R066 M9 " + name + " differs; no replacement is inferred")
    return {"slot": 4, "state": "EXACT_EXISTING_PAIR_VERIFIED_NO_COLOR_WRITE",
            "record_sha256": pair["record_sha256"], "basis_sha256": pair["basis_sha256"],
            "source_attribution": deepcopy(pair["source_attribution"]), "accuracy": pair["accuracy"]}


def _strings(raw):
    _need(len(raw) >= 16 and raw[:8] == b"uxc\x07\0\0\0\0", "Expected UXC-v7 string resource")
    kind, group, descriptor = struct.unpack_from("<HHI", raw, 8)
    count = descriptor & 0x1FFF
    _need(kind == 8 and group == 5 and count in (3032, _NAMED_COUNT) and descriptor == count | (count << 12),
          "Unsupported exact native/named string layout")
    base = (16 + count * 2 + 3) & ~3
    _need(base < len(raw) and len(raw) % 4 == 0, "String resource index/alignment differs")
    _need(count == 3032 or all(struct.unpack_from("<H", raw, 16 + 2 * i)[0] == 0xFFFF for i in range(3032, 3042)),
          "Reserved string indices unexpectedly occupied")
    entries = {}
    for index in range(count):
        pointer = struct.unpack_from("<H", raw, 16 + 2 * index)[0]
        if pointer == 0xFFFF:
            continue
        at = base + pointer * 4
        rid = 0x02000000 | ((group << 13) + index)
        _need(at + 5 <= len(raw) and struct.unpack_from("<I", raw, at)[0] == 0x1E000000 | (rid & 0xFFFFFF),
              "UXC string index/record differs")
        end = raw.find(b"\0", at + 4)
        _need(end >= 0, "Unterminated native string")
        try:
            text = raw[at + 4:end].decode("utf-8")
        except UnicodeError as exc:
            raise ValueError("Invalid UTF-8 native string") from exc
        entries[rid] = {"text": text, "pointer": pointer, "index_offset": 16 + 2 * index}
    _need(count == 3032 or set(_LABELS) <= set(entries), "Installed six reserved display labels are incomplete")
    return base, entries


def _rename_m9(raw, name):
    _need(1 <= len(name.encode("utf-8")) <= 63, "Right-side name must contain 1..63 UTF-8 bytes")
    base, entries = _strings(raw)
    if base == 16 + 3032 * 2:
        return _migrate_strings(raw, base, entries, name)
    rid = _LABELS[0]
    entry = entries[rid]
    if entry["text"] == name:
        return raw, []
    target = bytearray(raw)
    pointer = (len(target) - base) // 4
    _need(pointer < 0xFFFF, "String pointer space exhausted")
    at = entry["index_offset"]
    before = raw[at:at + 2]
    after = struct.pack("<H", pointer)
    target[at:at + 2] = after
    target.extend(struct.pack("<I", 0x1E000000 | (rid & 0xFFFFFF)) + name.encode("utf-8") + b"\0")
    target.extend(bytes((-len(target)) % 4))
    result = bytes(target)
    _, check = _strings(result)
    _need(check[rid]["text"] == name and all(check[k] == v for k, v in entries.items() if k != rid),
          "An unselected or native string changed")
    return result, [{"offset": at, "before_hex": before.hex(), "after_hex": after.hex(), "route": "right-title", "slot": 1}]


def _migrate_strings(raw, base, entries, name):
    """Grow indices in place; relocate only records overlapping the new 32B."""
    new_base = base + 32
    _need(new_base <= len(raw), "Native resource has no bounded index-growth area")
    target = bytearray(raw)
    struct.pack_into("<I", target, 12, _NAMED_COUNT | (_NAMED_COUNT << 12))
    target[base:new_base] = b"\xff\xff" * 16
    for rid, row in entries.items():
        at = base + 4 * row["pointer"]
        if at < new_base:
            end = raw.find(b"\0", at + 4)
            _need(end >= 0, "Unterminated relocated native string")
            end = (end + 4) & ~3
            relocated = bytes(raw[at:end])
            target.extend(bytes((-len(target)) % 4))
            pointer = (len(target) - new_base) // 4
            target.extend(relocated)
        else:
            pointer = row["pointer"] - 8
        _need(0 <= pointer < 0xFFFF, "Migrated native string pointer exceeds16 bits")
        struct.pack_into("<H", target, row["index_offset"], pointer)
    for number, rid in enumerate(_LABELS):
        text = name if number == 0 else "ST"
        target.extend(bytes((-len(target)) % 4))
        pointer = (len(target) - new_base) // 4
        _need(pointer < 0xFFFF, "New string label pointer space exhausted")
        struct.pack_into("<H", target, 16 + 2 * ((rid & 0xFFFFFF) - 0xA000), pointer)
        target.extend(struct.pack("<I", 0x1E000000 | (rid & 0xFFFFFF)) + text.encode("utf-8") + b"\0")
        target.extend(bytes((-len(target)) % 4))
    result = bytes(target)
    _, checked = _strings(result)
    _need(all(checked[rid]["text"] == row["text"] for rid, row in entries.items())
          and checked[_LABELS[0]]["text"] == name
          and all(checked[rid]["text"] == "ST" for rid in _LABELS[1:]), "Native string semantics changed during index migration")
    windows = []
    for at in range(12, new_base, 4096):
        end = min(new_base, at + 4096)
        windows.append({"offset": at, "before_hex": raw[at:end].hex(), "after_hex": result[at:end].hex(),
                        "route": "stock-string-index-rebase-and-32B-relocation", "slot": 1})
    return result, windows


def _assets(project, text):
    _need(isinstance(project, (str, os.PathLike)), "Selected Custom1 requires a local native icon project")
    path = Path(project)
    _need(not any(p.is_symlink() for p in (path, *path.parents)), "Native project must not cross symbolic links")
    manifest, base = icons._project(path)
    seen, result = set(), {}
    for row in manifest["assets"]:
        _need(isinstance(row, dict) and row.get("slot") == 1 and row.get("text") == text,
              "This coordinated route accepts only the selected Custom1 text/assets")
        key = row.get("bank_variant"), row.get("route")
        _need(key in {(v, r) for v in icons.VARIANTS for r in icons.ROUTES} and key not in seen,
              "Duplicate or invalid native asset route")
        seen.add(key)
        raw = _read(_file(base, row.get("raw")), icons.RAW_BYTES)
        encoded = _read(_file(base, row.get("compressed")), icons.RAW_BYTES * 2)
        png = _read(_file(base, row.get("png")), 1024 * 1024)
        _need(len(raw) == icons.RAW_BYTES and _sha(raw) == row.get("raw_sha256")
              and _sha(encoded) == row.get("compressed_sha256") and _sha(png) == row.get("png_sha256"),
              "Native project full asset SHA-256 differs")
        _need(icons.decompress_native(encoded) == raw and icons._png(raw) == png,
              "Native compressed payload and decoded PNG preview differ")
        result[key] = encoded
    _need(seen == {(v, r) for v in icons.VARIANTS for r in icons.ROUTES}, "All six slot1 assets are required")
    _need(manifest.get("slots") and len(manifest["slots"]) == 1 and manifest["slots"][0].get("slot") == 1
          and manifest["slots"][0].get("text") == text, "Native project selection differs")
    return result


def _bank(raw, assets, variant, *, owned_playback=False):
    bank = icons._inspect_bank(raw)
    target, windows, edited = bytearray(raw), [], set()
    routes = [("list-normal", icons.NORMAL[0]), ("list-selected", icons.SELECTED[0])]
    if owned_playback and 0x1E9A in bank["records"]:
        routes.append(("playback", 0x1E9A))
    for route, index in routes:
        _need(index in bank["records"], "Existing R066 native image route is missing")
        old = bank["records"][index]
        _need((old["width"], old["height"], old["flags"], old["field"]) == (70, 35, 0xC0000000, 12),
              "R066 native route geometry differs")
        encoded = assets[(variant, route)]
        if encoded == raw[old["start"]:old["start"] + old["size"]]:
            continue
        target.extend(bytes((-len(target)) % 4))
        start = len(target)
        target.extend(encoded)
        at = old["at"] + old["field"]
        before = raw[at:at + 8]
        after = struct.pack("<II", len(encoded), start - old["at"] - 4)
        target[at:at + 8] = after
        windows.append({"offset": at, "before_hex": before.hex(), "after_hex": after.hex(),
                        "slot": 1, "route": route, "image_index": index})
        edited.add(index)
    # C2 MIT imagebank.add strategy: relocate one independent existing payload
    # to EOF and use exactly 20 bytes of its old span for the new metadata.
    # This preserves every old image ID without growing the 16-bit index area.
    index = 0x1E9A
    if index in bank["records"]:
        _need(owned_playback, "Independent Custom1 playback image ID is already occupied")
        target.extend(bytes((-len(target)) % 4))
        result = bytes(target)
        checked = icons._inspect_bank(result)
        _need(set(checked["records"]) == set(bank["records"]), "Unexpected image registration changed on update")
        for old_id, old in bank["records"].items():
            current = checked["records"][old_id]
            _need(all(old[k] == current[k] for k in ("at", "field", "width", "height", "flags")),
                  "An existing image's geometry/registration changed")
            if old_id not in edited:
                _need(old == current and raw[old["start"]:old["start"] + old["size"]]
                      == result[current["start"]:current["start"] + current["size"]],
                      "An unselected encoded image changed on update")
        return result, windows
    metadata_end = max(r["at"] + r["field"] + 8 for r in bank["records"].values())
    donors = []
    excluded = {icons.NORMAL[0], icons.SELECTED[0], 0x1E98, 0x1E99}
    for donor_id, row in bank["records"].items():
        start, end = row["start"], row["start"] + row["size"]
        if (donor_id in excluded or row["size"] < 20 or start < metadata_end
                or (start - bank["base"]) % 4 or (start - bank["base"]) // 4 >= 0xFFFF):
            continue
        if any(other != donor_id and r["start"] < end and start < r["start"] + r["size"]
               for other, r in bank["records"].items()):
            continue
        donors.append((row["size"], donor_id, row))
    _need(donors, "No independent native payload can hold the new Custom1 image metadata")
    _, donor_id, donor = min(donors, key=lambda item: item[:2])

    def append(payload):
        target.extend(bytes((-len(target)) % 4))
        at = len(target)
        target.extend(payload)
        return at

    def change(at, value, route):
        before = raw[at:at + len(value)]
        _need(len(before) == len(value), "Image registration window outside complete bank")
        target[at:at + len(value)] = value
        windows.append({"offset": at, "before_hex": before.hex(), "after_hex": value.hex(),
                        "slot": 1, "route": route, "image_index": index})

    moved = append(raw[donor["start"]:donor["start"] + donor["size"]])
    change(donor["at"] + donor["field"] + 4, struct.pack("<I", moved - donor["at"] - 4), "relocate-original-image")
    encoded = assets[(variant, "playback")]
    payload = append(encoded)
    at = donor["start"]
    change(at, struct.pack("<IIHHII", 0x1A000000 + index, 0xC0000000, 70, 35,
                          len(encoded), payload - at - 4), "playback-metadata")
    change(16 + 2 * index, struct.pack("<H", (at - bank["base"]) // 4), "publish-playback-index")
    target.extend(bytes((-len(target)) % 4))
    result = bytes(target)
    checked = icons._inspect_bank(result)
    _need(set(checked["records"]) == set(bank["records"]) | {index}, "Unexpected native image registration changed")
    for index, old in bank["records"].items():
        current = checked["records"][index]
        if index not in edited:
            _need(raw[old["start"]:old["start"] + old["size"]]
                  == result[current["start"]:current["start"] + current["size"]], "An unselected encoded image changed")
            _need(all(old[k] == current[k] for k in ("at", "field", "width", "height", "flags", "size")),
                  "An unselected image's metadata changed")
            _need(index == donor_id or old == current, "An unselected image reference changed")
    return result, windows


def _playback_ap(raw, info, *, stock=False):
    """Expand only the existing reviewed RX suffix, within its mapped page."""
    _need(len(raw) >= 64 and raw[:7] == b"\x7fELF\x02\x01\x01"
          and struct.unpack_from("<H", raw, 18)[0] == 183, "Expected little-endian AArch64 ELF")
    phoff, shoff = struct.unpack_from("<QQ", raw, 32)
    phsize, phnum, shsize, shnum = struct.unpack_from("<HHHH", raw, 54)
    _need(phsize >= 56 and 0 < phnum <= 128 and phoff + phsize * phnum <= len(raw)
          and (shnum == 0 or shsize >= 64 and shnum <= 10000 and shoff + shsize * shnum <= len(raw)),
          "AP ELF tables outside complete image")
    start, hook = info["helper_offset"], info["hook_offset"]
    code = bytes.fromhex(info["stock_helper_hex"] if stock else info["helper_hex"])
    old_end, end = (start - 9 if stock else start + info["old_helper_bytes"]), start + len(code)
    expected_hook = bytes.fromhex("3f5c0071") if stock else bytes.fromhex(info["hook_hex"])
    _need(len(code) == (info["stock_helper_bytes"] if stock else info["helper_bytes"])
          == (24 if stock else 44) and old_end < end <= len(raw)
          and raw[hook:hook + 4] == expected_hook, "Existing AP playback hook differs")
    segments = [(phoff + i * phsize, struct.unpack_from("<II6Q", raw, phoff + i * phsize)) for i in range(phnum)]
    rx = [(at, h) for at, h in segments if h[0] == 1 and h[1] == 5 and h[2] == h[3] == 0]
    _need(len(rx) == 1 and rx[0][1][5] == rx[0][1][6] == old_end and rx[0][1][7] == 65536,
          "Exact existing AP RX mapping differs")
    _need(not any(raw[old_end:end]) and all((old_end - 1) // p == (end - 1) // p for p in (4096, 65536)),
          "Custom1 helper would overwrite padding or add an RX mapping page")
    for i in range(shnum):
        sh = struct.unpack_from("<II4QII2Q", raw, shoff + i * shsize)
        _need(sh[1] == 8 or sh[4] + sh[5] <= len(raw), "AP section outside complete image")
        _need(sh[1] == 8 or not sh[5] or max(start, sh[4]) >= min(end, sh[4] + sh[5]),
              "Custom1 playback helper overlaps an ELF section")
        if sh[1] == 9:
            _need(not sh[5], "Unreviewed AP REL relocation table")
        if sh[1] == 4 and sh[5]:
            _need(sh[9] == 24 and sh[5] % 24 == 0, "Malformed AP RELA table")
            for at in range(sh[4], sh[4] + sh[5], 24):
                offset, _, addend = struct.unpack_from("<QQq", raw, at)
                _need(not start <= offset < end and not start <= addend < end,
                      "AP relocation references the Custom1 helper")
    windows = [{"offset": start, "before_hex": raw[start:end].hex(), "after_hex": code.hex(),
                "route": "custom1-independent-playback-code", "slot": 1}]
    if stock:
        windows.append({"offset": hook, "before_hex": expected_hook.hex(), "after_hex": info["hook_hex"],
                        "route": "custom1-playback-hook", "slot": 1})
    for field in (32, 40):
        at = rx[0][0] + field
        windows.append({"offset": at, "before_hex": raw[at:at + 8].hex(),
                        "after_hex": struct.pack("<Q", end).hex(), "route": "existing-RX-extent", "slot": 1})
    result = bytearray(raw)
    for row in windows:
        at, value = row["offset"], bytes.fromhex(row["after_hex"])
        result[at:at + len(value)] = value
    return bytes(result), windows


def _custom1_pair(raw, data):
    """Write only the selected fixed record+basis; Custom4 remains unchanged."""
    result, windows = bytearray(raw), []
    for name, at in (("record", 0xBA5EA0 - 0x108000), ("basis", 0x1045D40 - 0x108000)):
        value = base64.b64decode(data["m9"][name + "_base64"], validate=True)
        _need(0 <= at <= len(raw) - len(value), "Custom1 M9 pair outside complete CP program")
        before = raw[at:at + len(value)]
        if before == value:
            continue
        result[at:at + len(value)] = value
        windows.append({"offset": at, "before_hex": before.hex(), "after_hex": value.hex(),
                        "route": "fixed-M9-" + name, "slot": 1})
    return bytes(result), windows


def _metadata_cp(raw, info, mode="current"):
    result, windows = bytearray(raw), []
    for row in info["sections"]:
        value = bytes.fromhex(row["after_hex"])
        if row["name"] == ".metadata":
            _need(len(value) <= info["metadata_budget"] == 144, "Custom1 metadata exceeds the reviewed tail")
            value += bytes(info["metadata_budget"] - len(value))
        at = row["offset"]
        _need(0 <= at <= len(raw) - len(value), "Custom1 metadata outside complete CP program")
        before = raw[at:at + len(value)]
        _need(_sha(before) == row["before_" + mode + "_sha256"], "CP metadata source preimage differs")
        if before != value:
            result[at:at + len(value)] = value
            windows.append({"offset": at, "before_hex": before.hex(), "after_hex": value.hex(),
                            "route": "Custom1-photo-metadata-" + row["name"], "slot": 1})
    return bytes(result), windows


def _stock_data():
    info = load_manifest(_DATA / "looks-stock-runtime.json")
    _need(info.get("schema") == "a7m4-stock-custom1-runtime/1", "Unknown stock runtime schema")
    for name, build in info["compiled"].items():
        for ext, key in ((".S", "assembly_sha256"), (".ld", "linker_sha256")):
            _need(_sha(_read(_DATA / ("looks-" + name + ext), 65536)) == build[key], "Stock runtime source differs")
        for row in build["sections"]:
            value = bytes.fromhex(row["after_hex"])
            _need(len(value) == row["size"] and _sha(value) == row["sha256"], "Stock runtime code differs")
    return info


def _fl23_data():
    info = load_manifest(_DATA / "looks-fl23-private.json")
    _need(info.get("schema") == "a7m4-internal-fl23-delta/1"
          and info["rights"]["public_redistribution_clearance"] is False, "Unknown private FL23 delta")
    for component in info["programs"].values():
        for row in component["windows"]:
            value = bytes.fromhex(row["after_hex"])
            _need(0 < len(value) == row["size"] <= 4096 and _sha(value) == row["after_sha256"],
                  "Private FL23 window payload identity differs")
    return info


def _program_rows(source, target, spans):
    """Union only declared ownership spans, then split bounded worker windows."""
    merged = []
    for start, size in sorted(spans):
        _need(type(start) is int and type(size) is int and 0 <= start < start + size <= len(source),
              "Program allocation outside complete source")
        end = start + size
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    rows, last = [], 0
    for start, end in merged:
        _need(source[last:start] == target[last:start], "Program complement changed outside declared allocations")
        for at in range(start, end, 4096):
            a, z = source[at:min(at + 4096, end)], target[at:min(at + 4096, end)]
            if a != z:
                rows.append({"offset": at, "before_hex": a.hex(), "after_hex": z.hex()})
        last = end
    _need(len(source) == len(target) and source[last:] == target[last:], "Program suffix/length changed")
    return rows


def _layer(source, target, spans, feature):
    from .program_worker import program_plan
    return program_plan({role: {"source": {"size": len(source[role]), "sha256": _sha(source[role])},
                                "target": {"size": len(target[role]), "sha256": _sha(target[role])},
                                "windows": _program_rows(source[role], target[role], spans[role])}
                         for role in ("ap", "cp")}, feature_id=feature)


def _fl23_programs(source, profile):
    info = _fl23_data()
    targets, spans = {}, {}
    for role in ("ap", "cp"):
        spec = info["programs"][role]
        identity_key = "enabled_source" if role == "cp" and profile["id"].endswith("enabled") else "source"
        _need({"size": len(source[role]), "sha256": _sha(source[role])} == spec[identity_key],
              "Stock complete FL23 source identity differs")
        target, spans[role] = bytearray(source[role]), []
        for row in spec["windows"]:
            at, value = row["offset"], bytes.fromhex(row["after_hex"])
            _need(_sha(source[role][at:at + len(value)]) == row["before_sha256"], "Exact stock FL23 preimage differs")
            target[at:at + len(value)] = value
            spans[role].append((at, len(value)))
        targets[role] = bytes(target)
        key = "enabled_target" if role == "cp" and profile["id"].endswith("enabled") else "target"
        _need({"size": len(target), "sha256": _sha(target)} == spec[key], "Fixed FL23 whole target identity differs")
    return targets, _layer(source, targets, spans, "looks-fl23-v1")


def _wide(reg, value, top=False):
    half = (0xF2C0 if top else 0xF240) | ((value >> 12) & 15) | (((value >> 11) & 1) << 10)
    return struct.pack("<HH", half, ((value >> 8) & 7) << 12 | reg << 8 | (value & 255))


def _stock_runtime(source, data, m9):
    info, expected = _stock_data(), _m9_payloads(data)
    cp, ap, base = source["cp"], source["ap"], info["link_base"]
    target, spans = {r: bytearray(source[r]) for r in ("ap", "cp")}, {"ap": [], "cp": []}

    def add(role, at, value):
        _need(0 <= at <= len(source[role]) - len(value) and value, "Stock allocation outside complete program")
        target[role][at:at + len(value)] = value
        spans[role].append((at, len(value)))

    _need(struct.unpack_from("<3I", cp, 0x20130) == (0x9E9000, 0x420E40, 0xB11000),
          "Stock initialized RO mapping differs")
    _need(struct.unpack_from("<3I", cp, 0x2013C) == (0xE0A000, 0x114000, 0xF32000)
          and struct.unpack_from("<I", cp, 0x20150)[0] == 0x1046000,
          "FL23 initialized DATA/BSS boundary does not cover native17 data")
    for row in info["four_slot_windows"]:
        at, old, value = row["offset"], bytes.fromhex(row["before_hex"]), bytes.fromhex(row["after_hex"])
        _need(cp[at:at + len(old)] in (old, value), "Stock four-slot dependency preimage differs")
        add("cp", at, value)
    zero = bytes(1215)
    fnv = 0x811C9DC5
    for value in zero:
        fnv = ((fnv ^ value) * 0x01000193) & 0xFFFFFFFF
    zero_record = b"M4L1" + struct.pack("<I", fnv) + zero + bytes(25)
    for slot, va in enumerate(info["record_vas"], 1):
        at = va - base
        _need(not any(cp[at:at + 1248]), "Stock record allocation is occupied")
        add("cp", at, expected["record"] if slot == 1 and m9 else zero_record)
    old_va, new_va = info["source_gamma_va"], info["target_gamma_va"]
    oldtable = cp[old_va - base:old_va - base + 51 * 28]
    _need(len(oldtable) == 1428 and not any(cp[new_va - base:new_va - base + 2432]),
          "Stock native17 data allocation differs")
    for row in (0, 10):
        for pointer in struct.unpack_from("<7I", oldtable, row * 28):
            _need(pointer == 0 or base <= pointer <= base + len(cp) - 576, "Original ST gamma pointer outside CP")
    table = oldtable + b"".join(oldtable[r * 28:(r + 1) * 28] for _ in range(4) for r in (0, 10))
    _need(len(table) == 1652 and table[:1428] == oldtable, "Original51 gamma rows changed")
    native = bytearray(2432)
    native[:len(table)] = table
    header = struct.pack("<8s6I", b"M4P17V1\0", 1, 4, 108, 17, 51, 59) + bytes(32)
    basis = (expected["basis"] if m9 else bytes(108)) + bytes(3 * 108)
    meta = 0x1045D00 - new_va
    native[meta:meta + 528] = header + basis + bytes(32)
    add("cp", new_va - base, bytes(native))
    for low, high, reg in info["gamma_moves"]:
        for va, value, top in ((low, new_va & 65535, False), (high, new_va >> 16, True)):
            old = _wide(reg, old_va >> 16 if top else old_va & 65535, top)
            _need(cp[va - base:va - base + 4] == old, "Stock native gamma consumer differs")
            add("cp", va - base, _wide(reg, value, top))
    for row in info["compiled"]["native17"]["sections"]:
        at, value = row["va"] - base, bytes.fromhex(row["after_hex"])
        if row["name"] == ".native17":
            _need(len(value) == 720 and not any(cp[at:at + 720]), "Stock native17 code allocation differs")
        add("cp", at, value)
    for row in info["compiled"]["stock-carrier"]["sections"]:
        add("ap", row["va"], bytes.fromhex(row["after_hex"]))
    for row in info["compiled"]["title"]["sections"]:
        add("ap", row["va"], bytes.fromhex(row["after_hex"]))
    menu = info.get("menu_offset", 0x3FDE878)
    _need(struct.unpack_from("<3I", ap, menu - 8) == (0x858, 0x858, 0x0200A302),
          "Stock Custom1 menu metadata differs")
    add("ap", menu, struct.pack("<I", _LABELS[0]))
    changed_cp, metadata_rows = _metadata_cp(bytes(target["cp"]), _metadata_data(), "stock")
    if not m9:
        # Only249 can be emitted on stock; preserve the native ST description.
        owned = bytearray(changed_cp)
        start, end = 0xBA6650 - base, 0xBA66E0 - base
        at = owned.find(b"m9\0" + bytes(13), start, end)
        _need(at >= start, "Stock metadata string allocation differs")
        owned[at:at + 16] = b"ST\0" + bytes(13)
        changed_cp = bytes(owned)
    target["cp"] = bytearray(changed_cp)
    spans["cp"].extend((row["offset"], len(bytes.fromhex(row["before_hex"]))) for row in metadata_rows)
    changed_ap, playback_rows = _playback_ap(bytes(target["ap"]), _playback_data(), stock=True)
    target["ap"] = bytearray(changed_ap)
    spans["ap"].extend((row["offset"], len(bytes.fromhex(row["before_hex"]))) for row in playback_rows)
    result = {r: bytes(target[r]) for r in target}
    return result, _layer(source, result, spans, "looks-custom1-stock-runtime-v1")


def _combined_stock_program(source, stages, final):
    """Compose only the two regenerated stock recipes against their first source.

    Gaps of at most32 unchanged bytes may be included to retain the existing
    native128-window/16KiB bounds. No PIN descriptor or sound gate is covered,
    even by an unchanged gap. This is not a user-supplied manifest entry point.
    """
    from .program_worker import program_plan, validate_plan
    from ..research.pin_plan import AP_OFFSETS
    from .pin_sources import GATE_WINDOWS
    _need(len(stages) == 2 and [p['feature_id'] for p in stages] ==
          ['looks-fl23-v1', 'looks-custom1-stock-runtime-v1'],
          'Only the fixed stock FL23 and Custom1 recipes may be composed')
    current = dict(source)
    owned = {'ap': [], 'cp': []}
    for plan in stages:
        validate_plan(plan)
        for role in ('ap', 'cp'):
            component = plan['components'][role]
            _need(_program_identity(current[role]) == component['source'], 'Composition stage source differs')
            raw = bytearray(current[role])
            for window in component['windows']:
                at = window['offset']; before = bytes.fromhex(window['before_hex'])
                after = bytes.fromhex(window['after_hex'])
                _need(raw[at:at+len(before)] == before, 'Composition stage preimage differs')
                raw[at:at+len(before)] = after
                owned[role].append((at, len(before)))
            current[role] = bytes(raw)
            _need(_program_identity(current[role]) == component['target'], 'Composition stage target differs')
    _need(current == final, 'Composition final complete programs differ')
    protected = {'ap': [(at, at+4) for at in AP_OFFSETS],
                 'cp': [(at, at+len(bytes.fromhex(before))) for at, before, _ in GATE_WINDOWS]}
    components = {}
    for role in ('ap', 'cp'):
        before, after = source[role], final[role]
        # This independent complement check precedes coalescing. Allocations
        # come only from the two recipes regenerated above, never a new range.
        _program_rows(before, after, owned[role])
        changed = sorted({at for start, size in owned[role] for at in range(start, start+size)
                          if before[at] != after[at]})
        ranges = []
        for at in changed:
            _need(all(not (a <= at < b) for a, b in protected[role]), 'Composition changes another owned feature')
            if ranges and at-ranges[-1][1] <= 32 and at+1-ranges[-1][0] <= 4096 and all(
                    at+1 <= a or ranges[-1][0] >= b for a, b in protected[role]):
                # Every newly bridged byte is explicitly checked as same-value.
                _need(before[ranges[-1][1]:at] == after[ranges[-1][1]:at], 'Composition gap changed')
                ranges[-1][1] = at+1
            else:
                ranges.append([at, at+1])
        spans = [(a, b-a) for a, b in ranges]
        rows = _program_rows(before, after, spans)
        _need(all(all(w['offset']+len(bytes.fromhex(w['before_hex'])) <= a or w['offset'] >= b
                      for a, b in protected[role]) for w in rows), 'Composition window covers another owned feature')
        components[role] = dict(source=_program_identity(before), target=_program_identity(after), windows=rows)
    return program_plan(components, feature_id='looks-stock-fl23-custom1-v1')


def _program_layers(source, profile, data, *, display, m9, fl23):
    if profile.get("kind", "current") == "stock":
        if not (display or fl23):
            return [], source
        target, first = _fl23_programs(source, profile)
        if not display:
            return [first], target
        final, second = _stock_runtime(target, data, m9)
        return [_combined_stock_program(source, [first, second], final)], final
    if not display:
        return [], source
    expected = _m9_payloads(data)
    for name, value in expected.items():
        at = data["m9"][name + "_offset"]
        _need(source["cp"][at:at + len(value)] == value, "Current Custom4 M9 pair differs")
    ap, ap_rows = _playback_ap(source["ap"], _playback_data())
    cp, cp_rows = _custom1_pair(source["cp"], data) if m9 else (source["cp"], [])
    if m9:
        cp, metadata = _metadata_cp(cp, _metadata_data())
        cp_rows.extend(metadata)
    target = {"ap": ap, "cp": cp}
    spans = {"ap": [(r["offset"], len(bytes.fromhex(r["before_hex"]))) for r in ap_rows],
             "cp": [(r["offset"], len(bytes.fromhex(r["before_hex"]))) for r in cp_rows]}
    return [_layer(source, target, spans, "looks-custom1-m9-v1")], target


def _program_identity(raw):
    return {"size": len(raw), "sha256": _sha(raw)}


def _canonical_program_profile(source, data):
    identities = {r: _program_identity(b) for r, b in source.items()}
    profiles = [p for p in data["profiles"] if all(
        {k: p["files"][name][k] for k in ("size", "sha256")} == identities[r]
        for r, name in (("ap", "appFw.so"), ("cp", "CPAPP-B.BIN")))]
    _need(len(profiles) == 1, "Overlay source is not a canonical complete AP/CP pair")
    return profiles[0]


def _program_states(canonical, data):
    """Regenerate allowed complete states, including the fixed native gate.

    The canonical witness is never a caller-supplied trusted hash: its full
    bytes must match a registered pair. Gate alternatives are admitted only
    after changing the two reviewed windows yields another registered pair.
    """
    first = _canonical_program_profile(canonical, data)
    bases = [(canonical, first)]
    gate = load_manifest(_DATA.parent.parent / "research" / "data" / "native-sound.json")
    for state in ("before_hex", "after_hex"):
        cp = bytearray(canonical["cp"])
        if any(row["offset"] + len(bytes.fromhex(row[state])) > len(cp) for row in gate["windows"]):
            continue
        for row in gate["windows"]:
            at, value = row["offset"], bytes.fromhex(row[state])
            cp[at:at + len(value)] = value
        base = {"ap": canonical["ap"], "cp": bytes(cp)}
        if any(base == value for value, _ in bases):
            continue
        matches = [p for p in data["profiles"] if all(
            p["files"][name]["sha256"] == _sha(base[role]) and p["files"][name]["size"] == len(base[role])
            for role, name in (("ap", "appFw.so"), ("cp", "CPAPP-B.BIN")))]
        if len(matches) == 1:
            bases.append((base, matches[0]))
    states, image_pool = [], {}
    def intern(images):
        # A stock pair has two native gate states and three feature states.
        # Their identical 98MB APs share one immutable Mac buffer.
        return {role: image_pool.setdefault((role, len(raw), _sha(raw)), raw)
                for role, raw in images.items()}
    for base, profile in bases:
        base = intern(base)
        states.append(dict(name="canonical", images=base, base=base, profile=profile, stages=[], m9=False))
        variants = [(True, True, True, "fixed-M9-display"), (True, False, True, "preserve-color-display")]
        if profile.get("kind") == "stock":
            variants.append((False, False, True, "FL23-only"))
        for display, m9, fl23, name in variants:
            stages, images = _program_layers(base, profile, data, display=display, m9=m9, fl23=fl23)
            states.append(dict(name=name, images=intern(images), base=base, profile=profile, stages=stages, m9=m9))
    return states


def _program_update(source, canonical, data, *, display, m9, fl23, _states=None):
    states = _program_states(canonical, data) if _states is None else _states
    matches = [state for state in states if source == state["images"]]
    _need(matches, "Current complete program is not an independently regenerated fixed state")
    state = matches[0]
    if not display and (not fl23 or state["name"] != "canonical" or state["profile"].get("kind") != "stock"):
        return [], source, state["profile"]
    # ST means preserve the existing color, including an already installed M9.
    desired_name = ("fixed-M9-display" if m9 or state["m9"] else "preserve-color-display") if display else "FL23-only"
    desired = next(row for row in states if row["base"] == state["base"] and row["name"] == desired_name)
    if source == desired["images"]:
        return [], source, state["profile"]
    if state["name"] == "canonical":
        return desired["stages"], desired["images"], state["profile"]
    if state["name"] == "FL23-only" and desired["profile"].get("kind") == "stock":
        target, remaining = _stock_runtime(source, data, m9 or state["m9"])
        _need(target == desired["images"], "FL23-only continuation differs from regenerated final state")
        return [remaining], target, state["profile"]
    spans = {role: [(w["offset"], len(bytes.fromhex(w["before_hex"])))
                    for row in (state, desired) for stage in row["stages"]
                    for w in stage["components"][role]["windows"]] for role in ("ap", "cp")}
    return [_layer(source, desired["images"], spans, "looks-custom1-update-v1")], desired["images"], state["profile"]


def validate_program_overlay(program_stages, source_ap_bytes, source_cp_bytes, *,
                             canonical_ap_bytes=None, canonical_cp_bytes=None) -> dict:
    """Independently regenerate fixed looks stages and legitimate update NOOPs.

    Optional canonical witnesses are complete original bytes obtained by the
    caller's independently verified receipt chain, never a trusted JSON flag.
    This function still checks their registered full hashes and regenerates
    every possible fixed source/target byte. Installation evidence is separate.
    """
    stages = program_stages if isinstance(program_stages, list) else [program_stages]
    _need(0 <= len(stages) <= 2 and all(isinstance(s, dict) for s in stages), "Expected zero/one/two fixed program stages")
    source = {"ap": source_ap_bytes, "cp": source_cp_bytes}
    _need((canonical_ap_bytes is None) == (canonical_cp_bytes is None), "Both canonical program witnesses are required")
    canonical = source if canonical_ap_bytes is None else {"ap": canonical_ap_bytes, "cp": canonical_cp_bytes}
    _need(all(isinstance(b, bytes) and 0 < len(b) <= 160 * 1024 * 1024 for b in (*source.values(), *canonical.values())),
          "Canonical source bytes must be bounded complete programs")
    data = _profile_data()
    profile = _canonical_program_profile(canonical, data)
    states = _program_states(canonical, data)
    variants = [(True, True, True, "fixed-M9-display"), (True, False, True, "preserve-color-display"),
                (False, False, True, "FL23-only"), (False, False, False, "preserve-existing")]
    for display, m9, fl23, variant in variants:
        expected, targets, current_profile = _program_update(source, canonical, data, display=display, m9=m9, fl23=fl23,
                                                            _states=states)
        if stages == expected:
            return {"verified": True, "source_profile": profile["id"], "current_gate_profile": current_profile["id"],
                    "variant": variant, "target": {r: _program_identity(b) for r, b in targets.items()},
                    "program_stages": expected, "camera_io": False, "network_io": False,
                    "installation_evidence": "NOT_PROVIDED_BY_THIS_PURE_VALIDATOR"}
    raise ValueError("Program overlay differs from all independently regenerated fixed looks stages")


def _delta(path, spec, source, target, windows):
    windows = sorted(windows, key=lambda row: row["offset"])
    end, ranges, digest, normalized = 0, [], hashlib.sha256(), []
    restored = bytearray(target)
    for row in windows:
        before, after, at = bytes.fromhex(row["before_hex"]), bytes.fromhex(row["after_hex"]), row["offset"]
        _need(0 < len(before) == len(after) and at >= end and source[at:at + len(before)] == before
              and target[at:at + len(after)] == after and source[end:at] == target[end:at], "Exact windows/complement differ")
        if at > end:
            data = source[end:at]
            ranges.append({"offset": end, "size": len(data), "sha256": _sha(data)})
            digest.update(data)
        restored[at:at + len(before)] = before
        normalized.append({**row, "size": len(before), "changed_bytes": sum(a != b for a, b in zip(before, after))})
        end = at + len(before)
    _need(source[end:] == target[end:len(source)], "Original trailing complement differs")
    if end < len(source):
        data = source[end:]
        ranges.append({"offset": end, "size": len(data), "sha256": _sha(data)})
        digest.update(data)
    tail = target[len(source):]
    _need(restored[:len(source)] == source and restored[len(source):] == tail, "Retained-tail inverse differs")
    return {"schema": "a7m4-toolbox-looks-component/1",
            "operation": "replace-references-and-append" if tail else "replace-exact-windows" if windows else "unchanged",
            "source": {"path": str(path), "kind": spec["kind"], "size": len(source), "sha256": _sha(source)},
            "target_path": spec["target_path"], "target": {"size": len(target), "sha256": _sha(target)}, "windows": normalized,
            "append": {"offset": len(source), "size": len(tail), "sha256": _sha(tail), "after_hex": tail.hex()},
            "changed_existing_bytes": sum(row["changed_bytes"] for row in normalized),
            "complement": {"verification": "whole-source-and-target-compared", "ranges": ranges,
                           "coverage_bytes": len(source), "size": len(source) - sum(row["size"] for row in normalized),
                           "sha256_concatenated_ranges": digest.hexdigest()},
            "inverse": {"source": {"size": len(target), "sha256": _sha(target)},
                        "windows": [{"offset": r["offset"], "before_hex": r["after_hex"], "after_hex": r["before_hex"]} for r in normalized],
                        "truncate": False, "retain_tail": True, "tail_identity": {"offset": len(source), "size": len(tail), "sha256": _sha(tail)},
                        "target": {"size": len(restored), "sha256": _sha(restored)},
                        "restored_original_prefix": {"size": len(source), "sha256": _sha(source)},
                        "full_original_file_restored": not tail},
            "device_execution_ready": False, "deployment_authorized": False}


def _unchanged(path, spec):
    identity = {k: spec[k] for k in ("size", "sha256")}
    return {"schema": "a7m4-toolbox-looks-component/1", "operation": "unchanged",
            "source": {"path": str(path), "kind": spec["kind"], **identity}, "target_path": spec["target_path"],
            "target": dict(identity), "windows": [], "append": {"offset": spec["size"], "size": 0, "after_hex": "", "sha256": _sha(b"")},
            "inverse": None, "device_execution_ready": False, "deployment_authorized": False}


def _write(path, value):
    if isinstance(value, dict):
        value = (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())


def _projected_programs(context, data, *, display, m9, fl23):
    canonical = {"ap": context["canonical_bytes"]["ap"], "cp": context["canonical_bytes"]["cp_program"]}
    normalized = {"ap": context["pin_normalized_bytes"]["ap"], "cp": context["pin_normalized_bytes"]["cp_program"]}
    actual = {"ap": context["actual_bytes"]["ap"], "cp": context["actual_bytes"]["cp_program"]}
    expected, _, _ = _program_update(normalized, canonical, data, display=display, m9=m9, fl23=fl23)
    projection = context["pin_projection"]["ap"]
    cursor = 0
    for row in sorted(projection, key=lambda r: r["offset"]):
        at, before, after = row["offset"], bytes.fromhex(row["actual_hex"]), bytes.fromhex(row["canonical_hex"])
        _need(type(at) is int and at >= cursor and len(before) == len(after) == 4
              and actual["ap"][cursor:at] == normalized["ap"][cursor:at]
              and actual["ap"][at:at + 4] == before and normalized["ap"][at:at + 4] == after,
              "PIN projection is not an exact disjoint four-byte witness")
        cursor = at + 4
    _need(actual["ap"][cursor:] == normalized["ap"][cursor:] and actual["cp"] == normalized["cp"],
          "PIN projection changed a program complement")
    stages, current = [], dict(actual)
    for plan in expected:
        targets, spans = dict(current), {"ap": [], "cp": []}
        for role in ("ap", "cp"):
            raw = bytearray(current[role])
            for row in plan["components"][role]["windows"]:
                at, before, after = row["offset"], bytes.fromhex(row["before_hex"]), bytes.fromhex(row["after_hex"])
                _need(role != "ap" or all(at + len(before) <= p["offset"] or at >= p["offset"] + 4 for p in projection),
                      "Looks window overlaps a PIN descriptor")
                _need(raw[at:at + len(before)] == before, "Actual source differs at a fixed looks window")
                raw[at:at + len(after)] = after
                spans[role].append((at, len(before)))
            targets[role] = bytes(raw)
        stages.append(_layer(current, targets, spans, plan["feature_id"]))
        current = targets
    return stages, current


def plan_looks(snapshot_dir: Path, selection: dict, native_project: Path | None, output: Path, *,
               previous_jobs=(), sound_job=None, capture=None) -> dict:
    """Plan fixed Custom1 M9/display, from stock6.02 or the exact R066 pair.

    selection is the strict a7m4-toolbox-filters/1 GUI/CLI payload. Only selected
    slot1 is admitted here; all other colors/names/icons remain exact. Existing
    Custom4 M9 is verified, then its licensed pair is copied to Custom1 only if
    requested. A new independent playback ID avoids changing Custom2/3/4.
    Stock composes FL23 and runtime into one bounded program transition. Settings
    writes require their separate fresh RAM/saved/SAVE guarded coordinator.
    No transport, space measurement, worker or deployment is implied.
    """
    root, out = _root(snapshot_dir), Path(output).absolute()
    _need(type(previous_jobs) in (list, tuple) and len(previous_jobs) <= 8, "At most eight chronological completed jobs")
    _need(not out.exists() and not out.is_symlink() and out.parent.is_dir(), "Choose a new output directory with an existing parent")
    _need(not any(p.is_symlink() for p in out.parents) and not out.is_relative_to(root), "Output must be outside the original snapshot, without symbolic-link parents")
    value = filter_selection(selection)
    _need(all(row["recipe"] != "m9" or row["slot"] == 1 for row in value["slots"]), "Fixed M9 installation targets Custom1/ST only")
    chosen = [row for row in value["slots"] if row["selected"]]
    _need(all(row["slot"] == 1 for row in chosen), "Only Custom1 is selected by this release; all other slots must remain unchanged")
    data = _profile_data()
    context, owned = None, False
    if previous_jobs or sound_job is not None:
        profile, observed, context, owned = _projected_admission(root, data, capture, previous_jobs, sound_job)
    else:
        profile, observed = _admit(root, data)
    stock = profile.get("kind") == "stock"
    pair = ({"state": "FACTORY_CUSTOM4_NATIVE_ST_PRESERVED"} if stock else _m9_pair(root, data))
    playback = _playback_data() if chosen else None
    rights = icons.check_templates()["rights"]
    components, targets, target_paths, append_paths = {}, {}, {}, {}
    assets = _assets(native_project, chosen[0]["icon_text"]) if chosen else None
    stages, source_programs, program_targets = [], {}, {}
    if chosen or stock and (value["include_fl2"] or value["include_fl3"]):
        for role, name in (("ap", "appFw.so"), ("cp", "CPAPP-B.BIN")):
            source_programs[role] = _read(_file(root, name), 160 * 1024 * 1024)
            _need({"size": len(source_programs[role]), "sha256": _sha(source_programs[role])} == observed[name],
                  "Local program changed after admission")
        builder = _program_layers if context is None else _projected_programs
        arguments = (source_programs, profile, data) if context is None else (context, data)
        stages, program_targets = builder(*arguments, display=bool(chosen),
                                           m9=bool(chosen and chosen[0]["recipe"] == "m9"),
                                           fl23=value["include_fl2"] or value["include_fl3"])
    for name, spec in profile["files"].items():
        path = _file(root, name)
        if spec["kind"] in ("ap", "cp"):
            if not stages:
                components[name] = _unchanged(path, spec)
            else:
                role = spec["kind"]
                raw, target = source_programs[role], program_targets[role]
                spans = [(row["offset"], len(bytes.fromhex(row["before_hex"])))
                         for stage in stages for row in stage["components"][role]["windows"]]
                windows = _program_rows(raw, target, spans)
                components[name] = _delta(path, spec, raw, target, windows)
            continue
        if not chosen or spec["kind"] == "audio":
            components[name] = _unchanged(path, spec)
            continue
        raw = _read(path, _BANK_LIMIT if spec["kind"] == "resource" else 160 * 1024 * 1024)
        _need({"size": len(raw), "sha256": _sha(raw)} == observed[name], "Local source changed after admission")
        if name.rsplit("/", 1)[-1].startswith("string_"):
            target, windows = _rename_m9(raw, chosen[0]["name"])
        else:
            variant = "23" if "_23_" in name else "32"
            target, windows = _bank(raw, assets, variant, owned_playback=owned)
        components[name] = _delta(path, spec, raw, target, windows)
        if target != raw and spec["kind"] == "resource":
            targets[name] = target
            target_paths[name] = "targets/" + name
            append_paths[name] = "appends/" + name + ".append.bin"
    # Reverify each complete caller input before creating any output. No whole
    # AP/CP target image is ever produced or substituted for the current source.
    for name, spec in profile["files"].items():
        _need(_identity(_file(root, name), spec["kind"]) == observed[name], "Original input changed during planning: " + name)
    program = stages[0] if len(stages) == 1 else None
    resources = [c for c in components.values() if c["source"]["kind"] == "resource"]
    resource_contract = {"schema": "fixed-windows-plus-append/1", "whole_resource_upload": False,
                         "max_window_bytes": max((w["size"] for c in resources for w in c["windows"]), default=0),
                         "max_append_bytes": max(c["append"]["size"] for c in resources),
                         "inverse_truncate": False, "inverse_retain_tail": True}
    _need(resource_contract["max_window_bytes"] <= 4096 and resource_contract["max_append_bytes"] < 65536,
          "Resource contract exceeds bounded staging")
    changed = any(c["source"]["sha256"] != c["target"]["sha256"] for c in components.values())
    report = {"schema": "a7m4-toolbox-looks-plan/2", "status": "NO_CHANGE_REQUIRED" if not changed else "PLANNED_OFFLINE_CUSTOM1_M9" if chosen else "PLANNED_OFFLINE_FL23",
              "output_dir": str(out), "profile": profile["id"], "selection": value,
              "camera_io": False, "network_io": False, "device_execution_ready": False, "camera_tests": "HELD",
              "verified_local_inputs": True, "physical_camera_observed": False,
              "retained_tail_admission": profile.get("retained_tail_admission", {}),
              "source_admission": {"program_and_PIN": deepcopy(context["admission"]) if context else None,
                                   "resource_jobs": profile.get("resource_history", []),
                                   "owned_Custom1_playback_update": owned,
                                   "previous_jobs": [str(_program_job_path(p)) for p in previous_jobs],
                                   "sound_job": str(_job_path(sound_job)) if sound_job is not None else None,
                                   "capture": str(Path(capture).absolute()) if capture is not None else None},
              "components": components, "target_paths": target_paths, "append_paths": append_paths, "program": program,
              "program_stages": stages, "program_stage_order": "forward listed order; inverse reverse order",
              "resource_contract": resource_contract,
              "m9": {"existing_Custom4": pair, "target_slot": 1, "color_write": bool(chosen and chosen[0]["recipe"] == "m9"),
                     "Custom4_unchanged": True, "Custom1_device_acceptance": "NOT_PERFORMED_NEW_ADAPTER"},
              "AP_CP_SysSound_unchanged": not stages, "SysSound_unchanged": True, "unselected_slots_unchanged": True,
              "display": {"selected_slots": [r["slot"] for r in chosen], "language_resources": len(device_scope.STRINGS),
                          "list_normal_index": icons.NORMAL[0], "list_selected_index": icons.SELECTED[0],
                          "playback_index": 0x1E9A, "playback_marker": 249,
                          "routes": "New Custom1 right-title/list-normal/list-selected/independent playback candidate",
                          "preserved_playback_indices": [0x1E98, 0x1E99] if not stock else [],
                          "preserved_marker_routes": {"250": 0x1E98, "251": 0x1E98, "252": 0x1E99} if not stock else "ALL_OTHER_VALUES_NATIVE_UNCHANGED",
                          "old_photos_rewritten": False, "Custom1_device_acceptance": "NOT_PERFORMED_NEW_ADAPTER",
                          "playback_build": playback, "stock_carrier": "ONLY_CUSTOM1_ST_EMITS249" if stock and chosen else "EXISTING_MARKERS_PRESERVED"},
              "settings": {"writes": False, "fresh_CP_color_records_observed": False,
                           "FL23_settings_state": "NOT_OBSERVED_NO_CHANGE", "ST_base": "USER_NOTICE_ONLY_NOT_READ_OR_WRITTEN",
                           "complete_SAVE_BIN_BAK_guards": False},
              "FL2_FL3": {"program_dependencies": "PREPARED_OFFLINE_SHARED_DEPENDENCY" if stock and stages else "PRESENT_IN_VERIFIED_OWN_PROGRAM_ENDPOINT" if stock and context else "ABSENT_NO_CHANGE" if stock else "PRESENT_IN_EXACT_R066_PROGRAM_PROFILE", "settings_modified": False,
                           "selection_means": "preserve existing dependencies, never uninstall or guess fresh settings"},
              "rights": {"native_frames": rights, "fixed_M9_data": deepcopy(data["m9"]["source_attribution"]),
                         "FL23_private_delta": _fl23_data()["rights"] if stock and stages else None},
              "inverse_policy": "Full target identity required; restore exact reference windows and retain all appended tails. Never truncate bank or string resources.",
              "space_budget": {"status": "PENDING_TRANSPORT_PREFLIGHT", "evaluated": False}}
    created = None
    try:
        out.mkdir(mode=0o700)
        info = out.lstat()
        created = info.st_dev, info.st_ino
        for name, target in targets.items():
            _write(out / target_paths[name], target)
            _write(out / append_paths[name], bytes.fromhex(components[name]["append"]["after_hex"]))
            _need(_identity(out / target_paths[name], "resource") == components[name]["target"], "Materialized target identity differs")
        _write(out / "looks-plan.json", report)
    except BaseException:
        if created is not None:
            # Never remove an unrelated path substituted for our new output.
            try:
                info = out.lstat()
                if stat.S_ISDIR(info.st_mode) and (info.st_dev, info.st_ino) == created:
                    shutil.rmtree(out)
            except FileNotFoundError:
                pass
        raise
    return report
