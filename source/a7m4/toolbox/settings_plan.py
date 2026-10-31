"""Fixed FL2/FL3 and separate AP55 own-body settings plans.

No device/library import, session, generic record editor or WBI operation.
Algorithm adapted from a7m4/fl23.py and native/service-fl23-settings (MIT).
The 3272-byte Sony preset payload has its own internal-study provenance;
the project's MIT license does not relicense those preset bytes.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
from types import MappingProxyType

from .bk4 import bk4_rows, MAX_SETTINGS_BYTES
from . import native_ui, save_effects

KEYS = (0x02A40001, 0x02A4000D, 0x02CF12C8, 0x02CF12CA,
        0x02CF13B0, 0x02CF13D0, 0x02CF143E, 0x02CF1440)
SIZES = (8192, 28672, 1, 1, 1, 1, 1, 1)
SPANS = (((0x1236, 0x123A), (0x17D0, 0x1800), (0x1810, 0x1840),
          (0x1850, 0x1880), (0x1890, 0x18C0)),
         ((0x1CC, 0x1D0), (0x43E0, 0x4FE0)), *(((0, 1),) for _ in range(6)))
SELECTED = tuple((int(i < 2), key) for i, key in enumerate(KEYS))
AP55, CP55, SERIAL = (0, 0x00510055), (1, 0x00510055), (0, 0x00E70003)
BOOT_DEVICE = (0, 0x004B0003)
AP55_COLLATERAL = {
    **{(chip, key): size for chip in (0, 1) for key, size in (
        (0x0051000F, 1), (0x00510020, 4), (0x0051004A, 128), (0x0051004B, 4))},
    (0, 0x00510013): 4, (0, 0x00510014): 4, (0, 0x00510036): 1,
    (0, 0x0051003D): 4, (1, 0x0051003D): 4,
}
PAYLOAD_SHA256 = "5eac323b7d70128234864f1c32ff06c5938f2e907bfb83920b316c2788945806"
METADATA_PROFILE = "m4-602-save-metadata-candidate/1"
_DATA = Path(__file__).with_name("data") / "settings-fl23-payload.json"


class SettingsError(ValueError):
    pass


def need(condition, message):
    if not condition:
        raise SettingsError(message)


def pending_save_error(pair, ram, saved, *, original=False):
    """Bounded private diagnostic only; admission and SAVE semantics stay strict."""
    def summary(value):
        preview = value.data[:16].hex() + ('...' if len(value.data) > 16 else '')
        return f'attrs=0x{value.attrs:x},size={len(value.data)},hex={preview}'
    prefix = 'Unowned pending value in original SAVE group' if original else 'Unowned pending value in SAVE group'
    chip = 'AP' if pair[0] == 0 else 'CP'
    return (f'{prefix} 0x{pair[1] >> 16:04X}: {chip} key=0x{pair[1]:08X}; '
            f'RAM({summary(ram)}) != saved({summary(saved)}). '
            '该组保存会连带写入未获允许的待保存值，已停止。')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def body_identity(serial):
    need(type(serial) is bytes and len(serial) == 4 and serial not in (bytes(4), b"\xff" * 4),
         "Nondegenerate fresh four-byte body identity required")
    return sha(serial.hex().encode("ascii"))


@dataclass(frozen=True)
class Value:
    attrs: int
    data: bytes


@dataclass(frozen=True)
class Image:
    raw: bytes
    records: object


@dataclass(frozen=True)
class Snapshot:
    ram: Image
    saved: Image
    bin: Image
    bak: Image
    serial: bytes
    direct_cp: tuple


@dataclass(frozen=True)
class Record:
    chip: int
    key: int
    spans: tuple
    before_ram: bytes
    before_saved: bytes
    after_ram: bytes
    after_saved: bytes


@dataclass(frozen=True)
class Plan:
    kind: str
    identity: str
    boot_id: str
    nonce: str
    baseline: Snapshot
    records: tuple
    groups: tuple
    inverse_of: str | None = None
    origin: Plan | None = None
    metadata_profile: str = METADATA_PROFILE
    original: Snapshot | None = None
    save_effects_policy: str = save_effects.LEGACY
    gate_original: tuple | None = None
    looks_selection: tuple | None = None
    looks_original: tuple | None = None

    @property
    def plan_id(self):
        return sha(json.dumps(plan_manifest(self), sort_keys=True, separators=(",", ":")).encode())


def parse_image(raw):
    need(type(raw) is bytes and 0 < len(raw) <= MAX_SETTINGS_BYTES, "Bounded immutable BK4 evidence required")
    try:
        rows = bk4_rows(raw)
    except (ValueError, struct.error, IndexError) as exc:
        raise SettingsError("Invalid complete BK4: " + str(exc)) from exc
    need(len(rows) == 2 and all(row["records"] for row in rows), "Both populated BK4 chips required")
    values = {(chip, key): Value(entry["attrs"], raw[entry["offset"]:entry["offset"] + entry["size"]])
              for chip, row in enumerate(rows) for key, entry in row["records"].items()}
    return Image(raw, MappingProxyType(values))


def parse_snapshot(ram, saved, bin, bak, *, cp_live, serial):
    """Parse four full own-body captures; replace only selected CP live cache.

    BIN and BAK are independent complete reads. Their raw bytes/hashes remain
    evidence even when an inactive previous generation has different values.
    """
    images = [parse_image(raw) for raw in (ram, saved, bin, bak)]
    ref = images[0].records
    for image in images[1:]:
        need(set(image.records) == set(ref), "Complete four-plane record inventories differ")
        need(all((image.records[p].attrs, len(image.records[p].data)) == (v.attrs, len(v.data))
                 for p, v in ref.items()), "Four-plane attributes/lengths differ")
    need(type(cp_live) is dict and set(cp_live) == set(KEYS[:2]), "Both fresh direct selector-1 CP records required")
    live = dict(ref)
    for key, size in zip(KEYS[:2], SIZES[:2]):
        pair = (1, key)
        need(pair in live and live[pair].attrs == 8 and type(cp_live[key]) is bytes
             and len(cp_live[key]) == size, "CP selector-1 record identity/length/attributes differ")
        live[pair] = Value(8, cp_live[key])
    images[0] = Image(images[0].raw, MappingProxyType(live))
    identity = body_identity(serial)
    need(all(image.records.get(SERIAL, Value(0, b"")).data == serial for image in images),
         "Direct serial and all complete snapshot identities differ")
    result = Snapshot(*images, serial, tuple(sorted(cp_live.items())))
    need(body_identity(result.serial) == identity, "Snapshot identity differs")
    return result


def validate_snapshot(snapshot):
    """Validate all raw/map/direct-CP evidence without asserting boot freshness."""
    need(type(snapshot) is Snapshot, "Complete immutable settings Snapshot required")
    body_identity(snapshot.serial)
    need(type(snapshot.direct_cp) is tuple and len(snapshot.direct_cp) == 2,
         "Fresh direct CP observations required")
    rebuilt = parse_snapshot(*(getattr(snapshot, name).raw for name in ("ram", "saved", "bin", "bak")),
                             cp_live=dict(snapshot.direct_cp), serial=snapshot.serial)
    need(all(getattr(snapshot, name).records == getattr(rebuilt, name).records
             for name in ("ram", "saved", "bin", "bak")), "Snapshot raw evidence and logical maps differ")
    return snapshot


def _binding(snapshot, identity, boot_id, nonce):
    validate_snapshot(snapshot)
    need(native_ui.snapshot_valid(snapshot), "Native UI diagnostic shape/complete word groups differ")
    need(body_identity(snapshot.serial) == identity, "Plan must bind the fresh own-body snapshot")
    need(type(boot_id) is str and re.fullmatch(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}", boot_id),
         "Fresh canonical boot UUID required")
    need(type(nonce) is str and re.fullmatch(r"[0-9a-f]{32}", nonce) and int(nonce, 16),
         "Fresh nonzero 128-bit nonce required")


def _payload():
    fd = os.open(_DATA, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and 0 < before.st_size < 65536, "Bounded regular fixed preset asset required")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(65536)
        after = os.fstat(fd)
        need(all(getattr(before, k) == getattr(after, k) for k in
                 ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns"))
             and len(raw) == before.st_size, "Fixed preset asset changed during read")
    finally:
        os.close(fd)
    need(len(raw) < 65536 and sha(raw) == PAYLOAD_SHA256, "Fixed FL23 payload provenance/hash differs")
    value = json.loads(raw)
    need(value["schema"] == "a7m4-fixed-fl23-preset-spans/1" and value["total_payload_bytes"] == 3272,
         "Unknown fixed preset payload schema")
    result = []
    for i, row in enumerate(value["records"]):
        need(row["key"] == f"{KEYS[i]:08x}" and row["size"] == SIZES[i], "Fixed payload key/size differs")
        entries = row["spans"]
        need(len(entries) == len(SPANS[i]), "Fixed payload span count differs")
        patches = []
        for entry, (start, end) in zip(entries, SPANS[i]):
            raw = bytes.fromhex(entry["target_hex"])
            need((entry["start"], entry["end"]) == (start, end) and len(raw) == end - start
                 and sha(raw) == entry["sha256"], "Fixed preset span differs")
            patches.append((start, end, raw))
        result.append(tuple(patches))
    need(len(result) == 2, "Only two fixed CP payloads admitted")
    return tuple(result)


def _merge(raw, patches):
    output = bytearray(raw)
    for start, end, value in patches:
        need(0 <= start < end <= len(raw) and end - start == len(value), "Finite patch outside own record")
        output[start:end] = value
    return bytes(output)


def _backing_preconditions(snapshot, selected):
    active = snapshot.saved.records
    need(any(image.records == active for image in (snapshot.bin, snapshot.bak)),
         "Neither complete backing generation equals active saved API")
    for image in (snapshot.bin, snapshot.bak):
        need(all(image.records[p] == active[p] for p in selected),
             "Inactive backing selected preimage differs; no implicit normalization")


def plan_fixed_settings(snapshot, *, identity, boot_id, nonce):
    """Eight fixed FL2/FL3 records, derived over each fresh own-body plane.

    The six records select native FL2/FL3, not the four custom-look M9 slots.
    Custom1/M9 and all unrelated user choices/calibration stay outside this API.
    """
    _binding(snapshot, identity, boot_id, nonce)
    need(all(getattr(snapshot, name).records.get(AP55) == Value(0, b"\2")
             for name in ("ram", "saved", "bin", "bak")),
         "AP55 must already be02 in all four planes; use separate exact AP55 transaction first")
    patches, records = _payload(), []
    for i, (pair, size, spans) in enumerate(zip(SELECTED, SIZES, SPANS)):
        ram, saved = snapshot.ram.records.get(pair), snapshot.saved.records.get(pair)
        need(ram is not None and saved is not None and ram.attrs == (8 if i < 2 else 0x60)
             and len(ram.data) == size, "Fixed record identity/length/attributes differ")
        patch = patches[i] if i < 2 else ((0, 1, bytes((10 if i % 2 == 0 else 11,))),)
        records.append(Record(*pair, spans, ram.data, saved.data,
                              _merge(ram.data, patch), _merge(saved.data, patch)))
    _backing_preconditions(snapshot, SELECTED)
    result = Plan("fl23", identity, boot_id, nonce, snapshot, tuple(records), (0x02A4, 0x02CF))
    validate_plan(result)
    return result


def validate_fixed_prerequisites(snapshot):
    """Read-only FL23 feasibility on stock00 or current02, before any writes.

    This is not an executable Plan, does not project a false fresh AP55=02,
    and grants no release. Actual plan_fixed_settings still requires the
    separate AP55 transaction to have completed in all four planes.
    """
    validate_snapshot(snapshot)
    need(native_ui.snapshot_valid(snapshot), "Native UI diagnostic shape/complete word groups differ")
    modes = [getattr(snapshot, name).records.get(AP55) for name in ("ram", "saved", "bin", "bak")]
    need(all(value == modes[0] for value in modes) and modes[0] in (Value(0, b"\0"), Value(0, b"\2")),
         "Fixed prerequisites require four-plane AP55 both00 or both02")
    need(all(getattr(snapshot, name).records.get(CP55) == Value(0, b"\0")
             and getattr(snapshot, name).records.get(BOOT_DEVICE) == Value(0, b"\1")
             for name in ("ram", "saved", "bin", "bak")),
         "CP55 must remain00 and BOOT_DEVICE original01 in every plane")
    _backing_preconditions(snapshot, SELECTED + (AP55, CP55))
    patches, need_save = _payload(), {0x02A4: False, 0x02CF: False}
    for index, (pair, size) in enumerate(zip(SELECTED, SIZES)):
        value = snapshot.ram.records.get(pair)
        need(value is not None and value.attrs == (8 if index < 2 else 0x60) and len(value.data) == size,
             "Fixed prerequisite record identity/length/attributes differ")
        patch = patches[index] if index < 2 else ((0, 1, bytes((10 if index % 2 == 0 else 11,))),)
        saved = snapshot.saved.records[pair].data
        need_save[pair[1] >> 16] |= _merge(saved, patch) != saved
    for group, required in need_save.items():
        if required:
            for pair, value in snapshot.ram.records.items():
                if pair[1] >> 16 == group and pair not in SELECTED and not native_ui.diagnostic(pair,snapshot.ram.records):
                    need(value == snapshot.saved.records[pair],
                         pending_save_error(pair, value, snapshot.saved.records[pair]))
    return {"schema": "a7m4-fixed-settings-prerequisites/1", "verified": True,
            "selected_records": 8, "requires_separate_AP55_transition": modes[0].data == b"\0",
            "save_groups_required": [group for group, required in need_save.items() if required],
            "fixed_payload_sha256": PAYLOAD_SHA256,
            "logical_sha256": {name: _mapping_sha(getattr(snapshot, name).records)
                               for name in ("ram", "saved", "bin", "bak")},
            "camera_io": False, "device_execution_ready": False}


def plan_ap55(snapshot, *, identity, boot_id, nonce, save_effects_policy=save_effects.LEGACY):
    """Separate exact AP00→02 / already02 no-op; CP55 never changes.

    SAVE51 can persist only the thirteen named native collateral records from
    their fresh own-body RAM values. Their saved originals are retained and
    reported; inverse restores AP55, not old boot flags or raw generations.
    """
    _binding(snapshot, identity, boot_id, nonce)
    for pair in (AP55, CP55):
        need(pair in snapshot.ram.records and snapshot.ram.records[pair].attrs == 0
             and len(snapshot.ram.records[pair].data) == 1, "AP/CP55 format differs")
    ram, saved = snapshot.ram.records[AP55].data, snapshot.saved.records[AP55].data
    need(ram == saved and ram in (b"\0", b"\2"), "Only fresh AP55 both00 or both02 is admitted")
    need(save_effects_policy in (save_effects.LEGACY,save_effects.NATIVE51), 'Unknown native SAVE effect policy')
    if save_effects_policy==save_effects.LEGACY:
        for pair, size in AP55_COLLATERAL.items():
            value = snapshot.ram.records.get(pair)
            need(value is not None and value.attrs == (0 if pair == (0, 0x00510036) else 2) and len(value.data) == size,
                 "Named SAVE51 collateral identity/length/attributes differ")
        _backing_preconditions(snapshot, (AP55, CP55))
    else:
        need(all(image.records[p]==snapshot.saved.records[p] for image in (snapshot.bin,snapshot.bak)
                 for p in (AP55,CP55,BOOT_DEVICE)), 'Current C/D backing preimages differ')
    record = Record(*AP55, ((0, 1),), ram, saved, b"\2", b"\2")
    result = Plan("ap55", identity, boot_id, nonce, snapshot, (record,), (0x0051,),save_effects_policy=save_effects_policy)
    validate_plan(result)
    return result


def validate_plan(plan):
    if type(plan) is Plan and plan.kind=='backup-target-ap55':
        from .backup_target_settings import validate_ap55_plan
        return validate_ap55_plan(plan)
    need(type(plan) is Plan,'Known finite settings Plan required')
    if type(plan) is Plan and plan.kind in ('scoped-looks','scoped-looks-restore','scoped-restore-st'):
        from .looks_settings import validate_plan as validate_scoped
        return validate_scoped(plan)
    need(plan.looks_selection is None and plan.looks_original is None,
         'Scoped looks metadata requires its finite plan kind')
    need(type(plan) is Plan and plan.save_effects_policy in (save_effects.LEGACY,save_effects.NATIVE51),
         'Known finite SAVE effect policy required')
    if plan.kind=='gate-restore-ap55':return _validate_gate_restore(plan)
    need(plan.gate_original is None,'Gate originals require the finite cumulative restore kind')
    need(plan.save_effects_policy==save_effects.LEGACY or plan.kind in ('ap55','original-ap55'), 'Native SAVE51 policy requires finite AP55 kind')
    if type(plan) is Plan and plan.kind in ('original-fl23','original-ap55'):
        return _validate_original_plan(plan)
    need(type(plan) is Plan and plan.kind in ("fl23", "ap55"), "Only fixed settings plans admitted")
    need(plan.original is None, "Legacy fixed plans cannot carry a foreign original snapshot")
    _binding(plan.baseline, plan.identity, plan.boot_id, plan.nonce)
    need(plan.metadata_profile in (METADATA_PROFILE, "strict-nonrecord-unchanged/1"),
         "Unknown settings metadata profile")
    if plan.metadata_profile == METADATA_PROFILE and plan.save_effects_policy==save_effects.LEGACY:
        ram_cp = bk4_rows(plan.baseline.ram.raw)[1]
        need(plan.baseline.ram.raw[ram_cp["base"] + 9] in (0, 1), "RAM CP+9 baseline outside candidate00/01")
    expected = SELECTED if plan.kind == "fl23" else (AP55,)
    need(tuple((r.chip, r.key) for r in plan.records) == expected, "Fixed plan record set/order differs")
    need(plan.groups == ((0x02A4, 0x02CF) if plan.kind == "fl23" else (0x0051,)), "Fixed SAVE groups differ")
    if plan.save_effects_policy==save_effects.LEGACY:
        _backing_preconditions(plan.baseline, expected)
    else:
        need(all(image.records[p]==plan.baseline.saved.records[p] for image in (plan.baseline.bin,plan.baseline.bak)
                 for p in (AP55,CP55,BOOT_DEVICE)), 'Current C/D backing preimages differ')
    need(all(getattr(plan.baseline, name).records.get(CP55) == Value(0, b"\0")
             and getattr(plan.baseline, name).records.get(BOOT_DEVICE) == Value(0, b"\1")
             for name in ("ram", "saved", "bin", "bak")),
         "CP55 must remain00 and BOOT_DEVICE original01 in every plane")
    if plan.kind == "fl23":
        need(all(getattr(plan.baseline, name).records.get(AP55) == Value(0, b"\2")
                 for name in ("ram", "saved", "bin", "bak")), "Fixed settings require separately verified AP55=02")
    else:
        for pair in (AP55, CP55):
            need(pair in plan.baseline.ram.records and plan.baseline.ram.records[pair].attrs == 0
                 and len(plan.baseline.ram.records[pair].data) == 1, "AP/CP55 format differs")
        need(plan.baseline.ram.records[AP55] == plan.baseline.saved.records[AP55], "AP55 planes differ")
        need(plan.baseline.ram.records[AP55].data in (b"\0", b"\2"), "AP55 fixed preimage differs")
        if plan.save_effects_policy==save_effects.LEGACY:
            for pair, size in AP55_COLLATERAL.items():
                value = plan.baseline.ram.records.get(pair)
                need(value is not None and value.attrs == (0 if pair == (0, 0x00510036) else 2)
                     and len(value.data) == size, "Named SAVE51 collateral format differs")
    if plan.inverse_of is None:
        need(plan.origin is None, "Forward plan cannot carry a foreign inverse origin")
    else:
        need(type(plan.origin) is Plan and plan.origin.inverse_of is None,
             "Inverse must retain the validated fixed forward plan")
        validate_plan(plan.origin)
        need(plan.origin.plan_id == plan.inverse_of and plan.origin.identity == plan.identity
             and plan.origin.kind == plan.kind and plan.nonce != plan.origin.nonce
             and plan.metadata_profile == plan.origin.metadata_profile
             and plan.save_effects_policy == plan.origin.save_effects_policy,
             "Inverse fixed forward binding differs")
    for i, record in enumerate(plan.records):
        pair = record.chip, record.key
        spans = SPANS[i] if plan.kind == "fl23" else ((0, 1),)
        need(record.spans == spans, "Finite ownership spans differ")
        size, attrs = (SIZES[i], 8 if i < 2 else 0x60) if plan.kind == "fl23" else (1, 0)
        need(plan.baseline.ram.records[pair].attrs == attrs, "Fixed record attributes differ")
        for plane in ("ram", "saved"):
            before, after = getattr(record, "before_" + plane), getattr(record, "after_" + plane)
            need(type(before) is bytes and type(after) is bytes and len(before) == len(after) == size
                 and before == getattr(plan.baseline, plane).records[pair].data, "Plan preimage/length differs")
            need(all(a == b or any(lo <= j < hi for lo, hi in spans)
                     for j, (a, b) in enumerate(zip(before, after))), "Change outside finite ownership")
            if plan.inverse_of is not None:
                original = plan.origin.records[i]
                need(all(before[a:b] == getattr(original, "after_" + plane)[a:b]
                         and after[a:b] == getattr(original, "before_" + plane)[a:b] for a, b in spans),
                     "Inverse values differ from the bound forward originals")
        if plan.inverse_of is None:
            need(all(record.after_ram[lo:hi] == record.after_saved[lo:hi] for lo, hi in spans),
                 "Forward target owned bytes differ between planes")
            if plan.kind == "ap55":
                need(record.after_ram == record.after_saved == b"\2", "Only fixed AP55 target02 admitted")
            elif i >= 2:
                need(record.after_ram == record.after_saved == bytes((10 if i % 2 == 0 else 11,)),
                     "Fixed FL2/FL3 target differs")
            else:
                need(all(record.after_ram[a:b] == raw for a, b, raw in _payload()[i]), "Fixed preset target differs")
    # SAVE copies complete selected-group RAM, so no unowned pending values
    # can be persisted accidentally. AP55 has exactly thirteen named effects.
    selected = set(expected)
    for group in plan.groups:
        need_save = any(r.key >> 16 == group and r.before_saved != r.after_saved for r in plan.records)
        if need_save:
            for pair, value in plan.baseline.ram.records.items():
                if pair[1] >> 16 == group and pair not in selected:
                    if save_effects.effect(plan,pair):continue
                    if plan.kind == "ap55" and pair in AP55_COLLATERAL:
                        continue
                    if native_ui.diagnostic(pair,plan.baseline.ram.records):continue
                    need(value == plan.baseline.saved.records[pair],
                         pending_save_error(pair, value, plan.baseline.saved.records[pair]))
    return plan


def plan_manifest(plan):
    """Private plan summary; immutable source bytes stay in the local job only."""
    return {**({'looks_selection':list(plan.looks_selection)} if plan.looks_selection is not None else {}),
            **({'looks_original':plan.looks_original} if plan.looks_original is not None else {}),
            **({'gate_original':list(plan.gate_original)} if plan.gate_original is not None else {}),
            **({'save_effects_policy':plan.save_effects_policy} if plan.save_effects_policy!=save_effects.LEGACY else {}),
            **({'original_target': {name: {'bytes':len(getattr(plan.original,name).raw),
               'sha256':sha(getattr(plan.original,name).raw)} for name in ('ram','saved','bin','bak')}}
               if plan.original is not None else {}),
            "schema": "a7m4-toolbox-fixed-settings-plan/1", "kind": plan.kind,
            "identity": plan.identity, "boot_id": plan.boot_id, "nonce": plan.nonce,
            "groups": list(plan.groups), "inverse_of": plan.inverse_of,
            "snapshots": {name: {"bytes": len(getattr(plan.baseline, name).raw),
                                     "sha256": sha(getattr(plan.baseline, name).raw),
                                     "logical_sha256": _mapping_sha(getattr(plan.baseline, name).records)}
                          for name in ("ram", "saved", "bin", "bak")},
            "direct_cp": [{"key": f"{key:08x}", "bytes": len(raw), "sha256": sha(raw)}
                          for key, raw in plan.baseline.direct_cp],
            "records": [{"chip": r.chip, "key": f"{r.key:08x}", "spans": list(r.spans),
                         **{name: {"bytes": len(getattr(r, name)), "sha256": sha(getattr(r, name))}
                            for name in ("before_ram", "before_saved", "after_ram", "after_saved")}}
                        for r in plan.records],
            "fixed_payload_sha256": PAYLOAD_SHA256 if plan.kind == "fl23" or
                (plan.kind=='scoped-looks' and plan.looks_selection[0]) else None,
            "metadata_profile": {"id": plan.metadata_profile,
                                 "status": "NEW_SOFTWARE_CANDIDATE_PHYSICAL_NOT_PERFORMED",
                                 "post_SAVE_AP_saved_count": "opaque-u32-recorded-no-step-or-filename-order-claim",
                                 "post_SAVE_RAM_CP_plus9": "observed-not-admission" if plan.save_effects_policy==save_effects.NATIVE51 or plan.kind in ('scoped-looks','scoped-looks-restore','scoped-restore-st') else "only00-to01-no-reversion",
                                 "other_nonrecord_bytes": "valid-complete-BK4-observed" if plan.kind in ('scoped-looks','scoped-looks-restore','scoped-restore-st') else "exact-unchanged-including-index-gap-trailer",
                                 "checksum": "complete-additive-recompute-each-segment"},
            "WBI_writes": 0, "automatic_rollback": False,
            "reload_and_program_adoption": "MAIN_SEPARATE_UNPROVEN_BY_SETTINGS",
            "camera_io": False, "device_execution_ready": False}


def _mapping_sha(values):
    digest = hashlib.sha256()
    for (chip, key), value in sorted(values.items()):
        digest.update(struct.pack("<BIHI", chip, key, value.attrs, len(value.data)))
        digest.update(value.data)
    return digest.hexdigest()


def inverse_plan(forward, fresh, *, boot_id, nonce, completion):
    """Only completed/readback-verified forward, fresh nonce and exact owned values."""
    validate_plan(forward)
    need(type(completion) is dict and completion.get("status") == "DONE"
         and completion.get("plan_id") == forward.plan_id and completion.get("full_readback_verified") is True,
         "Inverse requires exact completed full-readback receipt, never partial state")
    _binding(fresh, forward.identity, boot_id, nonce)
    need(nonce != forward.nonce, "Inverse nonce must be fresh")
    rows = []
    for old in forward.records:
        pair = old.chip, old.key
        before_ram, before_saved = fresh.ram.records[pair].data, fresh.saved.records[pair].data
        for plane, value in (("ram", before_ram), ("saved", before_saved)):
            need(all(value[a:b] == getattr(old, "after_" + plane)[a:b] for a, b in old.spans),
                 "Installed owned bytes changed; no automatic inverse")
        rows.append(replace(old, before_ram=before_ram, before_saved=before_saved,
                            after_ram=_merge(before_ram, tuple((a, b, old.before_ram[a:b]) for a, b in old.spans)),
                            after_saved=_merge(before_saved, tuple((a, b, old.before_saved[a:b]) for a, b in old.spans))))
    if forward.save_effects_policy==save_effects.LEGACY:
        _backing_preconditions(fresh, tuple((r.chip, r.key) for r in rows))
    result = Plan(forward.kind, forward.identity, boot_id, nonce, fresh, tuple(rows), forward.groups,
                  forward.plan_id, forward, forward.metadata_profile,save_effects_policy=forward.save_effects_policy)
    validate_plan(result)
    return result


# Original-backup recovery is independent of a previous forward operation.
# Fixed business spans only; the original snapshot is retained, not a patch API.
ORIGINAL_BASE_KEYS = (0x02CF0D0D, 0x02CF0D0F, 0x02CF0D11,
                      0x02CF12EB, 0x02CF12ED, 0x02CF12EF,
                      0x02CF130B, 0x02CF130D, 0x02CF130F)


def _original_records(fresh, original, kind):
    validate_snapshot(fresh); validate_snapshot(original)
    need(fresh.serial == original.serial, 'Original settings belong to another camera')
    for plane in ('ram','saved','bin','bak'):
        current, target = getattr(fresh,plane).records, getattr(original,plane).records
        need(set(current) == set(target) and all(
            current[p].attrs == target[p].attrs and len(current[p].data) == len(target[p].data)
            for p in current), 'Original/current complete settings inventory/attributes differ')
    pairs = (AP55,) if kind == 'original-ap55' else SELECTED + tuple(
        (0,key) for key in ORIGINAL_BASE_KEYS if (0,key) in fresh.ram.records)
    spans = {**dict(zip(SELECTED,SPANS)), AP55:((0,1),),
             **{(0,key):((0,1),) for key in ORIGINAL_BASE_KEYS}}
    rows = []
    for pair in pairs:
        expected_size = 1 if pair == AP55 or pair[1] in ORIGINAL_BASE_KEYS else SIZES[SELECTED.index(pair)]
        expected_attrs = 0 if pair == AP55 else 8 if pair[0] == 1 else 0x60
        need(fresh.ram.records[pair].attrs == expected_attrs
             and len(fresh.ram.records[pair].data) == expected_size, 'Original fixed record format differs')
        values = {}
        for plane in ('ram','saved'):
            before, target = getattr(fresh,plane).records[pair].data, getattr(original,plane).records[pair].data
            values['before_'+plane] = before
            values['after_'+plane] = _merge(before,tuple((lo,hi,target[lo:hi]) for lo,hi in spans[pair]))
        rows.append(Record(*pair,spans[pair],**values))
    return tuple(rows), ((0x0051,) if kind == 'original-ap55' else (0x02A4,0x02CF))


def _validate_original_plan(plan):
    _binding(plan.baseline, plan.identity, plan.boot_id, plan.nonce)
    need(plan.original is not None and plan.inverse_of is None and plan.origin is None,
         'Original-value plan requires original snapshot, not a forward/inverse job')
    need(plan.metadata_profile == METADATA_PROFILE, 'Original-value SAVE metadata profile differs')
    rows,groups = _original_records(plan.baseline, plan.original, plan.kind)
    need(plan.records == rows and plan.groups == groups, 'Original-value target or finite span differs')
    if plan.save_effects_policy==save_effects.LEGACY:
        _backing_preconditions(plan.baseline,tuple((r.chip,r.key) for r in rows))
    else:
        need(all(image.records[p]==plan.baseline.saved.records[p] for image in (plan.baseline.bin,plan.baseline.bak)
                 for p in (AP55,CP55,BOOT_DEVICE)), 'Current original C/D backing preimages differ')
    ram_cp=bk4_rows(plan.baseline.ram.raw)[1]
    need(plan.baseline.ram.raw[ram_cp['base']+9] in (0,1), 'RAM CP flag outside reviewed metadata profile')
    for snapshot in (plan.baseline,plan.original):
        for plane in ('ram','saved','bin','bak'):
            values=getattr(snapshot,plane).records
            need(values.get(CP55)==Value(0,b'\0') and values.get(BOOT_DEVICE)==Value(0,b'\1'),
                 'Original/current CP55 or BOOT_DEVICE outside supported scope')
            need(values.get(AP55) in (Value(0,b'\0'),Value(0,b'\2')), 'Original/current AP55 outside00/02')
    selected={(r.chip,r.key) for r in rows}
    if plan.kind=='original-ap55':
        need(plan.baseline.ram.records[AP55]==plan.baseline.saved.records[AP55], 'AP55 current planes differ')
        for pair,size in (AP55_COLLATERAL.items() if plan.save_effects_policy==save_effects.LEGACY else ()):
            v=plan.baseline.ram.records.get(pair)
            need(v is not None and v.attrs==(0 if pair==(0,0x00510036) else 2) and len(v.data)==size,
                 'Named original SAVE51 collateral format differs')
    for group in groups:
        if any(r.before_saved!=r.after_saved for r in rows if r.key>>16==group):
            for pair,value in plan.baseline.ram.records.items():
                if pair[1]>>16==group and pair not in selected:
                    if save_effects.effect(plan,pair):continue
                    if plan.kind=='original-ap55' and pair in AP55_COLLATERAL:continue
                    if native_ui.diagnostic(pair,plan.baseline.ram.records):continue
                    need(value==plan.baseline.saved.records[pair],
                         pending_save_error(pair, value, plan.baseline.saved.records[pair], original=True))
    return plan


def plan_original_values(fresh, original, *, kind, identity, boot_id, nonce,save_effects_policy=save_effects.LEGACY):
    need(kind in ('original-fl23','original-ap55'), 'Only finite original business-value groups admitted')
    rows,groups = _original_records(fresh,original,kind)
    result=Plan(kind,identity,boot_id,nonce,fresh,rows,groups,original=original,save_effects_policy=save_effects_policy)
    return validate_plan(result)


def _validate_gate_restore(plan):
    """Only capsule's AP55 original; partial current C is safe to overwrite."""
    _binding(plan.baseline,plan.identity,plan.boot_id,plan.nonce)
    need(plan.save_effects_policy==save_effects.NATIVE51 and plan.inverse_of is None
         and plan.origin is None and plan.original is None and plan.groups==(0x51,)
         and plan.metadata_profile==METADATA_PROFILE and len(plan.records)==1,
         'Finite cumulative AP55 restore metadata differs')
    need(type(plan.gate_original) is tuple and len(plan.gate_original)==2
         and all(x in ('00','02') for x in plan.gate_original),'Exact earliest AP55 targets required')
    r=plan.records[0]
    need((r.chip,r.key)==AP55 and r.spans==((0,1),),'Only registered AP55 restore C permitted')
    for p in ('ram','saved','bin','bak'):
        values=getattr(plan.baseline,p).records;v=values.get(AP55)
        need(v is not None and v.attrs==0 and len(v.data)==1,'Current AP55 C shape differs')
        need(values.get(CP55)==Value(0,b'\0') and values.get(BOOT_DEVICE)==Value(0,b'\1'),
             'Restore required CP55/BOOT D differs')
    need(r.before_ram==plan.baseline.ram.records[AP55].data and r.before_saved==plan.baseline.saved.records[AP55].data
         and r.after_ram==bytes.fromhex(plan.gate_original[0]) and r.after_saved==bytes.fromhex(plan.gate_original[1]),
         'Cumulative AP55 plan target/preimage differs')
    return plan


def needs_save(plan,group):
    if plan.kind in ('scoped-looks','scoped-looks-restore','scoped-restore-st'):
        from .looks_settings import needs_save as scoped_needs_save
        return scoped_needs_save(plan,group)
    if any(r.key>>16==group and r.before_saved!=r.after_saved for r in plan.records):return True
    return plan.kind in ('gate-restore-ap55','backup-target-ap55') and group==0x51 and any(
        getattr(plan.baseline,p).records[AP55].data!=plan.records[0].after_saved for p in ('bin','bak'))
