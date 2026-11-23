"""Portable four-slot ST CUBE compiler and exact local AP/CP content plans.

The native signed7 packing, BT.601 coordinate hypothesis, trilinear CUBE
sampling and bounded fitting mathematics adapt the MIT A7C II looktool source.
The complete upstream license, M4 runtime source and reproducible build hashes
are retained in data/lut-runtime.json. No calibration NPZ or Sony image is
bundled. NumPy >=2 is an explicit compilation dependency, imported lazily.

Compilation is a mathematical approximation with a declared response matrix;
it is not measured M4 color calibration. Public planning currently supports
the existing R050/R051c combination and its LUT-only derivatives. Stock runtime
research is retained as an explicitly unreviewed offline artifact, not exposed
as a supported installation path. Current-combination changes retain the
existing native17/name/sound code.
These functions never connect to a camera or write a complete image.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from functools import lru_cache
import hashlib
import io
import itertools
import json
import math
import os
from pathlib import Path
import shlex
import struct
from typing import Any

from .offline import PlanError, _path, _regular_reader, inspect_image, plan_content_changes


MAX_CUBE_BYTES = 256 * 1024 * 1024
TABLE_BYTES = 1215
RECORD_BYTES = 1248
NODES = 405
MAX_SAMPLES = 65536


def _numpy():
    try:
        import numpy as np
    except ImportError as exc:
        raise PlanError("CUBE compilation requires the explicit NumPy >=2 dependency") from exc
    if int(np.__version__.split(".", 1)[0]) < 2:
        raise PlanError("CUBE compilation requires NumPy >=2")
    return np


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _finite(value: Any, field: str, minimum: float, maximum: float) -> float:
    if type(value) not in (int, float) or not math.isfinite(value) or not minimum <= value <= maximum:
        raise PlanError(f"{field} must be a finite number in {minimum}..{maximum}")
    return float(value)


@lru_cache(maxsize=1)
def _profile() -> dict[str, Any]:
    return json.loads((Path(__file__).with_name("data") / "lut-runtime.json").read_text(encoding="utf-8"))


@dataclass(frozen=True)
class Cube:
    """A standalone CUBE at its original grid size; red varies fastest."""

    title: str
    size: int
    minimum: tuple[float, float, float]
    maximum: tuple[float, float, float]
    values: Any
    sha256: str
    filename: str

    def sample(self, rgb: Any):
        np = _numpy()
        colors = np.asarray(rgb, dtype=float)
        if colors.ndim != 2 or colors.shape[1] != 3 or not np.isfinite(colors).all():
            raise PlanError("CUBE sampling requires a finite N by 3 RGB array")
        at = np.clip((colors - self.minimum) / (np.asarray(self.maximum) - self.minimum), 0, 1) * (self.size - 1)
        lo = np.minimum(at.astype(int), self.size - 2)
        fraction = at - lo
        result = np.zeros_like(colors)
        for red, green, blue in itertools.product((0, 1), repeat=3):
            weight = ((fraction[:, 0] if red else 1 - fraction[:, 0]) *
                      (fraction[:, 1] if green else 1 - fraction[:, 1]) *
                      (fraction[:, 2] if blue else 1 - fraction[:, 2]))
            result += weight[:, None] * self.values[lo[:, 2] + blue, lo[:, 1] + green, lo[:, 0] + red]
        return result


def parse_cube(path: str | os.PathLike[str]) -> Cube:
    """Strictly parse a local standalone 3D CUBE, grid 2..129, no shaper.

    The source is bounded and read once. Duplicate/late headers, nonfinite data,
    malformed titles, invalid domains and extra/missing rows are rejected.
    Header claims about color space are not inferred: the API contract is an
    explicitly supplied display-encoded sRGB-to-sRGB transform.
    """
    np = _numpy()
    local = _path(path)
    with _regular_reader(local) as (stream, info):
        if info.st_size > MAX_CUBE_BYTES:
            raise PlanError("CUBE exceeds the 256 MiB local input limit")
        raw = stream.read(MAX_CUBE_BYTES + 1)
    if len(raw) > MAX_CUBE_BYTES:
        raise PlanError("CUBE exceeds the 256 MiB local input limit")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeError as exc:
        raise PlanError("CUBE must be UTF-8 text") from exc
    minimum, maximum = (0., 0., 0.), (1., 1., 1.)
    title, size, rows, values, seen = "", None, 0, None, set()
    for line_number, line in enumerate(io.StringIO(text), 1):
        if len(line) > 4096:
            raise PlanError(f"CUBE line {line_number} is too long")
        try:
            words = shlex.split(line, comments=True)
        except ValueError as exc:
            raise PlanError(f"CUBE line {line_number}: malformed quoting") from exc
        if not words:
            continue
        key = words[0]
        if key in ("TITLE", "LUT_3D_SIZE", "DOMAIN_MIN", "DOMAIN_MAX"):
            if key in seen or rows:
                raise PlanError("CUBE has a duplicate or late header")
            seen.add(key)
            if key == "TITLE":
                if len(words) != 2 or len(words[1].encode("utf-8")) > 1024 or any(not c.isprintable() for c in words[1]):
                    raise PlanError("CUBE TITLE needs one printable value of at most 1024 UTF-8 bytes")
                title = words[1]
            elif key == "LUT_3D_SIZE":
                if len(words) != 2 or not words[1].isascii() or not words[1].isdigit():
                    raise PlanError("CUBE LUT_3D_SIZE needs an integer")
                size = int(words[1])
                if not 2 <= size <= 129:
                    raise PlanError("CUBE grid must be 2..129")
                values = np.empty((size ** 3, 3), dtype=float)
            else:
                if len(words) != 4:
                    raise PlanError("CUBE domain needs three finite values")
                try:
                    domain = tuple(float(v) for v in words[1:])
                except ValueError as exc:
                    raise PlanError("CUBE domain needs three finite values") from exc
                if not all(math.isfinite(v) and abs(v) <= 1e12 for v in domain):
                    raise PlanError("CUBE domain needs finite bounded values")
                if key == "DOMAIN_MIN":
                    minimum = domain
                else:
                    maximum = domain
            continue
        if key.startswith("LUT_") or len(words) != 3 or size is None:
            raise PlanError("Only standalone 3D CUBE input is supported; 1D/shaper LUTs are unsupported")
        if rows >= size ** 3:
            raise PlanError("CUBE has more rows than its declared grid")
        try:
            color = tuple(float(v) for v in words)
        except ValueError as exc:
            raise PlanError(f"CUBE line {line_number} needs three finite RGB values") from exc
        if not all(math.isfinite(v) and abs(v) <= 1e12 for v in color):
            raise PlanError("CUBE contains nonfinite or unbounded RGB data")
        values[rows] = color
        rows += 1
    if size is None or rows != size ** 3:
        raise PlanError("CUBE is incomplete for its declared 3D grid")
    if any(high <= low for low, high in zip(minimum, maximum)):
        raise PlanError("CUBE DOMAIN_MAX must exceed DOMAIN_MIN in every channel")
    values = values.reshape(size, size, size, 3)
    values.flags.writeable = False
    return Cube(title, size, minimum, maximum, values, _sha(raw), local.name)


def _coordinates(rgb):
    np = _numpy()
    kr, kb = .299, .114
    kg = 1 - kr - kb
    matrix = np.array([[kr, kg, kb], [-kr / (2 * (1 - kb)), -kg / (2 * (1 - kb)), .5],
                       [.5, -kg / (2 * (1 - kr)), -kb / (2 * (1 - kr))]])
    return (rgb @ matrix.T - [16 / 255, 0, 0]) * 255 / [219, 224, 224]


def _interpolation(rgb):
    np = _numpy()
    at = np.clip(_coordinates(rgb) * [4, 8, 8] + [0, 4, 4], [0, 0, 0], [4, 8, 8])
    lo = np.minimum(at.astype(int), [3, 7, 7])
    fraction = at - lo
    ids, weights = [], []
    for dy, dc1, dc2 in itertools.product((0, 1), repeat=3):
        ids.append((lo[:, 0] + dy) * 81 + (lo[:, 1] + dc1) * 9 + lo[:, 2] + dc2)
        weights.append(np.prod(np.where([dy, dc1, dc2], fraction, 1 - fraction), axis=1))
    return np.stack(ids, axis=1), np.stack(weights, axis=1)


def encode_table(coefficients: Any) -> bytes:
    np = _numpy()
    array = np.asarray(coefficients)
    if (array.shape != (NODES, 3) or not np.isfinite(array).all() or
            np.any(array != np.rint(array)) or np.any((array < -64) | (array > 63))):
        raise PlanError("Native table requires 405 by 3 integer signed7 coefficients in -64..63")
    return array.astype("i1").T.copy().tobytes()


def decode_table(raw: bytes):
    np = _numpy()
    if not isinstance(raw, bytes) or len(raw) != TABLE_BYTES:
        raise PlanError("Native table must contain exactly 1215 planar bytes")
    array = np.frombuffer(raw, dtype="i1").reshape(3, NODES).T.astype(int)
    encode_table(array)
    return array


def _fnv(raw: bytes) -> int:
    value = 0x811c9dc5
    for byte in raw:
        value = ((value ^ byte) * 0x01000193) & 0xffffffff
    return value


def make_record(table: bytes) -> bytes:
    decode_table(table)
    return b"M4L1" + struct.pack("<I", _fnv(table)) + table + bytes(25)


def _check_record(raw: bytes) -> None:
    if (len(raw) != RECORD_BYTES or raw[:4] != b"M4L1" or raw[1223:] != bytes(25) or
            struct.unpack_from("<I", raw, 4)[0] != _fnv(raw[8:1223])):
        raise PlanError("Existing LUT record has invalid M4L1/FNV/padding")
    decode_table(raw[8:1223])


@lru_cache(maxsize=1)
def _smoothness():
    np = _numpy()
    matrix = np.zeros((NODES, NODES))
    for y, c1, c2 in itertools.product(range(5), range(9), range(9)):
        i = y * 81 + c1 * 9 + c2
        for condition, j in ((y < 4, i + 81), (c1 < 8, i + 9), (c2 < 8, i + 1)):
            if condition:
                matrix[i, i] += 1
                matrix[j, j] += 1
                matrix[i, j] -= 1
                matrix[j, i] -= 1
    return matrix


def _fit(source, target, response, regularization):
    np = _numpy()
    if np.max(np.abs(target - source)) < 1e-11:
        return np.zeros((NODES, 3), dtype=int), {"epochs": 0, "max_coordinate_update": 0., "converged": True}
    ids, weights = _interpolation(source)
    delta = (target - source) @ np.linalg.inv(response) * 256
    h, rhs = np.zeros((NODES, NODES)), np.zeros((NODES, 3))
    for i in range(8):
        np.add.at(rhs, ids[:, i], weights[:, i, None] * delta)
        for j in range(8):
            np.add.at(h, (ids[:, i], ids[:, j]), weights[:, i] * weights[:, j])
    matrix = h + regularization * _smoothness() + np.eye(NODES) * .001
    coefficients = np.clip(np.linalg.solve(matrix, rhs), -64, 63)
    residual = rhs - matrix @ coefficients
    update = float("inf")
    for epoch in range(300):
        update = 0.
        for i in range(NODES):
            change = np.clip(coefficients[i] + residual[i] / matrix[i, i], -64, 63) - coefficients[i]
            update = max(update, float(np.max(np.abs(change))))
            coefficients[i] += change
            residual -= matrix[:, i, None] * change[None, :]
        if update < .0001:
            break
    return np.rint(coefficients).astype(int), {"epochs": epoch + 1, "max_coordinate_update": update, "converged": update < .0001}


def _metrics(actual, expected) -> dict[str, float]:
    np = _numpy()
    error = np.abs(actual - expected)
    return {"rgb_mae": float(error.mean()), "abs_rgb_p95": float(np.quantile(error, .95)),
            "max_channel_error": float(error.max())}


def compile_cube(path: str | os.PathLike[str], *, strength: float = 1., response_matrix: Any = None,
                 samples: int = 4096, regularization: float = .1, seed: int = 602) -> dict[str, Any]:
    """Produce a real native table/record, paired with zero native108 controls.

    ``strength`` blends the display transform with the input before fitting.
    The default response is explicitly an uncalibrated identity matrix, not a
    C2 or M4 measured response. A caller-supplied response is likewise reported
    as supplied and unverified. Quality values assess this declared algebra
    only and do not gate user acceptance or claim camera color accuracy.
    """
    np = _numpy()
    strength = _finite(strength, "strength", 0., 1.)
    regularization = _finite(regularization, "regularization", 1e-12, 1e6)
    if type(samples) is not int or not 512 <= samples <= MAX_SAMPLES:
        raise PlanError("samples must be an integer in 512..65536")
    if type(seed) is not int or not 0 <= seed < (1 << 64):
        raise PlanError("seed must be an integer in 0..2**64-1")
    response = np.eye(3) if response_matrix is None else np.asarray(response_matrix, dtype=float)
    if response.shape != (3, 3) or not np.isfinite(response).all() or np.linalg.cond(response) > 30:
        raise PlanError("response_matrix must be finite, invertible and well-conditioned 3 by 3")
    cube = parse_cube(path)
    rng = np.random.default_rng(seed)
    gray = np.repeat(np.linspace(.01, .99, 512)[:, None], 3, axis=1)
    training = np.concatenate([rng.uniform(.015, .985, (samples, 3)), gray])
    testing = rng.uniform(.015, .985, (2048, 3))

    def targets(colors):
        return colors + strength * (np.clip(cube.sample(colors), 0, 1) - colors)

    coefficients, convergence = _fit(training, targets(training), response, regularization)
    table = encode_table(coefficients)
    record = make_record(table)
    ids, weights = _interpolation(testing)
    predicted = np.clip(testing + (coefficients[ids] * weights[:, :, None]).sum(axis=1) / 256 @ response, 0, 1)
    raw_target = cube.sample(testing)
    expected = targets(testing)
    return {
        "schema": "a7m4-compiled-cube/1", "base_look": "ST", "strength": strength,
        "source_cube": {"filename": cube.filename, "title": cube.title, "sha256": cube.sha256,
                        "grid": cube.size, "domain_min": list(cube.minimum), "domain_max": list(cube.maximum),
                        "contract": "explicit-user-supplied-display-encoded-sRGB-to-sRGB", "resampled_to_common_grid": False},
        "response": {"kind": "uncalibrated-identity-matrix" if response_matrix is None else "caller-supplied-unverified-matrix",
                     "matrix": response.tolist(), "M4_measured_calibration": False},
        "format": "native-5x9x9-signed7-planar-M4L1-FNV1a", "table_hex": table.hex(),
        "record_hex": record.hex(), "table_sha256": _sha(table), "record_sha256": _sha(record),
        "native_basis_hex": bytes(108).hex(), "native_controls": [0.] * 17,
        "fit": {"seed": seed, "training_samples": len(training), "holdout_samples": len(testing),
                "regularization": regularization, "convergence": convergence,
                "coefficient_minimum": int(coefficients.min()), "coefficient_maximum": int(coefficients.max()),
                "bounded_coefficients": int(np.count_nonzero((coefficients == -64) | (coefficients == 63)))},
        "quality": {"declared_model_holdout": _metrics(predicted, expected), "no_effect_baseline": _metrics(testing, expected),
                    "clipped_cube_holdout_components": int(((raw_target < 0) | (raw_target > 1)).sum()),
                    "physical_camera_error": None, "camera_accuracy_verified": False},
        "camera_io": False, "network_io": False, "images_written": False,
        "limitations": ["The coordinate/response model is an explicit mathematical hypothesis, not measured M4 calibration.",
                        "Selected imports pair this table with zero native108; do not retain an unrelated joint-fit basis.",
                        "Native17 physical response and M9 calibration remain independent research."],
    }


def _read_cp(path: str | os.PathLike[str]) -> tuple[dict[str, Any], bytes]:
    local = _path(path)
    with _regular_reader(local) as (stream, info):
        if info.st_size != _profile()["cp_size"]:
            raise PlanError("CP size is not the supported complete 6.02 component size")
        raw = stream.read(info.st_size + 1)
        if len(raw) != info.st_size:
            raise PlanError("CP size changed while reading")
    return {"path": str(local), "kind": "cp", "size": len(raw), "sha256": _sha(raw)}, raw


def _matches_segments(blob: bytes, family: Mapping[str, Any]) -> bool:
    return all(_sha(blob[item["offset"]:item["offset"] + item["size"]]) == item["sha256"]
               for item in family["immutable_segments"])


def _admit(ap: dict[str, Any], cp: dict[str, Any], blob: bytes) -> dict[str, Any]:
    profile = _profile()
    if ap["size"] != profile["ap_size"]:
        raise PlanError("AP size is not the supported complete 6.02 component size")
    for stock in profile["stock_inputs"]:
        if ap["sha256"] == stock["ap_sha256"] and cp["sha256"] == stock["cp_sha256"]:
            return {**stock, "kind": "stock-uninitialized", "native_basis": False}
    for family in profile["families"]:
        if family["kind"] != "current-combination":
            continue
        if ap["sha256"] != family["ap_sha256"] or not _matches_segments(blob, family):
            continue
        for va in profile["record_vas"]:
            start = va - profile["link_base"]
            _check_record(blob[start:start + RECORD_BYTES])
        if family["native_basis"]:
            start = profile["native_basis_va"] - profile["link_base"]
            for slot in range(4):
                basis = blob[start + slot * 108:start + (slot + 1) * 108]
                if _sha(basis) not in family["allowed_native_basis_sha256_by_slot"][slot]:
                    raise PlanError("Current native108 basis is neither the recorded pair nor a compiler-produced zero pair")
        return family
    raise PlanError("Unsupported or mixed AP/CP LUT pair: immutable full-complement identity and valid owned records are required")


def _unchanged(source: dict[str, Any]) -> dict[str, Any]:
    summary = {key: source[key] for key in ("kind", "size", "sha256")}
    return {"schema": "a7m4-offline-content-plan-result/1", "status": "NO_CHANGE_REQUIRED",
            "offline_only": True, "deployment_authorized": False, "device_execution_ready": False,
            "images_written": False, "source": source,
            "target": {**summary, "materialized": False}, "windows": [],
            "append": {"offset": source["size"], "size": 0, "after_hex": "", "sha256": _sha(b"")},
            "changed_existing_bytes": 0, "inverse": None,
            "complement": {"verification": "complete-source-identity-no-change", "physical_candidate_compared": False,
                           "size": source["size"], "coverage_bytes": source["size"],
                           "ranges": [{"offset": 0, "size": source["size"], "sha256": source["sha256"]}]},
            "space_budget": {"status": "PENDING_TRANSPORT_PREFLIGHT", "evaluated": False}}


def lut_plan(ap_path: str | os.PathLike[str], cp_path: str | os.PathLike[str], operations: list[dict[str, Any]],
             *, response_matrix: Any = None, samples: int = 4096, regularization: float = .1) -> dict[str, Any]:
    """Compile and plan real CUBE imports or ST resets for selected slots 1..4.

    Each operation is ``{slot, cube, strength?}`` or ``{slot, action:'reset'}``.
    Imported tables have an explicit zero native108 basis. On the existing
    combination the native17 runtime, unselected bases/records, names, photo
    identity and factory sound gate are byte-for-byte preserved. Stock inputs
    are recognized but rejected: the missing runtime is a separate unreviewed
    research artifact, not a supported installation path. Saved/runtime slot
    settings still require the separate settings transaction to bind ST.
    The returned components contain all exact bytes
    and local source paths required for materialization, plus exact inverses.

    Previously generated LUT states are admitted by all immutable CP ranges,
    valid record checksums and bounded known basis states, not firmware labels
    or partial signatures. Other code, name or sound mutations must use their
    independently registered/composed profile rather than bypass this check.
    """
    if not isinstance(operations, list) or not 1 <= len(operations) <= 4:
        raise PlanError("operations must contain 1..4 selected slot operations")
    normalized, seen = [], set()
    for value in operations:
        if not isinstance(value, dict) or set(value) - {"slot", "cube", "strength", "action"} or "slot" not in value:
            raise PlanError("LUT operation fields are slot, cube, optional strength, or action=reset")
        slot = value["slot"]
        if type(slot) is not int or not 1 <= slot <= 4 or slot in seen:
            raise PlanError("LUT slots must be unique integers 1..4")
        seen.add(slot)
        action = value.get("action", "import")
        if action == "reset":
            if set(value) != {"slot", "action"}:
                raise PlanError("ST reset requires only slot and action=reset")
            normalized.append((slot, action, None))
        elif action == "import":
            if "cube" not in value:
                raise PlanError("Import requires the user's local CUBE path")
            _finite(value.get("strength", 1.), "strength", 0., 1.)
            normalized.append((slot, action, value))
        else:
            raise PlanError("LUT action must be import or reset")
    ap = inspect_image(ap_path, "ap")["source"]
    cp, blob = _read_cp(cp_path)
    admission = _admit(ap, cp, blob)
    profile = _profile()
    if admission["kind"] == "stock-uninitialized":
        raise PlanError("Stock 6.02 pair recognized, but its missing four-slot runtime is an unreviewed offline research artifact; stock LUT installation is not supported by this planner")
    stock_install = False
    windows: dict[int, dict[str, Any]] = {}

    def add(offset: int, after: bytes, purpose: str) -> None:
        before = blob[offset:offset + len(after)]
        if len(before) != len(after) or not after:
            raise PlanError("LUT window outside complete CP")
        for existing in windows.values():
            if offset < existing["offset"] + len(bytes.fromhex(existing["after_hex"])) and existing["offset"] < offset + len(after):
                raise PlanError("LUT runtime/data windows overlap")
        if before != after:
            windows[offset] = {"offset": offset, "before_hex": before.hex(), "after_hex": after.hex(), "purpose": purpose}

    zero_record = make_record(bytes(TABLE_BYTES))
    results = []
    replacements: dict[int, bytes] = {}
    for slot, action, value in sorted(normalized):
        compiled = None if action == "reset" else compile_cube(value["cube"], strength=value.get("strength", 1.),
                    response_matrix=response_matrix, samples=samples, regularization=regularization)
        record = zero_record if compiled is None else bytes.fromhex(compiled["record_hex"])
        replacements[slot] = record
        start = profile["record_vas"][slot - 1] - profile["link_base"]
        before = blob[start:start + RECORD_BYTES]
        before_basis = b""
        if admission["native_basis"]:
            basis_at = profile["native_basis_va"] - profile["link_base"] + (slot - 1) * 108
            before_basis = blob[basis_at:basis_at + 108]
            add(basis_at, bytes(108), f"slot-{slot}-table-paired-zero-native108")
        results.append({"slot": slot, "action": action, "base_look": "ST", "compiled": compiled,
                        "before_record_sha256": _sha(before), "after_record_sha256": _sha(record),
                        "native_basis_policy": "zero-selected-with-new-table" if admission["native_basis"] else "stock-native-ST-no-native17-wrapper",
                        "selected_native_basis_changed": bool(any(before_basis)),
                        "native_controls_after": [0.] * 17,
                        "content_changed": before != record or bool(any(before_basis))})
    for slot, va in enumerate(profile["record_vas"], 1):
        if slot in replacements:
            add(va - profile["link_base"], replacements.get(slot, zero_record), f"slot-{slot}-M4L1-record")
    rows = [{key: row[key] for key in ("offset", "before_hex", "after_hex")} for row in sorted(windows.values(), key=lambda x: x["offset"])]
    cp_plan = (plan_content_changes({"schema": "a7m4-offline-content-plan/1", "source": cp, "windows": rows})
               if rows else _unchanged(cp))
    ap_plan = _unchanged(ap)
    for component, device_path in ((ap_plan, "/usr/lib/appFw.so"), (cp_plan, "/cp/CPAPP-B.BIN")):
        component["device_path"] = device_path
        component["device_execution_ready"] = False
    return {
        "schema": "a7m4-four-slot-lut-plan/1", "feature_id": "four-slot-ST-CUBE-import",
        "model": profile["model"], "firmware": profile["firmware"], "base_look": "ST",
        "offline_only": True, "camera_io": False, "network_io": False, "images_written": False,
        "deployment_authorized": False, "device_execution_ready": False,
        "status": "PLANNED_OFFLINE" if rows or stock_install else "NO_CHANGE_REQUIRED",
        "source_profile": admission["id"], "admission": "fixed-stock-pair" if stock_install else "complete-immutable-complement-and-owned-record-validation",
        "sound_gate_state_preserved": admission["sound_state"],
        "selected_slots": sorted(seen), "operations": results, "components": {"ap": ap_plan, "cp": cp_plan},
        "source": {"ap": ap, "cp": cp}, "target": {"ap": ap_plan["target"], "cp": cp_plan["target"]},
        "inverse": {"ap": ap_plan["inverse"], "cp": cp_plan["inverse"]},
        "runtime_dependencies": {"installed_by_this_plan": stock_install,
                                 "stock_loader_text_length_extension": stock_install,
                                 "stock_rodata_execution_permission": stock_install,
                                 "data_segment_or_BSS_extension": False,
                                 "donor_FL2_FL3_data_included": False,
                                 "current_native17_code_replaced": False,
                                 "runtime_source_and_license": "data/lut-runtime.json"},
        "preservation": {"names_and_photo_identity": "unchanged except the declared stock ST marker carrier needed by this LUT runtime",
                         "native_factory_sound_gate": "unchanged", "unselected_existing_records_and_native_bases": not stock_install,
                         "factory_native_look_paths": "preserved; stock legacy look indices 0..9 retained",
                         "settings_changed": False, "unselected_stock_records": "initialized to zero correction only when installing missing runtime" if stock_install else "unchanged"},
        "settings_requirements": {"status": "PENDING_SEPARATE_SETTINGS_TRANSACTION", "slots": sorted(seen),
                                  "saved_base": "ST", "runtime_base": "ST",
                                  "scope": "Bind only selected slots; preserve unselected settings and all body calibration/counters."},
        "window_purposes": sorted(windows.values(), key=lambda row: row["offset"]),
        "space_budget": {"status": "PENDING_TRANSPORT_PREFLIGHT", "evaluated": False,
                         "each_upload_bytes_exclusive": 65536, "minimum_remaining_free_bytes": 8388608},
        "physical_validation": {"this_planner": "not-performed", "stock_runtime": "new-offline-composition-requires-Main-real-test",
                                "new_CUBE_color_accuracy": "not-measured", "M9_calibration": "paused"},
        "limitations": list(profile["limitations"]),
    }
