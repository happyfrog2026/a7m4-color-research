"""Offline builder and receipt guard for fixed AP/CP program windows.

The caller must supply a plan produced by a separately restricted feature
planner. This generic internal building block is not a user manifest executor.
No camera, USB, SSH, network or discovery dependency is imported here.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
from typing import Any, Mapping

REQUEST = struct.Struct("<8sII16s32s8I4Q")
METADATA_KEYS = tuple(role+"_"+field for role in ("ap","cp") for field in ("mode","nlink","uid","gid"))
FILE_ID_KEYS = ("ap_dev","ap_inode","cp_dev","cp_inode")
REPORT = struct.Struct("<8sIIII7q6Q32s16sq6Q8I")
REQUEST_PATH = "/tmp/jiritsu/m4.program.request"
RESULT_PATH = "/tmp/jiritsu/m4.program.result"
UPLOAD_PATH = "/tmp/jiritsu/libJit.so"
PATHS = {"ap": "/usr/lib/appFw.so", "cp": "/cp/CPAPP-B.BIN"}
SCHEMA = "a7m4-program-plan/1"
MAX_FILE = 512 * 1024 * 1024
MAX_WINDOWS = 128
MAX_WINDOW_BYTES = 4096
MAX_TOTAL_BYTES = 16384
MAX_AP_BYTES = 8192
NATIVE_SOURCE_SHA256 = "4020f6f1d4abaecbd6d5382711f2d02ffec6aa49737d655482f6840e6fca2d03"


class ProgramError(ValueError):
    pass


class ProgramReadOnlyRefusal(ProgramError):
    """A fully framed first mode0 refusal; never authorizes a feature write."""
    def __init__(self, report):
        super().__init__('Program read-only inspection refused before persistent writes')
        self.report = report


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise ProgramError(message)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":"), allow_nan=False).encode("ascii")


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _hex(value: Any, size: int | None = None) -> bytes:
    _need(type(value) is str and len(value) % 2 == 0
          and re.fullmatch("[0-9a-f]*", value) is not None, "Invalid lowercase hex")
    raw = bytes.fromhex(value)
    _need(size is None or len(raw) == size, "Hex length differs")
    return raw


def _identity(value: Any) -> dict:
    _need(type(value) is dict and set(value) == {"size", "sha256"}, "Identity requires size/sha256 only")
    _need(type(value["size"]) is int and 0 < value["size"] <= MAX_FILE, "Invalid program size")
    _hex(value["sha256"], 32)
    return dict(value)


def program_plan(components: Mapping[str, Any], *, feature_id: str) -> dict:
    """Normalize an internally approved exact transition; no source I/O."""
    _need(type(feature_id) is str and re.fullmatch("[a-z0-9_.-]{1,64}", feature_id) is not None,
          "Invalid fixed feature ID")
    _need(type(components) is dict and set(components) == {"ap", "cp"}, "Both fixed program roles required")
    result, total, count, ap_bytes = {}, 0, 0, 0
    for role in ("ap", "cp"):
        item = components[role]
        _need(type(item) is dict and set(item) == {"source", "target", "windows"}, "Unexpected component fields")
        source, target = _identity(item["source"]), _identity(item["target"])
        _need(source["size"] == target["size"], "Program append/truncate is forbidden")
        _need(type(item["windows"]) is list and len(item["windows"]) <= MAX_WINDOWS, "Invalid window count")
        windows = []
        for row in item["windows"]:
            _need(type(row) is dict and set(row) == {"offset", "before_hex", "after_hex"}, "Unexpected window fields")
            offset = row["offset"]
            before, after = _hex(row["before_hex"]), _hex(row["after_hex"])
            _need(type(offset) is int and offset >= 0 and 0 < len(before) <= MAX_WINDOW_BYTES
                  and len(before) == len(after) and offset <= source["size"] - len(before), "Invalid exact window")
            _need(before != after, "Unchanged windows must be omitted")
            total += len(before)
            count += 1
            if role == "ap":
                ap_bytes += len(before)
            windows.append(dict(row))
        windows.sort(key=lambda w: w["offset"])
        end = 0
        for row in windows:
            _need(row["offset"] >= end, "Overlapping windows")
            end = row["offset"] + len(bytes.fromhex(row["before_hex"]))
        _need(bool(windows) == (source != target), "Unchanged component identity/windows disagree")
        result[role] = {"source": source, "target": target, "windows": windows}
    _need(0 < count <= MAX_WINDOWS and total <= MAX_TOTAL_BYTES and ap_bytes <= MAX_AP_BYTES,
          "Bounded nonempty program transition required")
    plan = {"schema": SCHEMA, "feature_id": feature_id, "components": result}
    plan["plan_id"] = _sha(_canonical(plan))
    return plan


def validate_plan(plan: Any) -> dict:
    _need(type(plan) is dict and set(plan) == {"schema", "feature_id", "components", "plan_id"}
          and plan["schema"] == SCHEMA, "Unsupported program plan")
    normalized = program_plan(plan["components"], feature_id=plan["feature_id"])
    _need(normalized == plan, "Program plan ID/content/order differs")
    return normalized


def _rows(plan: dict):
    for role in ("cp", "ap"):
        for row in plan["components"][role]["windows"]:
            yield role, row


def render_header(plan: dict) -> bytes:
    validate_plan(plan)
    array = lambda raw: "{" + ",".join(str(x) for x in raw) + "}"
    lines = ["/* Generated exact local plan; not a device authorization. */",
             "struct Window {u64 offset;u32 length,chip;const u8 *before,*after;};"]
    rows = list(_rows(plan))
    for index, (_, row) in enumerate(rows):
        for side in ("before", "after"):
            lines.append(f"static const u8 {side}_{index}[]={array(bytes.fromhex(row[side + '_hex']))};")
    lines.append("static const struct Window windows[]={" + ",".join(
        "{%dUL,%d,%d,before_%d,after_%d}" %
        (row["offset"], len(bytes.fromhex(row["before_hex"])), int(role == "cp"), index, index)
        for index, (role, row) in enumerate(rows)) + "};")
    lines += [f"static const u32 window_count={len(rows)};",
              "static const u64 file_sizes[]={%dUL,%dUL};" % tuple(
                  plan["components"][role]["source"]["size"] for role in ("ap", "cp")),
              "static const u8 plan_id[32]=" + array(bytes.fromhex(plan["plan_id"])) + ";"]
    return ("\n".join(lines) + "\n").encode("ascii")


def make_request(plan: dict, mode: int, nonce: bytes, *, metadata=None, file_ids=None) -> bytes:
    validate_plan(plan)
    _need(type(mode) is int and mode in range(4), "Invalid program mode")
    _need(type(nonce) is bytes and len(nonce) == 16 and any(nonce), "Fresh nonzero nonce16 required")
    return REQUEST.pack(b"M4PG0002", mode, 0, nonce, bytes.fromhex(plan["plan_id"]),
                        *(metadata or (0,)*8), *(file_ids or (0,)*4))


REPORT_KEYS = ("magic", "version", "mode", "phase", "writes", "status", "rollback", "remount",
               "readonly", "cleanup", "euid", "pid", "ap_dev", "ap_inode", "ap_size",
               "cp_dev", "cp_inode", "cp_size", "plan_id", "nonce", "cp_mount_status",
               "jiritsu_type", "jiritsu_unit", "jiritsu_available", "cp_type", "cp_unit", "cp_available",
               "ap_mode", "ap_nlink", "ap_uid", "ap_gid", "cp_mode", "cp_nlink", "cp_uid", "cp_gid")


def decode_report(raw: bytes) -> dict:
    _need(type(raw) is bytes and len(raw) == REPORT.size, "Missing/partial program report: STOP_UNKNOWN")
    return dict(zip(REPORT_KEYS, REPORT.unpack(raw)))


def _read_identity(path: Any) -> dict:
    path = Path(path)
    before = path.lstat()
    _need(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= MAX_FILE, "Expected bounded regular program")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    signature = lambda st: (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        opened = os.fstat(stream.fileno())
        _need(signature(opened) == signature(before), "Program changed while opening")
        digest, size = hashlib.sha256(), 0
        while raw := stream.read(1024 * 1024):
            size += len(raw)
            _need(size <= MAX_FILE, "Program exceeded size bound")
            digest.update(raw)
        _need(signature(os.fstat(stream.fileno())) == signature(opened)
              and signature(path.lstat()) == signature(opened), "Program changed during full read")
    return {"size": size, "sha256": digest.hexdigest()}


def verify_readback(plan: dict, images: Mapping[str, Any], direction: str = "forward") -> dict:
    validate_plan(plan)
    _need(direction in ("forward", "inverse", "source") and set(images) == {"ap", "cp"}, "Both complete programs required")
    side = "target" if direction == "forward" else "source"
    actual = {role: _read_identity(images[role]) for role in ("ap", "cp")}
    _need(all(actual[role] == plan["components"][role][side] for role in actual),
          "Complete program readback differs: STOP_UNKNOWN")
    return {"status": "FULL_READBACK_VERIFIED", "endpoint": side, "files": actual,
            "plan_id": plan["plan_id"], "camera_validation_claimed": False}


class ProgramProtocol:
    """One finite transaction; any uncertain report consumes and poisons it.

    Call confirm_readback with complete local captures after source/target
    inspection and before the next mutation. It checks actual file bytes.
    """
    def __init__(self, plan: dict):
        self.plan = copy.deepcopy(validate_plan(plan))
        self.state = "READY"
        self.pending = None
        self.previous_mode = None
        self.identity = None
        self.metadata = self.file_ids = None
        self.used_nonces: set[bytes] = set()
        self.steps = 0
        self.full_endpoint = None

    def request(self, mode: int, nonce: bytes) -> bytes:
        _need(self.state == "READY" and self.pending is None and self.steps < 5,
              "Program transaction ended/unknown/pending; no replay")
        raw = make_request(self.plan, mode, nonce, metadata=self.metadata, file_ids=self.file_ids)
        _need(nonce not in self.used_nonces, "Program nonce already consumed")
        if self.previous_mode is None:
            _need(mode in (0, 3), "Inspect before any program mutation")
        else:
            _need(mode == {0: 1, 1: 3, 3: 2, 2: 0}[self.previous_mode], "Program phase order differs")
        if mode in (1, 2):
            _need(self.full_endpoint == ("source" if mode == 1 else "target"), "Complete fresh readback required before mutation")
        self.pending = (mode, nonce)
        self.used_nonces.add(nonce)
        self.full_endpoint = None
        self.steps += 1
        return raw

    def unknown(self) -> None:
        self.state = "STOP_UNKNOWN"

    def accept(self, raw: bytes) -> dict:
        _need(self.state == "READY" and self.pending is not None, "No pending program request")
        try:
            report = decode_report(raw)
            mode, nonce = self.pending
            _need(report["magic"] == b"M4PGR001" and report["version"] == 2
                  and report["plan_id"] == bytes.fromhex(self.plan["plan_id"])
                  and report["mode"] == mode and report["nonce"] == nonce, "Report plan/nonce/phase differs")
            if (mode == 0 and self.previous_mode is None and self.steps == 1
                    and report['phase'] in (1, 2) and report['status'] < 0
                    and report['pid'] > 1 and all(report[k] == 0 for k in
                        ('writes','rollback','remount','readonly','cleanup','cp_mount_status','euid'))):
                raise ProgramReadOnlyRefusal(report)
            _need(report["phase"] == 9 and all(report[k] == 0 for k in
                  ("status", "rollback", "remount", "readonly", "cleanup", "cp_mount_status", "euid")),
                  "Program result is incomplete/failed: STOP_UNKNOWN")
            count = sum(len(c["windows"]) for c in self.plan["components"].values())
            _need(report["writes"] == (count if mode in (1, 2) else 0), "Program write count differs")
            for role in ("ap", "cp"):
                _need(report[role + "_size"] == self.plan["components"][role]["source"]["size"]
                      and report[role + "_inode"] > 0
                      and report[role + "_mode"] & 0o170000 == 0o100000
                      and report[role + "_nlink"] == 1, "Program FD identity differs")
            _need(report["pid"] > 1, "Missing native process identity")
            identity = tuple(report[k] for k in ("pid", "ap_dev", "ap_inode", "ap_size", "cp_dev", "cp_inode", "cp_size",
                "ap_mode", "ap_nlink", "ap_uid", "ap_gid", "cp_mode", "cp_nlink", "cp_uid", "cp_gid"))
            _need(self.identity is None or identity == self.identity, "Cross-phase process/FD identity changed")
            for name in ("jiritsu", "cp"):
                _need(report[name + "_type"] == 0x4D44 and 0 < report[name + "_unit"] <= 65536,
                      "Native fresh space measurement is invalid")
            if mode in (1, 2):
                unit = report["jiritsu_unit"]
                needed = ((8388608 + unit - 1) // unit + (REPORT.size + unit - 1) // unit) * unit
                _need(report["jiritsu_available"] >= needed
                      and report["cp_available"] >= 2 * report["cp_unit"],
                      "Mutation receipt lacks required native space reserve")
            self.identity = identity
            self.metadata = tuple(report[k] for k in METADATA_KEYS)
            self.file_ids = tuple(report[k] for k in FILE_ID_KEYS)
            self.pending = None
            self.previous_mode = mode
            # NativeActions retains raw bytes separately and durably serializes
            # this view. Returning raw byte fields would poison a valid phase.
            return {key: (value.decode("ascii") if key == "magic" else value.hex())
                    if isinstance(value, bytes) else value for key, value in report.items()}
        except ProgramReadOnlyRefusal:
            self.state = 'REFUSED_READ_ONLY'
            self.pending = None
            raise
        except BaseException:
            self.unknown()
            raise

    def confirm_readback(self, images: Mapping[str, Any]) -> dict:
        _need(self.state == "READY" and self.pending is None and self.previous_mode in (0, 3),
              "Readback confirmation requires complete source/target inspection")
        try:
            result = verify_readback(self.plan, images, "source" if self.previous_mode == 0 else "forward")
            self.full_endpoint = result["endpoint"]
            return result
        except BaseException:
            self.unknown()
            raise


def _save(path: Path, raw: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def _elf(raw: bytes) -> dict:
    _need(len(raw) >= 64 and raw[:6] == b"\x7fELF\x02\x01", "Invalid worker ELF")
    h = struct.unpack_from("<16sHHIQQQIHHHHHH", raw)
    _need(h[1] == 3 and h[2] == 183 and h[9] == 56 and 0 < h[10] < 128
          and h[5] + h[10] * 56 <= len(raw), "Worker must be AArch64 ET_DYN")
    stack = False
    for i in range(h[10]):
        kind, flags, start, _, _, size, _, _ = struct.unpack_from("<IIQQQQQQ", raw, h[5] + i * 56)
        _need(start + size <= len(raw) and not (kind == 1 and flags & 3 == 3), "Unsafe ELF segment")
        if kind == 0x6474E551:
            _need(not flags & 1, "Executable worker stack")
            stack = True
        if kind == 2:
            _need(size % 16 == 0, "Malformed dynamic table")
            for at in range(start, start + size, 16):
                tag, _ = struct.unpack_from("<qQ", raw, at)
                _need(tag not in (1, 22) and not (tag == 30 and struct.unpack_from("<qQ", raw, at)[1] & 4),
                      "Worker dependency/text relocation rejected")
    _need(stack, "Explicit non-executable stack required")
    return {"machine": "AArch64", "type": "ET_DYN", "external_dependencies": False, "executable_stack": False}


def build_program_worker(plan: dict, output: Any, *, compiler: Any = None) -> dict:
    """Explicit offline Zig build. Missing compiler is BLOCKED, never fetched."""
    validate_plan(plan)
    result = {"schema": "a7m4-program-worker-bundle/1", "plan_id": plan["plan_id"],
              "status": "BLOCKED_COMPILER_UNAVAILABLE", "worker_built": False,
              "device_execution_state": "HELD", "device_io": False, "network_io": False,
              "request": {"path": REQUEST_PATH, "bytes": REQUEST.size},
              "report": {"path": RESULT_PATH, "bytes": REPORT.size},
              "unknown_result_policy": "STOP_UNKNOWN_NO_REPLAY", "blockers": []}
    if compiler is None:
        result["blockers"] = ["Explicit offline Zig 0.13.0 required; no download attempted"]
        return result
    command = [os.fspath(compiler)] if isinstance(compiler, (str, os.PathLike)) else list(compiler)
    _need(command and all(type(x) is str and x for x in command), "Invalid compiler command")
    directory = Path(output).absolute()
    _need(not directory.exists() and not directory.is_symlink() and directory.parent.is_dir()
          and not any(p.is_symlink() for p in directory.parents), "New real private output directory required")
    canonical = Path(__file__).resolve().parents[2] / "native/program-worker/program.c"
    packaged = Path(__file__).with_name("data") / "program-worker.c"
    present = [candidate for candidate in (packaged, canonical)
               if candidate.exists() or candidate.is_symlink()]
    _need(present, "Packaged program worker source missing")
    for candidate in present:
        _need(candidate.is_file() and not candidate.is_symlink()
              and _sha(candidate.read_bytes()) == NATIVE_SOURCE_SHA256,
              "Canonical/packaged program worker source binding differs")
    source = present[0]
    raw_source = source.read_bytes()
    _need(_sha(raw_source) == NATIVE_SOURCE_SHA256, "Native source differs from reviewed source pin")
    directory.mkdir(mode=0o700)
    header = render_header(plan)
    _save(directory / "patch_manifest.h", header)
    _save(directory / "plan.json", _canonical(plan) + b"\n")
    env = dict(os.environ, ZIG_GLOBAL_CACHE_DIR=str(directory / "zig-global"), ZIG_LOCAL_CACHE_DIR=str(directory / "zig-local"))
    try:
        version = subprocess.run(command + ["version"], capture_output=True, text=True, check=True,
                                 timeout=20, env=env).stdout.strip()
        _need(version == "0.13.0", "Reviewed Zig 0.13.0 required")
        common = command + ["cc", "-target", "aarch64-linux-gnu", "-std=c11", "-O2", "-ffreestanding", "-fno-builtin", "-I", str(directory)]
        abi = directory / "target-abi.o"
        subprocess.run(common + ["-DM4_FL23_TARGET_ABI_CHECK", "-c", str(source), "-o", str(abi)],
                       capture_output=True, check=True, timeout=180, env=env)
        abi.chmod(0o600)
        flags = ["-Wall", "-Wextra", "-Werror", "-shared", "-fPIC", "-fno-stack-protector", "-fno-unwind-tables",
                 "-fno-asynchronous-unwind-tables", "-nostdlib", "-g0", "-Wl,--strip-debug", "-Wl,--no-undefined",
                 "-Wl,--build-id=none", "-Wl,-Bsymbolic", "-Wl,-z,noexecstack"]
        binaries = []
        for name in ("program-worker.so", "program-worker-repeat.so"):
            target = directory / name
            subprocess.run(common + flags + [str(source), "-o", str(target)], capture_output=True,
                           check=True, timeout=180, env=env)
            target.chmod(0o600)
            raw = target.read_bytes()
            _need(0 < len(raw) < 65536, "Every worker upload must be strictly below 65536B")
            _elf(raw)
            binaries.append(raw)
        _need(binaries[0] == binaries[1] and raw_source == source.read_bytes()
              and all(_sha(candidate.read_bytes()) == NATIVE_SOURCE_SHA256 for candidate in present),
              "Double build/source binding differs")
        result.update(status="BUILT_OFFLINE_NOT_DEVICE_VALIDATED", worker_built=True,
                      worker={"path": str(directory / "program-worker.so"), "size": len(binaries[0]),
                              "sha256": _sha(binaries[0]), "upload_path": UPLOAD_PATH,
                              "source_sha256": _sha(raw_source), "header_sha256": _sha(header),
                              "target_abi_sha256": _sha(abi.read_bytes()), "compiler": "Zig 0.13.0",
                              "double_build_identical": True, "elf": _elf(binaries[0])})
    except (OSError, subprocess.SubprocessError, ProgramError) as exc:
        result["status"] = "BLOCKED_NATIVE_BUILD"
        detail = getattr(exc, "stderr", "") or str(exc)
        if isinstance(detail, bytes):
            detail = detail.decode(errors="replace")
        result["blockers"] = [str(detail)[-3000:]]
    _save(directory / "bundle.json", _canonical(result) + b"\n")
    return result
