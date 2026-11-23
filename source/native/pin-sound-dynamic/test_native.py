"""Actual dynamic C, synthetic sparse images and in-memory syscalls only.

No callback forwards a Linux syscall to the host. Clang only builds a temporary
host library; no real firmware, device, network, USB or session is imported.
"""
import ctypes
import hashlib
import importlib.util
from pathlib import Path
import shutil
import struct
import sys
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from a7m4.research import pin_plan as pin

spec = importlib.util.spec_from_file_location("pin_dynamic_bounded_fake", ROOT / "tests/test_native_fl23_direct_program.py")
fake = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = fake
spec.loader.exec_module(fake)
fake.CP = "/cp/SysSound.bin"
fake.REQUEST = "/tmp/jiritsu/m4.pin-dynamic.request"
fake.RESULT = "/tmp/jiritsu/m4.pin-dynamic.result"
fake.READ_FLAGS = 0x88800
SOURCE_PATH = "/tmp/jiritsu/test.source.bin"
TARGET_PATH = "/tmp/jiritsu/test.target.bin"
MAPS, MEM = "/proc/self/maps", "/proc/self/mem"
CSV = "/usr/share/avsystemsound/custom.txt"
BIAS = 0x200000000
AP_AFTER = pin._ap_after({"sha": 64, "kasha": 128})
SOURCE_BANK = bytes(108480)
TARGET_BANK = bytearray(110528)
TARGET_BANK[:256] = bytes([0, 7] * 128)
TARGET_BANK[77504:77568] = bytes([0, 4] * 32)
TARGET_BANK[92928:93056] = bytes([0, 3] * 64)
TARGET_BANK = bytes(TARGET_BANK)


def packet(index, bank):
    data = bank[:256] + bank[77504:]
    return pin.PACK_HEADER.pack(b"M4PIND01", fake.PLAN_ID, index, len(data)) + data


PACKETS = {SOURCE_PATH: packet(0, SOURCE_BANK), TARGET_PATH: packet(1, TARGET_BANK)}


class SparseAP:
    def __init__(self, target=False):
        self.values = {}
        for offset, word in zip(pin.AP_OFFSETS, AP_AFTER if target else pin.AP_BEFORE):
            self[offset:offset + 4] = word

    def __len__(self):
        return 98212632

    def __getitem__(self, key):
        if isinstance(key, slice):
            return bytes(self.values.get(at, 0) for at in range(*key.indices(len(self))))
        return self.values.get(key, 0)

    def __setitem__(self, key, value):
        if isinstance(key, slice):
            positions = range(*key.indices(len(self)))
            assert len(positions) == len(value)
            self.values.update(zip(positions, value))
        else:
            self.values[key] = value


def header():
    array = lambda raw: "{" + ",".join(map(str, raw)) + "}"
    rows = ["struct Window {u64 offset;u32 length,chip;const u8 *before,*after;};"]
    for index, (before, after) in enumerate(zip(pin.AP_BEFORE, AP_AFTER)):
        rows += [f"static const u8 before_{index}[]={array(before)};", f"static const u8 after_{index}[]={array(after)};"]
    rows.append("static const struct Window windows[]={" + ",".join(
        "{%dUL,4,0,before_%d,after_%d}" % (offset, index, index) for index, offset in enumerate(pin.AP_OFFSETS)) + "};")
    rows += ["static const u32 window_count=7;", "static const u64 file_sizes[]={98212632UL,108480UL};",
             f"static const u8 plan_id[32]={array(fake.PLAN_ID)};",
             f"static const u8 protected_bank_sha[32]={array(hashlib.sha256(SOURCE_BANK[256:77504]).digest())};"]
    for name, path in (("source", SOURCE_PATH), ("target", TARGET_PATH)):
        raw = PACKETS[path]
        rows += [f"static const u32 {name}_packet_bytes={len(raw)};",
                 f"static const u8 {name}_packet_sha[32]={array(hashlib.sha256(raw).digest())};",
                 f'static const char {name}_packet_path[]="{path}";']
    return "\n".join(rows) + "\n"


@pytest.fixture(scope="module")
def actual_c(tmp_path_factory):
    clang = shutil.which("clang")
    if not clang:
        pytest.skip("host clang required for actual-C bounded-syscall tests")
    directory = tmp_path_factory.mktemp("pin-dynamic-same-C")
    (directory / "patch_manifest.h").write_text(header())
    (directory / "shim.c").write_text(
        "typedef long(*cb)(long,long,long,long,long,long,long);static cb current;"
        "void m4_direct_set_callback(cb value){current=value;}"
        "long m4_fl23_direct_test_syscall(long n,long a,long b,long c,long d,long e,long f)"
        "{return current?current(n,a,b,c,d,e,f):-38;}")
    output = directory / "test-worker.dylib"
    process = subprocess.run([clang, "-std=c11", "-O1", "-Wall", "-Wextra", "-Werror", "-ffreestanding",
                              "-fno-builtin", "-shared", "-fPIC", "-DM4_FL23_DIRECT_TEST", "-I", str(directory),
                              str(Path(__file__).with_name("program.c")), str(directory / "shim.c"), "-o", str(output)],
                             text=True, capture_output=True)
    assert process.returncode == 0, process.stderr
    module = ctypes.CDLL(str(output))
    module.m4_direct_set_callback.argtypes = [fake.CALLBACK]
    module.m4_fl23_direct_run.argtypes = []
    module.m4_fl23_direct_run.restype = None
    return module


class Machine(fake.Machine):
    def __init__(self, module, mode=1, target=False):
        super().__init__(module, mode)
        self.nodes[fake.AP].data = SparseAP(target)
        self.nodes[fake.CP].data = bytearray(TARGET_BANK if target else SOURCE_BANK)
        self.nodes[fake.REQUEST].data = bytearray(pin.REQUEST.pack(b"M4PIN001", mode, 0, fake.NONCE, fake.PLAN_ID))
        for index, (path, raw) in enumerate(PACKETS.items()):
            self.nodes[path] = fake.Node(bytearray(raw), 300 + index)
        self.memory = {}
        for offset in pin.AP_OFFSETS:
            page = offset // 4096 * 4096
            self.memory[page] = bytearray(self.nodes[fake.AP].data[page:page + 4096])
        self.frozen = set()
        self.shared_map = self.low_space = self.low_jiritsu = False
        self.bad_memory = False
        self.mem_writes = []
        self.jiritsu_blocks = None
        self.jiritsu_frsize = 0

    def _dispatch(self, nr, a, b, c, d, e, f):
        if nr == 43:
            path = ctypes.string_at(a).decode()
            assert path in ("/cp", "/tmp/jiritsu")
            self.events.append(("statfs", path))
            free = 1 if (self.low_space if path == "/cp" else self.low_jiritsu) else 10000
            if path == "/tmp/jiritsu" and self.jiritsu_blocks is not None:
                free = self.jiritsu_blocks
            raw = bytearray(120)
            struct.pack_into("<qqQQQQQ", raw, 0, 0x4D44, 4096, 20000, free, free, 1000, 100)
            if path == "/tmp/jiritsu":
                struct.pack_into("<q", raw, 72, self.jiritsu_frsize)
            ctypes.memmove(b, bytes(raw), len(raw))
            return 0
        if nr == 56:
            path = ctypes.string_at(b).decode()
            assert c & 0x800, "every opened target must avoid blocking before fstat"
            if path == CSV:
                return -2 if CSV not in self.nodes else -17
            if path in (MAPS, MEM) or path in PACKETS:
                assert a == -100 and c & 0x88000 == 0x88000
                assert c & 0x800, "NONBLOCK must precede regular-file fstat guards"
                self.events.append(("open", path, c, d))
                if path == MAPS:
                    node = fake.Node(bytearray("".join(
                        f"{BIAS + at:x}-{BIAS + at + 4096:x} r-x{'s' if self.shared_map else 'p'} {at:08x} 00:11 101 {fake.AP}\n"
                        for at in sorted(self.memory)).encode()), 201)
                elif path == MEM:
                    node = fake.Node(bytearray(), 202)
                else:
                    node = self.nodes[path]
                fd = self.next_fd
                self.next_fd += 1
                self.fds[fd] = [path, node, c, 0]
                return fd
        if nr in (67, 68) and a in self.fds and self.fds[a][0] == MEM:
            offset = d - BIAS
            page = offset // 4096 * 4096
            at = offset - page
            assert page in self.memory and at + c <= 4096
            failure = self.failure("mem_pwrite" if nr == 68 else "mem_read", MEM)
            if failure is not None:
                return failure
            if nr == 67:
                raw = bytes(self.memory[page][at:at + c])
                if self.bad_memory:
                    raw = bytes([raw[0] ^ 1]) + raw[1:]
                ctypes.memmove(b, raw, len(raw))
                return len(raw)
            data = ctypes.string_at(b, c)
            self.memory[page][at:at + c] = data
            self.frozen.add(page)
            self.mem_writes.append((d, data))
            self.events.append(("selfmem", d, c))
            return c
        if nr == 46:
            path, node, flags, _ = self.fds[a]
            assert path == fake.CP and flags & 3 == 2
            self.events.append(("truncate", path, b))
            failure = self.failure("truncate", path)
            if failure is not None:
                return failure
            del node.data[b:]
            return 0
        if nr == 68 and self.fds[a][0] == fake.AP:
            assert all(at // 4096 * 4096 in self.frozen for at in range(d, d + c)), "AP persisted before source-identical COW"
        return super()._dispatch(nr, a, b, c, d, e, f)


@pytest.mark.parametrize("mode,target", [(0, False), (1, False), (3, True), (2, True)])
def test_native_success_exact_endpoints_and_data_before_descriptors(actual_c, mode, target):
    machine = Machine(actual_c, mode, target)
    memory = {key: bytes(value) for key, value in machine.memory.items()}
    report = machine.run()
    result_target = mode in (1, 3)
    assert report["magic"] == b"M4PINR01" and report["phase"] == 9
    assert all(report[key] == 0 for key in ("status", "rollback", "remount", "readonly", "cleanup", "cp_mount_status"))
    assert report["writes"] == (8 if mode in (1, 2) else 0)
    assert bytes(machine.nodes[fake.CP].data) == (TARGET_BANK if result_target else SOURCE_BANK)
    assert [machine.nodes[fake.AP].data[at:at + 4] for at in pin.AP_OFFSETS] == list(AP_AFTER if result_target else pin.AP_BEFORE)
    assert {key: bytes(value) for key, value in machine.memory.items()} == memory
    assert machine.usr_ro and not machine.fds and fake.LOADER not in machine.nodes
    writes = machine.program_writes()
    if mode == 1:
        assert [event[1] for event in writes] == [fake.CP, fake.CP] + [fake.AP] * 7
        last_bank = max(index for index, event in enumerate(machine.events) if event[0] == "pwrite" and event[1] == fake.CP)
        first_ap = next(index for index, event in enumerate(machine.events) if event[0] == "pwrite" and event[1] == fake.AP)
        assert any(event[:2] == ("fsync", fake.CP) for event in machine.events[last_bank + 1:first_ap])
    elif mode == 2:
        assert [event[1] for event in writes] == [fake.AP] * 7 + [fake.CP, fake.CP]
        assert [event for event in machine.events if event[0] == "truncate"] == [("truncate", fake.CP, 108480)]
    else:
        assert not writes
    assert all(event[2] == 0 and len(event[3]) == 256 or event[2] >= 77504 for event in writes if event[1] == fake.CP)


@pytest.mark.parametrize("fault", ["foreign-request-plan", "source-packet", "target-packet", "packet-fifo", "ap-fifo", "bank-fifo", "protected", "owned", "shared-map", "bad-memory", "cow", "cp-space", "jiritsu-space"])
def test_native_prewrite_failure_never_persists(actual_c, fault):
    machine = Machine(actual_c)
    if fault == "foreign-request-plan":
        machine.nodes[fake.REQUEST].data[32] ^= 1
    elif fault == "source-packet":
        machine.nodes[SOURCE_PATH].data[-1] ^= 1
    elif fault == "target-packet":
        machine.nodes[TARGET_PATH].data[50] ^= 1
    elif fault in ("packet-fifo", "ap-fifo", "bank-fifo"):
        path = {"packet-fifo": SOURCE_PATH, "ap-fifo": fake.AP, "bank-fifo": fake.CP}[fault]
        machine.nodes[path].mode = 0o010600
    elif fault == "protected":
        machine.nodes[fake.CP].data[300] ^= 1
    elif fault == "owned":
        machine.nodes[fake.CP].data[77504] ^= 1
    elif fault == "shared-map":
        machine.shared_map = True
    elif fault == "bad-memory":
        machine.bad_memory = True
    elif fault == "cow":
        machine.fail("mem_pwrite", MEM, -5)
    elif fault == "cp-space":
        machine.low_space = True
    else:
        machine.low_jiritsu = True
    bank = bytes(machine.nodes[fake.CP].data)
    report = machine.run()
    assert report["status"] < 0 and report["writes"] == 0 and not machine.program_writes()
    assert bytes(machine.nodes[fake.CP].data) == bank
    assert machine.usr_ro and not machine.fds


@pytest.mark.parametrize("fault", ["bank-write", "bank-sync", "ap-write", "ap-sync", "inverse-truncate"])
def test_native_partial_failure_is_held_without_automatic_inverse(actual_c, fault):
    machine = Machine(actual_c, 2, True) if fault == "inverse-truncate" else Machine(actual_c)
    if fault == "bank-write":
        machine.fail("pwrite", fake.CP, 0)
    elif fault == "bank-sync":
        machine.fail("fsync", fake.CP, -5)
    elif fault == "ap-write":
        machine.fail("pwrite", fake.AP, -5)
    elif fault == "ap-sync":
        machine.fail("fsync", fake.AP, -5)
    else:
        machine.fail("truncate", fake.CP, -5)
    report = machine.run()
    assert report["status"] < 0 and report["phase"] == 6 and report["rollback"] == -125
    assert machine.usr_ro and not machine.fds
    # The worker never attempts a second automatic transaction after failure.
    writes = machine.program_writes()
    if fault == "bank-write":
        assert not writes
    elif fault == "bank-sync":
        assert all(event[1] == fake.CP for event in writes)


@pytest.mark.parametrize("unit", [512, 4096, 65536])
@pytest.mark.parametrize("report_headroom", [False, True])
def test_native_exact_eight_MiB_must_also_leave_final_report_allocation(actual_c, unit, report_headroom):
    machine = Machine(actual_c)
    machine.jiritsu_frsize = unit
    machine.jiritsu_blocks = pin.MINIMUM_RESERVE // unit + int(report_headroom)
    report = machine.run()
    if report_headroom:
        assert report["status"] == 0 and report["phase"] == 9
    else:
        assert report["status"] == -28 and report["writes"] == 0
        assert not machine.program_writes()

