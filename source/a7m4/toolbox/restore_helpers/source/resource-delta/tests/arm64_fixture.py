# SPDX-License-Identifier: MIT
"""Finite synthetic ARM64 tests for owned-resource prefix restoration.

No camera/network interface exists here. Source and baseline bytes are
synthetic. The fake file page cache intentionally updates private mappings
which have not been COW-frozen, so missing live-view protection is observable.
"""
from pathlib import Path
from copy import deepcopy
import argparse
import hashlib
import importlib.util
import json
import struct
import unittest

from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_INTR
from unicorn.arm64_const import (
    UC_ARM64_REG_SP, UC_ARM64_REG_LR, UC_ARM64_REG_CPACR_EL1,
    UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
    UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X8,
)

ROOT = Path(__file__).resolve().parents[1]
SHA = lambda raw: hashlib.sha256(raw).hexdigest()
STAT = struct.Struct('<QQ4I2QqII8Q')
FS = struct.Struct('<qq5Q2I7q')
OPTIONS = None
OBSERVATIONS = []


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def align_up(value):
    return (value + 4095) & ~4095


def load_arm64(path):
    cpu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    base, stop = 0x10000000, 0x70000000
    with Path(path).open('rb') as stream:
        elf = ELFFile(stream)
        assert elf.header['e_machine'] == 'EM_AARCH64' and elf.header['e_type'] == 'ET_DYN'
        segments = [s for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD']
        length = max(s['p_vaddr'] + s['p_memsz'] for s in segments)
        cpu.mem_map(base, align_up(length))
        for segment in segments:
            cpu.mem_write(base + segment['p_vaddr'], segment.data())
        for section in elf.iter_sections():
            if section['sh_type'] == 'SHT_RELA':
                for rel in section.iter_relocations():
                    assert rel['r_info_type'] == 1027 and not rel['r_info_sym']
                    cpu.mem_write(base + rel['r_offset'], struct.pack('<Q', base + rel['r_addend']))
        dynamic = elf.get_section_by_name('.dynamic')
        assert not any(t.entry.d_tag == 'DT_NEEDED' for t in dynamic.iter_tags())
        init = next(t.entry.d_val for t in dynamic.iter_tags() if t.entry.d_tag == 'DT_INIT')
    cpu.mem_map(0x60000000, 0x100000)
    cpu.mem_map(stop, 4096)
    cpu.reg_write(UC_ARM64_REG_SP, 0x600F0000)
    cpu.reg_write(UC_ARM64_REG_LR, stop)
    cpu.reg_write(UC_ARM64_REG_CPACR_EL1, 0x300000)
    return cpu, base + init, stop


def dirent(name):
    name = str(name).encode() + b'\0'
    size = (19 + len(name) + 7) & ~7
    return struct.pack('<QqHB', 21, 0, size, 4) + name + bytes(size - 19 - len(name))


def synthetic(length, label):
    data = b''.join(hashlib.sha256(label.encode() + struct.pack('<I', i)).digest()
                    for i in range((length + 31) // 32))[:length]
    header = b'uxc\x07\0\0\0\0' + struct.pack('<HHI', 8, 5, 4 | (4 << 12)) + b'\xff\xff' * 4
    return header + data[len(header):]


class PrefixFixture:
    PID, DEV, INO, UID, GID = 498, 0x1234, 424242, 1000, 1001
    FILE_VA, ALIAS_VA = 0x40000000, 0x42000000

    def __init__(self, module, plan, artifact, source, *, aliases=1,
                 permissions=1, private=True, foreign_mapping=False,
                 cow_failure=False, partial_file_failure=False,
                 add_alias_after_cow=False, false_cow_success=False):
        self.module, self.plan, self.artifact = module, plan, artifact
        self.path = plan['resource_path']
        self.data = bytearray(source)
        self.aliases, self.permissions, self.private = aliases, permissions, private
        self.foreign_mapping = foreign_mapping
        self.cow_failure, self.partial_file_failure = cow_failure, partial_file_failure
        self.add_alias_after_cow = add_alias_after_cow
        self.false_cow_success = false_cow_success
        self.va_shift = 0
        self.cow_alias_added = False
        self.events, self.remounts, self.file_writes, self.cow_writes = [], [], [], []
        self.file_fail_started = False
        self.last_live_views = []

    def run(self, request, parse):
        cpu, start, stop = load_arm64(self.artifact['path'])
        module = self.module
        library, rqpath, outpath = module.LIBRARY_PATH, module.REQUEST_PATH, module.RESULT_PATH
        dev = f'{(self.DEV >> 8) & 0xfff:x}:{self.DEV & 0xff:x}'
        mapped_length = align_up(len(self.data))
        initial_memory = bytes(self.data) + bytes(mapped_length-len(self.data))
        vm = [dict(va=0x10000000, end=0x10001000, off=0, dev='56:78',
                   ino=33, prot=5, priv=True, path=library, frozen=set())]
        for index in range(self.aliases):
            va = self.FILE_VA + self.va_shift + index * (self.ALIAS_VA-self.FILE_VA)
            cpu.mem_map(va, mapped_length)
            cpu.mem_write(va, initial_memory)
            cpu.mem_protect(va, mapped_length, self.permissions)
            vm.append(dict(va=va, end=va+mapped_length, off=0, dev=dev,
                           ino=self.INO, prot=self.permissions, priv=self.private,
                           path=self.path, frozen=set()))
        files = {rqpath: bytearray(request), library: bytearray(b'synthetic-plugin')}
        fds, nextfd, links, ro = {}, 10, 1, True
        processes = ['.', '..', 'self', str(self.PID), '601', '2']

        def cstring(address):
            out = bytearray()
            while len(out) < 1024:
                value = bytes(cpu.mem_read(address+len(out), 1))
                if value == b'\0':
                    return out.decode()
                out.extend(value)
            raise AssertionError('Unbounded path')

        def maps():
            lines = []
            for row in sorted(vm, key=lambda item: item['va']):
                prot = row['prot']
                mode = ('r' if prot & 1 else '-') + ('w' if prot & 2 else '-') + ('x' if prot & 4 else '-') + ('p' if row['priv'] else 's')
                lines.append(f"{row['va']:x}-{row['end']:x} {mode} {row['off']:08x} {row['dev']} {row['ino']} {row['path']}\n")
            return ''.join(lines).encode()

        def content(path):
            if path == '/proc/self/maps':
                return maps()
            if path == '/proc/self/auxv':
                return struct.pack('<4Q', 6, 4096, 0, 0)
            if path == '/proc/self/mounts':
                return b'/dev/synthetic-usr /usr ext2 ' + (b'ro' if ro else b'rw') + b',sync 0 0\n'
            if path == '/proc/601/maps':
                return (f'30000000-{0x30000000+mapped_length:x} r--p 00000000 {dev} {self.INO} {self.path}\n').encode() if self.foreign_mapping else b''
            if path == '/proc/2/maps':
                return b''
            if path == self.path:
                return bytes(self.data)
            return bytes(files[path])

        def file_stat(path):
            if path == self.path:
                return STAT.pack(self.DEV, self.INO, 0o100644, 1, self.UID, self.GID,
                                 0, 0, len(self.data), 1024, 0, (len(self.data)+511)//512,
                                 1, 2, 3, 4, 5, 6, 0)
            assert path == library
            return STAT.pack(0x5678, 33, 0o100644, links, 0, 0, 0, 0, 16,
                             512, 0, 1, 1, 2, 3, 4, 5, 6, 0)

        def memory_row(address, length):
            rows = [row for row in vm if row['path'] == self.path
                    and row['va'] <= address and address+length <= row['end']]
            assert len(rows) == 1
            return rows[0]

        def write_file(offset, raw):
            assert offset+len(raw) <= len(self.data)
            self.data[offset:offset+len(raw)] = raw
            # Model file-page-cache visibility. Without an actual same-value
            # /proc/self/mem write, private mappings still follow file changes.
            for row in vm:
                if row['path'] != self.path:
                    continue
                lo = max(offset, row['off'])
                hi = min(offset+len(raw), row['off']+row['end']-row['va'])
                for at in range(lo, hi):
                    address = row['va']+at-row['off']
                    if address//4096 not in row['frozen']:
                        cpu.mem_write(address, raw[at-offset:at-offset+1])
            self.file_writes.append((offset, len(raw)))

        def hook(_cpu, _interrupt, _data):
            nonlocal nextfd, links, ro
            number = cpu.reg_read(UC_ARM64_REG_X8)
            args = [cpu.reg_read(reg) for reg in (UC_ARM64_REG_X0, UC_ARM64_REG_X1,
                    UC_ARM64_REG_X2, UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_X5)]
            result = 0
            if number == 56:
                path, flags = cstring(args[1]), args[2]
                assert path in (rqpath, outpath, library, self.path, '/proc',
                                '/proc/self/maps', '/proc/self/mem', '/proc/self/auxv',
                                '/proc/self/mounts', '/proc/601/maps', '/proc/2/maps'), path
                if flags & 64:
                    assert path == outpath and flags & 128 and path not in files
                    files[path] = bytearray()
                if path == self.path and flags & 3:
                    assert not ro
                nextfd += 1
                fds[nextfd] = dict(path=path, flags=flags, at=0)
                result = nextfd
                self.events.append(('open', path, flags))
            elif number == 57:
                row = fds.pop(args[0])
                self.events.append(('close', row['path'], row['flags']))
                if (row['path'] == '/proc/self/mem' and row['flags'] & 3 == 2
                        and self.cow_writes and self.add_alias_after_cow
                        and not self.cow_alias_added):
                    va = 0x44000000
                    cpu.mem_map(va, mapped_length)
                    cpu.mem_write(va, initial_memory)
                    cpu.mem_protect(va, mapped_length, 1)
                    vm.append(dict(va=va, end=va+mapped_length, off=0, dev=dev,
                                   ino=self.INO, prot=1, priv=True,
                                   path=self.path, frozen=set()))
                    self.cow_alias_added = True
                    self.events.append(('new-alias-after-complete-cow', va))
            elif number in (63, 67):
                row = fds[args[0]]
                if row['flags'] & 3 == 1:
                    result = -9
                elif row['path'] == '/proc/self/mem':
                    assert number == 67
                    memory_row(args[3], args[2])
                    raw = bytes(cpu.mem_read(args[3], args[2]))
                    cpu.mem_write(args[1], raw)
                    result = len(raw)
                else:
                    offset = args[3] if number == 67 else row['at']
                    raw = content(row['path'])[offset:offset+args[2]]
                    if raw:
                        cpu.mem_write(args[1], raw)
                    result = len(raw)
                    if number == 63:
                        row['at'] += result
            elif number == 68:
                row = fds[args[0]]
                assert row['flags'] & 3 == 2
                raw = bytes(cpu.mem_read(args[1], args[2]))
                if row['path'] == '/proc/self/mem':
                    view = memory_row(args[3], len(raw))
                    assert view['priv'] and view['prot'] == 1
                    assert raw == bytes(cpu.mem_read(args[3], len(raw)))
                    self.cow_writes.append((args[3], len(raw)))
                    if self.cow_failure:
                        result = -5
                    else:
                        cpu.mem_write(args[3], raw)
                        if not self.false_cow_success:
                            view['frozen'].update(range(args[3]//4096,
                                                        (args[3]+len(raw)-1)//4096+1))
                        result = len(raw)
                else:
                    assert row['path'] == self.path and not ro
                    if self.partial_file_failure:
                        if not self.file_fail_started:
                            self.file_fail_started = True
                            write_file(args[3], raw[:1])
                            result = 1
                        else:
                            result = -5
                    else:
                        write_file(args[3], raw)
                        result = len(raw)
            elif number == 80:
                cpu.mem_write(args[1], file_stat(fds[args[0]]['path']))
            elif number == 79:
                assert cstring(args[1]) == self.path and args[3] == 0x100
                cpu.mem_write(args[2], file_stat(self.path))
            elif number == 35:
                assert cstring(args[1]) == library and links == 1
                links = 0
                files.pop(library)
                self.events.append(('unlink-own-plugin', library))
            elif number == 43:
                assert cstring(args[0]) == '/tmp/jiritsu'
                cpu.mem_write(args[1], FS.pack(0x4D44, 512, 48000, 45000, 45000,
                    0, 0, 1, 2, 255, 512, 0, 0, 0, 0, 0))
            elif number == 61:
                row = fds[args[0]]
                assert row['path'] == '/proc'
                raw = b''.join(dirent(name) for name in processes) if row['at'] == 0 else b''
                assert len(raw) <= args[2]
                if raw:
                    cpu.mem_write(args[1], raw)
                row['at'] += len(raw)
                result = len(raw)
            elif number == 40:
                assert cstring(args[1]) == '/usr' and args[3] in (0xC30, 0xC31)
                if args[3] == 0xC31:
                    assert not any(row['path'] == self.path and row['flags'] & 3 for row in fds.values())
                ro = args[3] == 0xC31
                self.remounts.append(ro)
            elif number == 64:
                row = fds[args[0]]
                assert row['path'] == outpath and row['flags'] & 3 == 1
                raw = bytes(cpu.mem_read(args[1], args[2]))
                files[outpath].extend(raw)
                result = len(raw)
            elif number == 82:
                assert fds[args[0]]['path'] in (outpath, self.path)
            elif number == 172:
                result = self.PID
            elif number == 175:
                result = 0
            else:
                # No mmap/mremap/ftruncate/rename/unlink-resource may hide in
                # this prefix-only worker.
                raise AssertionError(('Unexpected syscall', number, args))
            cpu.reg_write(UC_ARM64_REG_X0, result & ((1 << 64)-1))

        cpu.hook_add(UC_HOOK_INTR, hook)
        cpu.emu_start(start, stop, count=70000000)
        assert not fds and library not in files
        self.last_live_views = [bytes(cpu.mem_read(row['va'], row['end']-row['va']))
                                for row in vm if row['path'] == self.path]
        return parse(bytes(files[outpath])), bytes(files[outpath])


def native_summary(report):
    names = ('mode', 'phase', 'native_status', 'mapping_count', 'cow_attempts',
             'cow_segments', 'cow_segments_expected', 'cow_bytes_expected',
             'bytes_cow_preserved', 'write_attempts', 'writes_completed',
             'bytes_written', 'cross_pids', 'cross_matches', 'readonly',
             'complete', 'cow_verified', 'cleanup_safe', 'mapping_state_unknown',
             'file_state_unknown', 'operation_state_unknown',
             'post_runtime_preserved_verified', 'resource_prefix_restore_complete',
             'full_file_restore_complete')
    return {name: report[name] for name in names if name in report}


class PrefixMechanismTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module('resource_delta_fixture_worker', ROOT / 'worker.py')
        cls.output = Path(OPTIONS.output).absolute()
        cls.output.mkdir(mode=0o700, parents=True, exist_ok=False)
        cls.target = synthetic(12239, 'SYNTHETIC-original-baseline')
        source = bytearray(cls.target)
        # Two distinct windows. The first crosses a hardware page boundary,
        # so preserving only its first page must make the live-view test fail.
        for index in range(4090, 4106):
            source[index] ^= 0x55
        for index in range(8200, 8208):
            source[index] ^= 0xAA
        cls.tail = synthetic(150, 'SYNTHETIC-owned-appended-tail')
        cls.source = bytes(source) + cls.tail
        cls.plan = cls.module.make_plan(
            '/usr/share/app/image_00_32_IPSX.uxc', cls.source, cls.target,
            authority={
                'schema': cls.module.AUTHORITY_SCHEMA,
                'original_backup_sha256': SHA(b'SYNTHETIC-original-complete-backup'),
                'current_file_readback_sha256': SHA(cls.source),
                'resource_reference_proof_sha256': SHA(b'SYNTHETIC-resource-reference-proof'),
                'boot_or_load_proof_sha256': SHA(b'SYNTHETIC-loaded-view-proof'),
            })
        cls.post = cls.target + cls.tail
        # One and only one native profile is built for this entire suite.
        cls.build = cls.module.build(cls.plan, cls.output / 'profile', compiler=OPTIONS.compiler)
        assert cls.build['target_ABI_checked'] and cls.build['double_build_identical']
        assert 0 < cls.build['worker']['size'] < 65536

    def fixture(self, **options):
        return PrefixFixture(self.module, deepcopy(self.plan), self.build['worker'],
                             self.source, **options)

    def phase(self, fixture, mode, nonce_number, inspection=None):
        nonce = bytes([nonce_number]) * 16
        request = self.module.request(self.plan, mode, nonce, inspection)
        self.assertEqual(len(request), 256)
        report, raw = fixture.run(request, lambda value: self.module.parse_report(
            self.plan, value, mode, nonce))
        self.assertEqual(len(raw), 544)
        self.assertEqual(report['source_dev'], PrefixFixture.DEV)
        self.assertEqual(report['source_ino'], PrefixFixture.INO)
        self.assertFalse(report['resource_prefix_restore_complete'])
        self.assertFalse(report['full_file_restore_complete'])
        self.assertTrue(report['full_readback_required'])
        return report

    def assert_tail_and_eof(self, fixture):
        self.assertEqual(len(fixture.data), len(self.source))
        self.assertEqual(bytes(fixture.data[len(self.target):]), self.tail)

    def roundtrip(self, fixture, aliases):
        inspect = self.phase(fixture, 0, 1)
        self.assertTrue(inspect['complete'])
        self.assertEqual(bytes(fixture.data), self.source)
        self.assertEqual(fixture.cow_writes, [])
        self.assertEqual(fixture.file_writes, [])
        old_views = list(fixture.last_live_views)
        applied = self.phase(fixture, 1, 2, inspect)
        self.assertTrue(applied['complete'])
        self.assertTrue(applied['cow_verified'])
        self.assertTrue(applied['post_runtime_preserved_verified'])
        self.assertTrue(applied['cleanup_safe'])
        self.assertFalse(applied['operation_state_unknown'])
        self.assertEqual(applied['mapping_count'], aliases)
        self.assertEqual(applied['cow_segments'], aliases*len(self.plan['windows']))
        self.assertEqual(applied['bytes_written'], self.plan['window_total_bytes'])
        self.assertEqual(bytes(fixture.data), self.post)
        self.assertEqual(SHA(fixture.data), self.plan['post']['sha256'])
        self.assertEqual(fixture.last_live_views, old_views)
        self.assert_tail_and_eof(fixture)
        self.assertEqual(fixture.remounts, [False, True])
        OBSERVATIONS.append(dict(test=self.id(), status='PASS',
            inspect=native_summary(inspect), apply=native_summary(applied),
            live_old_views_preserved=True, post_SHA=SHA(fixture.data),
            tail_SHA=SHA(self.tail), EOF_unchanged=True))

    def test_01_page_crossing_COW_then_exact_prefix_write_keeps_live_old_view(self):
        self.roundtrip(self.fixture(), aliases=1)

    def test_02_all_private_aliases_COW_before_any_file_window_write(self):
        self.roundtrip(self.fixture(aliases=2), aliases=2)

    def test_03_no_related_alias_can_restore_without_process_memory_write(self):
        fixture = self.fixture(aliases=0)
        self.roundtrip(fixture, aliases=0)
        self.assertEqual(fixture.cow_writes, [])

    def test_04_mapping_drift_before_or_after_COW_stops_before_file_write(self):
        before = self.fixture()
        inspect = self.phase(before, 0, 1)
        before.va_shift = 0x100000
        rejected_before = self.phase(before, 1, 2, inspect)
        self.assertFalse(rejected_before['complete'])
        self.assertTrue(rejected_before['cleanup_safe'])
        self.assertEqual(before.cow_writes, [])
        self.assertEqual(before.file_writes, [])
        self.assertEqual(bytes(before.data), self.source)

        after = self.fixture(add_alias_after_cow=True)
        inspect = self.phase(after, 0, 3)
        rejected_after = self.phase(after, 1, 4, inspect)
        self.assertTrue(after.cow_alias_added)
        self.assertFalse(rejected_after['complete'])
        self.assertTrue(rejected_after['cow_verified'])
        self.assertTrue(rejected_after['cleanup_safe'])
        self.assertFalse(rejected_after['operation_state_unknown'])
        self.assertEqual(after.file_writes, [])
        self.assertEqual(after.remounts, [])
        self.assertEqual(bytes(after.data), self.source)
        OBSERVATIONS.append(dict(test=self.id(), status='PASS',
            before_COW=native_summary(rejected_before),
            after_COW=native_summary(rejected_after),
            file_bytes_unchanged=True,
            fully_verified_same_value_COW_semantic_refusal_is_known=True))

    def test_05_other_PID_touched_page_mapping_refuses_without_mutation(self):
        fixture = self.fixture(foreign_mapping=True)
        report = self.phase(fixture, 0, 1)
        self.assertFalse(report['complete'])
        self.assertTrue(report['cleanup_safe'])
        self.assertEqual(report['cross_matches'], 1)
        self.assertEqual(fixture.file_writes, [])
        self.assertEqual(fixture.cow_writes, [])
        self.assertEqual(bytes(fixture.data), self.source)
        OBSERVATIONS.append(dict(test=self.id(), status='PASS', report=native_summary(report)))

    def test_06_shared_writable_executable_maps_all_refuse_before_COW(self):
        reports = []
        for name, options in (('shared', {'private': False}),
                              ('writable', {'permissions': 3}),
                              ('executable', {'permissions': 5})):
            with self.subTest(permission=name):
                fixture = self.fixture(**options)
                report = self.phase(fixture, 0, 1)
                self.assertFalse(report['complete'])
                self.assertTrue(report['cleanup_safe'])
                self.assertEqual(report['native_status'], -13)
                self.assertEqual(fixture.cow_writes, [])
                self.assertEqual(fixture.file_writes, [])
                self.assertEqual(fixture.remounts, [])
                self.assertEqual(bytes(fixture.data), self.source)
                reports.append(dict(permission=name, report=native_summary(report)))
        OBSERVATIONS.append(dict(test=self.id(), status='PASS', cases=reports))

    def test_07_failed_same_value_memory_write_is_UNKNOWN_and_no_file_write(self):
        fixture = self.fixture(cow_failure=True)
        inspect = self.phase(fixture, 0, 1)
        report = self.phase(fixture, 1, 2, inspect)
        self.assertFalse(report['complete'])
        self.assertFalse(report['cleanup_safe'])
        self.assertTrue(report['mapping_state_unknown'])
        self.assertTrue(report['operation_state_unknown'])
        self.assertEqual(report['cow_attempts'], 1)
        self.assertEqual(report['cow_segments'], 0)
        self.assertEqual(fixture.file_writes, [])
        self.assertEqual(fixture.remounts, [])
        self.assertEqual(bytes(fixture.data), self.source)
        OBSERVATIONS.append(dict(test=self.id(), status='PASS', report=native_summary(report),
            cleanup_and_healthy_STOP_not_authorized=True))

    def test_08_partial_file_write_then_EIO_is_UNKNOWN_tail_stays_unchanged(self):
        fixture = self.fixture(partial_file_failure=True)
        inspect = self.phase(fixture, 0, 1)
        old_views = list(fixture.last_live_views)
        report = self.phase(fixture, 1, 2, inspect)
        self.assertFalse(report['complete'])
        self.assertFalse(report['cleanup_safe'])
        self.assertTrue(report['file_state_unknown'])
        self.assertTrue(report['operation_state_unknown'])
        self.assertEqual(report['write_attempts'], 1)
        self.assertEqual(report['writes_completed'], 0)
        self.assertEqual(report['bytes_written'], 1)
        self.assertEqual(fixture.file_writes[0][1], 1)
        self.assertNotEqual(bytes(fixture.data), self.source)
        self.assertNotEqual(bytes(fixture.data), self.post)
        self.assertEqual(fixture.last_live_views, old_views)
        self.assert_tail_and_eof(fixture)
        OBSERVATIONS.append(dict(test=self.id(), status='PASS', report=native_summary(report),
            actual_partial_file_byte_changed=True, live_old_views_preserved=True,
            tail_and_EOF_unchanged=True, cleanup_and_healthy_STOP_not_authorized=True))

    def test_09_false_same_value_COW_success_detected_after_file_changes(self):
        fixture = self.fixture(false_cow_success=True)
        inspect = self.phase(fixture, 0, 1)
        old_views = list(fixture.last_live_views)
        report = self.phase(fixture, 1, 2, inspect)
        self.assertFalse(report['complete'])
        self.assertFalse(report['post_runtime_preserved_verified'])
        self.assertFalse(report['cleanup_safe'])
        self.assertTrue(report['mapping_state_unknown'])
        self.assertTrue(report['operation_state_unknown'])
        self.assertEqual(report['writes_completed'], len(self.plan['windows']))
        self.assertEqual(bytes(fixture.data), self.post)
        self.assertNotEqual(fixture.last_live_views, old_views)
        self.assert_tail_and_eof(fixture)
        OBSERVATIONS.append(dict(test=self.id(), status='PASS', report=native_summary(report),
            fake_COW_write_returned_success_without_freezing_pages=True,
            disk_postimage_exact_but_runtime_old_view_lost=True,
            post_runtime_check_rejected_false_success=True,
            cleanup_and_healthy_STOP_not_authorized=True))


def main():
    global OPTIONS
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler', required=True, help='Explicit offline Zig0.13.0 executable')
    parser.add_argument('--output', required=True, help='New, real output directory')
    OPTIONS = parser.parse_args()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(PrefixMechanismTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    paths = [ROOT / 'native/prefix_delta.c', ROOT / 'worker.py', Path(__file__)]
    receipt = dict(schema='a7m4-resource-prefix-delta-synthetic-arm-tests/1',
        status='PASS' if result.wasSuccessful() else 'FAIL', tests_run=result.testsRun,
        failures=len(result.failures), errors=len(result.errors),
        source_sha256={str(p.resolve()): SHA(p.read_bytes()) for p in paths},
        device_io=False, network_io=False, private_firmware_inputs=False,
        simulation_not_hardware_evidence=True, compiler=str(Path(OPTIONS.compiler).resolve()),
        cases=OBSERVATIONS, limitations=[
            'Actual ARM64 instructions under finite simulated file/pagecache/proc/syscall behavior.',
            'No model of all kernel races, ext2 behavior, low-memory or power failures.',
            'Synthetic file bytes and non-camera identities do not grant deployment admission.',
            'No USB or vendor STOP executes; unsafe report cleanup admission is checked only.',
            'Host source/target hashes, nonces, plan identity and session barriers have separate owner tests.',
        ])
    output = Path(OPTIONS.output)
    if output.exists():
        (output / 'native-test-results.json').write_text(json.dumps(receipt, indent=2) + '\n')
    raise SystemExit(0 if result.wasSuccessful() else 1)


if __name__ == '__main__':
    main()
