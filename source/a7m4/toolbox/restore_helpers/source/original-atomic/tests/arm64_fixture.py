# SPDX-License-Identifier: MIT
"""Finite synthetic ARM64 verification of original-backup atomic replacement.

This fixture executes the compiled constructor, with a deliberately finite
in-memory model of files, inodes, mounts and syscalls. It has no device or
network interface. Its synthetic inputs are never deployment admission.
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


def aligned(value, unit=4096):
    return (value + unit - 1) // unit * unit


def load_arm64(path):
    cpu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    base, stop = 0x10000000, 0x70000000
    with Path(path).open('rb') as stream:
        elf = ELFFile(stream)
        assert elf.header['e_machine'] == 'EM_AARCH64' and elf.header['e_type'] == 'ET_DYN'
        segments = [s for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD']
        cpu.mem_map(base, aligned(max(s['p_vaddr'] + s['p_memsz'] for s in segments)))
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


def synthetic(length, label):
    return b''.join(hashlib.sha256(label.encode() + struct.pack('<I', i)).digest()
                    for i in range((length + 31) // 32))[:length]


class Node:
    def __init__(self, data=b'', *, dev=0x1234, ino=424242, mode=0o100644,
                 uid=1000, gid=1001, nlink=1):
        self.data, self.dev, self.ino = bytearray(data), dev, ino
        self.mode, self.uid, self.gid, self.nlink = mode, uid, gid, nlink

    def stat(self):
        return STAT.pack(self.dev, self.ino, self.mode, self.nlink, self.uid, self.gid,
                         0, 0, len(self.data), 1024, 0, (len(self.data)+511)//512,
                         1, 2, 3, 4, 5, 6, 0)


class AtomicFixture:
    PID, DEV, SOURCE_INO, STAGE_INO = 498, 0x1234, 424242, 525252
    FILE_VA = 0x40000000

    def __init__(self, module, plan, artifact, source, *, resource_free=None,
                 workspace_free=12*1024*1024, partial_append=False,
                 rename_failure=False, post_rename_dirsync_failure=False,
                 create_race=False, create_unknown_failure=False, defer_usr_ro=False):
        self.module, self.plan, self.artifact = module, plan, artifact
        self.path, self.stagepath = plan['resource_path'], plan['stage_path']
        self.cp = self.path.startswith('/cp/')
        self.mountpoint = '/cp' if self.cp else '/usr'
        self.parent = self.path.rsplit('/', 1)[0]
        # Non-root, mount-derived VFAT ownership is intentional.
        self.original = Node(source, ino=self.SOURCE_INO,
                             mode=0o100755 if self.cp else 0o100640,
                             uid=501 if self.cp else 1000, gid=20 if self.cp else 1001)
        self.nodes = {self.path: self.original}
        for index, path in enumerate(('/usr', '/usr/share', '/usr/share/app', '/cp')):
            self.nodes[path] = Node(ino=800+index, mode=0o40755, uid=0, gid=0)
        unit = 1024
        self.resource_initial_free = (aligned(plan['target']['size'], unit)+32*unit
                                      if resource_free is None else resource_free)
        self.workspace_free = workspace_free
        self.partial_append, self.rename_failure = partial_append, rename_failure
        self.post_rename_dirsync_failure = post_rename_dirsync_failure
        self.create_race = create_race
        self.create_unknown_failure = create_unknown_failure
        self.defer_usr_ro = defer_usr_ro
        self.partial_started = False
        self.ro = not self.cp
        self.events, self.remounts, self.stage_writes = [], [], []
        self.last_old_view = None
        self.renamed = False

    def stage(self):
        return self.nodes.get(self.stagepath)

    def run(self, request, parse):
        cpu, start, stop = load_arm64(self.artifact['path'])
        library, rqpath, outpath = (self.module.LIBRARY_PATH,
                                   self.module.REQUEST_PATH, self.module.RESULT_PATH)
        # Each invocation receives a newly uploaded loader/request/report pair.
        self.nodes[library] = Node(b'SYNTHETIC-plugin', dev=0x5678, ino=33,
                                   mode=0o100755, uid=0, gid=0)
        self.nodes[rqpath] = Node(request, dev=0x5678, ino=34,
                                  mode=0o100755, uid=0, gid=0)
        self.nodes.pop(outpath, None)
        fds, nextfd = {}, 10
        old_length = aligned(max(1, len(self.original.data)))
        cpu.mem_map(self.FILE_VA, old_length)
        if self.original.data:
            cpu.mem_write(self.FILE_VA, bytes(self.original.data))
        cpu.mem_protect(self.FILE_VA, old_length, 1)

        def cstring(address):
            out = bytearray()
            while len(out) < 2048:
                value = bytes(cpu.mem_read(address+len(out), 1))
                if value == b'\0':
                    return out.decode()
                out.extend(value)
            raise AssertionError('Unbounded path')

        def resolve(dirfd, path):
            if path.startswith('/'):
                return path
            return fds[dirfd]['path'].rstrip('/') + '/' + path

        def node_content(path):
            if path == '/proc/self/maps':
                return (f'10000000-10001000 r-xp 00000000 56:78 33 {library}\n'
                        f'{self.FILE_VA:x}-{self.FILE_VA+old_length:x} r--p 00000000 12:34 '
                        f'{self.original.ino} {self.path}\n').encode()
            if path == '/proc/self/mounts':
                opts = ('rw,sync,noatime,nodiratime,fmask=0022,dmask=0022,codepage=437,'
                        'iocharset=ascii,shortname=mixed,posix_attr,avoid_dlink,errors=remount-ro'
                        if self.cp else ('ro' if self.ro else 'rw') +
                        ',sync,noatime,nodiratime,errors=continue')
                device = '/dev/nflasha8' if self.cp else '/dev/nflasha15'
                return f'{device} {self.mountpoint} {"vfat" if self.cp else "ext2"} {opts} 0 0\n'.encode()
            return bytes(self.nodes[path].data)

        def fd_node(fd):
            return fds[fd]['node']

        def filesystem(address, *, workspace=False):
            unit = 512 if workspace else 1024
            stage = self.stage()
            used = aligned(len(stage.data), unit) if stage else 0
            available = self.workspace_free if workspace else self.resource_initial_free-used
            assert available >= 0
            cpu.mem_write(address, FS.pack(0x4D44 if workspace or self.cp else 0xEF53,
                unit, 48000, available//unit, available//unit, 0, 0, 1, 2,
                255, unit, 0, 0, 0, 0, 0))

        def hook(_cpu, _interrupt, _data):
            nonlocal nextfd
            number = cpu.reg_read(UC_ARM64_REG_X8)
            args = [cpu.reg_read(reg) for reg in (UC_ARM64_REG_X0, UC_ARM64_REG_X1,
                    UC_ARM64_REG_X2, UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_X5)]
            result = 0
            if number == 56:
                path, flags = resolve(args[0], cstring(args[1])), args[2]
                assert path in self.nodes or path in (self.stagepath, outpath,
                    '/proc/self/maps', '/proc/self/mounts'), path
                if flags & 64:
                    assert flags & 128, 'Every creation is exclusive'
                    if path in self.nodes:
                        result = -17
                    elif path == self.stagepath and self.create_race:
                        self.nodes[path] = Node(b'FOREIGN-race-stage', ino=self.STAGE_INO+99)
                        self.create_race = False
                        result = -17
                    else:
                        assert path in (self.stagepath, outpath)
                        if path == self.stagepath:
                            assert self.cp or not self.ro
                            self.nodes[path] = Node(ino=self.STAGE_INO,
                                mode=(self.original.mode if self.cp else 0o100000 | (args[3] & 0o777)),
                                uid=self.original.uid if self.cp else 0,
                                gid=self.original.gid if self.cp else 0)
                        else:
                            self.nodes[path] = Node(dev=0x5678, ino=35, uid=0, gid=0)
                        if path == self.stagepath and self.create_unknown_failure:
                            # A creation error does not prove absence: model
                            # a filesystem which created the dirent then EIO.
                            result = -5
                elif path not in self.nodes and not path.startswith('/proc/'):
                    result = -2
                if result == 0:
                    if path in (self.path, self.stagepath) and flags & 3:
                        assert self.cp or not self.ro
                    nextfd += 1
                    fds[nextfd] = dict(path=path, flags=flags, at=0, node=self.nodes.get(path))
                    result = nextfd
                self.events.append(('open', path, flags, result))
            elif number == 57:
                row = fds.pop(args[0])
                self.events.append(('close', row['path'], row['flags']))
            elif number in (63, 67):
                row = fds[args[0]]
                if row['flags'] & 3 == 1:
                    result = -9
                else:
                    at = args[3] if number == 67 else row['at']
                    content = (node_content(row['path']) if row['node'] is None
                               else bytes(row['node'].data))
                    raw = content[at:at+args[2]]
                    if raw:
                        cpu.mem_write(args[1], raw)
                    result = len(raw)
                    if number == 63:
                        row['at'] += result
            elif number == 68:
                row = fds[args[0]]
                assert row['path'] == self.stagepath and row['flags'] & 3 == 2
                assert self.cp or not self.ro
                raw, at = bytes(cpu.mem_read(args[1], args[2])), args[3]
                assert at == len(row['node'].data), 'Native must append at exact stage EOF'
                if self.partial_append and self.partial_started:
                    result = -5
                else:
                    if self.partial_append:
                        raw = raw[:1]
                        self.partial_started = True
                    row['node'].data.extend(raw)
                    self.stage_writes.append((at, len(raw)))
                    result = len(raw)
            elif number == 64:
                row = fds[args[0]]
                assert row['path'] == outpath and row['flags'] & 3 == 1
                raw = bytes(cpu.mem_read(args[1], args[2]))
                row['node'].data.extend(raw)
                result = len(raw)
            elif number == 80:
                cpu.mem_write(args[1], fd_node(args[0]).stat())
            elif number == 79:
                assert args[3] == 0x100
                path = resolve(args[0], cstring(args[1]))
                if path in self.nodes:
                    cpu.mem_write(args[2], self.nodes[path].stat())
                else:
                    result = -2
            elif number in (52, 55):
                assert not self.cp, 'VFAT profile must never chmod/chown'
                assert fd_node(args[0]) is self.stage()
                if number == 52:
                    fd_node(args[0]).mode = 0o100000 | args[1]
                else:
                    fd_node(args[0]).uid, fd_node(args[0]).gid = args[1:3]
                self.events.append(('fchmod' if number == 52 else 'fchown',))
            elif number == 35:
                path = resolve(args[0], cstring(args[1]))
                assert path in (library, self.stagepath), 'No source unlink syscall'
                self.nodes[path].nlink -= 1
                self.nodes.pop(path)
                self.events.append(('unlink', path))
            elif number == 38:
                old, new = resolve(args[0], cstring(args[1])), resolve(args[2], cstring(args[3]))
                assert old == self.stagepath and new == self.path
                self.events.append(('rename', old, new))
                if self.rename_failure:
                    result = -5
                else:
                    self.nodes[new].nlink -= 1
                    self.nodes[new] = self.nodes.pop(old)
                    self.renamed = True
            elif number == 43:
                assert cstring(args[0]) == '/tmp/jiritsu'
                filesystem(args[1], workspace=True)
            elif number == 44:
                assert fds[args[0]]['path'] == self.parent
                filesystem(args[1])
            elif number == 40:
                assert not self.cp and cstring(args[1]) == '/usr' and args[3] in (0xC30, 0xC31)
                if args[3] == 0xC31:
                    assert not any(row['path'] == self.stagepath and row['flags'] & 3 for row in fds.values())
                requested_ro = args[3] == 0xC31
                self.remounts.append(requested_ro)
                if requested_ro and self.defer_usr_ro:
                    result = -16
                else:
                    self.ro = requested_ro
            elif number == 82:
                path = fds[args[0]]['path']
                assert path in (self.parent, self.stagepath, outpath)
                if path == self.parent and self.renamed and self.post_rename_dirsync_failure:
                    result = -5
                self.events.append(('fsync', path, result))
            elif number == 172:
                result = self.PID
            elif number == 175:
                result = 0
            else:
                raise AssertionError(('Unexpected syscall; no source pwrite/truncate permitted', number, args))
            cpu.reg_write(UC_ARM64_REG_X0, result & ((1 << 64)-1))

        cpu.hook_add(UC_HOOK_INTR, hook)
        cpu.emu_start(start, stop, count=70000000)
        assert not fds
        self.last_old_view = bytes(cpu.mem_read(self.FILE_VA, len(self.original.data)))
        assert bytes(self.original.data) == self.last_old_view
        raw = bytes(self.nodes[outpath].data)
        return parse(raw), raw


def summary(report):
    keys = ('mode', 'phase', 'native_status', 'flags', 'source_ino', 'source_size',
            'stage_ino', 'stage_size', 'fs_available', 'fs_needed', 'bytes_written',
            'bytes_verified', 'write_attempts', 'rename_attempts', 'renamed',
            'stage_created', 'stage_removed', 'complete', 'cleanup_safe',
            'operation_state_unknown', 'full_file_restore_complete', 'readonly')
    return {key: report[key] for key in keys if key in report}


class AtomicMechanismTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module('original_atomic_fixture_worker', ROOT / 'worker.py')
        cls.output = Path(OPTIONS.output).absolute()
        cls.output.mkdir(mode=0o700, parents=True, exist_ok=False)
        cls.profiles = {}
        for name, path, source_size, target_size in (
            ('usr', '/usr/share/app/image_00_32_IPSX.uxc', 1703, 1103),
            ('cp', '/cp/SysSound.bin', 1301, 33707),
        ):
            source = synthetic(source_size, 'SYNTHETIC-current-' + name)
            target = synthetic(target_size, 'SYNTHETIC-original-' + name)
            plan = cls.module.make_plan(path, source, target, authority={
                'schema': cls.module.AUTHORITY_SCHEMA,
                'original_backup_sha256': SHA(b'SYNTHETIC-original-complete-backup'),
                'current_file_readback_sha256': SHA(source),
                'resource_reference_proof_sha256': SHA(b'SYNTHETIC-original-reference-proof'),
                'boot_or_load_proof_sha256': SHA(b'SYNTHETIC-load-compatibility-proof'),
            })
            build = cls.module.build(plan, cls.output / name, compiler=OPTIONS.compiler)
            assert build['target_ABI_checked'] and build['double_build_identical']
            assert 0 < build['worker']['size'] < 65536
            cls.profiles[name] = dict(plan=plan, source=source, target=target, build=build)

    def fixture(self, profile='usr', **options):
        data = self.profiles[profile]
        return AtomicFixture(self.module, deepcopy(data['plan']), data['build']['worker'],
                             data['source'], **options)

    def phase(self, fixture, mode, nonce, previous=None, *, chunk=b'',
              source_readback=None, stage_readback=None, mutate=None):
        nonce_bytes = bytes([nonce]) * 16
        request = self.module.request(fixture.plan, mode, nonce_bytes, previous,
            chunk=chunk, source_readback=source_readback, stage_readback=stage_readback)
        self.assertLess(len(request), 65536)
        if mutate:
            request = mutate(request)
        report, raw = fixture.run(request, lambda value: self.module.parse_report(
            fixture.plan, value, mode, nonce_bytes, request_bytes=request))
        self.assertEqual(len(raw), 384)
        self.assertFalse(report.get('full_file_restore_complete', False))
        return report

    def begin(self, fixture):
        inspected = self.phase(fixture, 0, 1)
        self.assertTrue(inspected['complete'])
        begun = self.phase(fixture, 1, 2, inspected,
            source_readback=self.module.verify_source(fixture.plan, bytes(fixture.original.data)))
        self.assertTrue(begun['complete'])
        self.assertEqual(len(fixture.stage().data), 0)
        return begun

    def staged(self, fixture, *, wrong_target=False):
        report = self.begin(fixture)
        target = bytearray(self.profiles['cp' if fixture.cp else 'usr']['target'])
        if wrong_target:
            target[-1] ^= 0x80
        chunk_size = 32768 if fixture.cp else 512
        for nonce, offset in enumerate(range(0, len(target), chunk_size), start=3):
            report = self.phase(fixture, 2, nonce, report,
                                chunk=bytes(target[offset:offset+chunk_size]))
            self.assertTrue(report['complete'])
        self.assertEqual(bytes(fixture.stage().data), bytes(target))
        return report

    def test_01_ext2_ordered_stream_full_stage_barrier_atomic_shrink_preserves_old_inode(self):
        fixture = self.fixture()
        source, target = self.profiles['usr']['source'], self.profiles['usr']['target']
        staged = self.staged(fixture)
        self.assertEqual(bytes(fixture.nodes[fixture.path].data), source)
        receipt = self.module.verify_stage(fixture.plan, bytes(fixture.stage().data))
        committed = self.phase(fixture, 3, 30, staged, stage_readback=receipt)
        self.assertTrue(committed['complete'])
        self.assertTrue(committed['cleanup_safe'])
        self.assertEqual(bytes(fixture.nodes[fixture.path].data), target)
        self.assertNotEqual(fixture.nodes[fixture.path].ino, fixture.original.ino)
        self.assertEqual(fixture.original.nlink, 0)
        self.assertEqual(bytes(fixture.original.data), source)
        self.assertEqual(fixture.last_old_view, source)
        self.assertNotIn(fixture.stagepath, fixture.nodes)
        self.module.verify_readback(fixture.plan, bytes(fixture.nodes[fixture.path].data))
        self.assertTrue(fixture.ro)
        OBSERVATIONS.append(dict(test=self.id(), status='PASS', commit=summary(committed),
            exact_target_SHA=SHA(target), old_inode_and_mapping_bytes_preserved=True,
            only_target_rounded_plus32_units_budget=True))

    def test_02_VFAT_growth_uses_dynamic_nonroot_metadata_without_chown_or_remount(self):
        fixture = self.fixture('cp')
        target = self.profiles['cp']['target']
        staged = self.staged(fixture)
        committed = self.phase(fixture, 3, 30, staged,
            stage_readback=self.module.verify_stage(fixture.plan, bytes(fixture.stage().data)))
        self.assertTrue(committed['complete'])
        self.assertEqual(bytes(fixture.nodes[fixture.path].data), target)
        self.assertEqual((fixture.nodes[fixture.path].uid, fixture.nodes[fixture.path].gid), (501, 20))
        self.assertEqual(fixture.remounts, [])
        self.assertFalse(fixture.ro)
        self.assertFalse(any(event[0] in ('fchown', 'fchmod') for event in fixture.events))
        OBSERVATIONS.append(dict(test=self.id(), status='PASS', commit=summary(committed),
            nonroot_VFAT_uid=501, no_chown_chmod_or_remount=True))

    def test_03_existing_stage_and_OEXCL_race_never_overwrite_foreign_bytes(self):
        cases = []
        fixture = self.fixture()
        foreign = Node(b'FOREIGN-owned-by-somebody-else', ino=616161)
        fixture.nodes[fixture.stagepath] = foreign
        refused = self.phase(fixture, 0, 1)
        self.assertFalse(refused['complete'])
        self.assertEqual(bytes(foreign.data), b'FOREIGN-owned-by-somebody-else')
        self.assertEqual(fixture.stage_writes, [])
        cases.append(summary(refused))
        race = self.fixture(create_race=True)
        inspected = self.phase(race, 0, 1)
        refused = self.phase(race, 1, 2, inspected,
            source_readback=self.module.verify_source(race.plan, bytes(race.original.data)))
        self.assertFalse(refused['complete'])
        self.assertEqual(bytes(race.stage().data), b'FOREIGN-race-stage')
        self.assertEqual(race.stage_writes, [])
        self.assertEqual(bytes(race.original.data), self.profiles['usr']['source'])
        cases.append(summary(refused))
        unknown = self.fixture(create_unknown_failure=True)
        inspected = self.phase(unknown, 0, 1)
        refused = self.phase(unknown, 1, 2, inspected,
            source_readback=self.module.verify_source(unknown.plan, bytes(unknown.original.data)))
        self.assertFalse(refused['complete'])
        self.assertTrue(refused['operation_state_unknown'])
        self.assertFalse(refused['cleanup_safe'])
        self.assertIsNotNone(unknown.stage())
        self.assertEqual(unknown.stage_writes, [])
        self.assertEqual(bytes(unknown.original.data), self.profiles['usr']['source'])
        cases.append(summary(refused))
        OBSERVATIONS.append(dict(test=self.id(), status='PASS', reports=cases,
            no_foreign_stage_overwrite=True,
            create_EIO_can_leave_stage_and_cannot_authorize_healthy_STOP=True))

    def test_04_stage_identity_source_identity_and_nonsequential_offsets_refuse(self):
        cases = []
        fixture = self.fixture()
        begun = self.begin(fixture)
        nonce = b'\x03'*16
        valid_packet = self.module.request(fixture.plan, 2, nonce, begun, chunk=b'X')
        invalid_packet = valid_packet[:152] + struct.pack('<Q', 1) + valid_packet[160:]
        _, raw = fixture.run(invalid_packet, lambda value: None)
        with self.assertRaises(ValueError):
            self.module.parse_report(fixture.plan, raw, 2, nonce, request_bytes=invalid_packet)
        # Invalid submitted framing has no accepted host report. Inspect only
        # the native status field to establish refusal before file operations.
        self.assertEqual(struct.unpack_from('<q', raw, 72)[0], -116)
        self.assertEqual(fixture.stage_writes, [])
        cases.append(dict(invalid_offset_native_status=-116, host_packet_rejected=True))
        fixture = self.fixture()
        begun = self.begin(fixture)
        fixture.stage().ino += 1
        refused = self.phase(fixture, 2, 3, begun, chunk=b'X')
        self.assertFalse(refused['complete'])
        self.assertEqual(fixture.stage_writes, [])
        cases.append(summary(refused))
        fixture = self.fixture()
        staged = self.staged(fixture)
        fixture.original.ino += 1
        refused = self.phase(fixture, 3, 30, staged,
            stage_readback=self.module.verify_stage(fixture.plan, bytes(fixture.stage().data)))
        self.assertFalse(refused['complete'])
        self.assertFalse(fixture.renamed)
        cases.append(summary(refused))
        OBSERVATIONS.append(dict(test=self.id(), status='PASS', reports=cases,
            source_path_never_written=True))

    def test_05_target_copy_reserve_and_jiritsu_budget_are_separate(self):
        target_units = aligned(self.profiles['usr']['plan']['target']['size'], 1024)
        cases = []
        for label, options in (
            ('resource_31_units_reserve', {'resource_free': target_units+31*1024}),
            ('workspace_below_8MiB', {'workspace_free': 8388608-512}),
        ):
            fixture = self.fixture(**options)
            refused = self.phase(fixture, 0, 1)
            self.assertFalse(refused['complete'])
            self.assertEqual(refused['native_status'], -28)
            self.assertIsNone(fixture.stage())
            self.assertEqual(fixture.remounts, [])
            cases.append(dict(guard=label, report=summary(refused)))
        OBSERVATIONS.append(dict(test=self.id(), status='PASS', cases=cases,
            exact_target_plus32_units_succeeds_in_test01=True))

    def test_06_positive_partial_append_then_EIO_is_UNKNOWN_and_not_replayable(self):
        fixture = self.fixture(partial_append=True)
        begun = self.begin(fixture)
        refused = self.phase(fixture, 2, 3, begun, chunk=self.profiles['usr']['target'][:512])
        self.assertFalse(refused['complete'])
        self.assertTrue(refused['operation_state_unknown'])
        self.assertFalse(refused['cleanup_safe'])
        self.assertEqual(bytes(fixture.stage().data), self.profiles['usr']['target'][:1])
        self.assertEqual(bytes(fixture.original.data), self.profiles['usr']['source'])
        self.assertFalse(fixture.renamed)
        with self.assertRaises(ValueError):
            self.module.request(fixture.plan, 2, b'Q'*16, refused, chunk=b'next')
        OBSERVATIONS.append(dict(test=self.id(), status='PASS', report=summary(refused),
            source_unchanged=True, stage_actual_partial_write=1,
            automatic_replay_and_healthy_STOP_not_authorized=True))

    def test_07_wrong_complete_stage_is_rejected_by_Mac_and_native_hash_before_rename(self):
        fixture = self.fixture()
        staged = self.staged(fixture, wrong_target=True)
        with self.assertRaises(ValueError):
            self.module.verify_stage(fixture.plan, bytes(fixture.stage().data))
        # An incorrectly supplied host assertion must still fail the native
        # complete stage hash. This does not grant a real device admission.
        false_receipt = self.module.verify_stage(fixture.plan, self.profiles['usr']['target'])
        refused = self.phase(fixture, 3, 30, staged, stage_readback=false_receipt)
        self.assertFalse(refused['complete'])
        self.assertEqual(refused['native_status'], -84)
        self.assertFalse(fixture.renamed)
        self.assertEqual(bytes(fixture.original.data), self.profiles['usr']['source'])
        OBSERVATIONS.append(dict(test=self.id(), status='PASS', report=summary(refused),
            dishonest_host_stage_assertion_does_not_bypass_native_full_hash=True))

    def test_08_rename_failure_or_postrename_dirsync_failure_is_UNKNOWN(self):
        cases = []
        for changed, options in ((False, {'rename_failure': True}),
                                 (True, {'post_rename_dirsync_failure': True})):
            with self.subTest(already_renamed=changed):
                fixture = self.fixture(**options)
                staged = self.staged(fixture)
                refused = self.phase(fixture, 3, 30, staged,
                    stage_readback=self.module.verify_stage(fixture.plan, bytes(fixture.stage().data)))
                self.assertFalse(refused['complete'])
                self.assertTrue(refused['operation_state_unknown'])
                self.assertFalse(refused['cleanup_safe'])
                self.assertEqual(fixture.renamed, changed)
                self.assertEqual(bytes(fixture.original.data), self.profiles['usr']['source'])
                expected = self.profiles['usr']['target' if changed else 'source']
                self.assertEqual(bytes(fixture.nodes[fixture.path].data), expected)
                cases.append(dict(rename_already_visible=changed, report=summary(refused)))
        OBSERVATIONS.append(dict(test=self.id(), status='PASS', cases=cases,
            automatic_inverse_retry_and_healthy_STOP_not_authorized=True))

    def test_09_explicit_abort_removes_only_exact_owned_partial_stage(self):
        fixture = self.fixture()
        begun = self.begin(fixture)
        partial = self.phase(fixture, 2, 3, begun, chunk=self.profiles['usr']['target'][:100])
        aborted = self.phase(fixture, 4, 4, partial,
            stage_readback=self.module.verify_abort_stage(fixture.plan, bytes(fixture.stage().data)))
        self.assertTrue(aborted['complete'])
        self.assertTrue(aborted['cleanup_safe'])
        self.assertIsNone(fixture.stage())
        self.assertEqual(bytes(fixture.original.data), self.profiles['usr']['source'])
        self.assertFalse(fixture.renamed)
        self.assertTrue(fixture.ro)
        OBSERVATIONS.append(dict(test=self.id(), status='PASS', report=summary(aborted),
            only_known_partial_stage_removed=True, source_unchanged=True))

    def test_10_known_RO_EBUSY_continues_only_bound_stage_then_commits_without_RO_claim(self):
        fixture = self.fixture(defer_usr_ro=True)
        staged = self.staged(fixture)
        self.assertTrue(staged['complete'])
        self.assertEqual(staged['native_status'], -16)
        self.assertEqual(staged['readonly'], -16)
        self.assertFalse(fixture.ro)
        committed = self.phase(fixture, 3, 30, staged,
            stage_readback=self.module.verify_stage(fixture.plan, bytes(fixture.stage().data)))
        self.assertTrue(committed['complete'])
        self.assertEqual(committed['native_status'], -16)
        self.assertEqual(committed['readonly'], -16)
        self.assertFalse(fixture.ro)
        self.assertTrue(fixture.renamed)
        self.assertEqual(bytes(fixture.nodes[fixture.path].data), self.profiles['usr']['target'])
        self.assertEqual(bytes(fixture.original.data), self.profiles['usr']['source'])
        OBSERVATIONS.append(dict(test=self.id(), status='PASS', staging=summary(staged),
            commit=summary(committed), same_plan_PID_source_stage_hash_chain=True,
            successful_file_commit_does_not_claim_usr_readonly=True))


def main():
    global OPTIONS
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler', required=True, help='Explicit offline Zig0.13.0 executable')
    parser.add_argument('--output', required=True, help='New real output directory')
    OPTIONS = parser.parse_args()
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(AtomicMechanismTests))
    paths = [ROOT/'native/original_atomic.c', ROOT/'native/original-sha256.h',
             ROOT/'worker.py', Path(__file__)]
    receipt = dict(schema='a7m4-original-atomic-synthetic-arm-tests/1',
        status='PASS' if result.wasSuccessful() else 'FAIL', tests_run=result.testsRun,
        failures=len(result.failures), errors=len(result.errors),
        source_sha256={str(p.resolve()): SHA(p.read_bytes()) for p in paths},
        device_io=False, network_io=False, private_firmware_inputs=False,
        simulation_not_hardware_evidence=True,
        compiler=str(Path(OPTIONS.compiler).resolve()), cases=OBSERVATIONS,
        limitations=[
            'Actual compiled ARM64 instructions; filesystem/syscall behavior is finite simulation.',
            'No claim to model all ext2/VFAT rename races, power failures, or kernel durability.',
            'Old inode mappings are synthetic inode-held views; no real camera kernel mapping executes.',
            'Host proof provenance, nonce history and full readback coordinator are product responsibilities.',
            'No device transport, vendor STOP, WBI or physical boot verification executes.',
        ])
    output = Path(OPTIONS.output)
    if output.exists():
        (output/'native-test-results.json').write_text(json.dumps(receipt, indent=2)+'\n')
    raise SystemExit(0 if result.wasSuccessful() else 1)


if __name__ == '__main__':
    main()
