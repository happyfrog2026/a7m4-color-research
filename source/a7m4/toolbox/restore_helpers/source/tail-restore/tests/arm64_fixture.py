# SPDX-License-Identifier: MIT
"""Finite ARM64 userspace fixtures; no device, firmware or transport access.

Only synthetic inputs belong here. Unicorn executes the compiled native
worker; a small syscall model records and checks its file/mapping effects.
It is not a model of every Linux/ext2 locking or power-failure behavior.
"""
from pathlib import Path
import struct

from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM
from unicorn.arm64_const import (
    UC_ARM64_REG_SP, UC_ARM64_REG_LR, UC_ARM64_REG_CPACR_EL1,
    UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
    UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X8,
)
from unicorn import UC_HOOK_INTR


def load_arm64(path):
    """Load only freestanding AArch64 ET_DYN with relative relocations."""
    cpu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    base, stop = 0x10000000, 0x70000000
    with Path(path).open('rb') as stream:
        elf = ELFFile(stream)
        assert elf.header['e_machine'] == 'EM_AARCH64'
        assert elf.header['e_type'] == 'ET_DYN'
        segments = [s for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD']
        length = max(s['p_vaddr'] + s['p_memsz'] for s in segments)
        cpu.mem_map(base, (length + 4095) & ~4095)
        for segment in segments:
            cpu.mem_write(base + segment['p_vaddr'], segment.data())
        for section in elf.iter_sections():
            if section['sh_type'] == 'SHT_RELA':
                for relocation in section.iter_relocations():
                    assert relocation['r_info_type'] == 1027
                    assert not relocation['r_info_sym']
                    cpu.mem_write(
                        base + relocation['r_offset'],
                        struct.pack('<Q', base + relocation['r_addend']),
                    )
        dynamic = elf.get_section_by_name('.dynamic')
        assert dynamic is not None
        assert not any(t.entry.d_tag == 'DT_NEEDED' for t in dynamic.iter_tags())
        init = next(t.entry.d_val for t in dynamic.iter_tags()
                    if t.entry.d_tag == 'DT_INIT')
    cpu.mem_map(0x60000000, 0x100000)
    cpu.mem_map(stop, 4096)
    cpu.reg_write(UC_ARM64_REG_SP, 0x600F0000)
    cpu.reg_write(UC_ARM64_REG_LR, stop)
    cpu.reg_write(UC_ARM64_REG_CPACR_EL1, 0x300000)
    return cpu, base + init, stop


def align_up(value, unit=4096):
    return (value + unit - 1) // unit * unit


def proc_dirent(name):
    """Linux getdents64 record, including its actual 19-byte name offset."""
    raw = str(name).encode() + b'\0'
    size = (19 + len(raw) + 7) & ~7
    return (struct.pack('<QqHB', 21, 0, size, 4) + raw
            + bytes(size - 19 - len(raw)))


STAT = struct.Struct('<QQ4I2QqII8Q')
FS = struct.Struct('<qq5Q2I7q')


class NativeFixture:
    """Synthetic file, mappings and proc entries for one native constructor.

    The source has deliberately non-camera dev/inode/owner values. It cannot
    stand in for any retained camera observation or deployment admission.
    """
    PID, DEV, INO, UID, GID = 498, 0x1234, 424242, 1000, 1001
    FILE_VA, SPLIT_VA = 0x40000000, 0x42000000

    def __init__(self, *, module, plan, artifact, source, target,
                 mapping='whole', permissions=1, private=True,
                 empty_processes=0, foreign_mapping=False, remap_failure=False):
        self.module, self.plan, self.artifact = module, plan, artifact
        self.path = plan['resource_path']
        self.data, self.target = bytearray(source), target
        self.mapping, self.permissions, self.private = mapping, permissions, private
        self.empty_processes = empty_processes
        self.foreign_mapping, self.remap_failure = foreign_mapping, remap_failure
        self.shadow_begin, self.shadow_end = plan['shadow_begin'], plan['shadow_end']
        self.events, self.remounts, self.truncates = [], [], []
        self.attempts = 0
        self.last_live_shadows = []

    def run(self, request, parse):
        """Execute real compiled ARM64 instructions with bounded fake syscalls."""
        cpu, start, stop = load_arm64(self.artifact['path'])
        mod, source_path = self.module, self.path
        library, request_path, result_path = (
            mod.LIBRARY_PATH, mod.REQUEST_PATH, mod.RESULT_PATH,
        )
        major = ((self.DEV >> 8) & 0xFFF) | ((self.DEV >> 32) & ~0xFFF)
        minor = (self.DEV & 0xFF) | ((self.DEV >> 12) & ~0xFF)
        device = f'{major:x}:{minor:x}'
        vm = [dict(va=0x10000000, end=0x10001000, off=0, dev='56:78',
                   ino=33, prot=5, priv=True, path=library)]
        shadow_ranges = []

        def source_map(va, offset, length):
            assert not (va | offset | length) & 4095
            cpu.mem_map(va, length)
            data = bytes(self.data[offset:offset+length])
            cpu.mem_write(va, data + bytes(length-len(data)))
            cpu.mem_protect(va, length, self.permissions)
            vm.append(dict(va=va, end=va+length, off=offset, dev=device,
                           ino=self.INO, prot=self.permissions, priv=self.private,
                           path=source_path))
            lo, hi = max(offset, self.shadow_begin), min(offset+length, self.shadow_end)
            if lo < hi:
                shadow_ranges.append((va+lo-offset, hi-lo, lo))

        if self.mapping == 'whole':
            source_map(self.FILE_VA, 0, align_up(len(self.data)))
        elif self.mapping == 'split':
            split = self.shadow_begin + 4096
            assert split < self.shadow_end
            source_map(self.FILE_VA, 0, split)
            source_map(self.SPLIT_VA, split, self.shadow_end-split)
        else:
            assert self.mapping == 'none'
        files = {request_path: bytearray(request), library: bytearray(b'fixture-only')}
        fdtable, nextfd, plugin_links = {}, 10, 1
        scratch_next, ro = 0x50000000, True
        process_names = [str(10000+i) for i in range(self.empty_processes)]
        process_names += ['601', '2']
        directory_names = ['.', '..', 'self', str(self.PID), *process_names]

        def maps():
            out = []
            for row in sorted(vm, key=lambda item: item['va']):
                prot = row['prot']
                permission = (('r' if prot & 1 else '-')
                              + ('w' if prot & 2 else '-')
                              + ('x' if prot & 4 else '-')
                              + ('p' if row['priv'] else 's'))
                out.append(f"{row['va']:x}-{row['end']:x} {permission} "
                           f"{row['off']:08x} {row['dev']} {row['ino']} {row['path']}\n")
            return ''.join(out).encode()

        def contents(path):
            if path == '/proc/self/maps':
                return maps()
            if path == '/proc/self/auxv':
                return struct.pack('<4Q', 6, 4096, 0, 0)
            if path == '/proc/self/mounts':
                return b'/dev/synthetic-usr /usr ext2 ' + (b'ro' if ro else b'rw') + b',sync 0 0\n'
            if path.startswith('/proc/') and path.endswith('/maps'):
                if path == '/proc/601/maps' and self.foreign_mapping:
                    return (f'30000000-{0x30000000+self.shadow_end:x} r--p '
                            f'00000000 {device} {self.INO} {source_path}\n').encode()
                assert path.split('/')[2] in process_names
                return b''
            if path == source_path:
                return bytes(self.data)
            return bytes(files[path])

        def cstring(pointer):
            out = bytearray()
            while len(out) < 1024:
                byte = bytes(cpu.mem_read(pointer+len(out), 1))
                if byte == b'\0':
                    return out.decode()
                out.extend(byte)
            raise AssertionError('Unbounded path')

        def packed_stat(path):
            if path == source_path:
                return STAT.pack(self.DEV, self.INO, 0o100644, 1,
                                 self.UID, self.GID, 0, 0, len(self.data),
                                 1024, 0, (len(self.data)+511)//512,
                                 1, 2, 3, 4, 5, 6, 0)
            assert path == library
            return STAT.pack(0x5678, 33, 0o100644, plugin_links, 0, 0,
                             0, 0, 12, 512, 0, 1, 1, 2, 3, 4, 5, 6, 0)

        def split_remove(va, length):
            updated, end = [], va+length
            for row in vm:
                if row['va'] >= end or row['end'] <= va:
                    updated.append(row)
                    continue
                if row['va'] < va:
                    updated.append(dict(row, end=va))
                if row['end'] > end:
                    updated.append(dict(row, va=end, off=row['off']+end-row['va']))
            vm[:] = updated

        def hook(_cpu, _interrupt, _data):
            nonlocal nextfd, plugin_links, scratch_next, ro
            syscall = cpu.reg_read(UC_ARM64_REG_X8)
            args = [cpu.reg_read(reg) for reg in (
                UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
                UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_X5,
            )]
            value = 0
            if syscall == 56:
                path, flags = cstring(args[1]), args[2]
                allowed = (source_path, library, request_path, result_path,
                           '/proc', '/proc/self/maps', '/proc/self/auxv', '/proc/self/mounts')
                assert path in allowed or (path.startswith('/proc/')
                                          and path.endswith('/maps')
                                          and path.split('/')[2] in process_names), path
                if flags & 64:
                    assert path == result_path and flags & 128 and path not in files
                    files[path] = bytearray()
                if path == source_path and flags & 3:
                    assert not ro
                nextfd += 1
                fdtable[nextfd] = dict(path=path, flags=flags, at=0)
                value = nextfd
                self.events.append(('open', path, flags))
            elif syscall == 57:
                row = fdtable.pop(args[0])
                self.events.append(('close', row['path'], row['flags']))
            elif syscall in (63, 67):
                row = fdtable[args[0]]
                if row['flags'] & 3 == 1:
                    value = -9
                else:
                    offset = args[3] if syscall == 67 else row['at']
                    raw = contents(row['path'])[offset:offset+args[2]]
                    if raw:
                        cpu.mem_write(args[1], raw)
                    value = len(raw)
                    if syscall == 63:
                        row['at'] += value
            elif syscall == 80:
                cpu.mem_write(args[1], packed_stat(fdtable[args[0]]['path']))
            elif syscall == 79:
                assert cstring(args[1]) == source_path and args[3] == 0x100
                cpu.mem_write(args[2], packed_stat(source_path))
            elif syscall == 35:
                assert cstring(args[1]) == library and plugin_links == 1
                plugin_links = 0
                files.pop(library)
                self.events.append(('unlink-own-plugin', library))
            elif syscall == 43:
                assert cstring(args[0]) == '/tmp/jiritsu'
                cpu.mem_write(args[1], FS.pack(
                    0x4D44, 512, 48000, 45000, 45000, 0, 0,
                    1, 2, 255, 512, 0, 0, 0, 0, 0,
                ))
            elif syscall == 61:
                row = fdtable[args[0]]
                assert row['path'] == '/proc'
                chunks, total, pos = [], 0, row['at']
                while pos < len(directory_names):
                    raw = proc_dirent(directory_names[pos])
                    if total+len(raw) > args[2]:
                        break
                    chunks.append(raw)
                    total += len(raw)
                    pos += 1
                if chunks:
                    cpu.mem_write(args[1], b''.join(chunks))
                row['at'] = pos
                value = total
            elif syscall == 222:
                assert (args[0] == 0 and 0 < args[1] <= 49152
                        and args[2:4] == [3, 0x22]
                        and args[4] == (1 << 64)-1 and args[5] == 0)
                va = scratch_next
                scratch_next += 0x10000
                cpu.mem_map(va, args[1])
                vm.append(dict(va=va, end=va+args[1], off=0, dev='00:00',
                               ino=0, prot=3, priv=True, path=''))
                self.events.append(('anonymous', va, args[1]))
                value = va
            elif syscall == 226:
                assert args[2] == 1
                row = next(row for row in vm if row['va'] == args[0]
                           and row['end']-row['va'] == args[1])
                row['prot'] = 1
                cpu.mem_protect(args[0], args[1], 1)
                self.events.append(('protect-readonly', args[0], args[1]))
            elif syscall == 216:
                self.attempts += 1
                assert args[1] == args[2] and args[3] == 3
                expected = next((row for row in shadow_ranges
                                 if row[0] == args[4] and row[1] == args[1]), None)
                assert expected is not None
                old = next(row for row in vm if row['va'] == args[0])
                assert old['prot'] == 1 and old['ino'] == 0
                data = bytes(cpu.mem_read(args[0], args[1]))
                expected_data = bytes(self.data[expected[2]:expected[2]+args[1]])
                expected_data += bytes(args[1]-len(expected_data))
                assert data == expected_data
                cpu.mem_unmap(args[4], args[1])
                split_remove(args[4], args[1])
                self.events.append(('fixed-remap-attempt', args[0], args[4], args[1]))
                if self.remap_failure:
                    value = -12  # Target has actually been removed in this model.
                else:
                    cpu.mem_map(args[4], args[1], 1)
                    cpu.mem_write(args[4], data)
                    cpu.mem_unmap(args[0], args[1])
                    vm.remove(old)
                    vm.append(dict(old, va=args[4], end=args[4]+args[1]))
                    value = args[4]
            elif syscall == 215:
                assert not self.attempts
                cpu.mem_unmap(args[0], args[1])
                split_remove(args[0], args[1])
            elif syscall == 40:
                assert cstring(args[1]) == '/usr' and args[3] in (0xC30, 0xC31)
                if args[3] == 0xC31:
                    assert not any(row['path'] == source_path and row['flags'] & 3
                                   for row in fdtable.values()), 'Writable FD open at RO remount'
                ro = args[3] == 0xC31
                self.remounts.append(ro)
            elif syscall == 46:
                row = fdtable[args[0]]
                if row['flags'] & 3 == 0:
                    value = -9
                else:
                    assert row['path'] == source_path and not ro
                    assert args[1] == len(self.target)
                    assert not any(
                        row['ino'] == self.INO and row['dev'] == device
                        and row['off'] < self.shadow_end
                        and row['off']+row['end']-row['va'] > self.shadow_begin
                        for row in vm
                    ), 'Truncate while current inode still maps a removed/partial EOF page'
                    assert not self.remap_failure
                    for va, length, offset in shadow_ranges:
                        expected = bytes(self.data[offset:offset+length])
                        expected += bytes(length-len(expected))
                        assert bytes(cpu.mem_read(va, length)) == expected
                    del self.data[args[1]:]
                    self.truncates.append(args[1])
            elif syscall == 64:
                row = fdtable[args[0]]
                assert row['path'] == result_path and row['flags'] & 3 == 1
                data = bytes(cpu.mem_read(args[1], args[2]))
                files[result_path].extend(data)
                value = len(data)
            elif syscall == 82:
                assert fdtable[args[0]]['path'] in (result_path, source_path)
            elif syscall == 172:
                value = self.PID
            elif syscall == 175:
                value = 0
            else:
                raise AssertionError(('Unexpected native syscall', syscall, args))
            cpu.reg_write(UC_ARM64_REG_X0, value & ((1 << 64)-1))

        cpu.hook_add(UC_HOOK_INTR, hook)
        cpu.emu_start(start, stop, count=70000000)
        assert not fdtable
        assert library not in files
        self.last_live_shadows = []
        if not self.remap_failure:
            self.last_live_shadows = [bytes(cpu.mem_read(va, length))
                                      for va, length, _ in shadow_ranges]
        return parse(bytes(files[result_path])), bytes(files[result_path])
