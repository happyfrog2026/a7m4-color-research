# SPDX-License-Identifier: MIT
"""Synthetic ARM64 syscall model, adapted from tail-restore/tests fixture.

No firmware or camera inputs. Every syscall is allowlisted; mount checks the
complete null/null/0xc31/null argument tuple and that every input fd is closed.
"""
from pathlib import Path
import struct

from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_INTR
from unicorn.arm64_const import (
    UC_ARM64_REG_SP, UC_ARM64_REG_LR, UC_ARM64_REG_CPACR_EL1,
    UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
    UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X8, UC_ARM64_REG_PC,
)

STAT = struct.Struct('<QQ4I2QqII8Q')
FS = struct.Struct('<qq5Q2I7q')


def load_arm64(path):
    cpu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    base, stop = 0x10000000, 0x70000000
    with Path(path).open('rb') as stream:
        elf = ELFFile(stream)
        assert elf.header['e_machine'] == 'EM_AARCH64' and elf.header['e_type'] == 'ET_DYN'
        segments = [s for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD']
        extent = max(s['p_vaddr'] + s['p_memsz'] for s in segments)
        cpu.mem_map(base, (extent + 4095) & ~4095)
        for segment in segments:
            cpu.mem_write(base + segment['p_vaddr'], segment.data())
        for section in elf.iter_sections():
            if section['sh_type'] == 'SHT_RELA':
                for rel in section.iter_relocations():
                    assert rel['r_info_type'] == 1027 and not rel['r_info_sym']
                    cpu.mem_write(base + rel['r_offset'], struct.pack('<Q', base + rel['r_addend']))
        dynamic = elf.get_section_by_name('.dynamic')
        assert not any(tag.entry.d_tag == 'DT_NEEDED' for tag in dynamic.iter_tags())
        init = next(tag.entry.d_val for tag in dynamic.iter_tags() if tag.entry.d_tag == 'DT_INIT')
    cpu.mem_map(0x60000000, 0x100000)
    cpu.mem_map(stop, 4096)
    cpu.reg_write(UC_ARM64_REG_SP, 0x600F0000)
    cpu.reg_write(UC_ARM64_REG_LR, stop)
    cpu.reg_write(UC_ARM64_REG_CPACR_EL1, 0x300000)
    return cpu, base + init, stop, base, extent


class Fixture:
    def __init__(self, module, artifact, *, ro=False, mounts=None, mount_error=0,
                 close_fail=None, proc_magic=0x9fa0, free_bytes=16*1024*1024,
                 euid=0, loader_match=True, report_write_error=False,
                 maps_transform=None, read_chunk=None, instruction_limit=10000000):
        self.mod, self.artifact = module, artifact
        self.ro, self.mounts, self.mount_error = ro, mounts, mount_error
        self.close_fail, self.proc_magic, self.free_bytes = close_fail, proc_magic, free_bytes
        self.euid, self.loader_match, self.report_write_error = euid, loader_match, report_write_error
        self.events, self.remounts, self.final_fds = [], [], None
        self.maps_transform,self.read_chunk,self.instruction_limit=maps_transform,read_chunk,instruction_limit
        self.maps_read_bytes,self.maps_read_calls,self.maps_eof_seen=0,0,False
        self.maps_data=None

    def run(self, packet):
        cpu, start, stop, base, extent = load_arm64(self.artifact['path'])
        m = self.mod
        files = {m.REQUEST_PATH: bytearray(packet), m.LIBRARY_PATH: bytearray(b'SYNTHETIC_LOADER')}
        fds, nextfd, links = {}, 10, 1

        def cstring(va):
            raw = bytearray()
            while True:
                value = cpu.mem_read(va + len(raw), 1)[0]
                if not value:
                    return raw.decode()
                raw.append(value)
                assert len(raw) < 200

        def stat_bytes(path):
            if path == '/tmp/jiritsu':
                mode, ino, nlink, size, dev = 0o40700, 202, 2, 0, 0x45
            else:
                assert path == m.LIBRARY_PATH
                mode, ino, nlink, size, dev = 0o100600, 771, links, Path(self.artifact['path']).stat().st_size, 0x1234
            return STAT.pack(dev, ino, mode, nlink, 0, 0, 0, 0, size, 4096, 0, *([0]*8))

        def contents(path):
            if path == '/proc/self/maps':
                ino = 771 if self.loader_match else 772
                if self.maps_data is None:
                    line=(f'{base:x}-{base+extent:x} r-xp 00000000 12:34 {ino} {m.LIBRARY_PATH}\n').encode()
                    self.maps_data=self.maps_transform(line) if self.maps_transform else line
                return self.maps_data
            if path == '/proc/self/mounts':
                if self.mounts is not None:
                    return self.mounts
                return b'rootfs / rootfs rw 0 0\n/dev/nflasha15 /usr ext2 ' + (b'ro' if self.ro else b'rw') + b',noatime,nodiratime 0 0\n'
            return bytes(files[path])

        def hook(cpu, interrupt, user):
            nonlocal nextfd, links
            regs = (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
                    UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_X5)
            args = [cpu.reg_read(reg) for reg in regs]
            syscall = cpu.reg_read(UC_ARM64_REG_X8)
            value = 0
            if syscall == 56:
                path = cstring(args[1]); flags = args[2]
                assert args[0] == (1 << 64)-100 and args[3] == 0o600
                if path == m.PENDING_PATH:
                    assert flags == 0x88000 | 1 | 64 | 128
                    if path in files:
                        value = -17
                    else:
                        files[path] = bytearray()
                elif path == '/tmp/jiritsu':
                    assert flags == 0x88000 | 0x4000
                else:
                    assert path in (m.REQUEST_PATH, m.LIBRARY_PATH, '/proc/self/maps', '/proc/self/mounts')
                    assert flags == 0x88000
                if value == 0:
                    value = nextfd; nextfd += 1
                    fds[value] = dict(path=path, flags=flags, at=0)
                self.events.append(('open', path, flags))
            elif syscall == 63:
                row = fds[args[0]]; data = contents(row['path'])
                assert row['flags'] == 0x88000
                count=min(args[2],self.read_chunk) if row['path']=='/proc/self/maps' and self.read_chunk else args[2]
                raw = data[row['at']:row['at'] + count]
                if row['path']=='/proc/self/maps':
                    self.maps_read_bytes+=len(raw);self.maps_read_calls+=1
                    if not raw:self.maps_eof_seen=True
                if raw:
                    cpu.mem_write(args[1], raw)
                row['at'] += len(raw); value = len(raw)
            elif syscall == 57:
                row = fds.pop(args[0])
                if row['path'] == self.close_fail:
                    value = -5
                self.events.append(('close', row['path'], value))
            elif syscall == 44:
                path = fds[args[0]]['path']
                if path.startswith('/proc/'):
                    kind, free = self.proc_magic, 0
                else:
                    assert path == '/tmp/jiritsu'
                    kind, free = 0x4d44, self.free_bytes // 4096
                cpu.mem_write(args[1], FS.pack(kind, 4096, 10000, free, free, 0, 0, 0, 0,
                                               255, 4096, 0, 0, 0, 0, 0))
            elif syscall == 80:
                cpu.mem_write(args[1], stat_bytes(fds[args[0]]['path']))
            elif syscall == 35:
                assert args[0] == (1 << 64)-100 and cstring(args[1]) == m.LIBRARY_PATH and args[2] == 0
                assert links == 1
                links = 0; del files[m.LIBRARY_PATH]
                self.events.append(('loader-unlink',))
            elif syscall == 40:
                assert args[0] == 0 and cstring(args[1]) == '/usr'
                assert args[2:] == [0, 0xc31, 0, 0], 'Native requested anything other than RO-only remount'
                assert not fds, 'Input fd still open at remount'
                assert not self.remounts, 'Native attempted automatic retry'
                self.remounts.append(0xc31); self.events.append(('remount-ro',))
                value = self.mount_error
                if value == 0:
                    self.ro = True
            elif syscall == 64:
                row = fds[args[0]]
                assert row['path'] == m.PENDING_PATH
                if self.report_write_error:
                    value = -5
                else:
                    raw = bytes(cpu.mem_read(args[1], args[2])); files[m.PENDING_PATH].extend(raw)
                    value = len(raw)
            elif syscall == 82:
                assert fds[args[0]]['path'] == m.PENDING_PATH
            elif syscall == 79:
                assert args[0] == (1 << 64)-100 and cstring(args[1]) == m.RESULT_PATH and args[3] == 0x100
                value = -2 if m.RESULT_PATH not in files else 0
            elif syscall == 38:
                assert args[0] == args[2] == (1 << 64)-100
                assert cstring(args[1]) == m.PENDING_PATH and cstring(args[3]) == m.RESULT_PATH
                assert m.RESULT_PATH not in files and not fds
                files[m.RESULT_PATH] = files.pop(m.PENDING_PATH)
                self.events.append(('publish-after-close',))
            elif syscall == 175:
                value = self.euid
            elif syscall == 172:
                value = 4001
            else:
                raise AssertionError(('Unexpected syscall', syscall, args))
            cpu.reg_write(UC_ARM64_REG_X0, value & ((1 << 64)-1))

        cpu.hook_add(UC_HOOK_INTR, hook)
        cpu.emu_start(start, stop, count=self.instruction_limit)
        assert cpu.reg_read(UC_ARM64_REG_PC)==stop, "Finite ARM instruction budget exhausted"
        assert not fds
        self.final_fds = len(fds)
        return bytes(files[m.RESULT_PATH]) if m.RESULT_PATH in files else None
