"""Offline ABI and build checks for the fixed read-only R009a inventory."""
import json
from pathlib import Path
import re
import struct
import subprocess

from hashlib import sha256

def digest(raw): return sha256(raw).hexdigest()
def require(ok, code, message):
    if not ok: raise ValueError(code + ": " + message)

SOURCE = Path(__file__).with_name("data") / "original-runtime-prereq.c"
SOURCE_SHA256='21f86689c3dc33660d4b879b4c99d696a210c2def58b83f86208f084af33e2e0'
REQUEST = struct.Struct("<8s16s")
HEADER = struct.Struct("<8sIIII16sIIIIIIqq")
SECTION = struct.Struct("<IIq")
STAT = struct.Struct("<QQIIIIQq")
FS = struct.Struct("<qqQQQQQqqq")
DIR = struct.Struct(STAT.format + FS.format[1:])
MAGIC = b"M4SSH002"
REQUEST_MAGIC = b"M4SREQ02"
VERSION = b"30181_18.2026041801"
MAX_WORKER = 65536
FREE_MARGIN = 8 * 1024 * 1024
REPORT_RESERVE = 128 * 1024
TMPFS_MAGIC = 0x01021994
VFAT_MAGIC = 0x4d44
LOADERS = {"3b19665f84bcd1b837a3b9377b40a91893010ff9732be71a430f3d0265c72c69": "6.02"}
BINARY_INPUTS = {
    "/usr/sbin/sshd": dict(bytes=767408, sha256="a6b871ef0da3990ea0d25d7996ee79c3bfc29385d4eb1670892814c0e1472534", local_name="sshd.private.elf"),
    "/usr/bin/ssh-keygen": dict(bytes=416976, sha256="c3aaf1e24721fa78308c7daadca29de29e6d3c384e632754422f155054373fa9", local_name="ssh-keygen.private.elf"),
}
SECTIONS = {
    1: ("/version.txt", 64), 2: ("getgroups", 256),
    3: ("/proc/self/status", 8192), 4: ("/proc/self/mountinfo", 16384),
    5: ("/proc/self/mounts", 16384), 6: ("/proc/self/net/dev", 4096),
    7: ("/proc/self/net/route", 4096), 8: ("/proc/self/net/if_inet6", 2048),
    9: ("/proc/self/net/wireless", 2048), 10: ("readlink:/proc/self/root", 512),
    11: ("readlink:/proc/self/ns/mnt", 128), 12: ("readlink:/proc/self/ns/net", 128),
    13: ("readlink:/proc/self/ns/user", 128), 14: ("readlink:/proc/self/ns/pid", 128),
    15: ("directory:/tmp/jiritsu", 128), 16: ("directory:/tmp_wbshd", 128),
    17: ("directory:/tmp_network", 128), 18: ("/etc/passwd", 8192),
    19: ("/etc/nsswitch.conf", 2048), 20: ("/etc/ssh/sshd_config", 8192),
    21: ("readlink:/etc/passwd", 512), 22: ("readlink:/etc/nsswitch.conf", 512),
    23: ("readlink:/etc/ssh/sshd_config", 512), 24: ("lstat:/usr/sbin/sshd", 48),
    25: ("lstat:/usr/bin/ssh-keygen", 48), 26: ("lstat:/lib/ld-linux-aarch64.so.1", 48),
    27: ("readlink:/usr/sbin/sshd", 512), 28: ("readlink:/usr/bin/ssh-keygen", 512),
    29: ("readlink:/lib/ld-linux-aarch64.so.1", 512), 30: ("/proc/self/limits", 4096),
    31: ("/etc/ld.so.preload", 1024), 32: ("readlink:/etc/ld.so.preload", 512),
    33: ("lstat:/etc/shadow", 48), 34: ("/proc/self/net/fib_trie", 8192),
    35: ("directory:/var", 128), 36: ("directory:/etc", 128),
    37: ("directory:/dev/pts", 128), 38: ("directory:/tmp", 128),
    39: ("input_diagnostics", 2432),
}
MAX_REPORT = HEADER.size + sum(SECTION.size + cap for _, cap in SECTIONS.values())
DIR_SLOTS = frozenset((15, 16, 17, 35, 36, 37, 38))
STAT_SLOTS = frozenset((24, 25, 26, 33))
OPTIONAL_ENOENT = frozenset((*range(6, 10), 13, 17, 31, 32, 33, 34))
OPTIONAL_NAMESPACE_LSTAT_ENOENT = frozenset((12, 14))
OPTIONAL_EINVAL = frozenset((21, 22, 23, 27, 28, 29, 32))
CONFIG_LINKS = {18: 21, 19: 22, 20: 23, 31: 32}
DIAGNOSTIC_HEADER = struct.Struct("<IIq")
DIAGNOSTIC_STAGES = {
    0: "NONE", 1: "LSTAT", 2: "TYPE", 3: "OWNER", 4: "OPEN",
    5: "FSTAT", 6: "IDENTITY", 7: "FSTATFS", 8: "READ", 9: "CLOSE",
    10: "READLINK", 11: "GROUPS", 12: "COMPLETE", 13: "BOUNDS", 14: "FS_KIND",
}
LINK_SLOTS = frozenset((10, 11, 12, 13, 14, 21, 22, 23, 27, 28, 29, 32))
PROC_SLOTS = frozenset((3, 4, 5, 6, 7, 8, 9, 30, 34))
FILE_SLOTS = frozenset((1, 18, 19, 20, 31)) | PROC_SLOTS
ROOT_ONLY_SLOTS = PROC_SLOTS | frozenset((10, 11, 12, 13, 14, 15))


def _input_diagnostics(by_slot):
    row = by_slot[39]
    require(row["status"] == 0 and len(row["data"]) == 38 * 64,
            "REPORT", "Missing fixed input diagnostics")
    observations = []
    for slot in range(1, 39):
        offset = (slot - 1) * 64
        stage, available, status = DIAGNOSTIC_HEADER.unpack_from(row["data"], offset)
        raw_stat = row["data"][offset + 16:offset + 64]
        require(stage in DIAGNOSTIC_STAGES and available in (0, 1)
                and status == by_slot[slot]["status"],
                "REPORT", "Input diagnostic framing or terminal status differs")
        require(available == 1 or raw_stat == bytes(STAT.size),
                "REPORT", "Unavailable metadata contains reserved bytes")
        meta = _stat(raw_stat) if available else None
        if stage == 0:
            require(status == -125 and not available,
                    "REPORT", "Unvisited observation contains evidence")
        elif status == 0:
            require(stage == 12 and bool(available) == (slot != 2),
                    "REPORT", "Successful observation lacks completed metadata")
        else:
            require(stage != 12, "REPORT", "Failed observation claims completion")
            if slot == 2:
                require(stage in (11, 13) and not available,
                        "REPORT", "Group failure has filesystem evidence")
            else:
                require(stage != 11 and (available or stage == 1),
                        "REPORT", "Filesystem failure lacks prior metadata")
                require(stage != 1 or not available or slot in LINK_SLOTS,
                        "REPORT", "Initial lstat failure claims prior metadata")
                if slot in LINK_SLOTS:
                    require(stage in (1, 2, 3, 6, 10, 13),
                            "REPORT", "Readlink diagnostic contains file IO stage")
                elif slot in DIR_SLOTS:
                    require(stage in (1, 2, 3, 4, 5, 6, 7, 9),
                            "REPORT", "Directory diagnostic contains another operation")
                elif slot in STAT_SLOTS:
                    require(stage in (1, 3), "REPORT", "Metadata-only observation performed file IO")
                else:
                    require(stage in (1, 2, 3, 4, 5, 6, 7, 8, 9, 13, 14),
                            "REPORT", "Regular input diagnostic contains another operation")
        if meta:
            owner = (meta["uid"], meta["gid"])
            owners = {(0, 0)} if slot in ROOT_ONLY_SLOTS else {(0, 0), (57285, 1000)}
            if status == 0:
                require(owner in owners, "REPORT", "Successful input has unadmitted owner")
            if stage == 3:
                require(status == -13 and owner not in owners,
                        "REPORT", "Owner rejection contradicts observed owner")
            if status == 0 and slot in DIR_SLOTS | STAT_SLOTS:
                observed = _stat(by_slot[slot]["data"][:STAT.size])
                require(all(meta[key] == observed[key]
                            for key in ("dev", "ino", "mode", "nlink", "uid", "gid", "rdev")),
                        "REPORT", "Returned metadata differs from initial identity")
        observations.append(dict(slot=slot, path=SECTIONS[slot][0], stage=stage,
                                 stage_name=DIAGNOSTIC_STAGES[stage], status=status,
                                 metadata_available=bool(available), before_stat=meta))
    return observations


def request(nonce):
    require(isinstance(nonce, bytes) and len(nonce) == 16 and any(nonce),
            "NONCE", "Use a fresh nonzero 16-byte SSH prerequisite nonce")
    return REQUEST.pack(REQUEST_MAGIC, nonce)


def _admitted(slot, row, by_slot):
    status = row["status"]
    if status == -2 and slot in OPTIONAL_NAMESPACE_LSTAT_ENOENT:
        diagnostics = by_slot[39]["data"]
        if len(diagnostics) != 38 * 64:
            return False
        # A missing unused proc entry is acceptable; disappearance after a
        # successful lstat, or an error from another operation, remains unsafe.
        return DIAGNOSTIC_HEADER.unpack_from(diagnostics, (slot - 1) * 64) == (1, 0, -2)
    return (status == 0 or (status == -2 and slot in OPTIONAL_ENOENT)
            or (status == -22 and slot in OPTIONAL_EINVAL)
            or (status == -40 and slot in CONFIG_LINKS and by_slot[CONFIG_LINKS[slot]]["status"] == 0))


def _stat(data):
    require(len(data) == STAT.size, "REPORT", "Incorrect fixed stat metadata length")
    fields = dict(zip(("dev", "ino", "mode", "nlink", "uid", "gid", "rdev", "size"), STAT.unpack(data)))
    require(fields["ino"] > 0 and fields["nlink"] > 0 and fields["size"] >= 0,
            "REPORT", "Invalid observed inode metadata")
    return fields


def _directory(data):
    require(len(data) == STAT.size + FS.size, "REPORT", "Incorrect directory metadata length")
    fields = _stat(data[:STAT.size])
    require(fields["mode"] & 0o170000 == 0o040000, "REPORT", "Directory observation has another file type")
    fields.update(zip(("fs_type", "block_size", "blocks", "bfree", "bavail", "files", "ffree",
                       "name_length", "fragment_size", "fs_flags"), FS.unpack(data[STAT.size:])))
    require(fields["block_size"] > 0 and fields["fragment_size"] > 0
            and fields["bavail"] <= fields["bfree"] <= fields["blocks"]
            and fields["blocks"] * fields["fragment_size"] <= 2**64 - 1,
            "REPORT", "Invalid filesystem accounting")
    fields["available_bytes"] = fields["bavail"] * fields["fragment_size"]
    fields["total_bytes"] = fields["blocks"] * fields["fragment_size"]
    return fields


def _status_fields(data):
    try:
        rows = dict(line.split(":", 1) for line in data.decode("ascii").splitlines() if ":" in line)
        cap = int(rows["CapEff"].strip(), 16) if "CapEff" in rows else None
        return dict(cap_sys_admin=None if cap is None else bool(cap & (1 << 21)),
                    cap_sys_chroot=None if cap is None else bool(cap & (1 << 18)),
                    no_new_privs=int(rows["NoNewPrivs"].strip()) if "NoNewPrivs" in rows else None,
                    seccomp=int(rows["Seccomp"].strip()) if "Seccomp" in rows else None,
                    umask_observed="Umask" in rows)
    except (UnicodeError, ValueError):
        return dict(cap_sys_admin=None, cap_sys_chroot=None, no_new_privs=None, seccomp=None, umask_observed=False)


def _root_account(data):
    try:
        rows = [line.split(":") for line in data.decode("ascii").splitlines() if line and not line.startswith("#")]
        if not all(len(r) == 7 and r[0] and r[2].isdecimal() and r[3].isdecimal()
                   and all("\0" not in field for field in r) for r in rows):
            return dict(unique_root_uid_gid_zero=False, root_shell=None)
        matches = [r for r in rows if r[0] == "root" or int(r[2]) == 0]
        okay = (len(matches) == 1 and matches[0][0] == "root"
                and int(matches[0][2]) == int(matches[0][3]) == 0)
        return dict(unique_root_uid_gid_zero=okay, root_shell=matches[0][6] if okay else None)
    except UnicodeError:
        return dict(unique_root_uid_gid_zero=False, root_shell=None)


def parse_report(raw, nonce):
    request(nonce)
    require(isinstance(raw, bytes) and HEADER.size <= len(raw) <= MAX_REPORT,
            "REPORT", "SSH prerequisite report is missing, short or oversized")
    magic, revision, size, total, count, observed, uid, euid, gid, egid, pid, flags, unlink, req = HEADER.unpack_from(raw)
    require((magic, revision, size, total, count) == (MAGIC, 2, HEADER.size, len(raw), len(SECTIONS)),
            "REPORT", "Unsupported or inconsistent SSH prerequisite header")
    require(observed == nonce, "NONCE", "SSH prerequisite report belongs to another run")
    require(pid > 0 and flags & ~63 == 0 and -4095 <= req <= 0 and -4095 <= unlink <= 0,
            "REPORT", "Invalid SSH prerequisite process, flags or status")
    require(bool(flags & 1) == (req == 0) and bool(flags & 4) == (unlink in (0, -2)),
            "REPORT", "SSH prerequisite flags disagree with request/unlink")
    offset, sections = HEADER.size, []
    for expected, (path, cap) in SECTIONS.items():
        require(offset + SECTION.size <= len(raw), "REPORT", "Truncated SSH prerequisite section")
        slot, length, status = SECTION.unpack_from(raw, offset)
        offset += SECTION.size
        require(slot == expected and length <= cap and -4095 <= status <= 0
                and (status == 0 or length == 0) and offset + length <= len(raw),
                "REPORT", "Invalid SSH prerequisite section framing")
        data = raw[offset:offset + length]
        offset += length
        sections.append(dict(slot=slot, path=path, status=status, size=length, sha256=digest(data), data=data))
    require(offset == len(raw), "REPORT", "Trailing SSH prerequisite bytes")
    by_slot = {s["slot"]: s for s in sections}
    input_diagnostics = _input_diagnostics(by_slot)
    admitted = all(_admitted(slot, row, by_slot) for slot, row in by_slot.items())
    require(bool(flags & 2) == admitted, "REPORT", "Observation completeness flag disagrees")
    require(req == 0 and unlink in (0, -2), "REPORT", "Request or loader unlink was not accepted")
    guards = uid == euid == gid == egid == 0 and by_slot[1]["status"] == 0 and by_slot[1]["data"] == VERSION
    require(bool(flags & 8) == guards, "REPORT", "Root/version guard flag disagrees")
    directories, metadata = {}, {}
    for slot in DIR_SLOTS:
        if by_slot[slot]["status"] == 0:
            directories[SECTIONS[slot][0].removeprefix("directory:")] = _directory(by_slot[slot]["data"])
    for slot in STAT_SLOTS:
        if by_slot[slot]["status"] == 0:
            metadata[SECTIONS[slot][0].removeprefix("lstat:")] = _stat(by_slot[slot]["data"])
    jiritsu = directories.get("/tmp/jiritsu")
    reserve = (((REPORT_RESERVE + jiritsu["fragment_size"] - 1) // jiritsu["fragment_size"] + 2)
               * jiritsu["fragment_size"]) if jiritsu else None
    space = (jiritsu is not None and jiritsu["fs_type"] == VFAT_MAGIC
             and jiritsu["available_bytes"] >= FREE_MARGIN + reserve)
    require(bool(flags & 32) == space, "REPORT", "Fresh VFAT budget flag disagrees")
    groups = None
    if by_slot[2]["status"] == 0:
        data = by_slot[2]["data"]
        require(len(data) % 4 == 0, "REPORT", "Malformed supplemental group array")
        groups = list(struct.unpack("<" + "I" * (len(data) // 4), data))
    capabilities = _status_fields(by_slot[3]["data"]) if by_slot[3]["status"] == 0 else {}
    account = _root_account(by_slot[18]["data"]) if by_slot[18]["status"] == 0 else {}
    input_closes = bool(flags & 16)
    complete = guards and admitted and input_closes and space
    return dict(schema="a7m4-ssh-prerequisite-observation/1", complete=complete,
                guards_verified=guards, all_observations_admitted=admitted,
                all_sections_complete=all(row["status"] == 0 for row in sections),
                input_closes_verified=input_closes, space_guard_verified=space,
                cleanup_verified=unlink in (0, -2), uid=uid, euid=euid, gid=gid, egid=egid,
                pid=pid, loader_unlink_status=unlink, sections=sections, input_diagnostics=input_diagnostics,
                version_sha256=by_slot[1]["sha256"] if by_slot[1]["status"] == 0 else None,
                groups=groups, capabilities=capabilities, account=account,
                directories=directories, file_metadata=metadata,
                jiritsu_available_bytes=jiritsu["available_bytes"] if jiritsu else None,
                output_allocation_reserve_bytes=reserve,
                remaining_after_reserved_output_bytes=jiritsu["available_bytes"] - reserve if jiritsu else None,
                candidate_tmpfs_paths=[path for path, d in directories.items() if d["fs_type"] == TMPFS_MAGIC],
                ssh_start_ready=False, ssh_started=False, namespace_operations_tested=False,
                network_connectivity_verified=False, raw_storage_read=False,
                raw_storage_written=False, firmware_or_settings_written=False, recovery_ready=False)


def public_report(report):
    # Raw configurations can contain password hashes, network addresses and
    # namespace identities. Their bytes AND digests stay in private evidence.
    public_keys = ("schema", "complete", "guards_verified", "all_observations_admitted", "all_sections_complete",
                   "input_closes_verified", "space_guard_verified", "cleanup_verified", "version_sha256",
                   "capabilities", "jiritsu_available_bytes", "output_allocation_reserve_bytes",
                   "remaining_after_reserved_output_bytes", "candidate_tmpfs_paths", "ssh_start_ready",
                   "ssh_started", "namespace_operations_tested", "network_connectivity_verified",
                   "raw_storage_read", "raw_storage_written", "firmware_or_settings_written", "recovery_ready")
    return {**{k: report[k] for k in public_keys},
            "sections": [{k: s[k] for k in ("slot", "path", "status", "size")} for s in report["sections"]],
            "input_diagnostics": [{k: row[k] for k in ("slot", "path", "stage", "stage_name", "status", "metadata_available")} for row in report["input_diagnostics"]]}



REQUEST_PATH='/tmp/jiritsu/a7m4.ssh-prereq-v2.request'
RESULT_PATH='/tmp/jiritsu/a7m4.ssh-prereq-v2.result'
PENDING_PATH=RESULT_PATH+'.pending'


def mount_state(raw):
    """Exact M4 /usr mount profile, with RO and known RW kept separate."""
    if type(raw) is not bytes or any(c not in (9,10) and not 32<=c<=126 for c in raw):return None
    rows=[line.split() for line in raw.decode('ascii').splitlines()]
    if any(len(row)!=6 for row in rows) or any(row[1].startswith('/usr/') for row in rows):return None
    matches=[row for row in rows if row[1]=='/usr']
    if len(matches)!=1 or matches[0][0]!='/dev/nflasha15' or matches[0][2]!='ext2':return None
    flags=matches[0][3].split(',')
    if not all(flags) or ('ro' in flags)==('rw' in flags):return None
    return 'RO' if 'ro' in flags else 'RW'


def mount_guard(raw):return mount_state(raw)=='RO'


def build_worker(output,*,compiler):
    import os
    from .program_worker import _elf
    if digest(SOURCE.read_bytes())!=SOURCE_SHA256:raise ValueError('Frozen runtime inventory source differs')
    output=Path(output).absolute()
    if output.exists() or not output.parent.is_dir() or any(p.is_symlink() for p in (output,*output.parents)):
        raise ValueError('New private inventory build required')
    output.mkdir(mode=0o700)
    env=dict(os.environ,ZIG_GLOBAL_CACHE_DIR=str(output/'zig-global'),ZIG_LOCAL_CACHE_DIR=str(output/'zig-local'))
    if subprocess.run([str(compiler),'version'],capture_output=True,text=True,check=True,env=env,timeout=20).stdout.strip()!='0.13.0':
        raise ValueError('Offline Zig0.13 required')
    args=[str(compiler),'cc','-target','aarch64-linux-gnu','-std=c11','-Os','-Wall','-Wextra','-Werror',
          '-shared','-fPIC','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-unwind-tables',
          '-fno-asynchronous-unwind-tables','-nostdlib','-g0','-Wl,--strip-debug','-Wl,--no-undefined',
          '-Wl,--build-id=none','-Wl,-Bsymbolic','-Wl,-z,noexecstack']
    blobs=[]
    for name in ('inventory.so','inventory-repeat.so'):
        path=output/name
        subprocess.run(args+['-o',str(path),str(SOURCE)],capture_output=True,text=True,check=True,env=env,timeout=180)
        raw=path.read_bytes();_elf(raw)
        if not 0<len(raw)<65536:raise ValueError('Inventory ELF upload must be below64KiB')
        path.chmod(0o600);blobs.append(raw)
    if blobs[0]!=blobs[1]:raise ValueError('Runtime inventory double build differs')
    from .build_scratch import discard_caches
    discard_caches(output)
    return blobs[0]


class OriginalRuntimeInventory:
    """Actual fixed read-only inventory over an already owned native channel."""
    def __init__(self,channel,output,*,compiler,actions_factory=None):
        from .native_actions import NativeActions
        self.channel=channel;self.output=Path(output)
        self.output.mkdir(mode=0o700,exist_ok=False)
        self.binary=build_worker(self.output/'build',compiler=compiler)
        self.actions_factory=actions_factory or NativeActions;self.index=0

    def measure(self):
        import os
        self.index+=1;folder=self.output/('%03d'%self.index);folder.mkdir(mode=0o700)
        actions=self.actions_factory(self.channel,folder/'native')
        if self.channel.peek(PENDING_PATH) is not None:raise ValueError('Unowned inventory pending report exists')
        nonce=os.urandom(16)
        observed={}
        def accept(raw):
            parsed=parse_report(raw,nonce)
            native=getattr(self.channel,'toolbox_identity',None)
            if (not parsed['complete'] or parsed['loader_unlink_status']!=0 or native is None
                    or parsed['pid']!=native[0]):
                raise ValueError('Native inventory is incomplete or process changed')
            mounts=next(row for row in parsed['sections'] if row['slot']==5)
            if mounts['status']!=0:raise ValueError('Native mount section missing')
            observed.update(parsed=parsed,raw_sha256=digest(raw),usr_ro=mount_guard(mounts['data']),mount_state=mount_state(mounts['data']))
            return dict(public_report(parsed),usr_readonly_verified=observed['usr_ro'])
        actions.phase(self.binary,REQUEST_PATH,request(nonce),RESULT_PATH,accept,
            report_bytes=MAX_REPORT,allow_large_readonly_report=True,native_report_capacity=131072,native_overhead_units=2)
        actions.clean_packets()
        if self.channel.peek(PENDING_PATH) is not None:raise ValueError('Inventory pending report remains after completed native')
        parsed=observed['parsed']
        return dict(schema='a7m4-original-runtime-inventory/1',usr_readonly_verified=observed['usr_ro'],
            usr_mount_state=observed['mount_state'],
            exact_owned_cleanup_verified=True,native_context_healthy=True,
            # Deliberately does not authorize STOP; the outer coordinator must
            # also prove complete target readback and all feature helper pairs.
            safe_stop_allowed=False,report_sha256=observed['raw_sha256'],
            boot_id=self.channel.toolbox_identity[1],process_id=parsed['pid'],
            fresh=True,jiritsu_available_bytes=parsed['jiritsu_available_bytes'])
