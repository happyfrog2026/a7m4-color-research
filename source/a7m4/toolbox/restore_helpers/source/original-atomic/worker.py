# SPDX-License-Identifier: MIT
"""Offline original-backup atomic replacement planner/compiler/wire parser.

The selected complete target bytes come from the earliest unmodified backup;
there is no per-feature uninstall or known-install-history requirement. The
product owns transport/coordinator, proof admission, ordered chunk streaming,
complete Mac readback barriers, cancellation and unified reboot verification.
This module performs no networking or device I/O and never truncates a source.
"""
from __future__ import annotations
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess

ROOT = Path(__file__).resolve().parent
FAMILY = 'a7m4-original-backup-atomic/1'
PLAN_SCHEMA = 'a7m4-original-backup-atomic-plan/1'
AUTHORITY_SCHEMA = 'a7m4-owned-tail-authority/1'
READBACK_SCHEMA = 'a7m4-original-backup-atomic-Mac-readback/1'
MAX_FILE_BYTES, MAX_CHUNK_BYTES, REQUEST_BYTES, MAX_REQUEST_BYTES = 16777216, 32768, 256, 33024
MAX_REPORT = 384
VFAT_MINIMUM_RESERVE_BYTES = 8388608
REQUEST_PATH = '/tmp/jiritsu/a7m4.original-atomic.request'
RESULT_PATH = '/tmp/jiritsu/a7m4.original-atomic.result'
LIBRARY_PATH = '/tmp/jiritsu/libJit.so'
PENDING_PATH = None
MAGIC = b'A7OA0001'
IDENTITY = struct.Struct('<QQQIIII')
RQ_PREFIX = struct.Struct('<8sII16s32sQ')
REPORT = struct.Struct('<8sII16s32sII10q3Q4I3Q4I7Q32s32s6IQ')
NATIVE_SOURCE_SHA256='206c17eb53396021ddc9e1009daf60083db94b3f7e656d62e36a654bb9eaf480'
SHA_SOURCE_SHA256 = 'a189ef6a033fabf465dbd08d11ad3e1d2653b65e8d81c7a82499c66ede8df4d3'
_SHA = re.compile(r'[0-9a-f]{64}\Z')
LANGUAGES = ('english', 'simplifiedchinese', 'traditionalchinese')
RESOURCE_FILENAMES = tuple(sorted(
    [f'string_{language}_{direction}.uxc' for language in LANGUAGES
     for direction in ('horizontal', 'vertical')]
    + ['image_00_23_IPSX.uxc', 'image_00_32_IPSX.uxc']))
RESOURCE_PATHS = tuple('/usr/share/app/' + name for name in RESOURCE_FILENAMES)

ORIGINAL_PATHS = RESOURCE_PATHS + ('/cp/SysSound.bin',)
assert len(ORIGINAL_PATHS) == 9 and REPORT.size == MAX_REPORT and IDENTITY.size == 40


def _need(condition, message):
    if not condition:
        raise ValueError(message)


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def _hash(value):
    return type(value) is str and bool(_SHA.fullmatch(value)) and value != '0' * 64


def _identity(raw):
    return dict(size=len(raw), sha256=sha256(raw))


def _bytes(value, label):
    _need(type(value) is bytes, f'Complete {label} bytes on the Mac required')
    return value


def _nonce(value):
    _need(type(value) is bytes and len(value) == 16 and any(value), 'Fresh nonzero16-byte nonce required')
    return value


def _authority(value, source_sha256):
    names = {'original_backup_sha256', 'current_file_readback_sha256',
             'resource_reference_proof_sha256', 'boot_or_load_proof_sha256'}
    _need(type(value) is dict and set(value) == names | {'schema'} and value['schema'] == AUTHORITY_SCHEMA
          and all(_hash(value[k]) for k in names) and value['current_file_readback_sha256'] == source_sha256,
          'Typed original-backup/current-read/reference/runtime digests required; current SHA must match source')
    return deepcopy(value)


def _plan_digest(plan):
    return sha256(canonical({k: v for k, v in plan.items() if k not in ('plan_id', 'stage_path')}))


def _stage_path(resource_path, plan_id):
    return resource_path.rsplit('/', 1)[0] + '/.a7m4-original-' + plan_id + '.stage'


def make_plan(resource_path, source, target, *, authority):
    """Bind a complete current file to one original complete-backup member.

    The product verifies backup/member provenance, body identity and runtime
    compatibility before any device job. Digests record these external proofs;
    accepting a dictionary here does not grant device authorization.
    """
    _need(resource_path in ORIGINAL_PATHS, 'Only70 UXC paths and /cp/SysSound.bin are supported')
    source, target = _bytes(source, 'current source'), _bytes(target, 'original backup target')
    _need(0 <= len(source) <= MAX_FILE_BYTES and 0 < len(target) <= MAX_FILE_BYTES,
          'Current<=16MiB and positive original target<=16MiB required')
    profile = 'cp-vfat-rw' if resource_path == '/cp/SysSound.bin' else 'usr-ext2-ro'
    plan = dict(schema=PLAN_SCHEMA, family=FAMILY, resource_path=resource_path, profile=profile,
                source=_identity(source), target=_identity(target), authority=_authority(authority, sha256(source)),
                no_op=source == target, max_chunk_bytes=MAX_CHUNK_BYTES)
    plan['plan_id'] = _plan_digest(plan)
    plan['stage_path'] = _stage_path(resource_path, plan['plan_id'])
    return validate_plan(plan)


def validate_plan(plan):
    keys = {'schema', 'family', 'resource_path', 'profile', 'source', 'target', 'authority', 'no_op',
            'max_chunk_bytes', 'plan_id', 'stage_path'}
    _need(type(plan) is dict and set(plan) == keys and plan['schema'] == PLAN_SCHEMA and plan['family'] == FAMILY
          and plan['resource_path'] in ORIGINAL_PATHS, 'Exact original-backup atomic plan required')
    for name in ('source', 'target'):
        row = plan[name]
        _need(type(row) is dict and set(row) == {'size', 'sha256'} and type(row['size']) is int
              and _hash(row['sha256']), 'Exact endpoint full size/SHA identities required')
    _need(0 <= plan['source']['size'] <= MAX_FILE_BYTES and 0 < plan['target']['size'] <= MAX_FILE_BYTES,
          'Bounded complete source/target files required')
    expected_profile = 'cp-vfat-rw' if plan['resource_path'] == '/cp/SysSound.bin' else 'usr-ext2-ro'
    _need(plan['profile'] == expected_profile and plan['max_chunk_bytes'] == MAX_CHUNK_BYTES
          and type(plan['no_op']) is bool and plan['no_op'] == (plan['source'] == plan['target']),
          'Fixed mount profile/chunk/no-op classification differs')
    _authority(plan['authority'], plan['source']['sha256'])
    _need(_hash(plan['plan_id']) and plan['plan_id'] == _plan_digest(plan)
          and plan['stage_path'] == _stage_path(plan['resource_path'], plan['plan_id']),
          'Canonical plan/stage path identity differs')
    return deepcopy(plan)


def _readback(plan, raw, endpoint, *, partial=False):
    p = validate_plan(plan); raw = _bytes(raw, endpoint)
    _need(endpoint in ('source', 'stage', 'target'), 'Explicit source/stage/target Mac readback required')
    expected = p['source'] if endpoint == 'source' else p['target']
    if partial:
        _need(endpoint == 'stage' and 0 <= len(raw) <= p['target']['size'], 'Bounded complete partial-stage read required')
    else:
        _need(_identity(raw) == expected, 'Complete Mac EOF/SHA differs from planned endpoint')
    return dict(schema=READBACK_SCHEMA, plan_id=p['plan_id'], endpoint=endpoint,
                device_path=p['stage_path'] if endpoint == 'stage' else p['resource_path'],
                identity=_identity(raw), partial=partial)


def verify_source(plan, raw):
    return _readback(plan, raw, 'source')


def verify_stage(plan, raw):
    return _readback(plan, raw, 'stage')


def verify_readback(plan, raw):
    return _readback(plan, raw, 'target')


def verify_abort_stage(plan, raw):
    """Fresh complete bytes of a known owned stage, possibly not yet full size."""
    return _readback(plan, raw, 'stage', partial=True)


def _require_readback(plan, receipt, endpoint, *, size=None, partial=False):
    p = validate_plan(plan)
    _need(type(receipt) is dict and set(receipt) == {'schema', 'plan_id', 'endpoint', 'device_path', 'identity', 'partial'}
          and receipt['schema'] == READBACK_SCHEMA and receipt['plan_id'] == p['plan_id']
          and receipt['endpoint'] == endpoint and receipt['partial'] is partial
          and receipt['device_path'] == (p['stage_path'] if endpoint == 'stage' else p['resource_path']),
          'Explicit matching complete Mac readback receipt required')
    identity = receipt['identity']
    _need(type(identity) is dict and set(identity) == {'size', 'sha256'} and type(identity['size']) is int
          and _hash(identity['sha256']), 'Exact Mac readback identity required')
    if partial:
        _need(identity['size'] == size and 0 <= size <= p['target']['size'], 'Fresh full partial-stage bytes/EOF required')
    else:
        _need(identity == p['source' if endpoint == 'source' else 'target'], 'Complete readback endpoint identity differs')
    return identity


def _core(report, side):
    return tuple(report[side + '_' + key] for key in ('dev', 'ino', 'size', 'mode', 'uid', 'gid', 'nlink'))


def request(plan, mode, nonce16, previous=None, *, chunk=b'', source_readback=None, stage_readback=None):
    """Build one request; the product coordinates transport and nonce history.

    Begin requires a complete Mac source receipt. Commit requires complete
    original-target stage EOF/SHA; explicit abort requires fresh complete stage
    bytes and binds its exact length. This helper never submits a request.
    """
    p = validate_plan(plan); _nonce(nonce16)
    _need(not p['no_op'] and type(mode) is int and mode in range(5), 'Nonempty original restore and explicit mode0..4 required')
    _need(type(chunk) is bytes and (mode == 2 or not chunk), 'Only append mode2 carries bounded payload')
    source = stage = (0,) * 7; pid = offset = guard = 0; stage_hash = chunk_hash = bytes(32)
    if mode == 0:
        _need(previous is None and source_readback is None and stage_readback is None, 'Inspect derives current source identity')
    else:
        _need(type(previous) is dict and previous.get('schema') == FAMILY and previous.get('plan_id') == p['plan_id']
              and previous.get('complete') is True and previous.get('cleanup_safe') is True
              and previous.get('nonce') != nonce16.hex(), 'Previous successful native report and distinct fresh nonce required')
        pid, source = previous['pid'], _core(previous, 'source')
        if mode == 1:
            _need(previous['mode'] == 0 and stage_readback is None, 'Inspect before one exclusive stage creation')
            _require_readback(p, source_readback, 'source')
        else:
            _need(previous['mode'] in (1, 2) and source_readback is None, 'Ordered known staging report required; no retry after commit/abort')
            stage = _core(previous, 'stage'); offset = stage[2]
            guard = int(p['profile'] == 'usr-ext2-ro' and previous.get('known_deferred_readonly') is True
                        and previous.get('readonly') == previous.get('native_status') == -16)
            if guard and mode == 2:
                _need(previous.get('stage_hash_verified') is True and _hash(previous.get('stage_sha256')),
                      'Known-RW continuation requires native complete-stage SHA token')
                stage_hash = bytes.fromhex(previous['stage_sha256'])
            if mode == 2:
                _need(stage_readback is None and 0 < len(chunk) <= MAX_CHUNK_BYTES
                      and offset + len(chunk) <= p['target']['size'], 'Append must start at previous exact stage EOF and remain within target')
                chunk_hash = bytes.fromhex(sha256(chunk))
            elif mode == 3:
                _need(offset == p['target']['size'], 'Original target must be completely staged before commit')
                _require_readback(p, stage_readback, 'stage')
                stage_hash = bytes.fromhex(p['target']['sha256'])
            else:
                identity = _require_readback(p, stage_readback, 'stage', size=offset, partial=True)
                stage_hash = bytes.fromhex(identity['sha256'])
    raw = bytearray(REQUEST_BYTES)
    RQ_PREFIX.pack_into(raw, 0, MAGIC, mode, len(chunk), nonce16, bytes.fromhex(p['plan_id']), pid)
    IDENTITY.pack_into(raw, 72, *source); IDENTITY.pack_into(raw, 112, *stage)
    struct.pack_into('<Q', raw, 152, offset); raw[160:192] = stage_hash; raw[192:224] = chunk_hash
    struct.pack_into('<I', raw, 224, guard)
    raw.extend(chunk)
    _need(len(raw) <= MAX_REQUEST_BYTES and len(raw) < 65536, 'Every upload request must remain below64KiB')
    return bytes(raw)


def render_header(plan):
    p = validate_plan(plan); _need(not p['no_op'], 'No-diff resources need no native compilation')
    array = lambda raw: '{' + ','.join(map(str, raw)) + '}'
    return ('/* Private original-backup identities; no embedded firmware payload. */\n'
            '#define OA_PATH ' + json.dumps(p['resource_path']) + '\n'
            '#define OA_STAGE_PATH ' + json.dumps(p['stage_path']) + '\n'
            f'#define OA_SOURCE_SIZE {p["source"]["size"]}UL\n'
            f'#define OA_TARGET_SIZE {p["target"]["size"]}UL\n'
            'static const u8 oa_plan_id[32]=' + array(bytes.fromhex(p['plan_id'])) + ';\n'
            'static const u8 oa_source_sha256[32]=' + array(bytes.fromhex(p['source']['sha256'])) + ';\n'
            'static const u8 oa_target_sha256[32]=' + array(bytes.fromhex(p['target']['sha256'])) + ';\n').encode()


def descriptor(path):
    path = Path(path).resolve(); raw = path.read_bytes()
    return dict(path=str(path), size=len(raw), sha256=sha256(raw))


def _save(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data); stream.flush(); os.fsync(stream.fileno())


def build(plan, output, *, compiler):
    p = validate_plan(plan); _need(not p['no_op'], 'No-diff resources need no native job')
    source = ROOT / 'native' / 'original_atomic.c'; initial = source.read_bytes()
    sha_source = ROOT / 'native' / 'original-sha256.h'; initial_sha = sha_source.read_bytes()
    _need(sha256(initial_sha) == SHA_SOURCE_SHA256, 'Reviewed native SHA implementation pin differs')
    _need(_hash(NATIVE_SOURCE_SHA256) and sha256(initial) == NATIVE_SOURCE_SHA256, 'Reviewed native source pin differs')
    out = Path(output).absolute()
    _need(not out.exists() and out.parent.is_dir() and not any(x.is_symlink() for x in (out, *out.parents)), 'New real private output directory required')
    command = [os.fspath(compiler)] if isinstance(compiler, (str, os.PathLike)) else list(compiler or ())
    _need(command and all(type(x) is str and x for x in command), 'Explicit offline Zig0.13 compiler command required')
    out.mkdir(mode=0o700); header = out / 'original-plan.private.h'; _save(header, render_header(p))
    _save(out / 'original-sha256.h', initial_sha)
    _save(out / 'plan.private.json', canonical(p) + b'\n')
    env = dict(os.environ, ZIG_GLOBAL_CACHE_DIR=str(out / 'zig-global'), ZIG_LOCAL_CACHE_DIR=str(out / 'zig-local'))
    version = subprocess.run(command + ['version'], capture_output=True, text=True, check=True, timeout=30, env=env).stdout.strip()
    _need(version == '0.13.0', 'Reviewed offline Zig0.13.0 required')
    args = command + ['cc', '-target', 'aarch64-linux-gnu', '-std=c11', '-DPATCH_MANIFEST="' + str(header) + '"']
    subprocess.run(args + ['-DTARGET_ABI', '-c', str(source), '-o', str(out / 'abi.o')], capture_output=True, check=True, timeout=120, env=env)
    args += ['-Os', '-shared', '-fPIC', '-ffreestanding', '-fno-builtin', '-fno-stack-protector',
             '-fno-unwind-tables', '-fno-asynchronous-unwind-tables', '-nostdlib', '-g0',
             '-Wl,--strip-debug', '-Wl,--no-undefined', '-Wl,--build-id=none', '-Wl,-Bsymbolic', '-Wl,-z,noexecstack']
    raws = []
    for name in ('original-atomic.so', 'original-atomic-repeat.so'):
        output_path = out / name
        subprocess.run(args + ['-o', str(output_path), str(source)], capture_output=True, check=True, timeout=180, env=env)
        raw = output_path.read_bytes()
        _need(0 < len(raw) < 65536 and raw[:7] == b'\x7fELF\x02\x01\x01'
              and struct.unpack_from('<HH', raw, 16) == (3, 183), 'Every AArch64 shared ELF upload must be below65536B')
        output_path.chmod(0o600); raws.append(raw)
    _need(raws[0] == raws[1] and source.read_bytes() == initial and sha_source.read_bytes() == initial_sha
          and header.read_bytes() == render_header(p), 'Native source/header/double-build identity differs')
    result = dict(schema=FAMILY, plan_id=p['plan_id'], worker=descriptor(out / 'original-atomic.so'), native_source=descriptor(source),
                  builder=descriptor(__file__), manifest=descriptor(header), sha_source=descriptor(sha_source), plan=descriptor(out / 'plan.private.json'),
                  double_build_identical=True, target_ABI_checked=True, allowed_modes=[0, 1, 2, 3, 4],
                  request_path=REQUEST_PATH, result_path=RESULT_PATH, request_bytes=REQUEST_BYTES, max_request_bytes=MAX_REQUEST_BYTES,
                  max_report=MAX_REPORT, VFAT_minimum_reserve_bytes=VFAT_MINIMUM_RESERVE_BYTES, source=p['source'], target=p['target'],
                  atomic_inode_replacement=True, source_truncate_forbidden=True, max_chunk_bytes=MAX_CHUNK_BYTES,
                  no_NOR_write=True, no_WBI_write=True, no_automatic_retry=True, camera_io=False, network_io=False, device_validation='NOT_PERFORMED')
    _save(out / 'build.private.json', canonical(result) + b'\n')
    return result


def _request_fields(plan, raw, mode, nonce16):
    _need(type(raw) is bytes and REQUEST_BYTES <= len(raw) <= MAX_REQUEST_BYTES, 'Exact emitted request packet required')
    magic, seen_mode, count, nonce, plan_id, pid = RQ_PREFIX.unpack_from(raw)
    source, stage = IDENTITY.unpack_from(raw, 72), IDENTITY.unpack_from(raw, 112)
    offset = struct.unpack_from('<Q', raw, 152)[0]; guard = struct.unpack_from('<I', raw, 224)[0]
    _need((magic, seen_mode, nonce, plan_id) == (MAGIC, mode, nonce16, bytes.fromhex(plan['plan_id']))
          and count <= MAX_CHUNK_BYTES and len(raw) == REQUEST_BYTES + count and not any(raw[228:256])
          and guard in (0, 1), 'Emitted request plan/mode/nonce/length/guard differs')
    _need(not guard or (plan['profile'] == 'usr-ext2-ro' and mode in (2, 3, 4)), 'Known-RW flag is only for an existing USR stage chain')
    if mode == 0:
        _need(not any(raw[64:]), 'Inspect identity and mutation fields must be zero')
    else:
        _need(pid > 0 and source[2] == plan['source']['size'] and source[1] > 0 and source[6] == 1,
              'Bound current native source identity required')
        if mode == 1:
            _need(not count and not any(raw[112:]), 'Exclusive begin carries only source identity')
        else:
            _need(stage[1] > 0 and stage[6] == 1 and offset == stage[2] <= plan['target']['size'], 'Bound exact stage EOF required')
        if mode == 2:
            _need(0 < count <= MAX_CHUNK_BYTES and offset + count <= plan['target']['size']
                  and raw[192:224] == bytes.fromhex(sha256(raw[256:]))
                  and (any(raw[160:192]) if guard else not any(raw[160:192])), 'Exact payload SHA and known-stage continuation token required')
        else:
            _need(not count and not any(raw[192:224]), 'Only append carries chunk bytes/hash')
        if mode == 3:
            _need(offset == plan['target']['size'] and raw[160:192] == bytes.fromhex(plan['target']['sha256']), 'Commit requires full original target stage')
        if mode == 4:
            _need(any(raw[160:192]), 'Abort requires fresh complete-stage SHA')
    return dict(pid=pid, source=source, stage=stage, offset=offset, chunk_bytes=count,
                stage_sha256=raw[160:192].hex(), guard_flags=guard)


def _regular(core):
    dev, ino, size, mode, uid, gid, nlink = core
    return ino > 0 and 0 <= size <= MAX_FILE_BYTES and mode & 0o170000 == 0o100000 and not mode & 0o7000 and nlink == 1


def parse_report(plan, raw, mode, nonce16, *, request_bytes):
    """Parse one completed native result against its exact submitted packet.

    Unknown writes/rename/unlink or unclosed native I/O never authorize retry,
    continuation or a healthy transport close. A known completed operation may
    explicitly defer USR read-only remount after EBUSY; it does not claim RO.
    """
    p = validate_plan(plan); _nonce(nonce16)
    _need(not p['no_op'] and type(mode) is int and mode in range(5) and type(raw) is bytes and len(raw) == MAX_REPORT,
          'Exact384-byte report for a nonempty original restore required')
    q = _request_fields(p, request_bytes, mode, nonce16)
    keys = ('magic', 'version', 'mode', 'nonce', 'plan_id', 'phase', 'flags', 'native_status', 'euid', 'pid',
            'plugin_unlink', 'close_errors', 'remount', 'readonly', 'source_status', 'stage_status', 'fs_status',
            'source_dev', 'source_ino', 'source_size', 'source_mode', 'source_uid', 'source_gid', 'source_nlink',
            'stage_dev', 'stage_ino', 'stage_size', 'stage_mode', 'stage_uid', 'stage_gid', 'stage_nlink',
            'fs_type', 'fs_unit', 'fs_available', 'fs_needed', 'offset', 'bytes_written', 'bytes_verified',
            'source_sha256', 'stage_sha256', 'write_attempts', 'rename_attempts', 'renamed', 'stage_created',
            'stage_removed', 'profile', 'reserved')
    r = dict(zip(keys, REPORT.unpack(raw)))
    _need((r['magic'], r['version'], r['mode'], r['nonce'], r['plan_id']) ==
          (MAGIC, 1, mode, nonce16, bytes.fromhex(p['plan_id'])) and r['reserved'] == 0
          and not r['flags'] & ~65535 and r['profile'] == int(p['profile'] == 'cp-vfat-rw'), 'Report framing/nonce/plan/profile differs')
    _need(r['renamed'] <= 1 and r['stage_created'] <= 1 and r['stage_removed'] <= 1 and r['rename_attempts'] <= 1
          and r['bytes_verified'] <= r['bytes_written'] <= MAX_CHUNK_BYTES and r['write_attempts'] <= MAX_CHUNK_BYTES + 3,
          'Bounded mutation counters required')
    loader_ok = r['euid'] == 0 and r['pid'] > 0 and r['plugin_unlink'] == 0
    source, stage = _core(r, 'source'), _core(r, 'stage'); flags = r['flags']; claimed = bool(flags & 1)
    deferred = bool(r['profile'] == 0 and mode > 0 and r['native_status'] == r['readonly'] == -16)
    clean_end = r['native_status'] == r['readonly'] == 0 or deferred
    common = (loader_ok and not any(r[k] for k in ('close_errors', 'remount', 'source_status', 'stage_status', 'fs_status'))
              and r['phase'] == 9 and clean_end and _regular(source) and r['source_size'] == p['source']['size']
              and flags & (2048 | 4096 | 8192) == 2048 | 4096 | 8192 and not flags & 32768)
    if mode:
        common = common and r['pid'] == q['pid'] and source == q['source']
    source_hash_ok = bool(flags & 512 and r['source_sha256'] == bytes.fromhex(p['source']['sha256']))
    stage_hash_ok = bool(flags & 1024 and any(r['stage_sha256']))
    if common:
        unit = r['fs_unit']; already = q['stage'][2] if mode >= 2 else 0
        _need(0 < unit <= 1048576 and r['fs_type'] == (0x4d44 if r['profile'] else 0xef53), 'Exact mount filesystem/capacity unit required')
        needed = 0 if mode == 4 else (((p['target']['size'] + unit - 1) // unit) - ((already + unit - 1) // unit) + 32) * unit
        common = r['fs_needed'] == needed and r['fs_available'] >= needed
    mutators = flags & (2 | 4 | 8 | 16 | 32 | 64 | 128 | 256 | 16384)
    stage_matches = (_regular(stage) and stage[0] == source[0] and stage[1] != source[1]
                     and stage[3:] == source[3:])
    zero_counts = not any(r[k] for k in ('bytes_written', 'bytes_verified', 'write_attempts', 'rename_attempts', 'renamed', 'stage_created', 'stage_removed', 'offset'))
    if mode == 0:
        complete = common and source_hash_ok and not any(stage) and mutators == 0 and zero_counts and flags == 14849
    elif mode == 1:
        complete = (common and source_hash_ok and stage_matches and stage[2] == 0
                    and mutators == 2 | 4 | 16384 and r['stage_created'] == 1
                    and not any(r[k] for k in ('bytes_written', 'bytes_verified', 'write_attempts', 'rename_attempts', 'renamed', 'stage_removed', 'offset'))
                    and (stage_hash_ok and r['stage_sha256'] == bytes.fromhex(sha256(b'')) if deferred else not flags & 1024))
    elif mode == 2:
        expected_stage = list(q['stage']); expected_stage[2] += q['chunk_bytes']
        complete = (common and stage_matches and stage == tuple(expected_stage) and mutators == 8 | 16
                    and r['offset'] == q['offset'] and r['bytes_written'] == r['bytes_verified'] == q['chunk_bytes']
                    and 1 <= r['write_attempts'] <= q['chunk_bytes'] + 3
                    and not any(r[k] for k in ('rename_attempts', 'renamed', 'stage_created', 'stage_removed'))
                    and (source_hash_ok if q['guard_flags'] or deferred else not flags & 512)
                    and (stage_hash_ok if deferred else not flags & 1024))
    elif mode == 3:
        complete = (common and source_hash_ok and stage_hash_ok and r['stage_sha256'] == bytes.fromhex(p['target']['sha256'])
                    and stage_matches and stage == q['stage'] and mutators == 32 | 64 | 16384
                    and r['rename_attempts'] == r['renamed'] == 1
                    and not any(r[k] for k in ('bytes_written', 'bytes_verified', 'write_attempts', 'stage_created', 'stage_removed', 'offset')))
    else:
        complete = (common and source_hash_ok and stage_hash_ok and r['stage_sha256'].hex() == q['stage_sha256']
                    and stage_matches and stage == q['stage'] and mutators == 128 | 256 | 16384 and r['stage_removed'] == 1
                    and not any(r[k] for k in ('bytes_written', 'bytes_verified', 'write_attempts', 'rename_attempts', 'renamed', 'stage_created', 'offset')))
    complete = bool(claimed and complete)
    _need(not claimed or complete, 'Native completion lacks exact operation/source/stage/capacity/hash proofs')
    effects = bool(r['stage_created'] or r['write_attempts'] or r['bytes_written'] or r['rename_attempts']
                   or r['renamed'] or r['stage_removed'] or flags & (8 | 32 | 128))
    unknown = bool(flags & 32768 or r['close_errors'] or effects and not complete)
    safe = bool(loader_ok and not r['close_errors'] and not unknown
                and (complete or r['readonly'] == 0 and not effects))
    r.update(schema=FAMILY, magic=MAGIC.decode(), nonce=nonce16.hex(), plan_id=p['plan_id'],
             source_sha256=r['source_sha256'].hex(), stage_sha256=r['stage_sha256'].hex(),
             complete=complete, native_complete=complete, cleanup_safe=safe, loader_unlink_verified=loader_ok,
             known_deferred_readonly=bool(complete and deferred), usr_readonly_verified=bool(complete and not r['profile'] and not deferred),
             cp_vfat_rw_verified=bool(complete and r['profile']), source_hash_verified=source_hash_ok,
             stage_hash_verified=stage_hash_ok, safe_inspect_refusal=bool(mode == 0 and not complete and safe),
             operation_state_unknown=unknown, atomic_commit_complete=bool(complete and mode == 3),
             full_file_restore_complete=False, full_target_readback_required=bool(complete and mode == 3),
             post_boot_full_file_verification_complete=False, automatic_retry_allowed=False,
             source_truncate_forbidden=True, source_prefix_overwrite=False, NOR_write=False, WBI_write=False,
             request_sha256=sha256(request_bytes), report_sha256=sha256(raw))
    return r
