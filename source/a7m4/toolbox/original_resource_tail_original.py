# SPDX-License-Identifier: MIT
"""Independent original-EOF runtime tail restoration profile.

Disk shadow retains the complete source append. Runtime shadow is derived only
from the original target prefix and zero padding within its last valid page.
No caller-selected RAM bytes are admitted. Apply requires a fresh native
inspection, complete source read, same PID/boot/inode and exact original RAM.

No camera access is performed here. The caller verifies the original complete
backup, same-body binding and current runtime reference safety before authorizing
a job. Backup/current-read/reference/load proof digests bind the private plan;
the helper neither validates external proof provenance nor grants device access.
The native completion bit is not a full-file restore claim: a fresh complete Mac
readback and exact EOF/SHA are still required by TailRestoreProtocol.
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
SOURCE = ROOT / 'data' / 'original-resource-tail-original.c'
FAMILY = 'a7m4-original-eof-tail-restore/1'
PLAN_SCHEMA = 'a7m4-original-eof-tail-plan/1'
AUTHORITY_SCHEMA = 'a7m4-owned-tail-authority/1'
NATIVE_SOURCE_SHA256='e58b150b3d4c58cfb329e24153d12db96e1bbe6bd620bdb3a7ad17721c6759df'
REQUEST_PATH = '/tmp/jiritsu/a7m4.original-tail-restore.request'
RESULT_PATH = '/tmp/jiritsu/a7m4.original-tail-restore.result'
LIBRARY_PATH = '/tmp/jiritsu/libJit.so'
PENDING_PATH = None
REQUEST_BYTES, MIN_REPORT, MAX_REPORT = 256, 544, 65536
PAGE_BYTES, MAX_FILE_BYTES, MAX_TAIL_BYTES = 4096, 16777216, 43008
MAX_SHADOW_BYTES, MAX_PREIMAGE_BYTES, MAX_ALIASES = 49152, 61440, 4
VFAT_MINIMUM_RESERVE_BYTES = 8388608
MAGIC = b'A7TO0001'
PREFIX = struct.Struct('<8sII16s32s8I9q3Q4I4Q4I')
RANGE = struct.Struct('<4Q')
RQ = struct.Struct('<8sII16s32sQ3Q4I2Q')
_SHA = re.compile(r'[0-9a-f]{64}\Z')
# Public resource basenames only; no firmware bytes or machine identities.
from ..resource_profile import LANGUAGES, RESOURCES as RESOURCE_FILENAMES, RESOURCE_PATHS
assert len(RESOURCE_PATHS) == 8 and PREFIX.size == 256 and RQ.size == 128


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
    return {'size': len(raw), 'sha256': sha256(raw)}


def _nonce(value):
    _need(type(value) is bytes and len(value) == 16 and any(value), 'Fresh nonzero 16-byte nonce required')
    return value


def _bytes(value, label):
    _need(type(value) is bytes, f'Complete {label} must be bytes read on the Mac')
    return value


def _plan_digest(plan):
    return sha256(canonical({k: v for k, v in plan.items() if k != 'plan_id'}))


def _validate_authority(authority, current_sha256):
    digests = {'original_backup_sha256', 'current_file_readback_sha256',
               'resource_reference_proof_sha256', 'boot_or_load_proof_sha256'}
    _need(type(authority) is dict and set(authority) == digests | {'schema'}
          and authority['schema'] == AUTHORITY_SCHEMA
          and all(_hash(authority[k]) for k in digests)
          and authority['current_file_readback_sha256'] == current_sha256,
          'Typed original-backup/current-read/reference/runtime proof digests required; current SHA must match source')
    return deepcopy(authority)


def make_plan(resource_path, source, target, *, authority, runtime):
    """Bind complete current bytes to an independently verified baseline.

    ``authority`` binds four externally checked proof digests: the earliest
    complete unmodified backup, this complete current file read, its restored
    resource references and current boot/load reference safety. The last proof
    may describe a new boot or an already-safe loaded runtime; a new boot is
    not inherently required. There is no completed-install-receipt requirement.
    Proof provenance/sufficiency belongs to the product admission layer; knowing
    a digest alone grants no execution authority. This function performs no I/O.
    """
    _need(resource_path in RESOURCE_PATHS, 'Only the seventy exact UXC resources are supported')
    source, target = _bytes(source, 'source'), _bytes(target, 'baseline target')
    _need(0 < len(target) < len(source) <= MAX_FILE_BYTES, 'Positive bounded appended-tail source required')
    _need(len(source) - len(target) <= MAX_TAIL_BYTES, 'Owned appended tail exceeds 43008 bytes')
    _need(source.startswith(target), 'Source must equal the complete baseline prefix plus owned append tail')
    _validate_authority(authority, sha256(source))
    begin = len(target) // PAGE_BYTES * PAGE_BYTES
    end = (len(source) + PAGE_BYTES - 1) // PAGE_BYTES * PAGE_BYTES
    _need(0 < end - begin <= MAX_SHADOW_BYTES, 'Tail page shadow exceeds 49152 bytes')
    shadow = source[begin:] + bytes(end - len(source))
    plan = dict(schema=PLAN_SCHEMA, family=FAMILY, resource_path=resource_path,
                source=_identity(source), target=_identity(target),
                owned_tail=_identity(source[len(target):]), shadow_begin=begin, shadow_end=end,
                expected_shadow_hex=shadow.hex(), expected_shadow_sha256=sha256(shadow),
                authority=deepcopy(authority), source_prefix_verified_on_mac=True,
                runtime=deepcopy(runtime), runtime_end=(len(target)+PAGE_BYTES-1)//PAGE_BYTES*PAGE_BYTES,
                runtime_shadow_hex=(target[begin:]+bytes((-len(target))%PAGE_BYTES)).hex(),
                runtime_shadow_sha256=sha256(target[begin:]+bytes((-len(target))%PAGE_BYTES)),
                runtime_profile="original-eof-zero-padded", inspect_only=False)
    plan['plan_id'] = _plan_digest(plan)
    return validate_plan(plan)


def validate_plan(plan):
    keys = {'schema', 'family', 'resource_path', 'source', 'target', 'owned_tail',
            'shadow_begin', 'shadow_end', 'expected_shadow_hex', 'expected_shadow_sha256',
            'authority', 'source_prefix_verified_on_mac', 'plan_id', 'runtime',
            'runtime_end', 'runtime_shadow_hex', 'runtime_shadow_sha256', 'runtime_profile', 'inspect_only'}
    _need(type(plan) is dict and set(plan) == keys, 'Exact tail plan fields required')
    _need(plan['schema'] == PLAN_SCHEMA and plan['family'] == FAMILY and plan['resource_path'] in RESOURCE_PATHS,
          'Unknown plan schema/family/resource')
    for name in ('source', 'target', 'owned_tail'):
        row = plan[name]
        _need(type(row) is dict and set(row) == {'size', 'sha256'}
              and type(row['size']) is int and _hash(row['sha256']), 'Exact endpoint size/SHA identities required')
    source, target, tail = (plan[k]['size'] for k in ('source', 'target', 'owned_tail'))
    _need(0 < target < source <= MAX_FILE_BYTES and 0 < tail == source - target <= MAX_TAIL_BYTES,
          'Bounded positive owned append required')
    begin, end = plan['shadow_begin'], plan['shadow_end']
    _need(type(begin) is int and type(end) is int and begin == target // PAGE_BYTES * PAGE_BYTES
          and end == (source + PAGE_BYTES - 1) // PAGE_BYTES * PAGE_BYTES
          and 0 < end - begin <= MAX_SHADOW_BYTES, 'Exact page-aligned tail shadow required')
    _need(type(plan['expected_shadow_hex']) is str and len(plan['expected_shadow_hex']) == 2 * (end - begin),
          'Exact bounded shadow hex required')
    try:
        shadow = bytes.fromhex(plan['expected_shadow_hex'])
    except ValueError as exc:
        raise ValueError('Canonical shadow hex required') from exc
    _need(shadow.hex() == plan['expected_shadow_hex'] and sha256(shadow) == plan['expected_shadow_sha256']
          and not any(shadow[source - begin:])
          and _identity(shadow[target - begin:source - begin]) == plan['owned_tail'], 'Shadow/tail bytes or zero padding differ')
    runtime_end = (target + PAGE_BYTES - 1) // PAGE_BYTES * PAGE_BYTES
    expected_runtime = shadow[:target-begin] + bytes(runtime_end-target)
    _need(plan['runtime_end'] == runtime_end and plan['runtime_shadow_hex'] == expected_runtime.hex()
          and plan['runtime_shadow_sha256'] == sha256(expected_runtime)
          and plan['runtime_profile'] == 'original-eof-zero-padded' and plan['inspect_only'] is False,
          'Runtime must be derived only from the original prefix and original EOF padding')
    runtime = plan['runtime']
    _need(type(runtime) is dict and set(runtime) == {'process_id','boot_id','original_ap_report_sha256'}
          and type(runtime['process_id']) is int and 0 < runtime['process_id'] <= 4194304
          and type(runtime['boot_id']) is str
          and re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',runtime['boot_id']) is not None
          and _hash(runtime['original_ap_report_sha256'])
          and runtime['original_ap_report_sha256'] == plan['authority']['boot_or_load_proof_sha256'],
          'Exact same-session original AP proof/PID/boot binding required')
    _validate_authority(plan['authority'], plan['source']['sha256'])
    _need(plan['source_prefix_verified_on_mac'] is True, 'Original complete-prefix Mac verification required')
    _need(_hash(plan['plan_id']) and plan['plan_id'] == _plan_digest(plan), 'Plan identity/content differs')
    return deepcopy(plan)


def verify_source(plan, raw):
    """Verify a new complete Mac source read, including its baseline prefix."""
    p = validate_plan(plan); raw = _bytes(raw, 'source')
    _need(_identity(raw) == p['source'] and _identity(raw[:p['target']['size']]) == p['target']
          and _identity(raw[p['target']['size']:]) == p['owned_tail'], 'Complete source/baseline-prefix/owned-tail SHA differs')
    shadow = raw[p['shadow_begin']:] + bytes(p['shadow_end'] - len(raw))
    _need(shadow.hex() == p['expected_shadow_hex'], 'Complete source does not match compiled tail shadow')
    return dict(status='FULL_SOURCE_MAC_VERIFIED', plan_id=p['plan_id'], identity=p['source'])


def verify_readback(plan, raw):
    """Verify complete post-truncate Mac bytes and exact original EOF."""
    p = validate_plan(plan); raw = _bytes(raw, 'target readback')
    _need(_identity(raw) == p['target'], 'Complete target Mac EOF/SHA differs')
    return dict(status='FULL_TARGET_MAC_VERIFIED', plan_id=p['plan_id'], identity=p['target'])


def _core(report):
    return tuple(report[k] for k in ('source_dev', 'source_ino', 'source_size',
                                    'source_mode', 'source_uid', 'source_gid', 'source_nlink'))


def mapping_metadata(report):
    """Public diagnostic fields; addresses are usable only from native inspect."""
    return {k: deepcopy(report[k]) for k in ('pid', 'source_dev', 'source_ino', 'source_size',
            'source_mode', 'source_uid', 'source_gid', 'source_nlink', 'ranges',
            'range_fingerprint_sha256', 'cross_pids', 'cross_matches', 'preimage_captured')}


def _fingerprint(plan, report):
    value = dict(plan_id=plan['plan_id'], pid=report['pid'], identity=list(_core(report)),
                 ranges=[{k: row[k] for k in ('va', 'len', 'off', 'prot')} for row in report['ranges']])
    return sha256(canonical(value))


def request(plan, mode, nonce16, inspection=None):
    p = validate_plan(plan); _nonce(nonce16)
    _need(type(mode) is int and mode in (0, 1), 'Only same-session inspect0 then apply1 is permitted')
    plan_id = bytes.fromhex(p['plan_id'])
    if mode == 0:
        _need(inspection is None, 'Inspection derives its own identity and ranges')
        return RQ.pack(MAGIC, 0, 0, nonce16, plan_id, *([0] * 10)) + bytes(128)
    _need(type(inspection) is dict and inspection.get('schema') == FAMILY
          and inspection.get('plan_id') == p['plan_id'] and inspection.get('mode') == 0
          and inspection.get('complete') is True and inspection.get('cleanup_safe') is True,
          'Successful native inspection of this exact plan required')
    _need(inspection['range_fingerprint_sha256'] == _fingerprint(p, inspection), 'Inspection identity/ranges changed')
    rows = inspection['ranges']; _need(len(rows) <= MAX_ALIASES, 'Bounded inspection aliases required')
    encoded = b''.join(RANGE.pack(*(row[k] for k in ('va', 'len', 'off', 'prot'))) for row in rows)
    return RQ.pack(MAGIC, 1, len(rows), nonce16, plan_id, inspection['pid'], *_core(inspection),
                   p['target']['size'], 0) + encoded + bytes(128 - len(encoded))


def parse_report(plan, raw, mode, nonce16):
    p = validate_plan(plan); _nonce(nonce16)
    _need(type(mode) is int and mode in (0, 1) and type(raw) is bytes
          and MIN_REPORT <= len(raw) <= MAX_REPORT, 'Bounded complete native report required')
    keys = ('magic', 'version', 'mode', 'nonce', 'plan_id', 'phase', 'index', 'range_count',
            'cross_pids', 'cross_matches', 'mremap_attempts', 'changed_aliases', 'flags',
            'native_status', 'euid', 'pid', 'plugin_unlink', 'close_errors', 'readonly',
            'remount', 'auxv_status', 'source_status', 'source_dev', 'source_ino', 'source_size',
            'source_mode', 'source_uid', 'source_gid', 'source_nlink', 'target_size', 'page_size',
            'anon_bytes', 'bytes_truncated', 'total', 'preimage_bytes', 'offender_pid', 'reserved')
    r = dict(zip(keys, PREFIX.unpack_from(raw)))
    _need((r['magic'], r['version'], r['mode'], r['nonce'], r['plan_id'], r['total']) ==
          (MAGIC, 1, mode, nonce16, bytes.fromhex(p['plan_id']), len(raw)), 'Report framing/plan/mode/nonce differs')
    _need((r['source_size'], r['target_size']) == (p['source']['size'], p['target']['size'])
          and r['reserved'] == 0 and not r['flags'] & ~255 and r['range_count'] <= MAX_ALIASES
          and r['preimage_bytes'] <= MAX_PREIMAGE_BYTES
          and len(raw) == MIN_REPORT + r['preimage_bytes'], 'Report bounds/size/flags differ')
    rows, total = [], 0
    for i in range(MAX_ALIASES):
        values = RANGE.unpack_from(raw, PREFIX.size + i * RANGE.size)
        if i >= r['range_count']:
            _need(not any(values), 'Unused range slot must be zero'); continue
        row = dict(zip(('va', 'len', 'off', 'prot'), values))
        _need(row['va'] > 0 and not (row['va'] | row['len'] | row['off']) & (PAGE_BYTES - 1)
              and 0 < row['len'] <= MAX_SHADOW_BYTES and row['va'] + row['len'] <= 1 << 64 and row['prot'] == 1
              and p['shadow_begin'] <= row['off'] < row['off'] + row['len'] <= p['runtime_end'],
              'Native range must be private read-only tail pages')
        _need(not rows or row['va'] >= rows[-1]['va'] + rows[-1]['len'], 'Native VAs overlap or are unordered')
        total += row['len']; rows.append(row)
    _need(total == r['preimage_bytes'], 'Alias preimage byte count differs')
    scratch = list(struct.unpack_from('<4Q', raw, 384))
    _need(all(not scratch[i] for i in range(r['range_count'], 4)), 'Unused scratch slot differs')
    captured = bool(r['flags'] & 128); at = MIN_REPORT
    shadow = bytes.fromhex(p['runtime_shadow_hex'])
    for row in rows:
        saved = raw[at:at + row['len']]; at += row['len']
        if captured:
            begin = row['off'] - p['shadow_begin']
            _need(saved == shadow[begin:begin + row['len']], 'Captured native memory differs from planned shadow')
        # A failed snapshot may have copied only earlier aliases. Without
        # flag128 none of this body is admitted as verified live evidence.
        row.update(preimage_hex=saved.hex(), preimage_sha256=sha256(saved), preimage_captured=captured)
    _need(r['changed_aliases'] <= r['mremap_attempts'] <= r['range_count'], 'Remap counters inconsistent')
    flags = r['flags']; claimed = bool(flags & 1)
    loader_ok = r['euid'] == 0 and r['pid'] > 0 and r['plugin_unlink'] == 0
    shared_ok = (loader_ok and r['close_errors'] == 0 and r['page_size'] == PAGE_BYTES
                 and r['cross_matches'] == r['auxv_status'] == r['source_status'] == r['remount'] == 0
                 and r['source_ino'] > 0 and r['source_nlink'] == 1
                 and r['source_mode'] & 0o170000 == 0o100000)
    if mode == 0:
        complete = (claimed and shared_ok and r['phase'] == 3 and r['native_status'] == r['readonly'] == 0
                    and flags == 193 and r['mremap_attempts'] == r['changed_aliases'] == r['anon_bytes']
                    == r['bytes_truncated'] == 0 and not any(scratch))
    else:
        complete = (claimed and shared_ok and r['phase'] == 9 and r['native_status'] == r['readonly']
                    and r['readonly'] in (0, -16) and flags == (251 if r['range_count'] else 249)
                    and r['mremap_attempts'] == r['changed_aliases'] == r['range_count']
                    and r['anon_bytes'] == total and r['bytes_truncated'] == p['owned_tail']['size'])
    _need(not claimed or complete, 'Native completion lacks exact success proofs')
    if complete:
        stat = struct.unpack_from('<QQIIII', raw, 416)
        _need(stat == (r['source_dev'], r['source_ino'], r['source_mode'], r['source_nlink'],
                       r['source_uid'], r['source_gid']) and struct.unpack_from('<q', raw, 464)[0] == r['source_size'],
              'Raw source stat and admitted core identity differ')
    dangerous = bool(mode == 1 and not complete and (r['mremap_attempts'] or flags & (2 | 4 | 16)
                     or r['changed_aliases'] or r['bytes_truncated'] or r['phase'] >= 7))
    unknown = bool(flags & 4 or dangerous)
    safe = bool(loader_ok and not r['close_errors'] and not unknown
                and (complete or (r['readonly'] == 0 and not r['mremap_attempts']
                                  and not r['changed_aliases'] and not r['bytes_truncated'])))
    _need(r['pid'] == p['runtime']['process_id'], 'Bound runtime PID differs')
    r.update(runtime_original_eof_verified=bool(complete), restoration_executed=bool(mode==1 and complete), inspect_only=False,
             schema=FAMILY, magic=MAGIC.decode(), nonce=nonce16.hex(), plan_id=p['plan_id'],
             ranges=rows, scratch_addresses=scratch, raw_source_stat_hex=raw[416:544].hex(),
             complete=bool(complete), native_complete=bool(complete), cleanup_safe=safe,
             loader_unlink_verified=loader_ok, preimage_captured=captured,
             safe_inspect_refusal=bool(mode == 0 and not complete and safe),
             mapping_state_unknown=unknown, truncated=bool(flags & 32),
             full_file_restore_complete=False, full_readback_required=True,
             no_automatic_retry=True, source_prefix_overwrite=False, NOR_write=False, WBI_write=False,
             report_sha256=sha256(raw))
    r['range_fingerprint_sha256'] = _fingerprint(p, r)
    return r


def render_header(plan):
    p = validate_plan(plan)
    array = lambda raw: '{' + ','.join(map(str, raw)) + '}'
    return ('/* Private, generated only from this user-supplied restoration plan. */\n'
            '#define TR_PATH ' + json.dumps(p['resource_path']) + '\n'
            f'#define TR_SOURCE_SIZE {p["source"]["size"]}UL\n'
            f'#define TR_TARGET_SIZE {p["target"]["size"]}UL\n'
            'static const u8 tr_plan_id[32]=' + array(bytes.fromhex(p['plan_id'])) + ';\n'
            'static const u8 tr_expected_shadow[]=' + array(bytes.fromhex(p['expected_shadow_hex'])) + ';\n'
            'static const u8 tr_runtime_shadow[]=' + array(bytes.fromhex(p['runtime_shadow_hex']) or bytes(1)) + ';\n'
            f'#define TR_PID {p["runtime"]["process_id"]}UL\n'
            'static const char tr_boot_id[]=' + json.dumps(p['runtime']['boot_id']) + ';\n').encode()


def descriptor(path):
    path = Path(path).resolve(); raw = path.read_bytes()
    return dict(path=str(path), size=len(raw), sha256=sha256(raw))


def _save(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data); stream.flush(); os.fsync(stream.fileno())


def build(plan, output, *, compiler):
    """Compile two byte-identical small ELFs using supplied offline Zig0.13."""
    p = validate_plan(plan); out = Path(output).absolute()
    _need(not out.exists() and out.parent.is_dir() and not any(x.is_symlink() for x in (out, *out.parents)),
          'A new real private output directory is required')
    command = [os.fspath(compiler)] if isinstance(compiler, (str, os.PathLike)) else list(compiler or ())
    _need(command and all(isinstance(x, str) and x for x in command), 'Explicit offline Zig0.13 compiler command required')
    source = SOURCE; initial = source.read_bytes()
    _need(sha256(initial) == NATIVE_SOURCE_SHA256, 'Reviewed portable native source pin differs')
    out.mkdir(mode=0o700)
    header = out / 'tail-plan.private.h'; _save(header, render_header(p))
    _save(out / 'plan.private.json', canonical(p) + b'\n')
    env = dict(os.environ, ZIG_GLOBAL_CACHE_DIR=str(out / 'zig-global'), ZIG_LOCAL_CACHE_DIR=str(out / 'zig-local'))
    version = subprocess.run(command + ['version'], capture_output=True, text=True, check=True, timeout=30, env=env).stdout.strip()
    _need(version == '0.13.0', 'Reviewed offline Zig0.13.0 required')
    args = command + ['cc', '-target', 'aarch64-linux-gnu', '-std=c11', '-DPATCH_MANIFEST="' + str(header) + '"']
    subprocess.run(args + ['-DTARGET_ABI', '-c', str(source), '-o', str(out / 'abi.o')],
                   capture_output=True, check=True, timeout=120, env=env)
    args += ['-Os', '-shared', '-fPIC', '-ffreestanding', '-fno-builtin', '-fno-stack-protector',
             '-fno-unwind-tables', '-fno-asynchronous-unwind-tables', '-nostdlib', '-g0',
             '-Wl,--strip-debug', '-Wl,--no-undefined', '-Wl,--build-id=none', '-Wl,-Bsymbolic', '-Wl,-z,noexecstack']
    raws = []
    for name in ('tail-restore.so', 'tail-restore-repeat.so'):
        path = out / name
        subprocess.run(args + ['-o', str(path), str(source)], capture_output=True, check=True, timeout=180, env=env)
        raw = path.read_bytes()
        _need(0 < len(raw) < 65536 and raw[:7] == b'\x7fELF\x02\x01\x01'
              and struct.unpack_from('<HH', raw, 16) == (3, 183), 'Every upload must be an AArch64 shared ELF below65536B')
        path.chmod(0o600); raws.append(raw)
    _need(raws[0] == raws[1] and source.read_bytes() == initial
          and header.read_bytes() == render_header(p), 'Double-build/source/header identity differs')
    result = dict(schema=FAMILY, plan_id=p['plan_id'], worker=descriptor(out / 'tail-restore.so'),
                  native_source=descriptor(source), builder=descriptor(__file__), manifest=descriptor(header),
                  plan=descriptor(out / 'plan.private.json'), double_build_identical=True, target_ABI_checked=True,
                  allowed_modes=[0, 1], request_path=REQUEST_PATH, result_path=RESULT_PATH,
                  request_bytes=REQUEST_BYTES, max_report=MAX_REPORT, VFAT_minimum_reserve_bytes=VFAT_MINIMUM_RESERVE_BYTES,
                  source=p['source'], target=p['target'], source_prefix_overwrite=False,
                  no_NOR_write=True, no_WBI_write=True, no_automatic_retry=True,
                  camera_io=False, network_io=False, device_validation='NOT_PERFORMED')
    _save(out / 'build.private.json', canonical(result) + b'\n')
    return result
