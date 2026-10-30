# SPDX-License-Identifier: MIT
"""Offline original-backup UXC prefix-delta plan/compiler/protocol.

Only the current bytes versus the earliest full unmodified backup determine
changes. This helper does not model feature uninstalls. Its generated private
worker changes bounded original-prefix windows while preserving any append tail.
The product validates original-backup/body/runtime proof provenance and owns
transport, WBI and unified final boot verification. No device I/O occurs here.
"""
from __future__ import annotations
from copy import deepcopy
import hashlib
import heapq
import json
import os
from pathlib import Path
import re
import struct
import subprocess

ROOT = Path(__file__).resolve().parent
FAMILY = 'a7m4-owned-resource-prefix-delta/1'
PLAN_SCHEMA = 'a7m4-owned-resource-prefix-delta-plan/1'
AUTHORITY_SCHEMA = 'a7m4-owned-tail-authority/1'
MAX_FILE_BYTES, MAX_WINDOWS, MAX_WINDOW_BYTES, MAX_WINDOW_TOTAL_BYTES = 16777216, 128, 512, 16384
VFAT_MINIMUM_RESERVE_BYTES = 8388608
_SHA = re.compile(r'[0-9a-f]{64}\Z')
LANGUAGES = ('english', 'simplifiedchinese', 'traditionalchinese')
RESOURCE_FILENAMES = tuple(sorted(
    [f'string_{language}_{direction}.uxc' for language in LANGUAGES
     for direction in ('horizontal', 'vertical')]
    + ['image_00_23_IPSX.uxc', 'image_00_32_IPSX.uxc']))
RESOURCE_PATHS = tuple('/usr/share/app/' + name for name in RESOURCE_FILENAMES)

assert len(RESOURCE_PATHS) == 8


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


def _validate_authority(authority, source_sha256):
    names = {'original_backup_sha256', 'current_file_readback_sha256',
             'resource_reference_proof_sha256', 'boot_or_load_proof_sha256'}
    _need(type(authority) is dict and set(authority) == names | {'schema'}
          and authority['schema'] == AUTHORITY_SCHEMA and all(_hash(authority[k]) for k in names)
          and authority['current_file_readback_sha256'] == source_sha256,
          'Typed original-backup/current-read/reference/runtime digests required; current SHA must match source')
    return deepcopy(authority)


def _plan_digest(plan):
    return sha256(canonical({k: v for k, v in plan.items() if k != 'plan_id'}))


def _windows(source, target):
    # Keep exact changed runs, then merge adjacent runs only when the total
    # small-window budget permits. Greedy smallest-gap merges minimize padding
    # introduced at each step, without copying an entire bank to Jiritsu.
    runs = []
    begin = None; changed_count = 0
    for at, (before, after) in enumerate(zip(source, target)):
        if before != after:
            changed_count += 1
            _need(changed_count <= MAX_WINDOW_TOTAL_BYTES, 'Original-prefix diff exceeds16384 changed bytes')
            if begin is None:
                begin = at
        elif begin is not None:
            runs.extend((offset, min(offset + MAX_WINDOW_BYTES, at))
                        for offset in range(begin, at, MAX_WINDOW_BYTES))
            begin = None
    if begin is not None:
        runs.extend((offset, min(offset + MAX_WINDOW_BYTES, len(target)))
                    for offset in range(begin, len(target), MAX_WINDOW_BYTES))
    total = sum(end - start for start, end in runs)
    _need(total <= MAX_WINDOW_TOTAL_BYTES, 'Original-prefix diff exceeds 16384 changed bytes')
    if len(runs) > MAX_WINDOWS:
        # Heap-bound adjacent merges avoid quadratic behavior for a sparse
        # but still bounded sixteen-thousand-byte difference set.
        starts, ends = [x[0] for x in runs], [x[1] for x in runs]
        previous, following = list(range(-1, len(runs) - 1)), list(range(1, len(runs) + 1))
        following[-1] = -1
        alive, heap, count = [True] * len(runs), [], len(runs)

        def offer(left):
            right = following[left] if left >= 0 else -1
            if right >= 0 and ends[right] - starts[left] <= MAX_WINDOW_BYTES:
                heapq.heappush(heap, (starts[right] - ends[left], left, right))

        for index in range(len(runs) - 1):
            offer(index)
        while count > MAX_WINDOWS:
            _need(heap, 'Original-prefix diff cannot fit128 windows of at most512 bytes')
            gap, left, right = heapq.heappop(heap)
            if not alive[left] or not alive[right] or following[left] != right:
                continue
            if gap != starts[right] - ends[left] or ends[right] - starts[left] > MAX_WINDOW_BYTES:
                continue
            _need(total + gap <= MAX_WINDOW_TOTAL_BYTES, 'Window merge padding exceeds16384-byte manifest budget')
            ends[left], following[left], alive[right] = ends[right], following[right], False
            if following[left] >= 0:
                previous[following[left]] = left
            total += gap; count -= 1
            offer(previous[left]); offer(left)
        runs = [(starts[i], ends[i]) for i in range(len(runs)) if alive[i]]
    return [dict(offset=start, before_hex=source[start:end].hex(), after_hex=target[start:end].hex())
            for start, end in runs]


def make_plan(resource_path, source, target, *, authority):
    """Compare complete current bytes to a selected original-backup member.

    Source may contain an owned append tail; this step leaves it byte-for-byte
    intact. The product proves that target is the selected member of the earliest
    complete unmodified backup identified by authority.original_backup_sha256.
    The four proof digests share the tail helper's typed authority structure;
    no known installation receipt or new-boot ceremony is inherently required.
    Proof sufficiency is validated by the product, not by accepting this dict.
    """
    _need(resource_path in RESOURCE_PATHS, 'Only the seventy exact UXC paths are supported')
    source, target = _bytes(source, 'current source'), _bytes(target, 'original backup target')
    _need(0 < len(target) <= len(source) <= MAX_FILE_BYTES, 'Positive source>=original target, at most16MiB required')
    _validate_authority(authority, sha256(source))
    windows = _windows(source, target)
    post = target + source[len(target):]
    plan = dict(schema=PLAN_SCHEMA, family=FAMILY, resource_path=resource_path,
                source=_identity(source), target=_identity(target), post=_identity(post),
                retained_tail=_identity(source[len(target):]), windows=windows,
                window_total_bytes=sum(len(bytes.fromhex(row['before_hex'])) for row in windows),
                changed_bytes=sum(a != b for a, b in zip(source, target)),
                no_op=not windows, authority=deepcopy(authority))
    plan['plan_id'] = _plan_digest(plan)
    return validate_plan(plan)


def validate_plan(plan):
    keys = {'schema', 'family', 'resource_path', 'source', 'target', 'post', 'retained_tail', 'windows',
            'window_total_bytes', 'changed_bytes', 'no_op', 'authority', 'plan_id'}
    _need(type(plan) is dict and set(plan) == keys and plan['schema'] == PLAN_SCHEMA
          and plan['family'] == FAMILY and plan['resource_path'] in RESOURCE_PATHS, 'Exact original-resource delta plan required')
    for name in ('source', 'target', 'post', 'retained_tail'):
        row = plan[name]
        _need(type(row) is dict and set(row) == {'size', 'sha256'} and type(row['size']) is int
              and _hash(row['sha256']), 'Exact complete endpoint size/SHA required')
    source, target = plan['source']['size'], plan['target']['size']
    _need(0 < target <= source <= MAX_FILE_BYTES and plan['post']['size'] == source
          and plan['retained_tail']['size'] == source - target, 'Delta must preserve source EOF and original-prefix length')
    rows = plan['windows']; _need(type(rows) is list and len(rows) <= MAX_WINDOWS, 'At most128 bounded windows required')
    total = changed = end = 0
    for row in rows:
        _need(type(row) is dict and set(row) == {'offset', 'before_hex', 'after_hex'}
              and type(row['offset']) is int and row['offset'] >= end
              and type(row['before_hex']) is str and type(row['after_hex']) is str,
              'Ordered disjoint exact original-prefix windows required')
        try:
            before, after = bytes.fromhex(row['before_hex']), bytes.fromhex(row['after_hex'])
        except ValueError as exc:
            raise ValueError('Canonical before/after window hex required') from exc
        _need(0 < len(before) == len(after) <= MAX_WINDOW_BYTES
              and before.hex() == row['before_hex'] and after.hex() == row['after_hex']
              and before != after and row['offset'] + len(before) <= target,
              'Each changed window must remain entirely inside the original prefix')
        total += len(before); changed += sum(a != b for a, b in zip(before, after)); end = row['offset'] + len(before)
    _need(type(plan['window_total_bytes']) is int and total == plan['window_total_bytes'] <= MAX_WINDOW_TOTAL_BYTES
          and type(plan['changed_bytes']) is int and changed == plan['changed_bytes']
          and type(plan['no_op']) is bool and plan['no_op'] == (not rows), 'Exact window budgets/no-op classification differ')
    _validate_authority(plan['authority'], plan['source']['sha256'])
    _need(_hash(plan['plan_id']) and plan['plan_id'] == _plan_digest(plan), 'Delta plan identity/content differs')
    return deepcopy(plan)


def verify_source(plan, raw):
    """Fresh whole Mac source read, before any native application."""
    p = validate_plan(plan); raw = _bytes(raw, 'source')
    _need(_identity(raw) == p['source'] and _identity(raw[p['target']['size']:]) == p['retained_tail'],
          'Full source EOF/SHA or retained tail differs')
    restored = bytearray(raw)
    for row in p['windows']:
        before, after = bytes.fromhex(row['before_hex']), bytes.fromhex(row['after_hex']); at = row['offset']
        _need(raw[at:at + len(before)] == before, 'Fresh source window preimage differs')
        restored[at:at + len(after)] = after
    _need(_identity(restored) == p['post'] and _identity(restored[:p['target']['size']]) == p['target'],
          'Delta does not reconstruct the complete original backup prefix')
    return dict(status='FULL_SOURCE_MAC_VERIFIED', plan_id=p['plan_id'], identity=p['source'])


def verify_readback(plan, raw):
    """Fresh complete resulting file, including unchanged append-tail bytes."""
    p = validate_plan(plan); raw = _bytes(raw, 'post-delta file')
    _need(_identity(raw) == p['post'] and _identity(raw[:p['target']['size']]) == p['target']
          and _identity(raw[p['target']['size']:]) == p['retained_tail'], 'Post delta full EOF/SHA/original-prefix/tail differs')
    return dict(status='FULL_POST_MAC_VERIFIED', plan_id=p['plan_id'], identity=p['post'],
                original_prefix_identity=p['target'], retained_tail_identity=p['retained_tail'])

# Native request identity fields deliberately come from fresh native inspection,
# never from an old camera receipt or a caller-chosen address.
REQUEST_PATH = '/tmp/jiritsu/a7m4.resource-delta.request'
RESULT_PATH = '/tmp/jiritsu/a7m4.resource-delta.result'
LIBRARY_PATH = '/tmp/jiritsu/libJit.so'
PENDING_PATH = None
REQUEST_BYTES = 256
MIN_REPORT = MAX_REPORT = 544
MAGIC = b'A7RD0001'
PREFIX = struct.Struct('<8sII16s32s8I9q3Q4I4Q4I')
RQ = struct.Struct('<8sII16s32sQ3Q4I2Q')
MAPPING = struct.Struct('<4Q')
NATIVE_SOURCE_SHA256='c1c70c7bb453ed4fb3c67c8b00a2e1490db61bb00c350f549b226d8407fffc17'
assert PREFIX.size == 256 and RQ.size == 128


def _nonce(value):
    _need(type(value) is bytes and len(value) == 16 and any(value), 'Fresh nonzero16-byte nonce required')
    return value


def _core(report):
    return tuple(report[k] for k in ('source_dev', 'source_ino', 'source_size',
                                    'source_mode', 'source_uid', 'source_gid', 'source_nlink'))


def _fingerprint(plan, report):
    return sha256(canonical(dict(plan_id=plan['plan_id'], pid=report['pid'], identity=list(_core(report)),
        mappings=[{k: row[k] for k in ('va', 'len', 'off', 'prot')} for row in report['mappings']])))


def mapping_metadata(report):
    return {k: deepcopy(report[k]) for k in ('pid', 'source_dev', 'source_ino', 'source_size',
            'source_mode', 'source_uid', 'source_gid', 'source_nlink', 'mappings',
            'mapping_fingerprint_sha256', 'cow_segments_expected', 'cow_bytes_expected', 'cross_pids', 'cross_matches')}


def request(plan, mode, nonce16, inspection=None):
    p = validate_plan(plan); _nonce(nonce16)
    _need(not p['no_op'], 'No-diff files require no native worker or device writes')
    _need(type(mode) is int and mode in (0, 1), 'Only inspection0/apply1 permitted')
    plan_id = bytes.fromhex(p['plan_id'])
    if mode == 0:
        _need(inspection is None, 'Inspection derives native current identity/mappings')
        return RQ.pack(MAGIC, 0, 0, nonce16, plan_id, *([0] * 10)) + bytes(128)
    _need(type(inspection) is dict and inspection.get('schema') == FAMILY and inspection.get('plan_id') == p['plan_id']
          and inspection.get('mode') == 0 and inspection.get('complete') is True and inspection.get('cleanup_safe') is True,
          'Successful same-plan native inspection required')
    _need(inspection['mapping_fingerprint_sha256'] == _fingerprint(p, inspection), 'Inspection source/PID/mappings changed')
    rows = inspection['mappings']; _need(len(rows) <= 4, 'At most4 native-derived source VMAs required')
    encoded = b''.join(MAPPING.pack(*(row[k] for k in ('va', 'len', 'off', 'prot'))) for row in rows)
    return RQ.pack(MAGIC, 1, len(rows), nonce16, plan_id, inspection['pid'], *_core(inspection),
                   p['target']['size'], 0) + encoded + bytes(128 - len(encoded))


def _expected_cow(plan, mappings):
    segments = total = 0
    for mapping in mappings:
        for window in plan['windows']:
            begin = max(mapping['off'], window['offset'])
            end = min(mapping['off'] + mapping['len'], window['offset'] + len(bytes.fromhex(window['before_hex'])))
            if begin < end:
                segments += 1; total += end - begin
    return segments, total


def parse_report(plan, raw, mode, nonce16):
    p = validate_plan(plan); _nonce(nonce16)
    _need(not p['no_op'] and type(mode) is int and mode in (0, 1) and type(raw) is bytes and len(raw) == MAX_REPORT,
          'Exact544-byte native report for a nonempty delta required')
    keys = ('magic', 'version', 'mode', 'nonce', 'plan_id', 'phase', 'index', 'mapping_count',
            'cross_pids', 'cross_matches', 'cow_attempts', 'cow_segments', 'flags', 'native_status',
            'euid', 'pid', 'plugin_unlink', 'close_errors', 'readonly', 'remount', 'auxv_status',
            'source_status', 'source_dev', 'source_ino', 'source_size', 'source_mode', 'source_uid',
            'source_gid', 'source_nlink', 'target_size', 'page_size', 'bytes_written', 'bytes_cow_preserved',
            'total', 'window_count', 'write_attempts', 'writes_completed')
    r = dict(zip(keys, PREFIX.unpack_from(raw)))
    _need((r['magic'], r['version'], r['mode'], r['nonce'], r['plan_id'], r['total']) ==
          (MAGIC, 1, mode, nonce16, bytes.fromhex(p['plan_id']), len(raw)), 'Report framing/mode/plan/nonce differs')
    _need((r['source_size'], r['target_size'], r['window_count']) ==
          (p['source']['size'], p['target']['size'], len(p['windows']))
          and r['mapping_count'] <= 4 and not r['flags'] & ~1023, 'Fixed source/target/windows/report bounds differ')
    rows = []
    for i in range(4):
        values = MAPPING.unpack_from(raw, 256 + i * 32)
        if i >= r['mapping_count']:
            _need(not any(values), 'Unused mapping slot differs'); continue
        row = dict(zip(('va', 'len', 'off', 'prot'), values))
        _need(row['va'] > 0 and not (row['va'] | row['len'] | row['off']) & 4095
              and 0 < row['len'] and row['va'] + row['len'] < 1 << 64
              and row['off'] + row['len'] < 1 << 64 and row['prot'] == 1
              and (not rows or row['va'] >= rows[-1]['va'] + rows[-1]['len']),
              'Only ordered disjoint native private read-only source VMAs are admitted')
        _need(any(max(row['off'], win['offset']) < min(row['off'] + row['len'],
                   win['offset'] + len(bytes.fromhex(win['before_hex']))) for win in p['windows']),
              'Reported source VMA has no delta window intersection')
        rows.append(row)
    expected_segments, expected_bytes, offender_pid, reserved = struct.unpack_from('<4Q', raw, 384)
    _need(reserved == 0 and expected_segments <= 4 * MAX_WINDOWS and expected_bytes <= 4 * MAX_WINDOW_TOTAL_BYTES,
          'Bounded COW proof diagnostics required')
    _need(r['cow_segments'] <= r['cow_attempts'] <= expected_segments
          and r['writes_completed'] <= r['write_attempts'] <= len(p['windows'])
          and r['bytes_written'] <= p['window_total_bytes'] and r['bytes_cow_preserved'] <= expected_bytes,
          'COW/file-write counters inconsistent')
    flags = r['flags']; claimed = bool(flags & 1)
    loader_ok = r['euid'] == 0 and r['pid'] > 0 and r['plugin_unlink'] == 0
    common = (loader_ok and r['close_errors'] == 0 and r['page_size'] == 4096
              and r['cross_matches'] == r['auxv_status'] == r['source_status'] == r['remount'] == 0
              and r['source_ino'] > 0 and r['source_nlink'] == 1 and r['source_mode'] & 0o170000 == 0o100000
              and (expected_segments, expected_bytes) == _expected_cow(p, rows))
    if mode == 0:
        complete = (claimed and common and r['phase'] == 3 and r['native_status'] == r['readonly'] == 0
                    and flags == 193 and r['cow_attempts'] == r['cow_segments'] == r['bytes_written']
                    == r['bytes_cow_preserved'] == r['write_attempts'] == r['writes_completed'] == 0)
    else:
        complete = (claimed and common and r['phase'] == 9 and r['native_status'] == r['readonly']
                    and r['readonly'] in (0, -16) and flags == (763 if expected_segments else 761)
                    and r['cow_attempts'] == r['cow_segments'] == expected_segments
                    and r['bytes_cow_preserved'] == expected_bytes
                    and r['write_attempts'] == r['writes_completed'] == len(p['windows'])
                    and r['bytes_written'] == p['window_total_bytes'])
    _need(not claimed or complete, 'Native completion lacks exact COW/file proofs')
    if complete:
        stat = struct.unpack_from('<QQIIII', raw, 416)
        _need(stat == (r['source_dev'], r['source_ino'], r['source_mode'], r['source_nlink'],
                       r['source_uid'], r['source_gid']) and struct.unpack_from('<q', raw, 464)[0] == r['source_size'],
              'Raw source stat differs from admitted source identity')
    cow_verified = bool(flags & 8 and r['cow_attempts'] == r['cow_segments'] == expected_segments
                        and r['bytes_cow_preserved'] == expected_bytes)
    attempted_file = bool(flags & 16 or r['write_attempts'] or r['bytes_written'] or r['writes_completed'])
    unknown = bool(flags & (4 | 256) or (mode == 1 and not complete and
                   ((r['cow_attempts'] and not cow_verified) or attempted_file)))
    safe = bool(loader_ok and not r['close_errors'] and not unknown and
                (complete or (r['readonly'] == 0 and not attempted_file and
                              (not r['cow_attempts'] or cow_verified))))
    r.update(schema=FAMILY, magic=MAGIC.decode(), nonce=nonce16.hex(), plan_id=p['plan_id'], mappings=rows,
             cow_segments_expected=expected_segments, cow_bytes_expected=expected_bytes, offender_pid=offender_pid,
             complete=bool(complete), native_complete=bool(complete), cleanup_safe=safe,
             loader_unlink_verified=loader_ok, cow_verified=cow_verified,
             post_runtime_preserved_verified=bool(flags & 512 and not flags & 4),
             safe_inspect_refusal=bool(mode == 0 and not complete and safe),
             mapping_state_unknown=bool(flags & 4 or (r['cow_attempts'] and not cow_verified and not complete)),
             file_state_unknown=bool(flags & 256 or attempted_file and not complete),
             operation_state_unknown=unknown, raw_source_stat_hex=raw[416:544].hex(), report_sha256=sha256(raw),
             resource_prefix_restore_complete=False, full_file_restore_complete=False,
             full_readback_required=True, source_eof_preserved=True, append_tail_preserved=True,
             automatic_retry_allowed=False, WBI_write=False, NOR_write=False)
    r['mapping_fingerprint_sha256'] = _fingerprint(p, r)
    return r


def render_header(plan):
    p = validate_plan(plan)
    _need(not p['no_op'], 'No-diff files need no native compilation')
    array = lambda raw: '{' + ','.join(map(str, raw)) + '}'
    lines = ['/* Private, generated from complete current/original backup bytes. */',
             '#define RD_PATH ' + json.dumps(p['resource_path']),
             f'#define RD_SOURCE_SIZE {p["source"]["size"]}UL',
             f'#define RD_TARGET_SIZE {p["target"]["size"]}UL',
             'static const u8 rd_plan_id[32]=' + array(bytes.fromhex(p['plan_id'])) + ';']
    for i, row in enumerate(p['windows']):
        for side in ('before', 'after'):
            lines.append(f'static const u8 rd_{side}_{i}[]=' + array(bytes.fromhex(row[side + '_hex'])) + ';')
    windows = ['{' + str(row['offset']) + 'UL,' + str(len(bytes.fromhex(row['before_hex'])))
               + ',rd_before_' + str(i) + ',rd_after_' + str(i) + '}' for i, row in enumerate(p['windows'])]
    lines.append('static const struct DeltaWindow rd_windows[]={' + ','.join(windows) + '};')
    return ('\n'.join(lines) + '\n').encode()


def descriptor(path):
    path = Path(path).resolve(); raw = path.read_bytes()
    return dict(path=str(path), size=len(raw), sha256=sha256(raw))


def _save(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data); stream.flush(); os.fsync(stream.fileno())


def build(plan, output, *, compiler):
    p = validate_plan(plan); _need(not p['no_op'], 'No-diff resources need no native job')
    source = ROOT / 'native' / 'prefix_delta.c'; initial = source.read_bytes()
    _need(_hash(NATIVE_SOURCE_SHA256) and sha256(initial) == NATIVE_SOURCE_SHA256, 'Reviewed native source pin differs')
    out = Path(output).absolute()
    _need(not out.exists() and out.parent.is_dir() and not any(x.is_symlink() for x in (out, *out.parents)),
          'New real private build directory required')
    command = [os.fspath(compiler)] if isinstance(compiler, (str, os.PathLike)) else list(compiler or ())
    _need(command and all(type(x) is str and x for x in command), 'Explicit offline Zig0.13 compiler command required')
    out.mkdir(mode=0o700); header = out / 'delta-plan.private.h'; _save(header, render_header(p))
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
    for name in ('resource-delta.so', 'resource-delta-repeat.so'):
        output_path = out / name
        subprocess.run(args + ['-o', str(output_path), str(source)], capture_output=True, check=True, timeout=180, env=env)
        raw = output_path.read_bytes()
        _need(0 < len(raw) < 65536 and raw[:7] == b'\x7fELF\x02\x01\x01'
              and struct.unpack_from('<HH', raw, 16) == (3, 183), 'Every AArch64 shared ELF upload must be below65536B')
        output_path.chmod(0o600); raws.append(raw)
    _need(raws[0] == raws[1] and source.read_bytes() == initial and header.read_bytes() == render_header(p),
          'Native source/header/double-build identity differs')
    result = dict(schema=FAMILY, plan_id=p['plan_id'], worker=descriptor(out / 'resource-delta.so'),
                  native_source=descriptor(source), builder=descriptor(__file__), manifest=descriptor(header),
                  plan=descriptor(out / 'plan.private.json'), double_build_identical=True, target_ABI_checked=True,
                  allowed_modes=[0, 1], request_path=REQUEST_PATH, result_path=RESULT_PATH, request_bytes=REQUEST_BYTES,
                  max_report=MAX_REPORT, VFAT_minimum_reserve_bytes=VFAT_MINIMUM_RESERVE_BYTES,
                  source=p['source'], target=p['target'], post=p['post'], source_eof_preserved=True,
                  append_tail_preserved=True, truncate=False, no_NOR_write=True, no_WBI_write=True,
                  no_automatic_retry=True, camera_io=False, network_io=False, device_validation='NOT_PERFORMED')
    _save(out / 'build.private.json', canonical(result) + b'\n')
    return result
