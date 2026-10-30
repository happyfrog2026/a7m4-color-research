# SPDX-License-Identifier: MIT
"""Offline /usr read-only finalizer builder and strict wire codec.

There is no transport, device enumeration, deployment, SSH or network API.
The product NativeActions owner supplies fresh plan+nonce per invocation,
uploads the fixed packets, and obtains the final fixed report only after the
constructor returns. Missing/short/unknown/close-failed reports are rejected.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import struct
import subprocess

ROOT = Path(__file__).resolve().parent
FAMILY = 'a7m4-usr-ro/1'
PLAN_SCHEMA = 'a7m4-usr-ro-plan/1'
SOURCE_POLICY = 'm4-exact-/dev/nflasha15-/usr-ext2-no-nested/1'
REQUEST_PATH = '/tmp/jiritsu/a7m4.usr-ro.request'
RESULT_PATH = '/tmp/jiritsu/a7m4.usr-ro.result'
PENDING_PATH = '/tmp/jiritsu/a7m4.usr-ro.result.pending'
LIBRARY_PATH = '/tmp/jiritsu/libJit.so'
REQUEST_MAGIC, REPORT_MAGIC = b'A7URQ001', b'A7URR001'
REQUEST_BYTES, MIN_REPORT, MAX_REPORT = 80, 256, 256
VFAT_MINIMUM_RESERVE_BYTES = 8388608
RQ = struct.Struct('<8sII16s32s16s')
REPORT = struct.Struct('<8sII80s4I11q5Q4I')
NATIVE_SOURCE_SHA256 = '8514501812fd6a54459055290407aaa04ac5c0fe234a42a983ca6e0a55a01628'
_HEX = re.compile(r'[0-9a-f]{64}\Z')
assert RQ.size == 80 and REPORT.size == 256


def _need(condition, message):
    if not condition:
        raise ValueError(message)


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def make_plan():
    """Create a fresh random compile-bound plan, without device/body inputs."""
    return validate_plan(dict(schema=PLAN_SCHEMA, family=FAMILY,
                              plan_id=secrets.token_hex(32), source_policy=SOURCE_POLICY))


def validate_plan(plan):
    _need(type(plan) is dict and set(plan) == {'schema', 'family', 'plan_id', 'source_policy'}
          and plan['schema'] == PLAN_SCHEMA and plan['family'] == FAMILY
          and plan['source_policy'] == SOURCE_POLICY,
          'Exact /usr-only plan and source policy required')
    _need(type(plan['plan_id']) is str and bool(_HEX.fullmatch(plan['plan_id']))
          and plan['plan_id'] != '0' * 64, 'Fresh nonzero 32-byte plan identity required')
    return deepcopy(plan)


def _nonce(nonce16):
    _need(type(nonce16) is bytes and len(nonce16) == 16 and any(nonce16),
          'Fresh nonzero 16-byte nonce required')
    return nonce16


def request(plan, nonce16):
    """Encode the only operation; the packet cannot request RW or another path.

    Freshness across invocations is enforced by the transport owner. A nonce
    must never be reused, including after a missing report or known EBUSY.
    """
    p = validate_plan(plan)
    return RQ.pack(REQUEST_MAGIC, 1, REQUEST_BYTES, _nonce(nonce16),
                   bytes.fromhex(p['plan_id']), bytes(16))


def parse_report(plan, raw, nonce16, *, expected_request=None):
    """Reject protocol ambiguity; return only RO state, never AP/CP health.

    RO_PENDING is a known EBUSY block with fresh valid mount observation.
    It does not permit retry, a healthy STOP, or an AP_UNKNOWN conclusion.
    Other native refusal is diagnostic only. An attempted remount with an
    unobserved/invalid post-state is rejected as unknown to this protocol.
    """
    p = validate_plan(plan)
    packet = request(p, nonce16)
    if expected_request is not None:
        _need(type(expected_request) is bytes and expected_request == packet,
              'Exact expected request packet differs')
    _need(type(raw) is bytes and len(raw) == REPORT.size,
          'Exactly 256 complete native report bytes required')
    keys = ('magic', 'version', 'total', 'exact_request', 'phase', 'flags',
            'outcome', 'mount_attempts', 'native_status', 'euid', 'pid',
            'plugin_unlink', 'proc_status', 'budget_status', 'request_status',
            'initial_mount', 'remount_status', 'final_mount', 'close_errors',
            'workspace_free', 'workspace_required', 'loader_dev', 'loader_ino',
            'loader_size', 'request_bytes', 'reserved0', 'reserved1', 'reserved2')
    r = dict(zip(keys, REPORT.unpack(raw)))
    _need((r['magic'], r['version'], r['total'], r['exact_request']) ==
          (REPORT_MAGIC, 1, REPORT.size, packet), 'Report magic/version/length/exact-packet binding differs')
    _need(not any(r[k] for k in ('reserved0', 'reserved1', 'reserved2'))
          and 1 <= r['phase'] <= 6 and r['flags'] & ~127 == 0
          and r['outcome'] in (1, 2, 3, 4) and r['mount_attempts'] in (0, 1),
          'Unknown report fields/flags/phase/outcome')
    _need(r['close_errors'] == 0, 'Native input close failure; report is not admissible')
    _need(r['request_bytes'] == REQUEST_BYTES and r['request_status'] == 0
          and r['flags'] & 1, 'Native did not admit this exact request')
    complete = r['outcome'] in (1, 2)
    pending = r['outcome'] == 3
    if complete or pending:
        _need(r['euid'] == 0 and r['pid'] > 0
              and r['plugin_unlink'] == r['proc_status'] == r['budget_status'] == 0
              and r['flags'] == (127 if complete else 63)
              and 0 < r['loader_size'] < 65536 and r['loader_ino'] > 0
              and r['workspace_required'] >= VFAT_MINIMUM_RESERVE_BYTES + 2
              and r['workspace_free'] >= r['workspace_required'],
              'Native root/loader/proc/workspace admissions missing')
        _need(r['initial_mount'] in (0, 1) and r['final_mount'] in (0, 1),
              'Fresh exact /usr ext2 mount observation required')
    if r['outcome'] == 1:
        _need((r['phase'], r['mount_attempts'], r['native_status'],
               r['initial_mount'], r['remount_status'], r['final_mount']) ==
              (6, 0, 0, 0, -1, 0), 'Already-RO no-op outcome differs')
    elif r['outcome'] == 2:
        _need((r['phase'], r['mount_attempts'], r['native_status'],
               r['initial_mount'], r['remount_status'], r['final_mount']) ==
              (6, 1, 0, 1, 0, 0), 'Remounted-RO outcome differs')
    elif pending:
        _need((r['phase'], r['mount_attempts'], r['native_status'],
               r['initial_mount'], r['remount_status']) == (5, 1, -16, 1, -16),
              'RO_PENDING requires the one EBUSY attempt and a fresh mount state')
    else:
        _need(r['native_status'] < 0 and not r['flags'] & 64
              and r['phase'] in (3, 5) and r['euid'] == 0 and r['pid'] > 0,
              'Refusal requires an explicit negative status without completion')
        if r['phase'] == 3:
            _need(r['mount_attempts'] == 0 and r['initial_mount'] < 0
                  and r['remount_status'] == r['final_mount'] == -1
                  and not r['flags'] & (16 | 32), 'Pre-mount refusal fields differ')
        else:
            _need(r['flags'] == 63 and r['plugin_unlink'] == r['budget_status'] == r['proc_status'] == 0
                  and r['final_mount'] in (0, 1)
                  and r['initial_mount'] == r['mount_attempts']
                  and (r['mount_attempts'] == 1 or r['remount_status'] == -1),
                  'Fresh post-operation state unknown; report is not admissible')
    r.pop('magic'); r.pop('exact_request')
    r.update(schema=FAMILY, plan_id=p['plan_id'], nonce=nonce16.hex(),
             request_sha256=sha256(packet), report_sha256=sha256(raw),
             state={1: 'ALREADY_RO', 2: 'REMOUNTED_RO', 3: 'RO_PENDING', 4: 'REFUSED'}[r['outcome']],
             complete=complete, readonly_confirmed=complete,
             known_ro_pending=pending, automatic_retry_permitted=False,
             healthy_stop_authorized=False, ap_state_inferred=False)
    return r


def render_header(plan):
    p = validate_plan(plan)
    return ('/* MIT; generated random plan identity, no camera inputs. */\n'
            'static const unsigned char ur_plan_id[32]={' +
            ','.join(str(x) for x in bytes.fromhex(p['plan_id'])) + '};\n').encode()


def descriptor(path):
    path = Path(path).absolute(); raw = path.read_bytes()
    return dict(path=str(path), size=len(raw), sha256=sha256(raw))


def _save(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())


def build(plan, output, *, compiler):
    """Build the small freestanding ELF twice using explicit offline Zig0.13."""
    p = validate_plan(plan); out = Path(output).absolute()
    _need(not out.exists() and out.parent.is_dir()
          and not any(x.is_symlink() for x in (out, *out.parents)),
          'A new real private output directory required')
    command = [os.fspath(compiler)] if isinstance(compiler, (str, os.PathLike)) else list(compiler or ())
    _need(command and all(type(x) is str and x for x in command), 'Explicit offline Zig compiler required')
    source = ROOT / 'native/usr_ro.c'; initial = source.read_bytes()
    _need(sha256(initial) == NATIVE_SOURCE_SHA256, 'Reviewed native source pin differs')
    out.mkdir(mode=0o700)
    header = out / 'usr-ro-plan.private.h'; _save(header, render_header(p))
    _save(out / 'plan.private.json', canonical(p) + b'\n')
    env = dict(os.environ, ZIG_GLOBAL_CACHE_DIR=str(out / 'zig-global'),
               ZIG_LOCAL_CACHE_DIR=str(out / 'zig-local'))
    version = subprocess.run(command + ['version'], capture_output=True, text=True,
                             check=True, timeout=30, env=env).stdout.strip()
    _need(version == '0.13.0', 'Offline Zig0.13.0 required')
    args = command + ['cc', '-target', 'aarch64-linux-gnu', '-std=c11',
                      '-DPLAN_MANIFEST="' + str(header) + '"']
    subprocess.run(args + ['-DTARGET_ABI', '-c', str(source), '-o', str(out / 'abi.o')],
                   capture_output=True, check=True, timeout=120, env=env)
    args += ['-Os', '-shared', '-fPIC', '-ffreestanding', '-fno-builtin', '-fno-stack-protector',
             '-fno-unwind-tables', '-fno-asynchronous-unwind-tables', '-nostdlib', '-g0',
             '-Wl,--strip-debug', '-Wl,--no-undefined', '-Wl,--build-id=none',
             '-Wl,-Bsymbolic', '-Wl,-z,noexecstack']
    binaries = []
    for name in ('usr-ro.so', 'usr-ro-repeat.so'):
        path = out / name
        subprocess.run(args + ['-o', str(path), str(source)], capture_output=True,
                       check=True, timeout=180, env=env)
        raw = path.read_bytes()
        _need(0 < len(raw) < 65536 and raw[:7] == b'\x7fELF\x02\x01\x01'
              and struct.unpack_from('<HH', raw, 16) == (3, 183), 'AArch64 shared ELF below65536B required')
        path.chmod(0o600); binaries.append(raw)
    _need(binaries[0] == binaries[1] and source.read_bytes() == initial
          and header.read_bytes() == render_header(p), 'Double-build/source/header differs')
    built = dict(schema=FAMILY, plan_id=p['plan_id'], worker=descriptor(out / 'usr-ro.so'),
                 native_source=descriptor(source), builder=descriptor(__file__),
                 manifest=descriptor(header), plan=descriptor(out / 'plan.private.json'),
                 request_path=REQUEST_PATH, result_path=RESULT_PATH, pending_path=PENDING_PATH,
                 request_bytes=REQUEST_BYTES, min_report=MIN_REPORT, max_report=MAX_REPORT,
                 double_build_identical=True, target_ABI_checked=True,
                 VFAT_minimum_reserve_bytes=VFAT_MINIMUM_RESERVE_BYTES,
                 mount_flags=0xc31, maximum_mount_attempts=1,
                 camera_io=False, network_io=False, device_validation='NOT_PERFORMED')
    _save(out / 'build.private.json', canonical(built) + b'\n')
    return built
