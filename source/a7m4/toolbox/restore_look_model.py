"""M4 6.02 restore safety boundary, without an unproved model setter.

Factory WRITE/SAVE and this proof are separate operations. The coordinator
first saves ST while the installed programs remain present, then requires a
new boot and proves the actual AP model agrees before removing any program.
This module never writes settings or AP memory. Importing performs no I/O.
"""
from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import re
import struct
import subprocess

from .native_actions import NativeActions

SCHEMA = 'a7m4-602-restore-look-model/1'
AP_SHA256 = '1e1b9202eaa69198f20df03dbfdab2f103b206cc4ebcd2e7bd817e6a710018a2'
AP_SIZE = 98212632
CURRENT = (0, 0x02CF0311)
BASE_KEYS = tuple((0, 0x02CF0000 | low) for first in (0x0D0B, 0x12E9, 0x1309)
                  for low in range(first, first + 12, 2))
FIELDS = (CURRENT, *BASE_KEYS)
ATTRS, LENGTH = 0x60, 1
CURRENT_VA = 0x7FEEA70
BASE_VAS = (0x802CE08, 0x802D120, 0x802D438)
GETTERS = (0x28F7680, 0x290E6AC, 0x290E6D4, 0x290E6FC)
GUARD_BYTES = 20
SOURCE = Path(__file__).with_name('data') / 'restore-look-model.c'
SOURCE_SHA256='6242659a9a3abafea76973342adb7d5703b654188fac91ca3ba2a41d3177667e'
REQUEST_PATH = '/tmp/jiritsu/a7m4.restore-look-model.request'
RESULT_PATH = '/tmp/jiritsu/a7m4.restore-look-model.result'
REQUEST = struct.Struct('<8s16s32s8s')
REPORT = struct.Struct('<8sII16s32s5qQ4I54I54I40s8s')
UUID = re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z')


def _need(condition, message):
    if not condition:
        raise ValueError(message)


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def validate_four_plane_st(snapshot):
    """Check precisely the current selection and eighteen base records.

    No requirement is made of unrelated E/F values, or CP presets. The caller
    owns authentication of the complete settings captures and body identity.
    """
    evidence = {}
    for plane in ('ram', 'saved', 'bin', 'bak'):
        records = getattr(snapshot, plane).records
        rows = []
        for pair in FIELDS:
            value = records.get(pair)
            _need(value is not None and type(value.attrs) is int and value.attrs == ATTRS
                  and type(value.data) is bytes and len(value.data) == LENGTH,
                  'Restore ST safety record missing or wrong attrs/length: %s/%08x' % (plane, pair[1]))
            _need(value.data == b'\0', 'Restore ST safety record is not ST: %s/%08x' % (plane, pair[1]))
            rows.append(dict(chip=pair[0], key='%08x' % pair[1], attrs=ATTRS, hex='00'))
        evidence[plane] = rows
    return dict(schema=SCHEMA, status='FOUR_PLANE_ST_VERIFIED', fields_per_plane=len(FIELDS),
                selected_sha256=sha256(_json(evidence)).hexdigest(), planes=evidence,
                unrelated_values_admission=False)


def require_fresh_boot(prior_boot_id, runtime_evidence):
    _need(type(prior_boot_id) is str and UUID.fullmatch(prior_boot_id), 'Prior native kernel boot ID required')
    _need(type(runtime_evidence) is dict and runtime_evidence.get('fresh') is True,
          'Fresh caller-owned runtime evidence required')
    boot, pid = runtime_evidence.get('boot_id'), runtime_evidence.get('process_id')
    _need(type(boot) is str and UUID.fullmatch(boot) and boot != prior_boot_id,
          'ST adoption requires a different native kernel boot before program removal')
    _need(type(pid) is int and 0 < pid <= 4194304, 'Fresh AP process ID required')
    return boot, pid


def _getter_result(raw, at):
    """Decode the exact ADRP x0; ADD x0,x0,#imm x3; RET getters."""
    words = struct.unpack_from('<5I', raw, at)
    first = words[0]
    _need(first & 0x9F00001F == 0x90000000 and words[4] == 0xD65F03C0,
          'Native getter ADRP/RET structure differs')
    imm = ((first >> 29) & 3) | (((first >> 5) & 0x7FFFF) << 2)
    if imm & 0x100000:
        imm -= 0x200000
    value = (at & ~4095) + (imm << 12)
    for word in words[1:4]:
        _need(word & 0xFF8003FF == 0x91000000, 'Native getter ADD register/width differs')
        value += ((word >> 10) & 4095) << (12 if word & (1 << 22) else 0)
    return value


def make_plan(original_ap):
    _need(type(original_ap) is bytes and len(original_ap) == AP_SIZE,
          'Retained M4 6.02 AP layout required; it is never bundled')
    _need(tuple(_getter_result(original_ap, at) for at in GETTERS) == (CURRENT_VA, *BASE_VAS),
          'Original AP getter-to-model address derivation differs')
    result = dict(schema=SCHEMA, original_ap_sha256=sha256(original_ap).hexdigest(),
                  current_va=CURRENT_VA, base_vas=list(BASE_VAS),
                  guards=[dict(offset=at, expected_hex=original_ap[at:at+GUARD_BYTES].hex()) for at in GETTERS],
                  targets=dict(current=0, indices=list(range(10, 16)), value=0),
                  native_write=False, route='factory-save-then-new-boot-native-proof')
    result['plan_id'] = sha256(_json({k:v for k,v in result.items() if k != 'original_ap_sha256'})).hexdigest()
    return validate_plan(result)


def validate_plan(plan):
    _need(type(plan) is dict and set(plan) == {'schema', 'original_ap_sha256', 'current_va', 'base_vas',
          'guards', 'targets', 'native_write', 'route', 'plan_id'} and plan['schema'] == SCHEMA,
          'Exact restore model plan required')
    _need(type(plan['original_ap_sha256']) is str and re.fullmatch('[0-9a-f]{64}',plan['original_ap_sha256'])
          and plan['current_va'] == CURRENT_VA
          and plan['base_vas'] == list(BASE_VAS) and plan['targets'] == dict(current=0, indices=list(range(10, 16)), value=0)
          and plan['native_write'] is False and plan['route'] == 'factory-save-then-new-boot-native-proof',
          'Fixed M4 ST-only read profile differs')
    _need(type(plan['guards']) is list and len(plan['guards']) == 4, 'Four exact native getter guards required')
    # Hashes are independently pinned to retained original AP bytes, not supplied
    # by a user-selectable plan. Firmware bytes remain private build inputs.
    pins = ('013b0eab2ac261556adba759153e105997512952fa72c314898235de885b1323',
            '44773d9b6e570121f37afbdded03c85ef607882178cd3e2a45c97426b1da8b73',
            '248cfd99e7e7f50cef375587c5ec3eaf40194695071474db584b21ec727eb11d',
            '6ffe7aa3e6397f4689a5a072d3bebdbce7e4f739300592ba853596b423c23db7')
    for row, at, pin in zip(plan['guards'], GETTERS, pins):
        _need(type(row) is dict and set(row) == {'offset', 'expected_hex'} and row['offset'] == at
              and type(row['expected_hex']) is str and re.fullmatch('[0-9a-f]{40}', row['expected_hex']),
              'Exact fixed getter window required')
        _need(sha256(bytes.fromhex(row['expected_hex'])).hexdigest() == pin, 'Native getter code pin differs')
    _need(plan['plan_id'] == sha256(_json({k: v for k, v in plan.items()
                                       if k not in ('plan_id','original_ap_sha256')})).hexdigest(),
          'Restore model plan digest differs')
    return plan


def parse_report(plan, raw, nonce, *, prior_boot_id, runtime_evidence):
    validate_plan(plan)
    boot, pid = require_fresh_boot(prior_boot_id, runtime_evidence)
    _need(type(raw) is bytes and len(raw) == REPORT.size and type(nonce) is bytes and len(nonce) == 16 and any(nonce),
          'Exact restore model report and nonce required')
    values = REPORT.unpack(raw)
    magic, version, phase, echoed, plan_id, status, euid, actual_pid, close, unlink, bias, guards, seen, current, current2 = values[:15]
    before, after, boot_bytes, reserved = values[15:69], values[69:123], values[123], values[124]
    _need((magic, version, phase, echoed, plan_id) == (b'A7LM0001', 1, 9, nonce, bytes.fromhex(plan['plan_id']))
          and status == euid == close == unlink == 0 and actual_pid == pid and bias > 0 and bias % 4096 == 0
          and guards == seen == 4 and boot_bytes == boot.encode() + bytes(4) and reserved == bytes(8),
          'Native restore model code/process/boot/nonce/close proof differs')
    _need(current == current2 == 0, 'Native current selection is not stably ST')
    selected = {context*18+index for context in range(3) for index in range(10,16)}
    _need(all(before[index] == after[index] == 0 for index in selected),
          'Native current/still/movie custom base model is not ST')
    return dict(schema=SCHEMA, status='NATIVE_ST_MODEL_VERIFIED_AFTER_NEW_BOOT',
                program_removal_gate_verified=True, current=0,
                context_custom_bases={name: list(before[i*18+10:i*18+16])
                                      for i, name in enumerate(('current', 'still', 'movie'))},
                prior_boot_id=prior_boot_id, boot_id=boot, process_id=pid,
                plan_id=plan['plan_id'], report_sha256=sha256(raw).hexdigest(),
                observed_reference_ap_sha256=plan['original_ap_sha256'], whole_ap_hash_admission=False,
                native_memory_write=False, native_setter_called=False,
                program_write=False, persistence_write=False, no_COW=True,
                unselected_model_changes=[dict(index=i,before=before[i],after=after[i])
                                          for i in range(54) if i not in selected and before[i]!=after[i]],
                unselected_model_changes_blocking=False)


def build(plan, output, *, compiler):
    validate_plan(plan)
    from .program_worker import _elf
    _need(sha256(SOURCE.read_bytes()).hexdigest() == SOURCE_SHA256, 'Restore model native source pin differs')
    output = Path(output).absolute()
    _need(not output.exists() and output.parent.is_dir() and not any(p.is_symlink() for p in (output, *output.parents)),
          'New private restore model build directory required')
    output.mkdir(mode=0o700)
    rows = ['static const B plan_id[32]={%s};' % ','.join(map(str, bytes.fromhex(plan['plan_id'])))]
    for index, guard in enumerate(plan['guards']):
        rows.append('static const B guard_%d[]={%s};' % (index, ','.join(map(str, bytes.fromhex(guard['expected_hex'])))))
    rows.append('static const struct Guard guards[]={%s};' % ','.join('{%dUL,guard_%d}' % (at, i) for i, at in enumerate(GETTERS)))
    header = output / 'look-model-plan.h'
    header.write_text('\n'.join(rows)+'\n'); header.chmod(0o600)
    env = dict(os.environ, ZIG_GLOBAL_CACHE_DIR=str(output/'zig-global'), ZIG_LOCAL_CACHE_DIR=str(output/'zig-local'))
    _need(subprocess.run([str(compiler), 'version'], capture_output=True, text=True, check=True, timeout=20, env=env).stdout.strip() == '0.13.0',
          'Offline reviewed Zig 0.13 required')
    args = [str(compiler), 'cc', '-target', 'aarch64-linux-gnu', '-std=c11', '-Os', '-Wall', '-Wextra', '-Werror',
            '-shared', '-fPIC', '-ffreestanding', '-fno-builtin', '-fno-stack-protector', '-fno-unwind-tables',
            '-fno-asynchronous-unwind-tables', '-nostdlib', '-g0', '-Wl,--strip-debug', '-Wl,--no-undefined',
            '-Wl,--build-id=none', '-Wl,-Bsymbolic', '-Wl,-z,noexecstack', '-DLOOK_MODEL_PLAN="'+str(header)+'"']
    binary = output/'look-model.so'
    subprocess.run(args+['-o', str(binary), str(SOURCE)], capture_output=True, text=True, check=True, timeout=180, env=env)
    raw = binary.read_bytes(); _elf(raw)
    _need(0 < len(raw) < 65536, 'Restore model helper exceeds bounded upload')
    binary.chmod(0o600)
    from .build_scratch import discard_caches
    discard_caches(output)
    return raw


def verify_after_cold_boot(channel, output, *, compiler, original_ap, prior_boot_id,
                           runtime_evidence, snapshot, actions_factory=NativeActions):
    """Borrow an already admitted channel. No discovery/service entry is done.

    This callable does I/O only when explicitly invoked by the owning job.
    Existing NativeActions enforces small uploads plus the VFAT reserve.
    The root coordinator still owns fresh actual program load proof and USB
    service exit; this result alone never claims a full restore is complete.
    """
    require_fresh_boot(prior_boot_id, runtime_evidence)
    settings = validate_four_plane_st(snapshot)
    plan = validate_plan(make_plan(original_ap))
    output = Path(output).absolute(); output.mkdir(mode=0o700, exist_ok=False)
    binary = build(plan, output/'build', compiler=compiler)
    nonce = os.urandom(16)
    request = REQUEST.pack(b'A7LMQ001', nonce, bytes.fromhex(plan['plan_id']), bytes(8))
    action = actions_factory(channel, output/'native')
    def accept(raw):
        result = parse_report(plan, raw, nonce, prior_boot_id=prior_boot_id, runtime_evidence=runtime_evidence)
        path = output/'model-report.private.bin'
        fd = os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        return result
    result = action.phase(binary, REQUEST_PATH, request, RESULT_PATH, accept, report_bytes=REPORT.size)
    action.clean_packets()
    return dict(result, settings_proof=settings, native_report_path=str(output/'model-report.private.bin'))
