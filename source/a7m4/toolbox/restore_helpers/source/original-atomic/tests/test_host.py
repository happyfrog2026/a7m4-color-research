# SPDX-License-Identifier: MIT
"""Finite synthetic original-atomic host contracts; no hardware/network/builds."""
from copy import deepcopy
import importlib.util
from pathlib import Path
import struct
import unittest

BASE = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('synthetic_original_atomic', BASE / 'worker.py')
worker = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(worker)
N0, N1, N2, N3 = (bytes([v]) * 16 for v in (11, 22, 33, 44))


def plan_for(path='/usr/share/app/image_00_23_IPSX.uxc', *, source=b'SYNTHETIC current modified', target=b'SYNTHETIC original backup member'):
    h = worker.sha256
    authority = dict(schema=worker.AUTHORITY_SCHEMA, original_backup_sha256=h(b'SYNTH original full backup'),
                     current_file_readback_sha256=h(source), resource_reference_proof_sha256=h(b'SYNTH reference proof'),
                     boot_or_load_proof_sha256=h(b'SYNTH loaded runtime proof'))
    return worker.make_plan(path, source, target, authority=authority), source, target


def previous(plan, mode, *, stage_size=0, nonce=N0):
    row = dict(schema=worker.FAMILY, plan_id=plan['plan_id'], complete=True, cleanup_safe=True,
               mode=mode, pid=700, nonce=nonce.hex())
    for side, ino, size in (('source', 424242, plan['source']['size']), ('stage', 424243 if mode else 0, stage_size)):
        for key, value in zip(('dev', 'ino', 'size', 'mode', 'uid', 'gid', 'nlink'),
                              (0x1234, ino, size, 0o100644, 42, 43, 1) if ino else (0,) * 7):
            row[side + '_' + key] = value
    return row


REPORT_KEYS = ('magic', 'version', 'mode', 'nonce', 'plan_id', 'phase', 'flags', 'native_status', 'euid', 'pid',
    'plugin_unlink', 'close_errors', 'remount', 'readonly', 'source_status', 'stage_status', 'fs_status',
    'source_dev', 'source_ino', 'source_size', 'source_mode', 'source_uid', 'source_gid', 'source_nlink',
    'stage_dev', 'stage_ino', 'stage_size', 'stage_mode', 'stage_uid', 'stage_gid', 'stage_nlink',
    'fs_type', 'fs_unit', 'fs_available', 'fs_needed', 'offset', 'bytes_written', 'bytes_verified',
    'source_sha256', 'stage_sha256', 'write_attempts', 'rename_attempts', 'renamed', 'stage_created',
    'stage_removed', 'profile', 'reserved')


def report_for(plan, mode, nonce, packet, *, target_data=None, readonly=0, overrides=None):
    q = worker._request_fields(plan, packet, mode, nonce)
    source = q['source'] if mode else (0x1234, 424242, plan['source']['size'], 0o100644, 42, 43, 1)
    stage = (0,) * 7 if not mode else (source[0], 424243, 0, *source[3:]) if mode == 1 else q['stage']
    if mode == 2:
        stage = list(stage); stage[2] += q['chunk_bytes']; stage = tuple(stage)
    flags = 1 | 2048 | 4096 | 8192
    source_hash = bytes(32); stage_hash = bytes(32)
    if mode != 2 or q['guard_flags'] or readonly == -16:
        flags |= 512; source_hash = bytes.fromhex(plan['source']['sha256'])
    if mode == 1:
        flags |= 2 | 4 | 16384
    elif mode == 2:
        flags |= 8 | 16
    elif mode == 3:
        flags |= 32 | 64 | 16384 | 1024; stage_hash = bytes.fromhex(plan['target']['sha256'])
    elif mode == 4:
        flags |= 128 | 256 | 16384 | 1024; stage_hash = bytes.fromhex(q['stage_sha256'])
    if readonly == -16 and mode in (1, 2):
        flags |= 1024
        stage_hash = bytes.fromhex(worker.sha256((target_data or b'')[:stage[2]]))
    already = q['stage'][2] if mode >= 2 else 0; unit = 1024
    needed = 0 if mode == 4 else (((plan['target']['size'] + unit - 1) // unit) - ((already + unit - 1) // unit) + 32) * unit
    row = dict(magic=worker.MAGIC, version=1, mode=mode, nonce=nonce, plan_id=bytes.fromhex(plan['plan_id']),
               phase=9, flags=flags, native_status=readonly, euid=0, pid=q['pid'] or 700, plugin_unlink=0,
               close_errors=0, remount=0, readonly=readonly, source_status=0, stage_status=0, fs_status=0,
               fs_type=0x4d44 if plan['profile'] == 'cp-vfat-rw' else 0xef53, fs_unit=unit,
               fs_available=needed + 1048576, fs_needed=needed, offset=q['offset'] if mode == 2 else 0,
               bytes_written=q['chunk_bytes'], bytes_verified=q['chunk_bytes'], source_sha256=source_hash,
               stage_sha256=stage_hash, write_attempts=int(mode == 2), rename_attempts=int(mode == 3),
               renamed=int(mode == 3), stage_created=int(mode == 1), stage_removed=int(mode == 4),
               profile=int(plan['profile'] == 'cp-vfat-rw'), reserved=0)
    for side, core in (('source', source), ('stage', stage)):
        row.update({side + '_' + key: value for key, value in zip(('dev', 'ino', 'size', 'mode', 'uid', 'gid', 'nlink'), core)})
    row.update(overrides or {})
    return worker.REPORT.pack(*(row[k] for k in REPORT_KEYS))


def observe(plan, mode, nonce, packet, **kwargs):
    raw = report_for(plan, mode, nonce, packet, **kwargs)
    return worker.parse_report(plan, raw, mode, nonce, request_bytes=packet)


class PlanTests(unittest.TestCase):
    def test_fixed_scope_profiles_and_canonical_stage_names(self):
        self.assertEqual(len(worker.ORIGINAL_PATHS), 71)
        for path, profile in (('/usr/share/app/string_english_horizontal.uxc', 'usr-ext2-ro'),
                              ('/cp/SysSound.bin', 'cp-vfat-rw')):
            p, source, target = plan_for(path)
            self.assertEqual(p['profile'], profile)
            self.assertEqual(p['stage_path'], path.rsplit('/', 1)[0] + '/.a7m4-original-' + p['plan_id'] + '.stage')
            self.assertEqual(worker.verify_source(p, source)['identity'], p['source'])
            self.assertEqual(worker.verify_readback(p, target)['identity'], p['target'])
        for path in ('/cp/CPAPP-B.BIN', '/usr/share/app/../app/image_00_23_IPSX.uxc'):
            with self.assertRaises(ValueError):
                plan_for(path)

    def test_no_install_history_and_corrupt_empty_current_restorable(self):
        p, _, _ = plan_for(source=b'')
        self.assertEqual(p['source']['size'], 0)
        self.assertNotIn('install_job', p)
        self.assertNotIn('completed_receipt_sha256', p['authority'])
        with self.assertRaises(ValueError):
            plan_for(target=b'')
        broken = deepcopy(p); broken['stage_path'] = '/cp/arbitrary.stage'
        with self.assertRaises(ValueError):
            worker.validate_plan(broken)
        broken = deepcopy(p); broken['authority']['current_file_readback_sha256'] = worker.sha256(b'wrong')
        with self.assertRaises(ValueError):
            worker.validate_plan(broken)

    def test_noop_has_no_native_request_and_headers_embed_no_firmware(self):
        p, source, _ = plan_for(target=b'SYNTHETIC current modified')
        self.assertTrue(p['no_op'])
        with self.assertRaises(ValueError):
            worker.request(p, 0, N0)
        p, source, target = plan_for()
        header = worker.render_header(p)
        self.assertIn(p['stage_path'].encode(), header)
        self.assertNotIn(source, header); self.assertNotIn(target, header)
        self.assertNotIn(b'424242', header)


class RequestTests(unittest.TestCase):
    def test_inspect_is_zero_identity_and_begin_requires_full_source_mac(self):
        p, source, _ = plan_for()
        raw = worker.request(p, 0, N0)
        self.assertEqual(len(raw), 256); self.assertFalse(any(raw[64:]))
        observed = previous(p, 0)
        for receipt in (None, True, worker.verify_stage(p, b'SYNTHETIC original backup member')):
            with self.assertRaises(ValueError):
                worker.request(p, 1, N1, observed, source_readback=receipt)
        raw = worker.request(p, 1, N1, observed, source_readback=worker.verify_source(p, source))
        self.assertEqual(worker.IDENTITY.unpack_from(raw, 72), worker._core(observed, 'source'))
        self.assertFalse(any(raw[112:]))

    def test_chunk_size_hash_and_offset_are_fixed_by_previous_stage(self):
        p, source, target = plan_for(target=b'Z' * 40000)
        begin = previous(p, 1, nonce=N1)
        data = b'Z' * 32768
        raw = worker.request(p, 2, N2, begin, chunk=data)
        self.assertEqual(len(raw), 33024)
        self.assertLess(len(raw), 65536)
        self.assertEqual(struct.unpack_from('<Q', raw, 152)[0], 0)
        self.assertEqual(raw[192:224], bytes.fromhex(worker.sha256(data)))
        self.assertEqual(raw[256:], data)
        tail = previous(p, 2, stage_size=32768, nonce=N2)
        raw = worker.request(p, 2, N3, tail, chunk=b'Z' * 7232)
        self.assertEqual(struct.unpack_from('<Q', raw, 152)[0], 32768)
        for invalid in (b'', b'Z' * 32769):
            with self.assertRaises(ValueError):
                worker.request(p, 2, N2, begin, chunk=invalid)
        with self.assertRaises(ValueError):
            worker.request(p, 2, N3, tail, chunk=b'Z' * 7233)

    def test_commit_requires_complete_original_stage_mac_receipt(self):
        p, source, target = plan_for()
        full = previous(p, 2, stage_size=len(target), nonce=N2)
        for proof in (None, True, worker.verify_source(p, source), worker.verify_abort_stage(p, target)):
            with self.assertRaises(ValueError):
                worker.request(p, 3, N3, full, stage_readback=proof)
        raw = worker.request(p, 3, N3, full, stage_readback=worker.verify_stage(p, target))
        self.assertEqual(raw[160:192], bytes.fromhex(p['target']['sha256']))
        self.assertEqual(len(raw), 256)
        with self.assertRaises(ValueError):
            worker.request(p, 3, N3, previous(p, 2, stage_size=len(target) - 1, nonce=N2), stage_readback=worker.verify_stage(p, target))
        with self.assertRaises(ValueError):
            worker.verify_stage(p, target + b'unexpected tail')

    def test_abort_requires_exact_partial_stage_mac_bytes(self):
        p, _, _ = plan_for()
        partial = b'SYNTH'; last = previous(p, 2, stage_size=len(partial), nonce=N2)
        with self.assertRaises(ValueError):
            worker.request(p, 4, N3, last)
        raw = worker.request(p, 4, N3, last, stage_readback=worker.verify_abort_stage(p, partial))
        self.assertEqual(raw[160:192], bytes.fromhex(worker.sha256(partial)))
        with self.assertRaises(ValueError):
            worker.request(p, 4, N3, last, stage_readback=worker.verify_abort_stage(p, partial + b'X'))

    def test_no_reorder_repeat_nonce_or_retry_after_finished_commit(self):
        p, source, target = plan_for()
        for mode, report in ((1, previous(p, 1)), (2, previous(p, 0)), (3, previous(p, 3, stage_size=len(target)))):
            with self.assertRaises(ValueError):
                worker.request(p, mode, N3, report, chunk=b'X' if mode == 2 else b'',
                               source_readback=worker.verify_source(p, source) if mode == 1 else None,
                               stage_readback=worker.verify_stage(p, target) if mode == 3 else None)
        with self.assertRaises(ValueError):
            worker.request(p, 2, N1, previous(p, 1, nonce=N1), chunk=b'X')
        unknown = previous(p, 2, stage_size=1, nonce=N2); unknown['cleanup_safe'] = False
        with self.assertRaises(ValueError):
            worker.request(p, 4, N3, unknown, stage_readback=worker.verify_abort_stage(p, b'X'))


class ParserTests(unittest.TestCase):
    def staging(self, path='/usr/share/app/image_00_23_IPSX.uxc', *, deferred=False):
        p, source, target = plan_for(path)
        q0 = worker.request(p, 0, N0); r0 = observe(p, 0, N0, q0)
        q1 = worker.request(p, 1, N1, r0, source_readback=worker.verify_source(p, source))
        r1 = observe(p, 1, N1, q1, readonly=-16 if deferred else 0)
        return p, source, target, r1

    def test_full_stage_chain_then_commit_new_inode_without_full_claim(self):
        p, _, target, r1 = self.staging()
        q2 = worker.request(p, 2, N2, r1, chunk=target); r2 = observe(p, 2, N2, q2)
        self.assertEqual(r2['stage_size'], len(target))
        self.assertNotEqual(r2['source_ino'], r2['stage_ino'])
        q3 = worker.request(p, 3, N3, r2, stage_readback=worker.verify_stage(p, target))
        r3 = observe(p, 3, N3, q3)
        self.assertTrue(r3['atomic_commit_complete']); self.assertTrue(r3['cleanup_safe'])
        self.assertFalse(r3['full_file_restore_complete']); self.assertTrue(r3['full_target_readback_required'])
        self.assertEqual(worker.verify_readback(p, target)['identity'], p['target'])

    def test_exact_packet_nonce_payload_progress_and_identity_are_checked(self):
        p, _, target, r1 = self.staging()
        q2 = worker.request(p, 2, N2, r1, chunk=target)
        good = report_for(p, 2, N2, q2)
        for bad in (good[:-1], good + b'\0', report_for(p, 2, N2, q2, overrides={'bytes_verified': len(target) - 1}),
                    report_for(p, 2, N2, q2, overrides={'source_uid': 999}),
                    report_for(p, 2, N2, q2, overrides={'stage_size': len(target) - 1})):
            with self.assertRaises(ValueError):
                worker.parse_report(p, bad, 2, N2, request_bytes=q2)
        with self.assertRaises(ValueError):
            worker.parse_report(p, good, 2, N3, request_bytes=q2)

    def test_cp_dynamic_metadata_and_rw_are_not_misreported_usr_ro(self):
        p, _, target, r1 = self.staging('/cp/SysSound.bin')
        self.assertEqual((r1['source_uid'], r1['stage_uid']), (42, 42))
        self.assertTrue(r1['cp_vfat_rw_verified']); self.assertFalse(r1['usr_readonly_verified'])
        q2 = worker.request(p, 2, N2, r1, chunk=target)
        self.assertEqual(struct.unpack_from('<I', q2, 224)[0], 0)
        with self.assertRaises(ValueError):
            worker.parse_report(p, report_for(p, 2, N2, q2, readonly=-16), 2, N2, request_bytes=q2)

    def test_known_ebusy_chain_uses_native_stage_hash_token_not_caller_bool(self):
        p, _, target, r1 = self.staging(deferred=True)
        self.assertTrue(r1['known_deferred_readonly']); self.assertFalse(r1['usr_readonly_verified'])
        q2 = worker.request(p, 2, N2, r1, chunk=target)
        self.assertEqual(struct.unpack_from('<I', q2, 224)[0], 1)
        self.assertEqual(q2[160:192].hex(), r1['stage_sha256'])
        r2 = observe(p, 2, N2, q2, target_data=target, readonly=-16)
        self.assertTrue(r2['complete']); self.assertTrue(r2['stage_hash_verified'])
        self.assertEqual(r2['stage_sha256'], p['target']['sha256'])
        q3 = worker.request(p, 3, N3, r2, stage_readback=worker.verify_stage(p, target))
        r3 = observe(p, 3, N3, q3, readonly=-16)
        self.assertTrue(r3['atomic_commit_complete']); self.assertTrue(r3['known_deferred_readonly'])
        self.assertFalse(r3['usr_readonly_verified'])

    def test_partial_write_and_rename_uncertainty_forbid_healthy_stop(self):
        p, _, target, r1 = self.staging()
        q2 = worker.request(p, 2, N2, r1, chunk=target)
        flags = 2048 | 4096 | 8192 | 8 | 32768
        raw = report_for(p, 2, N2, q2, overrides={'phase': 5, 'flags': flags, 'native_status': -5,
                         'bytes_written': 1, 'bytes_verified': 0, 'stage_size': 0})
        r = worker.parse_report(p, raw, 2, N2, request_bytes=q2)
        self.assertTrue(r['operation_state_unknown']); self.assertFalse(r['cleanup_safe'])
        r2 = observe(p, 2, N2, q2)
        q3 = worker.request(p, 3, N3, r2, stage_readback=worker.verify_stage(p, target))
        raw = report_for(p, 3, N3, q3, overrides={'phase': 6, 'flags': 2048 | 4096 | 8192 | 512 | 1024 | 32 | 32768,
                         'native_status': -5, 'renamed': 0})
        r = worker.parse_report(p, raw, 3, N3, request_bytes=q3)
        self.assertTrue(r['operation_state_unknown']); self.assertFalse(r['cleanup_safe'])

    def test_inspect_enospc_is_known_zero_write_and_abort_needs_zero_space(self):
        p, _, _, r1 = self.staging()
        q0 = worker.request(p, 0, N0)
        raw = report_for(p, 0, N0, q0, overrides={'phase': 2, 'flags': 2048 | 4096 | 8192 | 512,
                         'native_status': -28, 'fs_status': -28, 'fs_available': 0})
        r = worker.parse_report(p, raw, 0, N0, request_bytes=q0)
        self.assertTrue(r['safe_inspect_refusal']); self.assertTrue(r['cleanup_safe'])
        q4 = worker.request(p, 4, N2, r1, stage_readback=worker.verify_abort_stage(p, b''))
        raw = report_for(p, 4, N2, q4, overrides={'fs_available': 0})
        r = worker.parse_report(p, raw, 4, N2, request_bytes=q4)
        self.assertTrue(r['complete']); self.assertEqual(r['stage_removed'], 1)
        self.assertEqual(r['fs_needed'], 0)


if __name__ == '__main__':
    unittest.main()
