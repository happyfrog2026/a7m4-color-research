# SPDX-License-Identifier: MIT
"""Finite synthetic original-backup delta host tests; no device/network/builds."""
from copy import deepcopy
import importlib.util
from pathlib import Path
import struct
import unittest

BASE = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location('synthetic_delta_' + name, BASE / (name + '.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


worker, session = load('worker'), load('session')
N0, N1 = b'SYNTH-INSPECT-01', b'SYNTH-APPLY-0001'
KEYS = ('magic', 'version', 'mode', 'nonce', 'plan_id', 'phase', 'index', 'mapping_count',
        'cross_pids', 'cross_matches', 'cow_attempts', 'cow_segments', 'flags', 'native_status',
        'euid', 'pid', 'plugin_unlink', 'close_errors', 'readonly', 'remount', 'auxv_status',
        'source_status', 'source_dev', 'source_ino', 'source_size', 'source_mode', 'source_uid',
        'source_gid', 'source_nlink', 'target_size', 'page_size', 'bytes_written', 'bytes_cow_preserved',
        'total', 'window_count', 'write_attempts', 'writes_completed')


def authority_for(source):
    h = worker.sha256
    return dict(schema=worker.AUTHORITY_SCHEMA, original_backup_sha256=h(b'SYNTH original backup'),
                current_file_readback_sha256=h(source), resource_reference_proof_sha256=h(b'SYNTH references'),
                boot_or_load_proof_sha256=h(b'SYNTH current runtime'))


def plan_for(*, tail=True, changed=True):
    target = bytes((i * 17 + 7) % 256 for i in range(5000))
    source = bytearray(target + (b'SYNTHETIC APPEND TAIL' if tail else b''))
    if changed:
        for at in (*range(8, 12), *range(4094, 4102)):
            source[at] ^= 255
    source = bytes(source)
    return worker.make_plan('/usr/share/app/image_00_23_IPSX.uxc', source, target,
                            authority=authority_for(source)), source, target


def report_for(plan, mode, nonce, *, mappings=None, overrides=None, expected_override=None):
    rows = [(0x50000000, 8192, 0, 1)] if mappings is None else mappings
    rowdicts = [dict(zip(('va', 'len', 'off', 'prot'), row)) for row in rows]
    segments, cowbytes = worker._expected_cow(plan, rowdicts)
    d = dict(magic=worker.MAGIC, version=1, mode=mode, nonce=nonce, plan_id=bytes.fromhex(plan['plan_id']),
             phase=3 if mode == 0 else 9, index=0, mapping_count=len(rows), cross_pids=301, cross_matches=0,
             cow_attempts=segments if mode else 0, cow_segments=segments if mode else 0,
             flags=193 if mode == 0 else 763 if segments else 761, native_status=0, euid=0, pid=700,
             plugin_unlink=0, close_errors=0, readonly=0, remount=0, auxv_status=0, source_status=0,
             source_dev=0x1234, source_ino=424242, source_size=plan['source']['size'], source_mode=0o100644,
             source_uid=42, source_gid=43, source_nlink=1, target_size=plan['target']['size'], page_size=4096,
             bytes_written=plan['window_total_bytes'] if mode else 0, bytes_cow_preserved=cowbytes if mode else 0,
             total=544, window_count=len(plan['windows']), write_attempts=len(plan['windows']) if mode else 0,
             writes_completed=len(plan['windows']) if mode else 0)
    d.update(overrides or {})
    raw = bytearray(544); raw[:256] = worker.PREFIX.pack(*(d[k] for k in KEYS))
    for i, row in enumerate(rows):
        worker.MAPPING.pack_into(raw, 256 + i * 32, *row)
    struct.pack_into('<4Q', raw, 384, *(expected_override or (segments, cowbytes, 0, 0)))
    struct.pack_into('<QQIIII', raw, 416, d['source_dev'], d['source_ino'], d['source_mode'],
                     d['source_nlink'], d['source_uid'], d['source_gid'])
    struct.pack_into('<q', raw, 464, d['source_size'])
    return bytes(raw)


class PlanTests(unittest.TestCase):
    def test_original_backup_diff_reconstructs_prefix_and_preserves_tail(self):
        p, source, target = plan_for()
        self.assertEqual(len(p['windows']), 2)
        self.assertEqual(p['changed_bytes'], p['window_total_bytes'])
        self.assertEqual(p['post']['size'], len(source))
        self.assertEqual(worker.verify_source(p, source)['identity'], p['source'])
        post = target + source[len(target):]
        self.assertEqual(worker.verify_readback(p, post)['identity'], p['post'])
        self.assertEqual(p['retained_tail'], worker._identity(source[len(target):]))
        with self.assertRaises(ValueError):
            worker.verify_readback(p, target)
        with self.assertRaises(ValueError):
            worker.verify_source(p, source[:-1] + b'X')

    def test_only_complete_original_backup_proof_scope(self):
        p, source, target = plan_for()
        self.assertNotIn('install_job', p)
        for path in ('/usr/share/app/../app/image_00_23_IPSX.uxc', '/cp/CPAPP-B.BIN'):
            with self.assertRaises(ValueError):
                worker.make_plan(path, source, target, authority=p['authority'])
        with self.assertRaises(ValueError):
            worker.make_plan(p['resource_path'], source, target, authority=dict(p['authority'], current_file_readback_sha256=worker.sha256(b'wrong')))
        with self.assertRaises(ValueError):
            worker.make_plan(p['resource_path'], target[:-1], target, authority=authority_for(target[:-1]))
        broken = deepcopy(p); broken['windows'][0]['after_hex'] = broken['windows'][0]['before_hex']
        with self.assertRaises(ValueError):
            worker.validate_plan(broken)

    def test_contiguous_window_split_and_sparse_merge_budgets(self):
        target = bytes(2000); source = b'\xff' * 1300 + target[1300:]
        p = worker.make_plan('/usr/share/app/string_english_horizontal.uxc', source, target, authority=authority_for(source))
        self.assertEqual([len(bytes.fromhex(w['before_hex'])) for w in p['windows']], [512, 512, 276])
        sparse = bytearray(1000)
        for at in range(0, 400, 2):
            sparse[at] = 255
        p = worker.make_plan('/usr/share/app/string_english_horizontal.uxc', bytes(sparse), bytes(1000), authority=authority_for(bytes(sparse)))
        self.assertEqual(len(p['windows']), 128)
        self.assertEqual(p['changed_bytes'], 200)
        self.assertLessEqual(p['window_total_bytes'], 16384)
        with self.assertRaises(ValueError):
            worker.make_plan('/usr/share/app/string_english_horizontal.uxc', b'\xff' * 16385,
                             bytes(16385), authority=authority_for(b'\xff' * 16385))

    def test_noop_retains_tail_without_native_arm_or_full_original_claim(self):
        p, source, _ = plan_for(changed=False)
        self.assertTrue(p['no_op'])
        with self.assertRaises(ValueError):
            worker.request(p, 0, N0)
        protocol = session.ResourceDeltaProtocol(p)
        protocol.confirm_source(source); receipt = protocol.finish()
        self.assertFalse(receipt['native_job_performed'])
        self.assertTrue(receipt['resource_prefix_restore_complete'])
        self.assertTrue(receipt['requires_tail_cleanup'])
        self.assertFalse(receipt['full_file_restore_complete'])
        p, source, _ = plan_for(tail=False, changed=False)
        protocol = session.ResourceDeltaProtocol(p); protocol.confirm_source(source)
        self.assertTrue(protocol.finish()['full_file_restore_complete'])


class ParserTests(unittest.TestCase):
    def test_inspect_identity_nonce_fixed_length_and_no_early_full_claim(self):
        p, _, _ = plan_for()
        request = worker.request(p, 0, N0)
        self.assertEqual(len(request), 256); self.assertFalse(any(request[64:]))
        raw = report_for(p, 0, N0); r = worker.parse_report(p, raw, 0, N0)
        self.assertTrue(r['complete']); self.assertFalse(r['resource_prefix_restore_complete'])
        self.assertEqual(len(worker.request(p, 1, N1, r)), 256)
        for bad in (raw[:-1], raw + b'\0', report_for(p, 0, b'X' * 16),
                    report_for(p, 0, N0, overrides={'plan_id': bytes(32)})):
            with self.assertRaises(ValueError):
                worker.parse_report(p, bad, 0, N0)

    def test_native_mapping_may_legally_extend_beyond_eof(self):
        p, _, _ = plan_for()
        r = worker.parse_report(p, report_for(p, 0, N0, mappings=[(0x50000000, 12288, 0, 1)]), 0, N0)
        self.assertTrue(r['complete'])
        self.assertGreater(r['mappings'][0]['len'], p['source']['size'])
        for row in ((0x50000000, 8192, 0, 3), (0x50000001, 8192, 0, 1)):
            with self.assertRaises(ValueError):
                worker.parse_report(p, report_for(p, 0, N0, mappings=[row]), 0, N0)

    def test_no_alias_and_split_alias_cow_count_success(self):
        p, _, _ = plan_for()
        for rows in ([], [(0x50000000, 4096, 0, 1), (0x51000000, 4096, 4096, 1)]):
            r = worker.parse_report(p, report_for(p, 1, N1, mappings=rows), 1, N1)
            self.assertTrue(r['complete'])
            self.assertEqual(r['cow_attempts'], r['cow_segments_expected'])
            self.assertEqual(r['bytes_cow_preserved'], r['cow_bytes_expected'])
            self.assertEqual(r['write_attempts'], len(p['windows']))
        for bad in (report_for(p, 1, N1, overrides={'cow_segments': 1}),
                    report_for(p, 1, N1, overrides={'flags': 251})):
            with self.assertRaises(ValueError):
                worker.parse_report(p, bad, 1, N1)

    def test_cow_attempt_zero_completed_failure_is_unknown(self):
        p, _, _ = plan_for()
        raw = report_for(p, 1, N1, overrides={'phase': 4, 'native_status': -5, 'flags': 198,
                         'cow_attempts': 1, 'cow_segments': 0, 'bytes_cow_preserved': 0,
                         'write_attempts': 0, 'writes_completed': 0, 'bytes_written': 0})
        r = worker.parse_report(p, raw, 1, N1)
        self.assertTrue(r['mapping_state_unknown']); self.assertTrue(r['operation_state_unknown'])
        self.assertFalse(r['cleanup_safe']); self.assertFalse(r['file_state_unknown'])

    def test_verified_cow_without_file_attempt_can_stop_known(self):
        p, _, _ = plan_for()
        raw = report_for(p, 1, N1, overrides={'phase': 4, 'native_status': -84, 'flags': 202,
                         'write_attempts': 0, 'writes_completed': 0, 'bytes_written': 0})
        r = worker.parse_report(p, raw, 1, N1)
        self.assertTrue(r['cow_verified']); self.assertTrue(r['cleanup_safe'])
        self.assertFalse(r['operation_state_unknown']); self.assertFalse(r['complete'])

    def test_partial_file_write_failure_never_counts_as_zero_write(self):
        p, _, _ = plan_for()
        raw = report_for(p, 1, N1, overrides={'phase': 8, 'native_status': -5, 'flags': 474,
                         'write_attempts': 1, 'writes_completed': 0, 'bytes_written': 1})
        r = worker.parse_report(p, raw, 1, N1)
        self.assertTrue(r['file_state_unknown']); self.assertFalse(r['cleanup_safe'])
        self.assertTrue(r['operation_state_unknown'])
        post_runtime_failure = report_for(p, 1, N1, overrides={
            'phase': 8, 'native_status': -84, 'flags': 254})
        r = worker.parse_report(p, post_runtime_failure, 1, N1)
        self.assertTrue(r['mapping_state_unknown']); self.assertFalse(r['cleanup_safe'])
        self.assertFalse(r['post_runtime_preserved_verified'])


class ProtocolTests(unittest.TestCase):
    def inspected(self, tail=True):
        p, source, target = plan_for(tail=tail)
        protocol = session.ResourceDeltaProtocol(p)
        protocol.request(0, N0); protocol.accept(report_for(p, 0, N0))
        return p, source, target, protocol

    def test_full_source_then_complete_post_barriers_and_tail_status(self):
        p, source, target, protocol = self.inspected()
        with self.assertRaises(ValueError):
            protocol.request(1, N1)
        protocol.confirm_source(source)
        with self.assertRaises(ValueError):
            protocol.request(1, N0)
        protocol.request(1, N1); protocol.accept(report_for(p, 1, N1))
        with self.assertRaises(ValueError):
            protocol.finish()
        protocol.confirm_readback(target + source[len(target):]); final = protocol.finish()
        self.assertTrue(final['resource_prefix_restore_complete'])
        self.assertFalse(final['full_file_restore_complete'])
        self.assertTrue(final['requires_tail_cleanup'])
        self.assertFalse(final['post_boot_full_file_verification_complete'])
        with self.assertRaises(ValueError):
            protocol.request(1, b'3' * 16)

    def test_equal_length_original_restore_can_be_full_file(self):
        p, source, target, protocol = self.inspected(tail=False)
        protocol.confirm_source(source); protocol.request(1, N1); protocol.accept(report_for(p, 1, N1))
        protocol.confirm_readback(target)
        self.assertTrue(protocol.finish()['full_file_restore_complete'])

    def test_semantic_full_post_mismatch_still_allows_known_native_cleanup(self):
        p, source, target, protocol = self.inspected()
        protocol.confirm_source(source); protocol.request(1, N1); protocol.accept(report_for(p, 1, N1))
        with self.assertRaises(ValueError):
            protocol.confirm_readback(target)
        self.assertTrue(protocol.cleanup_admission()['native_pair_cleanup_allowed'])
        with self.assertRaises(ValueError):
            protocol.finish()

    def test_pid_drift_partial_native_and_unknown_write_never_retry(self):
        for case in ('pid', 'framing', 'write'):
            p, source, _, protocol = self.inspected()
            protocol.confirm_source(source); protocol.request(1, N1)
            raw = report_for(p, 1, N1, overrides={'pid': 701} if case == 'pid' else None)
            if case == 'write':
                raw = report_for(p, 1, N1, overrides={'phase': 8, 'native_status': -5, 'flags': 474,
                                 'write_attempts': 1, 'writes_completed': 0, 'bytes_written': 1})
                protocol.accept(raw)
            else:
                with self.assertRaises(ValueError):
                    protocol.accept(raw if case == 'pid' else raw[:-1])
            self.assertEqual(protocol.state, 'STOP_UNKNOWN')
            self.assertFalse(protocol.cleanup_admission()['native_pair_cleanup_allowed'])
            with self.assertRaises(ValueError):
                protocol.request(1, b'4' * 16)


if __name__ == '__main__':
    unittest.main()
