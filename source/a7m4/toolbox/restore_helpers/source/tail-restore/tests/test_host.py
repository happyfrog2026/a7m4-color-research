# SPDX-License-Identifier: MIT
"""Finite synthetic host contract tests. No hardware, firmware, network or builds.

Run: python3 -m unittest discover -s <tail-restore>/tests -p test_host.py -v
The report encoder below models wire fields only; native execution/syscalls are
independently exercised by the ARM64 fixtures owned by another reviewer.
"""
from copy import deepcopy
import importlib.util
from pathlib import Path
import struct
import unittest

BASE = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location('synthetic_tail_' + name, BASE / (name + '.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


worker, session = load('worker'), load('session')
N0, N1 = b'SYNTH-INSPECT-01', b'SYNTH-APPLY-0001'
KEYS = ('magic', 'version', 'mode', 'nonce', 'plan_id', 'phase', 'index', 'range_count',
        'cross_pids', 'cross_matches', 'mremap_attempts', 'changed_aliases', 'flags',
        'native_status', 'euid', 'pid', 'plugin_unlink', 'close_errors', 'readonly',
        'remount', 'auxv_status', 'source_status', 'source_dev', 'source_ino', 'source_size',
        'source_mode', 'source_uid', 'source_gid', 'source_nlink', 'target_size', 'page_size',
        'anon_bytes', 'bytes_truncated', 'total', 'preimage_bytes', 'offender_pid', 'reserved')


def bytes_for(count, multiplier=19):
    return bytes((i * multiplier + 11) % 256 for i in range(count))


def plan_for(target_size=5000, tail_size=2000, path='/usr/share/app/image_00_32_IPSX.uxc'):
    target = bytes_for(target_size)
    source = target + bytes_for(tail_size, 31)
    h = worker.sha256
    authority = dict(schema=worker.AUTHORITY_SCHEMA,
                     original_backup_sha256=h(b'SYNTHETIC original complete backup'),
                     current_file_readback_sha256=h(source),
                     resource_reference_proof_sha256=h(b'SYNTHETIC verified original references'),
                     boot_or_load_proof_sha256=h(b'SYNTHETIC current loaded safety proof'))
    return worker.make_plan(path, source, target, authority=authority), source, target


def report_for(plan, mode, nonce, *, aliases=True, overrides=None, preimage_override=None):
    length = plan['shadow_end'] - plan['shadow_begin']
    rows = [(0x50000000, length, plan['shadow_begin'], 1)] if aliases else []
    count = len(rows); captured = bytes.fromhex(plan['expected_shadow_hex']) if aliases else b''
    values = dict(magic=worker.MAGIC, version=1, mode=mode, nonce=nonce,
                  plan_id=bytes.fromhex(plan['plan_id']), phase=3 if mode == 0 else 9,
                  index=0, range_count=count, cross_pids=301, cross_matches=0,
                  mremap_attempts=count if mode else 0, changed_aliases=count if mode else 0,
                  flags=193 if mode == 0 else 251 if count else 249,
                  native_status=0, euid=0, pid=700, plugin_unlink=0, close_errors=0,
                  readonly=0, remount=0, auxv_status=0, source_status=0,
                  source_dev=0x1234, source_ino=424242, source_size=plan['source']['size'],
                  source_mode=0o100644, source_uid=42, source_gid=43, source_nlink=1,
                  target_size=plan['target']['size'], page_size=4096,
                  anon_bytes=length if mode and count else 0,
                  bytes_truncated=plan['owned_tail']['size'] if mode else 0,
                  total=544 + len(captured), preimage_bytes=len(captured), offender_pid=0, reserved=0)
    values.update(overrides or {})
    body = bytearray(544)
    body[:256] = worker.PREFIX.pack(*(values[k] for k in KEYS))
    for i, row in enumerate(rows):
        worker.RANGE.pack_into(body, 256 + i * 32, *row)
        if mode:
            struct.pack_into('<Q', body, 384 + i * 8, 0x51000000 + i * 0x10000)
    struct.pack_into('<QQIIII', body, 416, values['source_dev'], values['source_ino'],
                     values['source_mode'], values['source_nlink'], values['source_uid'], values['source_gid'])
    struct.pack_into('<q', body, 464, values['source_size'])
    return bytes(body) + (captured if preimage_override is None else preimage_override)


class PlanTests(unittest.TestCase):
    def test_exact_original_prefix_and_public_scope(self):
        p, source, target = plan_for()
        self.assertEqual(len(worker.RESOURCE_PATHS), 8)
        self.assertEqual(worker.verify_source(p, source)['identity'], p['source'])
        self.assertEqual(worker.verify_readback(p, target)['identity'], p['target'])
        self.assertEqual(p['shadow_begin'], 4096)
        self.assertEqual(p['shadow_end'], 8192)
        for path in ('/usr/share/app/../app/image_00_32_IPSX.uxc', '/cp/CPAPP-B.BIN'):
            with self.assertRaises(ValueError):
                worker.make_plan(path, source, target, authority=p['authority'])
        with self.assertRaises(ValueError):
            worker.make_plan(p['resource_path'], source, b'BAD' + target[3:], authority=p['authority'])

    def test_typed_original_backup_authority_not_install_receipt(self):
        p, source, target = plan_for()
        self.assertNotIn('completed_receipt_sha256', p['authority'])
        for changed in ({'completed_receipt_sha256': worker.sha256(b'old'), 'boot_proof_sha256': worker.sha256(b'oldboot')},
                        dict(p['authority'], current_file_readback_sha256=worker.sha256(b'wrong current')),
                        dict(p['authority'], runtime_references_safe=True)):
            with self.assertRaises(ValueError):
                worker.make_plan(p['resource_path'], source, target, authority=changed)
        altered = deepcopy(p); altered['authority']['original_backup_sha256'] = worker.sha256(b'other backup')
        with self.assertRaises(ValueError):
            worker.validate_plan(altered)

    def test_positive_tail_bound_padding_and_plan_identity(self):
        p, source, target = plan_for(4097, 43008)
        self.assertLessEqual(p['shadow_end'] - p['shadow_begin'], worker.MAX_SHADOW_BYTES)
        self.assertEqual(p['owned_tail']['size'], 43008)
        self.assertEqual(bytes.fromhex(p['expected_shadow_hex'])[len(source) - p['shadow_begin']:],
                         bytes(p['shadow_end'] - len(source)))
        for invalid_source in (target, target + bytes(43009)):
            authority = dict(p['authority'], current_file_readback_sha256=worker.sha256(invalid_source))
            with self.assertRaises(ValueError):
                worker.make_plan(p['resource_path'], invalid_source, target, authority=authority)
        broken = deepcopy(p); broken['expected_shadow_hex'] = '00' + broken['expected_shadow_hex'][2:]
        with self.assertRaises(ValueError):
            worker.validate_plan(broken)

    def test_fresh_source_must_match_entire_prefix_not_just_tail(self):
        p, source, _ = plan_for(9000)
        changed = bytes([source[0] ^ 1]) + source[1:]
        with self.assertRaises(ValueError):
            worker.verify_source(p, changed)
        with self.assertRaises(ValueError):
            worker.verify_source(p, source[:-1])
        header = worker.render_header(p)
        self.assertIn(p['resource_path'].encode(), header)
        self.assertNotIn(b'424242', header)
        self.assertNotIn(b'SYNTHETIC current loaded', header)


class ParserTests(unittest.TestCase):
    def test_request_and_report_identity_nonce_framing(self):
        p, _, _ = plan_for()
        request = worker.request(p, 0, N0)
        self.assertEqual(len(request), 256)
        self.assertFalse(any(request[64:]))
        good = report_for(p, 0, N0)
        observed = worker.parse_report(p, good, 0, N0)
        self.assertTrue(observed['native_complete'])
        self.assertFalse(observed['full_file_restore_complete'])
        self.assertEqual(len(worker.request(p, 1, N1, observed)), 256)
        for bad in (good[:-1], good + b'\0', report_for(p, 0, b'X' * 16),
                    report_for(p, 0, N0, overrides={'plan_id': bytes(32)})):
            with self.assertRaises(ValueError):
                worker.parse_report(p, bad, 0, N0)

    def test_completed_proofs_counter_stat_and_snapshot_checks(self):
        p, _, _ = plan_for()
        bad_reports = [report_for(p, 1, N1, overrides={'mremap_attempts': 0}),
                       report_for(p, 0, N0, overrides={'page_size': 16384}),
                       report_for(p, 1, N1, preimage_override=bytes(4096))]
        raw = bytearray(report_for(p, 0, N0)); struct.pack_into('<Q', raw, 424, 999)
        bad_reports.append(bytes(raw))
        for i, raw in enumerate(bad_reports):
            with self.subTest(i=i), self.assertRaises(ValueError):
                worker.parse_report(p, raw, 0 if i in (1, 3) else 1, N0 if i in (1, 3) else N1)

    def test_no_alias_is_valid_and_known_rw_is_not_claimed_ro(self):
        p, _, _ = plan_for()
        inspected = worker.parse_report(p, report_for(p, 0, N0, aliases=False), 0, N0)
        self.assertEqual(inspected['ranges'], [])
        applied = worker.parse_report(p, report_for(p, 1, N1, aliases=False,
                                            overrides={'native_status': -16, 'readonly': -16}), 1, N1)
        self.assertTrue(applied['complete'])
        self.assertTrue(applied['cleanup_safe'])
        self.assertEqual(applied['readonly'], -16)

    def test_safe_inspect_refusal_has_no_full_restore_claim(self):
        p, _, _ = plan_for()
        raw = report_for(p, 0, N0, overrides={'phase': 2, 'native_status': -16,
                         'flags': 0, 'cross_matches': 1, 'offender_pid': 900}, preimage_override=bytes(4096))
        r = worker.parse_report(p, raw, 0, N0)
        self.assertTrue(r['safe_inspect_refusal'])
        self.assertTrue(r['cleanup_safe'])
        self.assertFalse(r['preimage_captured'])
        self.assertFalse(r['complete'])

    def test_partial_uncaptured_snapshot_is_diagnostic_only(self):
        p, _, _ = plan_for()
        raw = report_for(p, 0, N0, overrides={'phase': 2, 'native_status': -84, 'flags': 64},
                         preimage_override=b'partial unverified' + bytes(4096 - 18))
        r = worker.parse_report(p, raw, 0, N0)
        self.assertTrue(r['cleanup_safe'])
        self.assertFalse(r['preimage_captured'])
        self.assertFalse(r['ranges'][0]['preimage_captured'])

    def test_destructive_mremap_failure_changed_zero_is_unknown(self):
        p, _, _ = plan_for()
        raw = report_for(p, 1, N1, overrides={'phase': 5, 'native_status': -12,
                         'flags': 198, 'changed_aliases': 0, 'bytes_truncated': 0})
        r = worker.parse_report(p, raw, 1, N1)
        self.assertTrue(r['mapping_state_unknown'])
        self.assertFalse(r['cleanup_safe'])
        self.assertEqual(r['changed_aliases'], 0)
        self.assertFalse(r['truncated'])


class ProtocolTests(unittest.TestCase):
    def inspected(self):
        p, source, target = plan_for()
        protocol = session.TailRestoreProtocol(p)
        protocol.request(0, N0); protocol.accept(report_for(p, 0, N0))
        return p, source, target, protocol

    def test_required_full_source_then_full_target_barriers(self):
        p, source, target, protocol = self.inspected()
        with self.assertRaises(ValueError):
            protocol.request(1, N1)
        protocol.confirm_source(source)
        with self.assertRaises(ValueError):
            protocol.request(1, N0)
        protocol.request(1, N1); protocol.accept(report_for(p, 1, N1))
        with self.assertRaises(ValueError):
            protocol.finish()
        protocol.confirm_readback(target)
        final = protocol.finish()
        self.assertTrue(final['full_file_restore_complete'])
        self.assertFalse(final['post_boot_full_file_verification_complete'])
        with self.assertRaises(ValueError):
            protocol.request(1, b'3' * 16)

    def test_semantic_readback_failure_allows_known_native_cleanup_not_success(self):
        p, source, target, protocol = self.inspected()
        protocol.confirm_source(source); protocol.request(1, N1); protocol.accept(report_for(p, 1, N1))
        with self.assertRaises(ValueError):
            protocol.confirm_readback(target + b'unexpected tail')
        self.assertEqual(protocol.state, 'STOP_TARGET_READBACK_MISMATCH')
        self.assertTrue(protocol.cleanup_admission()['native_pair_cleanup_allowed'])
        with self.assertRaises(ValueError):
            protocol.finish()

    def test_pid_drift_or_partial_report_never_allows_cleanup_or_retry(self):
        for mode in ('pid', 'partial'):
            p, source, _, protocol = self.inspected()
            protocol.confirm_source(source); protocol.request(1, N1)
            raw = report_for(p, 1, N1, overrides={'pid': 701} if mode == 'pid' else None)
            with self.assertRaises(ValueError):
                protocol.accept(raw if mode == 'pid' else raw[:-1])
            self.assertEqual(protocol.state, 'STOP_UNKNOWN')
            self.assertFalse(protocol.cleanup_admission()['native_pair_cleanup_allowed'])
            with self.assertRaises(ValueError):
                protocol.request(1, b'4' * 16)

    def test_known_refusal_and_attempted_mremap_failure_are_distinct(self):
        p, source, _, protocol = self.inspected()
        protocol.confirm_source(source); protocol.request(1, N1)
        raw = report_for(p, 1, N1, overrides={'phase': 5, 'native_status': -12, 'flags': 198,
                                            'changed_aliases': 0, 'bytes_truncated': 0})
        protocol.accept(raw)
        self.assertEqual(protocol.state, 'STOP_UNKNOWN')
        self.assertFalse(protocol.cleanup_admission()['native_pair_cleanup_allowed'])
        other = session.TailRestoreProtocol(p); other.request(0, N0)
        raw = report_for(p, 0, N0, overrides={'phase': 2, 'native_status': -16, 'flags': 0,
                                            'cross_matches': 1}, preimage_override=bytes(4096))
        other.accept(raw)
        self.assertEqual(other.state, 'STOP_KNOWN_REFUSAL')
        self.assertTrue(other.cleanup_admission()['native_pair_cleanup_allowed'])
        self.assertFalse(other.cleanup_admission()['automatic_retry_allowed'])


if __name__ == '__main__':
    unittest.main()
