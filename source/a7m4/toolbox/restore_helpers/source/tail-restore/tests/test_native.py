# SPDX-License-Identifier: MIT
"""Nine finite synthetic ARM64 mechanism tests, without camera access.

Run with an explicit offline Zig 0.13.0 executable. All input bytes are
generated locally; no Sony image, body identifier or retained receipt is read.
The fake kernel deliberately removes a fixed-remap destination before ENOMEM.
"""
from pathlib import Path
from copy import deepcopy
import argparse
import hashlib
import importlib.util
import json
import struct
import unittest

from arm64_fixture import NativeFixture

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('portable_tail_worker_test', ROOT / 'worker.py')
WORKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(WORKER)

SHA = lambda raw: hashlib.sha256(raw).hexdigest()
OPTIONS = None
OBSERVATIONS = []


def synthetic_bytes(length, label):
    """Deterministic UXC-labelled patterns; never a usable camera baseline."""
    seed = ('SYNTHETIC_ONLY_NOT_DEVICE_ADMISSION/' + label).encode()
    result = bytearray()
    for index in range((length + 31) // 32):
        result.extend(hashlib.sha256(seed + struct.pack('<I', index)).digest())
    result = result[:length]
    # Public container label with four absent resource indices. The remaining
    # bytes are synthetic, deliberately unrelated to any original firmware.
    header = b'uxc\x07\0\0\0\0' + struct.pack('<HHI', 8, 5, 4 | (4 << 12))
    if length >= 24:
        result[:24] = header + b'\xff\xff' * 4
    return bytes(result)


def make_fixture_plan(resource_path, target_size, tail_size, label):
    target = synthetic_bytes(target_size, label + '/baseline')
    tail = synthetic_bytes(tail_size, label + '/owned-tail')
    source = target + tail
    plan = WORKER.make_plan(resource_path, source, target, authority={
        'schema': 'a7m4-owned-tail-authority/1',
        'original_backup_sha256': SHA(b'SYNTHETIC_ORIGINAL_BACKUP_NOT_AUTHORIZATION'),
        'current_file_readback_sha256': SHA(source),
        'resource_reference_proof_sha256': SHA(b'SYNTHETIC_REFERENCE_PROOF_NOT_AUTHORIZATION'),
        'boot_or_load_proof_sha256': SHA(b'SYNTHETIC_LOAD_PROOF_NOT_AUTHORIZATION'),
    })
    return plan, source, target


def summarize(report):
    fields = ('mode', 'phase', 'native_status', 'range_count', 'cross_pids',
              'cross_matches', 'mremap_attempts', 'changed_aliases', 'anon_bytes',
              'bytes_truncated', 'readonly', 'complete', 'cleanup_safe',
              'mapping_state_unknown', 'full_file_restore_complete',
              'full_readback_required', 'preimage_captured')
    return {key: report[key] for key in fields}


class NativeMechanismTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # This directory is in the explicit test-output tree, not the OS /var
        # symlink. The portable builder rejects symlinked output ancestors.
        cls.output = Path(OPTIONS.output).absolute()
        cls.output.mkdir(mode=0o700, parents=True, exist_ok=False)
        cls.bank_plan, cls.bank_source, cls.bank_target = make_fixture_plan(
            '/usr/share/app/image_00_32_IPSX.uxc', 8192 + 752, 11528, 'bank')
        cls.string_plan, cls.string_source, cls.string_target = make_fixture_plan(
            '/usr/share/app/string_english_horizontal.uxc', 900, 150, 'string')
        cls.bank_build = WORKER.build(cls.bank_plan, cls.output / 'bank', compiler=OPTIONS.compiler)
        cls.string_build = WORKER.build(cls.string_plan, cls.output / 'string', compiler=OPTIONS.compiler)
        for built in (cls.bank_build, cls.string_build):
            assert built['target_ABI_checked'] and built['double_build_identical']
            assert 0 < built['worker']['size'] < 65536

    def fixture(self, *, string=False, **kwargs):
        plan, source, target, build = (
            (self.string_plan, self.string_source, self.string_target, self.string_build)
            if string else (self.bank_plan, self.bank_source, self.bank_target, self.bank_build))
        return NativeFixture(module=WORKER, plan=deepcopy(plan), artifact=build['worker'],
                             source=source, target=target, **kwargs)

    def phase(self, fixture, mode, nonce_number, inspection=None):
        nonce = bytes([nonce_number]) * 16
        request = WORKER.request(fixture.plan, mode, nonce, inspection)
        self.assertEqual(len(request), 256)
        report, raw = fixture.run(request, lambda value: WORKER.parse_report(
            fixture.plan, value, mode, nonce))
        self.assertLessEqual(len(raw), 65536)
        self.assertEqual(report['source_dev'], NativeFixture.DEV)
        self.assertEqual(report['source_ino'], NativeFixture.INO)
        self.assertEqual(report['source_uid'], NativeFixture.UID)
        self.assertEqual(report['source_gid'], NativeFixture.GID)
        self.assertFalse(report['full_file_restore_complete'])
        self.assertTrue(report['full_readback_required'])
        return report, raw

    def roundtrip(self, fixture, *, expected_ranges, expected_shadow, empty_maps=0):
        source_before_inspection = bytes(fixture.data)
        inspect, inspect_raw = self.phase(fixture, 0, 1)
        self.assertTrue(inspect['complete'])
        self.assertEqual(inspect['range_count'], expected_ranges)
        self.assertEqual(bytes(fixture.data), source_before_inspection)
        self.assertEqual(fixture.remounts, [])
        self.assertEqual(fixture.truncates, [])
        source_shadow = list(fixture.last_live_shadows)
        applied, apply_raw = self.phase(fixture, 1, 2, inspect)
        self.assertTrue(applied['complete'])
        self.assertTrue(applied['cleanup_safe'])
        self.assertFalse(applied['mapping_state_unknown'])
        self.assertEqual(applied['changed_aliases'], expected_ranges)
        self.assertEqual(applied['mremap_attempts'], expected_ranges)
        self.assertEqual(applied['anon_bytes'], expected_shadow)
        self.assertEqual(fixture.last_live_shadows, source_shadow)
        self.assertEqual(bytes(fixture.data), fixture.target)
        self.assertEqual(SHA(fixture.data), fixture.plan['target']['sha256'])
        self.assertEqual(fixture.truncates, [len(fixture.target)])
        self.assertEqual(fixture.remounts, [False, True])
        self.assertGreaterEqual(applied['cross_pids'], empty_maps)
        OBSERVATIONS.append(dict(test=self.id(), status='PASS',
            inspect=summarize(inspect), apply=summarize(applied),
            raw_report_sizes=[len(inspect_raw), len(apply_raw)],
            target_size=len(fixture.data), target_sha256=SHA(fixture.data),
            native_source_stat_is_synthetic=True, same_VA_bytes_preserved=True))

    def refusal(self, fixture, expected_status):
        before = bytes(fixture.data)
        report, raw = self.phase(fixture, 0, 3)
        self.assertFalse(report['complete'])
        self.assertTrue(report['safe_inspect_refusal'])
        self.assertTrue(report['cleanup_safe'])
        self.assertFalse(report['mapping_state_unknown'])
        self.assertEqual(report['native_status'], expected_status)
        self.assertEqual(bytes(fixture.data), before)
        self.assertEqual(fixture.remounts, [])
        self.assertEqual(fixture.truncates, [])
        self.assertEqual(fixture.attempts, 0)
        self.assertFalse(any(event[0] == 'anonymous' for event in fixture.events))
        OBSERVATIONS.append(dict(test=self.id(), status='PASS', report=summarize(report),
            raw_report_size=len(raw), synthetic_source_bytes_unchanged=True))

    def test_01_bank_multiple_tail_pages_and_300_empty_kernel_maps(self):
        self.roundtrip(self.fixture(empty_processes=300), expected_ranges=1,
                       expected_shadow=12288, empty_maps=300)

    def test_02_string_append_within_last_partial_page(self):
        self.roundtrip(self.fixture(string=True), expected_ranges=1, expected_shadow=4096)

    def test_03_no_tail_alias_requires_no_anonymous_mapping(self):
        self.roundtrip(self.fixture(mapping='none'), expected_ranges=0, expected_shadow=0)

    def test_04_split_tail_aliases_preserve_both_original_addresses(self):
        self.roundtrip(self.fixture(mapping='split'), expected_ranges=2, expected_shadow=12288)

    def test_05_other_process_tail_mapping_refuses_without_mutation(self):
        self.refusal(self.fixture(foreign_mapping=True), -16)

    def test_06_shared_tail_mapping_refuses_without_mutation(self):
        self.refusal(self.fixture(private=False), -13)

    def test_07_writable_tail_mapping_refuses_without_mutation(self):
        self.refusal(self.fixture(permissions=3), -13)

    def test_08_executable_tail_mapping_refuses_without_mutation(self):
        self.refusal(self.fixture(permissions=5), -13)

    def test_09_failed_fixed_remap_after_destination_unmapped_is_unknown(self):
        fixture = self.fixture(remap_failure=True)
        inspect, _ = self.phase(fixture, 0, 4)
        self.assertTrue(inspect['complete'])
        before = bytes(fixture.data)
        report, raw = self.phase(fixture, 1, 5, inspect)
        self.assertFalse(report['complete'])
        self.assertFalse(report['cleanup_safe'])
        self.assertTrue(report['mapping_state_unknown'])
        self.assertEqual(report['native_status'], -12)
        self.assertEqual(report['mremap_attempts'], 1)
        self.assertEqual(report['changed_aliases'], 0)
        self.assertEqual(report['bytes_truncated'], 0)
        self.assertEqual(bytes(fixture.data), before)
        self.assertEqual(fixture.truncates, [])
        self.assertEqual(fixture.remounts, [])
        self.assertFalse(any(event[0] == 'truncate' for event in fixture.events))
        OBSERVATIONS.append(dict(test=self.id(), status='PASS', report=summarize(report),
            raw_report_size=len(raw), destination_actually_unmapped_before_ENOMEM=True,
            synthetic_source_bytes_unchanged=True,
            native_cleanup_admission_denied=True, healthy_STOP_not_authorized_by_report=True))


def main():
    global OPTIONS
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler', required=True, help='Offline Zig 0.13.0 executable')
    parser.add_argument('--output', required=True, help='New, real test output directory')
    OPTIONS = parser.parse_args()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(NativeMechanismTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    paths = [ROOT / 'native/tail_restore.c', ROOT / 'worker.py',
             Path(__file__), Path(__file__).with_name('arm64_fixture.py')]
    receipt = dict(schema='a7m4-tail-restore-synthetic-arm-tests/1',
        status='PASS' if result.wasSuccessful() else 'FAIL', tests_run=result.testsRun,
        failures=len(result.failures), errors=len(result.errors),
        device_io=False, network_io=False, private_firmware_inputs=False,
        deployment_admission=False, source_sha256={str(path.resolve()): SHA(path.read_bytes()) for path in paths},
        compiler=str(Path(OPTIONS.compiler).resolve()), cases=OBSERVATIONS,
        limitations=[
            'Real ARM64 instructions execute under Unicorn with a finite simulated syscall model.',
            'These are synthetic UXClabelled bytes and non-camera file identities, never device evidence.',
            'No proof of all Linux mmap races, ext2 metadata behavior, low-memory or power-loss behavior.',
            'Host prefix/nonce/plan/session barriers are independently tested by the protocol owner.',
            'No actual USB START/STOP occurs; unsafe native results deny cleanup admission only.',
        ])
    output = Path(OPTIONS.output)
    if output.exists():
        (output / 'native-test-results.json').write_text(json.dumps(receipt, indent=2) + '\n')
    raise SystemExit(0 if result.wasSuccessful() else 1)


if __name__ == '__main__':
    main()
