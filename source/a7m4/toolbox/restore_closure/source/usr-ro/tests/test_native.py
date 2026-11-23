# SPDX-License-Identifier: MIT
"""Finite synthetic cases: real ARM64 instructions, no camera/network IO."""
from pathlib import Path
import argparse
import importlib.util
import json
import unittest

from arm64_fixture import Fixture

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('usr_ro_worker_test', ROOT / 'worker.py')
WORKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(WORKER)
OPTIONS = None
OBSERVATIONS = []


class NativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.output = Path(OPTIONS.output).absolute()
        cls.output.mkdir(mode=0o700, exist_ok=False)
        cls.plan = WORKER.make_plan()
        cls.built = WORKER.build(cls.plan, cls.output / 'build', compiler=OPTIONS.compiler)
        cls.nonce = b'\x07' * 16
        cls.packet = WORKER.request(cls.plan, cls.nonce)
        assert cls.built['double_build_identical'] and cls.built['target_ABI_checked']
        assert 0 < cls.built['worker']['size'] < 65536

    def fixture(self, **kwargs):
        return Fixture(WORKER, self.built['worker'], **kwargs)

    def parse(self, raw):
        return WORKER.parse_report(self.plan, raw, self.nonce, expected_request=self.packet)

    def record(self, label, fixture, report=None):
        OBSERVATIONS.append(dict(case=label, state=report['state'] if report else 'HOST_REJECTED',
                                 remounts=fixture.remounts, all_fds_closed=fixture.final_fds == 0,
                                 events=fixture.events))

    def test_01_rw_to_ro_exactly_one_attempt(self):
        f = self.fixture(); r = self.parse(f.run(self.packet))
        self.assertEqual(r['state'], 'REMOUNTED_RO')
        self.assertTrue(r['complete']); self.assertEqual(f.remounts, [0xc31])
        self.assertFalse(r['healthy_stop_authorized']); self.assertFalse(r['ap_state_inferred'])
        self.record('RW_TO_RO', f, r)

    def test_02_already_ro_noop_with_fresh_confirmation(self):
        f = self.fixture(ro=True); r = self.parse(f.run(self.packet))
        self.assertEqual(r['state'], 'ALREADY_RO'); self.assertEqual(f.remounts, [])
        self.assertTrue(r['readonly_confirmed']); self.record('ALREADY_RO', f, r)

    def test_03_duplicate_usr_refused(self):
        line = b'/dev/nflasha15 /usr ext2 rw 0 0\n'
        f = self.fixture(mounts=line + line); r = self.parse(f.run(self.packet))
        self.assertEqual(r['state'], 'REFUSED'); self.assertEqual(f.remounts, [])
        self.record('DUPLICATE_USR', f, r)

    def test_04_wrong_fs_source_or_nested_mount_refused(self):
        for mounts in (b'/dev/nflasha15 /usr ext4 rw 0 0\n',
                       b'/dev/not-m4 /usr ext2 rw 0 0\n',
                       b'/dev/nflasha15 /usr ext2 rw 0 0\n/dev/foo /usr/share ext2 ro 0 0\n'):
            f = self.fixture(mounts=mounts); r = self.parse(f.run(self.packet))
            self.assertEqual(r['state'], 'REFUSED'); self.assertEqual(f.remounts, [])
            self.record('MOUNT_ADMISSION_REFUSED', f, r)

    def test_05_ebusy_is_known_ro_pending_without_retry(self):
        f = self.fixture(mount_error=-16); r = self.parse(f.run(self.packet))
        self.assertEqual(r['state'], 'RO_PENDING'); self.assertEqual(f.remounts, [0xc31])
        self.assertFalse(r['complete']); self.assertTrue(r['known_ro_pending'])
        self.assertFalse(r['automatic_retry_permitted']); self.assertFalse(r['ap_state_inferred'])
        self.record('EBUSY_KNOWN_PENDING', f, r)

    def test_06_input_and_output_close_failures_are_host_rejection(self):
        for path in (WORKER.REQUEST_PATH, '/proc/self/mounts', WORKER.PENDING_PATH):
            f = self.fixture(close_fail=path); raw = f.run(self.packet)
            with self.assertRaises(ValueError):
                self.parse(raw)
            if path != WORKER.PENDING_PATH:
                self.assertEqual(f.remounts, [])
            else:
                self.assertIsNone(raw)
            self.record('CLOSE_FAILURE_HOST_REJECTION', f)

    def test_07_zero_nonce_and_wrong_plan_never_mount(self):
        for lo, hi in ((16, 32), (32, 64)):
            packet = self.packet[:lo] + bytes(hi-lo) + self.packet[hi:]
            f = self.fixture(); raw = f.run(packet)
            self.assertEqual(f.remounts, [])
            with self.assertRaises(ValueError):
                self.parse(raw)
            self.record('NONCE_PLAN_REJECTION', f)

    def test_08_strict_request_and_report_framing(self):
        for packet in (self.packet[:-1], self.packet + b'x'):
            f = self.fixture(); raw = f.run(packet)
            self.assertEqual(f.remounts, [])
            with self.assertRaises(ValueError):
                self.parse(raw)
            self.record('REQUEST_FRAMING_REJECTION', f)
        f = self.fixture(ro=True); raw = f.run(self.packet)
        for mutated in (raw[:-1], raw+b'x', b'BADMAGIC'+raw[8:], raw[:32]+b'X'+raw[33:]):
            with self.assertRaises(ValueError):
                self.parse(mutated)
        with self.assertRaises(ValueError):
            WORKER.parse_report(self.plan, raw, b'\x08'*16)

    def test_09_root_real_proc_loader_identity_and_fresh_budget_admission(self):
        for kwargs in (dict(euid=1000), dict(proc_magic=0x1234),
                       dict(loader_match=False), dict(free_bytes=8*1024*1024)):
            f = self.fixture(**kwargs); raw = f.run(self.packet)
            self.assertEqual(f.remounts, [])
            if kwargs.get('euid'):
                with self.assertRaises(ValueError):
                    self.parse(raw)
                self.record('ROOT_REQUEST_NOT_ADMITTED', f)
            else:
                r = self.parse(raw); self.assertEqual(r['state'], 'REFUSED')
                self.record('PROC_LOADER_BUDGET_REFUSED', f, r)

    def test_10_failed_report_publication_and_post_mount_unknown_rejected(self):
        f = self.fixture(report_write_error=True)
        self.assertIsNone(f.run(self.packet)); self.assertEqual(f.remounts, [0xc31])
        self.record('REPORT_WRITE_FAILURE', f)
        # A syscall-success report with unknown final mount state cannot be
        # promoted to RO. Mutating a captured diagnostic tests host admission.
        f = self.fixture(); raw = f.run(self.packet)
        fields = list(WORKER.REPORT.unpack(raw))
        fields[4:8] = [5, 31, 4, 1]
        fields[8] = -22; fields[17] = -22
        with self.assertRaises(ValueError):
            self.parse(WORKER.REPORT.pack(*fields))


    def test_11_large_maps_complete_EOF_and_finite_overflow(self):
        def view(size):
            def make(line):
                filler=b'40000000-40001000 r--p 00000000 00:00 0 /synthetic/'
                row=filler+b'x\n'
                n=size-len(line)
                count=max(0,(n-len(filler)-1)//len(row))
                tail=filler+b'x'*(n-count*len(row)-len(filler)-1)+b'\n'
                data=row*count+tail+line
                assert len(data)==size
                return data
            return make
        for size in (131072,1048576,1048577):
            f=self.fixture(maps_transform=view(size),read_chunk=4093,instruction_limit=200000000)
            report=self.parse(f.run(self.packet))
            if size<=1048576:
                self.assertEqual(report['state'],'REMOUNTED_RO')
                self.assertTrue(f.maps_eof_seen)
                self.assertEqual(f.maps_read_bytes,size)
            else:
                self.assertEqual(report['state'],'REFUSED')
                self.assertEqual(f.remounts,[])
            self.record('MAPS_FINITE_CAP_'+str(size),f,report)


def main():
    global OPTIONS
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--compiler', required=True)
    p.add_argument('--output', required=True)
    OPTIONS = p.parse_args()
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(NativeTests))
    paths = [ROOT/'native/usr_ro.c', ROOT/'worker.py', Path(__file__), Path(__file__).with_name('arm64_fixture.py')]
    receipt = dict(schema='a7m4-usr-ro-synthetic-arm-tests/1',
                   status='PASS' if result.wasSuccessful() else 'FAIL', tests_run=result.testsRun,
                   failures=len(result.failures), errors=len(result.errors),
                   camera_io=False, network_io=False, private_firmware_inputs=False,
                   deployment_admission=False, cases=OBSERVATIONS,
                   source_sha256={str(path.resolve()): WORKER.sha256(path.read_bytes()) for path in paths},
                   compiler=str(Path(OPTIONS.compiler).resolve()),
                   limitations=['Finite syscall model, no real ext2/kernel/VFAT/power-loss or USB health proof.',
                                'Freshness and exclusive transport ownership belong to the product NativeActions owner.',
                                'No automatic retries or external-writer fd closure are implemented.'])
    if Path(OPTIONS.output).exists():
        (Path(OPTIONS.output)/'native-test-results.json').write_text(json.dumps(receipt, indent=2)+'\n')
    raise SystemExit(0 if result.wasSuccessful() else 1)


if __name__ == '__main__':
    main()
