# SPDX-License-Identifier: MIT
"""Small transport-free state machine for portable owned-resource tail restore.

The product owns USB/session locks, fresh VFAT admission, original-backup/body/runtime-proof
validation, exact temporary-file cleanup, WBI policy and final boot acceptance.
This class emits request bytes and accepts complete reports/complete Mac reads;
it never contacts a device and cannot authorize START/STOP or automatic retry.
"""
from __future__ import annotations

from copy import deepcopy
import importlib.util
from pathlib import Path

try:
    from . import worker
except ImportError:
    _spec = importlib.util.spec_from_file_location('a7m4_portable_tail_worker', Path(__file__).with_name('worker.py'))
    worker = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(worker)


class TailRestoreProtocol:
    def __init__(self, plan):
        self.plan = worker.validate_plan(plan)
        self.state = 'READY_FOR_INSPECTION'
        self.pending = None
        self.inspection = None
        self.applied = None
        self.nonces = set()
        self.source_barrier = None
        self.target_barrier = None
        self.last_report = None

    def request(self, mode, nonce16):
        expected = {0: 'READY_FOR_INSPECTION', 1: 'FULL_SOURCE_MAC_VERIFIED'}
        worker._need(type(mode) is int and mode in expected and self.state == expected[mode]
                     and self.pending is None, 'Inspect then fresh full source read before one apply; no replay')
        worker._nonce(nonce16)
        worker._need(nonce16 not in self.nonces, 'Every native phase requires a distinct fresh nonce')
        raw = worker.request(self.plan, mode, nonce16, self.inspection if mode else None)
        self.nonces.add(nonce16)
        self.pending = (mode, nonce16)
        self.state = 'INSPECTION_PENDING' if mode == 0 else 'APPLY_PENDING'
        return raw

    def accept(self, raw):
        worker._need(self.pending is not None and self.state in ('INSPECTION_PENDING', 'APPLY_PENDING'),
                     'No native report pending')
        mode, nonce = self.pending
        try:
            report = worker.parse_report(self.plan, raw, mode, nonce)
            if mode == 1 and report['complete']:
                worker._need(report['range_fingerprint_sha256'] == self.inspection['range_fingerprint_sha256'],
                             'Apply identity/PID/ranges differ from admitted native inspection')
        except BaseException:
            self.state = 'STOP_UNKNOWN'
            raise
        self.pending = None
        self.last_report = deepcopy(report)
        if report['complete']:
            if mode == 0:
                self.inspection = deepcopy(report)
                self.state = 'INSPECTED_NEEDS_FULL_SOURCE_MAC_READ'
            else:
                self.applied = deepcopy(report)
                self.state = 'APPLIED_NEEDS_FULL_TARGET_MAC_READ'
        else:
            self.state = 'STOP_KNOWN_REFUSAL' if report['cleanup_safe'] else 'STOP_UNKNOWN'
        return deepcopy(report)

    def confirm_source(self, complete_bytes):
        worker._need(self.state == 'INSPECTED_NEEDS_FULL_SOURCE_MAC_READ' and self.pending is None,
                     'Only a fresh complete Mac source read after inspection establishes the apply barrier')
        try:
            proof = worker.verify_source(self.plan, complete_bytes)
        except BaseException:
            self.state = 'STOP_SOURCE_MISMATCH'
            raise
        self.source_barrier = proof
        self.state = 'FULL_SOURCE_MAC_VERIFIED'
        return deepcopy(proof)

    def confirm_readback(self, complete_bytes):
        worker._need(self.state == 'APPLIED_NEEDS_FULL_TARGET_MAC_READ' and self.pending is None,
                     'Native completion must precede complete Mac target readback')
        try:
            proof = worker.verify_readback(self.plan, complete_bytes)
        except BaseException:
            # Native has already finished and its exact pair may be cleaned;
            # a semantic SHA failure does not by itself mean unfinished native I/O.
            self.state = 'STOP_TARGET_READBACK_MISMATCH'
            raise
        self.target_barrier = proof
        self.state = 'FULL_TARGET_MAC_VERIFIED'
        return deepcopy(proof)

    def finish(self):
        worker._need(self.state == 'FULL_TARGET_MAC_VERIFIED' and self.pending is None
                     and self.source_barrier is not None and self.target_barrier is not None
                     and self.applied is not None and self.applied['complete'],
                     'Exact full source and target Mac barriers plus native completion are required')
        self.state = 'COMPLETE'
        return dict(schema=worker.FAMILY, plan_id=self.plan['plan_id'],
                    resource_path=self.plan['resource_path'], full_file_restore_complete=True,
                    post_boot_full_file_verification_complete=False,
                    source_readback=deepcopy(self.source_barrier), target_readback=deepcopy(self.target_barrier),
                    native_report_sha256=self.applied['report_sha256'],
                    current_usr_readonly_verified=self.applied['readonly'] == 0,
                    requires_post_boot_readonly_verification=self.applied['readonly'] != 0,
                    no_automatic_retry=True, WBI_write=False, NOR_write=False,
                    camera_io=False, network_io=False)

    def cleanup_admission(self):
        """Native known completion/refusal only; transport cleanup stays external."""
        safe = self.pending is None and self.last_report is not None and self.last_report['cleanup_safe']
        return dict(native_pair_cleanup_allowed=bool(safe),
                    native_state_unknown=self.state == 'STOP_UNKNOWN',
                    automatic_retry_allowed=False, state=self.state)
