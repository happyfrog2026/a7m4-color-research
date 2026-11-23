"""Explicit ordinary-USB channel for frozen, once-only native jobs.

Derived from the Main real test R066 borrowed-channel admission model. No USB
module is imported and no device is discovered until the caller opens a session.
This module does not choose a feature, generate a plan, or authorize execution.
"""
from __future__ import annotations

import hashlib
import re
import struct
import time
from collections.abc import Mapping


class ChannelError(RuntimeError):
    pass


LIBRARY = "/tmp/jiritsu/libJit.so"
_OWNED = re.compile(r"/tmp/jiritsu/[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_SAFE_READ = re.compile(r"/(?:usr|cp|setting)/[A-Za-z0-9_./-]+\Z")


def channel_class(read_paths: Mapping[str, int], owned_paths: Mapping[str, int], *, base=None, readonly_reports=None):
    """Return a channel type for one prevalidated job and exact path inventory.

    ``owned_paths`` is the complete temporary file inventory for the job. A path
    merely being present does not permit an upload: exact bytes must be armed
    for a unique operation before each upload. No shell, reset, or settings SET
    command is exposed. The feature orchestrator owns backup/plan/readback gates.
    """
    reads, owned = dict(read_paths), dict(owned_paths)
    reports=dict(readonly_reports or {})
    fixed_reports={'/tmp/jiritsu/a7m4.ssh-prereq-v2.result','/tmp/jiritsu/a7m4.ssh-prereq-v2.result.pending'}
    if (set(reports)-fixed_reports or set(reports)&(set(reads)|set(owned))
            or any(type(n) is not int or not 0<n<=131072 for n in reports.values())):
        raise ChannelError('Only fixed read-only inventory reports may exceed the upload bound')
    if (LIBRARY not in owned or not reads or set(reads) & set(owned)
            or any(not isinstance(p, str) or not _OWNED.fullmatch(p) for p in owned)
            or any(type(n) is not int or not 0 < n < 65536 for n in owned.values())
            or any(not isinstance(p, str) or (p not in ("/version.txt","/proc/sys/kernel/random/boot_id","/tmp/jbusy") and not _SAFE_READ.fullmatch(p))
                   or any(part in ("", ".", "..") for part in p.split("/")[1:]) for p in reads)
            or any(type(n) is not int or not 0 < n <= 160 * 1024 * 1024 for n in reads.values())
            or reads.get('/tmp/jbusy',0)>64):
        raise ChannelError("Invalid exact native job path inventory")
    if base is None:
        from .usb_read import ReadChannel
        base = ReadChannel
    caps = reads | owned | reports

    class NativeChannel(base):
        def __init__(self, driver, paths=(), begin=None):
            self.selected = None
            self.safe_to_stop = False
            self.native_deadline = None
            self._armed = {}
            self._sent = set()
            self._operations = set()
            self._poisoned = False
            self.audit = []
            owner = self

            class Tap:
                def read(self, length, **kwargs):
                    if owner.native_deadline is None:
                        return driver.read(length, **kwargs)
                    remaining = int((owner.native_deadline - time.monotonic()) * 1000)
                    if kwargs or not 0 < length <= 4096 or not 0 < remaining <= 150000:
                        raise ChannelError("Native reply deadline or transfer bound exceeded")
                    return bytes(driver.backend.dev.read(driver.epIn[0], length, timeout=remaining))

                def write(self, raw):
                    return driver.write(raw)

            super().__init__(Tap(), (), begin)

        def admit_original_stage(self, plan):
            """Add only an SDK-derived original-restore stage as a read path."""
            from .restore_helper_loader import load_helper
            worker, = load_helper('original-atomic')
            worker.validate_plan(plan)
            target, stage = plan['resource_path'], plan['stage_path']
            if (self._poisoned or not self.healthy or self.safe_to_stop
                    or target not in reads or plan['source']['size'] > reads[target]
                    or plan['target']['size'] > reads[target]
                    or stage in owned or stage in reports
                    or stage in caps and caps[stage] != plan['target']['size']):
                raise ChannelError('Original stage is outside the declared restore target')
            stages = getattr(self, '_original_stages', set())
            if len(stages) >= 71 and stage not in stages:
                raise ChannelError('Original stage inventory exhausted')
            stages.add(stage); self._original_stages = stages
            caps[stage] = plan['target']['size']
            return stage

        def arm_uploads(self, operation_id: str, mapping: Mapping[str, bytes]):
            if (self._poisoned or not self.healthy or self.safe_to_stop
                    or not isinstance(operation_id, str) or not re.fullmatch(r"[a-zA-Z0-9._-]{1,128}", operation_id)
                    or operation_id in self._operations or len(self._operations) >= 4096
                    or self._armed and self._sent != set(self._armed)
                    or not isinstance(mapping, Mapping) or not mapping
                    or any(p not in owned or type(raw) is not bytes or not 0 < len(raw) <= owned[p]
                           for p, raw in mapping.items())):
                raise ChannelError("Unfinished, repeated, or unbounded upload operation")
            self._operations.add(operation_id)
            self._armed = dict(mapping)
            self._sent = set()

        def _admit(self, function, data, limit, success, request_limit):
            if function == 0x10:
                if data != struct.pack("<HHB", 0, 0x1f, 0) or limit != 4096 or success != 1:
                    raise ChannelError("Only the fixed HASP read is allowed")
                return None
            if function != 0x40 or len(data) < 4 or success != 0:
                raise ChannelError("Unexpected service function")
            category, command = struct.unpack_from("<HH", data)
            payload = data[4:]
            if category == 0x603:
                valid = (command == 1 and
                         ((payload == struct.pack("<I", 0x00e70003) and limit == 4)
                          or (payload == struct.pack("<I", 0x00510055) and limit == 1)))
                valid |= command == 5 and payload in (b"\0", b"\1") and limit == 32 * 1024 * 1024
                if not valid:
                    raise ChannelError("Settings mutation or undeclared read is forbidden")
                return None
            if category != 0x1001:
                raise ChannelError("Only fixed file operations are allowed")
            if command == 0x400f:
                choices = {self._wire_path(p): p for p in caps}
                if payload not in choices or limit != 4:
                    raise ChannelError("File selection is outside this exact job")
                return choices[payload]
            if self.selected not in caps:
                raise ChannelError("File operation lacks a valid selection")
            path = self.selected
            if command == 0x4011:
                if payload != b"\0\xff\0" or limit != caps[path] + 4:
                    raise ChannelError("File read bound differs")
            elif command == 0x4010:
                if (path not in self._armed or path in self._sent or limit != 4
                        or payload != b"\0\xff\0" + self._armed[path]
                        or request_limit != len(data)):
                    raise ChannelError("Upload must equal its frozen, once-only intent")
                # Admission consumes the intent before I/O; even a lost reply is
                # not permission to write the same operation a second time.
                self._sent.add(path)
            elif command == 0x4012:
                if (path not in owned and path not in reports) or path == LIBRARY or payload != b"\0\xff\0" or limit != 4:
                    raise ChannelError("Deletion is restricted to this job's owned temporary files")
            else:
                raise ChannelError("Unknown file operation")
            return None

        @staticmethod
        def _wire_path(path):
            wire = path if path.startswith("/tmp/jiritsu/") else "/tmp/jiritsu/../../" + path.lstrip("/")
            return b"\0" + wire.encode("ascii") + b"\0"

        def _exchange(self, function, data, limit, success=0, *, request_limit=1024):
            if self._poisoned or not self.healthy:
                raise ChannelError("STOP_UNKNOWN: channel cannot be reused")
            selection = self._admit(function, data, limit, success, request_limit)
            native = (function == 0x40 and data[:4] == struct.pack("<HH", 0x1001, 0x4010)
                      and self.selected == LIBRARY)
            self.native_deadline = time.monotonic() + 150 if native else None
            self.audit.append({"function": function, "request_bytes": len(data),
                               "request_sha256": hashlib.sha256(data).hexdigest(),
                               "reply_limit": limit, "reply_verified": False})
            try:
                raw = super()._exchange(function, data, limit, success, request_limit=request_limit)
                if selection is not None:
                    if raw != bytes(4):
                        raise ChannelError("File selection was rejected")
                    self.selected = selection
                elif function == 0x40 and data[:2] == struct.pack("<H", 0x1001):
                    self.selected = None
                self.audit[-1]["reply_verified"] = True
                return raw
            except BaseException:
                self._poisoned = True
                self.healthy = self.safe_to_stop = False
                raise
            finally:
                self.native_deadline = None

        def _select(self, path):
            if path not in caps:
                raise ChannelError("Undeclared path")
            self._exchange(0x40, struct.pack("<HH", 0x1001, 0x400f) + self._wire_path(path), 4)

        def peek(self, path):
            self._select(path)
            raw = self._exchange(0x40, struct.pack("<HH", 0x1001, 0x4011) + b"\0\xff\0", caps[path] + 4)
            if len(raw) < 4:
                self._poisoned = True
                self.healthy = self.safe_to_stop = False
                raise ChannelError("Truncated file result")
            status = struct.unpack_from("<I", raw)[0]
            if status not in (0, 0x10000006) or status and len(raw) != 4:
                self._poisoned = True
                self.healthy = self.safe_to_stop = False
                raise ChannelError("Unknown file status")
            return None if status else raw[4:]

        def file(self, path, maximum=None):
            if maximum is not None and (type(maximum) is not int or not 0 < maximum <= caps.get(path, 0)):
                raise ChannelError("Read maximum differs from declared inventory")
            raw = self.peek(path)
            if raw is None or maximum is not None and len(raw) > maximum:
                raise ChannelError("Required complete file is missing or oversized")
            return raw

        def upload(self, path):
            if path not in self._armed:
                raise ChannelError("No exact upload intent")
            self._select(path)
            raw = self._armed[path]
            data = struct.pack("<HH", 0x1001, 0x4010) + b"\0\xff\0" + raw
            if self._exchange(0x40, data, 4, request_limit=len(data)) != bytes(4):
                self._poisoned = True
                self.healthy = self.safe_to_stop = False
                raise ChannelError("Upload returned failure; do not replay")

        def delete_owned(self, path):
            self._select(path)
            data = struct.pack("<HH", 0x1001, 0x4012) + b"\0\xff\0"
            if self._exchange(0x40, data, 4) != bytes(4):
                self._poisoned = True
                self.healthy = self.safe_to_stop = False
                raise ChannelError("Owned cleanup result is unknown")

        def read_ap55(self):
            return self._exchange(0x40, struct.pack("<HHI", 0x603, 1, 0x00510055), 1)

        def allow_clean_stop(self):
            if self._poisoned or not self.healthy or self._sent != set(self._armed):
                raise ChannelError("Cannot stop an unknown or incomplete native job")
            self.safe_to_stop = True

    return NativeChannel
