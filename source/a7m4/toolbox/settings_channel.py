"""Fixed settings wire codec borrowed from an existing Main-owned channel.

Adapted from native/service-fl23-settings/usb.py (MIT). Importing never loads
USB, enumerates devices, opens a session or grants StopSenser. Exact request
bytes must be durably journaled before dispatch. No retries or generic SET,
file upload, WBI, memory, block, shell or firmware write API is provided.
"""
from __future__ import annotations

import struct

from .settings_plan import (KEYS, SIZES, AP55, SERIAL, MAX_SETTINGS_BYTES, needs_save,
                            SettingsError, need, parse_snapshot, validate_plan)

HEADER = struct.Struct("<IHHBBBB")
MAX_TRANSFER = 0x100000
BACKING = frozenset(("/setting/BACKUP.BIN", "/setting/BACKUP.BAK"))
BACKING_CAP = 8 * 1024 * 1024


class SettingsChannel:
    def __init__(self, owner, *, intent, reply):
        need(getattr(owner, "healthy", False) is True and type(owner.sequence) is int
             and callable(intent) and callable(reply), "Healthy borrowed channel and durable raw journals required")
        self.owner, self.driver = owner, owner.driver
        self.intent, self.reply = intent, reply
        self.healthy = True
        self.camera_io = False
        self.mutation_attempted = False
        self.unknown_remote_state = False
        self._armed = None
        self._writes, self._saves, self._nonces = set(), set(), set()
        self._steps = []
        self.before_mutation_dispatch = None
        self._last_capture = None

    def _poison(self, unknown=False):
        self.healthy = self.owner.healthy = False
        self.owner.safe_to_stop = False
        self.unknown_remote_state |= unknown

    def arm(self, plan):
        validate_plan(plan)
        need(self.healthy and self.owner.healthy and self._armed is None
             and plan.nonce not in self._nonces, "Settings plan is single-use on an exclusive channel")
        self._armed = plan
        self._nonces.add(plan.nonce)
        self._writes, self._saves = set(), set()
        self.mutation_attempted = False
        self._steps = []
        for group in plan.groups:
            records = [r for r in plan.records if r.key >> 16 == group]
            save = needs_save(plan,group)
            from . import looks_settings
            different=lambda r,a,b:not looks_settings.equal(a,b,r.spans) if looks_settings.active(plan) else a!=b
            if save:
                self._steps.extend(("write", r.chip, r.key, r.after_saved)
                                   for r in records if different(r,r.before_ram,r.after_saved))
                self._steps.append(("save", group))
            self._steps.extend(("write", r.chip, r.key, r.after_ram) for r in records
                               if different(r,r.after_saved if save else r.before_ram,r.after_ram))

    def disarm(self):
        self._armed = None
        self._steps = []

    def _exchange(self, command, payload, cap, *, operation, category=0x603,
                  expected=None, empty=False, terminal=False, mutation=False, **facts):
        need(self.healthy and self.owner.healthy, "STOP_UNKNOWN: failed settings channel cannot be reused")
        frame = struct.pack("<HH", category, command) + payload
        need(0 < len(frame) < 65536 and 0 < cap <= MAX_SETTINGS_BYTES + 4,
             "Fixed settings request/reply bounds differ")
        sequence = self.owner.sequence
        request = HEADER.pack(len(frame), 0x40, sequence, 0, 0, 0, 0) + frame
        observation = dict(operation=operation, category=category, command=command,
                           sequence=sequence, request=request, **facts)
        wire, tail, body = bytearray(), b"", None
        dispatch = recorded = response_recorded = False

        def exact(count):
            output, blanks = bytearray(), 0
            while len(output) < count:
                raw = bytes(self.driver.read(min(4096, count - len(output))))
                wire.extend(raw)
                need(len(raw) <= count - len(output) and len(wire) <= cap + 16384,
                     "Settings response exceeds exact bounded frame")
                if not raw:
                    blanks += 1
                    need(blanks <= 64, "Too many empty settings transfers")
                else:
                    output.extend(raw)
                    blanks = 0
            return bytes(output)

        try:
            result = self.intent(dict(observation))
            need(result is None or type(result) is int and result == 0,
                 "Request intent journal did not confirm durable success")
            recorded = True
            self.owner.safe_to_stop = False
            self.owner.begin()
            self.owner.healthy = self.healthy = False
            if mutation and self.before_mutation_dispatch is not None:
                self.before_mutation_dispatch(dict(observation))
            dispatch = self.camera_io = True
            self.mutation_attempted |= mutation
            sent = self.driver.write(request)
            need(sent is None or type(sent) is int and sent == len(request), "Partial settings request write")
            output, remaining = bytearray(), None
            while True:
                size, function, seq, a, b, c, status = HEADER.unpack(exact(HEADER.size))
                need((function, seq, status) == (0x40, sequence, 0), "Settings response identity/status differs")
                need(size <= cap - len(output) and (remaining is None or size == remaining)
                     and (size > 0 or empty and not output), "Settings response length differs")
                count = min(size, MAX_TRANSFER)
                output.extend(exact(count))
                remaining = size - count
                if not remaining:
                    break
            body = bytes(output)
            need(expected is None or len(body) == expected, "Fixed settings record length differs")
            ending = "not_applicable"
            if terminal:
                try:
                    tail = bytes(self.driver.read(512, timeout=1000))
                    ending = "empty" if not tail else "nonempty"
                except Exception as exc:
                    # Match PyUSB's actual timeout class only, never arbitrary
                    # exceptions whose text happens to contain 'timeout'.
                    from usb.core import USBTimeoutError
                    if not isinstance(exc, USBTimeoutError):
                        raise
                    ending = "usb_timeout"
                need(not tail, "Unexpected CP READ40 terminal bytes")
            result = self.reply(dict(observation, wire=bytes(wire), body=body, tail=tail,
                                     ending=ending, verified=True))
            need(result is None or type(result) is int and result == 0,
                 "Response journal did not confirm durable success")
            response_recorded = True
            self.owner.sequence = (sequence + 1) & 0xFFFF
            self.owner.healthy = self.healthy = True
            return body
        except BaseException as exc:
            self._poison(dispatch)
            if recorded and not response_recorded:
                try:
                    self.reply(dict(observation, wire=bytes(wire), body=body, tail=tail,
                                    verified=False, error_type=type(exc).__name__, error=str(exc)))
                except BaseException:
                    pass  # preserve the last durable intent; do not mask failure
            raise

    def settings(self, memory):
        need(type(memory) is bool, "Explicit RAM/saved selector required")
        return self._exchange(5, bytes((int(memory),)), MAX_SETTINGS_BYTES,
                              operation="full-settings", memory=memory)

    def read_record(self, role, key):
        pair = int(role == "cp"), key
        allowed = {(int(i < 2), key): size for i, (key, size) in enumerate(zip(KEYS, SIZES))}
        allowed[AP55], allowed[SERIAL] = 1, 4
        need(role in ("ap", "cp") and type(key) is int and pair in allowed,
             "Read outside fixed settings set")
        cp = role == "cp"
        return self._exchange(0x40 if cp else 1,
                              struct.pack("<II", key, 1) if cp else struct.pack("<I", key),
                              allowed[pair], expected=allowed[pair], terminal=cp,
                              operation="fixed-record-read", role=role, key=key)

    def write_record(self, role, key, raw):
        need(self._armed is not None and role in ("ap", "cp") and type(raw) is bytes,
             "A bound fixed settings plan must be armed before WRITE")
        pair = int(role == "cp"), key
        from . import looks_settings
        if looks_settings.active(self._armed):
            rows=[r for r in self._armed.records if (r.chip,r.key)==pair]
            need(len(rows)==1 and self._steps and self._steps[0][:3]==('write',*pair)
                 and self._last_capture is not None,'Scoped WRITE outside current finite step')
            r=rows[0];target=self._steps[0][3];current=self._last_capture.ram.records[pair].data
            need(raw==looks_settings.merge(current,target,r.spans),'Scoped WRITE must preserve freshly read F complement')
            admitted=rows
            wanted_step=self._steps[0]
        else:
            admitted = [r for r in self._armed.records if (r.chip, r.key) == pair
                        and raw in (r.after_ram, r.after_saved)]
            wanted_step=("write", *pair, raw)
        claim = pair, raw
        need(admitted and claim not in self._writes and self._steps
             and self._steps[0] == wanted_step, "Unplanned, out-of-order or repeated settings WRITE")
        self._steps.pop(0)
        self._writes.add(claim)  # consume before journal/dispatch; never replay
        cp = role == "cp"
        return self._exchange(0x41 if cp else 2,
                              (struct.pack("<II", key, 1) if cp else struct.pack("<I", key)) + raw,
                              4096, empty=True, mutation=True,
                              operation="fixed-record-write", role=role, key=key)

    def save_group(self, group):
        need(self._armed is not None and type(group) is int and group in self._armed.groups
             and group not in self._saves and self._steps and self._steps[0] == ("save", group),
             "Unplanned, out-of-order or repeated group SAVE")
        self._steps.pop(0)
        self._saves.add(group)
        return self._exchange(3, struct.pack("<H", group), 4096, empty=True, mutation=True,
                              operation="fixed-group-save", group=group)

    def backing_file(self, path):
        need(path in BACKING, "Only two fixed read-only backing files admitted")
        wire_path = b"\0/tmp/jiritsu/../../" + path.lstrip("/").encode("ascii") + b"\0"
        selected = self._exchange(0x400F, wire_path, 4, expected=4, category=0x1001,
                                  operation="backing-select", path=path)
        need(selected == bytes(4), "Backing file select rejected")
        raw = self._exchange(0x4011, b"\0\xff\0", BACKING_CAP + 4, category=0x1001,
                             operation="backing-read", path=path)
        need(len(raw) > 4 and raw[:4] == bytes(4), "Complete backing file missing or rejected")
        return raw[4:]

    def capture(self):
        ram, saved = self.settings(True), self.settings(False)
        bin = self.backing_file("/setting/BACKUP.BIN")
        bak = self.backing_file("/setting/BACKUP.BAK")
        cp = {key: self.read_record("cp", key) for key in KEYS[:2]}
        serial = self.read_record("ap", SERIAL[1])
        snapshot = parse_snapshot(ram, saved, bin, bak, cp_live=cp, serial=serial)
        direct55 = self.read_record("ap", AP55[1])
        need(snapshot.ram.records.get(AP55) is not None and snapshot.ram.records[AP55].data == direct55,
             "Direct AP55 and complete live settings differ")
        self._last_capture = snapshot
        return snapshot
