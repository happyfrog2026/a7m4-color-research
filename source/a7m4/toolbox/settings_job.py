"""Finite saved-first settings transaction over an injected borrowed channel.

Pure Python host driver, using the reviewed C engine's order: complete
preflight, CP saved staging/SAVE/RAM restoration, AP staging/SAVE/RAM, full
readback. AP55 is a separate plan/SAVE51. No C compiler, ctypes, lifecycle,
WBI, retry, automatic inverse or camera discovery is needed here.

This adapter defaults HELD. An offline plan is never an execution grant.
Unknown outcomes require a fresh reviewed capture; replay is prohibited.
"""
from __future__ import annotations

from .bk4 import bk4_rows
from . import native_ui, save_effects
from .run_log import event as diagnostic_event
from .settings_plan import (SettingsError, Value, Plan, Snapshot, AP55_COLLATERAL,
                            need, sha, body_identity, validate_plan, validate_snapshot, plan_manifest, _mapping_sha,
                            METADATA_PROFILE, needs_save)

PLANES = ("ram", "saved", "bin", "bak")


def _maps(snapshot):
    return {name: dict(getattr(snapshot, name).records) for name in PLANES}


def _envelope(raw, *, plane, after_save, candidate):
    """Freeze header/index/gaps/trailer; only record data/checksum are masked.

    Candidate mode permits only post-SAVE AP saved-count u32 and RAM CP+9.
    The latter's exact00→01 transition is checked separately against the last
    verified read. Neither field is a full-header mask or a persistence proof.
    """
    output = bytearray(raw)
    for chip, row in enumerate(bk4_rows(raw)):
        output[row["base"] + 0x20:row["base"] + 0x24] = bytes(4)
        if candidate and after_save:
            if plane in ("saved", "bin", "bak") and chip == 0:
                output[row["base"] + 0x2C:row["base"] + 0x30] = bytes(4)
            if plane == "ram" and chip == 1:
                output[row["base"] + 9] = 0
        for entry in row["records"].values():
            start, length = entry["offset"], entry["size"]
            output[start:start + length] = bytes(length)
    return bytes(output)


def _runtime_counter(pair, before, after):
    # Named, bounded RAM-only rules, outside every SAVE group.
    # 02770015 is an explicit M4 6.02 candidate policy: attrs2/u32,
    # nondecreasing <=1000000. Name and time unit remain unproven.
    if pair[0] != 0 or before.attrs != after.attrs:
        return False
    if pair[1] == 0x01070000 and len(before.data) == len(after.data) == 8:
        return 0 <= int.from_bytes(after.data, "little") - int.from_bytes(before.data, "little") <= 1000000
    if pair[1] == 0x02770015 and before.attrs == 2 and len(before.data) == len(after.data) == 4:
        return 0 <= int.from_bytes(after.data, "little") - int.from_bytes(before.data, "little") <= 1000000
    if pair[1] == 0x02780000 and len(before.data) == len(after.data) == 256:
        delta = int.from_bytes(after.data[24:28], "little") - int.from_bytes(before.data[24:28], "little")
        return before.data[:24] == after.data[:24] and before.data[28:] == after.data[28:] and 0 < delta <= 1000000
    return False


def check_full(plan, current, expected, *, after_save=False, previous=None, native_ui_saved=False):
    validate_snapshot(current)
    need(native_ui.snapshot_valid(current) and native_ui.snapshot_valid(plan.baseline),
         "Native UI diagnostic shape/complete word groups differ")
    need(type(current) is Snapshot and current.serial == plan.baseline.serial
         and body_identity(current.serial) == plan.identity, "Complete readback body binding differs")
    for plane in PLANES:
        old_image, image = getattr(plan.baseline, plane), getattr(current, plane)
        old, actual, wanted = old_image.records, image.records, expected[plane]
        need(set(actual) == set(old) == set(wanted), "Complete readback record inventory differs")
        candidate = plan.metadata_profile == METADATA_PROFILE
        need(_envelope(image.raw, plane=plane, after_save=after_save, candidate=candidate) ==
             _envelope(old_image.raw, plane=plane, after_save=after_save, candidate=candidate),
             "Unreviewed BK4 structural/header/generation change; preserve raw evidence and stop")
        if candidate and after_save and plane == "ram":
            last = getattr(previous or plan.baseline, plane)
            old_cp, new_cp = bk4_rows(last.raw)[1], bk4_rows(image.raw)[1]
            before, after = last.raw[old_cp["base"] + 9], image.raw[new_cp["base"] + 9]
            need(before == after or (before, after) == (0, 1), "RAM CP+9 outside exact00-to01 candidate transition")
        for pair, value in old.items():
            now = actual[pair]
            need((now.attrs, len(now.data)) == (value.attrs, len(value.data)), "Readback record attributes/lengths differ")
            if now != wanted[pair]:
                if save_effects.effect(plan,pair):continue
                if native_ui.diagnostic(pair,actual) and (plane == 'ram' or pair == native_ui.SCREEN
                        or native_ui_saved and after_save and pair in native_ui.TIME_FIELDS):
                    diagnostic_event('native-ui-diagnostic-observation',policy=native_ui.POLICY,
                        plane=plane,key='%08x'%pair[1],native_ui_saved=native_ui_saved,
                        value_hashes=dict(expected=sha(wanted[pair].data),observed=sha(now.data)),
                        explicit_record_write=False)
                    continue
                if plane == "ram" and pair[1] >> 16 not in plan.groups and _runtime_counter(pair, wanted[pair], now):
                    continue
                raise SettingsError("Unplanned complete readback value: " + plane + "/%d/%08x" % pair)


def check_forward_C_D(plan,current,expected):
    validate_snapshot(current)
    need(current.serial==plan.baseline.serial and body_identity(current.serial)==plan.identity,
         'Gate current body identity differs')
    for plane in PLANES:
        actual=getattr(current,plane).records
        for pair in ((0,0x00510055),(1,0x00510055),(0,0x004B0003)):
            need(actual.get(pair)==expected[plane].get(pair),'Gate C/D readback differs: '+plane+'/%d/%08x'%pair)
        need(actual.get((1,0x00510055))==Value(0,b'\0') and actual.get((0,0x004B0003))==Value(0,b'\1'),
             'Gate required CP55/BOOT dependency differs')


def observe_forward_F(current,expected):
    differences=[]
    for plane in PLANES:
        actual=getattr(current,plane).records
        for pair in sorted(set(actual)|set(expected[plane])):
            if pair in ((0,0x00510055),(1,0x00510055),(0,0x004B0003)):continue
            before,after=expected[plane].get(pair),actual.get(pair)
            if before!=after:
                identify=lambda v:None if v is None else save_effects.identity(v)
                differences.append(dict(plane=plane,chip=pair[0],key=f'{pair[1]:08x}',
                    category='E' if pair[1]>>16==0x51 else 'F',expected=identify(before),actual=identify(after)))
        protected={p:expected[plane][p] for p in ((0,0x00510055),(1,0x00510055),(0,0x004B0003))}
        expected[plane]=dict(actual);expected[plane].update(protected)
    return differences


class SettingsJob:
    """No constructor I/O. Main supplies durable journal and current binding.

    capture defaults to SettingsChannel.capture. ``bind`` must freshly return
    exact identity/boot/nonce plus model/firmware and exclusive-owner proof.
    Main must durably retain complete raw snapshots and the plan's original
    selected planes before granting execution. Raw journal callback failures
    are failures, not logging warnings.
    """
    def __init__(self, channel, *, bind, journal, capture=None,forward_observation_only=False):
        need(callable(bind) and callable(journal), "Fresh Main binding and durable journal required")
        self.channel, self.bind, self.journal = channel, bind, journal
        self.capture = capture or channel.capture
        need(callable(self.capture), "Complete four-plane capture provider required")
        need(type(forward_observation_only) is bool,'Explicit forward observation policy required')
        self.forward_observation_only=forward_observation_only
        self.F_observations=[]
        self.phase = "HELD"
        self._released = None
        self._claimed = set()
        self.mutation_attempted = False
        self.writes = self.saves = 0
        self.saved_groups = set()
        self._last_snapshot = None
        self.effect_observations=[]

    @property
    def verified_snapshot(self):
        """Immutable endpoint from the durably completed full guard, not a recapture."""
        need(self.phase == "DONE" and self._last_snapshot is not None,
             "No completed verified settings endpoint")
        return self._last_snapshot

    def _event(self, event, **values):
        result = self.journal(dict(schema="a7m4-toolbox-settings-event/1", event=event,
                                   phase=self.phase, **values))
        need(result is None or type(result) is int and result == 0, "Settings journal did not confirm durable success")

    def release(self, plan, proof):
        """Explicit Main-only one-plan grant; absent proof keeps execution HELD."""
        validate_plan(plan)
        need(self.phase in ("HELD", "DONE") and self._released is None and plan.nonce not in self._claimed,
             "Settings job cannot release a replay or unknown state")
        need(type(proof) is dict and proof.get("schema") == "a7m4-toolbox-settings-release/1"
             and proof.get("plan_id") == plan.plan_id and proof.get("identity") == plan.identity
             and proof.get("boot_id") == plan.boot_id and proof.get("nonce") == plan.nonce
             and proof.get("backup_verified") is True and proof.get("program_dependencies_verified") is True
             and proof.get("user_risk_confirmation_fresh") is True and proof.get("release_gate") == "RELEASED",
             "Explicit fresh Main backup/program/risk/release proof required")
        self._event("release", plan_id=plan.plan_id, proof=dict(proof))
        self._released = plan.plan_id
        self.phase = "RELEASED"

    def _fresh(self, plan, expected, label):
        from . import looks_settings
        snapshot = self.capture()
        # Raw evidence must survive a guard rejection, too.
        self._event("capture", label=label, snapshots={name: getattr(snapshot, name).raw for name in PLANES},
                    raw_sha256={name: sha(getattr(snapshot, name).raw) for name in PLANES})
        if self.forward_observation_only:
            from . import looks_settings
            if looks_settings.active(plan):
                looks_settings.check(plan,snapshot,expected)
                differences=looks_settings.observe(plan,snapshot,expected,saved_groups=self.saved_groups)
            else:
                check_forward_C_D(plan,snapshot,expected)
                differences=observe_forward_F(snapshot,expected)
            self._event('forward-E-F-observations',label=label,differences=differences,
                        acceptance_scope='C-and-explicit-D-only',extra_WRITE_authorized=False)
            self.F_observations.append(dict(label=label,differences=differences))
        else:
            check_full(plan, snapshot, expected, after_save=self.saves > 0, previous=self._last_snapshot,
                       native_ui_saved=0x02CF in self.saved_groups)
        if save_effects.active(plan):
            observation=save_effects.observation(plan,snapshot,expected)
            self._event('native-SAVE-effects-observation',label=label,**observation)
            import json
            canonical=json.dumps(observation['inventory'],sort_keys=True,separators=(',',':')).encode()
            self.effect_observations.append(dict(label=label,policy=observation['profile'],
                inventory_count=len(observation['inventory']),inventory_sha256=sha(canonical),
                complete_inventory_in_private_journal=True,differences=observation['differences']))
            save_effects.adopt(plan,snapshot,expected)
        if not looks_settings.active(plan) and any(expected['ram'].get(pair)!=snapshot.ram.records.get(pair) for pair in native_ui.FIELDS):
            self._event('native-ui-RAM-observation',policy=native_ui.POLICY,label=label,
                        before=native_ui.state(expected['ram']),after=native_ui.state(snapshot.ram.records))
        # Fresh diagnostic RAM is not historical restore intent. It is never
        # explicitly written, but a later authorized SAVE predicts this state.
        for pair in native_ui.FIELDS:
            if native_ui.diagnostic(pair,snapshot.ram.records):expected['ram'][pair]=snapshot.ram.records[pair]
        if self._last_snapshot is not None:
            transitions = []
            for plane in PLANES:
                before_raw, after_raw = getattr(self._last_snapshot, plane).raw, getattr(snapshot, plane).raw
                before_rows, after_rows = bk4_rows(before_raw), bk4_rows(after_raw)
                for chip, (before, after) in enumerate(zip(before_rows, after_rows)):
                    for offset, length, label in ((0x2C, 4, "opaque_native_count"), (9, 1, "header_plus9")):
                        left = before_raw[before["base"] + offset:before["base"] + offset + length]
                        right = after_raw[after["base"] + offset:after["base"] + offset + length]
                        if left != right:
                            transitions.append(dict(plane=plane, chip=chip, offset=offset,
                                                    field=label, before_hex=left.hex(), after_hex=right.hex()))
            if transitions:
                self._event("candidate-metadata-observation", profile=plan.metadata_profile,
                            transitions=transitions, physical_validation="NOT_PERFORMED")
        self._last_snapshot = snapshot
        return snapshot

    def _fresh_binding(self,plan):
        binding=self.bind(plan)
        need(type(binding) is dict and binding.get('exclusive_owner') is True and all(binding.get(k)==v for k,v in {
            'identity':plan.identity,'boot_id':plan.boot_id,'nonce':plan.nonce,'model':'ILCE-7M4','firmware':'6.02'}.items()),
            'Fresh Main model/firmware/body/boot/nonce/exclusive binding differs')

    def _write(self, plan, record, wanted, expected, label):
        pair, role = (record.chip, record.key), "cp" if record.chip else "ap"
        from . import looks_settings
        scoped=looks_settings.active(plan)
        if (looks_settings.equal(expected['ram'][pair].data,wanted,record.spans) if scoped else expected["ram"][pair].data == wanted):
            return
        # Complete readback immediately before every write detects unrelated
        # drift and foreign changes before the next operation is armed.
        self._fresh_binding(plan)
        self._fresh(plan, expected, "before-" + label)
        if scoped:wanted=looks_settings.merge(expected['ram'][pair].data,wanted,record.spans)
        self._event("write-intent", role=role, key=record.key, bytes=len(wanted), sha256=sha(wanted))
        try:
            self.channel.write_record(role, record.key, wanted)
        finally:
            self.mutation_attempted |= bool(getattr(self.channel, "mutation_attempted", True))
        self.writes += 1
        expected["ram"][pair] = Value(expected["ram"][pair].attrs, wanted)
        self._fresh(plan, expected, "after-" + label)
        self._event("write-receipt", role=role, key=record.key, full_readback_verified=True)

    def execute(self, plan):
        validate_plan(plan)
        from . import looks_settings
        scoped=looks_settings.active(plan)
        need((not scoped or self.forward_observation_only) and (not self.forward_observation_only or scoped
             or (plan.kind in ('ap55','gate-restore-ap55','backup-target-ap55') and plan.save_effects_policy==save_effects.NATIVE51)),
             'Observation-only execution requires a finite Gate or scoped looks plan')
        need(self.phase == "RELEASED" and self._released == plan.plan_id and plan.nonce not in self._claimed,
             "HELD: plan creation is not camera execution authorization")
        self._claimed.add(plan.nonce)
        self._released = None
        self.writes = self.saves = 0
        self.saved_groups = set()
        self.mutation_attempted = False
        self._last_snapshot = None
        self.effect_observations=[]
        self.F_observations=[]
        self.phase = "PREFLIGHT"
        try:
            self._event("claim", plan_id=plan.plan_id, manifest=plan_manifest(plan),
                        native_ui_collateral=None if scoped else native_ui.collateral(plan),
                        original_records=[dict(chip=r.chip, key=r.key, before_ram=r.before_ram,
                                               before_saved=r.before_saved) for r in plan.records])
            self._fresh_binding(plan)
            expected = _maps(plan.baseline)
            self._fresh(plan, expected, "preflight")
            self.channel.arm(plan)
            selected = {(r.chip, r.key) for r in plan.records}
            for group in plan.groups:
                records = [r for r in plan.records if r.key >> 16 == group]
                need_save = needs_save(plan,group)
                if need_save:
                    self.phase = "STAGE_SAVED"
                    for record in records:
                        self._write(plan, record, record.after_saved, expected, "stage-%08x" % record.key)
                    self._fresh_binding(plan)
                    self._fresh(plan, expected, "before-save-%04x" % group)
                    if save_effects.active(plan):
                        self._event('native-SAVE-effects-prediction',group=group,
                            basis='immediately-fresh-RAM-to-saved-both-chips',
                            inventory=save_effects.observation(plan,self._last_snapshot,expected)['inventory'],
                            explicit_extra_record_WRITE=0)
                    self.phase = "SAVE"
                    self._event("save-intent", group=group)
                    if group==0x02CF and not scoped:
                        self._event('native-ui-save-collateral-intent',policy=native_ui.POLICY,
                                    pre_saved=native_ui.state(expected['saved']),predicted_RAM=native_ui.state(expected['ram']),
                                    explicit_record_writes=0)
                    try:
                        self.channel.save_group(group)
                    finally:
                        self.mutation_attempted |= bool(getattr(self.channel, "mutation_attempted", True))
                    self.saves += 1
                    self.saved_groups.add(group)
                    for pair, value in expected["ram"].items():
                        if pair[1] >> 16 == group:
                            # Named AP55 boot collateral is explicitly included
                            # in this exact predicted merge. Native refresh
                            # values that differ from fresh RAM remain blocked.
                            need(scoped or pair in selected or save_effects.effect(plan,pair) or value == expected["saved"][pair]
                                 or plan.kind in ("ap55", "original-ap55") and pair in AP55_COLLATERAL
                                 or group==0x02CF and native_ui.diagnostic(pair,expected['ram']),
                                 "Unexpected unowned SAVE collateral")
                            expected["saved"][pair] = value
                    expected["bin"] = dict(expected["saved"])
                    expected["bak"] = dict(expected["saved"])
                    self._fresh(plan, expected, "after-save-%04x" % group)
                    self._event("save-receipt", group=group, complete_BIN_BAK_verified=True,
                                native_ui_observed={plane:native_ui.state(getattr(self._last_snapshot,plane).records) for plane in PLANES}
                                if group==0x02CF and not scoped else None)
                self.phase = "RESTORE_RAM"
                for record in records:
                    self._write(plan, record, record.after_ram, expected, "ram-%08x" % record.key)
            self.phase = "VERIFY"
            self._fresh_binding(plan)
            final = self._fresh(plan, expected, "final")
            self.phase = "DONE"
            receipt = dict(schema="a7m4-toolbox-fixed-settings-result/1", status="DONE",
                           plan_id=plan.plan_id, kind=plan.kind, nonce=plan.nonce,
                           writes=self.writes, saves=self.saves, saved_groups=sorted(self.saved_groups),
                           native_ui_policy=native_ui.POLICY, mutation_attempted=self.mutation_attempted,
                           full_readback_verified=True, complete_BIN_BAK_verified=True,
                           backing_copies_match_active_saved=all(getattr(final, name).records == final.saved.records
                                                                for name in ("bin", "bak")),
                           raw_sha256={name: sha(getattr(final, name).raw) for name in PLANES},
                           logical_sha256={name: _mapping_sha(getattr(final, name).records) for name in PLANES},
                           direct_cp=[dict(key=f"{key:08x}", bytes=len(raw), sha256=sha(raw))
                                      for key, raw in final.direct_cp],
                           powercycle_persistence_verified=False, WBI_writes=0,
                           camera_io=bool(getattr(self.channel, "camera_io", False)),
                           no_boot_rescue_verified=False, stop_authorized=False,
                           native_metadata_policy=plan.metadata_profile,
                           metadata_profile_validation="NEW_SOFTWARE_CANDIDATE_PHYSICAL_NOT_PERFORMED",
                           live_validation="HELD_NOT_EXECUTED_BY_OFFLINE_TESTS")
            if self.forward_observation_only:
                receipt['forward_observations']=dict(acceptance_scope='C-and-explicit-D-only',
                    E_F_gate_execution=False,observations=self.F_observations,extra_WRITE_authorized=False)
            if scoped:
                receipt['validation_scope']='scoped-looks-C-D-only-E-F-observations/1'
                receipt['native_SAVE_effects']=dict(policy=looks_settings.POLICY,groups=sorted(self.saved_groups),
                    observations=self.F_observations,explicit_extra_record_WRITE=0,E_F_gate_execution=False,
                    C_D_readback_verified=True,E_F_restore_promised=False)
            if save_effects.active(plan):
                receipt['native_SAVE_effects']=dict(policy=save_effects.NATIVE51,
                    observations=self.effect_observations,explicit_extra_record_WRITE=0,
                    admission_effect_values_checked=False,post_effect_values_observed=True,
                    C_D_readback_verified=True,F_readback_observation_only=self.forward_observation_only,
                    C_D_and_F_readback_protected=not self.forward_observation_only)
            self._event("done", receipt=receipt)
            self.channel.disarm()
            return receipt
        except BaseException as exc:
            self.phase = "NEEDS_REVIEW"
            # Any prior mutation or failed wire exchange makes outcome unknown;
            # never clean, replay, SAVE again, inverse or grant STOP here.
            if self.mutation_attempted or getattr(self.channel, "unknown_remote_state", False):
                poison = getattr(self.channel, "_poison", None)
                if poison:
                    poison(True)
            try:
                self._event("failure", error_type=type(exc).__name__, error=str(exc),
                            mutation_attempted=self.mutation_attempted,
                            writes=self.writes, saves=self.saves,
                            camera_io=bool(getattr(self.channel, "camera_io", False)),
                            fresh_snapshot_required=True, automatic_rollback=False)
            except BaseException:
                pass
            raise
