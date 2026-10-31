"""Finite settings C targets from a revalidated selected backup, no history."""
import os
from . import settings_plan as sp, looks_settings as looks, save_effects
from .backup_target_execution import authenticated_plan as validate_plan, authenticated_payload


def _pairs(execution):
    execution=validate_plan(execution)
    rows = execution['scope_plan']['settings']['records']
    result = []
    for row in rows:
        key = row['key']
        key = int(key, 16) if isinstance(key, str) else key
        pair = row['chip'], key
        if pair not in looks.SPEC and pair != sp.AP55:
            raise ValueError('Settings target is outside finite product C')
        if pair not in result:
            result.append(pair)
    return tuple(result)


def check_snapshot_C(snapshot,execution,*,backup):
    plan=validate_plan(execution)
    sp.validate_snapshot(snapshot)
    for row in plan['scope_plan']['settings']['records']:
        pair=row['chip'],row['key']
        for plane in ('ram','saved'):
            value=getattr(snapshot,plane).records.get(pair)
            if value is None or (value.attrs,len(value.data))!=(row['attrs'],row['size']):
                raise ValueError('Authenticated settings C shape changed')
            for window in row['spans']:
                expected=window[plane+('_target_hex' if backup else '_before_hex')]
                if value.data[window['start']:window['end']].hex()!=expected:
                    raise ValueError('Authenticated settings C bytes changed')
    return True


def settings_plans(fresh, backup, execution, *, boot_id):
    sp.validate_snapshot(fresh); sp.validate_snapshot(backup)
    if fresh.serial != backup.serial:
        raise ValueError('Backup settings target belongs to another body')
    check_snapshot_C(backup,execution,backup=True)
    pairs = _pairs(execution)
    identity = sp.body_identity(fresh.serial)
    looks.dependencies(fresh, forward=False)
    rows, originals = [], []
    for pair in pairs:
        if pair == sp.AP55:
            continue
        looks._shape(fresh, pair); looks._shape(backup, pair)
        attrs, size, spans = looks.SPEC[pair]
        before = {p: getattr(fresh, p).records[pair].data for p in ('ram', 'saved')}
        target = {p: getattr(backup, p).records[pair].data for p in ('ram', 'saved')}
        originals.append((pair[0], pair[1], attrs, size,
            tuple((a, b, target['ram'][a:b].hex(), target['saved'][a:b].hex()) for a, b in spans)))
        rows.append(sp.Record(*pair, spans, before['ram'], before['saved'],
            looks.merge(before['ram'], target['ram'], spans), looks.merge(before['saved'], target['saved'], spans)))
    plans = []
    if rows:
        plans.append(looks.validate_plan(sp.Plan('scoped-looks-restore', identity, boot_id, os.urandom(16).hex(),
            fresh, tuple(rows), tuple(sorted({r.key >> 16 for r in rows})),
            save_effects_policy=looks.POLICY, looks_original=tuple(originals))))
    if sp.AP55 in pairs:
        target = tuple(getattr(backup, p).records[sp.AP55].data for p in ('ram', 'saved'))
        if any(v not in (b'\0', b'\2') for v in target):
            raise ValueError('Backup AP55 target outside 00/02')
        row = sp.Record(*sp.AP55, ((0, 1),), fresh.ram.records[sp.AP55].data,
            fresh.saved.records[sp.AP55].data, target[0], target[1])
        plans.append(sp.validate_plan(sp.Plan('backup-target-ap55', identity, boot_id, os.urandom(16).hex(),
            fresh, (row,), (0x51,), save_effects_policy=save_effects.NATIVE51,
            gate_original=tuple(v.hex() for v in target))))
    return plans


def check_settings_source(plan, current):
    if looks.active(plan):
        looks.check_current(plan, current)
    else:
        from .settings_job import check_forward_C_D, _maps
        check_forward_C_D(plan, current, _maps(plan.baseline))


def settings_plan_changed(plan):
    return any(r.before_ram != r.after_ram or r.before_saved != r.after_saved for r in plan.records) or any(
        sp.needs_save(plan, group) for group in plan.groups)


def check_settings_target(current, backup, execution, *, allow_saved_ram=False):
    sp.validate_snapshot(current); sp.validate_snapshot(backup)
    if current.serial != backup.serial:
        raise ValueError('Final settings body differs')
    looks.dependencies(current, forward=False)
    check_snapshot_C(backup,execution,backup=True)
    for pair in _pairs(execution):
        spans = ((0, 1),) if pair == sp.AP55 else looks.SPEC[pair][2]
        for plane in ('ram', 'saved', 'bin', 'bak'):
            actual = getattr(current, plane).records[pair]
            target = getattr(backup, 'saved' if plane in ('bin', 'bak') else plane).records[pair]
            if (actual.attrs, len(actual.data)) != (target.attrs, len(target.data)):
                raise ValueError('Final settings C shape differs')
            if pair == sp.AP55 and plane == 'ram' and allow_saved_ram:
                if actual.data in (backup.ram.records[pair].data, backup.saved.records[pair].data):
                    continue
            if not looks.equal(actual.data, target.data, spans):
                raise ValueError('Final settings C target differs: %s/%s' % (plane, pair))
    return dict(C_D_verified=True, E_F_observation_only=True)


def validate_ap55_plan(plan):
    """Finite backup AP55 target; valid nonowned BK4 values are observations."""
    sp.need(type(plan) is sp.Plan and plan.kind=='backup-target-ap55'
        and plan.save_effects_policy==save_effects.NATIVE51 and plan.metadata_profile==sp.METADATA_PROFILE,
        'Finite backup-target AP55 plan required')
    sp.validate_snapshot(plan.baseline)
    looks._binding(plan.baseline,plan.identity,plan.boot_id,plan.nonce)
    sp.need(plan.origin is plan.original is plan.inverse_of is plan.looks_original is plan.looks_selection is None,
        'Backup AP55 plan cannot carry another authority')
    sp.need(type(plan.gate_original) is tuple and len(plan.gate_original)==2
        and all(v in ('00','02') for v in plan.gate_original)
        and plan.groups==(0x51,) and len(plan.records)==1,'Exact finite AP55 endpoints required')
    looks.dependencies(plan.baseline,forward=False)
    row=plan.records[0]
    sp.need(type(row) is sp.Record and (row.chip,row.key)==sp.AP55 and row.spans==((0,1),)
        and row.before_ram==plan.baseline.ram.records[sp.AP55].data
        and row.before_saved==plan.baseline.saved.records[sp.AP55].data
        and row.after_ram==bytes.fromhex(plan.gate_original[0])
        and row.after_saved==bytes.fromhex(plan.gate_original[1]),'AP55 C/preimage/target differs')
    for p in looks.PLANES:
        value=getattr(plan.baseline,p).records[sp.AP55]
        sp.need(value.attrs==0 and len(value.data)==1,'AP55 C format differs')
    return plan
