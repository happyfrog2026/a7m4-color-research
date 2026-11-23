"""M4 6.02 consumer safety transaction, before removing program patches.

This is an explicitly authorized temporary protection C, independent of the
selected backup's feature C. Use RAM WRITE + factory SAVE02CF; never edit BK4
files. Four-plane ST is necessary but does not prove the live menu model.
"""
import os
from . import settings_plan as sp, looks_settings as looks

KIND = 'scoped-restore-st'
CURRENT = (0, 0x02CF0311)
BASES = tuple((0, start + 2*i) for start in (0x02CF0D0B, 0x02CF12E9, 0x02CF1309) for i in range(6))
PAIRS = (CURRENT, *BASES)
SPEC = {p: (0x60, 1, ((0, 1),)) for p in PAIRS}


def shape(snapshot, pair):
    sp.need(pair in SPEC, 'Outside finite restore ST protection C')
    for plane in looks.PLANES:
        value = getattr(snapshot, plane).records.get(pair)
        sp.need(value is not None and value.attrs == 0x60 and len(value.data) == 1,
                'Restore ST protection record shape differs')


def require_st(snapshot):
    sp.validate_snapshot(snapshot)
    looks.dependencies(snapshot, forward=False)
    for pair in PAIRS:
        shape(snapshot, pair)
        for plane in looks.PLANES:
            sp.need(getattr(snapshot, plane).records[pair].data == b'\0',
                    'Current look and all six base looks must be saved ST: %s/%08x' % (plane, pair[1]))
    return True


def make_plan(fresh, *, boot_id):
    sp.validate_snapshot(fresh)
    rows = []
    for pair in PAIRS:
        shape(fresh, pair)
        rows.append(sp.Record(*pair, ((0, 1),), fresh.ram.records[pair].data,
                              fresh.saved.records[pair].data, b'\0', b'\0'))
    return validate_plan(sp.Plan(KIND, sp.body_identity(fresh.serial), boot_id, os.urandom(16).hex(),
        fresh, tuple(rows), (0x02CF,), save_effects_policy=looks.POLICY))


def validate_plan(plan):
    sp.need(type(plan) is sp.Plan and plan.kind == KIND and plan.save_effects_policy == looks.POLICY,
            'Finite restore ST protection plan required')
    looks._binding(plan.baseline, plan.identity, plan.boot_id, plan.nonce)
    looks.dependencies(plan.baseline, forward=False)
    sp.need(plan.origin is plan.original is plan.inverse_of is plan.gate_original is
            plan.looks_original is plan.looks_selection is None and plan.metadata_profile == sp.METADATA_PROFILE,
            'ST protection cannot carry other restore intent')
    sp.need(plan.groups == (0x02CF,) and tuple((r.chip, r.key) for r in plan.records) == PAIRS,
            'Exact current and six bases in current/still/movie required')
    for r in plan.records:
        shape(plan.baseline, (r.chip, r.key))
        sp.need(type(r) is sp.Record and r.spans == ((0, 1),) and
                r.before_ram == plan.baseline.ram.records[r.chip, r.key].data and
                r.before_saved == plan.baseline.saved.records[r.chip, r.key].data and
                r.after_ram == r.after_saved == b'\0', 'ST protection preimage/target differs')
    return plan
