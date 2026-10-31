"""Finite M4 6.02 APP diagnostic metadata, not recipe/calibration ownership.

Names are exact retained 6.02 BKID catalogue entries. The two word groups
are retained together; a high/low uint64 millisecond interpretation is only
an inference and is not used for admission. No code here emits WRITE/SAVE.
"""
POLICY = 'm4-602-native-APP-UI-diagnostics/1'
SCREEN = (0, 0x02CF0B6E)
TIME_GROUPS = (((0,0x02CF13F6),(0,0x02CF13F7)),
               ((0,0x02CF140B),(0,0x02CF140C)))
FIELDS = {
    SCREEN: (0x40,4,'BKID_APP_TOP_DISPLAY_LAYER_SCREEN_ID'),
    (0,0x02CF13F6): (0,4,'BKID_APP_CONTENTS_INFO_LIST_UPDATE_TIME_SLOT10'),
    (0,0x02CF13F7): (0,4,'BKID_APP_CONTENTS_INFO_LIST_UPDATE_TIME_SLOT11'),
    (0,0x02CF140B): (0,4,'BKID_APP_CONTENTS_INFO_LIST_REGENERATE_TIME_SLOT10'),
    (0,0x02CF140C): (0,4,'BKID_APP_CONTENTS_INFO_LIST_REGENERATE_TIME_SLOT11'),
}
TIME_FIELDS = frozenset(pair for group in TIME_GROUPS for pair in group)


def _shape(pair,value):
    return (value is not None and type(value.data) is bytes
            and (value.attrs,len(value.data))==FIELDS[pair][:2])


def mapping_valid(values):
    if SCREEN in values and not _shape(SCREEN,values[SCREEN]):return False
    present=TIME_FIELDS.intersection(values)
    return not present or (present==TIME_FIELDS and all(_shape(p,values[p]) for p in TIME_FIELDS))


def snapshot_valid(snapshot):
    return all(mapping_valid(getattr(snapshot,plane).records) for plane in ('ram','saved','bin','bak'))


def diagnostic(pair,values):
    return pair in FIELDS and mapping_valid(values) and _shape(pair,values.get(pair))


def state(values):
    if not mapping_valid(values):raise ValueError('Native UI diagnostic shape/complete word groups differ')
    fields=[dict(chip=p[0],key='%08x'%p[1],name=spec[2],attrs=spec[0],bytes=spec[1],raw_hex=values[p].data.hex())
            for p,spec in FIELDS.items() if p in values]
    groups=[dict(keys=['%08x'%p[1] for p in group],
                 raw_words_hex=[values[p].data.hex() for p in group],
                 semantic_limit='two complete named words; scalar/time-unit interpretation is unproven')
            for group in TIME_GROUPS if all(p in values for p in group)]
    return dict(policy=POLICY,fields=fields,time_word_groups=groups,explicit_record_writes=0)


def collateral(plan):
    """Private pre-SAVE evidence; this does not change a legacy Plan ID."""
    groups=[g for g in plan.groups if any(r.key>>16==g and r.before_saved!=r.after_saved for r in plan.records)]
    if 0x02CF not in groups:return None
    return dict(policy=POLICY,group=0x02CF,pre_ram=state(plan.baseline.ram.records),
                pre_saved=state(plan.baseline.saved.records),
                predicted_native_copy='from immediately fresh RAM; SCREEN live/stored equality is not asserted',
                explicit_record_writes=0,historical_UI_restore_target=False)
