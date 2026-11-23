"""Observed effects of a selected native SAVE, never extra record writes.

The Gate profile accepts group51's native AP+CP merge. C(AP55) and D(CP55)
remain exact; every other group is protected against this operation's fresh
baseline. E values are retained for comparison, not admission or replay.
"""
from hashlib import sha256

LEGACY = 'named-save-collateral/1'
NATIVE51 = 'native-save51-observe/1'
C_D = frozenset(((0,0x00510055),(1,0x00510055)))


def active(plan):
    from .settings_plan import needs_save
    return (getattr(plan,'save_effects_policy',LEGACY)==NATIVE51 and plan.kind in ('ap55','original-ap55','gate-restore-ap55','backup-target-ap55')
            and any(needs_save(plan,g) for g in plan.groups))


def effect(plan,pair):
    return active(plan) and pair[1]>>16==0x51 and pair not in C_D


def identity(value):
    return dict(attrs=value.attrs,size=len(value.data),sha256=sha256(value.data).hexdigest())


def observation(plan,snapshot,expected):
    rows=[];differences=[]
    for pair in sorted(snapshot.ram.records):
        if not effect(plan,pair):continue
        planes={p:identity(getattr(snapshot,p).records[pair]) for p in ('ram','saved','bin','bak')}
        rows.append(dict(chip=pair[0],key=f'{pair[1]:08x}',planes=planes))
        for plane in planes:
            wanted=expected[plane][pair];actual=getattr(snapshot,plane).records[pair]
            if wanted!=actual:
                differences.append(dict(plane=plane,chip=pair[0],key=f'{pair[1]:08x}',
                                        expected=identity(wanted),actual=identity(actual)))
    return dict(profile=NATIVE51,scope='native-SAVE51-both-chip-group-minus-C-and-D',
                inventory=rows,differences=differences,extra_WRITE_authorized=False)


def adopt(plan,snapshot,expected):
    for plane in ('ram','saved','bin','bak'):
        for pair,value in getattr(snapshot,plane).records.items():
            if effect(plan,pair):expected[plane][pair]=value
