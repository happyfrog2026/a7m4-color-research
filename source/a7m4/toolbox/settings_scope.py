"""Read evidence and operation-specific settings admission; never WRITE/SAVE.

Raw BK4 snapshots remain complete immutable evidence. Their valid, out-of-scope
values are observations, not historical restore intent or a permission mask.
The existing transaction's full-record/complement/SAVE guards stay separate.
"""
from hashlib import sha256
from . import settings_plan as sp

CAPTURE_PROFILE='m4-602-owned-scope-read-capture/1'
FRESHNESS_PROFILE='m4-602-operation-settings-freshness/1'
PLANES=('ram','saved','bin','bak')
OWNED=dict(zip(sp.SELECTED,sp.SPANS))|{sp.AP55:((0,1),)}|{(0,k):((0,1),) for k in sp.ORIGINAL_BASE_KEYS}
SCOPES={'sound-bank':{},'sound-ap55':{sp.AP55:((0,1),)},'looks':OWNED,'original-restore':OWNED}

def digest(raw):return sha256(raw).hexdigest()

def _report(before,after,operation):
    if operation not in SCOPES:raise ValueError('Explicit registered settings operation scope required')
    sp.validate_snapshot(before);sp.validate_snapshot(after)
    if before.serial!=after.serial:raise ValueError('Settings snapshots belong to different bodies')
    spans=SCOPES[operation];errors=[];observations=[];planes={};absent_optional=[]
    for plane in PLANES:
        old,new=getattr(before,plane),getattr(after,plane)
        planes[plane]=dict(before_sha256=digest(old.raw),after_sha256=digest(new.raw),raw_equal=old.raw==new.raw)
        for pair,ranges in spans.items():
            left,right=old.records.get(pair),new.records.get(pair)
            # Original-value plans already treat absent optional base-selector
            # records as absent, never synthesizing or writing them. Formats
            # accepted for actual WRITE are still checked by that finite Plan.
            if left is None and right is None and pair[1] in sp.ORIGINAL_BASE_KEYS:
                absent_optional.append(dict(plane=plane,chip=pair[0],key='%08x'%pair[1]));continue
            if (left is None or right is None or (left.attrs,len(left.data))!=(right.attrs,len(right.data))
                    or any(not 0<=lo<hi<=len(left.data) for lo,hi in ranges)):
                errors.append('%s/%d/%08x: scoped record shape differs'%(plane,*pair));continue
            if any(left.data[lo:hi]!=right.data[lo:hi] for lo,hi in ranges):
                errors.append('%s/%d/%08x: scoped source bytes changed'%(plane,*pair))
        for pair in sorted(set(old.records)|set(new.records)):
            left,right=old.records.get(pair),new.records.get(pair)
            if left==right:continue
            def identity(v):return None if v is None else dict(attrs=v.attrs,size=len(v.data),sha256=digest(v.data))
            observations.append(dict(plane=plane,chip=pair[0],key='%08x'%pair[1],before=identity(left),after=identity(right),
                owned_ranges=[list(x) for x in spans.get(pair,())],explicit_WRITE_authorized=False))
    # These are current operational prerequisites, not whole historical-image
    # fingerprints. Direct CP record structure/CRC is checked by validate_snapshot;
    # any complete-record WRITE must still preserve its freshly read complement.
    for plane in PLANES:
        records=getattr(after,plane).records
        for pair,value in ((sp.CP55,sp.Value(0,b'\0')),(sp.BOOT_DEVICE,sp.Value(0,b'\1'))):
            if records.get(pair)!=value:errors.append('%s/%d/%08x: current dependency not admitted'%(plane,*pair))
    modes=[getattr(after,p).records.get(sp.AP55) for p in PLANES]
    if not all(v==modes[0] for v in modes) or modes[0] not in (sp.Value(0,b'\0'),sp.Value(0,b'\2')):
        errors.append('Current AP55 four-plane mode/shape is not coherent 00 or02')
    return dict(schema='a7m4-operation-settings-observation/1',profile=FRESHNESS_PROFILE,operation=operation,
        stable=not errors,raw_equal=all(r['raw_equal'] for r in planes.values()),integrity_verified=True,
        planes=planes,errors=errors,observed_differences=observations[:256],observed_difference_count=len(observations),
        diagnostic_sample_truncated=len(observations)>256,owned_record_count=len(spans),absent_optional_base_records=absent_optional,
        scope=[dict(chip=p[0],key='%08x'%p[1],ranges=[list(x) for x in ranges]) for p,ranges in sorted(spans.items())],
        dependency_scope='fresh AP55 mode; CP55=00; BOOT_DEVICE=01; complete parsed direct-CP structure',
        scope_note='looks conservatively retains all18 owned dependencies' if operation=='looks' else 'registered operation scope',
        full_snapshot_static=False,atomic_snapshot=False,authorizes_device_write=False,
        write_readback_policy_relaxed=False,historical_nonowned_values_replayed=False,
        finite_plan_format_and_SAVE_validation_still_required=True)

def capture_scope_report(before,after):
    report=_report(before,after,'original-restore')
    # A valid complete archive and applicability to a later write are different
    # facts. Owned drift stays visible and may refuse a later scoped operation.
    report.update(schema='a7m4-capture-settings-observation/1',profile=CAPTURE_PROFILE,
        capture_integrity_verified=True,settings_applicability=report['stable'],
        completeness_scope='two independently valid full settings snapshots; no atomic/static claim')
    return report

def settings_scope_freshness_report(before,after,*,operation,native_context=None):
    report=_report(before,after,operation);report['native_context']=native_context;return report

def sound_operation(snapshot,*,restore_ap55=False):
    sp.validate_snapshot(snapshot)
    # No-op AP55 plans have groups51 but emit no WRITE/SAVE. Bank/gate-only
    # work therefore has no historical slot/colour/settings fingerprint.
    return 'sound-ap55' if restore_ap55 or any(getattr(snapshot,p).records.get(sp.AP55)!=sp.Value(0,b'\2') for p in PLANES) else 'sound-bank'
