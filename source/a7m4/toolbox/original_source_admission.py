"""Rebuild a complete forward bootable source without an old install receipt.

Used only when current disk and AP runtime differ, before any restore writes.
Unknown/mixed/partial combinations are refused; file hashes alone do not grant
source adoption. Ordinary restoration of an already adopted source is separate.
"""
from hashlib import sha256
from pathlib import Path
from .restore_authority import validate_plan as validate_restore_authority
from . import looks,settings_archive,settings_plan as sp,original_restore as diff
from .capture_inputs import read_private
from .original_sound_adapter import descriptor_profile
from ..research import pin_plan,native_icons as icons
from .pin_sources import STOCK_WORDS


def _program_match(master):
    by_kind={r['kind']:r for r in master['objects'] if r['kind'] in ('ap','cp')}
    current={role:read_private(by_kind[role]['source_path'],160*1024*1024) for role in ('ap','cp')}
    original={role:read_private(by_kind[role]['original_path'],160*1024*1024) for role in ('ap','cp')}
    data=looks._profile_data()
    # A registered current/R066 pair can itself be the canonical witness.
    for words in (STOCK_WORDS,pin_plan.AP_BEFORE):
        ap=bytearray(current['ap'])
        for at,word in zip(pin_plan.AP_OFFSETS,words):ap[at:at+4]=word
        normalized={'ap':bytes(ap),'cp':current['cp']}
        try:
            profile=looks._canonical_program_profile(normalized,data)
            return dict(name='canonical',profile=profile,display=False,root='source')
        except ValueError:pass
    # Reuse the forward generator over the registered original complete pair.
    profile=looks._canonical_program_profile(original,data)
    states=looks._program_states(original,data)
    words=tuple(original['ap'][at:at+4] for at in pin_plan.AP_OFFSETS)
    ap=bytearray(current['ap'])
    for at,word in zip(pin_plan.AP_OFFSETS,words):ap[at:at+4]=word
    normalized={'ap':bytes(ap),'cp':current['cp']}
    match=next((state for state in states if normalized==state['images']),None)
    if match is None:raise ValueError('Current AP/CP is not one independently rebuilt forward combination')
    return dict(name=match['name'],profile=match['profile'],display='display' in match['name'],root='original')


def validate_source_boot(master):
    master=validate_restore_authority(master)
    state=_program_match(master)
    root=Path(master['source_capture']['receipt']).parent
    snapshot=settings_archive.load_snapshot(root/'settings');sp.validate_fixed_prerequisites(snapshot)
    bank=next(r for r in master['objects'] if r['kind']=='audio')
    ap=next(r for r in master['objects'] if r['kind']=='ap')
    pin=descriptor_profile(read_private(ap['source_path'],160*1024*1024),read_private(bank['source_path'],131072))
    bank_raw=read_private(bank['source_path'],131072)
    # All non-owned consumers must match the fixed registered source profile.
    profile=state['profile']
    # Full bank may be imported audio, but the shared non-PIN area is fixed.
    if sha256(bank_raw[6144:77504]).hexdigest()!='a7cd1be07a678108382692e21103225ba3a23b0b756a764e3f1ca418f3a3f313':
        raise ValueError('Source bank changes non-PIN consumers')
    if state['name']!='canonical' or profile['kind']!='stock' or pin['profile']!='stock-native-pin':
        if any(getattr(snapshot,p).records[sp.AP55].data!=b'\x02' for p in ('ram','saved','bin','bak')):
            raise ValueError('Forward installed source requires coherent saved/live AP55=02')
    fl23=profile['kind']!='stock' or state['name']!='canonical'
    if fl23:
        patches=sp._payload()
        for i,pair in enumerate(sp.SELECTED):
            patch=patches[i] if i<2 else ((0,1,bytes((10 if i%2==0 else 11,))),)
            for plane in ('ram','saved','bin','bak'):
                raw=getattr(snapshot,plane).records[pair].data
                if sp._merge(raw,patch)!=raw:raise ValueError('Forward program and FL23 saved settings are a partial combination')
    resources=[r for r in master['objects'] if r['kind']=='resource'];names=set()
    for row in resources:
        raw=read_private(row['source_path'],16*1024*1024)
        if not state['display']:
            spec=profile['files'][row['path']]
            if len(raw)<spec['size'] or sha256(raw[:spec['size']]).hexdigest()!=spec['sha256']:
                raise ValueError('Canonical programs and source resource references do not form one forward endpoint')
            continue
        baseline=read_private(row['original_path'],16*1024*1024)
        spec=profile['files'][row['path']]
        if len(baseline)<spec['size'] or sha256(baseline[:spec['size']]).hexdigest()!=spec['sha256']:
            raise ValueError('No registered resource baseline for independent source adoption')
        baseline=baseline[:spec['size']]
        if Path(row['path']).name.startswith('string_'):
            _,current=looks._strings(raw);_,before=looks._strings(baseline)
            labels=set(looks._LABELS)
            if set(current)!=(set(before)|labels):raise ValueError('Source language registration scope differs')
            if any(current[k]['text']!=v['text'] for k,v in before.items() if k not in labels):
                raise ValueError('Source language changes an unowned label')
            if any(current[k]['text']!=(before[k]['text'] if k in before else 'ST') for k in looks._LABELS[1:]):
                raise ValueError('Source changed another custom label')
            name=current[looks._LABELS[0]]['text']
            if not 1<=len(name.encode())<=63:raise ValueError('Source custom name is unbounded')
            names.add(name)
        else:
            current=icons._inspect_bank(raw)['records'];before=icons._inspect_bank(baseline)['records']
            owned={icons.NORMAL[0],icons.SELECTED[0],0x1E9A}
            if set(current)!=(set(before)|{0x1E9A}):raise ValueError('Source icon registration scope differs')
            for key,record in current.items():
                if key in owned:
                    if (record['width'],record['height'],record['flags'],record['field'])!=(70,35,0xC0000000,12):
                        raise ValueError('Source custom icon geometry differs')
                    icons.decompress_native(raw[record['start']:record['start']+record['size']])
                else:
                    old=before[key]
                    if any(record[k]!=old[k] for k in ('width','height','flags','field','size')) or raw[record['start']:record['start']+record['size']]!=baseline[old['start']:old['start']+old['size']]:
                        raise ValueError('Source changes another icon consumer')
    if state['display'] and len(names)!=1:raise ValueError('Source language names are not a consistent forward endpoint')
    return dict(schema='a7m4-original-source-boot-admission/1',profile=profile['id'],program_state=state['name'],
        independent_forward_reconstruction=True,resource_count=len(resources),settings_coherent=True,
        native_pin_profile=pin['profile'],source_archive_sha256=master['source_capture']['archive_sha256'])
