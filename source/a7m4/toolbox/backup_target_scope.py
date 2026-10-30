"""Backup-selected, finite feature restoration; no service or device operations.

This authority is deliberately different from an actual-dispatch C capsule.
The user selects a complete backup, and the registry below defines the only
fields restored from it.  Every other current byte remains current.  Native
writers, fresh runtime evidence and device ownership belong to the executor.
"""
from .. import resource_profile as device_scope
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import struct

from . import looks_program as lp, looks_settings as ls, looks_resource_scope as lr
from . import looks_resource_restore as rr, gate_scope as gate, sound_scope as sound
from . import settings_archive, settings_plan as sp
from .capture_inputs import read_private
from .capture_recovery import data_capture
from .native_actions import _json
from ..research import native_icons as icons
from ..research.native_audio_codec import decode_filter0

SCHEMA = 'a7m4-backup-target-scope/1'
REGISTRY = 'm4-602-supported-backup-targets/1'
AP, CP, BANK = (sound.PATHS[k] for k in ('ap', 'cp', 'bank'))
CUTOFF = 3182020
MAX_RESOURCE = 16 * 1024 * 1024
MAX_TAIL = 61440
MAX_PLAN = 16 * 1024 * 1024


def need(ok, message):
    if not ok:
        raise ValueError(message)


def identity(raw):
    return dict(size=len(raw), sha256=sha256(raw).hexdigest())


def _seal(value):
    value = deepcopy(value)
    value.pop('plan_id', None)
    value.pop('materialized', None)
    value['plan_id'] = sha256(_json(value)).hexdigest()
    return value


def _ranges(rows):
    """Normalize half-open registered ranges, not all source/backup diffs."""
    result = []
    for lo, hi in sorted(rows):
        need(type(lo) is int and type(hi) is int and 0 <= lo < hi, 'Invalid registered range')
        if result and lo <= result[-1][1]:
            result[-1][1] = max(result[-1][1], hi)
        else:
            result.append([lo, hi])
    return result


def _windows(before, after, ranges):
    result = []
    for lo, hi in _ranges(ranges):
        end = min(hi, len(before), len(after))
        # A migrated language table changes thousands of isolated pointer
        # bytes. Bound representation and native window count by grouping
        # within registered C only; never bridge an unowned F gap.
        for at in range(lo,end,512):
            stop=min(end,at+512)
            if before[at:stop]!=after[at:stop]:
                result.append(dict(offset=at,before_hex=before[at:stop].hex(),after_hex=after[at:stop].hex()))
    return result


def _project(current, backup, ranges, *, target_size=None):
    target_size = len(current) if target_size is None else target_size
    target = bytearray(current[:target_size])
    if target_size > len(target):
        target.extend(bytes(target_size-len(target)))
    for lo, hi in _ranges(ranges):
        need(hi <= len(backup) and hi <= len(target), 'Backup C range exceeds complete file')
        target[lo:hi] = backup[lo:hi]
    return bytes(target)


def _component(current, backup, target, ranges):
    return dict(source=identity(current), backup=identity(backup), target=identity(target),
        owned_ranges=_ranges(ranges), windows=_windows(current, target, ranges),
        append_hex=target[len(current):].hex(), source_eof=len(current), target_eof=len(target),
        E_F_restored=False, whole_file_identity_is_observation=True)


def _anchors(images, rows, owned):
    result = []
    for role, at, expected in rows:
        need(0 <= at < at+len(expected) <= len(images[role]), 'Dependency outside supported geometry')
        # C/D overlap remains C; dependencies never redefine target ownership.
        pieces = []
        for i, byte in enumerate(expected):
            if any(lo <= at+i < hi for lo, hi in owned[role]):
                continue
            need(images[role][at+i] == byte, 'Supported code dependency differs: %s/%d' % (role, at+i))
            if pieces and pieces[-1][0]+len(pieces[-1][1]) == at+i:
                pieces[-1][1].append(byte)
            else:
                pieces.append((at+i, bytearray((byte,))))
        result.extend(dict(role=role, offset=a, size=len(b), hex=bytes(b).hex()) for a,b in pieces)
    return result


def program_projection(current, backup):
    """All registered FL23/M9, sound words/Gate and cutoff over current F."""
    spec = lp.profile_data()
    owned = {r:[] for r in ('ap','cp')}
    for profile in spec['profiles'].values():
        for role, rows in profile.items():
            for row in rows:
                at, size = row['offset'], row['size']
                need(backup[role][at:at+size].hex() in {
                    row[k+'_hex'] for k in ('original','fl23','m9','m9_shared') if k+'_hex' in row},
                    'Backup contains an unsupported registered program target')
                owned[role].append((at,at+size))
    owned['ap'].extend((at,at+4) for at in sound.AP_OFFSETS)
    owned['cp'].extend((at,at+len(bytes.fromhex(off))) for at,off,on in gate.GATE_WINDOWS)
    owned['cp'].append((CUTOFF,CUTOFF+4))
    owned = {r:_ranges(v) for r,v in owned.items()}
    for role in ('ap','cp'):
        need(type(current[role]) is bytes and type(backup[role]) is bytes
             and len(current[role]) == len(backup[role]) == lp.LIMITS[role], 'Fixed program geometry differs')
    for images in (current,backup):
        need(images['ap'][:7] == b'\x7fELF\x02\x01\x01'
             and int.from_bytes(images['ap'][18:20],'little') == 183, 'AP AArch64 ELF differs')
    for at, off, on in gate.GATE_WINDOWS:
        need(backup['cp'][at:at+len(bytes.fromhex(off))].hex() in (off,on), 'Backup sound Gate target differs')
    gate.state(backup['cp'])
    need(backup['cp'][CUTOFF:CUTOFF+4].hex() in ('41ea0221','41f2a551'), 'Backup cutoff target differs')
    rows = [(r,a['offset'],bytes.fromhex(a['hex']))
        for r,anchors in spec['dependencies']['m9'].items() for a in anchors]
    rows += [('cp',a['offset'],bytes.fromhex(a['hex'])) for a in gate.profile()['anchors']]
    setup = json.loads(read_private(Path(sound.__file__).with_name('data')/'sound-dependencies.json',65536))
    need(setup['schema']=='m4-602-sound-setup-D/1' and setup['total_bytes']==172, 'Sound setup dependency profile differs')
    rows += [('ap',a['offset'],bytes.fromhex(a['hex'])) for a in setup['anchors']]
    D = _anchors(current,rows,owned)
    _anchors(backup,rows,owned)
    targets = {r:_project(current[r],backup[r],owned[r]) for r in owned}
    return dict(components={r:_component(current[r],backup[r],targets[r],owned[r]) for r in owned},
        D=D, cutoff=dict(offset=CUTOFF,size=4,target_hex=backup['cp'][CUTOFF:CUTOFF+4].hex()),
        blockers=[] if backup['cp'][CUTOFF:CUTOFF+4].hex()=='41ea0221' else [dict(path=CP,
            code='BACKUP_CUTOFF_TARGET_UNSUPPORTED',reason='This restore executor targets the original1/8 cutoff only')],
        E_F_gate_execution=False), targets


def _sound_descriptors(ap):
    words=[ap[at:at+4] for at in sound.AP_OFFSETS]
    if words==list(sound.STOCK_WORDS):
        return dict(family='stock',words=[w.hex() for w in words])
    need(all(len(w)==4 for w in words),'Sound descriptor bounds differ')
    if words==list(sound.pin_plan.AP_BEFORE):
        lengths=dict(ka=256,sha=(int.from_bytes(words[1],'little')>>5)&65535,
            kasha=(int.from_bytes(words[6],'little')>>5)&65535)
        starts={r:65536+((int.from_bytes(words[i],'little')>>5)&65535) for r,i in (('sha',0),('kasha',4))}
        need(starts['sha']==77504 and starts['kasha']==91904 and starts['kasha']+lengths['kasha']==108480,
             'Historical R066 sound geometry differs')
        return dict(family='historical-r066',words=[w.hex() for w in words],native_lengths=lengths,
            slots={r:[starts[r],lengths[r]] for r in starts})
    lengths=dict(ka=256,sha=(int.from_bytes(words[1],'little')>>5)&65535,
        kasha=(int.from_bytes(words[6],'little')>>5)&65535)
    need(all(0<n<=sound.pin_plan.SLOTS[r][1] and n%64==0 for r,n in lengths.items())
         and words==list(sound.pin_plan._ap_after(lengths)), 'Backup sound descriptor is not a registered layout')
    return dict(family='registered-custom',words=[w.hex() for w in words],native_lengths=lengths)


def settings_projection(current, backup):
    """Only two CP color spans, six FL slots, Custom1 three fields and AP55."""
    sp.validate_snapshot(current); sp.validate_snapshot(backup)
    need(current.serial == backup.serial, 'Backup settings belong to a different body')
    for snapshot in (current,backup):
        for plane in ls.PLANES:
            values=getattr(snapshot,plane).records
            need(values.get(sp.CP55)==sp.Value(0,b'\0') and values.get(sp.BOOT_DEVICE)==sp.Value(0,b'\1'),
                 'Required CP55/BOOT setting differs')
            need(values.get(sp.AP55) in (sp.Value(0,b'\0'),sp.Value(0,b'\2')), 'Supported AP55 endpoint differs')
    specs=dict(ls.SPEC); specs[sp.AP55]=(0,1,((0,1),))
    records=[]; groups=set()
    for pair,(attrs,size,spans) in sorted(specs.items()):
        for snapshot in (current,backup):
            for plane in ls.PLANES:
                value=getattr(snapshot,plane).records.get(pair)
                need(value is not None and value.attrs==attrs and len(value.data)==size, 'Registered setting shape differs')
        row=dict(chip=pair[0],key=pair[1],attrs=attrs,size=size,spans=[])
        for lo,hi in spans:
            field=dict(start=lo,end=hi)
            for plane in ('ram','saved'):
                field[plane+'_before_hex']=getattr(current,plane).records[pair].data[lo:hi].hex()
                field[plane+'_target_hex']=getattr(backup,plane).records[pair].data[lo:hi].hex()
            row['spans'].append(field)
        row['ram_changed']=any(w['ram_before_hex']!=w['ram_target_hex'] for w in row['spans'])
        row['needs_save']=any(getattr(current,p).records[pair].data[lo:hi]!=backup.saved.records[pair].data[lo:hi]
            for p in ('saved','bin','bak') for lo,hi in spans)
        row['changed']=row['ram_changed'] or row['needs_save']
        if row['needs_save']:groups.add(pair[1]>>16)
        records.append(row)
    return dict(records=records,protected_spans=[dict(chip=r['chip'],key=r['key'],attrs=r['attrs'],size=r['size'],
        spans=[[w['start'],w['end']] for w in r['spans']]) for r in records],groups=sorted(groups),
        D=dict(CP55='00',BOOT_DEVICE='01',AP55_allowed=['00','02']),
        save_policy='native-observe-only-outside-selected-C',E_F_gate_execution=False,
        raw_BK4_replay=False,Custom2_to_6_restored=False)


def _strings(raw):
    need(type(raw) is bytes and len(raw)>=16 and raw[:12]==b'uxc\7\0\0\0\0\x08\0\x05\0'
         and len(raw)%4==0, 'Unsupported string layout')
    descriptor=struct.unpack_from('<I',raw,12)[0]; count=descriptor&8191
    need(count in (3032,3048) and descriptor==count|(count<<12), 'Unsupported string index geometry')
    base=(16+2*count+3)&~3; need(base<len(raw),'String index outside file')
    entries={}
    for i in range(count):
        p=struct.unpack_from('<H',raw,16+2*i)[0]
        if p==65535:continue
        at=base+4*p; end=raw.find(b'\0',at+4)
        need(at+5<=len(raw) and raw[at:at+4]==struct.pack('<I',0x1e00a000+i) and end>=0,
             'String reference/record bounds differ')
        entries[i]=dict(at=at,end=(end+4)&~3,index=16+2*i,text=raw[at+4:end])
    return dict(count=count,base=base,entries=entries)


def _bitmap_end(raw, start):
    """Find one self-delimiting native70x35 payload, including old inactive ones."""
    at=start
    for expected in (4096,icons.RAW_BYTES-4096):
        need(at<len(raw) and raw[at]==0xf0,'Unrecognized native bitmap page');at+=1; produced=0
        while True:
            need(at<len(raw),'Truncated bitmap flags');flags=raw[at];at+=1;done=False
            for bit in range(8):
                if flags>>bit&1:
                    need(at+2<=len(raw),'Truncated bitmap reference');a,b=raw[at:at+2];at+=2
                    if not(a or b):
                        need(flags>>(bit+1)==0 and produced==expected,'Bitmap terminator differs');done=True;break
                    distance,count=(a&15)*256+b,icons._LENGTHS[a>>4]
                    need(0<distance<=produced and produced+count<=expected,'Bitmap reference differs');produced+=count
                else:
                    need(at<len(raw) and produced<expected,'Bitmap literal differs');at+=1;produced+=1
            if done:break
    icons.decompress_native(raw[start:at])
    return at


def _tail_layout(path, larger, smaller):
    need(0<len(larger)-len(smaller)<=MAX_TAIL,'Resource tail exceeds registered bounded layout')
    at=len(smaller); chunks=[]
    if Path(path).name.startswith('string_'):
        small,big=_strings(smaller),_strings(larger)
        expected=[0xabe2-0xa000]
        if small['count']==3032 and big['count']==3048:
            expected=[i for i,r in sorted(small['entries'].items()) if r['at']<small['base']+32]
            expected.extend(range(0xabe2-0xa000,0xabe2-0xa000+6))
        else:need(small['count']==big['count']==3048,'No registered label append topology')
        for index in expected:
            need(at+5<=len(larger),'Unrecognized string tail')
            rid=struct.unpack_from('<I',larger,at)[0];end=larger.find(b'\0',at+4)
            need(rid==0x1e00a000+index and end>=0,'Unrecognized string append order')
            need(big['entries'].get(index,{}).get('at')==at,'Appended string is not the active registered generation')
            if index>=0xabe2-0xa000:
                text=larger[at+4:end];need(1<=len(text)<=63,'Custom label size differs');text.decode('utf-8')
            stop=(end+4)&~3;need(stop<=len(larger) and not any(larger[end+1:stop]),'String tail padding differs')
            chunks.append(dict(offset=at,size=stop-at,kind='registered-label-or-index-relocation'));at=stop
        need(at==len(larger),'Unrecognized inactive string append after the active generation')
    else:
        small,big=icons._inspect_bank(smaller),icons._inspect_bank(larger)
        def consume(row,kind):
            nonlocal at
            need(row['start']==at,'Image append is not the active canonical route group')
            stop=at+row['size'];need(stop<=len(larger),'Image append outside EOF')
            if kind!='relocated-original-image':need(_bitmap_end(larger,at)==stop,'Image payload length differs')
            chunks.append(dict(offset=at,size=row['size'],kind=kind))
            pad=(-stop)%4;need(stop+pad<=len(larger) and not any(larger[stop:stop+pad]),'Image tail padding differs');at=stop+pad
        for index in (icons.NORMAL[0],icons.SELECTED[0]):
            before,after=small['records'][index],big['records'][index]
            if (before['start'],before['size'])!=(after['start'],after['size']):consume(after,'native-list-route-'+str(index))
        if 0x1e9a not in small['records']:
            need(0x1e9a in big['records'],'No active playback registration proves the remaining image tail')
            donor_id,donor=_deterministic_donor(small)
            need(big['records'][0x1e9a]['at']==donor['start'],'Playback donor is not the canonical independent payload')
            actual=big['records'].get(donor_id)
            need(actual is not None and all(actual[k]==donor[k] for k in ('at','field','width','height','flags','size')),
                 'Relocated donor geometry differs')
            # The donor first20 bytes were replaced by metadata (C); the rest
            # is still current F, never restored from a historical full file.
            expected=smaller[donor['start']:donor['start']+20]+larger[donor['start']+20:donor['start']+donor['size']]
            need(larger[actual['start']:actual['start']+actual['size']]==expected,'Relocated donor bytes are not the registered current payload')
            consume(actual,'relocated-original-image');consume(big['records'][0x1e9a],'native-playback-route')
        else:
            need(0x1e9a in big['records'],'Playback registration was already removed; tail provenance needs a retained checkpoint')
            before,after=small['records'][0x1e9a],big['records'][0x1e9a]
            if (before['start'],before['size'])!=(after['start'],after['size']):consume(after,'native-playback-route')
        need(at==len(larger),'Unrecognized inactive bitmap beyond the canonical active route group')
    return dict(verified=True,chunks=chunks,bytes=len(larger)-len(smaller),
        basis='recognized supported codec/layout, not fabricated dispatch history')


def _deterministic_donor(bank):
    metadata_end=max(r['at']+r['field']+8 for r in bank['records'].values());candidates=[]
    for i,r in bank['records'].items():
        start,end=r['start'],r['start']+r['size']
        if i in {icons.NORMAL[0],icons.SELECTED[0],0x1e98,0x1e99} or r['size']<20 or start<metadata_end:continue
        if (start-bank['base'])%4 or (start-bank['base'])//4>=65535:continue
        if any(j!=i and other['start']<end and start<other['start']+other['size'] for j,other in bank['records'].items()):continue
        candidates.append((r['size'],i,r))
    need(candidates,'No independent canonical playback donor')
    _,i,r=min(candidates,key=lambda v:v[:2]);return i,r


def _image_aliases(raw,ranges,*,victim=None):
    bank=icons._inspect_bank(raw);checked=0
    for index,row in bank['records'].items():
        lo,hi=row['start'],row['start']+row['size']
        for a,b in _ranges(ranges):
            if a>=hi or lo>=b:continue
            allowed=(victim is not None and index==victim['id'] and lo==victim['start']
                and lo<=max(a,lo)<min(b,hi)<=lo+20)
            need(allowed,'Live image payload aliases a registered metadata/victim write')
        checked+=1
    return dict(verified=True,kind='all-live-payload-vs-registered-write-ranges',records=checked,
        original_payload_bytes_are_F=True)


def _factory_bank_eof(path):
    variant='23' if '_23_' in path else '32'
    profiles=[r for r in icons._profile_data() if r['id']=='official602']
    need(len(profiles)==1,'Registered original bank geometry is missing')
    return profiles[0]['banks'][variant]['size']


def check_resource_D(component,current,target):
    """Fresh semantic D for an already authenticated scope component.

    Executors pass the component from their immutable validated job.  This
    function does not grant C, infer tail provenance or rebuild file history.
    It checks fresh alias/reference safety without comparing unrelated pixels.
    """
    path=component['path'];need(path in lr.PATHS,'Unknown registered resource path')
    proof=dict(reference_bounds=rr.references(path,target,len(target)),E_F_hash_admission=False)
    if Path(path).name.startswith('image_'):
        victim=component.get('layout',{}).get('victim')
        proof.update(source_alias_D=_image_aliases(current,component['owned_ranges'],victim=victim),
            target_alias_D=_image_aliases(target,component['owned_ranges'],victim=victim))
    return proof


def _unsupported_resource_target(path,current,backup,reason,*,code='BACKUP_RESOURCE_TARGET_UNSUPPORTED'):
    row=_component(current,backup,current,[])
    row.update(path=path,layout=dict(kind='unsupported-backup-target'),
        tail=dict(action='PRESERVE_UNSUPPORTED_BACKUP_TARGET' if code=='BACKUP_RESOURCE_TARGET_UNSUPPORTED' else 'PRESERVE_SOURCE_GEOMETRY_CONFLICT',
            source_eof=len(current),target_eof=len(current)),
        blockers=[dict(path=path,code=code,reason=reason,current_preserved=True)])
    return row,current


def resource_projection(path, current, backup):
    """Backup registered routes over current F, with a separately guarded EOF."""
    need(path in lr.PATHS and 0<len(current)<=MAX_RESOURCE and 0<len(backup)<=MAX_RESOURCE,'Unknown resource path/geometry')
    ranges=[]; layout={}; blockers=[]
    if Path(path).name.startswith('string_'):
        b=_strings(backup)
        if b['count']!=3032:
            return _unsupported_resource_target(path,current,backup,'Selected original backup must use factory3032 string resources, not added custom labels')
        a=_strings(current);layout=dict(kind='strings',source_count=a['count'],backup_count=b['count'])
        if a['count']!=b['count']:
            ranges.append((12,min(len(backup),max(a['base'],b['base']))))
            if b['count']==3032:ranges.append((b['base'],min(b['base']+32,len(backup))))
            else:
                for i,r in b['entries'].items():
                    if i>=3032 or r['at']>=len(current):ranges.append((r['at'],r['end']))
        elif b['count']==3048:
            index=0xabe2-0xa000;need(index in a['entries'] and index in b['entries'],'Custom1 label reference missing')
            r=b['entries'][index];ranges.append((r['index'],r['index']+2))
    else:
        b=icons._inspect_bank(backup)
        if 0x1e9a in b['records'] or len(backup)!=_factory_bank_eof(path):
            return _unsupported_resource_target(path,current,backup,'Selected original backup must use the original factory bank EOF without custom playback registration/appended routes')
        a=icons._inspect_bank(current)
        need(a['base']==b['base'] and current[:16]==backup[:16],'Image index geometry differs')
        layout=dict(kind='imagebank',routes=deepcopy(lr.ROUTES))
        victim=None
        for index in (icons.NORMAL[0],icons.SELECTED[0],0x1e9a):
            x,y=a['records'].get(index),b['records'].get(index)
            if index!=0x1e9a:need(x is not None and y is not None,'Required Custom1 list route missing')
            if x is None and y is None:continue
            need(all((r['width'],r['height'],r['flags'],r['field'])==(70,35,0xc0000000,12)
                for r in (x,y) if r is not None),'Registered native route geometry differs')
            if y is not None:
                if x is not None:
                    need((x['at'],x['field'],x['width'],x['height'],x['flags'])==
                        (y['at'],y['field'],y['width'],y['height'],y['flags']),'Registered image metadata geometry differs')
                    need(current[16+2*index:18+2*index]==backup[16+2*index:18+2*index],'Existing image index dependency differs')
                    ranges.append((y['at']+y['field'],y['at']+y['field']+8))
                else:
                    need(index==0x1e9a,'Only playback registration may be added')
                    ranges.extend(((16+2*index,18+2*index),(y['at'],y['at']+20)))
                    donors=[(i,r) for i,r in a['records'].items() if r['start']==y['at']]
                    need(len(donors)==1,'Backup playback donor is not independently registered')
                    donor_id,donor=donors[0];ranges.append((donor['at']+donor['field']+4,donor['at']+donor['field']+8))
                    victim=dict(id=donor_id,start=donor['start'])
            elif x is not None:
                ranges.append((16+2*index,18+2*index))
                donors=[(i,r) for i,r in b['records'].items() if r['start']==x['at']]
                need(len(donors)==1,'Unknown playback donor relocation')
                donor_id,donor=donors[0];actual=a['records'].get(donor_id)
                need(actual is not None and all(actual[k]==donor[k] for k in ('at','field','width','height','flags','size')),
                     'Playback donor dependency differs')
                ranges.extend(((donor['at']+donor['field']+4,donor['at']+donor['field']+8),(donor['start'],donor['start']+20)))
                layout['playback_donor_id']=donor_id
                victim=dict(id=donor_id,start=donor['start'])
        layout['victim']=victim
    if len(current)<len(backup):
        return _unsupported_resource_target(path,current,backup,'Current resource is shorter than the original factory EOF; no supported append restoration is inferred',
            code='RESOURCE_SOURCE_FACTORY_EOF_DEPENDENCY')
    desired=len(backup); prefix_size=max(len(current),desired)
    if desired>len(current):ranges.append((len(current),desired))
    target=_project(current,backup,ranges,target_size=prefix_size)
    if not Path(path).name.startswith('string_'):
        layout['source_alias_D']=_image_aliases(current,ranges,victim=victim)
        layout['target_alias_D']=_image_aliases(target,ranges,victim=victim)
    tail=dict(action='NO_CHANGE',source_eof=len(current),target_eof=desired,requires_fresh_runtime_load_proof=False)
    if len(current)!=desired:
        try:
            tail['layout']=_tail_layout(path,current,backup) if len(current)>desired else _tail_layout(path,backup,current)
            rr.references(path,target,desired)
            tail.update(action='TRUNCATE_KNOWN_APPEND' if len(current)>desired else 'APPEND_BACKUP_REGISTERED_DATA',
                requires_fresh_runtime_load_proof=len(current)>desired,
                reference_bounds_verified=True,original_backup_is_authority=True)
            target=target[:desired]
        except ValueError as error:
            tail.update(action='PRESERVE_DEPENDENCY_CONFLICT',error=str(error),target_eof=len(current))
            blockers.append(dict(path=path,code='RESOURCE_TAIL_LAYOUT_OR_REFERENCE_DEPENDENCY',reason=str(error),tail_preserved=True))
            target=target[:len(current)]
    if not blockers:
        rr.references(path,target,len(target))
    row=_component(current,backup,target,ranges)
    row.update(path=path,layout=layout,tail=tail,blockers=blockers,
        prefix_target=identity(_project(current,backup,ranges,target_size=prefix_size)),
        authority='selected-backup-registered-layout',requires_consumer_reload_before_EOF=bool(len(current)>desired))
    return row,target


def sound_projection(current, backup, *, current_ap=None, backup_ap=None):
    ranges=[(0,256)]; blockers=[]
    if len(backup)!=sound.ORIGINAL_EOF or (backup_ap is not None and
            [backup_ap[at:at+4] for at in sound.AP_OFFSETS]!=list(sound.STOCK_WORDS)):
        blockers.append(dict(path=BANK,code='BACKUP_SOUND_TARGET_UNSUPPORTED',
            reason='Selected backup must have the supported original77504-byte sound bank and stock seven descriptors',current_preserved=True))
        return dict(**_component(current,backup,current,[]),path=BANK,blockers=blockers,tail_action='PRESERVE_UNSUPPORTED_BACKUP_TARGET'),current
    try:
        need(current_ap is not None,'Current sound descriptors must be observed before any persistent write')
        descriptor=_sound_descriptors(current_ap)
        if len(current)==sound.ORIGINAL_EOF:
            need(descriptor['family']=='stock' and current[:256]==backup[:256], 'Factory sound descriptor/head endpoint differs')
            source_layout='stock-native-pin'
        else:
            words=[current_ap[at:at+4] for at in sound.AP_OFFSETS]
            r066=len(current)==108480 and words==list(sound.pin_plan.AP_BEFORE)
            need((r066 and descriptor['family']=='historical-r066') or
                 (len(current)==sound.TARGET_EOF and descriptor['family']=='registered-custom'),
                 'Sound EOF/descriptor endpoint is outside registered R066/fixed110528 families')
            source_layout='historical-r066-native-pin' if r066 else 'fixed110528-native-pin'
            lengths=descriptor['native_lengths'];decode_filter0(current[:256])
            for role in ('sha','kasha'):
                at,capacity=(descriptor['slots'][role] if r066 else sound.pin_plan.SLOTS[role]);size=lengths[role]
                need(at+size<=len(current),'Sound descriptor exceeds observed bank EOF')
                decode_filter0(current[at:at+size])
                need(not any(current[at+size:min(at+capacity,len(current))]),'Unknown bytes occupy unused registered sound capacity')
    except ValueError as error:
        blockers.append(dict(path=BANK,code='UNKNOWN_SOUND_SOURCE_ENDPOINT',reason=str(error),current_preserved=True))
        return dict(**_component(current,backup,current,[]),path=BANK,blockers=blockers,tail_action='PRESERVE_UNKNOWN_TAIL'),current
    if len(backup)>sound.ORIGINAL_EOF:ranges.append((sound.ORIGINAL_EOF,len(backup)))
    target=_project(current,backup,ranges,target_size=len(backup))
    return dict(**_component(current,backup,target,ranges),path=BANK,blockers=blockers,
        tail_action='TRUNCATE_REGISTERED_SOUND_SLOTS' if len(current)>len(backup) else 'PROJECT_REGISTERED_SOUND_SLOTS',
        source_layout=source_layout,source_descriptor_layout=descriptor,
        source_descriptor_words=None if current_ap is None else [current_ap[at:at+4].hex() for at in sound.AP_OFFSETS],
        source_head_identity=identity(current[:256]),
        preserved_current_interval=[256,sound.ORIGINAL_EOF],native_descriptor_offsets=list(sound.AP_OFFSETS),
        requires_matching_descriptor_and_runtime_proof=True),target


def _load(path, *, current):
    path=Path(path).absolute(); before=read_private(path,2*1024*1024);receipt=data_capture(path)
    if current:need(receipt.get('normal_return_verified') is True,'Current device admission needs a confirmed normal return')
    settings=settings_archive.load_snapshot(path.parent/'settings')
    files={}
    for name,row in receipt['objects'].items():
        if row['target_path'] not in device_scope.READ_PATHS:continue
        raw=read_private(Path(receipt['snapshot_dir'])/name,160*1024*1024)
        need(identity(raw)=={k:row[k] for k in ('size','sha256')},'Capture snapshot changed during scope reconstruction')
        files[row['target_path']]=raw
    need(read_private(path,2*1024*1024)==before,'Capture receipt changed during scope reconstruction')
    after=path.parent/('settings-after' if receipt.get('portable_import') else 'evidence/settings-after')/'manifest.json'
    binding=dict(receipt=str(path),receipt_sha256=sha256(before).hexdigest(),
        archive_sha256=receipt['archive_sha256'],body_binding=receipt['body_binding'],
        settings_manifest_sha256=sha256(read_private(path.parent/'settings/manifest.json',32768)).hexdigest(),
        after_settings_manifest_sha256=sha256(read_private(after,32768)).hexdigest() if after.is_file() else None,
        historical_normal_return_verified=receipt['normal_return_verified'])
    return binding,settings,files


def _construct(current_capture,backup_capture):
    current,cs,source=_load(current_capture,current=True); backup,bs,original=_load(backup_capture,current=False)
    need(current['body_binding']==backup['body_binding'] and set(source)==set(original),'Backup/current body or complete inventory differs')
    program,p=program_projection({r:source[k] for r,k in (('ap',AP),('cp',CP))},
        {r:original[k] for r,k in (('ap',AP),('cp',CP))})
    targets=dict(source);targets[AP],targets[CP]=p['ap'],p['cp']
    settings=settings_projection(cs,bs);resources=[];blockers=deepcopy(program['blockers'])
    for path in lr.PATHS:
        try:row,target=resource_projection(path,source[path],original[path])
        except ValueError as error:
            row=dict(path=path,source=identity(source[path]),backup=identity(original[path]),target=identity(source[path]),
                owned_ranges=[],windows=[],source_eof=len(source[path]),target_eof=len(source[path]),
                blockers=[dict(path=path,code='RESOURCE_REGISTERED_LAYOUT_DEPENDENCY',reason=str(error),current_preserved=True)])
            target=source[path]
        resources.append(row);targets[path]=target;blockers.extend(row['blockers'])
    audio,targets[BANK]=sound_projection(source[BANK],original[BANK],current_ap=source[AP],backup_ap=original[AP]);blockers.extend(audio['blockers'])
    audio['backup_descriptors']=_sound_descriptors(original[AP])
    changed=[p for p in sorted(targets) if targets[p]!=source[p]]
    value=dict(schema=SCHEMA,registry=REGISTRY,resource_profile=device_scope.ID,current_capture=current,backup_capture=backup,
        firmware='6.02',body_binding=current['body_binding'],program=program,settings=settings,
        resources=dict(files=resources,known_paths=len(lr.PATHS)),sound=audio,changed_objects=changed,blockers=blockers,
        operation='RESTORE_SUPPORTED_BACKUP_SCOPE' if changed or any(r['changed'] for r in settings['records']) or blockers else 'NO_OP',
        ready_for_execution=not blockers,E_F_gate_execution=False,E_F_restored=False,cache_restore='NORMAL_REBUILD',
        authority_kind='selected-backup-supported-feature-registry',actual_dispatch_history_required=False,
        observations=dict(files=[dict(path=p,current=identity(source[p]),backup=identity(original[p]),
            projected=identity(targets[p]),whole_source_backup_different=source[p]!=original[p]) for p in sorted(source)],
            whole_file_hashes_are_admission=False),camera_io=False,network_io=False)
    return _seal(value),targets


def make_plan(current_capture,backup_capture,*,output=None):
    plan,targets=rebuild_projection(current_capture,backup_capture)
    if output is not None:
        root=Path(output).absolute()
        need(not root.exists() and root.parent.is_dir() and not any(p.is_symlink() for p in (root,*root.parents)), 'New private projection directory required')
        root.mkdir(mode=0o700);refs={}
        for i,path in enumerate(plan['changed_objects']):
            target=root/('%03d.bin'%i);fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            with os.fdopen(fd,'wb') as stream:stream.write(targets[path]);stream.flush();os.fsync(stream.fileno())
            refs[path]=dict(path=str(target),**identity(targets[path]))
        plan['materialized']=refs
    return plan


def _validated_projection(plan):
    need(type(plan) is dict and plan.get('schema')==SCHEMA and len(_json(plan))<=MAX_PLAN,'Finite backup-target plan required')
    expected,targets=rebuild_projection(plan['current_capture']['receipt'],plan['backup_capture']['receipt'])
    actual=deepcopy(plan);refs=actual.pop('materialized',None)
    need(actual==expected,'Backup-target plan differs from complete dual-source reconstruction')
    if refs is not None:
        need(type(refs) is dict and set(refs)==set(plan['changed_objects']),'Projected output inventory differs')
        for path,row in refs.items():
            raw=read_private(Path(row['path']),160*1024*1024)
            need(identity(raw)=={k:row[k] for k in ('size','sha256')}==identity(targets[path]),'Projected output differs from selected backup scope')
    return deepcopy(plan),targets


def validate_plan(plan):
    return _validated_projection(plan)[0]


def projected_images(plan):
    return _validated_projection(plan)[1]


def validated_projection(plan):
    """One dual-source reconstruction, returning its bound immutable bytes.

    This is per-call reuse for an executor's single validated job, never a
    global/path cache or permission to skip fresh C/D/native checks.
    """
    return _validated_projection(plan)


def rebuild_projection(current_capture,backup_capture):
    """Public dual-source constructor returning the plan and its same bytes."""
    return _construct(current_capture,backup_capture)
