"""Offline Custom1 M9 resource C/D plans and actual-dispatch originals.

Only the seventy known UXC resources, the fixed M9 name and six M9 icon routes
are supported. Whole-file identities are observations, including during a native
transaction. The caller owns service entry, body/boot binding, all-resource
inspection before the first write, WBI, cleanup and healthy STOP policy.
"""
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import subprocess
import uuid

from . import looks, resource_forward as forward, resource_worker as atomic
from .program_worker import _elf, _save
from ..research import native_icons as icons
from .policy import display_name as checked_name

SCHEMA = 'a7m4-custom1-resource-C-D/2'
CAPSULE_SCHEMA = 'a7m4-custom1-resource-original-C/1'
PATHS = tuple(sorted(forward.PATHS))
ROUTES = {'list-normal': icons.NORMAL[0], 'list-selected': icons.SELECTED[0], 'playback': 0x1E9A}
NATIVE_SHA='c6718acdd58525b5f1c440c1ecbeecb3b189c5aea7e70a6c01e5d56abc18e9d5'
REQUEST_PATH, REPORT_PATH = forward.REQUEST_PATH, forward.RESULT_PATH
REQUEST_BYTES, REPORT_BYTES = forward.REQUEST.size, 672
REPORT_VERSION = 2
_BUDGET_KEYS = ('usr_type','usr_unit','usr_available','usr_required','append_bytes',
                'append_attempts','append_completed','unknown_dirty_blocks')
_SCAN_KEYS = ('scanned_dirty_blocks','scanned_pending_files','capacity_scan_complete','capacity_reserved')
need, canonical = atomic.need, atomic.canonical


def identity(raw):
    return dict(size=len(raw), sha256=sha256(raw).hexdigest())


def seal(value, key='plan_id'):
    value = deepcopy(value); value.pop(key, None)
    value[key] = sha256(canonical(value)).hexdigest()
    return value


def _read(value):
    if type(value) is bytes:
        return value
    from .capture_inputs import read_private
    return read_private(Path(value), atomic.LIMIT)


def _private_json(path, value):
    path = Path(path)
    need(path.parent.is_dir() and not any(p.is_symlink() for p in (path, *path.parents)),
         'Private capsule path must not cross symbolic links')
    tmp = path.with_name('.' + path.name + '.' + uuid.uuid4().hex)
    _save(tmp, canonical(value) + b'\n')
    os.replace(tmp, path)
    fd = os.open(path.parent, os.O_RDONLY)
    try: os.fsync(fd)
    finally: os.close(fd)


def project_display(project):
    """Display snapshot is independent of the finite M9 program recipe."""
    manifest,base=icons._project(project)
    slots=manifest.get('slots');need(type(slots) is list and len(slots)==1 and slots[0].get('slot')==1,'Exactly Custom1 display is required')
    text=icons._text(slots[0].get('text'))
    value=manifest.get('toolbox_display')
    if value is None:name=checked_name(text)
    else:
        need(type(value) is dict and set(value)=={'schema','slot','display_name','icon_text'}
             and value['schema']=='a7m4-custom1-display/1' and value['slot']==1 and value['icon_text']==text,
             'Frozen Custom1 display metadata differs from native icon text')
        name=checked_name(value['display_name'])
    raw=looks._read(Path(base)/'manifest.json',1024*1024)
    return dict(schema='a7m4-custom1-display/1',slot=1,display_name=name,icon_text=text,
        manifest_sha256=sha256(raw).hexdigest(),manifest_bytes=len(raw))


def _string(raw,name='M9'):
    """Existing index migration, without interpreting unrelated UTF-8 text."""
    title=checked_name(name).encode('utf-8')
    need(len(raw) >= 16 and raw[:12] == b'uxc\x07\0\0\0\0\x08\0\x05\0'
         and len(raw) % 4 == 0, 'Fixed aligned UXC-v7 string layout required')
    descriptor = struct.unpack_from('<I', raw, 12)[0]; count = descriptor & 8191
    need(count in (3032, 3048) and descriptor == count | (count << 12), 'Fixed string index geometry required')
    base = (16 + 2 * count + 3) & ~3
    need(base < len(raw), 'String index lies outside resource')
    target = bytearray(raw)
    if count == 3048:
        at = 16 + 2 * ((looks._LABELS[0] & 0xffffff) - 0xa000)
        pointer = struct.unpack_from('<H', raw, at)[0]; start = base + 4 * pointer
        need(pointer != 65535 and start + 5 <= len(raw)
             and raw[start:start + 4] == struct.pack('<I', 0x1e00abe2), 'Custom1 label reference differs')
        end = raw.find(b'\0', start + 4)
        need(end >= 0, 'Custom1 label is unterminated')
        if raw[start + 4:end] == title: return raw, []
        pointer = (len(target) - base) // 4
        need(pointer < 65535, 'String pointer space exhausted')
        struct.pack_into('<H', target, at, pointer)
        target.extend(struct.pack('<I', 0x1e00abe2) + title+b'\0')
        target.extend(bytes(-len(target) % 4))
        return bytes(target), [dict(offset=at, before_hex=raw[at:at+2].hex(), after_hex=target[at:at+2].hex())]
    # Adding the existing six reserved labels is a format dependency of the
    # four-slot runtime. Only Custom1 receives M9; the remaining labels are ST.
    new_base = base + 32
    need(new_base <= len(raw), 'String resource lacks bounded index-growth area')
    struct.pack_into('<I', target, 12, 3048 | (3048 << 12)); target[base:new_base] = b'\xff\xff' * 16
    for i in range(count):
        p = struct.unpack_from('<H', raw, 16 + 2*i)[0]
        if p == 65535: continue
        start = base + 4*p
        need(start + 5 <= len(raw) and raw[start:start+4] == struct.pack('<I', 0x1e00a000+i),
             'String index/record dependency differs')
        if start < new_base:
            end = raw.find(b'\0', start+4)
            need(end >= 0, 'Relocated native string is unterminated')
            end = (end+4) & ~3
            target.extend(bytes(-len(target) % 4)); p = (len(target)-new_base)//4
            target.extend(raw[start:end])
        else: p -= 8
        need(0 <= p < 65535, 'Migrated string pointer exceeds16 bits')
        struct.pack_into('<H', target, 16+2*i, p)
    for i, rid in enumerate(looks._LABELS):
        target.extend(bytes(-len(target) % 4)); p = (len(target)-new_base)//4
        need(p < 65535, 'Reserved label pointer exceeds16 bits')
        struct.pack_into('<H', target, 16+2*((rid & 0xffffff)-0xa000), p)
        target.extend(struct.pack('<I', 0x1e000000 | (rid & 0xffffff)) + (title if not i else b'ST') + b'\0')
        target.extend(bytes(-len(target) % 4))
    result = bytes(target)
    return result, [dict(offset=at, before_hex=raw[at:min(at+4096,new_base)].hex(),
                         after_hex=result[at:min(at+4096,new_base)].hex()) for at in range(12,new_base,4096)]


def _anchor(source, target, at, size):
    need(0 <= at < at+size <= len(source) and at+size <= len(target), 'Finite resource D lies outside old EOF')
    return dict(offset=at, before_hex=source[at:at+size].hex(), after_hex=target[at:at+size].hex())


def _dependencies(path, source, target):
    # Header chooses the codec/index geometry. Index and 12-byte record heads
    # select only Custom1's normal/selected/playback records; payload refs are C.
    spans = {(0,16)}
    if Path(path).name.startswith('image_'):
        for raw in (source, target):
            bank = icons._inspect_bank(raw)
            for index in ROUTES.values():
                spans.add((16+2*index,2))
                if index in bank['records']:
                    at = bank['records'][index]['at']
                    if at+12 <= min(len(source),len(target)): spans.add((at,12))
    else:
        # Descriptor migration is itself C; the reserved index is finite D/C.
        if (struct.unpack_from('<I',source,12)[0] & 8191) == 3048:
            spans.add((16+2*(0xabe2-0xa000),2))
    return [_anchor(source,target,at,n) for at,n in sorted(spans)]


def _target_C(path, target,name='M9'):
    rows = []
    def add(at,n): rows.append(dict(offset=at, hex=target[at:at+n].hex()))
    if Path(path).name.startswith('string_'):
        count = struct.unpack_from('<I',target,12)[0] & 8191; base = (16+2*count+3)&~3
        at = 16+2*(0xabe2-0xa000); p = struct.unpack_from('<H',target,at)[0]; start=base+4*p
        expected=struct.pack('<I',0x1e00abe2)+checked_name(name).encode('utf-8')+b'\0'
        need(target[start:start+len(expected)]==expected,'Custom1 display title target differs')
        add(at,2);add(start,len(expected))
    else:
        bank=icons._inspect_bank(target)
        for index in ROUTES.values():
            row=bank['records'][index]
            add(16+2*index,2);add(row['at'],row['field']+8);add(row['start'],row['size'])
    return rows


def _component(path, source, target, windows):
    return dict(source=dict(kind='resource',**identity(source)),target=identity(target),target_path=path,
                windows=[{k:w[k] for k in ('offset','before_hex','after_hex')} for w in windows],
                append=dict(after_hex=target[len(source):].hex()))


def capacity_geometry(entries):
    """Geometry bounds only. Actual allocation is proved by fresh native scans."""
    entries=[forward._allocation(e) for e in entries]
    need(0<len(entries)<=8 and len({e['path'] for e in entries})==len(entries),'Complete distinct remaining resource scope required')
    growth=sum((e['target_size']+1023)//1024-(e['source_size']+1023)//1024 for e in entries)
    dirty=sum(len(e['dirty_blocks']) for e in entries)
    return dict(policy='native-fresh-nonzero-dirty-block-scan/1',unit=1024,reserve_bytes=8388608,
        pending_files=len(entries),existing_dirty_blocks=dirty,growth_blocks=growth,
        lower_required_bytes=8388608+(4*growth+2)*1024,
        upper_required_bytes=8388608+(4*(growth+dirty)+2)*1024,
        historical_witness_values_are_observations=True)


def scoped_file(path, source, target, windows, *, direction='forward', target_C=None, victim=None):
    """Internal fixed-UXC C union projection; no complete historical target."""
    need(path in PATHS and type(source) is bytes and type(target) is bytes
         and 0 < len(source) <= len(target) <= atomic.LIMIT, 'Fixed resource/append geometry required')
    need(direction in ('forward','restore-prefix'), 'Unknown resource phase')
    component=_component(path,source,target,windows); native=None
    need(len(target)-len(source)<=16384,'Resource owned append exceeds the finite native16384B profile')
    if source != target:
        evidence=forward.allocation_evidence(component,source)
        native=forward.from_component(component,source,pending=[evidence])
    return seal(dict(schema=SCHEMA,direction=direction,target_path=path,native_plan=native,
        source=identity(source),forecast=identity(target),D=_dependencies(path,source,target),
        C_owned_windows=[] if native is None else deepcopy(native['windows']),
        C_targets=target_C or [],append=dict(offset=len(source),hex=target[len(source):].hex()),
        capacity=None if native is None else capacity_geometry(native['pending']),
        victim=victim or dict(offset=0,size=0,donor_id=0),E_F_gate_execution=False,
        semantic_whole_target_verified=False,camera_io=False))


def plan_file(path, source, *, assets, owned_playback=False,display_name='M9'):
    need(path in PATHS and type(source) is bytes, 'Known UXC path and complete local bytes required')
    if Path(path).name.startswith('string_'):
        target, windows=_string(source,display_name); victim=None
    else:
        variant='23' if '_23_' in path else '32'
        before=icons._inspect_bank(source)
        target,windows=looks._bank(source,assets,variant,owned_playback=owned_playback)
        victim=None
        if 0x1e9a not in before['records']:
            after=icons._inspect_bank(target);at=after['records'][0x1e9a]['at']
            donor=next(i for i,r in before['records'].items() if r['start']==at)
            victim=dict(offset=at,size=20,donor_id=donor)
    return scoped_file(path,source,target,windows,target_C=_target_C(path,target,display_name),victim=victim)


def plan_forward(resources, *, icon_project, owned_playback=False):
    need(type(resources) is dict and set(resources)==set(PATHS), 'All seventy fresh known UXC inputs required')
    display=project_display(icon_project)
    assets=looks._assets(icon_project,display['icon_text'])
    rows=[plan_file(p,resources[p],assets=assets,owned_playback=owned_playback,display_name=display['display_name']) for p in PATHS]
    need(project_display(icon_project)==display,'Native display manifest changed during planning')
    changed=[r for r in rows if r['native_plan'] is not None]
    for i,row in enumerate(changed):
        row['native_plan']['pending']=[deepcopy(r['native_plan']['pending'][0]) for r in changed[i:]]
        row['native_plan']=seal(row['native_plan']);row['capacity']=capacity_geometry(row['native_plan']['pending']);row.update(seal(row))
    return seal(dict(schema='a7m4-custom1-resources/1',slot=1,name=display['display_name'],icon_text=display['icon_text'],display=display,
        routes=ROUTES,files=rows,E_F_gate_execution=False,camera_io=False,
        device_validation='NOT_PERFORMED',all_sources_inspect_before_any_write=True))


def plan_resources(current_files, profile, config, native_project):
    """Three fixed product configurations; FL23 alone owns no resource C."""
    need(config in (
        dict(id='fl23-only',fl23=True,m9=False,sound=False,slot=1,display_name='M9'),
        dict(id='custom1-m9',fl23=False,m9=True,sound=False,slot=1,display_name='M9'),
        dict(id='full',fl23=True,m9=True,sound=True,slot=1,display_name='M9')),
        'Only the three fixed offline test configurations are supported')
    if not config['m9']:
        return seal(dict(schema='a7m4-custom1-resources/1',slot=1,name='M9',icon_text='M9',routes=ROUTES,
            files=[],E_F_gate_execution=False,camera_io=False,device_validation='NOT_PERFORMED',all_sources_inspect_before_any_write=True))
    # Playback ownership must come from the validated actual-dispatch capsule,
    # never from a broad installed-profile label or a matching full file hash.
    owned=bool(type(profile) is dict and profile.get('owned_Custom1_playback') is True)
    return plan_forward({p:current_files[p] for p in PATHS},icon_project=native_project,owned_playback=owned)


def owned_paths():
    return {REQUEST_PATH:REQUEST_BYTES,REPORT_PATH:REPORT_BYTES}


def validate(plan):
    need(type(plan) is dict and plan.get('schema')==SCHEMA and seal(plan)==plan,'Resource scope integrity differs')
    need(plan['target_path'] in PATHS and plan['direction'] in ('forward','restore-prefix')
         and plan['E_F_gate_execution'] is False and plan['semantic_whole_target_verified'] is False,
         'Fixed Custom1 resource C/D scope required')
    native=plan['native_plan']
    if native is not None:
        forward.validate_plan(native)
        need(native['target_path']==plan['target_path'] and native['source']==plan['source']
             and native['target']==plan['forecast'] and native['windows']==plan['C_owned_windows']
             and native['append_hex']==plan['append']['hex']
             and plan['capacity']==capacity_geometry(native['pending']),
             'Native resource projection differs')
    else:need(plan['capacity'] is None,'No-op cannot claim native capacity proof')
    for row in plan['D']:
        need(set(row)=={'offset','before_hex','after_hex'} and type(row['offset']) is int
             and 0<len(bytes.fromhex(row['before_hex']))==len(bytes.fromhex(row['after_hex']))<=512
             and 0<=row['offset']<=plan['source']['size']-len(bytes.fromhex(row['before_hex'])), 'Finite resource D differs')
    need(len(plan['D'])<=128 and sum(len(bytes.fromhex(r['before_hex'])) for r in plan['D'])<=16384,
         'Resource D bound exceeded')
    return plan


def check(plan, raw, *, target):
    validate(plan); raw=_read(raw); side='after_hex' if target else 'before_hex'
    need(len(raw)==plan['forecast' if target else 'source']['size'], 'Resource C EOF differs')
    for row in plan['C_owned_windows']+plan['D']:
        data=bytes.fromhex(row[side]);at=row['offset']
        need(raw[at:at+len(data)]==data,'Resource C/D endpoint differs')
    victim=plan['victim']
    if victim['size']:
        bank=icons._inspect_bank(raw)
        for index,row in bank['records'].items():
            need(index==victim['donor_id'] or row['start']>=victim['offset']+victim['size']
                 or row['start']+row['size']<=victim['offset'],'Foreign live image payload aliases the metadata victim')
    if target:
        tail=bytes.fromhex(plan['append']['hex']);at=plan['append']['offset']
        need(raw[at:]==tail,'Resource owned append differs')
        for row in plan['C_targets']:
            data=bytes.fromhex(row['hex']);need(raw[row['offset']:row['offset']+len(data)]==data,'M9 resource C target differs')
    return dict(C_D_verified=True,E_F_gate_execution=False,semantic_whole_target_verified=False,observed_file=identity(raw))


class Protocol(forward.ResourceProtocol):
    """Independent v2 raw codec; all retained identity/mapping checks stay strict.

    The first640 bytes retain the reviewed layout; offset600 is explicitly the
    dynamic unknown-block count. The 32-byte suffix proves the complete native
    scan. No report bytes, ticket or global generic validator are rewritten.
    """
    def __init__(self,plan):
        self.scope=deepcopy(validate(plan));need(plan['native_plan'] is not None,'No-op has no native protocol')
        super().__init__(plan['native_plan']);self.plan['plan_id']=plan['plan_id']
    def accept(self,raw):
        need(self.state=='READY' and self.pending is not None,'No pending scoped resource request')
        try:
            mode,nonce=self.pending;p=self.plan
            need(type(raw) is bytes and len(raw)==REPORT_BYTES,'Complete v2 resource report required')
            r=dict(zip(forward.KEYS,forward.PREFIX.unpack_from(raw)))
            need((r['magic'],r['version'],r['mode'],r['nonce'],r['plan_id'],r['total'])==
                 (forward.MAGIC,REPORT_VERSION,mode,nonce,bytes.fromhex(p['plan_id']),REPORT_BYTES),
                 'Scoped resource plan/nonce/version/report differs')
            need(r['mapping_count']<=4 and r['window_count']==len(p['windows']) and r['target_size']==p['target']['size'],
                 'Scoped native resource scope differs')
            need(not r['flags']&~1023,'Unknown resource proof flags')
            r.update(zip(_BUDGET_KEYS,struct.unpack_from('<8Q',raw,544)))
            r.update(zip(_SCAN_KEYS,struct.unpack_from('<4Q',raw,640)))
            capacity=self._capacity_proof(r,mode)
            # Same zero-mutation/RO/own-loader refusal boundary as the retained
            # parser, with an explicitly validated v2 capacity suffix. This
            # grants exact packet cleanup, never mapping/source admission.
            if (mode==0 and self.previous is None and r['native_status']<0 and r['phase'] in (1,2)
                    and r['pid']>1 and not any(r[k] for k in ('euid','close_errors','readonly','remount','plugin_unlink',
                        'cow_attempts','cow_segments','bytes_cow_preserved','write_attempts','writes_completed','bytes_written',
                        'append_bytes','append_attempts','append_completed')) and not r['flags']&(4|16|256)):
                if capacity['complete'] and not capacity['sufficient']:
                    need(r['native_status']==-28 and r['phase']==2 and r['source_status']==0 and r['flags']==0
                         and not r['mapping_count'] and not r['cross_pids'] and not r['cross_matches'],
                         'Insufficient native budget is not a complete zero-mutation capacity refusal')
                raise forward.ForwardReadOnlyRefusal(dict(pid=r['pid'],phase=r['phase'],status=r['native_status'],
                    source_status=r['source_status'],flags=r['flags'],mode=0,cleanup_safe=True,
                    mapping_state_unknown=False,complete=False,capacity_proof=capacity,
                    **{k:r[k] for k in _BUDGET_KEYS+_SCAN_KEYS}))
            rows=[forward.MAPPING.unpack_from(raw,256+i*32) for i in range(4)]
            need(all(not any(row) for row in rows[r['mapping_count']:]),'Unused native mapping slot differs')
            rows=rows[:r['mapping_count']]
            for i,m in enumerate(rows):
                va,length,offset,prot=m
                need(va>0 and length>0 and not (va|length|offset)&4095 and va+length<1<<64
                     and offset+length<1<<64 and prot==1 and (not i or va>=rows[i-1][0]+rows[i-1][1]),
                     'Only ordered private readonly source mappings admitted')
            segments=total=0
            for _,length,offset,_ in rows:
                for w in p['protection']:
                    n=min(offset+length,w['offset']+w['size'])-max(offset,w['offset'])
                    if n>0:segments+=1;total+=n
            expected_segments,expected_bytes,offender,reserved=struct.unpack_from('<4Q',raw,384)
            need((expected_segments,expected_bytes)==(segments,total) and total<=65536 and not offender and not reserved,
                 'Scoped protected-page proof differs')
            r['mappings']=rows;r['runtime_sha256']=raw[608:640].hex();r['capacity_proof']=capacity
            need(all(r[k]==0 for k in ('native_status','euid','plugin_unlink','close_errors','readonly','remount',
                'auxv_status','source_status','cross_matches')),'Scoped resource native outcome incomplete: STOP_UNKNOWN')
            need(r['pid']>1 and r['source_ino']>0 and r['source_nlink']==1
                 and r['source_mode']&0o170000==0o100000 and r['page_size']==4096
                 and r['source_size']==p['target' if mode==3 else 'source']['size'],'Scoped source identity differs')
            stat=struct.unpack_from('<QQIIII',raw,416)
            need(stat==(r['source_dev'],r['source_ino'],r['source_mode'],r['source_nlink'],r['source_uid'],r['source_gid'])
                 and struct.unpack_from('<q',raw,464)[0]==r['source_size'],'Scoped raw stat differs')
            if mode!=3:need(capacity['complete'] and capacity['sufficient'],'Fresh complete native allocation proof required')
            if mode==1:
                append=len(bytes.fromhex(p['append_hex']));count=len(p['windows'])+bool(append)
                need(r['phase']==9 and r['flags']==(763 if segments else 761)
                     and r['cow_attempts']==r['cow_segments']==segments and r['bytes_cow_preserved']==total
                     and r['write_attempts']==r['writes_completed']==count
                     and r['bytes_written']==sum(len(bytes.fromhex(w['before_hex'])) for w in p['windows'])+append
                     and r['append_bytes']==append and r['append_attempts']==r['append_completed']==bool(append),
                     'Scoped append/window/runtime preservation proof incomplete')
            else:
                need(r['phase']==3 and r['flags']==193 and not any(r[k] for k in
                    ('cow_attempts','cow_segments','bytes_cow_preserved','write_attempts','writes_completed','bytes_written',
                     'append_bytes','append_attempts','append_completed')),'Readonly scoped inspection proof differs')
            if self.inspection is not None:
                first=self.inspection
                need(all(r[k]==first[k] for k in ('pid','source_dev','source_ino','source_mode','source_uid','source_gid',
                     'source_nlink','runtime_sha256')) and rows==first['mappings'],'Scoped cross-phase identity/runtime changed')
            else:self.inspection=deepcopy(r)
            self.previous=mode;self.pending=None
            return {k:(v.decode() if k=='magic' else v.hex()) if isinstance(v,bytes) else v for k,v in r.items()}
        except forward.ForwardReadOnlyRefusal:
            self.state='REFUSED_READ_ONLY';self.pending=None;raise
        except BaseException:
            self.unknown();raise
    def _capacity_proof(self,r,mode):
        geometry=self.scope['capacity']
        need(r['capacity_reserved']==0 and r['capacity_scan_complete'] in (0,1),'Unknown capacity extension fields')
        if mode==3:
            need(not any(r[k] for k in _BUDGET_KEYS+_SCAN_KEYS),'Target inspection must not claim a capacity scan')
            return dict(complete=False,sufficient=False,performed=False)
        if not r['capacity_scan_complete']:
            need(not any(r[k] for k in ('usr_required','unknown_dirty_blocks','scanned_dirty_blocks','scanned_pending_files')),
                 'Incomplete native scan cannot claim allocation evidence')
            need((r['usr_type'],r['usr_unit'],r['usr_available'])==(0,0,0)
                 or (r['usr_type']==0xef53 and r['usr_unit']==1024),'Incomplete scan filesystem observation differs')
            return dict(complete=False,sufficient=False,performed=False)
        need(r['scanned_pending_files']==geometry['pending_files']
             and r['scanned_dirty_blocks']==geometry['existing_dirty_blocks']
             and r['unknown_dirty_blocks']<=r['scanned_dirty_blocks'],'Incomplete/out-of-scope native allocation scan')
        required=8388608+(4*(geometry['growth_blocks']+r['unknown_dirty_blocks'])+2)*1024
        need(r['usr_type']==0xef53 and r['usr_unit']==1024 and r['usr_required']==required
             and r['usr_available']%1024==0
             and geometry['lower_required_bytes']<=required<=geometry['upper_required_bytes'],
             'Dynamic native capacity formula differs')
        return dict(complete=True,sufficient=r['usr_available']>=required,performed=True,
            unknown_dirty_blocks=r['unknown_dirty_blocks'],scanned_dirty_blocks=r['scanned_dirty_blocks'],
            scanned_pending_files=r['scanned_pending_files'],required_bytes=required,reserve_bytes=8388608)
    def confirm_readback(self,path):
        try:
            need(self.state=='READY' and self.pending is None and self.previous in (0,3),'Inspect before resource C/D readback')
            proof=check(self.scope,path,target=self.previous==3);self.barrier='target' if self.previous==3 else 'source'
            return dict(proof,endpoint=self.barrier,plan_id=self.scope['plan_id'])
        except BaseException:
            self.unknown();raise


def _dependency_header(plan):
    arr=lambda b:'{'+','.join(map(str,b))+'}'
    lines=['struct ScopeDependency{u64 at;u32 size;const u8*before,*after;};']
    for i,row in enumerate(plan['D']):
        for side in ('before','after'):
            lines.append('static const u8 d_%s_%d[]=%s;'%(side,i,arr(bytes.fromhex(row[side+'_hex']))))
    lines.append('static const struct ScopeDependency scope_d[]={'+(','.join(
        '{%dUL,%d,d_before_%d,d_after_%d}'%(r['offset'],len(bytes.fromhex(r['before_hex'])),i,i)
        for i,r in enumerate(plan['D'])) or '{0,0,0,0}')+'};')
    lines.append('static const u32 scope_d_count=%d;'%len(plan['D']))
    v=plan['victim'];lines.append('static const u64 scope_victim=%dUL,scope_victim_size=%dUL;'%(v['offset'],v['size']))
    lines.append('static const u32 scope_donor_id=%d;'%v['donor_id'])
    return ('\n'.join(lines)+'\n').encode()


def render_header(plan):
    validate(plan);need(plan['native_plan'] is not None,'No-op does not build')
    raw=forward.render_header(plan['native_plan']).decode()
    # The frozen renderer supplies only the unchanged window/protection data.
    # Its historical witness values and static unknown charges are not emitted.
    raw=raw.split('struct Witness{',1)[0]
    raw='\n'.join(l for l in raw.splitlines() if not l.startswith(('static const u8 source_hash','static const u8 target_hash')))+'\n'
    arr=lambda h:'{'+','.join(map(str,bytes.fromhex(h)))+'}'
    raw=raw.replace('rd_plan_id[32]='+arr(plan['native_plan']['plan_id']), 'rd_plan_id[32]='+arr(plan['plan_id']))
    blocks=[];files=[]
    for entry in plan['native_plan']['pending']:
        begin=len(blocks);blocks.extend(entry['dirty_blocks'])
        files.append('{%s,%dUL,%dUL,%d,%d}'%(json.dumps(entry['path']),entry['source_size'],entry['target_size'],begin,len(entry['dirty_blocks'])))
    raw+='struct BudgetFile{const char*path;u64 source_size,target_size;u32 dirty_begin,dirty_count;};\n'
    raw+='static const u32 dirty_blocks[]={'+(','.join(map(str,blocks)) or '0')+'};\n'
    raw+='static const u32 dirty_block_count=%d;\n'%len(blocks)
    raw+='static const struct BudgetFile pending_files[]={'+','.join(files)+'};\n'
    raw+='static const u32 pending_count=%d;\n'%len(files)
    return raw.encode()+_dependency_header(plan)


def _build(source_name, pin, header, output, *, compiler):
    out=Path(output).absolute()
    need(not out.exists() and out.parent.is_dir() and not any(p.is_symlink() for p in (out,*out.parents)), 'New private build directory required')
    source=Path(__file__).with_name('data')/('looks-resource-'+source_name+'.c')
    native=Path(__file__).resolve().parents[2]/'native/looks-resource-scope'/(source_name+'.c')
    paths=[p for p in (source,native) if p.exists()]
    need(paths and all(sha256(p.read_bytes()).hexdigest()==pin for p in paths),'Scoped resource source pin differs')
    out.mkdir(mode=0o700);_save(out/'scope-plan.h',header)
    sha_header=atomic.SHA_SOURCE.read_bytes();need(sha256(sha_header).hexdigest()==atomic.SHA_SOURCE_SHA256,'SHA source pin differs')
    _save(out/'resource-sha256.h',sha_header)
    command=[os.fspath(compiler)];env=dict(os.environ,ZIG_GLOBAL_CACHE_DIR=str(out/'zig-global'),ZIG_LOCAL_CACHE_DIR=str(out/'zig-local'))
    need(subprocess.run(command+['version'],capture_output=True,text=True,check=True,env=env,timeout=30).stdout.strip()=='0.13.0','Offline Zig0.13.0 required')
    args=command+['cc','-target','aarch64-linux-gnu','-std=c11','-ffreestanding','-fno-builtin','-DPATCH_MANIFEST="scope-plan.h"','-I',str(out)]
    subprocess.run(args+['-DTARGET_ABI','-c',str(paths[0]),'-o',str(out/'abi.o')],capture_output=True,check=True,env=env,timeout=180)
    flags=['-O2','-Wall','-Wextra','-Werror','-shared','-fPIC','-fno-stack-protector','-fno-unwind-tables','-fno-asynchronous-unwind-tables',
        '-nostdlib','-g0','-Wl,--strip-debug','-Wl,--no-undefined','-Wl,--build-id=none','-Wl,-Bsymbolic','-Wl,-z,noexecstack']
    raws=[]
    for name in ('scope.so','scope-repeat.so'):
        p=out/name;subprocess.run(args+flags+[str(paths[0]),'-o',str(p)],capture_output=True,check=True,env=env,timeout=180)
        p.chmod(0o600);raw=p.read_bytes();need(0<len(raw)<65536,'Every native upload must remain below64KiB');_elf(raw);raws.append(raw)
    need(raws[0]==raws[1] and all(sha256(p.read_bytes()).hexdigest()==pin for p in paths)
         and (out/'scope-plan.h').read_bytes()==header,'Resource ABI/double-build/source binding differs')
    result=dict(worker=dict(path=str(out/'scope.so'),**identity(raws[0])),native_source_sha256=pin,
        double_build_identical=True,target_ABI_checked=True,E_F_gate_execution=False,camera_io=False,device_validation='NOT_PERFORMED')
    if source_name=='forward':result['wire']=dict(request_bytes=REQUEST_BYTES,report_bytes=REPORT_BYTES,report_version=REPORT_VERSION)
    _save(out/'build.private.json',canonical(result)+b'\n');return result


def build(plan,output,*,compiler):
    return _build('forward',NATIVE_SHA,render_header(plan),output,compiler=compiler)


def validate_capsule(value,body=None):
    need(type(value) is dict and value.get('schema')==CAPSULE_SCHEMA and seal(value,'capsule_sha256')==value,'Resource original-C capsule differs')
    need(body is None or value['body_binding']==body,'Resource originals belong to another body')
    need(value['E_F_restore_promised'] is False and set(value['originals'])<=set(PATHS),'Resource capsule scope differs')
    for path,row in value['originals'].items():
        need(0<row['eof']<=atomic.LIMIT and type(row['windows']) is list,'Original resource EOF/C differs')
        end=0
        for w in row['windows']:
            data=bytes.fromhex(w['hex']);need(type(w['offset']) is int and end<=w['offset']<w['offset']+len(data)<=row['eof'],'Disjoint original resource C required')
            end=w['offset']+len(data)
        end=row['eof']
        for a in row['appends']:
            data=bytes.fromhex(a['hex']);need(a['offset']==end and 0<len(data)<=16384,'Contiguous actual-dispatch append ownership required');end+=len(data)
        need(end<=atomic.LIMIT,'Owned resource append exceeds file bound')
    return deepcopy(value)


class ResourceCapsule:
    def __init__(self,root,body,*,parent=None,on_change=None):
        self.on_change=on_change
        self.path=Path(root)/'looks-resource-C.private.json'
        self.value=validate_capsule(parent,body) if parent is not None else dict(schema=CAPSULE_SCHEMA,
            body_binding=deepcopy(body),originals={},events=[],E_F_restore_promised=False,cache_restore='NORMAL_REBUILD')
        self.persist()
    def persist(self):
        self.value=seal(self.value,'capsule_sha256');validate_capsule(self.value);_private_json(self.path,self.value)
        if self.on_change is not None:self.on_change(deepcopy(self.value))
    def dispatch(self,plan,request):
        validate(plan);native=plan['native_plan']
        need(plan['direction']=='forward' and native is not None and type(request) is bytes and len(request)==REQUEST_BYTES
             and request[:8]==forward.MAGIC and any(request[16:32])
             and struct.unpack_from('<I',request,8)[0]==1 and request[32:64].hex()==plan['plan_id'],'Actual resource mode1 dispatch required')
        need(not any(e['ticket']==plan['plan_id'] for e in self.value['events']),'No resource native ticket replay')
        path=plan['target_path'];row=self.value['originals'].setdefault(path,dict(eof=plan['source']['size'],windows=[],appends=[]))
        original={w['offset']+i:b for w in row['windows'] for i,b in enumerate(bytes.fromhex(w['hex']))}
        for w in plan['C_owned_windows']:
            for i,b in enumerate(bytes.fromhex(w['before_hex'])):
                if w['offset']+i<row['eof']: original.setdefault(w['offset']+i,b)
        merged=[]
        for at in sorted(original):
            if merged and merged[-1][0]+len(merged[-1][1])==at:merged[-1][1].append(original[at])
            else:merged.append((at,bytearray([original[at]])))
        row['windows']=[dict(offset=at,hex=bytes(raw).hex()) for at,raw in merged]
        append=plan['append']
        if append['hex']:
            end=row['eof']+sum(len(bytes.fromhex(a['hex'])) for a in row['appends'])
            need(append['offset']==end,'Foreign/unrecorded resource EOF cannot become owned')
            row['appends'].append(deepcopy(append))
        self.value['events'].append(dict(ticket=plan['plan_id'],path=path,request_sha256=sha256(request).hexdigest(),outcome='ATTEMPTED_UNKNOWN'))
        self.persist()
    def confirmed(self,plan,raw):
        proof=check(plan,raw,target=True)
        event=next(e for e in self.value['events'] if e['ticket']==plan['plan_id']);event['outcome']='C_D_READBACK_VERIFIED'
        self.persist();return proof
