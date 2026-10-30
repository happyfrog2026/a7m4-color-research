"""Finite FL23/Custom1-ST settings C and actual-dispatch originals.

Pure plans and local private journals only. No discovery, session, device or
WBI execution. E/F values are observations before and after every operation;
only selected C, explicit D and valid complete BK4 structure control admission.
"""
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import re
import struct
import uuid

from . import settings_plan as sp
from .capture_inputs import read_private
from .native_actions import _json, _write
from .usb_read import _atomic_json, LOADER_SHA256

POLICY='native-scoped-looks-observe/1'
SCHEMA='a7m4-looks-settings-cumulative-C/1'
KINDS=('scoped-looks','scoped-looks-restore','scoped-restore-st')
PLANES=('ram','saved','bin','bak')
CUSTOM1=((0,0x02CF0D0B),(0,0x02CF12E9),(0,0x02CF1309))
SPEC={p:(8 if i<2 else 0x60,n,s) for i,(p,n,s) in enumerate(zip(sp.SELECTED,sp.SIZES,sp.SPANS))}
SPEC.update({p:(0x60,1,((0,1),)) for p in CUSTOM1})
D=(sp.AP55,sp.CP55,sp.BOOT_DEVICE)
MAX_EVENTS=128


def active(plan):return type(plan) is sp.Plan and plan.kind in KINDS


def selected(*,fl23,m9):
    sp.need(type(fl23) is bool and type(m9) is bool and (fl23 or m9),'Select FL23 and/or Custom1 M9')
    return (sp.SELECTED if fl23 else ())+ (CUSTOM1 if m9 else ())


def equal(left,right,spans):return all(left[a:b]==right[a:b] for a,b in spans)


def merge(current,target,spans):return sp._merge(current,tuple((a,b,target[a:b]) for a,b in spans))


def _binding(snapshot,identity,boot_id,nonce):
    sp.validate_snapshot(snapshot)
    sp.need(sp.body_identity(snapshot.serial)==identity,'Looks settings body differs')
    sp.need(type(boot_id) is str and re.fullmatch(r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}',boot_id), 'Fresh looks boot UUID required')
    sp.need(type(nonce) is str and re.fullmatch('[0-9a-f]{32}',nonce) and int(nonce,16),'Fresh nonzero looks nonce required')


def dependencies(snapshot,*,forward):
    sp.validate_snapshot(snapshot)
    for plane in PLANES:
        values=getattr(snapshot,plane).records
        sp.need(values.get(sp.CP55)==sp.Value(0,b'\0') and values.get(sp.BOOT_DEVICE)==sp.Value(0,b'\1'),
                'Looks required CP55/BOOT dependency differs')
        sp.need(values.get(sp.AP55) in (sp.Value(0,b'\2'),) if forward else
                values.get(sp.AP55) in (sp.Value(0,b'\0'),sp.Value(0,b'\2')),'Looks AP55 loader prerequisite differs')


def _shape(snapshot,pair):
    if pair not in SPEC:
        from .restore_st_settings import shape
        return shape(snapshot,pair)
    attrs,size,_=SPEC[pair]
    for plane in PLANES:
        value=getattr(snapshot,plane).records.get(pair)
        sp.need(value is not None and value.attrs==attrs and len(value.data)==size,'Looks selected C record shape differs')


def _targets(fl23,m9):
    rows={}
    if fl23:
        rows.update(zip(sp.SELECTED[:2],sp._payload()))
        rows.update({p:((0,1,bytes((10 if i%2==0 else 11,))),) for i,p in enumerate(sp.SELECTED[2:])})
    if m9:rows.update({p:((0,1,b'\0'),) for p in CUSTOM1})
    return rows


def plan_forward(fresh,*,fl23,m9,identity,boot_id,nonce):
    _binding(fresh,identity,boot_id,nonce);dependencies(fresh,forward=True)
    pairs=selected(fl23=fl23,m9=m9);targets=_targets(fl23,m9);rows=[]
    for pair in pairs:
        _shape(fresh,pair);ram=fresh.ram.records[pair].data;saved=fresh.saved.records[pair].data
        rows.append(sp.Record(*pair,SPEC[pair][2],ram,saved,sp._merge(ram,targets[pair]),sp._merge(saved,targets[pair])))
    plan=sp.Plan('scoped-looks',identity,boot_id,nonce,fresh,tuple(rows),tuple(sorted({p[1]>>16 for p in pairs})),
        save_effects_policy=POLICY,looks_selection=(fl23,m9))
    return validate_plan(plan)


def _original_tuple(rows):
    return tuple((r['chip'],int(r['key'],16),r['attrs'],r['size'],
        tuple((w['start'],w['end'],w['ram_hex'],w['saved_hex']) for w in r['spans'])) for r in rows)


def plan_restore(fresh,capsule,*,identity,boot_id,nonce):
    _binding(fresh,identity,boot_id,nonce);dependencies(fresh,forward=False)
    value=load(capsule) if isinstance(capsule,(str,Path)) else validate(capsule)
    sp.need(value['identity']==identity,'Looks settings originals belong to another body')
    originals=tuple(value['originals'][k] for k in sorted(value['originals']));rows=[]
    for original in originals:
        pair=original['chip'],int(original['key'],16);_shape(fresh,pair)
        ram=fresh.ram.records[pair].data;saved=fresh.saved.records[pair].data
        rows.append(sp.Record(*pair,SPEC[pair][2],ram,saved,
            sp._merge(ram,tuple((w['start'],w['end'],bytes.fromhex(w['ram_hex'])) for w in original['spans'])),
            sp._merge(saved,tuple((w['start'],w['end'],bytes.fromhex(w['saved_hex'])) for w in original['spans']))))
    return validate_plan(sp.Plan('scoped-looks-restore',identity,boot_id,nonce,fresh,tuple(rows),
        tuple(sorted({r.key>>16 for r in rows})),save_effects_policy=POLICY,looks_original=_original_tuple(originals)))


def validate_plan(plan):
    if type(plan) is sp.Plan and plan.kind=='scoped-restore-st':
        from .restore_st_settings import validate_plan as validate_st
        return validate_st(plan)
    sp.need(active(plan) and plan.save_effects_policy==POLICY,'Finite scoped looks plan required')
    _binding(plan.baseline,plan.identity,plan.boot_id,plan.nonce);dependencies(plan.baseline,forward=plan.kind==KINDS[0])
    sp.need(plan.origin is plan.original is plan.inverse_of is plan.gate_original is None,'Scoped looks cannot carry legacy restore intent')
    sp.need(plan.metadata_profile==sp.METADATA_PROFILE,'Scoped looks metadata profile differs')
    if plan.kind==KINDS[0]:
        sp.need(type(plan.looks_selection) is tuple and len(plan.looks_selection)==2 and plan.looks_original is None,'Finite looks selection required')
        pairs=selected(fl23=plan.looks_selection[0],m9=plan.looks_selection[1]);targets=_targets(*plan.looks_selection)
    else:
        sp.need(plan.looks_selection is None and type(plan.looks_original) is tuple,'Only actual-dispatch original C may be restored')
        pairs=tuple((r[0],r[1]) for r in plan.looks_original);targets={}
        sp.need(len(pairs)==len(set(pairs)) and len(pairs)<=11,'Bounded distinct looks originals required')
        for row in plan.looks_original:
            _validate_original(dict(chip=row[0],key=f'{row[1]:08x}',attrs=row[2],size=row[3],
                spans=[dict(start=a,end=b,ram_hex=r,saved_hex=s) for a,b,r,s in row[4]]))
            targets[row[0],row[1]]=row[4]
    sp.need(tuple((r.chip,r.key) for r in plan.records)==pairs and plan.groups==tuple(sorted({p[1]>>16 for p in pairs})), 'Scoped looks selected records/groups differ')
    for r in plan.records:
        pair=r.chip,r.key;_shape(plan.baseline,pair)
        sp.need(type(r) is sp.Record and r.spans==SPEC[pair][2] and r.before_ram==plan.baseline.ram.records[pair].data
            and r.before_saved==plan.baseline.saved.records[pair].data,'Scoped looks preimage/ranges differ')
        for plane in ('ram','saved'):
            before=getattr(r,'before_'+plane);after=getattr(r,'after_'+plane)
            patches=targets[pair] if plan.kind==KINDS[0] else tuple((a,b,bytes.fromhex(ram if plane=='ram' else saved)) for a,b,ram,saved in targets[pair])
            sp.need(type(after) is bytes and after==sp._merge(before,patches),'Scoped looks changes outside C or substitutes target')
    return plan


def needs_save(plan,group):
    return any(r.key>>16==group and (not equal(r.before_saved,r.after_saved,r.spans) or any(
        not equal(getattr(plan.baseline,p).records[r.chip,r.key].data,r.after_saved,r.spans) for p in ('bin','bak')))
        for r in plan.records)


def check(plan,current,expected):
    sp.validate_snapshot(current)
    sp.need(current.serial==plan.baseline.serial and sp.body_identity(current.serial)==plan.identity,'Looks current identity differs')
    dependencies(current,forward=plan.kind==KINDS[0])
    for plane in PLANES:
        actual=getattr(current,plane).records
        for pair in D:sp.need(actual.get(pair)==expected[plane].get(pair),'Looks required D changed')
        for r in plan.records:
            pair=r.chip,r.key;_shape(current,pair)
            sp.need(equal(actual[pair].data,expected[plane][pair].data,r.spans),'Looks selected C changed: '+plane+'/'+str(pair))


def check_current(plan,current):
    """Initial C/D admission for a coordinator before any persistent phase."""
    validate_plan(plan)
    check(plan,current,{p:dict(getattr(plan.baseline,p).records) for p in PLANES})


def observe(plan,current,expected,*,saved_groups=()):
    differences=[];records={(r.chip,r.key):r for r in plan.records}
    identify=lambda v:None if v is None else dict(attrs=v.attrs,size=len(v.data),sha256=sp.sha(v.data))
    for plane in PLANES:
        actual=getattr(current,plane).records
        for pair in sorted(set(actual)|set(expected[plane])):
            if pair in D:continue
            old,new=expected[plane].get(pair),actual.get(pair)
            if pair in records and old is not None and new is not None:
                r=records[pair];old=sp.Value(old.attrs,merge(old.data,new.data,r.spans))
            if old!=new:
                differences.append(dict(plane=plane,chip=pair[0],key=f'{pair[1]:08x}',category='E' if pair[1]>>16 in saved_groups else 'F',
                    expected=identify(old),actual=identify(new)))
        updated=dict(actual)
        for pair in D:updated[pair]=expected[plane][pair]
        for pair,r in records.items():
            value=updated[pair];updated[pair]=sp.Value(value.attrs,merge(value.data,expected[plane][pair].data,r.spans))
        expected[plane]=updated
    return differences


def _seal(value):
    value=deepcopy(value);value.pop('capsule_sha256',None);value['capsule_sha256']=sha256(_json(value)).hexdigest();return value


def _validate_original(row):
    sp.need(type(row) is dict and set(row)=={'chip','key','attrs','size','spans'},'Exact looks original C metadata required')
    sp.need(type(row['chip']) is int and type(row['key']) is str and type(row['attrs']) is int and type(row['size']) is int,
            'Typed original looks C metadata required')
    pair=row['chip'],int(row['key'],16);sp.need(pair in SPEC and row['key']==f'{pair[1]:08x}','Original outside fixed looks C')
    attrs,size,spans=SPEC[pair]
    sp.need(row['attrs']==attrs and row['size']==size and type(row['spans']) is list and len(row['spans'])==len(spans),'Original looks C shape differs')
    for w,(a,b) in zip(row['spans'],spans):
        sp.need(set(w)=={'start','end','ram_hex','saved_hex'} and (w['start'],w['end'])==(a,b),'Original looks C bounds differ')
        for plane in ('ram','saved'):
            raw=bytes.fromhex(w[plane+'_hex']);sp.need(len(raw)==b-a and raw.hex()==w[plane+'_hex'],'Canonical exact C original bytes required')
    return row


def validate(value,body=None):
    sp.need(type(value) is dict and value.get('schema')==SCHEMA and _seal(value)==value,'Looks settings C capsule integrity differs')
    sp.need(value['firmware']=='6.02' and value['loader_sha256']==LOADER_SHA256 and value['policy']==POLICY
        and value['E_F_restore_promised'] is False and value['cache_restore']=='NORMAL_REBUILD','Looks settings C scope differs')
    sp.need(body is None or value['body_binding']==body,'Looks settings C body differs')
    sp.need(value['identity']==value['body_binding']['serial_sha256'],'Looks settings C serial binding differs')
    sp.need(type(value['events']) is list and len(value['events'])<=MAX_EVENTS,'Bounded looks C dispatch history required')
    originals={};ids=set()
    for e in value['events']:
        sp.need(e['event_id'] not in ids and re.fullmatch('[0-9a-f]{32}',e['event_id']) and e['outcome'] in ('ATTEMPTED_UNKNOWN','C_READBACK_VERIFIED'),'Looks C event identity/outcome differs');ids.add(e['event_id'])
        sp.need(e['command'] in (2,0x41,3) and re.fullmatch('[0-9a-f]{64}',e['request_sha256'])
            and re.fullmatch('[0-9a-f]{64}',e['plan_id']) and 1<=len(e['originals'])<=11,'Actual finite settings dispatch required')
        for r in e['originals']:
            _validate_original(r);pair=r['chip'],int(r['key'],16)
            sp.need((e['command']==3 and e.get('group') in (0x02A4,0x02CF) and pair[1]>>16==e['group'])
                or (e['command']==(0x41 if pair[0] else 2) and len(e['originals'])==1 and e.get('key')==pair[1]), 'C original does not belong to actual dispatch')
            originals.setdefault(f'{pair[0]}/{pair[1]:08x}',r)
    sp.need(value['originals']==originals,'Looks C union differs from earliest actual dispatch')
    return deepcopy(value)


def load(path,body=None):return validate(json.loads(read_private(Path(path),2*1024*1024)),body)


class Capsule:
    """Attach dispatch(plan, observation) before wire WRITE/SAVE; no no-op C."""
    def __init__(self,root,body,*,parent=None,result=None,restoring=False,on_change=None):
        sp.need(on_change is None or callable(on_change),'Optional master C commit callback required')
        self.root=Path(root);self.path=self.root/'looks-settings-C-capsule.private.json';self.result=result;self.restoring=restoring;self.on_change=on_change
        self.value=validate(parent,body) if parent is not None else _seal(dict(schema=SCHEMA,firmware='6.02',loader_sha256=LOADER_SHA256,
            policy=POLICY,body_binding=body,identity=body['serial_sha256'],E_F_restore_promised=False,cache_restore='NORMAL_REBUILD',originals={},events=[]))
        self.pending=[];self.persist()
    def persist(self):
        self.value=_seal(self.value);validate(self.value);_atomic_json(self.path,self.value)
        raw=read_private(self.path,2*1024*1024)
        if self.result is not None:self.result['looks_settings_C_capsule_ref']=dict(path=self.path.name,size=len(raw),sha256=sp.sha(raw))
        if self.on_change is not None:
            committed=self.on_change(deepcopy(self.value))
            sp.need(committed is None or type(committed) is int and committed==0,'Master C journal did not confirm durable commit')
    def dispatch(self,plan,observation):
        validate_plan(plan)
        if self.restoring:return
        sp.need(plan.kind==KINDS[0] and plan.identity==self.value['identity'],'Only own forward settings register C')
        command=observation.get('command');request=observation.get('request');group=observation.get('group')
        if command==3:rows=[r for r in plan.records if r.key>>16==group and needs_save(plan,group)]
        elif command in (2,0x41):rows=[r for r in plan.records if r.key==observation.get('key') and r.chip==int(command==0x41)]
        else:sp.need(False,'Only actual scoped settings mutations register C')
        sp.need(type(request) is bytes and len(request)>16 and struct.unpack_from('<HH',request,12)==(0x603,command),'Actual scoped mutation wire required')
        length,function,_,a,b,c,status=struct.unpack_from('<IHHBBBB',request)
        sp.need(len(request)<65536 and length==len(request)-12 and function==0x40 and (a,b,c,status)==(0,0,0,0),
                'Exact bounded settings dispatch frame required')
        if command==3:
            sp.need(request[16:]==struct.pack('<H',group),'Exact native SAVE dispatch required')
        else:
            r=rows[0] if len(rows)==1 else None;sp.need(r is not None,'WRITE outside selected C')
            offset=24 if r.chip else 20;payload=request[offset:]
            sp.need(struct.unpack_from('<I',request,16)[0]==r.key and len(payload)==SPEC[r.chip,r.key][1]
                and (not r.chip or struct.unpack_from('<I',request,20)[0]==1)
                and any(equal(payload,v,r.spans) for v in (r.after_ram,r.after_saved)),'Mutation C target or CP selector differs')
        originals=[]
        for r in rows:
            pair=r.chip,r.key
            changed=not equal(r.before_ram,r.after_ram,r.spans) or not equal(r.before_saved,r.after_saved,r.spans) or any(
                not equal(getattr(plan.baseline,p).records[pair].data,r.after_saved,r.spans) for p in ('bin','bak'))
            if changed:
                originals.append(dict(chip=r.chip,key=f'{r.key:08x}',attrs=SPEC[pair][0],size=SPEC[pair][1],spans=[dict(start=a,end=b,
                    ram_hex=r.before_ram[a:b].hex(),saved_hex=r.before_saved[a:b].hex()) for a,b in r.spans]))
        if not originals:return
        sp.need(len(self.value['events'])<MAX_EVENTS,'Looks C history exhausted before dispatch')
        event=dict(event_id=uuid.uuid4().hex,command=command,group=group,key=observation.get('key'),originals=originals,
            request_sha256=sp.sha(request),plan_id=plan.plan_id,outcome='ATTEMPTED_UNKNOWN')
        _write(self.root/('settings-C-dispatch-'+event['event_id']+'.json'),_json(event))
        self.value['events'].append(event)
        for r in originals:self.value['originals'].setdefault(f"{r['chip']}/{r['key']}",r)
        self.pending.append(event['event_id']);self.persist()
    def confirmed(self,plan,snapshot):
        validate_plan(plan)
        expected={p:dict(getattr(plan.baseline,p).records) for p in PLANES}
        for r in plan.records:
            pair=r.chip,r.key
            for p in PLANES:
                old=expected[p][pair];target=r.after_ram if p=='ram' else r.after_saved
                expected[p][pair]=sp.Value(old.attrs,merge(old.data,target,r.spans))
        check(plan,snapshot,expected)
        if self.restoring:return
        for e in self.value['events']:
            if e['event_id'] in self.pending and e['plan_id']==plan.plan_id:e['outcome']='C_READBACK_VERIFIED'
        self.persist()
