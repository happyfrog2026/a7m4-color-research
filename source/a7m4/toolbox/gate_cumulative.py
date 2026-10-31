"""Gate-only cumulative C capsule and exact restore planning. No device I/O.

Capsules contain only actual dispatch C preimages and supporting metadata.
They make no promise to restore E/F, native generations or old WBI images.
A supplied capsule is an explicit history chain, not automatic global history.
"""
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import uuid

from . import gate_scope as gs, program_worker, settings_plan as sp, save_effects
from .capture_inputs import read_private
from .native_actions import _json, _write
from .usb_read import _atomic_json, LOADER_SHA256

SCHEMA='a7m4-gate-cumulative-C/1'
RESTORE_POLICY='gate-cumulative-C-restore/1'
MAX_EVENTS=512


def need(value,message):
    if not value:raise ValueError(message)


def _digest(value):return sha256(_json(value)).hexdigest()


def _sealed(value):
    value=deepcopy(value);value.pop('capsule_sha256',None)
    return dict(value,capsule_sha256=_digest(value))


def validate(value,body=None):
    need(type(value) is dict and value.get('schema')==SCHEMA,'Gate C capsule schema required')
    plain=dict(value);digest=plain.pop('capsule_sha256',None)
    need(digest==_digest(plain),'Gate C capsule integrity differs')
    need(value.get('firmware')=='6.02' and value.get('loader_sha256')==LOADER_SHA256
         and value.get('profile')==gs.PROFILE and value.get('coverage')=='Gate-only-explicit-history'
         and value.get('cache_restore')=='NORMAL_REBUILD' and value.get('E_F_restore_promised') is False,
         'Gate C capsule dependency/restore scope differs')
    need(body is None or value.get('body_binding')==body,'Gate C capsule belongs to another body')
    need(type(value.get('events')) is list and len(value['events'])<=MAX_EVENTS,'Bounded Gate C event history required')
    originals=value.get('originals');need(type(originals) is dict and set(originals)<=set(('cp','ap55')),'Only Gate C originals admitted')
    expected={}
    ids=set()
    for event in value['events']:
        need(type(event) is dict and event.get('outcome') in ('ATTEMPTED_UNKNOWN','C_READBACK_VERIFIED'), 'C event outcome differs')
        need(type(event.get('event_id')) is str and event['event_id'] not in ids,'Unique C event ID required');ids.add(event['event_id'])
        source=event.get('preimage');kind=event.get('kind')
        need(kind in ('cp','ap55') and type(source) is dict,'Finite C dispatch source required')
        if kind=='cp':
            windows=source.get('windows')
            need(type(windows) is list and 1<=len(windows)<=2,'Finite CP C preimages required')
            for row in windows:
                matches=[(at,off,on) for at,off,on in gs.GATE_WINDOWS if row.get('offset')==at]
                need(len(matches)==1,'CP C offset outside fixed Gate ranges')
                at,off,on=matches[0]
                need(row.get('original_hex') in (off,on),'Earliest Gate CP original must be a known exact endpoint')
            need(len({r['offset'] for r in windows})==len(windows),'Duplicate CP C ranges')
            need(type(event.get('request_sha256')) is str and len(event['request_sha256'])==64
                 and type(event.get('ticket_id')) is str and len(event['ticket_id'])==64,'Dispatch request/ticket identity required')
            target=expected.setdefault('cp',dict(path='/cp/CPAPP-B.BIN',file_size=gs.CP_SIZE,windows=[]))
            for row in windows:
                if not any(r['offset']==row['offset'] for r in target['windows']):target['windows'].append(row)
            target['windows'].sort(key=lambda r:r['offset'])
        else:
            need(source.get('chip')==0 and source.get('key')=='00510055' and source.get('attrs')==0
                 and source.get('size')==1 and source.get('ram_hex') in ('00','02') and source.get('saved_hex') in ('00','02'),
                 'Only earliest AP55 original values admitted')
            need(event.get('command')==2 and type(event.get('request_sha256')) is str
                 and len(event['request_sha256'])==64,'Only actual AP55 cmd2 dispatch can register AP55 C')
            expected.setdefault('ap55',source)
    need(originals==expected,'C union differs from earliest actual-dispatch preimages')
    return deepcopy(value)


def load(path,body=None):
    return validate(json.loads(read_private(Path(path),2*1024*1024)),body)


def parent_from_jobs(jobs,body):
    """Only the explicit latest Gate capsule; legacy histories stay uncovered."""
    for job in reversed(jobs):
        path=Path(job).absolute();path=path/'job.private.json' if path.is_dir() else path
        receipt=json.loads(read_private(path,2*1024*1024))
        if receipt.get('gate_C_capsule_ref'):
            ref=receipt['gate_C_capsule_ref'];need(ref.get('path')=='gate-C-capsule.private.json','Fixed C capsule reference required')
            raw=read_private(path.parent/ref['path'],2*1024*1024)
            need(len(raw)==ref.get('size') and sha256(raw).hexdigest()==ref.get('sha256'),'Referenced Gate C capsule changed')
            return validate(json.loads(raw),body)
    return None


class Capsule:
    def __init__(self,root,body,*,parent=None,result=None,restoring=False,on_change=None):
        self.root=Path(root);self.path=self.root/'gate-C-capsule.private.json';self.result=result
        self.restoring=restoring
        self.on_change=on_change
        self.value=validate(parent,body) if parent is not None else _sealed(dict(schema=SCHEMA,
            body_binding=body,firmware='6.02',loader_sha256=LOADER_SHA256,profile=gs.PROFILE,
            coverage='Gate-only-explicit-history',cache_restore='NORMAL_REBUILD',E_F_restore_promised=False,
            originals={},events=[]))
        self.pending=[];self.persist()

    def persist(self):
        self.value=_sealed(self.value);validate(self.value)
        _atomic_json(self.path,self.value)
        raw=read_private(self.path,2*1024*1024)
        if self.result is not None:self.result['gate_C_capsule_ref']=dict(path=self.path.name,size=len(raw),sha256=sha256(raw).hexdigest())
        if self.on_change is not None:
            committed=self.on_change(deepcopy(self.value))
            need(committed is None or type(committed) is int and committed==0,'Master Gate C commit failed before dispatch')

    def _register(self,kind,preimage,**facts):
        if self.restoring:return
        need(len(self.value['events'])<MAX_EVENTS,'Gate C ledger capacity reached before dispatch')
        event=dict(event_id=uuid.uuid4().hex,kind=kind,preimage=preimage,outcome='ATTEMPTED_UNKNOWN',**facts)
        # Persist intent immediately before dispatch. A crash in the final host
        # instruction gap stays ATTEMPTED_UNKNOWN, never asserted executed.
        _write(self.root/('C-dispatch-'+event['event_id']+'.json'),_json(event))
        self.value['events'].append(event)
        if kind=='cp':
            row=self.value['originals'].setdefault('cp',dict(path='/cp/CPAPP-B.BIN',file_size=gs.CP_SIZE,windows=[]))
            for window in preimage['windows']:
                if not any(w['offset']==window['offset'] for w in row['windows']):row['windows'].append(window)
            row['windows'].sort(key=lambda w:w['offset'])
        else:self.value['originals'].setdefault('ap55',preimage)
        self.pending.append(event['event_id']);self.persist()

    def program_dispatch(self,plan,request):
        # Forward tickets require all fixed source endpoints; restore never
        # replaces originals with its current/possibly partial preimage.
        if self.restoring:return
        gs.GateProtocol(plan)
        self._register('cp',dict(windows=[dict(offset=w['offset'],original_hex=w['before_hex'])
            for w in plan['components']['cp']['windows']]),ticket_id=plan['plan_id'],request_sha256=sha256(request).hexdigest())

    def settings_dispatch(self,plan,observation):
        if observation.get('command')!=2 or observation.get('role')!='ap' or observation.get('key')!=sp.AP55[1]:return
        r=plan.records[0];value=plan.baseline.ram.records[sp.AP55]
        self._register('ap55',dict(chip=0,key='00510055',attrs=value.attrs,size=1,
            ram_hex=r.before_ram.hex(),saved_hex=r.before_saved.hex()),command=2,
            request_sha256=sha256(observation['request']).hexdigest(),settings_plan_id=plan.plan_id)

    def confirmed(self,kind):
        if self.restoring:return
        for event in self.value['events']:
            if event['event_id'] in self.pending and event['kind']==kind:event['outcome']='C_READBACK_VERIFIED'
        self.persist()


def cp_program(ap,cp,originals):
    gs.dependencies(ap,cp)
    target=bytearray(cp);windows=[]
    for row in originals.get('cp',{}).get('windows',[]):
        at=row['offset'];after=bytes.fromhex(row['original_hex']);before=cp[at:at+len(after)]
        if before!=after:
            windows.append(dict(offset=at,before_hex=before.hex(),after_hex=after.hex()));target[at:at+len(after)]=after
    if not windows:return None
    return program_worker.program_plan(dict(ap=dict(source=gs.identity(ap),target=gs.identity(ap),windows=[]),
        cp=dict(source=gs.identity(cp),target=gs.identity(bytes(target)),windows=windows)),feature_id='electronic-sound-gate')


def check_cp_target(cp,originals):
    for row in originals.get('cp',{}).get('windows',[]):
        raw=bytes.fromhex(row['original_hex']);at=row['offset']
        need(cp[at:at+len(raw)]==raw,'Cumulative Gate CP original target differs')


def settings_plan(snapshot,originals,**binding):
    row=originals.get('ap55');need(row is not None,'AP55 is not registered C; do not restore it')
    sp._binding(snapshot,**binding)
    before=[getattr(snapshot,p).records.get(sp.AP55) for p in ('ram','saved','bin','bak')]
    need(all(v is not None and v.attrs==0 and len(v.data)==1 for v in before),'Current AP55 C shape differs')
    record=sp.Record(*sp.AP55,((0,1),),before[0].data,before[1].data,bytes.fromhex(row['ram_hex']),bytes.fromhex(row['saved_hex']))
    result=sp.Plan('gate-restore-ap55',binding['identity'],binding['boot_id'],binding['nonce'],snapshot,(record,),(0x51,),
        save_effects_policy=save_effects.NATIVE51,gate_original=(row['ram_hex'],row['saved_hex']))
    sp.validate_plan(result);return result


def local_selection(capture_path,capture,capsule):
    capsule=validate(capsule,capture['body_binding']);root=Path(capture['snapshot_dir'])
    ap=read_private(root/'appFw.so',gs.BOUNDS['ap']);cp=read_private(root/'CPAPP-B.BIN',gs.CP_SIZE)
    originals=capsule['originals'];planned=cp_program(ap,cp,originals)
    components={}
    for name,row in capture['objects'].items():
        value={k:row[k] for k in ('size','sha256')}
        components[name]=dict(source=dict(path=str(root/name),kind=row['kind'],**value),target_path=row['target_path'],
            target=dict(value),windows=[],append=dict(offset=row['size'],size=0,after_hex='',sha256=sha256(b'').hexdigest()))
    if planned:components['CPAPP-B.BIN']['target']=planned['components']['cp']['target']
    return dict(schema='a7m4-toolbox-gate-selection/1',source_basis=gs.POLICY,restore_policy=RESTORE_POLICY,
        C_originals=originals,capsule_sha256=capsule['capsule_sha256'],body_binding=capture['body_binding'],
        capture_receipt=str(Path(capture_path).absolute()),components=components,program_stages=[planned] if planned else [],
        gate=dict(schema='a7m4-toolbox-sound-gate/2',gate=dict(desired_state='restore-C',current_state='current-C'),program=planned,
            source_admission=dict(policy=RESTORE_POLICY,dependencies=gs.dependencies(ap,cp),historical_F_admission=False)),
        selection=dict(include_fl2=False,include_fl3=False,slots=[]))


def settings_freshness(before,after,originals):
    sp.validate_snapshot(before);sp.validate_snapshot(after)
    errors=[]
    if before.serial!=after.serial:errors.append('Restore same-body binding differs')
    for p in ('ram','saved','bin','bak'):
        values=getattr(after,p).records
        for pair,value in ((sp.CP55,sp.Value(0,b'\0')),(sp.BOOT_DEVICE,sp.Value(0,b'\1'))):
            if values.get(pair)!=value:errors.append('Restore current CP55/BOOT D differs')
        value=values.get(sp.AP55)
        if value is None or value.attrs!=0 or len(value.data)!=1:errors.append('Restore AP55 path shape differs')
        if 'ap55' not in originals and value!=getattr(before,p).records.get(sp.AP55):errors.append('Unregistered AP55 D changed')
    if 'ap55' not in originals:
        modes=[getattr(after,p).records[sp.AP55] for p in ('ram','saved','bin','bak')]
        if not all(v==modes[0] for v in modes) or modes[0] not in (sp.Value(0,b'\0'),sp.Value(0,b'\2')):
            errors.append('Unregistered AP55 D must be coherent00/02')
    return dict(schema='gate-C-restore-settings-freshness/1',stable=not errors,errors=errors,E_F_gate_execution=False)


class RestoreProtocol(gs.GateProtocol):
    def __init__(self,plan):
        program_worker.ProgramProtocol.__init__(self,plan)
        need(plan['feature_id']=='electronic-sound-gate' and plan['components']['ap']['windows']==[]
             and plan['components']['cp']['source']['size']==gs.CP_SIZE,'Finite Gate restore ticket required')
        self.originals={'cp':dict(windows=[])}
        for w in plan['components']['cp']['windows']:
            matches=[(at,off,on) for at,off,on in gs.GATE_WINDOWS if at==w['offset']]
            need(len(matches)==1 and w['after_hex'] in matches[0][1:]
                 and len(w['before_hex'])==len(w['after_hex']),'Restore window outside registered Gate shape/endpoints')
            self.originals['cp']['windows'].append(dict(offset=w['offset'],original_hex=w['after_hex']))
        self.endpoint_plan=None;self.source_paths=None

    def confirm_readback(self,images):
        need(self.state=='READY' and self.pending is None and self.previous_mode in (0,3),'Gate restore full inspection required')
        try:
            need(set(images)=={'ap','cp'},'Both complete program observations required')
            ap=read_private(Path(images['ap']),gs.BOUNDS['ap']);cp=read_private(Path(images['cp']),gs.CP_SIZE)
            gs.dependencies(ap,cp)
            if self.previous_mode==0:
                endpoint=cp_program(ap,cp,self.originals)
                need(endpoint is not None and all(endpoint['components'][r]['windows']==self.plan['components'][r]['windows']
                    and endpoint['components'][r]['source']['size']==self.plan['components'][r]['source']['size'] for r in ('ap','cp')),
                    'Restore current C or native FD layout changed')
                self.endpoint_plan=endpoint;self.source_paths={r:str(Path(images[r])) for r in ('ap','cp')};self.full_endpoint='source'
                return dict(status='CURRENT_RESTORE_C_D_VERIFIED_F_OBSERVED',native_ticket_id=self.plan['plan_id'],F_gate_execution=False)
            need(self.endpoint_plan is not None,'Restore needs source C confirmation')
            check_cp_target(cp,self.originals);self.full_endpoint='target'
            return dict(status='RESTORE_C_D_VERIFIED_E_F_OBSERVED',native_ticket_id=self.plan['plan_id'],
                actual_files={'ap':gs.identity(ap),'cp':gs.identity(cp)},F_gate_execution=False)
        except BaseException:self.unknown();raise
