"""Gate C/D plan and current-session F baseline; no device I/O on import.

C: only the24 existing CP bytes and AP55. D: finite code/layout anchors,
body/version/loader and runtime channel conditions checked by the caller.
Unchanged content is never a historical admission fingerprint.
"""
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path

from . import program_worker
from .capture_inputs import read_private
from .pin_sources import GATE_WINDOWS

POLICY='gate-current-CDEF/2'
PROFILE='m4-602-gate-finite-dependencies/1'
DATA=Path(__file__).with_name('data')/'gate-dependencies.json'
CP_SIZE=16236816
BOUNDS={'ap':160*1024*1024,'cp':CP_SIZE,'audio':16*1024*1024,'resource':16*1024*1024}
MAX_BASELINE=256*1024*1024


def need(ok,message):
    if not ok:raise ValueError(message)


def identity(raw):return dict(size=len(raw),sha256=sha256(raw).hexdigest())


def profile():
    value=json.loads(read_private(DATA,65536))
    need(value.get('schema')==PROFILE and value.get('review_status')=='REVIEWED_COMPLETE'
         and value.get('cp_size')==CP_SIZE,'Finite Gate dependency anchors not reviewed')
    anchors=value.get('anchors')
    expected=((3181876,36),(3181916,32),(3181968,52),(3182024,94),(6912346,104))
    need(type(anchors) is list and len(anchors)==len(expected),'Exact finite Gate D anchor set required')
    for row,(offset,size) in zip(anchors,expected):
        raw=bytes.fromhex(row['hex'])
        need(type(row.get('offset')) is int and row['offset']==offset and len(raw)==size
             and row.get('sha256')==sha256(raw).hexdigest(),'Gate D anchor identity differs')
        need(all(offset+size<=at or at+len(bytes.fromhex(off))<=offset for at,off,on in GATE_WINDOWS),
             'Gate C and D ranges overlap')
    variants=value.get('variants')
    need(type(variants) is list and len(variants)==1 and variants[0].get('offset')==3182020
         and variants[0].get('allowed_hex')==['41ea0221','41f2a551'],'Exact finite cutoff dependency required')
    return value


def dependencies(ap,cp):
    spec=profile()
    need(type(ap) is bytes and 20<=len(ap)<=BOUNDS['ap'] and ap[:6]==b'\x7fELF\x02\x01'
         and int.from_bytes(ap[18:20],'little')==183,'Gate AP path/layout must remain AArch64 ELF')
    need(type(cp) is bytes and len(cp)==spec['cp_size'],'Gate CP fixed layout size differs')
    for row in spec['anchors']:
        raw=bytes.fromhex(row['hex']);at=row['offset']
        need(cp[at:at+len(raw)]==raw,'Gate concrete D code anchor differs: '+row['name'])
    variant=[]
    for row in spec['variants']:
        at=row['offset'];actual=cp[at:at+4].hex()
        need(actual in row['allowed_hex'],'Gate existing cutoff is outside finite supported endpoints')
        variant.append(dict(offset=at,bytes=4,actual_hex=actual,preserved=True))
    return dict(profile=PROFILE,cp_size=len(cp),AP_layout='AArch64-ELF',variants=variant,
                anchors=[dict(offset=r['offset'],size=len(bytes.fromhex(r['hex'])),sha256=r['sha256'],name=r['name']) for r in spec['anchors']],
                whole_AP_CP_or_sound_family_hash_required=False)


def state(cp):
    values=[]
    for at,off,on in GATE_WINDOWS:
        raw=cp[at:at+len(bytes.fromhex(off))]
        values.append('disabled' if raw==bytes.fromhex(off) else 'enabled' if raw==bytes.fromhex(on) else 'unknown')
    need(len(set(values))==1 and values[0]!='unknown','Gate C has unknown/mixed exact preimages')
    return values[0]


def program(ap,cp,desired):
    need(desired in ('enabled','disabled'),'Explicit Gate target required')
    dependencies(ap,cp);current=state(cp)
    if current==desired:return None
    target=bytearray(cp);windows=[]
    for at,off,on in GATE_WINDOWS:
        before,after=bytes.fromhex(off if desired=='enabled' else on),bytes.fromhex(on if desired=='enabled' else off)
        need(cp[at:at+len(before)]==before,'Gate C exact source changed')
        target[at:at+len(after)]=after
        windows.append(dict(offset=at,before_hex=before.hex(),after_hex=after.hex()))
    return program_worker.program_plan(dict(ap=dict(source=identity(ap),target=identity(ap),windows=[]),
        cp=dict(source=identity(cp),target=identity(bytes(target)),windows=windows)),feature_id='electronic-sound-gate')


def selection_program(selection,ap,cp):
    if selection.get('restore_policy'):
        from .gate_cumulative import cp_program,RESTORE_POLICY
        need(selection['restore_policy']==RESTORE_POLICY,'Unknown cumulative C restore policy')
        return cp_program(ap,cp,selection['C_originals'])
    return program(ap,cp,selection['gate']['gate']['desired_state'])


def check_target(selection,cp):
    if selection.get('restore_policy'):
        from .gate_cumulative import check_cp_target
        check_cp_target(cp,selection['C_originals'])
    else:need(state(cp)==selection['gate']['gate']['desired_state'],'Gate C target differs')


def local_selection(capture_path,capture,state_name,*,program_jobs=(),sound_job=None):
    root=Path(capture['snapshot_dir'])
    ap=read_private(root/'appFw.so',BOUNDS['ap']);cp=read_private(root/'CPAPP-B.BIN',CP_SIZE)
    proof=dependencies(ap,cp);planned=program(ap,cp,state_name)
    components={}
    for name,row in capture['objects'].items():
        source={k:row[k] for k in ('size','sha256')}
        components[name]=dict(source=dict(path=str(root/name),kind=row['kind'],**source),
            target_path=row['target_path'],target=dict(source),windows=[],
            append=dict(offset=row['size'],size=0,after_hex='',sha256=sha256(b'').hexdigest()))
    if planned:components['CPAPP-B.BIN']['target']=planned['components']['cp']['target']
    gate=dict(schema='a7m4-toolbox-sound-gate/2',body_binding=capture['body_binding'],
        gate=dict(desired_state=state_name,current_state=state(cp)),program=planned,
        source_admission=dict(policy=POLICY,dependencies=proof,historical_F_admission=False),
        program_jobs=[str(Path(p).absolute()) for p in program_jobs],
        sound_job=str(Path(sound_job).absolute()) if sound_job is not None else None,
        camera_io=False,device_validation='not-performed')
    return dict(schema='a7m4-toolbox-gate-selection/1',source_basis=POLICY,
        capture_receipt=str(Path(capture_path).absolute()),body_binding=capture['body_binding'],gate=gate,
        components=components,program_stages=[planned] if planned else [],
        selection=dict(include_fl2=False,include_fl3=False,slots=[]))


def rebind(planned,capture,folder,files,*,boot_id):
    """Derive complete native hashes over current F; never enlarge C windows."""
    ap=read_private(Path(folder)/'appFw.so',BOUNDS['ap']);cp=read_private(Path(folder)/'CPAPP-B.BIN',CP_SIZE)
    proof=dependencies(ap,cp)
    need(identity(ap)=={k:files['appFw.so'][k] for k in ('size','sha256')} and identity(cp)=={k:files['CPAPP-B.BIN'][k] for k in ('size','sha256')},
         'Held current Gate program preimage changed after capture')
    if not planned.get('restore_policy'):
        need(state(cp)==planned['gate']['gate']['current_state'],'Gate C differs from selected backup preimage')
    result=deepcopy(planned);gate=result['gate'];desired=gate['gate']['desired_state']
    changed=selection_program(planned,ap,cp);gate['program']=changed
    gate['source_admission']=dict(policy=POLICY,dependencies=proof,historical_F_admission=False,
        current_session_preimage=True,boot_id=boot_id)
    result['program_stages']=[changed] if changed else []
    observations=[]
    for name,row in capture['objects'].items():
        actual=files[name];before={k:row[k] for k in ('size','sha256')}
        source={k:actual[k] for k in ('size','sha256')}
        result['components'][name]=dict(source=dict(path=str(Path(folder)/name),kind=row['kind'],**source),
            target_path=row['target_path'],target=dict(source),windows=[],
            append=dict(offset=source['size'],size=0,after_hex='',sha256=sha256(b'').hexdigest()))
        if before!=source:observations.append(dict(name=name,historical=before,current=source,admission_blocked=False))
    if changed:result['components']['CPAPP-B.BIN']['target']=changed['components']['cp']['target']
    result['current_source']=dict(policy=POLICY,body_binding=capture['body_binding'],boot_id=boot_id,
        historical_F_differences=observations,full_postreadback_baseline='this-session-preimages',
        C_byte_count=sum(len(bytes.fromhex(off)) for at,off,on in GATE_WINDOWS),
        C_paths=['/cp/CPAPP-B.BIN','AP00510055'],supporting_persistent_WBI_or_mode_writes=[],
        source_files=files)
    return result


class GateProtocol(program_worker.ProgramProtocol):
    """Immutable native C ticket plus independently bound latest F endpoints.

    The native engine checks24C bytes, FD shape, nonce and its original ticket
    ID. It does not hash F. Its acknowledgement is NEVER relabeled with the
    new semantic endpoint ID. Full POST is read; C/D is validated and F differences remain observations.
    """
    def __init__(self,plan):
        super().__init__(plan)
        need(plan['feature_id']=='electronic-sound-gate' and plan['components']['ap']['windows']==[],
             'Only the fixed CP Gate ticket is admitted')
        candidates=[]
        for enabled in (True,False):
            candidates.append([dict(offset=at,before_hex=off if enabled else on,after_hex=on if enabled else off)
                               for at,off,on in GATE_WINDOWS])
        need(plan['components']['cp']['windows'] in candidates and plan['components']['cp']['source']['size']==CP_SIZE,
             'Gate ticket may only contain the24 fixed C bytes')
        self.desired='enabled' if plan['components']['cp']['windows']==candidates[0] else 'disabled'
        self.endpoint_plan=None
        self.source_paths=None

    def confirm_readback(self,images):
        need(self.state=='READY' and self.pending is None and self.previous_mode in (0,3),
             'Complete Gate source/target inspection required')
        try:
            need(set(images)=={'ap','cp'},'Both full Gate program readbacks required')
            if self.previous_mode==0:
                ap=read_private(Path(images['ap']),BOUNDS['ap']);cp=read_private(Path(images['cp']),CP_SIZE)
                endpoint=program(ap,cp,self.desired)
                need(endpoint is not None and all(endpoint['components'][r]['windows']==self.plan['components'][r]['windows']
                     and endpoint['components'][r]['source']['size']==self.plan['components'][r]['source']['size'] for r in ('ap','cp')),
                     'Gate C/D or native file shape changed')
                self.endpoint_plan=endpoint;self.source_paths={r:str(Path(images[r])) for r in ('ap','cp')}
                self.full_endpoint='source'
                return dict(status='CURRENT_C_D_VERIFIED_F_BOUND_FOR_POST',native_ticket_id=self.plan['plan_id'],
                            semantic_endpoint_id=endpoint['plan_id'],historical_or_initial_F_admission=False)
            need(self.endpoint_plan is not None,'No current Gate F endpoint was bound before writing')
            ap=read_private(Path(images['ap']),BOUNDS['ap']);cp=read_private(Path(images['cp']),CP_SIZE)
            dependencies(ap,cp)
            need(state(cp)==self.desired,'Gate C target readback differs')
            actual={'ap':identity(ap),'cp':identity(cp)}
            forecast={r:self.endpoint_plan['components'][r]['target'] for r in ('ap','cp')}
            self.full_endpoint='target'
            return dict(status='COMPLETE_READ_C_D_VERIFIED_E_F_OBSERVED',native_ticket_id=self.plan['plan_id'],
                semantic_endpoint_id=self.endpoint_plan['plan_id'],actual_files=actual,predicted_files=forecast,
                F_differences_observed=actual!=forecast,F_gate_execution=False)
        except BaseException:
            self.unknown();raise


def verify_ticket_binding(selection,root):
    """Validate the scoped receipt bridge for existing program composition."""
    if selection.get('source_basis')!=POLICY:return
    tickets=selection.get('native_program_tickets',[]);stages=selection['program_stages']
    need(len(tickets)==len(stages)<=1,'Bounded Gate ticket/endpoint bridge required')
    for ticket,endpoint in zip(tickets,stages):
        if selection.get('restore_policy'):
            from .gate_cumulative import RestoreProtocol
            RestoreProtocol(ticket)
        else:GateProtocol(ticket)
        program_worker.validate_plan(endpoint)
        stored=json.loads(read_private(Path(root)/'program-0/native-ticket-plan.json',65536))
        need(stored==ticket,'Retained native Gate ticket changed')
        ap=read_private(Path(root)/'program-0/0-ap.bin',BOUNDS['ap'])
        cp=read_private(Path(root)/'program-0/0-cp.bin',CP_SIZE)
        expected=selection_program(selection,ap,cp)
        need(expected==endpoint and selection['gate']['program']==endpoint,'Gate semantic endpoint derivation changed')
        need(all(ticket['components'][r]['windows']==endpoint['components'][r]['windows']
                 and ticket['components'][r]['source']['size']==endpoint['components'][r]['source']['size'] for r in ('ap','cp')),
             'Native Gate ticket and semantic C windows/layout differ')
        for role,name in (('ap','appFw.so'),('cp','CPAPP-B.BIN')):
            row=selection['components'][name]
            need(row['source']['path']==str(Path(root)/'program-0'/('0-'+role+'.bin'))
                 and {k:row['source'][k] for k in ('size','sha256')}==endpoint['components'][role]['source']
                 and row['target']==endpoint['components'][role]['target'],'Gate scoped program source/target binding differs')


# Frozen legacy receipt reconstruction; never the new forward entry.
def legacy_selection(capture_path,state,*,program_jobs=(),sound_job=None):
    """Restricted complete source plus two fixed electronic-sound windows."""
    import os,uuid
    from .device_job import complete_capture
    from .settings_plan import plan_ap55
    from .pin_sources import GATE_WINDOWS,identity as image_identity
    from .policy import sound_state
    capture,settings=complete_capture(capture_path)
    state=sound_state(state)
    from .pin_composition import product_source_context
    context=product_source_context(capture_path,previous_job=sound_job,program_jobs=program_jobs)
    admission=context['admission']
    blobs=context['actual_bytes'];cp=blobs['cp_program'];current=[]
    for at,off,on in GATE_WINDOWS:
        raw=cp[at:at+len(bytes.fromhex(off))]
        current.append('disabled' if raw==bytes.fromhex(off) else 'enabled' if raw==bytes.fromhex(on) else 'unknown')
    if len(set(current))!=1 or current[0]=='unknown':raise ValueError('Electronic-sound gate is in an unknown/mixed exact state')
    program=None;target=bytearray(cp);windows=[]
    if current[0]!=state:
        for at,off,on in GATE_WINDOWS:
            old,new=bytes.fromhex(off if state=='enabled' else on),bytes.fromhex(on if state=='enabled' else off)
            if cp[at:at+len(old)]!=old:raise ValueError('Exact electronic-sound source differs')
            target[at:at+len(old)]=new;windows.append(dict(offset=at,before_hex=old.hex(),after_hex=new.hex()))
        ap=image_identity(blobs['ap'])
        program=program_worker.program_plan(dict(ap=dict(source=ap,target=ap,windows=[]),
            cp=dict(source=image_identity(cp),target=image_identity(bytes(target)),windows=windows)),feature_id='electronic-sound-gate')
    gate=dict(schema='a7m4-toolbox-sound-gate/2',body_binding=capture['body_binding'],source_admission=admission,
        gate=dict(desired_state=state,current_state=current[0]),program=program,
        program_jobs=[str(Path(p).absolute()) for p in program_jobs],
        sound_job=str(Path(sound_job).absolute()) if sound_job is not None else None,camera_io=False,device_validation='not-performed')
    # Validate the complete AP55 SAVE preconditions locally before any entry.
    if gate['program'] is not None or state=='enabled':
        plan_ap55(settings,identity=capture['body_binding']['serial_sha256'],boot_id=str(uuid.uuid4()),nonce=os.urandom(16).hex())
    components={}
    for name,row in capture['objects'].items():
        identity={k:row[k] for k in ('size','sha256')}
        components[name]=dict(source=dict(path=str(Path(capture['snapshot_dir'])/name),kind=row['kind'],**identity),
            target_path=row['target_path'],target=dict(identity),windows=[],append=dict(offset=row['size'],size=0,after_hex='',sha256=sha256(b'').hexdigest()))
    if gate['program'] is not None:
        components['CPAPP-B.BIN']['target']=gate['program']['components']['cp']['target']
    return dict(schema='a7m4-toolbox-gate-selection/1',capture_receipt=str(Path(capture_path).absolute()),
        body_binding=capture['body_binding'],gate=gate,components=components,
        program_stages=[gate['program']] if gate['program'] is not None else [],
        selection=dict(include_fl2=False,include_fl3=False,slots=[]))



def observed_normalization(selection,ap,cp):
    """C-only source normalization over observed F, not an execution claim."""
    dependencies(ap,cp)
    if selection.get('restore_policy'):
        check_target(selection,cp)
        return []  # Restore receipts are not forward source-lineage claims.
    desired=selection['gate']['gate']['desired_state']
    need(state(cp)==desired,'Observed Gate C target differs')
    before=selection['gate']['gate']['current_state']
    if before==desired:return []
    source=bytearray(cp)
    for at,off,on in GATE_WINDOWS:
        raw=bytes.fromhex(off if before=='disabled' else on);source[at:at+len(raw)]=raw
    normalized=program(ap,bytes(source),desired)
    return [normalized] if normalized else []


def read_observed_file(path,maximum):
    """Static private evidence may represent an empty/unavailable F file."""
    import os,stat
    path=Path(path)
    if path.stat().st_size:return read_private(path,maximum)
    need(not any(p.is_symlink() for p in (path,*path.parents)),'Observed evidence path redirected')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size==0 and os.read(fd,1)==b'',
             'Empty F evidence changed')
        after=os.fstat(fd);current=path.lstat()
        fields=('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')
        need(all(getattr(before,k)==getattr(after,k)==getattr(current,k) for k in fields),'Empty F evidence changed')
    finally:os.close(fd)
    return b''
