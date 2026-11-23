"""Fixed FL23/Custom1 program scopes over fresh F, no device operations.

The finite C recipes are projected from the existing reviewed stock helpers.
Historical complete AP/CP identities are extraction provenance, not admission.
"""
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path

from . import program_worker as worker
from .capture_inputs import read_private
from .native_actions import _json, _write
from .usb_read import _atomic_json,LOADER_SHA256

SCHEMA='a7m4-looks-program-scope/1'
CAPSULE='a7m4-looks-program-C/1'
PROFILE='m4-602-looks-program-C-D/1'
DATA=Path(__file__).with_name('data')/'looks-program-scope.json'
DATA_SHA='0c3ded70299e431abb43c5212602ff17c2eea010be5c9c63a73b07096447aa06'
LIMITS=dict(ap=98212632,cp=16236816)


def need(ok,message):
    if not ok:raise ValueError(message)


def identity(raw):return dict(size=len(raw),sha256=sha256(raw).hexdigest())


def seal(value,key='scope_id'):
    value=deepcopy(value);value.pop(key,None);value[key]=sha256(_json(value)).hexdigest();return value


def profile_data():
    raw=read_private(DATA,1024*1024);need(sha256(raw).hexdigest()==DATA_SHA,'Finite looks program profile source changed')
    value=json.loads(raw);need(value['schema']==PROFILE and value['historical_full_hash_admission'] is False,'Finite program scope differs')
    return value


def _config(config):
    need(type(config) is dict and type(config.get('fl23')) is bool and type(config.get('m9')) is bool
         and (config['fl23'] or config['m9']),'Fixed FL23 and/or Custom1 M9 intent required')
    need(config.get('slot',1)==1 and config.get('display_name','M9')=='M9','Only Custom1 M9 is supported')
    return deepcopy(config)


def _profile(config):return 'm9' if config['m9'] else 'fl23'


def dependencies(ap,cp,feature,*,classify=True):
    data=profile_data();images=dict(ap=ap,cp=cp)
    need(feature in ('fl23','m9'),'Unknown fixed program profile')
    for role,raw in images.items():need(type(raw) is bytes and len(raw)==LIMITS[role],'Looks '+role+' fixed geometry differs')
    need(ap[:7]==b'\x7fELF\x02\x01\x01' and int.from_bytes(ap[18:20],'little')==183,'Looks AP ELF ABI differs')
    rows=[]
    for role,anchors in data['dependencies'][feature].items():
        for row in anchors:
            expected=bytes.fromhex(row['hex']);at=row['offset']
            need(images[role][at:at+len(expected)]==expected,'Looks finite D differs: '+role+'/'+str(at))
            rows.append(dict(role=role,offset=at,size=len(expected),sha256=row['sha256']))
    if feature=='fl23' and classify:
        marker=data['m9_marker'];at=marker['offset'];raw=cp[at:at+marker['size']]
        need(raw.hex() in (marker['original_hex'],marker['m9_hex']),'Preserve-M9 classifier D differs')
        rows.append(dict(role='cp',offset=at,size=len(raw),sha256=sha256(raw).hexdigest(),finite_variant=True))
    return dict(profile=PROFILE,feature=feature,anchors=rows,total_D_bytes=sum(r['size'] for r in rows),whole_file_hash_admission=False)


def _m9_active(cp,data):
    m=data['m9_marker'];raw=cp[m['offset']:m['offset']+m['size']].hex()
    need(raw in (m['original_hex'],m['m9_hex']),'Custom1 runtime marker is not a known dependency endpoint')
    return raw==m['m9_hex']


def _rows(ap,cp,config):
    data=profile_data();feature=_profile(config);proof=dependencies(ap,cp,feature);images=dict(ap=ap,cp=cp)
    active=_m9_active(cp,data);result={}
    for role,rows in data['profiles'][feature].items():
        result[role]=[]
        for row in rows:
            at=row['offset'];before=images[role][at:at+row['size']].hex()
            need(before in {row[x+'_hex'] for x in ('original','fl23','m9','m9_shared') if x+'_hex' in row},'Unknown looks C preimage: '+role+'/'+str(at))
            # FL23-only preserves an existing M9 runtime even where its
            # reviewed carrier shares the FL23 foundation's original ranges.
            target=row['m9_hex'] if config['m9'] or active else row['fl23_hex']
            result[role].append(dict(offset=at,before_hex=before,after_hex=target))
    return result,proof,active


def plan(ap,cp,profile=None,config=None):
    """One fixed scoped ticket, with native_plan=None for a true program NOOP."""
    if config is None:config=profile;profile=None
    config=_config(config);feature=_profile(config)
    need(profile in (None,PROFILE,feature),'Unexpected program profile override')
    rows,D,active=_rows(ap,cp,config);source=dict(ap=ap,cp=cp);components={}
    for role in ('ap','cp'):
        target=bytearray(source[role]);windows=[]
        for row in rows[role]:
            raw=bytes.fromhex(row['after_hex']);at=row['offset'];target[at:at+len(raw)]=raw
            if row['before_hex']!=row['after_hex']:windows.append(row)
        components[role]=dict(source=identity(source[role]),target=identity(bytes(target)),windows=windows)
    native=worker.program_plan(components,feature_id='scoped-looks-program-v1') if any(c['windows'] for c in components.values()) else None
    value=dict(schema=SCHEMA,direction='forward',profile=feature,config=config,C_targets=rows,D=D,
        native_plan=native,program_stages=[native] if native else [],m9_previously_active=active,
        source_observation={r:identity(v) for r,v in source.items()},E_F_gate_execution=False,
        FL23_program_foundation_written_for_M9=config['m9'],FL23_business_settings_requested=config['fl23'],
        native_mode_order=[0,1,3],camera_io=False)
    return seal(value)


plan_forward=plan


def validate(ticket):
    need(type(ticket) is dict and ticket.get('schema')==SCHEMA and seal(ticket)==ticket,'Looks program ticket integrity differs')
    need(ticket['direction'] in ('forward','restore') and ticket['profile'] in ('fl23','m9') and ticket['E_F_gate_execution'] is False,'Looks program scope differs')
    native=ticket['native_plan']
    if native is not None:worker.validate_plan(native)
    need(ticket['program_stages']==([native] if native else []),'Looks native stage binding differs')
    data=profile_data()
    if ticket['direction']=='forward':
        config=_config(ticket['config']);need(_profile(config)==ticket['profile'],'Looks profile and intent differ')
        expected=data['profiles'][ticket['profile']]
        for role in ('ap','cp'):
            actual=ticket['C_targets'][role];need(len(actual)==len(expected[role]),'Complete fixed C targets required')
            for row,spec in zip(actual,expected[role]):
                need(row['offset']==spec['offset'] and row['before_hex'] in {spec[x+'_hex'] for x in ('original','fl23','m9','m9_shared') if x+'_hex' in spec},'Looks C source/range differs')
                target=spec['m9_hex'] if config['m9'] or ticket['m9_previously_active'] else spec['fl23_hex']
                need(row['after_hex']==target,'Looks C target differs from the fixed recipe')
        if native is not None:
            for role in ('ap','cp'):
                need(native['components'][role]['windows']==[r for r in ticket['C_targets'][role] if r['before_hex']!=r['after_hex']],
                    'Native looks window set differs from C targets')
    else:
        need(ticket['native_mode_order']==[3,2,0],'Restore must use native inverse with C-only readback')
        capsule=validate_capsule(ticket['restore_capsule'])
        original_bytes={role:{row['offset']+j:v for row in rows for j,v in enumerate(bytes.fromhex(row['before_hex']))}
                        for role,rows in capsule['originals'].items()}
        for role,rows in ticket['C_targets'].items():
            for row in rows:
                raw=bytes.fromhex(row['after_hex'])
                need(all(original_bytes[role].get(row['offset']+j)==v for j,v in enumerate(raw)),
                     'Restore C target is not the actual-dispatch capsule original')
        if native is not None:
            for role in ('ap','cp'):
                need(native['components'][role]['windows']==[dict(offset=r['offset'],before_hex=r['after_hex'],after_hex=r['before_hex'])
                    for r in ticket['C_targets'][role] if r['before_hex']!=r['after_hex']], 'Inverse native C windows differ')
    return ticket


def check(ticket,images,*,target):
    validate(ticket);D=dependencies(images['ap'],images['cp'],ticket['profile'],classify=ticket['direction']=='forward')
    key='after_hex' if target else 'before_hex'
    for role,rows in ticket['C_targets'].items():
        for row in rows:
            raw=bytes.fromhex(row[key]);at=row['offset']
            need(images[role][at:at+len(raw)]==raw,'Looks C endpoint differs: '+role+'/'+str(at))
    return dict(C_D_verified=True,E_F_gate_execution=False,D=D,observed_files={r:identity(v) for r,v in images.items()},
        semantic_whole_target_verified=False,observation_surface='disk-files',running_AP_C_verified=False)


def build(ticket,output,*,compiler=None):
    validate(ticket);need(ticket['native_plan'] is not None,'True program NOOP needs no native helper')
    return worker.build_program_worker(ticket['native_plan'],output,compiler=compiler)


class Protocol(worker.ProgramProtocol):
    """Unchanged native ticket; host barriers check only fixed C and finite D."""
    def __init__(self,ticket):
        self.scope=deepcopy(validate(ticket));need(ticket['native_plan'] is not None,'No native operation for NOOP')
        super().__init__(ticket['native_plan']);self.semantic_endpoint=None
    def confirm_readback(self,paths):
        try:
            need(self.state=='READY' and self.pending is None and self.previous_mode in (0,3),'Complete program inspect required')
            images={r:read_private(Path(paths[r]),LIMITS[r]) for r in ('ap','cp')}
            initial=(self.previous_mode==(3 if self.scope['direction']=='restore' else 0))
            checked=check(self.scope,images,target=not initial)
            if initial:
                if self.scope['direction']=='forward':
                    latest=plan(images['ap'],images['cp'],config=self.scope['config'])
                    need(latest['C_targets']==self.scope['C_targets'] and latest['native_plan'] is not None
                         and all(latest['native_plan']['components'][r]['windows']==self.plan['components'][r]['windows']
                         and latest['native_plan']['components'][r]['source']['size']==self.plan['components'][r]['source']['size'] for r in ('ap','cp')),
                         'Latest C or preserve-M9 classification changed before native dispatch')
                # F may change after compilation. The request and report keep
                # the original ticket ID; this forecast is a separate record.
                target={r:bytearray(v) for r,v in images.items()}
                for role,rows in self.scope['C_targets'].items():
                    for row in rows:
                        raw=bytes.fromhex(row['after_hex']);at=row['offset'];target[role][at:at+len(raw)]=raw
                self.semantic_endpoint={r:identity(bytes(v)) for r,v in target.items()}
            self.full_endpoint=('target' if initial else 'source') if self.scope['direction']=='restore' else ('source' if initial else 'target')
            return dict(checked,native_ticket_id=self.plan['plan_id'],semantic_endpoint_forecast=self.semantic_endpoint,
                forecast_is_native_report_id=False)
        except BaseException:self.unknown();raise


def _known_owned(role,offset,raw):
    """An original can only contain bytes from the finite known C endpoints."""
    rows=[r for p in profile_data()['profiles'].values() for r in p[role]]
    for j,byte in enumerate(raw):
        at=offset+j;candidates=[]
        for row in rows:
            if row['offset']<=at<row['offset']+row['size']:
                candidates.extend(bytes.fromhex(row[k+'_hex'])[at-row['offset']] for k in ('original','fl23','m9','m9_shared') if k+'_hex' in row)
        need(byte in candidates,'Original byte is outside fixed looks C authority')


def _union(events):
    result={role:{} for role in ('ap','cp')}
    for event in events:
        ticket=validate(event['ticket']);need(ticket['direction']=='forward' and ticket['native_plan'] is not None,'Only actual forward native dispatch grants C ownership')
        for role,c in ticket['native_plan']['components'].items():
            for row in c['windows']:
                raw=bytes.fromhex(row['before_hex'])
                for j,v in enumerate(raw):result[role].setdefault(row['offset']+j,v)
    out={}
    for role,values in result.items():
        rows=[]
        for at in sorted(values):
            if rows and at==rows[-1]['offset']+len(bytes.fromhex(rows[-1]['before_hex'])) and len(rows[-1]['before_hex'])<8192:
                rows[-1]['before_hex']+=bytes([values[at]]).hex()
            else:rows.append(dict(offset=at,before_hex=bytes([values[at]]).hex()))
        out[role]=rows
    return out


def validate_capsule(value,body=None):
    need(type(value) is dict and value.get('schema')==CAPSULE and seal(value,'capsule_sha256')==value,'Looks program capsule integrity differs')
    need(body is None or value['body_binding']==body,'Looks program capsule belongs to another body')
    need(value['firmware']=='6.02' and value['loader_sha256']==LOADER_SHA256 and value['E_F_restore_promised'] is False,'Looks program capsule scope differs')
    events=value['events'];need(type(events) is list and len(events)<=32,'Bounded program C history required')
    for e in events:
        need(e['outcome'] in ('ATTEMPTED_UNKNOWN','C_READBACK_VERIFIED') and len(e['request_sha256'])==64,'Program dispatch evidence differs')
    need(value['originals']==_union(events),'Program originals differ from earliest actual-dispatch C union')
    return deepcopy(value)


def load_capsule(path,body=None):return validate_capsule(json.loads(read_private(Path(path),4*1024*1024)),body)


class ProgramCapsule:
    def __init__(self,root,body,parent=None,*,on_change=None):
        self.path=Path(root)/'looks-program-C-capsule.private.json';self.on_change=on_change
        self.value=validate_capsule(parent,body) if parent is not None else seal(dict(schema=CAPSULE,body_binding=body,
            firmware='6.02',loader_sha256=LOADER_SHA256,E_F_restore_promised=False,cache_restore='NORMAL_REBUILD',events=[],originals=dict(ap=[],cp=[])),'capsule_sha256')
        self.persist()
    def persist(self):
        self.value=seal(self.value,'capsule_sha256');validate_capsule(self.value);_atomic_json(self.path,self.value)
        if self.on_change is not None:self.on_change(deepcopy(self.value))
    def dispatch(self,ticket,request):
        ticket=validate(ticket);need(ticket['direction']=='forward' and ticket['native_plan'] is not None,'No ownership for inverse/NOOP')
        fields=worker.REQUEST.unpack(request);need(fields[1]==1 and fields[4]==bytes.fromhex(ticket['native_plan']['plan_id']),'Only actual bound native mode1 dispatch grants ownership')
        e=dict(ticket=deepcopy(ticket),request_sha256=sha256(request).hexdigest(),outcome='ATTEMPTED_UNKNOWN')
        _write(self.path.parent/('program-C-dispatch-%02d.json'%len(self.value['events'])),_json(e))
        self.value['events'].append(e);self.value['originals']=_union(self.value['events']);self.persist()
    def confirmed(self,images):
        need(bool(self.value['events']),'No program dispatch to confirm')
        if isinstance(images,dict) and all(isinstance(v,(str,Path)) for v in images.values()):images={r:read_private(Path(v),LIMITS[r]) for r,v in images.items()}
        check(self.value['events'][-1]['ticket'],images,target=True)
        self.value['events'][-1]['outcome']='C_READBACK_VERIFIED';self.persist()


def restore(ap,cp,originals):
    """C-only inverse batches over observed F; normal native mapping guards stay.

    Unknown partial disk C is admissible. The unchanged native worker may still
    refuse a third RAM endpoint; no fallback or automatic retry is provided.
    """
    cap=load_capsule(originals) if isinstance(originals,(str,Path)) else validate_capsule(originals)
    feature='m9' if any(e['ticket']['profile']=='m9' for e in cap['events']) else 'fl23'
    dependencies(ap,cp,feature,classify=False);images=dict(ap=ap,cp=cp);pending=[]
    for role,rows in cap['originals'].items():
        for row in rows:
            raw=bytes.fromhex(row['before_hex']);_known_owned(role,row['offset'],raw)
            if images[role][row['offset']:row['offset']+len(raw)]!=raw:pending.append((role,row))
    groups=[]
    for item in pending:
        n=len(bytes.fromhex(item[1]['before_hex']))
        if not groups or len(groups[-1])>=128 or sum(len(bytes.fromhex(r['before_hex'])) for _,r in groups[-1])+n>16384:groups.append([])
        groups[-1].append(item)
    stages=[]
    for group in groups:
        C={r:[] for r in ('ap','cp')};components={}
        for role in ('ap','cp'):
            target=bytearray(images[role]);windows=[]
            for rr,row in group:
                if rr!=role:continue
                at=row['offset'];old=bytes.fromhex(row['before_hex']);now=images[role][at:at+len(old)]
                C[role].append(dict(offset=at,before_hex=now.hex(),after_hex=old.hex()))
                windows.append(dict(offset=at,before_hex=old.hex(),after_hex=now.hex()));target[at:at+len(old)]=old
            # Original/restored is native source; current observed disk is its
            # target. Mode3→2→0 protects already loaded original/modified RAM.
            components[role]=dict(source=identity(bytes(target)),target=identity(images[role]),windows=windows)
        native=worker.program_plan(components,feature_id='scoped-looks-original-c-v1')
        ticket=seal(dict(schema=SCHEMA,direction='restore',profile=feature,config=None,C_targets=C,restore_capsule=cap,
            native_plan=native,program_stages=[native],D=dependencies(images['ap'],images['cp'],feature,classify=False),
            E_F_gate_execution=False,native_mode_order=[3,2,0],camera_io=False))
        validate(ticket);stages.append(ticket)
        for role,rows in C.items():
            raw=bytearray(images[role])
            for row in rows:
                at=row['offset'];v=bytes.fromhex(row['after_hex']);raw[at:at+len(v)]=v
            images[role]=bytes(raw)
    return stages


def check_restored(ap,cp,originals):
    cap=load_capsule(originals) if isinstance(originals,(str,Path)) else validate_capsule(originals)
    feature='m9' if any(e['ticket']['profile']=='m9' for e in cap['events']) else 'fl23'
    dependencies(ap,cp,feature,classify=False);images=dict(ap=ap,cp=cp)
    for role,rows in cap['originals'].items():
        for row in rows:
            raw=bytes.fromhex(row['before_hex']);at=row['offset']
            need(images[role][at:at+len(raw)]==raw,'Final cumulative looks program C differs')
    return dict(C_D_verified=True,E_F_gate_execution=False,observed_files={r:identity(v) for r,v in images.items()},
        observation_surface='disk-files',running_AP_C_verified=False)


def make_loaded_C_probe(ap,originals):
    """Read-only subset of unchanged original_ap_load; never a factory proof.

    Only this child's earliest AP C and its explicit AP D are expected. The
    complete disk SHA is an observation needed by the original wire schema;
    neither the native checker nor this adapter compares unrelated F hashes.
    """
    from . import original_ap_load as ro
    cap=load_capsule(originals) if isinstance(originals,(str,Path)) else validate_capsule(originals)
    feature='m9' if any(e['ticket']['profile']=='m9' for e in cap['events']) else 'fl23'
    need(type(ap) is bytes and len(ap)==LIMITS['ap'],'AP geometry required for C-only load probe')
    expected={}
    for row in profile_data()['dependencies'][feature]['ap']:
        raw=bytes.fromhex(row['hex']);at=row['offset'];need(ap[at:at+len(raw)]==raw,'AP D differs before load probe')
        for j,v in enumerate(raw):expected[at+j]=v
    for row in cap['originals']['ap']:
        raw=bytes.fromhex(row['before_hex']);at=row['offset'];need(ap[at:at+len(raw)]==raw,'Earliest AP C is not restored on disk')
        for j,v in enumerate(raw):
            need(at+j not in expected or expected[at+j]==v,'AP C/D proof ranges conflict');expected[at+j]=v
    rows=[]
    for at in sorted(expected):
        if rows and at==rows[-1]['offset']+len(bytes.fromhex(rows[-1]['expected_hex'])) and len(rows[-1]['expected_hex'])<1024:
            rows[-1]['expected_hex']+=bytes([expected[at]]).hex()
        else:rows.append(dict(offset=at,expected_hex=bytes([expected[at]]).hex()))
    value=dict(schema='a7m4-original-ap-load-plan/1',master_plan_id=cap['capsule_sha256'],ap_target=identity(ap),
        windows=rows,endpoint='source')
    value['plan_id']=sha256(ro._json(value)).hexdigest();ro.validate_probe_plan(value);return value


def verify_loaded_C_borrowed(channel,output,*,originals,compiler,boot_id,pid,actions_factory=None):
    """Fresh maps+/proc/self/mem proof with honest scoped flags and no writes."""
    import os
    from . import original_ap_load as ro
    from .native_actions import NativeActions
    from .build_scratch import discard_caches
    actions_factory=actions_factory or NativeActions
    output=Path(output);output.mkdir(mode=0o700,exist_ok=False)
    plan=make_loaded_C_probe(channel.file('/usr/lib/appFw.so'),originals)
    _write(output/'scoped-load-plan.json',_json(plan));binary=ro.build(plan,output/'build',compiler=compiler)
    nonce=os.urandom(16);request=ro.REQUEST.pack(b'A7ALQ001',nonce,bytes.fromhex(plan['plan_id']),bytes(8))
    actions=actions_factory(channel,output/'native')
    def accept(raw):
        _write(output/'report.private.bin',raw)
        parsed=ro.parse_report(plan,raw,nonce,boot_id=boot_id,pid=pid)
        fields=ro.REPORT.unpack(raw)
        return dict(schema='a7m4-looks-earliest-AP-C-loaded/1',plan_id=plan['plan_id'],program_capsule_sha256=plan['master_plan_id'],
            loaded_earliest_owned_AP_C_verified=parsed['loaded_current_ap_verified'],standard_original_AP_verified=False,
            standard_current_AP_verified=False,scope='earliest-owned-AP-C-plus-explicit-AP-D-only',
            process_id=pid,boot_id=boot_id,disk_device=fields[10],disk_inode=fields[11],disk_size=fields[12],
            cleanup_safe=parsed['cleanup_safe'],native_status=parsed['native_status'],aliases=parsed['aliases'],covered=parsed['covered'],
            window_count=parsed['window_count'],phase=fields[2],native_comparisons=fields[16],report_sha256=parsed['report_sha256'],nonce_hex=nonce.hex(),
            no_memory_write=True,no_COW=True,whole_F_hash_admission=False)
    result=actions.phase(binary,ro.REQUEST_PATH,request,ro.RESULT_PATH,accept,report_bytes=ro.REPORT.size)
    actions.clean_packets()
    # Recheck only this proof's C/D after the native read. F may have changed.
    current=channel.file('/usr/lib/appFw.so');need(len(current)==plan['ap_target']['size'],'AP probe geometry changed')
    for row in plan['windows']:
        raw=bytes.fromhex(row['expected_hex']);at=row['offset'];need(current[at:at+len(raw)]==raw,'AP C/D changed during load proof')
    discard_caches(output/'build');return result
