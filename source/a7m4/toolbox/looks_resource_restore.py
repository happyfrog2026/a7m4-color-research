"""Original resource C union, followed by independently admitted EOF cleanup.

No per-feature inverse sequence and no complete historical F replay. Prefix
plans project earliest actually dispatched C into today's F. EOF cleanup needs
restored C, dynamic global reference bounds, a fresh independently verified
program/load proof and one of the two reviewed runtime shadow endpoints. A
known clean inspection refusal can require another startup boundary; unknown
mapping/I/O outcomes never authorize fallback, replay or healthy STOP.
"""
from copy import deepcopy
from hashlib import sha256
from pathlib import Path
import re
import struct

from . import looks_resource_scope as scope
from .restore_helper_loader import load_helper
from . import original_resource_tail_original as original_tail
from .original_resource_tail_original_protocol import OriginalTailProtocol
from ..research import native_icons as icons

need,canonical,identity=scope.need,scope.canonical,scope.identity
SCHEMA='a7m4-custom1-resource-EOF-C-D/1'
NATIVE_SHA='f0410292c83f875606132826744fffd6a664eb76f8dd82b3c2aff9ba0fdff3dc'


class RequiredBoundary(ValueError):
    def __init__(self,message,*,reason='RESOURCE_LOAD_PROOF_REQUIRED',details=None):
        super().__init__(message)
        self.checkpoint=dict(status='RESOURCE_RESTORE_BOUNDARY_REQUIRED',reason=reason,complete=False,
            union_C_restored=False,normal_MSC_required=True,requires_new_boot_evidence=True,
            required_evidence='fresh same-body boot/PID + independently verified original program C loaded + native resource shadow inspection',
            details=details or {},automatic_retry=False)


def _rows(original):
    return [dict(offset=w['offset'],hex=w['hex']) for w in original['windows']]


def _check_original(raw,original):
    need(type(raw) is bytes and original['eof']<=len(raw)<=original['eof']+sum(len(bytes.fromhex(a['hex'])) for a in original['appends']),
         'Current EOF is outside actual-dispatch ownership')
    for w in original['windows']:
        data=bytes.fromhex(w['hex']);need(raw[w['offset']:w['offset']+len(data)]==data,'Original resource C is not restored')


def plan_prefix(path,source,original):
    """Equal-length C restore; appended bytes/EOF and all F remain untouched."""
    need(path in scope.PATHS and type(source) is bytes and len(source)>=original['eof'],'Original resource prefix geometry differs')
    target=bytearray(source);windows=[]
    for row in original['windows']:
        at=row['offset'];data=bytes.fromhex(row['hex'])
        need(0<=at<at+len(data)<=original['eof'],'Original C window lies outside original EOF')
        target[at:at+len(data)]=data
        for i in range(0,len(data),512):
            old=source[at+i:at+i+min(512,len(data)-i)];new=data[i:i+512]
            if old!=new:windows.append(dict(offset=at+i,before_hex=old.hex(),after_hex=new.hex()))
    return scope.scoped_file(path,source,bytes(target),windows,direction='restore-prefix',target_C=_rows(original))


def references(path,raw,limit):
    """Dynamic global reference safety D for the EOF being removed.

    Pixels/text content have no expected full hash. Every registered reference
    must be self-contained below the target EOF; an unrelated active reference
    into the owned tail is a real dependency and prevents truncation.
    """
    need(path in scope.PATHS and type(raw) is bytes and 0<limit<=len(raw),'Finite reference geometry differs')
    prefix=raw[:limit]
    if Path(path).name.startswith('image_'):
        bank=icons._inspect_bank(prefix)
        proof=dict(kind='image-index-and-payload-bounds',count=len(bank['records']),limit=limit)
    else:
        need(len(prefix)>=16 and prefix[:12]==b'uxc\x07\0\0\0\0\x08\0\x05\0','String header dependency differs')
        descriptor=struct.unpack_from('<I',prefix,12)[0];count=descriptor&8191
        need(count in (3032,3048) and descriptor==count|(count<<12),'String index dependency differs')
        base=(16+2*count+3)&~3;seen=0
        need(base<limit,'String index exceeds target EOF')
        for i in range(count):
            p=struct.unpack_from('<H',prefix,16+2*i)[0]
            if p==65535:continue
            at=base+4*p
            need(at+5<=limit and prefix[at:at+4]==struct.pack('<I',0x1e00a000+i)
                 and prefix.find(b'\0',at+4)>=0,'Active string reference reaches removed EOF or is malformed')
            seen+=1
        proof=dict(kind='string-index-record-and-terminator-bounds',count=seen,limit=limit)
    return dict(proof,E_F_hash_admission=False,verified=True)


def _runtime(runtime):
    required={'body_binding','boot_id','process_id','fresh','original_backup_sha256','load_proof'}
    need(type(runtime) is dict and required<=set(runtime) and runtime['fresh'] is True
         and type(runtime['process_id']) is int and 1<runtime['process_id']<=4194304
         and type(runtime['boot_id']) is str and re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',runtime['boot_id']),
         'Fresh independently bound resource runtime required')
    proof=runtime['load_proof']
    if not (type(proof) is dict and proof.get('C_loaded_verified') is True and proof.get('fresh') is True
            and proof.get('process_id')==runtime['process_id'] and proof.get('boot_id')==runtime['boot_id']
            and re.fullmatch('[0-9a-f]{64}',str(proof.get('report_sha256','')))):
        raise RequiredBoundary('Original program C has not been independently proved loaded; retain resource tail')
    need(re.fullmatch('[0-9a-f]{64}',str(runtime['original_backup_sha256'])),'Authenticated original backup binding required')
    return deepcopy(runtime)


def plan_tail(path,source,original,*,runtime,profile='disk-shadow'):
    """Bind one fresh EOF stage; no native failure implicitly selects a profile."""
    _check_original(source,original)
    need(len(source)>original['eof'],'Equal-length resource needs no EOF worker')
    runtime=_runtime(runtime);need(profile in ('disk-shadow','original-eof-zero-padded'),'Explicit reviewed runtime profile required')
    target=source[:original['eof']];ref=references(path,source,original['eof'])
    # Native compares restored original C again immediately before truncation.
    D=[dict(offset=w['offset']+i,before_hex=bytes.fromhex(w['hex'])[i:i+512].hex(),
            after_hex=bytes.fromhex(w['hex'])[i:i+512].hex()) for w in original['windows'] for i in range(0,len(bytes.fromhex(w['hex'])),512)]
    D.append(dict(offset=0,before_hex=source[:16].hex(),after_hex=source[:16].hex()))
    need(len(D)<=128 and sum(len(bytes.fromhex(d['before_hex'])) for d in D)<=16384,'Restored resource C/D exceeds native proof bound')
    evidence=dict(original_C=original,reference_bounds=ref,D=D,load_proof=runtime['load_proof'],runtime_profile=profile)
    authority=dict(schema='a7m4-owned-tail-authority/1',original_backup_sha256=runtime['original_backup_sha256'],
        current_file_readback_sha256=sha256(source).hexdigest(),resource_reference_proof_sha256=sha256(canonical(evidence)).hexdigest(),
        boot_or_load_proof_sha256=runtime['load_proof']['report_sha256'])
    if profile=='disk-shadow':
        worker,_=load_helper('tail-restore');native=worker.make_plan(path,source,target,authority=authority)
    else:
        native=original_tail.make_plan(path,source,target,authority=authority,runtime=dict(process_id=runtime['process_id'],
            boot_id=runtime['boot_id'],original_ap_report_sha256=runtime['load_proof']['report_sha256']))
    return scope.seal(dict(schema=SCHEMA,target_path=path,native_plan=native,profile=profile,D=D,
        victim=dict(offset=0,size=0,donor_id=0),original=deepcopy(original),runtime=runtime,
        reference_proof=ref,E_F_gate_execution=False,semantic_whole_target_verified=False,camera_io=False))


def validate(plan):
    need(type(plan) is dict and plan.get('schema')==SCHEMA and scope.seal(plan)==plan,'Resource EOF scope integrity differs')
    worker=original_tail if plan['profile']=='original-eof-zero-padded' else load_helper('tail-restore')[0]
    worker.validate_plan(plan['native_plan']);_runtime(plan['runtime'])
    need(plan['target_path']==plan['native_plan']['resource_path'] and plan['target_path'] in scope.PATHS
         and plan['original']['eof']==plan['native_plan']['target']['size'] and plan['E_F_gate_execution'] is False,
         'Resource EOF ownership differs')
    return plan


def check(plan,raw,*,target):
    validate(plan);raw=scope._read(raw);p=plan['native_plan']
    need(len(raw)==p['target' if target else 'source']['size'],'Resource EOF endpoint differs')
    _check_original(raw,plan['original']);references(plan['target_path'],raw,p['target']['size'])
    for row in plan['D']:
        data=bytes.fromhex(row['after_hex' if target else 'before_hex'])
        need(raw[row['offset']:row['offset']+len(data)]==data,'Resource EOF finite C/D differs')
    if not target:
        # Only the finite physical shadow is a source dependency. It provides
        # the exact page bytes preserved by the mapped-tail mechanism.
        shadow=raw[p['shadow_begin']:] + bytes(p['shadow_end']-len(raw))
        need(shadow.hex()==p['expected_shadow_hex'],'Resource tail/shadow source dependency differs')
    return dict(C_D_verified=True,E_F_gate_execution=False,semantic_whole_target_verified=False,observed_file=identity(raw))


class TailProtocol:
    """Frozen wire/mapping parser with C/D-only host barriers and honest result."""
    def __init__(self,plan):
        self.scope=deepcopy(validate(plan))
        if plan['profile']=='original-eof-zero-padded':self.inner=OriginalTailProtocol(plan['native_plan'])
        else:self.inner=load_helper('tail-restore')[1].TailRestoreProtocol(plan['native_plan'])
    def __getattr__(self,name):return getattr(self.inner,name)
    def request(self,mode,nonce):return self.inner.request(mode,nonce)
    def accept(self,raw):
        report=self.inner.accept(raw)
        if report['pid']!=self.scope['runtime']['process_id']:
            self.inner.state='STOP_UNKNOWN';raise ValueError('Resource EOF native process differs')
        return report
    def confirm_source(self,raw):
        need(self.inner.state=='INSPECTED_NEEDS_FULL_SOURCE_MAC_READ' and self.inner.pending is None,'Inspect before fresh resource source C/D')
        try:proof=check(self.scope,raw,target=False)
        except BaseException:self.inner.state='STOP_SOURCE_MISMATCH';raise
        self.inner.source_barrier=proof;self.inner.state='FULL_SOURCE_MAC_VERIFIED';return proof
    def confirm_readback(self,raw):
        need(self.inner.state=='APPLIED_NEEDS_FULL_TARGET_MAC_READ' and self.inner.pending is None,'Native completion before EOF C/D readback')
        try:proof=check(self.scope,raw,target=True)
        except BaseException:self.inner.state='STOP_TARGET_READBACK_MISMATCH';raise
        self.inner.target_barrier=proof;self.inner.state='FULL_TARGET_MAC_VERIFIED';return proof
    def finish(self):
        result=self.inner.finish()
        # Legacy finish's whole-file statement relied on its SHA barriers;
        # these scoped barriers deliberately make only an original-C/EOF claim.
        result.update(full_file_restore_complete=False,original_C_EOF_restored=True,
            E_F_restored=False,semantic_whole_target_verified=False,complete=True)
        return result


def render_header(plan):
    validate(plan);p=plan['native_plan'];arr=lambda b:'{'+','.join(map(str,b))+'}'
    if plan['profile']=='original-eof-zero-padded':
        raw=original_tail.render_header(p);end=p['runtime_end'];kind=1;worker=original_tail
    else:
        worker=load_helper('tail-restore')[0];raw=worker.render_header(p);end=p['shadow_end'];kind=2
        raw+=('static const u8 tr_runtime_shadow[]='+arr(bytes.fromhex(p['expected_shadow_hex']))+';\n'
            '#define TR_PID %dUL\n'%plan['runtime']['process_id']+'static const char tr_boot_id[]='+
            __import__('json').dumps(plan['runtime']['boot_id'])+';\n').encode()
    raw+=('#define TR_RUNTIME_END %dUL\n#define TR_PROFILE %d\n'%(end,kind)+
        '#define TR_REQUEST_PATH '+__import__('json').dumps(worker.REQUEST_PATH)+'\n'+
        '#define TR_RESULT_PATH '+__import__('json').dumps(worker.RESULT_PATH)+'\n'+
        '#define TR_MAGIC '+arr(worker.MAGIC)+'\n').encode()
    return raw+scope._dependency_header(plan)


def build(plan,output,*,compiler):
    return scope._build('tail',NATIVE_SHA,render_header(plan),output,compiler=compiler)


def owned_paths():
    legacy=load_helper('tail-restore')[0]
    return {legacy.REQUEST_PATH:256,legacy.RESULT_PATH:65536,original_tail.REQUEST_PATH:256,original_tail.RESULT_PATH:65536}


def packets(plan):
    validate(plan)
    worker=original_tail if plan['profile']=='original-eof-zero-padded' else load_helper('tail-restore')[0]
    return dict(request_path=worker.REQUEST_PATH,report_path=worker.RESULT_PATH,request_bytes=256,
        report_bytes=worker.MIN_REPORT+worker.MAX_PREIMAGE_BYTES,native_report_capacity=65536,native_overhead_units=2)


def acknowledge_clean_inspection(actions,protocol):
    """Classify one fully cleaned borrowed NativeActions phase as read-only.

    This does not grant STOP. The coordinator still checks all earlier jobs,
    WBI, channel health and the selected checkpoint. No unknown state is reset.
    """
    report=protocol.last_report;paths=packets(protocol.scope)
    need(type(report) is dict and report.get('mode')==0 and protocol.pending is None
         and report.get('cleanup_safe') is True and report.get('mapping_state_unknown') is False
         and all(report.get(k)==0 for k in ('euid','plugin_unlink','close_errors','readonly','remount',
             'mremap_attempts','changed_aliases','anon_bytes','bytes_truncated')),
         'Only a complete parsed, zero-mutation, cleanup-safe tail inspection is read-only')
    need(not actions.failed and actions.channel.healthy and not actions.unknown_remote_state
         and all(actions.channel.peek(p) is None for p in
             ('/tmp/jiritsu/libJit.so',paths['request_path'],paths['report_path']))
         and not actions.owned,'Exact tail native packet cleanup must precede read-only classification')
    actions.feature_attempted=False;actions.inspection_complete=True
    return dict(read_only_inspection_verified=True,healthy_STOP_granted=False,
        native_report_sha256=report['report_sha256'],complete=report['complete'])


def boundary_from_refusal(report):
    """Only a proved clean RAM endpoint mismatch can suggest a startup step."""
    known=(type(report) is dict and report.get('mode')==0 and report.get('phase')==2
        and report.get('source_status')==0 and report.get('flags')==64
        and report.get('status',report.get('native_status'))==-84 and report.get('cleanup_safe') is True
        and report.get('mapping_state_unknown') is False
        and all(report.get(k,0)==0 for k in ('mremap_attempts','changed_aliases','anon_bytes','bytes_truncated')))
    if not known:return None
    return RequiredBoundary('Native inspect proved a clean RAM resource endpoint mismatch; retain EOF and obtain fresh original-C load evidence',
        reason='RESOURCE_RAM_ENDPOINT_MISMATCH',details=dict(pid=report.get('pid'),inspection_failed=True,
            original_eof_profile_requires_explicit_fresh_plan=True,failed_inspection_does_not_count_as_success=True))


def plan_original_eof_after_clean_refusal(protocol,actions,source,*,runtime):
    """The retained R067 alternative, after a proved disk-shadow RAM refusal.

    A new boot is not demanded when fresh independent original-C load evidence
    already exists. The old failed inspect remains failed. Unknown, apply,
    disk-C/D or malformed outcomes never reach the alternative native profile.
    """
    old=validate(protocol.scope);report=protocol.last_report
    need(old['profile']=='disk-shadow' and boundary_from_refusal(report) is not None
         and report.get('range_count',0)>0 and report.get('safe_inspect_refusal') is True
         and report.get('preimage_captured') is False
         and report.get('pid')==old['runtime']['process_id']
         and report.get('plan_id')==old['native_plan']['plan_id'],
         'Only the exact proved RAM-only disk-shadow inspection refusal admits original-EOF planning')
    fresh=_runtime(runtime)
    need((fresh['body_binding'],fresh['boot_id'],fresh['process_id'])==
         (old['runtime']['body_binding'],old['runtime']['boot_id'],old['runtime']['process_id']),
         'Alternative EOF profile requires the same fresh body/boot/PID')
    cleanup=acknowledge_clean_inspection(actions,protocol)
    check(old,source,target=False)
    new=plan_tail(old['target_path'],source,old['original'],runtime=fresh,profile='original-eof-zero-padded')
    new['prior_failed_inspection']=dict(report_sha256=report['report_sha256'],native_ticket_id=report['plan_id'],
        failed_inspection_preserved=True,cleanup=cleanup)
    return scope.seal(new)


def restore_resources(current_files, originals, runtime):
    """Replan after every completed checkpoint; never force a one-round restore."""
    cap=scope.validate_capsule(originals,runtime.get('body_binding'))
    prefix=[plan_prefix(p,current_files[p],o) for p,o in cap['originals'].items()]
    pending=[p for p in prefix if p['native_plan'] is not None]
    if pending:
        return dict(phase='RESTORE_REFERENCES',files=prefix,complete=False,union_C_restored=False,
            EOF_deferred=True,requires_fresh_replan=True,E_F_restored=False,camera_io=False)
    tails=[]
    for path,original in cap['originals'].items():
        raw=current_files[path];_check_original(raw,original)
        if len(raw)>original['eof']:
            tails.append(plan_tail(path,raw,original,runtime=runtime,profile=runtime.get('resource_tail_profile','disk-shadow')))
    return dict(phase='RESTORE_EOF' if tails else 'C_EOF_VERIFIED',files=tails,
        complete=not tails,union_C_restored=not tails,E_F_restored=False,semantic_whole_target_verified=False,camera_io=False)
