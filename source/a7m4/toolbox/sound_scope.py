"""Finite first-stock M9 sound C/D and independent observed F endpoints.

No device I/O. The legacy PIN family planner and workers remain unchanged.
"""
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import subprocess

from . import gate_scope as gate, pin_sources, workspace
from .capture_inputs import read_private
from .native_actions import _json, _write
from .pin_product_worker import _elf
from ..research import pin_plan, pin_audio

SCHEMA='m4-stock-sound-C-D/1'
REQUEST_PATH='/tmp/jiritsu/m4.sound-scope.request'
REPORT_PATH='/tmp/jiritsu/m4.sound-scope.result'
REQUEST=struct.Struct('<8sII16s32s')
REPORT=struct.Struct('<8sIIII7q6Q32s16sq')
NATIVE_SHA='afda42c10a0a98900281f306b2a283b5681e5876dbb07b7f991e4412a2b6eaeb'
PATHS=dict(ap='/usr/lib/appFw.so',cp='/cp/CPAPP-B.BIN',bank='/cp/SysSound.bin')
LIMITS=dict(ap=98212632,cp=16236816,bank=110528)
AP_OFFSETS=pin_plan.AP_OFFSETS
STOCK_WORDS=pin_sources.STOCK_WORDS
ORIGINAL_EOF=77504
TARGET_EOF=110528
TAIL=TARGET_EOF-ORIGINAL_EOF
R066_RESTORE_PROFILE='r066-108480-to-stock/1'
R066_LENGTHS=dict(ka=256,sha=14400,kasha=16576)
SELECTED_CONTROLS='selected-sound-controls/1'
CUTOFF_INSTRUCTIONS={0.125:'41ea0221',0.02:'41f2a551'}


def need(ok,message):
    if not ok:raise ValueError(message)


def identity(raw):return dict(size=len(raw),sha256=sha256(raw).hexdigest())


def seal(value):
    value=deepcopy(value);value.pop('plan_id',None)
    value['plan_id']=sha256(_json(value)).hexdigest();return value


def words(ap):return [ap[at:at+4].hex() for at in AP_OFFSETS]


def dependencies(ap,cp,*,enabled=None,registered_cutoffs=False):
    need(type(ap) is bytes and len(ap)==LIMITS['ap'],'Fixed sound AP file geometry differs')
    proof=gate.dependencies(ap,cp)
    spec=json.loads(read_private(Path(__file__).with_name('data')/'sound-dependencies.json',65536))
    need(spec['schema']=='m4-602-sound-setup-D/1' and spec['total_bytes']==172,'Finite sound D profile differs')
    need([(r['offset'],len(bytes.fromhex(r['hex']))) for r in spec['anchors']]==
         [(0x317c59c,84),(0x317c600,40),(0x317c634,48)],'Exact finite sound D ranges required')
    for row in spec['anchors']:
        raw=bytes.fromhex(row['hex']);at=row['offset']
        need(ap[at:at+len(raw)]==raw,'Finite sound AP setup D differs')
    if enabled is not None:need(gate.state(cp)==('enabled' if enabled else 'disabled'),'Required CP electronic-sound Gate state differs')
    # This closed first experiment preserves the native1/8 split instruction.
    observed=cp[3182020:3182024].hex()
    need(observed in (tuple(CUTOFF_INSTRUCTIONS.values()) if registered_cutoffs else ('41ea0221',)),
         'Sound CP cutoff is outside its registered dependency endpoints')
    return dict(AP_setup_D_bytes=172,CP_gate_dependencies=proof,cutoff_write=False,whole_F_hash_admission=False)


def _selected_controls(c):
    need(type(c) is dict,'Complete selected sound controls required')
    normalized=pin_audio._controls(dict(clips=dict(recock={}),gain_db=c['gain_db'],
        recock=dict(enabled=c['recock_enabled'],gap_ms=c['recock_gap_ms']),
        hybrid_cutoff=dict(denominator=c['cutoff_denominator']),
        kasha_synthesis=dict(link_pair_delay_to_cutoff=c['link_pair_delay_to_cutoff'],
                            pair_delay_seconds=c['kasha_pair_delay_seconds'],preserve_tails=c['preserve_tails'])))
    need(c==normalized and c['cutoff_seconds'] in CUTOFF_INSTRUCTIONS,
         'Selected sound controls or supported camera cutoff differ')
    need(c['link_pair_delay_to_cutoff'] is False and c['kasha_pair_delay_seconds']==.02,
         'Selected sound requires the independent fixed internal20ms pair delay')
    return c


def prepared(path,*,selected=False):
    manifest=pin_audio.validate_prepared_pack(path);manifest,clips=pin_plan._pack(manifest)
    c=manifest['controls']
    if selected:_selected_controls(c)
    else:need(c['recock_enabled'] is True and c['recock_gap_ms']==40 and c['cutoff_seconds']==0.02,
              'First scoped experiment requires M9 recock40ms and fixed Kasha internal20ms')
    return manifest,clips


def _plan(ap,cp,bank,after_words,head,tail,*,restore,runtime_words,selected=False):
    dependencies(ap,cp,enabled=None if restore else True,registered_cutoffs=restore or selected)
    need(type(bank) is bytes and ORIGINAL_EOF<=len(bank)<=TARGET_EOF,'Sound C EOF geometry differs')
    need(len(head)==256 and len(tail)==(0 if restore else TAIL),'Fixed sound C content geometry differs')
    need(restore or len(bank)==ORIGINAL_EOF,'Only first stock sound installation is supported')
    target_size=ORIGINAL_EOF+len(tail)
    need(len(after_words)==len(runtime_words)==7 and all(len(bytes.fromhex(w))==4 for w in after_words+runtime_words),'Exact seven sound words required')
    target_ap=bytearray(ap)
    for at,h in zip(AP_OFFSETS,after_words):target_ap[at:at+4]=bytes.fromhex(h)
    target_bank=bank[:256]+bank[256:ORIGINAL_EOF]+tail
    target_bank=head+target_bank[256:]
    return seal(dict(schema=SCHEMA,direction='restore' if restore else 'forward',
        source=dict(ap=identity(ap),cp=identity(cp),bank=identity(bank)),
        forecast=dict(ap=identity(bytes(target_ap)),cp=identity(cp),bank=identity(target_bank)),
        ap_windows=[dict(offset=at,before_hex=ap[at:at+4].hex(),after_hex=h) for at,h in zip(AP_OFFSETS,after_words)],
        bank=dict(source_eof=len(bank),target_eof=target_size,before_head_hex=bank[:256].hex(),
            before_tail_hex=bank[ORIGINAL_EOF:].hex(),after_head_hex=head.hex(),after_tail_hex=tail.hex()),
        runtime_words=runtime_words,dependencies=dependencies(ap,cp,enabled=None if restore else True,registered_cutoffs=restore or selected),
        control_scope='C-and-explicit-D-only',E_F_gate_execution=False,cutoff_write=False,
        cache_restore='NORMAL_REBUILD',camera_io=False))


def forward(ap,cp,bank,pack,*,selected=False):
    manifest,clips=prepared(pack,selected=selected)
    need(words(ap)==[x.hex() for x in STOCK_WORDS],'First sound installation requires stock seven C words')
    after=[w.hex() for w in pin_plan._ap_after({r:len(v) for r,v in clips.items()})]
    tail=bytearray(TAIL)
    for role in ('sha','kasha'):
        at,capacity=pin_plan.SLOTS[role];start=at-ORIGINAL_EOF
        tail[start:start+capacity]=clips[role]+bytes(capacity-len(clips[role]))
    plan=_plan(ap,cp,bank,after,clips['ka']+bytes(256-len(clips['ka'])),bytes(tail),restore=False,runtime_words=words(ap),selected=selected)
    plan.pop('plan_id');plan['controls']=manifest['controls'];plan['native_lengths']={r:len(v) for r,v in clips.items()}
    if selected:plan['controls_profile']=SELECTED_CONTROLS
    return seal(plan)


def restore(ap,cp,bank,original):
    need(original['eof']==ORIGINAL_EOF and original['ap_words']==[x.hex() for x in STOCK_WORDS],
         'Only authenticated earliest stock sound C originals are admitted')
    plan=_plan(ap,cp,bank,original['ap_words'],bytes.fromhex(original['head_hex']),b'',
        restore=True,runtime_words=original['installed_ap_words'])
    plan.pop('plan_id');plan['installed_native_lengths']=original['native_lengths']
    if original.get('runtime_profile') is not None:plan['restore_runtime_profile']=original['runtime_profile']
    return seal(plan)


def validate(plan):
    need(type(plan) is dict and plan.get('schema')==SCHEMA and seal(plan)==plan,'Sound scoped plan integrity differs')
    restore=plan['direction']=='restore';need(restore or plan['direction']=='forward','Explicit sound direction required')
    need(plan['cutoff_write'] is False and plan['E_F_gate_execution'] is False,'Sound scope differs')
    need(plan['source']['ap']['size']==LIMITS['ap'] and plan['source']['cp']['size']==LIMITS['cp'],'Sound geometry differs')
    rows=plan['ap_windows'];need([r['offset'] for r in rows]==list(AP_OFFSETS),'Only fixed seven sound words allowed')
    b=plan['bank'];need(ORIGINAL_EOF<=b['source_eof']<=TARGET_EOF and b['target_eof']==(ORIGINAL_EOF if restore else TARGET_EOF),'Sound EOF authority differs')
    need(restore or b['source_eof']==ORIGINAL_EOF,'First sound source EOF differs')
    for key,size in (('before_head_hex',256),('after_head_hex',256),('before_tail_hex',b['source_eof']-ORIGINAL_EOF),('after_tail_hex',b['target_eof']-ORIGINAL_EOF)):
        need(len(bytes.fromhex(b[key]))==size,'Sound C packet size differs')
    for row in rows:need(len(bytes.fromhex(row['before_hex']))==len(bytes.fromhex(row['after_hex']))==4,'Sound word width differs')
    if restore:
        need('controls_profile' not in plan,'Forward selected controls cannot authorize restoration')
        need([r['after_hex'] for r in rows]==[x.hex() for x in STOCK_WORDS],'Restoration AP target differs')
        sizes=plan['installed_native_lengths']
        need(set(sizes)==set(pin_plan.SLOTS) and all(type(sizes[r]) is int and 0<sizes[r]<=pin_plan.SLOTS[r][1] and sizes[r]%64==0 for r in sizes),'Registered sound lengths differ')
        runtime_profile=plan.get('restore_runtime_profile')
        if runtime_profile is None:
            need(plan['runtime_words']==[w.hex() for w in pin_plan._ap_after(sizes)],'Restore runtime endpoint must come from registered installed descriptors')
        else:
            need(runtime_profile==R066_RESTORE_PROFILE and b['source_eof']==108480 and sizes==R066_LENGTHS
                 and plan['runtime_words']==[w.hex() for w in pin_plan.AP_BEFORE], 'Only the exact R066 restore runtime profile is admitted')
            need([r['before_hex'] for r in rows] in ([w.hex() for w in pin_plan.AP_BEFORE],[w.hex() for w in STOCK_WORDS]),
                 'R066 restore current disk descriptor endpoint differs')
    else:
        need('restore_runtime_profile' not in plan,'Restore runtime profile cannot authorize a forward install')
        need([r['before_hex'] for r in rows]==[x.hex() for x in STOCK_WORDS],'First sound AP source differs')
        c=plan['controls']
        if plan.get('controls_profile')==SELECTED_CONTROLS:_selected_controls(c)
        else:
            need('controls_profile' not in plan,'Unknown sound controls profile')
            need(c['recock_enabled'] is True and c['recock_gap_ms']==40 and c['cutoff_seconds']==0.02,'First sound controls differ (Kasha internal20ms; body threshold remains1/8)')
        sizes=plan['native_lengths']
        need(set(sizes)==set(pin_plan.SLOTS) and all(type(sizes[r]) is int and 0<sizes[r]<=pin_plan.SLOTS[r][1] and sizes[r]%64==0 for r in sizes),'Bounded native sound lengths required')
        need([w.hex() for w in pin_plan._ap_after(sizes)]==[r['after_hex'] for r in rows],'Sound target descriptor layout differs')
        need(plan['runtime_words']==[w.hex() for w in STOCK_WORDS],'First sound runtime words differ')
    return plan


def check(plan,images,*,target):
    validate(plan);ap,cp,bank=(images[k] for k in ('ap','cp','bank'))
    dependencies(ap,cp,enabled=None if plan['direction']=='restore' else True,
                 registered_cutoffs=plan['direction']=='restore' or plan.get('controls_profile')==SELECTED_CONTROLS)
    side='after' if target else 'before';b=plan['bank']
    for row in plan['ap_windows']:
        need(ap[row['offset']:row['offset']+4].hex()==row[side+'_hex'],'Sound C AP endpoint differs')
    need(len(bank)==b['target_eof' if target else 'source_eof'] and bank[:256].hex()==b[side+'_head_hex']
         and bank[ORIGINAL_EOF:].hex()==b[side+'_tail_hex'],'Sound C bank endpoint/EOF differs')
    return dict(C_D_verified=True,E_F_gate_execution=False,observed_files={r:identity(raw) for r,raw in images.items()},
        semantic_whole_target_verified=False)


def packets(plan):
    validate(plan);out={}
    for index,side in enumerate(('before','after')):
        data=bytes.fromhex(plan['bank'][side+'_head_hex']+plan['bank'][side+'_tail_hex'])
        raw=pin_plan.PACK_HEADER.pack(b'M4PIND01',bytes.fromhex(plan['plan_id']),index,len(data))+data
        need(0<len(raw)<65536,'Sound C packet exceeds strict upload bound')
        out['source' if index==0 else 'target']=dict(data=raw,upload_path='/tmp/jiritsu/m4.sound-scope.'+('source' if index==0 else 'target')+'.bin')
    return out


def header(plan):
    validate(plan);array=lambda raw:'{'+','.join(str(x) for x in raw)+'}'
    lines=['struct Window {unsigned long offset;unsigned int length,chip;const unsigned char *before,*after;};']
    for i,w in enumerate(plan['ap_windows']):
        for side in ('before','after'):lines.append('static const u8 %s_%d[]=%s;'%(side,i,array(bytes.fromhex(w[side+'_hex']))))
    lines+=['static const struct Window windows[]={'+','.join('{%dUL,4,0,before_%d,after_%d}'%(w['offset'],i,i) for i,w in enumerate(plan['ap_windows']))+'};',
        'static const u32 window_count=7;',
        'static const u32 scoped_restore=%d;'%int(plan['direction']=='restore'),
        'static const u32 target_bank_size=%d;'%plan['bank']['target_eof'],
        'static const u32 allow_target_runtime=%d;'%int(plan['direction']=='restore'),
        'static const u64 file_sizes[]={%dUL,%dUL};'%(LIMITS['ap'],plan['bank']['source_eof']),
        'static const u8 plan_id[32]='+array(bytes.fromhex(plan['plan_id']))+';',
        'static const u8 previous_plan_id[32]='+array(bytes.fromhex(plan['plan_id']))+';',
        'static const u8 runtime_ap_words[7][4]={'+','.join(array(bytes.fromhex(h)) for h in plan['runtime_words'])+'};']
    for name,row in packets(plan).items():
        raw=row['data'];lines+=['static const u32 %s_packet_bytes=%d;'%(name,len(raw)),
            'static const u8 %s_packet_sha[32]=%s;'%(name,array(sha256(raw).digest())),
            'static const char %s_packet_path[]="%s";'%(name,row['upload_path'])]
    return ('\n'.join(lines)+'\n').encode()


def build(plan,output,*,compiler):
    validate(plan);output=Path(output);need(not output.exists() and output.parent.is_dir(),'New sound build directory required')
    output.mkdir(mode=0o700);source=Path(__file__).with_name('data')/'sound-scope.c'
    canonical=Path(__file__).resolve().parents[2]/'native/sound-scope/program.c'
    for p in (source,canonical):
        if p.exists():need(sha256(read_private(p,65536)).hexdigest()==NATIVE_SHA,'Sound native source binding differs')
    _write(output/'patch_manifest.h',header(plan))
    env=dict(os.environ,ZIG_GLOBAL_CACHE_DIR=str(output/'zig-global'),ZIG_LOCAL_CACHE_DIR=str(output/'zig-local'))
    need(subprocess.run([str(compiler),'version'],capture_output=True,text=True,check=True,env=env).stdout.strip()=='0.13.0','Reviewed offline Zig0.13 required')
    common=[str(compiler),'cc','-target','aarch64-linux-gnu','-std=c11','-O2','-ffreestanding','-fno-builtin','-I',str(output)]
    subprocess.run(common+['-DM4_FL23_TARGET_ABI_CHECK','-c',str(source),'-o',str(output/'abi.o')],capture_output=True,check=True,env=env,timeout=120)
    flags=['-Wall','-Wextra','-Werror','-shared','-fPIC','-fno-stack-protector','-fno-unwind-tables','-fno-asynchronous-unwind-tables','-nostdlib','-g0','-Wl,--strip-debug','-Wl,--no-undefined','-Wl,--build-id=none','-Wl,-Bsymbolic','-Wl,-z,noexecstack']
    blobs=[]
    for suffix in ('','-repeat'):
        p=output/('sound-scope'+suffix+'.so');subprocess.run(common+flags+[str(source),'-o',str(p)],capture_output=True,check=True,env=env,timeout=120)
        p.chmod(0o600);raw=read_private(p,65535);_elf(raw);blobs.append(raw)
    need(blobs[0]==blobs[1] and sha256(read_private(source,65536)).hexdigest()==NATIVE_SHA,'Sound double build differs')
    result=dict(worker_built=True,worker=dict(path=str(output/'sound-scope.so'),**identity(blobs[0]),source_sha256=NATIVE_SHA,double_build_identical=True),
        target_abi_sha256=sha256(read_private(output/'abi.o',1024*1024)).hexdigest(),plan_id=plan['plan_id'])
    _write(output/'build.json',_json(result))
    from .build_scratch import discard_caches
    discard_caches(output);return result


class Protocol:
    def __init__(self,plan):self.plan=deepcopy(validate(plan));self.step=0;self.pending=None;self.nonces=set();self.failed=False;self.identities=None;self.barrier=False
    def unknown(self):self.failed=True;self.pending=None
    def request(self,mode,nonce):
        need(not self.failed and self.pending is None and self.step<3 and mode==(0,1,3)[self.step]
             and type(nonce) is bytes and len(nonce)==16 and any(nonce) and nonce not in self.nonces,'Sound mode/nonce/replay differs')
        need(mode!=1 or self.barrier,'Sound C/D source readback required')
        self.nonces.add(nonce);self.pending=(mode,nonce)
        return REQUEST.pack(b'M4PF0001',mode,0,nonce,bytes.fromhex(self.plan['plan_id']))
    def accept(self,raw):
        try:
            need(self.pending is not None and type(raw) is bytes and len(raw)==REPORT.size,'Missing sound native report')
            f=REPORT.unpack(raw);mode,nonce=self.pending
            need(f[:4]==(b'M4PFR001',1,mode,9) and f[4]==(8 if mode==1 else 0)
                and all(f[i]==0 for i in (5,6,7,8,9,10,20)) and f[11]>0,'Sound native phase/status/root differs')
            need(f[18]==bytes.fromhex(self.plan['plan_id']) and f[19]==nonce,'Sound native immutable ticket/nonce differs')
            need(f[14]==LIMITS['ap'] and f[17]==self.plan['bank']['target_eof' if mode in (1,3) else 'source_eof'],'Sound native geometry differs')
            ids=f[12],f[13],f[15],f[16],f[11]
            need(f[13]>0 and f[16]>0 and (self.identities is None or self.identities==ids),'Sound PID/FD identity changed')
            self.identities=ids;self.pending=None;self.step+=1
            return dict(mode=mode,phase=9,status=0,pid=f[11],native_completed=True)
        except BaseException:self.unknown();raise
    def confirm(self,images):
        try:
            need(not self.failed and self.pending is None and self.step in (1,3),'Sound complete inspect required')
            result=check(self.plan,images,target=self.step==3)
            if self.step==1:self.barrier=True
            return result
        except BaseException:self.unknown();raise
