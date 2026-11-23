"""Read-only original runtime on an explicitly bound current AP inode.

This separate proof never authorizes a boot, labels source RAM as adopted, or
becomes the standard original-on-original-disk proof. No device discovery.
"""
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import subprocess
from .restore_authority import validate_plan as validate_restore_authority
from . import original_ap_load as old, original_restore as diff
from .capture_inputs import read_private
from .native_actions import NativeActions

SOURCE=Path(__file__).with_name('data')/'original-ap-original-on-source.c'
SOURCE_SHA256='d0ab60223eb4473e3b03dc8d44687d1af1c7aa81d4a8d061de37f4697c83c14f'
REQUEST_PATH='/tmp/jiritsu/a7m4.original-ap-original-on-source.request'
RESULT_PATH='/tmp/jiritsu/a7m4.original-ap-original-on-source.result'
REQUEST=old.REQUEST
REPORT=old.REPORT
SCHEMA='a7m4-original-ap-on-source-plan/1'
PROOF_SCHEMA='a7m4-original-ap-on-source-proof/1'


def need(ok,text):
    if not ok:raise ValueError(text)


def _json(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()


def _anchor(master,proof):
    need(type(proof) is dict and proof.get('schema')=='a7m4-original-ap-load-proof/1'
         and proof.get('master_plan_id')==master['plan_id']
         and proof.get('loaded_current_ap_verified') is False and proof.get('loaded_original_ap_verified') is False
         and proof.get('native_status') in (-84,-18)
         and all(proof.get(k) is True for k in ('cleanup_safe','no_memory_write','no_COW')),
         'Only a known complete read-only source mismatch can request the separate proof')
    raw=read_private(proof['native_report_path'],REPORT.size)
    need(len(raw)==REPORT.size and sha256(raw).hexdigest()==proof['report_sha256'],'Source probe report changed')
    nonce=bytes.fromhex(proof['nonce_hex']);plan=old.make_plan(master,endpoint='source')
    checked=old.parse_report(plan,raw,nonce,boot_id=proof['boot_id'],pid=proof['process_id'])
    need(all(proof.get(k)==v for k,v in checked.items()),'Source proof differs from its complete native report')
    values=REPORT.unpack(raw);dev,ino,size=values[10:13]
    need(dev>0 and ino>0 and size==plan['ap_target']['size'],'Source probe lacks a current inode identity')
    return dict(report_sha256=proof['report_sha256'],plan_id=plan['plan_id'],dev=dev,ino=ino,
                size=size,process_id=proof['process_id'],boot_id=proof['boot_id'])


def make_plan(master,source_proof):
    master=validate_restore_authority(master);anchor=_anchor(master,source_proof)
    ap=next(r for r in master['objects'] if r['kind']=='ap')
    source=read_private(ap['source_path'],160*1024*1024)
    original=read_private(ap['original_path'],160*1024*1024)
    need(diff._identity(source)==ap['source'] and diff._identity(original)==ap['target']
         and len(source)==len(original)==anchor['size'],'Complete fixed current/original AP endpoints required')
    rows=[]
    for row in old._ranges(master,original):
        at=row['offset'];runtime=bytes.fromhex(row['expected_hex'])
        rows.append(dict(offset=at,source_hex=source[at:at+len(runtime)].hex(),original_hex=runtime.hex()))
    value=dict(schema=SCHEMA,master_plan_id=master['plan_id'],source_ap=ap['source'],original_ap=ap['target'],
               source_anchor=anchor,windows=rows)
    value['plan_id']=sha256(_json(value)).hexdigest();return validate_plan(value)


def validate_plan(plan):
    need(type(plan) is dict and set(plan)=={'schema','master_plan_id','source_ap','original_ap','source_anchor','windows','plan_id'}
         and plan['schema']==SCHEMA,'Separate original-on-source plan required')
    for key in ('source_ap','original_ap'):
        value=plan[key]
        need(type(value) is dict and set(value)=={'size','sha256'} and type(value['size']) is int
             and 0<value['size']<=160*1024*1024 and type(value['sha256']) is str
             and re.fullmatch('[0-9a-f]{64}',value['sha256']),'Bounded whole AP identity required')
    anchor=plan['source_anchor']
    need(type(anchor) is dict and set(anchor)=={'report_sha256','plan_id','dev','ino','size','process_id','boot_id'}
         and all(type(anchor[k]) is int and anchor[k]>0 for k in ('dev','ino','size','process_id'))
         and anchor['size']==plan['source_ap']['size']==plan['original_ap']['size']
         and type(anchor['boot_id']) is str and re.fullmatch('[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',anchor['boot_id']),
         'Complete process/boot/current-inode source anchor required')
    for value in (plan['plan_id'],plan['master_plan_id'],anchor['plan_id'],anchor['report_sha256']):
        need(type(value) is str and re.fullmatch('[0-9a-f]{64}',value),'Bounded proof digest required')
    need(type(plan['windows']) is list and 0<len(plan['windows'])<=256,'Bounded AP proof windows required')
    end=total=0
    for row in plan['windows']:
        need(type(row) is dict and set(row)=={'offset','source_hex','original_hex'},'Exact dual window required')
        at=row['offset'];a=row['source_hex'];b=row['original_hex']
        need(type(at) is int and at>=end and type(a) is str and type(b) is str
             and re.fullmatch('[0-9a-f]+',a) and re.fullmatch('[0-9a-f]+',b)
             and len(a)==len(b) and len(a)%2==0 and 0<len(a)//2<=512
             and at+len(a)//2<=anchor['size'],'Dual AP window bounds differ')
        end=at+len(a)//2;total+=len(a)//2
    need(total<=16384 and sha256(_json({k:v for k,v in plan.items() if k!='plan_id'})).hexdigest()==plan['plan_id'],
         'Separate AP proof plan identity differs')
    return plan


def parse_report(plan,raw,nonce):
    validate_plan(plan)
    need(type(raw) is bytes and len(raw)==REPORT.size and type(nonce) is bytes and len(nonce)==16 and any(nonce),
         'Complete original-on-source native report required')
    (magic,version,phase,bound,planid,status,euid,pid,close,unlink,dev,ino,size,windows,covered,aliases,comparisons,boot,reserved)=REPORT.unpack(raw)
    anchor=plan['source_anchor']
    need((magic,version,bound,planid)==(b'A7AO0001',1,nonce,bytes.fromhex(plan['plan_id']))
         and reserved==bytes(8) and boot==anchor['boot_id'].encode()+bytes(4)
         and pid==anchor['process_id'] and euid==close==unlink==0
         and windows==len(plan['windows']) and -4095<=status<=0
         and phase in (1,9) and (status==0 or phase==1), 'Separate AP report framing/process/boot differs')
    loaded=status==0 and phase==9 and covered==windows and aliases>0 and comparisons>=windows
    need(status!=0 or loaded,'Separate AP proof lacks complete byte coverage')
    need((dev,ino,size)==(anchor['dev'],anchor['ino'],anchor['size']), 'Separate AP current inode binding differs')
    return dict(schema=PROOF_SCHEMA,plan_id=plan['plan_id'],master_plan_id=plan['master_plan_id'],
        source_ap=plan['source_ap'],original_ap=plan['original_ap'],source_probe_report_sha256=anchor['report_sha256'],
        disk_dev=dev,disk_inode=ino,disk_size=size,process_id=pid,boot_id=anchor['boot_id'],
        loaded_original_on_current_source_verified=loaded,loaded_current_ap_verified=False,loaded_original_ap_verified=False,
        native_status=status,window_count=windows,covered=covered,aliases=aliases,comparisons=comparisons,
        report_sha256=sha256(raw).hexdigest(),cleanup_safe=True,no_memory_write=True,no_COW=True,camera_io=False)


def build(plan,output,*,compiler):
    validate_plan(plan)
    from .program_worker import _elf
    need(sha256(read_private(SOURCE,65536)).hexdigest()==SOURCE_SHA256,'Separate AP native source changed')
    output=Path(output).absolute()
    need(not output.exists() and output.parent.is_dir() and not any(p.is_symlink() for p in (output,*output.parents)),
         'New private separate AP build required')
    output.mkdir(mode=0o700);anchor=plan['source_anchor'];array=lambda raw:'{'+','.join(map(str,raw))+'}'
    lines=['static const unsigned long ap_size=%dUL,expected_dev=%dUL,expected_ino=%dUL,expected_pid=%dUL;'%
           (anchor['size'],anchor['dev'],anchor['ino'],anchor['process_id']),
           'static const unsigned char expected_boot[36]='+array(anchor['boot_id'].encode())+';',
           'static const unsigned char plan_id[32]='+array(bytes.fromhex(plan['plan_id']))+';']
    for i,row in enumerate(plan['windows']):
        for key in ('source','original'):lines.append('static const unsigned char %s_%d[]=%s;'%(key,i,array(bytes.fromhex(row[key+'_hex']))))
    lines+=['static const struct Window windows[]={'+','.join('{%dUL,%d,source_%d,original_%d}'%
            (r['offset'],len(r['source_hex'])//2,i,i) for i,r in enumerate(plan['windows']))+'};',
            'static const unsigned int window_count=%d;'%len(plan['windows'])]
    header=output/'ap-original-on-source-plan.h';header.write_text('\n'.join(lines)+'\n');header.chmod(0o600)
    env=dict(os.environ,ZIG_GLOBAL_CACHE_DIR=str(output/'zig-global'),ZIG_LOCAL_CACHE_DIR=str(output/'zig-local'))
    need(subprocess.run([str(compiler),'version'],capture_output=True,text=True,check=True,timeout=20,env=env).stdout.strip()=='0.13.0',
         'Offline Zig0.13 required')
    args=[str(compiler),'cc','-target','aarch64-linux-gnu','-std=c11','-Os','-Wall','-Wextra','-Werror',
        '-shared','-fPIC','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-unwind-tables',
        '-fno-asynchronous-unwind-tables','-nostdlib','-g0','-Wl,--strip-debug','-Wl,--no-undefined',
        '-Wl,--build-id=none','-Wl,-Bsymbolic','-Wl,-z,noexecstack','-DAP_ORIGINAL_ON_SOURCE_PLAN="'+str(header)+'"']
    abi=output/'target-abi.o'
    subprocess.run([str(compiler),'cc','-target','aarch64-linux-gnu','-std=c11','-Wall','-Wextra','-Werror',
        '-DAP_ORIGINAL_ON_SOURCE_TARGET_ABI_CHECK','-DAP_ORIGINAL_ON_SOURCE_PLAN="'+str(header)+'"',
        '-c',str(SOURCE),'-o',str(abi)],capture_output=True,text=True,check=True,timeout=180,env=env)
    blobs=[]
    for name in ('original-on-source.so','original-on-source-repeat.so'):
        path=output/name;subprocess.run(args+['-o',str(path),str(SOURCE)],capture_output=True,text=True,check=True,timeout=180,env=env)
        raw=path.read_bytes();_elf(raw);need(0<len(raw)<65536,'Separate AP ELF exceeds upload bound');path.chmod(0o600);blobs.append(raw)
    need(blobs[0]==blobs[1],'Separate AP double build differs')
    from .build_scratch import discard_caches
    (output/'build.json').write_bytes(_json(dict(schema='a7m4-original-ap-on-source-build/1',camera_io=False,
        source_sha256=SOURCE_SHA256,header_sha256=sha256(header.read_bytes()).hexdigest(),
        target_abi_sha256=sha256(abi.read_bytes()).hexdigest(),double_build_identical=True,
        worker_sha256=sha256(blobs[0]).hexdigest(),worker_bytes=len(blobs[0])))+b'\n')
    discard_caches(output);return blobs[0]


def verify_borrowed(master,source_proof,channel,output,*,compiler,runtime_evidence,actions_factory=NativeActions):
    plan=make_plan(master,source_proof);anchor=plan['source_anchor'];output=Path(output);output.mkdir(mode=0o700,exist_ok=False)
    def guard():
        runtime=runtime_evidence()
        need(runtime.get('body_binding')==master['body_binding'] and runtime.get('fresh') is True
             and runtime.get('process_id')==anchor['process_id'] and runtime.get('boot_id')==anchor['boot_id'],
             'Original-on-source runtime identity changed')
        need(diff._identity(channel.file('/usr/lib/appFw.so'))==plan['source_ap'],'Complete current AP disk identity changed')
    guard();binary=build(plan,output/'build',compiler=compiler);guard();nonce=os.urandom(16)
    packet=REQUEST.pack(b'A7AOQ001',nonce,bytes.fromhex(plan['plan_id']),bytes(8));actions=actions_factory(channel,output/'native')
    def accept(raw):
        path=output/'report.private.bin';fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
        return parse_report(plan,raw,nonce)
    result=actions.phase(binary,REQUEST_PATH,packet,RESULT_PATH,accept,report_bytes=REPORT.size)
    actions.clean_packets();guard()
    result.update(native_report_path=str(output/'report.private.bin'),nonce_hex=nonce.hex(),full_current_disk_before_after_verified=True)
    (output/'proof.private.json').write_bytes(_json(result)+b'\n');(output/'proof.private.json').chmod(0o600)
    return result


def validate_proof(master,proof,source_proof):
    plan=make_plan(master,source_proof)
    need(type(proof) is dict and proof.get('schema')==PROOF_SCHEMA
         and proof.get('full_current_disk_before_after_verified') is True,'Complete separate host proof required')
    raw=read_private(proof['native_report_path'],REPORT.size)
    need(sha256(raw).hexdigest()==proof.get('report_sha256'),'Separate AP native report changed')
    parsed=parse_report(plan,raw,bytes.fromhex(proof['nonce_hex']))
    need(all(proof.get(k)==v for k,v in parsed.items()) and parsed['loaded_original_on_current_source_verified'] is True,
         'Original-on-source proof did not verify the expected runtime')
    return parsed
