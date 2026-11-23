"""Original AP runtime byte proof: read-only native maps and /proc/self/mem.

A new kernel boot or PID alone is never a load proof. Expected windows cover
all known product-modifiable AP regions plus the actual original-backup diff.
No device discovery, memory write, COW, WBI or program write is provided here.
"""
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import struct
import subprocess

from .restore_authority import validate_plan as validate_restore_authority
from . import original_restore as diff
from .capture_inputs import read_private
from .native_actions import NativeActions

SOURCE=Path(__file__).with_name('data')/'original-ap-load.c'
SOURCE_SHA256='2edb992f99ed110d312c56661df796c156b9850ce83c646303340a28298751ab'
REQUEST_PATH='/tmp/jiritsu/a7m4.original-ap-load.request'
RESULT_PATH='/tmp/jiritsu/a7m4.original-ap-load.result'
REPORT=struct.Struct('<8sII16s32s5q3Q4I40s8s')
REQUEST=struct.Struct('<8s16s32s8s')


def _json(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()


def _ranges(master,original):
    from ..research.pin_plan import AP_OFFSETS
    rows=[(at,4) for at in AP_OFFSETS]
    data=Path(__file__).with_name('data')
    fl23=json.loads(read_private(data/'looks-fl23-private.json',1024*1024))
    rows.extend((w['offset'],len(bytes.fromhex(w['after_hex']))) for w in fl23['programs']['ap']['windows'])
    stock=json.loads(read_private(data/'looks-stock-runtime.json',1024*1024))
    for key in ('stock-carrier','title'):
        rows.extend((w['va'],w['size']) for w in stock['compiled'][key]['sections'])
    rows.append((stock['menu_offset'],4))
    playback=json.loads(read_private(data/'looks-playback-custom1.json',65536))
    rows.extend(((playback['hook_offset'],4),(playback['helper_offset'],max(playback[k] for k in
        ('helper_bytes','old_helper_bytes','stock_helper_bytes')))))
    # Include ELF PT_LOAD extent fields changed by the display builder.
    if original[:4]!=b'\x7fELF':raise ValueError('Original AP ELF required for load proof')
    phoff=struct.unpack_from('<Q',original,32)[0];phsize,count=struct.unpack_from('<HH',original,54)
    if phsize!=56 or not 0<count<=128 or phoff+phsize*count>len(original):raise ValueError('Original AP ELF bounds differ')
    for i in range(count):
        at=phoff+i*phsize;kind,flags=struct.unpack_from('<II',original,at)
        if kind==1 and flags==5:rows.extend(((at+32,8),(at+40,8)))
    ap=next(r for r in master['objects'] if r['kind']=='ap')
    rows.extend((w['offset'],len(bytes.fromhex(w['after_hex']))) for w in ap['windows'])
    merged=[]
    for lo,size in sorted(rows):
        hi=lo+size
        if not 0<=lo<hi<=len(original):raise ValueError('Known original AP probe region is outside this firmware')
        if merged and lo<=merged[-1][1]:merged[-1]=(merged[-1][0],max(hi,merged[-1][1]))
        else:merged.append((lo,hi))
    return [dict(offset=at,expected_hex=original[at:min(at+512,hi)].hex())
            for lo,hi in merged for at in range(lo,hi,512)]


def make_plan(master, *, endpoint="original"):
    master=validate_restore_authority(master);ap=next(r for r in master['objects'] if r['kind']=='ap')
    if endpoint not in ('original','source'):raise ValueError('Unknown AP probe endpoint')
    original=read_private(ap['original_path' if endpoint=='original' else 'source_path'],160*1024*1024)
    rows=_ranges(master,original)
    if not 0<len(rows)<=256 or sum(len(bytes.fromhex(r['expected_hex'])) for r in rows)>16384:
        raise ValueError('Original AP runtime window proof exceeds bounded helper')
    result=dict(schema='a7m4-original-ap-load-plan/1',master_plan_id=master['plan_id'],ap_target=ap['target' if endpoint=='original' else 'source'],windows=rows)
    if endpoint=='source':result['endpoint']='source'
    result['plan_id']=sha256(_json(result)).hexdigest();return result


def parse_report(plan,raw,nonce,*,boot_id,pid):
    validate_probe_plan(plan)
    if type(raw) is not bytes or len(raw)!=REPORT.size or type(nonce) is not bytes or len(nonce)!=16 or not any(nonce):
        raise ValueError('Exact original AP load report/nonce required')
    values=REPORT.unpack(raw)
    magic,version,phase,bound,planid,status,euid,actualpid,close,unlink,dev,ino,size,windows,covered,aliases,comparisons,boot,reserved=values
    if (magic,version,bound,planid)!=(b'A7AL0001',1,nonce,bytes.fromhex(plan['plan_id'])) or reserved!=bytes(8):
        raise ValueError('Original AP load report framing/plan/nonce differs')
    try:actualboot=boot[:36].decode('ascii')
    except UnicodeError:raise ValueError('Invalid native boot identity') from None
    if (actualboot!=boot_id or boot[36:]!=bytes(4) or actualpid!=pid or euid or close or unlink
            or windows!=len(plan['windows']) or status>0 or status<-4095):
        raise ValueError('Original AP load process/boot/root/input-close binding differs')
    if phase not in (1,9) or status<0 and phase!=1:raise ValueError('Original AP probe phase contradicts read-only outcome')
    loaded=status==0 and phase==9 and covered==windows and aliases>0 and comparisons>=windows
    if status==0 and not loaded:raise ValueError('Original AP load completion lacks byte coverage')
    if loaded and (size!=plan['ap_target']['size'] or not ino):raise ValueError('Original AP disk identity differs')
    return dict(schema='a7m4-original-ap-load-proof/1',plan_id=plan['plan_id'],master_plan_id=plan['master_plan_id'],
        ap_target=plan['ap_target'],boot_id=actualboot,process_id=actualpid,loaded_original_ap_verified=loaded and plan.get('endpoint')!='source',
        loaded_current_ap_verified=loaded if plan.get('endpoint')=='source' else False,
        cleanup_safe=True,native_status=status,window_count=windows,covered=covered,aliases=aliases,
        report_sha256=sha256(raw).hexdigest(),no_memory_write=True,no_COW=True,camera_io=False)


def build(plan,output,*,compiler):
    validate_probe_plan(plan)
    from .program_worker import _elf
    if sha256(read_private(SOURCE,65536)).hexdigest()!=SOURCE_SHA256:raise ValueError('Original AP load source pin differs')
    output=Path(output).absolute()
    if output.exists() or not output.parent.is_dir() or any(p.is_symlink() for p in (output,*output.parents)):
        raise ValueError('New private AP load build required')
    output.mkdir(mode=0o700);lines=['static const unsigned long ap_size=%dUL;'%plan['ap_target']['size'],
        'static const unsigned char plan_id[32]={'+','.join(map(str,bytes.fromhex(plan['plan_id'])))+'};']
    for index,row in enumerate(plan['windows']):
        lines.append('static const unsigned char bytes_%d[]={%s};'%(index,','.join(map(str,bytes.fromhex(row['expected_hex'])))))
    lines.append('static const struct Window windows[]={'+','.join('{%dUL,%d,bytes_%d}'%(r['offset'],len(bytes.fromhex(r['expected_hex'])),i)
        for i,r in enumerate(plan['windows']))+'};')
    lines.append('static const unsigned int window_count=%d;'%len(plan['windows']))
    header=output/'ap-load-plan.h';header.write_text('\n'.join(lines)+'\n');header.chmod(0o600)
    env=dict(os.environ,ZIG_GLOBAL_CACHE_DIR=str(output/'zig-global'),ZIG_LOCAL_CACHE_DIR=str(output/'zig-local'))
    if subprocess.run([str(compiler),'version'],capture_output=True,text=True,check=True,timeout=20,env=env).stdout.strip()!='0.13.0':raise ValueError('Offline Zig0.13 required')
    args=[str(compiler),'cc','-target','aarch64-linux-gnu','-std=c11','-Os','-Wall','-Wextra','-Werror',
        '-shared','-fPIC','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-unwind-tables',
        '-fno-asynchronous-unwind-tables','-nostdlib','-g0','-Wl,--strip-debug','-Wl,--no-undefined',
        '-Wl,--build-id=none','-Wl,-Bsymbolic','-Wl,-z,noexecstack','-DAP_LOAD_PLAN="'+str(header)+'"']
    blobs=[]
    for name in ('ap-load.so','ap-load-repeat.so'):
        path=output/name;subprocess.run(args+['-o',str(path),str(SOURCE)],capture_output=True,text=True,check=True,timeout=180,env=env)
        raw=path.read_bytes();_elf(raw)
        if not 0<len(raw)<65536:raise ValueError('AP load ELF exceeds upload bound')
        path.chmod(0o600);blobs.append(raw)
    if blobs[0]!=blobs[1]:raise ValueError('AP load double build differs')
    from .build_scratch import discard_caches
    discard_caches(output)
    return blobs[0]


def verify_borrowed(master,channel,output,*,compiler,boot_id,pid,actions_factory=NativeActions,endpoint='original'):
    plan=make_plan(master,endpoint=endpoint);output=Path(output);output.mkdir(mode=0o700,exist_ok=False)
    binary=build(plan,output/'build',compiler=compiler);nonce=os.urandom(16)
    request=REQUEST.pack(b'A7ALQ001',nonce,bytes.fromhex(plan['plan_id']),bytes(8))
    ap=next(r for r in master['objects'] if r['kind']=='ap')
    if diff._identity(channel.file('/usr/lib/appFw.so'))!=plan['ap_target']:
        raise ValueError('Complete original AP disk readback required before runtime proof')
    actions=actions_factory(channel,output/'native')
    def accept(raw):
        path=output/'report.private.bin'
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
        return parse_report(plan,raw,nonce,boot_id=boot_id,pid=pid)
    result=actions.phase(binary,REQUEST_PATH,request,RESULT_PATH,
        accept,report_bytes=REPORT.size)
    actions.clean_packets()
    if diff._identity(channel.file('/usr/lib/appFw.so'))!=plan['ap_target']:
        raise ValueError('Original AP file changed during runtime proof')
    return dict(result,native_report_path=str(output/'report.private.bin'),nonce_hex=nonce.hex())


def validate_probe_plan(plan):
    if (type(plan) is not dict or set(plan) not in ({'schema','master_plan_id','ap_target','windows','plan_id'},
                {'schema','master_plan_id','ap_target','windows','plan_id','endpoint'})
            or 'endpoint' in plan and plan['endpoint']!='source'
            or plan['schema']!='a7m4-original-ap-load-plan/1'
            or type(plan['windows']) is not list or not 0<len(plan['windows'])<=256):
        raise ValueError('Exact bounded AP load plan required')
    for digest in (plan['master_plan_id'],plan['plan_id'],plan['ap_target'].get('sha256')):
        if type(digest) is not str or not re.fullmatch('[0-9a-f]{64}',digest):raise ValueError('AP load plan hash differs')
    size=plan['ap_target'].get('size')
    if type(size) is not int or not 0<size<=160*1024*1024:raise ValueError('Bounded original AP size required')
    end=total=0
    for row in plan['windows']:
        if type(row) is not dict or set(row)!={'offset','expected_hex'}:raise ValueError('Exact original AP window required')
        raw=row['expected_hex'];at=row['offset']
        if (type(at) is not int or at<end or type(raw) is not str or not re.fullmatch('[0-9a-f]+',raw)
                or len(raw)%2 or not 0<len(raw)//2<=512 or at+len(raw)//2>size):
            raise ValueError('Original AP window is out of bounds')
        end=at+len(raw)//2;total+=len(raw)//2
    if total>16384 or sha256(_json({k:v for k,v in plan.items() if k!='plan_id'})).hexdigest()!=plan['plan_id']:
        raise ValueError('Original AP load plan identity/content differs')
    return plan
