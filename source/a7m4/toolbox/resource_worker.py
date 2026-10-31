"""Internal fixed-UXC atomic replacement builder and finite receipt protocol.

This is a building block for the restricted looks/restore planners. It is not
a public arbitrary-path or patch-manifest device API. No device import occurs.
"""
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import struct
import subprocess

from ..resource_profile import RESOURCES as RESOURCE_FILENAMES
from .program_worker import _elf, _save, _read_identity

DATA = Path(__file__).with_name('data')
SOURCE = DATA/'resource-worker.c'
SHA_SOURCE = DATA/'resource-sha256.h'
SOURCE_SHA256='c588e0d41fea9f59c2f35d6fe43a542f557a33ec40f8af55043902bd9af1c750'
SHA_SOURCE_SHA256='a189ef6a033fabf465dbd08d11ad3e1d2653b65e8d81c7a82499c66ede8df4d3'
REQUEST_PATH='/tmp/jiritsu/m4.resource.request'
RESULT_PATH='/tmp/jiritsu/m4.resource.result'
REQUEST=struct.Struct('<8sII16s32s7Q')
REPORT=struct.Struct('<8s4I6q11Q32s16s32s')
KEYS=('magic version mode phase commits status remount readonly cleanup euid pid '
      'dev ino size uid gid modebits fs_type fs_unit fs_avail backup_dev backup_ino observed nonce plan').split()
LIMIT=16*1024*1024


def need(ok,message):
    if not ok:raise ValueError(message)


def canonical(value):
    return json.dumps(value,ensure_ascii=True,sort_keys=True,separators=(',',':'),allow_nan=False).encode()


def identity(value):
    need(type(value) is dict and set(value)=={'size','sha256'},'Exact size/SHA identity required')
    need(type(value['size']) is int and 0<value['size']<=LIMIT,'Resource file size outside bound')
    need(type(value['sha256']) is str and re.fullmatch('[0-9a-f]{64}',value['sha256']),'Resource SHA differs')
    return dict(value)


def hx(value):
    need(type(value) is str and re.fullmatch('[0-9a-f]*',value) and len(value)%2==0,'Canonical hex required')
    return bytes.fromhex(value)


def resource_plan(target_path,source,target,windows,append=b'',*,pending_target_sizes=None):
    """Normalize a single allowlisted, byte-exact feature transition."""
    need(target_path in {'/usr/share/app/'+x for x in RESOURCE_FILENAMES},'Unknown resource destination')
    source,target=identity(source),identity(target)
    pending=list(pending_target_sizes) if pending_target_sizes is not None else [target['size']]
    need(0<len(pending)<=8 and pending[0]==target['size'] and all(type(n) is int and 0<n<=LIMIT for n in pending),'Complete remaining resource allocation sizes required')
    need(type(append) is bytes and target['size']==source['size']+len(append),'Append-only size required')
    need(type(windows) is list and len(windows)<=128,'Bounded windows required')
    rows=[];total=len(append)
    for row in windows:
        need(type(row) is dict and set(row)=={'offset','before_hex','after_hex'},'Exact resource window fields required')
        a,b=hx(row['before_hex']),hx(row['after_hex']);at=row['offset']
        need(type(at) is int and 0<=at<=source['size']-len(a) and 0<len(a)<=4096 and len(a)==len(b) and a!=b,'Invalid resource window')
        rows.append(dict(row));total+=len(a)+len(b)
    rows.sort(key=lambda r:r['offset']);end=0
    for row in rows:
        need(row['offset']>=end,'Overlapping resource windows')
        end=row['offset']+len(bytes.fromhex(row['before_hex']))
    need((rows or append) and source!=target and total<=43008,'Nonempty resource transition exceeds helper budget')
    plan=dict(schema='a7m4-resource-plan/1',target_path=target_path,source=source,target=target,
              windows=rows,append_hex=append.hex(),replacement='atomic-new-inode',automatic_inverse=False,pending_target_sizes=pending)
    plan['plan_id']=sha256(canonical(plan)).hexdigest()
    return plan


def validate_plan(plan):
    need(type(plan) is dict and set(plan)=={'schema','target_path','source','target','windows','append_hex','replacement','automatic_inverse','pending_target_sizes','plan_id'},'Unknown resource plan')
    expected=resource_plan(plan['target_path'],plan['source'],plan['target'],plan['windows'],hx(plan['append_hex']),pending_target_sizes=plan['pending_target_sizes'])
    need(expected==plan,'Resource plan identity/content differs')
    return expected


def from_component(component):
    need(component.get('source',{}).get('kind')=='resource','Only resource component accepted')
    return resource_plan(component['target_path'],{k:component['source'][k] for k in ('size','sha256')},
        component['target'],[{k:r[k] for k in ('offset','before_hex','after_hex')} for r in component['windows']],
        hx(component['append']['after_hex']))


def render_header(plan):
    validate_plan(plan)
    arr=lambda raw:'{'+','.join(map(str,raw))+'}'
    lines=['struct Window{U offset,size;const B*before,*after;};']
    for j,row in enumerate(plan['windows']):
        for side in ('before','after'):
            lines.append('static const B %s_%d[]=%s;'%(side,j,arr(hx(row[side+'_hex']))))
    rows=['{%dUL,%dUL,before_%d,after_%d}'%(r['offset'],len(hx(r['before_hex'])),j,j) for j,r in enumerate(plan['windows'])]
    lines.append('static const struct Window windows[]={'+(','.join(rows) if rows else '{0,0,0,0}')+'};')
    lines.append('static const W window_count=%d;'%len(rows))
    lines.append('static const U allocation_sizes[]={'+','.join(str(n)+'UL' for n in plan['pending_target_sizes'])+'};')
    lines.append('static const W allocation_count=%d;'%len(plan['pending_target_sizes']))
    for name,size in (('source_size',plan['source']['size']),('target_size',plan['target']['size']),('append_size',len(hx(plan['append_hex'])))):
        lines.append('static const U %s=%dUL;'%(name,size))
    for name,raw in (('plan_id',bytes.fromhex(plan['plan_id'])),('source_hash',bytes.fromhex(plan['source']['sha256'])),
                     ('target_hash',bytes.fromhex(plan['target']['sha256'])),('append_data',hx(plan['append_hex']) or b'\0')):
        lines.append('static const B %s[]=%s;'%(name,arr(raw)))
    for name,path in (('actual_path',plan['target_path']),('stage_path','/usr/share/app/.a7m4-'+plan['plan_id']+'.stage'),
                      ('backup_path','/usr/share/app/.a7m4-'+plan['plan_id']+'.original')):
        lines.append('static const char %s[]=%s;'%(name,json.dumps(path)))
    return ('\n'.join(lines)+'\n').encode()


def build_resource_worker(plan,output,*,compiler):
    validate_plan(plan);folder=Path(output).absolute()
    need(not folder.exists() and folder.parent.is_dir() and not any(p.is_symlink() for p in (folder,*folder.parents)),'New real build directory required')
    need(compiler is not None,'Bundled offline Zig 0.13.0 required')
    sources={SOURCE:SOURCE.read_bytes(),SHA_SOURCE:SHA_SOURCE.read_bytes()}
    need(sha256(sources[SOURCE]).hexdigest()==SOURCE_SHA256
         and sha256(sources[SHA_SOURCE]).hexdigest()==SHA_SOURCE_SHA256,'Reviewed resource worker source pin differs')
    folder.mkdir(mode=0o700);header=render_header(plan);_save(folder/'resource-plan.h',header)
    _save(folder/'resource-sha256.h',sources[SHA_SOURCE]);_save(folder/'plan.json',canonical(plan)+b'\n')
    env=dict(os.environ,ZIG_GLOBAL_CACHE_DIR=str(folder/'zig-global'),ZIG_LOCAL_CACHE_DIR=str(folder/'zig-local'))
    command=[os.fspath(compiler)]
    version=subprocess.run(command+['version'],check=True,capture_output=True,text=True,timeout=30,env=env).stdout.strip()
    need(version=='0.13.0','Reviewed Zig 0.13.0 required')
    flags=['cc','-target','aarch64-linux-gnu','-std=c11','-O2','-ffreestanding','-fno-builtin','-Wall','-Wextra','-Werror',
        '-shared','-fPIC','-fno-stack-protector','-fno-unwind-tables','-fno-asynchronous-unwind-tables','-nostdlib',
        '-g0','-Wl,--strip-debug','-Wl,--no-undefined','-Wl,--build-id=none','-Wl,-Bsymbolic','-Wl,-z,noexecstack','-I',str(folder)]
    raws=[]
    for name in ('resource-worker.so','resource-worker-repeat.so'):
        path=folder/name
        subprocess.run(command+flags+[str(SOURCE),'-o',str(path)],check=True,capture_output=True,timeout=180,env=env)
        raw=path.read_bytes();need(0<len(raw)<65536,'Every helper upload must be below 65536B');_elf(raw);path.chmod(0o600);raws.append(raw)
    need(raws[0]==raws[1] and all(p.read_bytes()==raw for p,raw in sources.items()),'Double build/source identity differs')
    result=dict(schema='a7m4-resource-worker-build/1',plan_id=plan['plan_id'],worker_built=True,
        worker=dict(path=str(folder/'resource-worker.so'),size=len(raws[0]),sha256=sha256(raws[0]).hexdigest()),
        source_sha256={p.name:sha256(raw).hexdigest() for p,raw in sources.items()},double_build_identical=True,
        camera_io=False,network_io=False,device_validation='not-performed',
        request=dict(path=REQUEST_PATH,bytes=REQUEST.size),report=dict(path=RESULT_PATH,bytes=REPORT.size))
    _save(folder/'build.json',canonical(result)+b'\n');return result


class ResourceProtocol:
    def __init__(self,plan):
        self.plan=deepcopy(validate_plan(plan));self.state='READY';self.pending=None;self.previous=None
        self.source=None;self.current=None;self.process=None;self.nonces=set();self.barrier=None;self.attributes=None

    def unknown(self):self.state='STOP_UNKNOWN'

    def request(self,mode,nonce):
        need(self.state=='READY' and self.pending is None,'Resource transaction unknown/pending; no replay')
        need(type(mode) is int and mode=={None:0,0:1,1:3,3:4}.get(self.previous),'Resource phase order differs')
        need(type(nonce) is bytes and len(nonce)==16 and any(nonce) and nonce not in self.nonces,'Fresh unique nonce required')
        if mode in (1,4):need(self.barrier==('source' if mode==1 else 'target'),'Complete fresh host readback required')
        self.nonces.add(nonce);self.pending=(mode,nonce);self.barrier=None
        return REQUEST.pack(b'M4RSQ002',mode,0,nonce,bytes.fromhex(self.plan['plan_id']),*(self.source or (0,0)),*(self.current or (0,0)),*(self.attributes or (0,0,0)))

    def accept(self,raw):
        need(self.state=='READY' and self.pending is not None,'No pending resource phase')
        try:
            need(type(raw) is bytes and len(raw)==REPORT.size,'Partial resource report: STOP_UNKNOWN')
            r=dict(zip(KEYS,REPORT.unpack(raw)));mode,nonce=self.pending;side='source' if mode==0 else 'target'
            need(r['magic']==b'M4RSR001' and r['version']==1 and r['mode']==mode and r['nonce']==nonce
                 and r['plan']==bytes.fromhex(self.plan['plan_id']),'Resource report plan/nonce differs')
            need(r['phase']==9 and all(r[k]==0 for k in ('status','remount','readonly','cleanup','euid')),'Resource native failure: STOP_UNKNOWN')
            need(r['commits']==int(mode==1) and r['pid']>1 and (self.process is None or self.process==r['pid']),'Native process or commit count differs')
            need(r['size']==self.plan[side]['size'] and r['observed'].hex()==self.plan[side]['sha256']
                 and r['dev']>0 and r['ino']>0 and r['uid']<=0xffffffff and r['gid']<=0xffffffff and r['modebits']&0o170000==0o100000,'Resource identity differs')
            need(r['fs_type']==0xef53 and 0<r['fs_unit']<=1048576,'Fresh /usr space measurement missing')
            required=8388608+(sum(((n+r['fs_unit']-1)//r['fs_unit']+4)*r['fs_unit'] for n in self.plan['pending_target_sizes']) if mode in (0,1) else 0)
            need(r['fs_avail']>=required,'Atomic replacement space reserve differs')
            attributes=(r['uid'],r['gid'],r['modebits'])
            need(self.attributes is None or self.attributes==attributes,'Resource source attributes changed')
            self.attributes=attributes
            now=(r['dev'],r['ino']);backup=(r['backup_dev'],r['backup_ino'])
            if mode==0:self.source=now
            elif mode==1:need(now!=self.source and backup==self.source,'Atomic inode replacement/backup differs')
            else:need(now==self.current and backup==self.source,'Cross-phase resource inode differs')
            self.current=now;self.process=r['pid'];self.pending=None;self.previous=mode
            if mode==4:self.state='COMPLETE'
            return {k:(v.decode() if k=='magic' else v.hex()) if isinstance(v,bytes) else v for k,v in r.items()}
        except BaseException:self.unknown();raise

    def confirm_readback(self,path):
        need(self.state=='READY' and self.pending is None and self.previous in (0,3),'Inspect before complete resource readback')
        try:
            side='source' if self.previous==0 else 'target';observed=_read_identity(path)
            need(observed==self.plan[side],'Full resource readback differs: STOP_UNKNOWN')
            self.barrier=side;return dict(status='FULL_READBACK_VERIFIED',endpoint=side,identity=observed,plan_id=self.plan['plan_id'])
        except BaseException:self.unknown();raise
