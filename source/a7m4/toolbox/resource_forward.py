"""Offline fixed-UXC forward delta and allocation proofs; no device imports.

Separate from the original-backup restoration authority. All changed bytes,
append bytes and allocation witnesses derive from a complete source capture.
The coordinator must inspect every resource before the first persistent write.
"""
from copy import deepcopy
from hashlib import sha256
from pathlib import Path
import json
import os
import struct
import subprocess

from . import resource_worker as atomic
from .program_worker import _elf, _save, _read_identity

SCHEMA = 'a7m4-resource-forward-delta/1'
PATHS = frozenset('/usr/share/app/'+n for n in atomic.RESOURCE_FILENAMES)
UNIT = 1024
RESERVE = 8388608
MAX_WINDOWS = 128
MAX_WINDOW_BYTES = 16384
SOURCE = Path(__file__).with_name('data')/'resource-forward.c'
SOURCE_SHA256='57b3521ebe05f5acf9fe1e772adfa867b5022d1c0888687e44959b1a2467cb06'
REQUEST_PATH = '/tmp/jiritsu/m4.resource-forward.request'
RESULT_PATH = '/tmp/jiritsu/m4.resource-forward.result'
MAGIC = b'M4RF0001'
REQUEST = struct.Struct('<8sII16s32sQ3Q4I2Q16Q32s')
# First 544 bytes retain the reviewed mapping/identity diagnostic layout.
REPORT_BYTES = 640
PREFIX = struct.Struct('<8sII16s32s8I9q3Q4I4Q4I')
MAPPING = struct.Struct('<4Q')
need = atomic.need
canonical = atomic.canonical


def _blocks(windows, source_size, target_size, unit):
    result = set()
    for row in windows:
        at, size = row['offset'],len(bytes.fromhex(row['before_hex']))
        result.update(range(at//unit,(at+size-1)//unit+1))
    if target_size > source_size and source_size % unit:
        result.add(source_size//unit)
    return sorted(result)


def allocation_evidence(component, source):
    """One nonzero byte proves each touched old block is not a sparse hole."""
    source = bytes(source)
    before = component['source'];after = component['target']
    need(len(source)==before['size'] and sha256(source).hexdigest()==before['sha256'],
         'Complete resource allocation source differs')
    windows = component['windows']
    for row in windows:
        raw=bytes.fromhex(row['before_hex']);at=row['offset']
        need(source[at:at+len(raw)]==raw,'Allocation window preimage differs')
    dirty=_blocks(windows,len(source),after['size'],UNIT)
    witnesses=[];unknown=[]
    for block in dirty:
        data=source[block*UNIT:(block+1)*UNIT]
        nonzero=next((i for i,b in enumerate(data) if b),None)
        if nonzero is None:unknown.append(block)
        else:witnesses.append(dict(block=block,offset=block*UNIT+nonzero,value=data[nonzero]))
    return dict(path=component['target_path'],source_size=len(source),target_size=after['size'],
        dirty_blocks=dirty,unknown_blocks=unknown,witnesses=witnesses)


def _allocation(entry):
    need(type(entry) is dict and set(entry)=={'path','source_size','target_size','dirty_blocks','unknown_blocks','witnesses'},
         'Exact allocation evidence fields required')
    need(entry['path'] in PATHS and type(entry['source_size']) is int and type(entry['target_size']) is int
         and 0<entry['source_size']<=entry['target_size']<=atomic.LIMIT,'Fixed allocation path/size differs')
    dirty=entry['dirty_blocks'];unknown=entry['unknown_blocks'];seen=[]
    need(type(dirty) is list and dirty==sorted(set(dirty)) and len(dirty)<=256,
         'Bounded unique existing dirty blocks required')
    need(type(unknown) is list and unknown==sorted(set(unknown)),'Unknown blocks must be explicit')
    need(type(entry['witnesses']) is list and len(entry['witnesses'])<=256,'Bounded original-block witnesses required')
    for w in entry['witnesses']:
        need(set(w)=={'block','offset','value'} and type(w['block']) is int and type(w['offset']) is int
             and 0<=w['offset']<entry['source_size'] and w['offset']//UNIT==w['block']
             and type(w['value']) is int and 0<w['value']<=255,'Nonzero original-block witness required')
        seen.append(w['block'])
    need(len(set(seen))==len(seen) and not set(seen).intersection(unknown)
         and sorted(seen+unknown)==dirty and all(type(b) is int and 0<=b<(entry['source_size']+UNIT-1)//UNIT for b in dirty),
         'Each touched existing block must be witnessed or conservatively charged')
    return deepcopy(entry)


def allocation_budget(entries):
    entries=[_allocation(e) for e in entries]
    need(0<len(entries)<=8 and len({e['path'] for e in entries})==len(entries),
         'All remaining unique resources required')
    data=sum((e['target_size']+UNIT-1)//UNIT-(e['source_size']+UNIT-1)//UNIT+len(e['unknown_blocks']) for e in entries)
    return dict(unit=UNIT,potential_new_data_blocks=data,required_bytes=(4*data+2)*UNIT,
        reserve_bytes=RESERVE,witness_count=sum(len(e['witnesses']) for e in entries))


def from_component(component, source, *, pending):
    # Reuse only the existing allowlist/byte-window validator, not its atomic
    # allocation rule or replacement semantics.
    old=atomic.from_component(component)
    rows=[]
    for row in old['windows']:
        a,b=bytes.fromhex(row['before_hex']),bytes.fromhex(row['after_hex'])
        for i in range(0,len(a),512):
            if a[i:i+512]!=b[i:i+512]:
                rows.append(dict(offset=row['offset']+i,before_hex=a[i:i+512].hex(),after_hex=b[i:i+512].hex()))
    need(len(rows)<=MAX_WINDOWS and sum(len(bytes.fromhex(w['before_hex'])) for w in rows)<=MAX_WINDOW_BYTES,
         'Forward resource window bound exceeded')
    protected=set()
    for w in rows:protected.update(range(w['offset']//4096,(w['offset']+len(bytes.fromhex(w['before_hex']))-1)//4096+1))
    if old['target']['size']>old['source']['size'] and old['source']['size']%4096:
        protected.add(old['source']['size']//4096)
    protect=[dict(offset=page*4096+i,size=512) for page in sorted(protected) for i in range(0,4096,512)]
    need(len(protect)<=128,'Protected page snapshot exceeds bounded native contract')
    reconstructed=bytearray(source)
    for row in rows:
        a,b=bytes.fromhex(row['before_hex']),bytes.fromhex(row['after_hex']);at=row['offset']
        need(reconstructed[at:at+len(a)]==a,'Forward complete preimage differs')
        reconstructed[at:at+len(a)]=b
    reconstructed.extend(bytes.fromhex(old['append_hex']))
    need(dict(size=len(reconstructed),sha256=sha256(reconstructed).hexdigest())==old['target'],
         'Forward windows/append do not reconstruct complete target')
    entries=[_allocation(e) for e in pending]
    own=allocation_evidence(component,source)
    need(entries and entries[0]==own,'Current complete allocation evidence must lead remaining scope')
    value=dict(schema=SCHEMA,target_path=old['target_path'],source=old['source'],target=old['target'],
        windows=rows,append_hex=old['append_hex'],protection=protect,pending=entries,
        replacement='same-inode-window-append',automatic_inverse=False,truncate=False)
    value['plan_id']=sha256(canonical(value)).hexdigest()
    validate_plan(value)
    return value


def validate_plan(plan):
    need(type(plan) is dict and set(plan)=={'schema','target_path','source','target','windows','append_hex','protection','pending','replacement','automatic_inverse','truncate','plan_id'},
         'Unknown forward resource contract')
    need(plan['schema']==SCHEMA and plan['replacement']=='same-inode-window-append'
         and plan['automatic_inverse'] is False and plan['truncate'] is False,'Forward-only resource contract required')
    atomic.resource_plan(plan['target_path'],plan['source'],plan['target'],plan['windows'],bytes.fromhex(plan['append_hex']))
    need(len(plan['windows'])<=128 and all(len(bytes.fromhex(w['before_hex']))<=512 for w in plan['windows'])
         and sum(len(bytes.fromhex(w['before_hex'])) for w in plan['windows'])<=16384,'Bounded native windows required')
    pages=set()
    for w in plan['windows']:pages.update(range(w['offset']//4096,(w['offset']+len(bytes.fromhex(w['before_hex']))-1)//4096+1))
    if plan['target']['size']>plan['source']['size'] and plan['source']['size']%4096:pages.add(plan['source']['size']//4096)
    need(plan['protection']==[dict(offset=p*4096+i,size=512) for p in sorted(pages) for i in range(0,4096,512)]
         and len(plan['protection'])<=128,'Exact changed/old-EOF page protection required')
    allocation_budget(plan['pending'])
    own=plan['pending'][0]
    need((own['path'],own['source_size'],own['target_size'])==(plan['target_path'],plan['source']['size'],plan['target']['size'])
         and set(_blocks(plan['windows'],own['source_size'],own['target_size'],UNIT)).issubset(own['dirty_blocks']),'Allocation scope omitted a changed block')
    digest=dict(plan);digest.pop('plan_id')
    need(plan['plan_id']==sha256(canonical(digest)).hexdigest(),'Forward plan identity differs')
    return deepcopy(plan)


def render_header(plan):
    p=validate_plan(plan)
    arr=lambda b:'{'+','.join(map(str,b))+'}'
    lines=['#define RD_SOURCE_SIZE %dUL'%p['source']['size'],
           '#define RD_TARGET_SIZE %dUL'%p['target']['size'],
           '#define RD_PATH '+json.dumps(p['target_path']),
           'static const u8 rd_plan_id[32]='+arr(bytes.fromhex(p['plan_id']))+';']
    for i,w in enumerate(p['windows']):
        for side in ('before','after'):lines.append('static const u8 w_%s_%d[]=%s;'%(side,i,arr(bytes.fromhex(w[side+'_hex']))))
    rows=['{%dUL,%d,w_before_%d,w_after_%d}'%(w['offset'],len(bytes.fromhex(w['before_hex'])),i,i) for i,w in enumerate(p['windows'])]
    lines+=['static const struct DeltaWindow rd_windows[]={'+(','.join(rows) or '{0,0,0,0}')+'};',
            'static const u32 rd_window_count=%d;'%len(rows),
            'struct Protect{u64 at;u32 size;};',
            'static const struct Protect protection[]={'+(','.join('{%dUL,%d}'%(w['offset'],w['size']) for w in p['protection']) or '{0,0}')+'};',
            'static const u32 protect_count=%d;'%len(p['protection']),
            'static const u64 append_size=%dUL;'%len(bytes.fromhex(p['append_hex'])),
            'static const u8 append_data[]='+arr(bytes.fromhex(p['append_hex']) or b'\0')+';',
            'static const u8 source_hash[32]='+arr(bytes.fromhex(p['source']['sha256']))+';',
            'static const u8 target_hash[32]='+arr(bytes.fromhex(p['target']['sha256']))+';',
            'struct Witness{u64 at;u32 value;};',
            'struct BudgetFile{const char*path;u64 source_size,target_size;u32 unknown_blocks,witness_begin,witness_count;};']
    witnesses=[];files=[]
    for e in p['pending']:
        start=len(witnesses)
        witnesses.extend('{%dUL,%d}'%(w['offset'],w['value']) for w in e['witnesses'])
        files.append('{%s,%dUL,%dUL,%d,%d,%d}'%(json.dumps(e['path']),e['source_size'],e['target_size'],len(e['unknown_blocks']),start,len(e['witnesses'])))
    lines+=['static const struct Witness witnesses[]={'+(','.join(witnesses) or '{0,0}')+'};',
            'static const u32 witness_count=%d;'%len(witnesses),
            'static const struct BudgetFile pending_files[]={'+','.join(files)+'};',
            'static const u32 pending_count=%d;'%len(files)]
    return ('\n'.join(lines)+'\n').encode()


def build_resource_worker(plan, output, *, compiler):
    p=validate_plan(plan);folder=Path(output).absolute()
    need(not folder.exists() and folder.parent.is_dir()
         and not any(q.is_symlink() for q in (folder,*folder.parents)), 'New private forward build directory required')
    canonical_source=Path(__file__).resolve().parents[2]/'native/resource-forward/resource-forward.c'
    candidates=[q for q in (SOURCE,canonical_source) if q.exists()]
    need(candidates and all(sha256(q.read_bytes()).hexdigest()==SOURCE_SHA256 for q in candidates),
         'Forward native source binding differs')
    source=candidates[0];folder.mkdir(mode=0o700)
    _save(folder/'forward-plan.h',render_header(p))
    sha_source=atomic.SHA_SOURCE.read_bytes()
    need(sha256(sha_source).hexdigest()==atomic.SHA_SOURCE_SHA256,'Reviewed SHA implementation changed')
    _save(folder/'resource-sha256.h',sha_source);_save(folder/'plan.json',canonical(p)+b'\n')
    cmd=[os.fspath(compiler)];env=dict(os.environ,ZIG_GLOBAL_CACHE_DIR=str(folder/'zig-global'),ZIG_LOCAL_CACHE_DIR=str(folder/'zig-local'))
    need(subprocess.run(cmd+['version'],capture_output=True,text=True,check=True,env=env,timeout=30).stdout.strip()=='0.13.0',
         'Reviewed offline Zig 0.13.0 required')
    abi=folder/'target-abi.o'
    subprocess.run(cmd+['cc','-target','aarch64-linux-gnu','-std=c11','-ffreestanding','-fno-builtin',
        '-DTARGET_ABI','-DPATCH_MANIFEST="forward-plan.h"','-I',str(folder),'-c',str(source),'-o',str(abi)],
        capture_output=True,check=True,env=env,timeout=180)
    abi.chmod(0o600)
    flags=['cc','-target','aarch64-linux-gnu','-std=c11','-O2','-ffreestanding','-fno-builtin','-Wall','-Wextra','-Werror',
        '-shared','-fPIC','-fno-stack-protector','-fno-unwind-tables','-fno-asynchronous-unwind-tables','-nostdlib','-g0',
        '-Wl,--strip-debug','-Wl,--no-undefined','-Wl,--build-id=none','-Wl,-Bsymbolic','-Wl,-z,noexecstack',
        '-DPATCH_MANIFEST="forward-plan.h"','-I',str(folder)]
    raw=[]
    for name in ('resource-forward.so','resource-forward-repeat.so'):
        out=folder/name
        subprocess.run(cmd+flags+[str(source),'-o',str(out)],capture_output=True,check=True,env=env,timeout=180)
        out.chmod(0o600);data=out.read_bytes();need(0<len(data)<65536,'Every forward upload must remain below64KiB');_elf(data);raw.append(data)
    need(raw[0]==raw[1] and all(sha256(q.read_bytes()).hexdigest()==SOURCE_SHA256 for q in candidates),
         'Forward double build/source identity differs')
    result=dict(worker_built=True,worker=dict(path=str(folder/'resource-forward.so'),size=len(raw[0]),sha256=sha256(raw[0]).hexdigest()),
        source_sha256=SOURCE_SHA256,target_abi_sha256=sha256(abi.read_bytes()).hexdigest(),double_build_identical=True,camera_io=False,network_io=False,
        request=dict(path=REQUEST_PATH,bytes=REQUEST.size),report=dict(path=RESULT_PATH,bytes=REPORT_BYTES))
    _save(folder/'build.json',canonical(result)+b'\n');return result


KEYS=('magic version mode nonce plan_id phase index mapping_count cross_pids cross_matches cow_attempts cow_segments flags '
      'native_status euid pid plugin_unlink close_errors readonly remount auxv_status source_status source_dev source_ino source_size '
      'source_mode source_uid source_gid source_nlink target_size page_size bytes_written bytes_cow_preserved total window_count write_attempts writes_completed').split()


class ForwardReadOnlyRefusal(ValueError):
    def __init__(self, report):
        super().__init__('Forward resource inspection refused without persistent writes')
        self.report=report


class ResourceProtocol:
    def __init__(self, plan):
        self.plan=validate_plan(plan);self.state='READY';self.pending=None;self.previous=None
        self.inspection=None;self.barrier=None;self.nonces=set()

    def unknown(self):self.state='STOP_UNKNOWN'

    def request(self, mode, nonce):
        need(type(mode) is int and mode in (0,1,3) and self.state=='READY' and self.pending is None and mode=={None:0,0:1,1:3}.get(self.previous),
             'Forward phase order differs; no replay')
        need(type(nonce) is bytes and len(nonce)==16 and any(nonce) and nonce not in self.nonces,'Fresh forward nonce required')
        if mode==1:need(self.barrier=='source','Complete fresh source readback required')
        if mode==0:values=[0]*26;runtime=bytes(32);count=0
        else:
            r=self.inspection;count=len(r['mappings'])
            values=[r['pid'],r['source_dev'],r['source_ino'],self.plan['target' if mode==3 else 'source']['size'],
                r['source_mode'],r['source_uid'],r['source_gid'],r['source_nlink'],self.plan['target']['size'],0]
            values += [v for m in r['mappings'] for v in m]
            values += [0]*(26-len(values));runtime=bytes.fromhex(r['runtime_sha256'])
        packet=REQUEST.pack(MAGIC,mode,count,nonce,bytes.fromhex(self.plan['plan_id']),*values,runtime)
        self.pending=(mode,nonce);self.nonces.add(nonce);self.barrier=None
        return packet

    def accept(self, raw):
        need(self.state=='READY' and self.pending is not None,'No pending forward request')
        try:
            mode,nonce=self.pending;p=self.plan
            need(type(raw) is bytes and len(raw)==REPORT_BYTES,'Complete forward report required')
            r=dict(zip(KEYS,PREFIX.unpack_from(raw)))
            need((r['magic'],r['version'],r['mode'],r['nonce'],r['plan_id'],r['total'])==
                 (MAGIC,1,mode,nonce,bytes.fromhex(p['plan_id']),REPORT_BYTES),'Forward plan/nonce/report differs')
            need(r['mapping_count']<=4 and r['window_count']==len(p['windows']) and r['target_size']==p['target']['size'],
                 'Forward native scope differs')
            need(not r['flags']&~1023,'Unknown forward proof flags')
            # Failed mode0 may contain incomplete mapping diagnostics (e.g.
            # an intentionally refused fifth alias). They never authorize a
            # source/mapping admission. Only the complete frozen helper's
            # zero-mutation/RO/own-loader proof permits exact temporary cleanup.
            early=dict(zip(('usr_type','usr_unit','usr_available','usr_required','append_bytes','append_attempts','append_completed','reserved2'),struct.unpack_from('<8Q',raw,544)))
            if (mode==0 and self.previous is None and r['native_status']<0 and r['phase'] in (1,2)
                    and r['pid']>1 and not any(r[k] for k in ('euid','close_errors','readonly','remount','plugin_unlink',
                        'cow_attempts','cow_segments','bytes_cow_preserved','write_attempts','writes_completed','bytes_written'))
                    and not any(early[k] for k in ('append_bytes','append_attempts','append_completed','reserved2'))
                    and not r['flags']&(4|16|256)):
                raise ForwardReadOnlyRefusal(dict(pid=r['pid'],phase=r['phase'],status=r['native_status']))
            rows=[MAPPING.unpack_from(raw,256+i*32) for i in range(4)]
            need(all(not any(row) for row in rows[r['mapping_count']:]),'Unused native mapping slot differs')
            rows=rows[:r['mapping_count']]
            for i,m in enumerate(rows):
                va,length,offset,prot=m
                need(va>0 and length>0 and not (va|length|offset)&4095 and va+length<1<<64
                     and offset+length<1<<64 and prot==1 and (not i or va>=rows[i-1][0]+rows[i-1][1]),
                     'Only ordered private readonly native source mappings admitted')
            segments=total=0
            for _,length,offset,_ in rows:
                for w in p['protection']:
                    n=min(offset+length,w['offset']+w['size'])-max(offset,w['offset'])
                    if n>0:segments+=1;total+=n
            expected_segments,expected_bytes,offender,reserved=struct.unpack_from('<4Q',raw,384)
            need((expected_segments,expected_bytes)==(segments,total) and total<=65536 and not offender and not reserved,
                 'Forward protected-page proof differs')
            budget=dict(zip(('usr_type','usr_unit','usr_available','usr_required','append_bytes','append_attempts','append_completed','reserved2'),struct.unpack_from('<8Q',raw,544)))
            r.update(budget);r['mappings']=rows;r['runtime_sha256']=raw[608:640].hex()
            need(all(r[k]==0 for k in ('native_status','euid','plugin_unlink','close_errors','readonly','remount','auxv_status','source_status','cross_matches','reserved2')),
                 'Forward native outcome incomplete: STOP_UNKNOWN')
            need(r['pid']>1 and r['source_ino']>0 and r['source_nlink']==1
                 and r['source_mode']&0o170000==0o100000 and r['page_size']==4096
                 and r['source_size']==p['target' if mode==3 else 'source']['size'],'Forward source identity differs')
            stat=struct.unpack_from('<QQIIII',raw,416)
            need(stat==(r['source_dev'],r['source_ino'],r['source_mode'],r['source_nlink'],r['source_uid'],r['source_gid'])
                 and struct.unpack_from('<q',raw,464)[0]==r['source_size'],'Forward raw stat differs')
            if mode!=3:
                budget_expected=allocation_budget(p['pending'])
                need(r['usr_type']==0xef53 and r['usr_unit']==UNIT and r['usr_required']==RESERVE+budget_expected['required_bytes']
                     and r['usr_available']>=r['usr_required'],'Forward allocation proof differs')
            if mode==1:
                append=len(bytes.fromhex(p['append_hex']));count=len(p['windows'])+bool(append)
                need(r['phase']==9 and r['flags']==(763 if segments else 761)
                     and r['cow_attempts']==r['cow_segments']==segments and r['bytes_cow_preserved']==total
                     and r['write_attempts']==r['writes_completed']==count
                     and r['bytes_written']==sum(len(bytes.fromhex(w['before_hex'])) for w in p['windows'])+append
                     and r['append_bytes']==append and r['append_attempts']==r['append_completed']==bool(append),
                     'Forward append/window/runtime preservation proof incomplete')
            else:
                need(r['phase']==3 and r['flags']==193 and not any(r[k] for k in
                    ('cow_attempts','cow_segments','bytes_cow_preserved','write_attempts','writes_completed','bytes_written','append_bytes','append_attempts','append_completed')),
                     'Readonly forward inspection proof differs')
            if self.inspection is not None:
                first=self.inspection
                need(all(r[k]==first[k] for k in ('pid','source_dev','source_ino','source_mode','source_uid','source_gid','source_nlink','runtime_sha256'))
                     and rows==first['mappings'],'Forward cross-phase identity/runtime changed')
            else:self.inspection=deepcopy(r)
            self.previous=mode;self.pending=None
            return {k:(v.decode() if k=='magic' else v.hex()) if isinstance(v,bytes) else v for k,v in r.items()}
        except ForwardReadOnlyRefusal:
            self.state='REFUSED_READ_ONLY';self.pending=None;raise
        except BaseException:
            self.unknown();raise

    def confirm_readback(self, path):
        try:
            need(self.state=='READY' and self.pending is None and self.previous in (0,3),'Inspect before forward full readback')
            side='source' if self.previous==0 else 'target'
            need(_read_identity(path)==self.plan[side],'Complete forward resource readback differs')
            self.barrier=side
            return dict(status='FULL_READBACK_VERIFIED',endpoint=side,plan_id=self.plan['plan_id'])
        except BaseException:
            self.unknown();raise
