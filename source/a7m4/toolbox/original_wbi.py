"""Portable bridge to unchanged forward WBI prepare/drop contracts.

No raw flash write, discovery, USB ownership, settings or STOP operation.
The outer restore owns original-target postimages and explicit authorization.
"""
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import types
from .capture_inputs import read_private
from .native_actions import NativeActions,_write,_json
from .build_scratch import discard_caches
from .program_worker import _elf

ROOT=Path(__file__).with_name('restore_closure')/'source'
PROVENANCE_SHA256='685e2a14f566526eed68db0ae77f66e4326f1240fa0f6a690cc4b6f0b8788fd3'


def load_sources():
    from .restore_closure_loader import verify_closure
    verify_closure()
    raw=read_private(ROOT/'wbi-source-provenance.json',65536)
    if sha256(raw).hexdigest()!=PROVENANCE_SHA256:raise ValueError('WBI source provenance differs')
    manifest=json.loads(raw);files={}
    if len(manifest['files'])!=4:raise ValueError('Exact WBI source closure required')
    for row in manifest['files']:
        data=read_private(ROOT/row['path'],65536)
        if len(data)!=row['size'] or sha256(data).hexdigest()!=row['sha256']:raise ValueError('WBI source pin differs')
        files[row['path']]=data
    modules=[]
    for name in ('prepare','drop'):
        key='wbi/'+name+'_wire.py';module=types.ModuleType('a7m4_original_wbi_'+name)
        module.__file__=str(ROOT/key);exec(compile(files[key],module.__file__,'exec'),module.__dict__);modules.append(module)
    return (*modules,files)


def report_bound(wire):return wire.HEADER.size+len(wire.CAPS)*wire.TLV.size+sum(wire.CAPS)


def classify_prepare(parsed):
    sections=parsed['sections'];boot=sections[1]['data']
    if sections[1]['status']!=0 or not re.fullmatch(rb'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\n',boot):
        raise ValueError('Canonical WBI boot observation missing')
    if (not parsed['complete'] and parsed['status']==-116 and parsed['before_mode']==b'0\n'
            and sections[2]['status']==sections[3]['status']==0
            and all(sections[i]['status']==-125 and not sections[i]['data'] for i in (4,5,6,7,8,9,10,11,16))):
        return dict(accepted=True,kind='SKIP_MODE0',boot_id=boot,preimage=b'')
    reads=parsed['header_reads']
    accepted=(parsed['complete'] is True and len(reads)==2 and len(reads[0])==8192 and reads[0]==reads[1]
        and (reads[0][:4]==b'WBI2' or reads[0][:512]==bytes(512))
        and parsed['before_mode']==parsed['after_mode']==b'2\n' and parsed['before_dev']==parsed['after_dev']==b'*wbi4\n')
    return dict(accepted=accepted,kind='PREPARED_MODE2' if accepted else 'OBSERVED_REFUSAL',boot_id=boot,
                preimage=reads[0][:512] if accepted else b'')


def build(name,output,*,compiler):
    _,_,files=load_sources();source=ROOT/'wbi/native'/(name+'.c')
    expected=files['wbi/native/'+name+'.c'];output=Path(output)
    if output.exists() or not output.parent.is_dir() or any(p.is_symlink() for p in (output,*output.parents)):
        raise ValueError('New private WBI build directory required')
    output.mkdir(mode=0o700)
    env=dict(os.environ,ZIG_GLOBAL_CACHE_DIR=str(output/'zig-global'),ZIG_LOCAL_CACHE_DIR=str(output/'zig-local'))
    if subprocess.run([str(compiler),'version'],capture_output=True,text=True,check=True,timeout=20,env=env).stdout.strip()!='0.13.0':
        raise ValueError('Offline Zig0.13 required')
    base=[str(compiler),'cc','-target','aarch64-linux-gnu','-std=c11']
    abi=output/'target-abi.o'
    subprocess.run(base+['-D'+('WI_TARGET_ABI' if name=='prepare' else 'WD_TARGET_ABI'),'-c',str(source),'-o',str(abi)],capture_output=True,check=True,timeout=120,env=env)
    abi.chmod(0o600)
    args=base+['-Os','-Wall','-Wextra','-Werror','-shared','-fPIC','-ffreestanding','-fno-builtin','-fno-stack-protector',
        '-fno-unwind-tables','-fno-asynchronous-unwind-tables','-nostdlib','-g0','-Wl,--strip-debug','-Wl,--no-undefined',
        '-Wl,--build-id=none','-Wl,-Bsymbolic','-Wl,-z,noexecstack']
    blobs=[]
    for suffix in ('','-repeat'):
        path=output/('wbi-'+name+suffix+'.so')
        subprocess.run(args+['-o',str(path),str(source)],capture_output=True,check=True,timeout=180,env=env)
        raw=read_private(path,65535);_elf(raw);path.chmod(0o600);blobs.append(raw)
    if blobs[0]!=blobs[1] or read_private(source,65536)!=expected:raise ValueError('WBI source/double-build changed')
    _write(output/'build.json',_json(dict(source_sha256=sha256(expected).hexdigest(),binary_sha256=sha256(blobs[0]).hexdigest(),
        binary_bytes=len(blobs[0]),target_abi_sha256=sha256(read_private(abi,1024*1024)).hexdigest(),camera_io=False)))
    discard_caches(output);return blobs[0]


class OriginalWBI:
    def __init__(self,channel,output,*,compiler,runtime_evidence,actions_factory=NativeActions):
        self.channel=channel;self.output=Path(output);self.output.mkdir(mode=0o700,exist_ok=False)
        self.prepare_wire,self.drop_wire,_=load_sources();self.runtime_evidence=runtime_evidence
        self.binary={name:build(name,self.output/(name+'-build'),compiler=compiler) for name in ('prepare','drop')}
        self.actions_factory=actions_factory;self.claimed=False;self.nonces=set()
    def _nonce(self):
        nonce=os.urandom(16)
        if not any(nonce) or nonce in self.nonces:raise ValueError('Repeated WBI nonce')
        self.nonces.add(nonce);return nonce
    def _run(self,name,packet,nonce,runtime,*,boot=None,preimage=None):
        wire=self.prepare_wire if name=='prepare' else self.drop_wire
        folder=self.output/('%02d-%s'%(len(self.nonces),name));folder.mkdir(mode=0o700)
        _write(folder/'request.private.bin',packet);observed={}
        actions=self.actions_factory(self.channel,folder/'native')
        if self.channel.peek(wire.PENDING) is not None:raise ValueError('Unowned WBI pending report present')
        def accept(raw):
            parsed=(wire.parse_report(raw,nonce) if name=='prepare' else wire.parse_report(raw,nonce,boot,preimage))
            header=wire.HEADER.unpack_from(raw)
            if (not parsed['cleanup_safe'] or header[12]!=runtime['process_id']
                    or parsed['sections'][1]['data']!=(runtime['boot_id']+'\n').encode()):
                raise ValueError('WBI raw report cleanup/process/boot proof failed')
            if name=='drop' and parsed['mutation_possible'] and not parsed['complete']:
                raise ValueError('WBI mutation outcome unknown/incomplete; no replay or healthy STOP')
            _write(folder/'report.private.bin',raw);observed.update(parsed=parsed)
            return {k:v for k,v in parsed.items() if type(v) in (str,int,bool,type(None))}
        actions.phase(self.binary[name],wire.REQUEST,packet,wire.RESULT,accept,report_bytes=report_bound(wire),native_report_capacity=65536,native_overhead_units=2)
        actions.clean_packets()
        if self.channel.peek(wire.PENDING) is not None:raise ValueError('WBI pending report remains')
        # Reopen exact retained originals before using their preparation claim.
        if read_private(folder/'request.private.bin',wire.REQUEST_BYTES)!=packet:raise ValueError('Retained WBI request changed')
        raw=read_private(folder/'report.private.bin',report_bound(wire))
        reparse=wire.parse_report(raw,nonce) if name=='prepare' else wire.parse_report(raw,nonce,boot,preimage)
        if reparse!=observed['parsed']:raise ValueError('Retained WBI report changed')
        return reparse,sha256(raw).hexdigest()
    def adopt(self,*,program_fullpost_verified,approval_verified,no_ssh_started):
        if self.claimed or not all(type(v) is bool and v for v in (program_fullpost_verified,approval_verified,no_ssh_started)):
            raise ValueError('Once-only WBI adoption requires original program readback and this operation authorization')
        self.claimed=True;runtime=self.runtime_evidence();nonce=self._nonce()
        parsed,prepare_sha=self._run('prepare',self.prepare_wire.request(nonce),nonce,runtime)
        prepared=classify_prepare(parsed)
        if not prepared['accepted']:
            return dict(success=False,known_clean_refusal=True,prepare_report_sha256=prepare_sha,native_status=parsed['status'])
        current=self.runtime_evidence()
        if (current['process_id'],current['boot_id'])!=(runtime['process_id'],runtime['boot_id']):raise ValueError('WBI preparation became stale')
        nonce=self._nonce()
        if prepared['kind']=='SKIP_MODE0':
            parsed,apply_sha=self._run('prepare',self.prepare_wire.request(nonce),nonce,current)
            fresh=classify_prepare(parsed)
            success=fresh['kind']=='SKIP_MODE0' and fresh['boot_id']==prepared['boot_id']
            kind='SKIP_FRESH_MODE0' if success else 'OBSERVED_REFUSAL'
        else:
            packet=self.drop_wire.request(nonce,prepared['boot_id'],prepared['preimage'])
            parsed,apply_sha=self._run('drop',packet,nonce,current,boot=prepared['boot_id'],preimage=prepared['preimage'])
            sections=parsed['sections']
            skipped=(not parsed['complete'] and parsed['status']==-116 and parsed['before_mode']==b'0\n'
                and sections[1]['status']==sections[2]['status']==sections[3]['status']==0
                and sections[1]['data']==prepared['boot_id'] and not parsed['attempted'] and not parsed['mode_attempted'])
            success=parsed['complete'] or skipped;kind='SKIP_FRESH_MODE0' if skipped else 'VENDOR_DROP_AND_MODE0' if success else 'OBSERVED_REFUSAL'
        return dict(success=bool(success),kind=kind,prepare_report_sha256=prepare_sha,apply_report_sha256=apply_sha,
            exact_owned_cleanup_verified=True,physical_persistence_verified=False,USB_STOP_granted=False)
