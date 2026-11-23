"""Bounded original-target streaming over one explicitly borrowed channel.

Each <=32KiB chunk goes directly through the small native request to a unique
same-directory stage. Complete stage Mac EOF/SHA precedes rename. No source
inode pwrite/truncate, arbitrary path, automatic abort or session lifecycle.
"""
from hashlib import sha256
import json
import os
from pathlib import Path
from .restore_authority import validate_plan as validate_restore_authority
from . import original_restore as diff
from .restore_helper_loader import load_helper
from .capture_inputs import read_private
from .native_actions import NativeActions


class OriginalAtomicAdapter:
    def __init__(self,master,channel,output,*,compiler,runtime_evidence,actions_factory=NativeActions):
        self.master=validate_restore_authority(master);self.channel=channel;self.output=Path(output)
        self.output.mkdir(mode=0o700,exist_ok=False)
        self.compiler=compiler;self.runtime_evidence=runtime_evidence
        self.actions_factory=actions_factory;self.index=0;self.needs_usr_readonly_verification=False

    def execute(self,row,source,target,*,reference_proof):
        definition=next(r for r in self.master['objects'] if r['path']==row['path'])
        if definition!=row or row['kind'] not in ('resource','audio') or diff._identity(target)!=row['target']:
            raise ValueError('Atomic target must be the selected original capture member')
        if read_private(row['original_path'],16*1024*1024)!=target:raise ValueError('Original atomic target changed')
        runtime=self.runtime_evidence()
        if (type(runtime) is not dict or runtime.get('body_binding')!=self.master['body_binding']
                or runtime.get('fresh') is not True or type(runtime.get('process_id')) is not int):
            raise ValueError('Fresh same-body runtime evidence required')
        if type(reference_proof) is not dict or reference_proof.get('source_inode_preservation_required') is not True:
            raise ValueError('Atomic source-consumer/reference proof missing')
        encode=lambda value:json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
        worker,=load_helper('original-atomic')
        authority=dict(schema=worker.AUTHORITY_SCHEMA,original_backup_sha256=self.master['original_capture']['archive_sha256'],
            current_file_readback_sha256=sha256(source).hexdigest(),resource_reference_proof_sha256=sha256(encode(reference_proof)).hexdigest(),
            boot_or_load_proof_sha256=sha256(encode(runtime)).hexdigest())
        plan=worker.make_plan(row['target_path'],source,target,authority=authority)
        if plan['no_op']:return dict(complete=True,no_op=True,full_file_readback=worker.verify_readback(plan,source))
        self.index+=1;root=self.output/('%03d'%self.index);root.mkdir(mode=0o700)
        built=worker.build(plan,root/'build',compiler=self.compiler)
        from .build_scratch import discard_caches
        discard_caches(root/'build')
        binary=read_private(built['worker']['path'],65535)
        if len(binary)!=built['worker']['size'] or sha256(binary).hexdigest()!=built['worker']['sha256']:
            raise ValueError('Original atomic helper changed after build')
        # This adds an exact SDK-derived stage as READ-ONLY. The host still
        # cannot upload/delete it directly; only the finite native contract can.
        self.channel.admit_original_stage(plan)
        actions=self.actions_factory(self.channel,root/'native');previous=None;nonces=set();reports=[]
        source_barrier=None;stage_barrier=None
        def phase(mode,*,chunk=b''):
            nonlocal previous,source_barrier,stage_barrier
            nonce=os.urandom(16)
            if nonce in nonces or not any(nonce):raise ValueError('Duplicate or zero atomic nonce')
            nonces.add(nonce)
            packet=worker.request(plan,mode,nonce,previous,chunk=chunk,
                source_readback=source_barrier if mode==1 else None,
                stage_readback=stage_barrier if mode==3 else None)
            def accept(raw):
                parsed=worker.parse_report(plan,raw,mode,nonce,request_bytes=packet)
                if parsed['pid']!=runtime['process_id'] or parsed.get('complete') is not True:
                    raise ValueError('Atomic native refusal, changed process or UNKNOWN; no retry')
                return parsed
            previous=actions.phase(binary,worker.REQUEST_PATH,packet,worker.RESULT_PATH,accept,report_bytes=worker.MAX_REPORT,native_report_capacity=worker.MAX_REPORT,native_overhead_units=2)
            reports.append(dict(mode=mode,nonce=nonce.hex(),report_sha256=previous['report_sha256'],
                known_deferred_readonly=previous.get('known_deferred_readonly',False)))
            if previous.get('known_deferred_readonly'):self.needs_usr_readonly_verification=True
        phase(0)
        actual=self.channel.file(row['target_path']);source_barrier=worker.verify_source(plan,actual)
        phase(1)
        for offset in range(0,len(target),worker.MAX_CHUNK_BYTES):phase(2,chunk=target[offset:offset+worker.MAX_CHUNK_BYTES])
        staged=self.channel.file(plan['stage_path']);stage_barrier=worker.verify_stage(plan,staged)
        # Retain actual complete staged bytes privately before committing.
        path=root/'stage-Mac.bin';fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:stream.write(staged);stream.flush();os.fsync(stream.fileno())
        phase(3)
        readback=worker.verify_readback(plan,self.channel.file(row['target_path']))
        if self.channel.peek(plan['stage_path']) is not None:raise ValueError('Published atomic stage name still exists')
        actions.clean_packets()
        return dict(schema=worker.FAMILY,complete=True,plan_id=plan['plan_id'],profile=plan['profile'],
            source_inode_truncated=False,source_inode_written=False,stage_mac_readback=stage_barrier,
            full_file_readback=readback,reports=reports,original_target_atomic_rename_verified=True,
            usr_readonly_verified=False,post_boot_full_file_verification_complete=False)
