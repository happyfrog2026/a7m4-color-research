"""Source-bound original AP/CP diff batching and native sequencing.

No device discovery, session lifecycle or arbitrary externally supplied patch
API. Inputs come exclusively from the reverified original-backup diff.
"""
from hashlib import sha256
import os
from pathlib import Path
from .restore_authority import validate_plan as validate_restore_authority
from . import original_restore as diff, program_worker as worker
from .capture_inputs import read_private
from .native_actions import NativeActions


def program_batches(plan):
    plan=validate_restore_authority(plan)
    roles={'appFw.so':'ap','CPAPP-B.BIN':'cp'}
    rows={r['path']:r for r in plan['objects']}
    images={role:read_private(rows[name]['source_path'],160*1024*1024) for name,role in roles.items()}
    pending=[]
    for name,role in roles.items():
        row=rows[name]
        if row['source']['size']!=row['target']['size']:raise ValueError('Original program sizes differ')
        pending.extend((role,w) for w in row['windows'])
    result=[]
    while pending:
        batch=[];total=ap=0
        while pending and len(batch)<worker.MAX_WINDOWS:
            role,w=pending[0];size=len(bytes.fromhex(w['before_hex']))
            if total+size>worker.MAX_TOTAL_BYTES or ap+(size if role=='ap' else 0)>worker.MAX_AP_BYTES:break
            pending.pop(0);batch.append((role,w));total+=size;ap+=size if role=='ap' else 0
        if not batch:raise ValueError('Program diff cannot fit bounded original-backup worker')
        source={r:diff._identity(raw) for r,raw in images.items()};targets=dict(images);windows={'ap':[],'cp':[]}
        for role,w in batch:
            raw=bytearray(targets[role]);at=w['offset'];before=bytes.fromhex(w['before_hex']);after=bytes.fromhex(w['after_hex'])
            if raw[at:at+len(before)]!=before:raise ValueError('Original program batch preimage changed')
            raw[at:at+len(after)]=after;targets[role]=bytes(raw);windows[role].append(w)
        result.append(worker.program_plan({r:dict(source=source[r],target=diff._identity(targets[r]),windows=windows[r])
                                          for r in ('ap','cp')},feature_id='restore-original-backup-v1'))
        images=targets
    if any(diff._identity(images[role])!=rows[name]['target'] for name,role in roles.items()):
        raise ValueError('Original program diff/complement does not reach original complete endpoint')
    return result


def inverse_restore_view(transition):
    """Use the existing AP-first inverse ABI over a newly derived restore diff."""
    worker.validate_plan(transition)
    return worker.program_plan({role:dict(source=c['target'],target=c['source'],
        windows=[dict(offset=w['offset'],before_hex=w['after_hex'],after_hex=w['before_hex']) for w in c['windows']])
        for role,c in transition['components'].items()},feature_id='restore-original-backup-inverse-v1')


class OriginalProgramAdapter:
    def __init__(self,plan,channel,output,*,compiler,expected_process_id,actions_factory=NativeActions):
        self.plan=validate_restore_authority(plan);self.channel=channel;self.output=Path(output)
        self.output.mkdir(mode=0o700,exist_ok=False);self.compiler=compiler
        self.pid=expected_process_id;self.actions_factory=actions_factory
        self.batches=program_batches(plan)

    def execute(self):
        results=[]
        for index,transition in enumerate(self.batches):
            plan=inverse_restore_view(transition)
            root=self.output/('%03d'%index);root.mkdir(mode=0o700)
            built=worker.build_program_worker(plan,root/'build',compiler=self.compiler)
            if built.get('worker_built') is not True:raise ValueError('Original program helper unavailable')
            from .build_scratch import discard_caches
            discard_caches(root/'build')
            binary=read_private(built['worker']['path'],65535);protocol=worker.ProgramProtocol(plan)
            actions=self.actions_factory(self.channel,root/'native')
            def accept(raw):
                result=protocol.accept(raw)
                if result['pid']!=self.pid:raise ValueError('Native process changed during original program restore')
                return result
            for mode in (3,2,0):
                actions.phase(binary,worker.REQUEST_PATH,protocol.request(mode,os.urandom(16)),worker.RESULT_PATH,
                              accept,report_bytes=worker.REPORT.size)
                if mode in (3,0):
                    images={}
                    for role,remote in worker.PATHS.items():
                        raw=self.channel.file(remote);path=root/('%d-%s.bin'%(mode,role))
                        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                        with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
                        images[role]=path
                    verified=protocol.confirm_readback(images)
            actions.clean_packets();results.append(dict(plan_id=plan['plan_id'],transition_id=transition['plan_id'],readback=verified,restore_order='AP-before-CP'))
        return dict(complete=True,batches=results,all_targets_verified=False)
