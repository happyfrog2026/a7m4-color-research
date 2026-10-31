"""Real native prefix/tail sequencing over an explicitly borrowed channel.

No USB construction, detection, mount change, STOP or WBI action is provided.
Main/coordinator proves original backup, body, all sources and runtime evidence.
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
from . import original_ap_load
from .original_restore_job import RequiredBoundary
from . import original_resource_tail_original as original_tail
from .original_resource_tail_original_protocol import OriginalTailProtocol


def _original_tail_candidate(result):
    """Only the legacy inspect's proved RAM-only mismatch admits this profile.

    The failed legacy proof stays failed. No status from apply, disk checking,
    malformed reports or an uncertain mapping can reach the second helper.
    """
    return (result.get('mode') == 0 and result.get('phase') == 2
        and result.get('native_status') == -84 and result.get('source_status') == 0
        and result.get('flags') == 64 and result.get('range_count', 0) > 0
        and result.get('safe_inspect_refusal') is True and result.get('cleanup_safe') is True
        and result.get('mapping_state_unknown') is False and result.get('preimage_captured') is False
        and all(result.get(k) == 0 for k in ('euid','plugin_unlink','close_errors','readonly','remount',
            'auxv_status','cross_matches','mremap_attempts','changed_aliases','anon_bytes','bytes_truncated'))
        and not any(result.get('scratch_addresses', [1])))


class OriginalResourceAdapter:
    def __init__(self,plan,channel,output,*,compiler,runtime_evidence,actions_factory=NativeActions):
        self.plan=validate_restore_authority(plan);self.channel=channel;self.output=Path(output)
        self.output.mkdir(mode=0o700,exist_ok=False)
        self.compiler=compiler;self.runtime_evidence=runtime_evidence;self.actions_factory=actions_factory
        self.sequence=0;self.needs_readonly_verification=False

    def _authority(self,row,source,target):
        actual=next(r for r in self.plan['objects'] if r['path']==row['path'])
        if actual!=row or row['kind']!='resource' or diff._identity(target)!=row['target']:
            raise ValueError('Resource target is not a selected complete original-backup member')
        if read_private(row['original_path'],16*1024*1024)!=target:
            raise ValueError('Original resource changed')
        # Independently inspect the complete ORIGINAL resource, never assume
        # prefix equality alone proves indices/payloads are in its own EOF.
        if row['path'].split('/')[-1].startswith('string_'):
            from .looks import _strings
            parsed=_strings(target)
        else:
            from ..research.native_icons import _inspect_bank
            parsed=_inspect_bank(target)
        evidence=self.runtime_evidence()
        if (type(evidence) is not dict or evidence.get('body_binding')!=self.plan['body_binding']
                or not isinstance(evidence.get('boot_id'),str) or type(evidence.get('process_id')) is not int
                or evidence['process_id']<=0 or evidence.get('fresh') is not True):
            raise ValueError('Fresh same-body runtime/load evidence missing')
        canonical=lambda value:json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
        return dict(schema='a7m4-owned-tail-authority/1',
            original_backup_sha256=self.plan['original_capture']['archive_sha256'],
            current_file_readback_sha256=sha256(source).hexdigest(),
            resource_reference_proof_sha256=sha256(canonical(dict(target=row['target'],path=row['target_path'],
                original_capture=self.plan['original_capture'],original_index_bounds_parsed=True))).hexdigest(),
            boot_or_load_proof_sha256=sha256(canonical(evidence)).hexdigest()),evidence

    def _run(self,kind,row,source,target):
        authority,runtime=self._authority(row,source,target)
        loaded=None
        if kind=='tail-restore':
            self.sequence+=1
            loaded=original_ap_load.verify_borrowed(self.plan,self.channel,self.output/('%03d-ap-load'%self.sequence),
                compiler=self.compiler,boot_id=runtime['boot_id'],pid=runtime['process_id'],actions_factory=self.actions_factory)
            if loaded['loaded_original_ap_verified'] is not True:
                if loaded.get('native_status') in (-84,-18) and loaded.get('cleanup_safe') is True:
                    raise RequiredBoundary('Original AP is not yet loaded; preserve tail, perform required startup/load boundary, then inspect again')
                raise ValueError('Initial tail AP proof is incomplete or unsupported; no startup or clean exit inference')
            authority['boot_or_load_proof_sha256']=loaded['report_sha256']
        worker,session=load_helper(kind)
        planned=worker.make_plan(row['target_path'],source,target,authority=authority)
        protocol=(session.TailRestoreProtocol(planned) if kind=='tail-restore' else session.ResourceDeltaProtocol(planned))
        self.sequence+=1;root=self.output/('%03d-%s'%(self.sequence,kind));root.mkdir(mode=0o700)
        if kind=='resource-delta' and planned['no_op']:
            protocol.confirm_source(source);done=protocol.finish();return dict(done,complete=True)
        built=worker.build(planned,root/'build',compiler=self.compiler)
        from .build_scratch import discard_caches
        discard_caches(root/'build')
        binary=read_private(built['worker']['path'],65535)
        if len(binary)!=built['worker']['size'] or sha256(binary).hexdigest()!=built['worker']['sha256']:
            raise ValueError('Built restoration helper changed before native dispatch')
        actions=self.actions_factory(self.channel,root/'native')
        def accept(raw):
            result=protocol.accept(raw)
            if result['pid']!=runtime['process_id']:
                raise ValueError('Restoration native refused or process identity changed; no automatic retry')
            if result['complete'] is not True and not (kind=='tail-restore' and _original_tail_candidate(result)):
                raise ValueError('Restoration native refused or process identity changed; no automatic retry')
            return result
        max_report=worker.MIN_REPORT+(worker.MAX_PREIMAGE_BYTES if kind=='tail-restore' else 0)
        for mode in (0,1):
            request=protocol.request(mode,os.urandom(16))
            observed=actions.phase(binary,worker.REQUEST_PATH,request,worker.RESULT_PATH,accept,report_bytes=max_report,native_report_capacity=65536,native_overhead_units=2)
            actual=self.channel.file(row['target_path'])
            if kind=='tail-restore' and mode==0 and _original_tail_candidate(observed):
                # phase() has proved and removed precisely this request/report.
                # Independently recheck the complete source before closing the
                # failed protocol and entering a different, typed profile.
                worker.verify_source(planned,actual)
                if actual!=source:raise ValueError('Complete tail source drifted after legacy refusal')
                actions.clean_packets()
                return self._restore_original_tail(row,source,target,legacy_refusal=observed)
            if mode==0:protocol.confirm_source(actual)
            else:protocol.confirm_readback(actual)
        actions.clean_packets();result=protocol.finish()
        self.needs_readonly_verification|=bool(result.get('requires_post_boot_readonly_verification'))
        return dict(result,complete=True,original_ap_load_proof=loaded,
                    all_targets_verified=False,post_boot_full_file_verification_complete=False)

    def _restore_original_tail(self,row,source,target,*,legacy_refusal):
        if not _original_tail_candidate(legacy_refusal):
            raise ValueError('Original-EOF profile requires the exact safe legacy inspect refusal')
        authority,runtime=self._authority(row,source,target)
        self.sequence+=1
        loaded=original_ap_load.verify_borrowed(self.plan,self.channel,self.output/('%03d-original-tail-ap'%self.sequence),
            compiler=self.compiler,boot_id=runtime['boot_id'],pid=runtime['process_id'],actions_factory=self.actions_factory)
        if loaded.get('loaded_original_ap_verified') is not True:
            if loaded.get('native_status') in (-84,-18) and loaded.get('cleanup_safe') is True:
                raise RequiredBoundary('Original AP byte/load proof refused; preserve resource tail for the startup boundary')
            raise ValueError('Fresh original AP proof is incomplete or unsupported; no tail fallback or clean exit inference')
        if (loaded['process_id'],loaded['boot_id'])!=(runtime['process_id'],runtime['boot_id']):
            raise ValueError('Original-EOF AP proof has a different runtime identity')
        authority['boot_or_load_proof_sha256']=loaded['report_sha256']
        bound=dict(process_id=runtime['process_id'],boot_id=runtime['boot_id'],original_ap_report_sha256=loaded['report_sha256'])
        planned=original_tail.make_plan(row['target_path'],source,target,authority=authority,runtime=bound)
        protocol=OriginalTailProtocol(planned)
        self.sequence+=1;root=self.output/('%03d-original-eof-tail'%self.sequence);root.mkdir(mode=0o700)
        from .native_actions import _write,_json
        _write(root/'legacy-readonly-refusal.json',_json(dict(legacy_refusal,
            legacy_failed=True,legacy_protocol_complete=False,exact_packets_cleaned=True)))
        built=original_tail.build(planned,root/'build',compiler=self.compiler)
        from .build_scratch import discard_caches
        discard_caches(root/'build')
        binary=read_private(built['worker']['path'],65535)
        if len(binary)!=built['worker']['size'] or sha256(binary).hexdigest()!=built['worker']['sha256']:
            raise ValueError('Original-EOF tail binary differs from its double build')
        actions=self.actions_factory(self.channel,root/'native')
        def accept(raw):
            result=protocol.accept(raw)
            if result['pid']!=runtime['process_id']:
                raise ValueError('Original-EOF tail process changed')
            safe_negative=(result['mode']==0 and not result['complete'] and result['cleanup_safe']
                and not result['mapping_state_unknown'] and result['readonly']==0
                and result['phase']==2 and result['native_status']<0 and result['source_status']==0
                and all(result[k]==0 for k in ('mremap_attempts','changed_aliases','anon_bytes','bytes_truncated')))
            if not result['complete'] and not safe_negative:
                raise ValueError('Original-EOF tail refused or mapping is unknown; no retry')
            return result
        for mode in (0,1):
            if self.runtime_evidence()!=runtime:raise ValueError('Original-EOF runtime drifted before native phase')
            request=protocol.request(mode,os.urandom(16))
            observed=actions.phase(binary,original_tail.REQUEST_PATH,request,original_tail.RESULT_PATH,accept,
                report_bytes=original_tail.MIN_REPORT+original_tail.MAX_PREIMAGE_BYTES,
                native_report_capacity=65536,native_overhead_units=2)
            actual=self.channel.file(row['target_path'])
            if mode==0 and not observed['complete']:
                original_tail.verify_source(planned,actual)
                actions.clean_packets()
                raise RequiredBoundary('Original-EOF tail inspection did not establish an admitted runtime profile; preserve the tail for a verified startup boundary')
            if mode==0:protocol.confirm_source(actual)
            else:protocol.confirm_readback(actual)
        actions.clean_packets();result=protocol.finish()
        self.needs_readonly_verification|=bool(result['requires_post_boot_readonly_verification'])
        return dict(result,complete=True,original_ap_load_proof=loaded,legacy_refusal=legacy_refusal,
            runtime_profile='original-eof-zero-padded',all_targets_verified=False,
            post_boot_full_file_verification_complete=False)

    def restore_prefix(self,row,source,target):
        return self._run('resource-delta',row,source,target)

    def restore_tail(self,row,source,target):
        if not source.startswith(target):raise ValueError('Restore original references/prefix before tail inspection')
        return self._run('tail-restore',row,source,target)
