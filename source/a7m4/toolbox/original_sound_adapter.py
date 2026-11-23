"""Restore native PIN bank via new inode; retain all current live consumers."""
from pathlib import Path
import struct
from .restore_authority import validate_plan as validate_restore_authority
from . import original_restore as diff, original_ap_load, original_ap_original_on_source
from .capture_inputs import read_private
from .original_atomic_adapter import OriginalAtomicAdapter
from .original_restore_job import RequiredBoundary
from .pin_sources import STOCK_WORDS
from ..research import pin_plan


def descriptor_profile(ap,bank):
    if not 77504<=len(bank)<=131072:raise ValueError('Unsupported native sound bank length')
    words=tuple(ap[at:at+4] for at in pin_plan.AP_OFFSETS)
    if words==STOCK_WORDS:
        if len(bank)!=77504:raise ValueError('Stock descriptors require complete stock bank')
        return dict(profile='stock-native-pin',bank=diff._identity(bank))
    if words==pin_plan.AP_BEFORE and len(bank)==108480:
        return dict(profile='r066-native-pin',bank=diff._identity(bank))
    if any(len(w)!=4 for w in words):raise ValueError('Native PIN AP descriptors are missing')
    lengths={k:(struct.unpack('<I',words[i])[0]>>5)&65535 for k,i in (('sha',1),('kasha',6))}
    if (not 0<lengths['sha']<=15424 or not 0<lengths['kasha']<=17600
            or any(n%64 for n in lengths.values())
            or words!=pin_plan._ap_after(lengths)
            or 77504+lengths['sha']>len(bank) or 92928+lengths['kasha']>len(bank)):
        raise ValueError('Unsupported native PIN descriptors or bank references')
    return dict(profile='bounded-native-pin',lengths=lengths,bank=diff._identity(bank))


def sound_admission(master):
    master=validate_restore_authority(master)
    ap=next(r for r in master['objects'] if r['kind']=='ap');bank=next(r for r in master['objects'] if r['kind']=='audio')
    src=read_private(bank['source_path'],131072);target=read_private(bank['original_path'],131072)
    if src[6144:77504]!=target[6144:77504]:raise ValueError('Protected non-PIN bank consumers differ')
    return dict(source=descriptor_profile(read_private(ap['source_path'],160*1024*1024),src),
        original=descriptor_profile(read_private(ap['original_path'],160*1024*1024),target),
        source_inode_preservation_required=True,protected_bank_complement_verified=True)


class OriginalSoundAdapter:
    def __init__(self,master,channel,output,*,compiler,runtime_evidence):
        self.master=master;self.channel=channel;self.output=Path(output);self.output.mkdir(mode=0o700,exist_ok=False)
        self.compiler=compiler;self.runtime_evidence=runtime_evidence;self.admission=sound_admission(master);self.proof=None
        self.original_on_source_proof=None;self.source_mismatch_proof=None
        self.atomic=OriginalAtomicAdapter(master,channel,self.output/'atomic',compiler=compiler,runtime_evidence=runtime_evidence)
    def prepare(self,source_proof=None):
        if self.proof is not None or self.original_on_source_proof is not None:raise ValueError('Sound source proof is once-only')
        if self.channel.peek('/usr/share/avsystemsound/custom.txt') is not None:raise ValueError('CSV/APP sound route is unsupported')
        runtime=self.runtime_evidence()
        self.proof=source_proof or original_ap_load.verify_borrowed(self.master,self.channel,self.output/'source-ap-load',
            compiler=self.compiler,boot_id=runtime['boot_id'],pid=runtime['process_id'],endpoint='source')
        if (self.proof.get('master_plan_id')!=self.master['plan_id']
                or (self.proof.get('process_id'),self.proof.get('boot_id'))!=(runtime['process_id'],runtime['boot_id'])):
            raise ValueError('Source AP proof master/process/boot binding differs')
        if not self.proof['loaded_current_ap_verified']:
            raise RequiredBoundary('Current AP runtime differs from capture; no sound/program writes dispatched')
        return self.proof
    def prepare_original_on_source(self,proof,source_mismatch):
        if self.proof is not None or self.original_on_source_proof is not None:raise ValueError('Sound consumer mode is once-only')
        original_ap_original_on_source.validate_proof(self.master,proof,source_mismatch)
        runtime=self.runtime_evidence()
        if (proof['process_id'],proof['boot_id'])!=(runtime['process_id'],runtime['boot_id']):raise ValueError('Original consumer entry proof is stale')
        if self.channel.peek('/usr/share/avsystemsound/custom.txt') is not None:raise ValueError('CSV/APP sound route is unsupported')
        self.original_on_source_proof=proof;self.source_mismatch_proof=source_mismatch
        return proof

    def execute(self,row,source,target,*,original_consumer_proof=None):
        runtime=self.runtime_evidence()
        if self.original_on_source_proof is not None:
            # The entry proof never becomes source-load success. Require the
            # later standard original disk/runtime report after program restore.
            entry=self.original_on_source_proof
            if self.proof is not None or (entry['process_id'],entry['boot_id'])!=(runtime['process_id'],runtime['boot_id']):
                raise ValueError('Original sound consumer entry is stale or ambiguous')
            proof=original_consumer_proof
            if not isinstance(proof,dict) or proof.get('loaded_original_ap_verified') is not True:
                raise ValueError('A standard original disk/runtime proof is required before sound restoration')
            plan=original_ap_load.make_plan(self.master)
            raw=read_private(proof['native_report_path'],original_ap_load.REPORT.size)
            from hashlib import sha256
            if sha256(raw).hexdigest()!=proof.get('report_sha256'):raise ValueError('Original sound consumer native proof changed')
            checked=original_ap_load.parse_report(plan,raw,bytes.fromhex(proof['nonce_hex']),
                boot_id=runtime['boot_id'],pid=runtime['process_id'])
            if not checked['loaded_original_ap_verified'] or any(proof.get(k)!=v for k,v in checked.items()):
                raise ValueError('Original sound consumer is not the independently bound original endpoint')
            ap=next(r for r in self.master['objects'] if r['kind']=='ap')
            if diff._identity(self.channel.file('/usr/lib/appFw.so'))!=ap['target']:
                raise ValueError('Complete original AP changed before sound restoration')
            reference=dict(self.admission,consumer_mode='original-on-original-disk',
                original_ap_report_sha256=checked['report_sha256'],original_on_source_entry_report_sha256=entry['report_sha256'])
        else:
            if original_consumer_proof is not None:raise ValueError('Original proof cannot switch a source consumer implicitly')
            if not self.proof or not self.proof['loaded_current_ap_verified']:raise ValueError('Current AP source load proof missing')
            if (runtime['process_id'],runtime['boot_id'])!=(self.proof['process_id'],self.proof['boot_id']):raise ValueError('Sound consumer process changed')
            reference=dict(self.admission,source_ap_report_sha256=self.proof['report_sha256'])
        if self.channel.peek('/usr/share/avsystemsound/custom.txt') is not None:raise ValueError('Sound route changed')
        return self.atomic.execute(row,source,target,reference_proof=reference)
