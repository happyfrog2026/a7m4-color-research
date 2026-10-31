"""Single RO-only attempt; known EBUSY remains pending, never inferred UNKNOWN."""
from pathlib import Path
from hashlib import sha256
import os
from .restore_closure_loader import load_ro
from .capture_inputs import read_private
from .native_actions import NativeActions
from .build_scratch import discard_caches


class OriginalReadonly:
    def __init__(self,channel,output,*,compiler,runtime_evidence,actions_factory=NativeActions):
        self.channel=channel;self.output=Path(output);self.output.mkdir(mode=0o700,exist_ok=False)
        self.runtime_evidence=runtime_evidence;self.actions_factory=actions_factory;self.worker=load_ro()
        self.plan=self.worker.make_plan();built=self.worker.build(self.plan,self.output/'build',compiler=compiler)
        self.binary=read_private(built['worker']['path'],65535)
        if len(self.binary)!=built['worker']['size'] or sha256(self.binary).hexdigest()!=built['worker']['sha256']:
            raise ValueError('RO helper changed after double build')
        discard_caches(self.output/'build');self.claimed=False;self.result=None
    def execute(self):
        if self.claimed:return self.result
        self.claimed=True;runtime=self.runtime_evidence();worker=self.worker;nonce=os.urandom(16)
        packet=worker.request(self.plan,nonce);actions=self.actions_factory(self.channel,self.output/'native')
        if self.channel.peek(worker.PENDING_PATH) is not None:raise ValueError('Unowned RO pending report exists')
        def accept(raw):
            parsed=worker.parse_report(self.plan,raw,nonce,expected_request=packet)
            if parsed['pid']!=runtime['process_id'] or not (parsed['complete'] or parsed['known_ro_pending']):
                raise ValueError('RO native refusal, unknown post-state or changed process')
            return parsed  # RO_PENDING is a parsed outcome, not native failure.
        self.result=actions.phase(self.binary,worker.REQUEST_PATH,packet,worker.RESULT_PATH,accept,report_bytes=worker.MAX_REPORT,native_report_capacity=worker.MAX_REPORT,native_overhead_units=2)
        actions.clean_packets()
        if self.channel.peek(worker.PENDING_PATH) is not None:raise ValueError('RO pending report remains')
        latest=self.runtime_evidence()
        if (latest['process_id'],latest['boot_id'])!=(runtime['process_id'],runtime['boot_id']):raise ValueError('RO proof context changed')
        return self.result
