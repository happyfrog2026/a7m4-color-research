"""Once-only native phases over an already owned, authenticated channel.

No service entry or feature admission is provided. The feature coordinator
must first validate same-body backups, exact full source identities, scope and
risk acknowledgement. All wire intents and raw results are durable on the Mac.
No failure path retries, replays, auto-inverts, cleans unknown state or grants
StopSenser. The first data-free workspace probe is explicitly a bootstrap.
"""
from hashlib import sha256
import json
import os
from pathlib import Path
import uuid

from . import workspace
from .run_log import event as diagnostic_event
from .native_channel import LIBRARY
from .program_worker import ProgramReadOnlyRefusal, REQUEST_PATH as PROGRAM_REQUEST, RESULT_PATH as PROGRAM_RESULT
from .resource_forward import (ForwardReadOnlyRefusal, ResourceProtocol as ForwardProtocol,
    REQUEST_PATH as FORWARD_REQUEST, RESULT_PATH as FORWARD_RESULT)


class NativeActionError(RuntimeError):
    pass


def _write(path,raw):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:
        stream.write(raw);stream.flush();os.fsync(stream.fileno())
    if Path(path).read_bytes()!=raw:raise NativeActionError('Durable local reopen differs')


def _json(value):
    return (json.dumps(value,ensure_ascii=False,sort_keys=True,allow_nan=False,indent=2)+'\n').encode()


class NativeActions:
    def __init__(self,channel,output):
        self.channel=channel
        self.output=Path(output).absolute()
        if self.output.exists() or not self.output.parent.is_dir() or any(p.is_symlink() for p in (self.output,*self.output.parents)):
            raise ValueError('New private native action journal directory required')
        self.output.mkdir(mode=0o700)
        self.failed=False;self.index=0;self.owned={}
        self.upload_attempted=False
        self.trigger_attempted=False
        self.unknown_remote_state=False
        self.feature_attempted=False
        self.inspection_complete=False
        # Install once per channel. Later NativeActions instances share this
        # first durable journal, including logical refusals after full replies.
        if hasattr(channel,'verified_frame_observer') and channel.verified_frame_observer is None:
            frames=self.output/'transport-frames';frames.mkdir(mode=0o700)
            ordinal=[0]
            def record_frame(proof):
                if ordinal[0]>=65536:raise NativeActionError('Verified frame journal exhausted')
                ordinal[0]+=1
                _write(frames/('%05d.json'%ordinal[0]),_json(proof))
                fd=os.open(frames,os.O_RDONLY|os.O_NOFOLLOW)
                try:os.fsync(fd)
                finally:os.close(fd)
            channel.verified_frame_observer=record_frame

    @property
    def safe_read_only_abort(self):
        return (not self.feature_attempted and (not self.upload_attempted or self.inspection_complete)
                and not self.unknown_remote_state
                and self.channel.healthy)

    def _guard(self):
        if self.failed or not self.channel.healthy:
            raise NativeActionError('STOP_UNKNOWN: native job cannot continue')

    def _poison(self):
        diagnostic_event('native-stop-unknown',stage='native-action',feature_attempted=self.feature_attempted)
        self.failed=True
        if self.feature_attempted or self.upload_attempted and not self.inspection_complete or self.unknown_remote_state:
            self.channel.healthy=False
        self.channel.safe_to_stop=False

    def _folder(self,label):
        self._guard();self.index+=1
        path=self.output/('%03d-'%self.index+label)
        path.mkdir(mode=0o700)
        return path

    def _absent(self,path):
        if self.channel.peek(path) is not None:
            self.unknown_remote_state=True
            raise NativeActionError('Unowned or stale temporary file; preserve it and stop: '+path)

    def _upload(self,path,raw,folder,*,before_dispatch=None):
        self._guard()
        if type(raw) is not bytes or not 0<len(raw)<65536:
            raise NativeActionError('Strict native upload bound exceeded')
        diagnostic_event('native-upload-intent',helper='libJit.so' if path==LIBRARY else Path(path).name,
            bytes=len(raw),sha256=sha256(raw).hexdigest())
        op=uuid.uuid4().hex
        name='upload-'+op
        # The exact bytes and once-only operation ID exist durably before the
        # channel is armed, including before the native execution trigger.
        _write(folder/(name+'.bin'),raw)
        _write(folder/(name+'.intent.json'),_json(dict(operation_id=op,path=path,
              size=len(raw),sha256=sha256(raw).hexdigest(),camera_write_attempted_next=True)))
        self.channel.arm_uploads(op,{path:raw})
        self.upload_attempted=True
        if path==LIBRARY:self.trigger_attempted=True
        if before_dispatch is not None:before_dispatch()
        self.channel.upload(path)
        _write(folder/(name+'.ack.json'),_json(dict(operation_id=op,acknowledged=True)))
        self.owned[path]=raw

    def probe(self):
        """Fixed generic workspace/boot probe; no persistent-feature write."""
        folder=self._folder('workspace')
        self.inspection_complete=False
        try:
            for path in (LIBRARY,workspace.REQUEST_PATH,workspace.REPORT_PATH):self._absent(path)
            record=json.loads((Path(__file__).with_name('data')/'workspace-probe-build.json').read_text())
            worker=(Path(__file__).with_name('helpers')/'workspace-probe.so').read_bytes()
            if (sha256(worker).hexdigest()!=record['binary_sha256'] or len(worker)!=record['binary_bytes']
                    or sha256(workspace.SOURCE.read_bytes()).hexdigest()!=record['source_sha256']):
                raise NativeActionError('Bundled fixed workspace probe integrity failed')
            nonce=os.urandom(16)
            request=workspace.probe_request(nonce)
            _write(folder/'bootstrap.json',_json(dict(persistent_device_writes=False,
               bootstrap_upload_not_prebudgeted=True,request_bytes=len(request),helper_bytes=len(worker))))
            self._upload(workspace.REQUEST_PATH,request,folder)
            if self.channel.file(workspace.REQUEST_PATH)!=request:
                raise NativeActionError('Workspace request readback differs')
            self._upload(LIBRARY,worker,folder)
            raw=self.channel.file(workspace.REPORT_PATH)
            _write(folder/'report.bin',raw)
            measured=workspace.parse_probe(raw,nonce)
            identity=(measured['process_id'],measured['boot_id'])
            previous=getattr(self.channel,'toolbox_identity',None)
            if previous is not None and previous!=identity:
                self.unknown_remote_state=True
                raise NativeActionError('Native process/kernel boot changed across probes; STOP_UNKNOWN')
            self.channel.toolbox_identity=identity
            for path in (LIBRARY,workspace.REQUEST_PATH):self._absent(path);self.owned.pop(path,None)
            self.channel.delete_owned(workspace.REPORT_PATH)
            self._absent(workspace.REPORT_PATH)
            _write(folder/'measured.json',_json(measured))
            self.inspection_complete=True
            return measured
        except BaseException:
            self._poison();raise

    def upload_data(self,mapping,*,report_sizes=(184,)):
        """Freshly budget and upload complete immutable small packets once."""
        if not isinstance(mapping,dict) or not mapping:raise ValueError('Explicit packet inventory required')
        measurement=self.probe()
        folder=self._folder('data')
        try:
            budget=workspace.admit_uploads(measurement,[len(raw) for raw in mapping.values()],
                  report_sizes=report_sizes,owned_existing_sizes=[len(raw) for raw in self.owned.values()])
            _write(folder/'budget.json',_json(budget))
            for path,raw in mapping.items():
                self.feature_attempted=True
                self._absent(path);self._upload(path,raw,folder)
                if self.channel.file(path)!=raw:raise NativeActionError('Packet readback differs')
            return budget
        except BaseException:
            self._poison();raise

    def phase(self,worker,request_path,request,report_path,validator,*,report_bytes=184,allow_large_readonly_report=False,native_report_capacity=0,native_overhead_units=0,before_dispatch=None):
        """One phase only. Caller supplies its strict finite protocol validator."""
        measurement=self.probe()
        folder=self._folder('phase')
        try:
            if allow_large_readonly_report and (request_path!='/tmp/jiritsu/a7m4.ssh-prereq-v2.request'
                    or report_path!='/tmp/jiritsu/a7m4.ssh-prereq-v2.result'):
                raise NativeActionError('Large read-only report exception is fixed to native inventory')
            if (type(native_report_capacity) is not int or not 0<=native_report_capacity<=131072
                    or type(native_overhead_units) is not int or not 0<=native_overhead_units<=2):
                raise NativeActionError('Invalid conservative native report reserve')
            unit=measurement['allocation_unit']
            extra=(max(0,((native_report_capacity+unit-1)//unit)-((report_bytes+unit-1)//unit))
                   +native_overhead_units)*unit
            budget=workspace.admit_uploads(measurement,[len(request),len(worker)],report_sizes=[report_bytes],
                    owned_existing_sizes=[len(raw) for raw in self.owned.values()],
                    report_limit=131072 if allow_large_readonly_report else 65535,reserve_extra_bytes=extra)
            _write(folder/'budget.json',_json(budget))
            for path in (LIBRARY,request_path,report_path):self._absent(path)
            self.feature_attempted=True
            self._upload(request_path,request,folder)
            if self.channel.file(request_path)!=request:raise NativeActionError('Native request readback differs')
            self._upload(LIBRARY,worker,folder,before_dispatch=before_dispatch)
            raw=self.channel.file(report_path)
            _write(folder/'report.bin',raw)
            decoded=validator(raw)
            diagnostic_event('native-phase-verified',helper=Path(request_path).name,
                native_phase=decoded.get('phase'),mode=decoded.get('mode'),
                status=decoded.get('native_status',decoded.get('status')),outcome=decoded.get('state'),
                complete=decoded.get('complete'),report_bytes=len(raw),report_sha256=sha256(raw).hexdigest())
            _write(folder/'validated.json',_json(decoded))
            self._absent(LIBRARY);self.owned.pop(LIBRARY,None)
            # PIN retains its request; the generic program worker may consume
            # it. Remove it only if it still equals this exact owned request.
            actual=self.channel.peek(request_path)
            if actual is not None:
                if actual!=request:raise NativeActionError('Owned request changed during native execution')
                self.channel.delete_owned(request_path);self._absent(request_path)
            self.owned.pop(request_path,None)
            self.channel.delete_owned(report_path);self._absent(report_path)
            if (request_path,report_path)==(FORWARD_REQUEST,FORWARD_RESULT) and isinstance(getattr(validator,'__self__',None),ForwardProtocol) and decoded.get('mode')==0:
                # A complete, cleaned, read-only preflight is not a persistent
                # operation. A later mode1 still marks feature_attempted first.
                self.feature_attempted=False;self.inspection_complete=True
            return decoded
        except (ProgramReadOnlyRefusal,ForwardReadOnlyRefusal) as refusal:
            try:
                proof=refusal.report
                allowed=((FORWARD_REQUEST,FORWARD_RESULT) if isinstance(refusal,ForwardReadOnlyRefusal)
                         else (PROGRAM_REQUEST,PROGRAM_RESULT))
                if ((request_path,report_path)!=allowed
                        or not self.channel.healthy or not self.feature_attempted
                        or self.owned.get(request_path)!=request
                        or getattr(self.channel,'toolbox_identity',None) is None
                        or proof['pid']!=self.channel.toolbox_identity[0]):
                    raise NativeActionError('Read-only refusal lacks exact native ownership/context')
                # Preserve failure evidence, then remove only byte-identical
                # request/report and prove the native library was consumed.
                _write(folder/'readonly-refusal.json',_json(dict(
                    schema='m4-first-mode0-readonly-refusal/1',mode=0,
                    phase=proof['phase'],status=proof['status'],writes=0,
                    report_sha256=sha256(raw).hexdigest(),feature_write_authorized=False)))
                self._absent(LIBRARY)
                if self.channel.file(request_path)!=request or self.channel.file(report_path)!=raw:
                    raise NativeActionError('Read-only refusal owned temporary content changed')
                for path in (request_path,report_path):
                    self.channel.delete_owned(path);self._absent(path);self.owned.pop(path,None)
                self.owned.pop(LIBRARY,None)
                _write(folder/'readonly-cleanup.json',_json(dict(complete=True,persistent_writes=0)))
                self.feature_attempted=False;self.inspection_complete=True;self.failed=True
            except BaseException:
                self._poison();raise
            # The transaction stays failed. Its coordinator alone may perform
            # bounded STOP if no earlier persistent operation was attempted.
            raise
        except BaseException:
            self._poison();raise

    def clean_packets(self):
        """Caller may call only after full authoritative host readback succeeds."""
        self._guard()
        for path,raw in list(self.owned.items()):
            if path==LIBRARY:raise NativeActionError('Unexpected live native library; do not clean')
            if self.channel.peek(path)!=raw:
                self._poison();raise NativeActionError('Owned packet changed; preserve unknown state')
            self.channel.delete_owned(path);self._absent(path)
            del self.owned[path]
