"""Explicit production USB backend for a source-bound original restore job.

Construction and preflight are local. Only __enter__, called by an explicitly
confirmed driver operation, touches a device. No discovery/import side effect.
"""
from contextlib import ExitStack
from hashlib import sha256
from pathlib import Path
import shutil
import subprocess
from . import original_restore as diff, original_ap_load, original_ap_original_on_source, workspace, program_worker
from . import original_runtime_inventory as inventory, settings_archive
from .capture_inputs import read_private
from .native_actions import NativeActions
from .native_channel import channel_class, LIBRARY
from .ownership import camera_lock, release_host_volumes, verify_normal_return
from .usb_read import ServiceSession, body_binding
from .restore_helper_loader import load_helper
from .original_program_adapter import OriginalProgramAdapter, program_batches
from .original_resource_adapter import OriginalResourceAdapter
from .original_atomic_adapter import OriginalAtomicAdapter
from .original_sound_adapter import OriginalSoundAdapter, sound_admission
from .original_restore_job import RequiredBoundary
from .device_job import Journal
from .settings_channel import SettingsChannel
from .settings_job import SettingsJob
from .settings_plan import plan_manifest
from .native_actions import _write, _json
from .run_log import event
from .original_wbi import OriginalWBI,load_sources,report_bound
from .original_ro import OriginalReadonly
from .restore_closure_loader import load_ro


def path_inventory(plan):
    reads={r['target_path']:max(r['source']['size'],r['target']['size'],1) for r in plan['objects']}
    reads.update({'/version.txt':4096,'/usr/lib/libJiritsu.so':160*1024*1024,
        '/usr/share/avsystemsound/custom.txt':65535,'/tmp/jbusy':64})
    owned={LIBRARY:65535,workspace.REQUEST_PATH:64,workspace.REPORT_PATH:workspace.REPORT.size,
        program_worker.REQUEST_PATH:program_worker.REQUEST.size,program_worker.RESULT_PATH:program_worker.REPORT.size,
        original_ap_load.REQUEST_PATH:original_ap_load.REQUEST.size,original_ap_load.RESULT_PATH:original_ap_load.REPORT.size,
        inventory.REQUEST_PATH:inventory.REQUEST.size,
        original_ap_original_on_source.REQUEST_PATH:original_ap_original_on_source.REQUEST.size,
        original_ap_original_on_source.RESULT_PATH:original_ap_original_on_source.REPORT.size}
    from . import original_resource_tail_original as original_tail
    from . import original_resource_tail_runtime as readonly_tail
    owned.update({original_tail.REQUEST_PATH:original_tail.REQUEST_BYTES,
        original_tail.RESULT_PATH:original_tail.MIN_REPORT+original_tail.MAX_PREIMAGE_BYTES,
        readonly_tail.REQUEST_PATH:readonly_tail.REQUEST_BYTES,
        readonly_tail.RESULT_PATH:readonly_tail.MIN_REPORT+readonly_tail.MAX_PREIMAGE_BYTES})
    for kind in ('tail-restore','resource-delta','original-atomic'):
        worker,*_=load_helper(kind)
        owned[worker.REQUEST_PATH]=getattr(worker,'MAX_REQUEST_BYTES',256)
        owned[worker.RESULT_PATH]=(worker.MAX_REPORT if kind=='original-atomic' else
            worker.MIN_REPORT+(worker.MAX_PREIMAGE_BYTES if kind=='tail-restore' else 0))
    for wire in load_sources()[:2]:
        owned.update({wire.REQUEST:wire.REQUEST_BYTES,wire.RESULT:report_bound(wire),wire.PENDING:report_bound(wire)})
    ro=load_ro();owned.update({ro.REQUEST_PATH:ro.REQUEST_BYTES,ro.RESULT_PATH:ro.MAX_REPORT,ro.PENDING_PATH:ro.MAX_REPORT})
    reports={inventory.RESULT_PATH:inventory.MAX_REPORT,inventory.PENDING_PATH:inventory.MAX_REPORT}
    return reads,owned,reports


class OriginalRestoreBackend:
    def __init__(self,output,*,compiler=None,owner_uid=None,session_factory=None,
                 release=release_host_volumes,normal_return=verify_normal_return,lock=None,verify_only=False):
        self.output=Path(output);self.compiler=compiler or shutil.which('zig');self.owner_uid=owner_uid
        self.session_factory=session_factory;self.release=release;self.verify_return=normal_return
        self.lock=lock or (lambda:camera_lock(owner_uid=owner_uid));self.stack=None;self.host_stack=None;self.plan=None
        self.original_load=None;self.source_load=None;self.original_on_source_load=None;self.serial=None;self.settings_index=0;self.ready=False
        self.verify_only=verify_only;self.adoption_endpoint="target";self.wbi_result=None;self.ro_result=None
        self.ro_index=0;self.resource_index=0;self.camera_io_started=False

    def preflight(self,plan):
        if type(self) is OriginalRestoreBackend and self.session_factory is None and not self.verify_only:
            raise ValueError('Legacy physical restore retired; use BackupTargetBackend with ST consumer protection')
        self.plan=diff.validate_plan(plan)
        if not self.compiler:raise ValueError('Bundled Zig compiler is unavailable')
        program_batches(plan)  # Complete local source/target chain, before USB.
        original_ap_load.make_plan(plan)
        if any(r['kind']=='audio' and r['action']!='NO_CHANGE' for r in plan['objects']):sound_admission(plan)
        for row in plan['objects']:
            if row['kind']=='resource' and row['action']!='NO_CHANGE':
                target=read_private(row['original_path'],16*1024*1024)
                if Path(row['path']).name.startswith('string_'):
                    from .looks import _strings
                    _strings(target)
                else:
                    from ..research.native_icons import _inspect_bank
                    _inspect_bank(target)
        self.reads,self.owned,self.reports=path_inventory(plan)
        self.channel_type=channel_class(self.reads,self.owned,readonly_reports=self.reports)
        # Reject a missing/incompatible local compiler before host volume work.
        version=subprocess.run([str(self.compiler),'version'],capture_output=True,text=True,check=True,timeout=20)
        if version.stdout.strip()!='0.13.0':raise ValueError('Zig0.13 is required')
        self.ready=True;event('original-backend-preflight',status='READY',object_count=len(self.plan['objects']))

    def __enter__(self):
        if not self.ready:raise ValueError('Original backend needs complete local preflight')
        self.stack=ExitStack();self.host_stack=ExitStack()
        try:
            self.host_stack.enter_context(self.lock())
            self.camera_io_started=self.session_factory is None
            self.released=self.release(self.output)
            self.session=(self.session_factory(self.channel_type,self.released) if self.session_factory else
                ServiceSession(channel_factory=self.channel_type,expected_usb_serial=self.released['camera']['usb_serial']))
            self.channel=self.stack.enter_context(self.session)
            for path in (*self.owned,*self.reports,'/tmp/jbusy'):
                if self.channel.peek(path) is not None:raise ValueError('Unowned native state present; preserve it: '+path)
            self.identity_actions=NativeActions(self.channel,self.output/'identity-native')
            runtime=self.runtime_evidence()
            self.serial=self.channel.serial()
            self.settings_journal=Journal(self.output/'settings-wire')
            self.settings=SettingsChannel(self.channel,intent=self.settings_journal,reply=self.settings_journal)
            self.inventory=inventory.OriginalRuntimeInventory(self.channel,self.output/'runtime-inventory',compiler=self.compiler)
            initial=self.inventory.measure()
            if not initial['usr_readonly_verified']:raise ValueError('Initial /usr is not the expected read-only mount')
            self.program=OriginalProgramAdapter(self.plan,self.channel,self.output/'programs',compiler=self.compiler,
                expected_process_id=runtime['process_id'])
            self.resources=OriginalResourceAdapter(self.plan,self.channel,self.output/'resources',compiler=self.compiler,
                runtime_evidence=self.runtime_evidence)
            self.atomic=OriginalAtomicAdapter(self.plan,self.channel,self.output/'atomic-resources',compiler=self.compiler,
                runtime_evidence=self.runtime_evidence)
            self.wbi=OriginalWBI(self.channel,self.output/'startup-adoption',compiler=self.compiler,runtime_evidence=self.runtime_evidence)
            self.sound=(OriginalSoundAdapter(self.plan,self.channel,self.output/'sound',compiler=self.compiler,
                runtime_evidence=self.runtime_evidence) if any(r['kind']=='audio' and r['action']!='NO_CHANGE'
                    for r in self.plan['objects']) else None)
            return self
        except BaseException:
            self.poison_unknown()
            try:self.stack.__exit__(*__import__('sys').exc_info())
            finally:self.host_stack.close();self.stack=None
            raise

    def __exit__(self,*args):
        try:
            result=self.stack.__exit__(*args)
        except BaseException:
            self.host_stack.close();raise
        finally:self.stack=None
        # Keep exclusive host ownership through the final same-body MSC proof.
        # Unknown failures do not perform that proof or leave an active lock.
        if args and args[0] is not None and not issubclass(args[0],RequiredBoundary):
            self.host_stack.close()
        return result

    def poison_unknown(self):
        channel=getattr(self,'channel',None)
        if channel is not None:
            channel.healthy=False;channel.safe_to_stop=False
        event('original-backend-held',status='STOP_UNKNOWN')

    def runtime_evidence(self):
        if sha256(self.channel.file('/version.txt')).hexdigest()!=diff.VERSION_SHA256 or sha256(self.channel.file('/usr/lib/libJiritsu.so')).hexdigest()!=diff.LOADER_SHA256:
            raise ValueError('Fresh firmware or loader identity differs')
        if body_binding(self.channel.serial())!=self.plan['body_binding']:raise ValueError('Current camera differs from original backup body')
        measured=self.identity_actions.probe()
        return dict(body_binding=self.plan['body_binding'],boot_id=measured['boot_id'],
            process_id=measured['process_id'],fresh=True)

    def context(self):
        return dict(self.runtime_evidence(),firmware='6.02',exclusive_owner=True,
                    camera_io=getattr(self.session,'camera_io',True))

    def capture_settings(self):return self.settings.capture()
    def read_complete(self,path):return self.channel.file(path)
    def prepare_current_runtime(self):
        runtime=self.runtime_evidence()
        self.source_load=original_ap_load.verify_borrowed(self.plan,self.channel,self.output/'source-ap-runtime',
            compiler=self.compiler,boot_id=runtime['boot_id'],pid=runtime['process_id'],endpoint='source')
        if not self.source_load['loaded_current_ap_verified']:
            if self.source_load.get('native_status') not in (-84,-18):
                self.adoption_endpoint='none'
                raise RequiredBoundary('Current AP read-only inspection refused; no restoration bytes dispatched. Inspect logs before choosing an adoption boundary')
            # Keep source_load failed and standard original_load independent.
            self.original_on_source_load=original_ap_original_on_source.verify_borrowed(
                self.plan,self.source_load,self.channel,self.output/'original-ap-on-source-runtime',
                compiler=self.compiler,runtime_evidence=self.runtime_evidence)
            if self.original_on_source_load['loaded_original_on_current_source_verified']:
                return self.original_on_source_load
            if self.original_on_source_load.get('native_status') not in (-84,-18):
                self.adoption_endpoint='none'
                raise RequiredBoundary('Separate original-on-source inspection refused; no restore or startup adoption dispatched')
            from .original_source_admission import validate_source_boot
            try:
                admission=validate_source_boot(self.plan)
            except ValueError as error:
                self.adoption_endpoint='none'
                raise RequiredBoundary('Current source is not one independently proved bootable forward combination; no startup adoption or restore writes dispatched: '+str(error)) from error
            _write(self.output/'source-boot-admission.json',_json(admission))
            self.adoption_endpoint='source'
            raise RequiredBoundary('Current disk source is not yet adopted; no restore byte was written. Prepare its verified startup boundary, cold-start, capture again and continue the same original target')
        return self.source_load
    def prepare_sound_runtime(self):
        if self.original_on_source_load is not None and self.original_on_source_load.get('loaded_original_on_current_source_verified') is True:
            return self.sound.prepare_original_on_source(self.original_on_source_load,self.source_load)
        return self.sound.prepare(self.source_load)
    def restore_programs(self,rows,targets):return self.program.execute()
    def restore_sound(self,row,source,target):
        if self.original_on_source_load is not None and self.original_on_source_load.get('loaded_original_on_current_source_verified') is True:
            # A new standard proof now requires original disk AND original RAM.
            return self.sound.execute(row,source,target,original_consumer_proof=self._original_runtime())
        return self.sound.execute(row,source,target)

    def _original_runtime(self):
        runtime=self.runtime_evidence()
        if self.original_load is None:
            self.original_load=original_ap_load.verify_borrowed(self.plan,self.channel,self.output/'original-ap-runtime',
                compiler=self.compiler,boot_id=runtime['boot_id'],pid=runtime['process_id'])
        if not self.original_load['loaded_original_ap_verified']:
            status=self.original_load.get('native_status')
            if status not in (-84,-18):
                self.adoption_endpoint='none'
                raise RequiredBoundary('Read-only AP load inspection could not establish adoption (status %s); preserve files and inspect diagnostic logs before choosing a startup boundary'%status)
            raise RequiredBoundary('Original program files are restored but the AP still runs previous bytes; a verified startup/load boundary is required before resource replacement')
        if (runtime['process_id'],runtime['boot_id'])!=(self.original_load['process_id'],self.original_load['boot_id']):
            raise ValueError('AP runtime proof is stale')
        return self.original_load

    def inspect_resource(self,row,source,target):
        # Atomically publishing original EOF is allowed only after original AP
        # references are actually loaded. Old inode readers remain untouched.
        proof=self._original_runtime()
        return dict(strategy='protected-delta' if len(source)>len(target) else
                    'atomic-target' if row.get('preferred_strategy')=='original-target-atomic' or len(target)<1024*1024
                    else 'protected-delta',source_inode_preservation_required=True,
                    original_ap_load_report_sha256=proof['report_sha256'])

    def verify_runtime_target(self):return self._original_runtime()

    def restore_resource_atomic(self,row,source,target,inspection):
        self.resources._authority(row,source,target)  # Parse original UXC bounds too.
        self._original_runtime()
        result=self.atomic.execute(row,source,target,reference_proof=inspection)
        return self._after_resource(row,target,result)
    def restore_resource_prefix(self,row,source,target,inspection):
        self._original_runtime();result=self.resources.restore_prefix(row,source,target)
        return self._after_resource(row,target+source[len(target):],result)
    def restore_resource_tail(self,row,source,target):
        self._original_runtime();result=self.resources.restore_tail(row,source,target)
        return self._after_resource(row,target,result)

    def _try_ro(self):
        self.ro_index+=1
        helper=OriginalReadonly(self.channel,self.output/('ro-finalizer-%03d'%self.ro_index),compiler=self.compiler,
            runtime_evidence=self.runtime_evidence)
        self.ro_result=helper.execute()
        return self.ro_result

    def _after_resource(self,row,expected,result):
        actual=self.channel.file(row['target_path'])
        if actual!=expected:raise ValueError('Complete resource endpoint changed before RO boundary')
        self.resource_index+=1;prefix='resource-completed-%03d'%self.resource_index
        _write(self.output/(prefix+'.json'),_json(dict(path=row['target_path'],identity=diff._identity(actual),receipt=result)))
        if (self.atomic.needs_usr_readonly_verification or self.resources.needs_readonly_verification):
            ro=self._try_ro();fresh=self.inventory.measure()
            if not fresh['usr_readonly_verified']:
                if not ro['known_ro_pending'] or ro['final_mount']!=1 or fresh.get('usr_mount_state')!='RW':
                    raise ValueError('RO result and fresh exact mount observation differ')
                raise RequiredBoundary('This complete resource is restored; /usr RO remains EBUSY. Prepare startup adoption, safely close, cold-start and continue only the remaining original differences')
            self.atomic.needs_usr_readonly_verification=False;self.resources.needs_readonly_verification=False
        return result

    def _adopt(self):
        if self.verify_only or self.adoption_endpoint=='none':return None
        if self.wbi_result is not None:return self.wbi_result
        for row in self.plan['objects']:
            if row['kind'] not in ('ap','cp','audio'):continue
            if diff._identity(self.channel.file(row['target_path']))!=row[self.adoption_endpoint]:
                raise ValueError('Complete program/sound endpoint changed before WBI adoption')
        self.wbi_result=self.wbi.adopt(program_fullpost_verified=True,approval_verified=True,no_ssh_started=True)
        _write(self.output/'startup-adoption-result.json',_json(dict(endpoint=self.adoption_endpoint,**self.wbi_result)))
        return self.wbi_result

    def restore_settings(self,plan):
        self.settings_index+=1;prefix='settings-%02d'%self.settings_index
        _write(self.output/(prefix+'-plan.json'),_json(plan_manifest(plan)))
        settings_archive.save_snapshot(self.settings.capture(),self.output/(prefix+'-before'))
        def binding(value):
            runtime=self.runtime_evidence()
            return dict(identity=body_binding(self.channel.serial())['serial_sha256'],boot_id=runtime['boot_id'],
                nonce=value.nonce,model='ILCE-7M4',firmware='6.02',exclusive_owner=True)
        job=SettingsJob(self.settings,bind=binding,journal=Journal(self.output/(prefix+'-journal')))
        job.release(plan,dict(schema='a7m4-toolbox-settings-release/1',plan_id=plan.plan_id,identity=plan.identity,
            boot_id=plan.boot_id,nonce=plan.nonce,backup_verified=True,program_dependencies_verified=True,
            user_risk_confirmation_fresh=True,release_gate='RELEASED'))
        result=job.execute(plan)
        settings_archive.save_snapshot(job.verified_snapshot,self.output/(prefix+'-after'))
        return dict(result,complete=result['status']=='DONE',plan_id=plan.plan_id,
            saved_groups=result['saved_groups'])

    def finish_known_context(self):
        self.runtime_evidence()
        adoption=self._adopt()
        proof=self.inventory.measure()
        if not proof['usr_readonly_verified']:
            ro=self.ro_result if self.ro_result and self.ro_result['known_ro_pending'] else self._try_ro()
            proof=self.inventory.measure()
        else:ro=self.ro_result
        known_pending=(not proof['usr_readonly_verified'] and ro is not None and ro['known_ro_pending']
            and ro['final_mount']==1 and proof.get('usr_mount_state')=='RW'
            and adoption is not None and adoption.get('success') is True)
        if not proof['usr_readonly_verified'] and not known_pending:
            raise ValueError('RO/known-pending adoption boundary not established; no STOP permission')
        for path in (*self.owned,*self.reports,*getattr(self.channel,'_original_stages',()),'/tmp/jbusy'):
            if self.channel.peek(path) is not None:raise ValueError('Native/stage state remains; preserve it: '+path)
        self.channel.allow_clean_stop()
        return dict(proof,exact_owned_cleanup_verified=True,safe_stop_allowed=True,
            known_deferred_readonly=bool(known_pending),native_inputs_closed=True,wbi_adoption=adoption,
            requires_physical_cold_start=bool(known_pending or adoption and adoption.get('success')),
            adoption_endpoint=self.adoption_endpoint,
            adoption_refused=bool(adoption is not None and not adoption.get('success')))

    def normal_return(self):
        try:
            if not getattr(self.session,'stop_succeeded',False) or not getattr(self.session,'resources_disposed',False):
                raise ValueError('Service exit was not confirmed')
            result=self.verify_return(self.released)
            return dict(result,service_exit_confirmed=True)
        finally:
            if self.host_stack is not None:self.host_stack.close()
