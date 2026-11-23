"""Independent selected-backup C restore coordinator; no install-history authority.

Every execution view is rebuilt from current capture plus the selected target.
Native helpers retain exact preimage/readback/cleanup/STOP requirements.
"""
from .. import resource_profile as device_scope
from hashlib import sha256
import json
import os
from pathlib import Path
import re
from contextlib import contextmanager

from . import original_restore as diff, settings_archive
from .capture_inputs import read_private
from .settings_plan import validate_snapshot
from .settings_scope import settings_scope_freshness_report
from .original_restore_job import RequiredBoundary
from .backup_target_execution import materialize as execution_view, validate_plan as validate_execution
from .backup_target_settings import settings_plans, check_settings_source, check_settings_target, settings_plan_changed, check_snapshot_C

class BackupTargetJobError(RuntimeError):
    def __init__(self,message,result):super().__init__(message);self.result=result


class BackupTargetCoordinator:
    def __init__(self,scope_plan,output,*,verify_after_startup=False):
        from . import backup_target_scope
        self.output=Path(output).absolute()
        if self.output.exists() or not self.output.parent.is_dir() or any(p.is_symlink() for p in (self.output,*self.output.parents)):
            raise ValueError('New private backup-target job directory required')
        from .job_ownership import create_job_output
        create_job_output(self.output)
        self.authority=execution_view(scope_plan,self.output/'targets')
        self.plan=self.authority.checked_plan()
        scope_plan=self.plan['scope_plan']
        self.verify_after_startup=verify_after_startup
        self.receipt=self.output/'job.private.json'
        self.original_settings=settings_archive.load_snapshot(Path(scope_plan['backup_capture']['receipt']).parent/'settings')
        self.source_settings=settings_archive.load_snapshot(Path(scope_plan['current_capture']['receipt']).parent/'settings')
        check_snapshot_C(self.source_settings,self.authority,backup=False)
        check_snapshot_C(self.original_settings,self.authority,backup=True)
        self.expected={r['path']:r['source'] for r in self.plan['objects']}
        self.events=[];self.attempted=False
        from .run_log import active_run_id
        self.result=dict(schema='a7m4-backup-target-job/1',resource_profile=device_scope.ID,plan_id=self.plan['plan_id'],scope_plan_id=scope_plan['plan_id'],
            model='ILCE-7M4',firmware='6.02',run_id=active_run_id(),backup_capture=scope_plan['backup_capture'],source_capture=scope_plan['current_capture'],
            body_binding=self.plan['body_binding'],receipt=str(self.receipt),status='HELD',camera_io=False,simulation=True,
            network_io=False,complete=False,all_targets_verified=False,scope_target_readback_complete=False,
            post_boot_scope_verification_complete=False,functional_restore_complete=False,
            restores_entire_original_files=False,install_history_required=False,E_F_observation_only=True,
            normal_return_verified=False,service_exit_confirmed=False,stop_safe=False,automatic_retry=False,events=self.events)
        self._save('plan.private.json',self.plan);self._record('created')

    def _save(self,name,value):
        raw=json.dumps(value,ensure_ascii=False,sort_keys=True,indent=2,allow_nan=False).encode()+b'\n'
        path=self.output/name
        # These are our own private journal files; commit before dispatch.
        temporary=path.with_name(path.name+'.pending')
        fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
        os.replace(temporary,path)

    def _record(self,event,**facts):
        from .run_log import event as diagnostic_event
        diagnostic_event('backup-target-restore-stage',stage=event,operation=facts.get('operation'),object_path=facts.get('path'))
        self.events.append(dict(index=len(self.events)+1,event=event,**facts))
        self._save('job.private.json',self.result)

    def _read(self,backend,row,identity,label):
        raw=backend.read_complete(row['target_path'])
        if type(raw) is not bytes or len(raw)!=identity['size']:
            raise ValueError('Scoped '+label+' EOF mismatch: '+row['path'])
        check=getattr(backend,'check_object',None)
        if check is None:raise ValueError('Backup-target backend needs a scoped C/D barrier')
        return check(row,raw,target=identity!=row['source'],expected_size=identity['size'])

    def _operation(self,backend,label,callback,**facts):
        self._record('operation-intent',operation=label,**facts)
        # Mark before dispatch. An exception never becomes a safe retry merely
        # because the adapter did not return a changed-byte count.
        self.attempted=True
        receipt=callback()
        if type(receipt) is not dict or receipt.get('complete') is not True:
            raise ValueError('Adapter did not prove native completion: '+label)
        self._record('operation-result',operation=label,receipt=receipt)
        return receipt

    def _restore_settings_kind(self,backend,source_plans,*,kind,boot_id):
        # Restore the selected backup's ordinary look values only AFTER the
        # independent ST consumer-safety gate has permitted program removal.
        # AP55 retains its separate, later resource-completion boundary.
        if kind not in ('looks','ap55'):raise ValueError('Unknown finite settings restore kind')
        current=backend.capture_settings();validate_snapshot(current)
        for baseline_plan in source_plans:
            if kind=='looks' or baseline_plan.kind=='backup-target-ap55':
                check_settings_source(baseline_plan,current)
        plans=settings_plans(current,self.original_settings,self.authority,boot_id=boot_id)
        plan=next((p for p in plans if (p.kind=='backup-target-ap55')==(kind=='ap55')),None)
        if plan is not None and settings_plan_changed(plan):
            self._operation(backend,'restore-backup-settings-C',lambda:backend.restore_settings(plan),kind=kind)

    def _protect_look_consumers(self,backend,fresh,context):
        """Never remove code while its saved or live consumers still use it."""
        from . import restore_st_settings as st
        plan=st.make_plan(fresh,boot_id=context['boot_id'])
        changed=settings_plan_changed(plan)
        from .settings_plan import plan_manifest
        self._save('consumer-ST-plan.json',plan_manifest(plan))
        if changed:
            self._operation(backend,'protect-current-and-six-bases-ST',lambda:backend.restore_settings(plan))
        current=backend.capture_settings();st.require_st(current)
        settings_archive.save_snapshot(current,self.output/'consumer-ST-readback')
        self.result['consumer_safety']=dict(stage='ST_SAVED_PATCHES_RETAINED',boot_id=context['boot_id'],
            settings_plan_id=plan.plan_id,all_four_planes_ST_verified=True,
            current_and_six_bases_per_profile=True,program_removal_gate_verified=False)
        self._record('consumer-ST-saved-before-program-removal')
        prior=self.result.get('previous_consumer_safety') or {}
        prior_boot=prior.get('boot_id') if not changed and (
            prior.get('stage')=='ST_SAVED_PATCHES_RETAINED' and prior.get('all_four_planes_ST_verified') is True
            and prior.get('boot_id')==self.result.get('previous_boot_id')) else None
        # The concrete backend must provide native model evidence. Saving BK4
        # alone is not that evidence, even when no settings WRITE was needed.
        protect=getattr(backend,'verify_restore_consumers',None)
        if protect is None:raise ValueError('Live current/base consumer proof adapter required before program removal')
        proof=protect(prior_boot_id=prior_boot)
        if type(proof) is not dict or proof.get('program_removal_gate_verified') is not True:
            raise ValueError('Live current/base ST model is not proved; program patches retained')
        self.result['consumer_safety'].update(stage='LIVE_ST_VERIFIED',program_removal_gate_verified=True,model_proof=proof)
        self._record('live-consumers-ST-verified-before-program-removal')
        # The safety transaction deliberately changed a few prior source C
        # fields. Rebind their exact current preimages, not unrelated E/F.
        return settings_plans(current,self.original_settings,self.authority,boot_id=context['boot_id'])

    def _finish(self,backend):
        proof=backend.finish_known_context()
        known_pending=(type(proof) is dict and proof.get('known_deferred_readonly') is True
            and proof.get('native_inputs_closed') is True and (proof.get('wbi_adoption') or {}).get('success') is True)
        if (type(proof) is not dict or any(proof.get(k) is not True for k in
            ('exact_owned_cleanup_verified','native_context_healthy','safe_stop_allowed'))
                or proof.get('usr_readonly_verified') is not True and not known_pending):
            raise ValueError('Fresh RO or reviewed known-pending startup boundary, exact cleanup and healthy close required')
        self.result['finalizer']=proof
        self._record('ready-for-service-exit')

    @contextmanager
    def _session(self,backend):
        with backend:
            try:yield
            except RequiredBoundary:
                try:self._finish(backend)
                except BaseException:
                    backend.poison_unknown()
                    raise
                raise
            except BaseException:
                backend.poison_unknown()
                raise

    def run(self,backend,*,ack_original=False,ack_backup=False,ack_brick=False,ack_risk=False,verify_runtime=False):
        if not all(type(v) is bool and v for v in (ack_original,ack_backup,ack_brick,ack_risk)):
            raise ValueError('Fresh original-backup, current-backup and risk confirmations required')
        try:
            self.authority.checked_plan(self.plan)
            if self.plan['blockers']:raise ValueError('Original diff has unresolved blockers')
            # Must fail locally before opening a device if any needed writer or
            # finalizer is absent. This is not the USB implementation itself.
            backend.preflight(self.plan)
            with self._session(backend):
                context=backend.context()
                if (type(context) is not dict or context.get('body_binding')!=self.plan['body_binding']
                        or context.get('firmware')!='6.02' or context.get('exclusive_owner') is not True
                        or type(context.get('camera_io')) is not bool
                        or not re.fullmatch(r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}',context.get('boot_id',''))):
                    raise ValueError('Fresh same-body firmware/boot/exclusive context missing')
                if context['camera_io'] and (type(context.get('process_id')) is not int or context['process_id']<=0):
                    raise ValueError('Actual native process identity missing')
                self.result.update(camera_io=context['camera_io'],simulation=not context['camera_io'],boot_id=context['boot_id'],
                    status='VERIFYING_COMPLETE_CURRENT_SOURCE')
                self._record('session-bound',context=context)
                if self.result.get('previous_boot_id') is not None:
                    if self.result.get('startup_confirmation_user_provided') is not True or context['boot_id']==self.result['previous_boot_id']:
                        raise ValueError('A new same-body boot and fresh startup confirmation are required to continue this checkpoint')
                for row in self.plan['objects']:self._read(backend,row,row['source'],'source')
                fresh=backend.capture_settings();validate_snapshot(fresh)
                settings_archive.save_snapshot(fresh,self.output/'settings-before')
                freshness=settings_scope_freshness_report(self.source_settings,fresh,operation='original-restore',
                    native_context=dict(process_id=context.get("process_id"),boot_id=context["boot_id"]))
                self._save('settings-freshness.json',freshness)
                self.result['settings_freshness']=freshness
                self._record('initial-settings-freshness-checked',stable=freshness['stable'])
                self.result['settings_freshness']['legacy_scope_is_observation_only']=True
                # Exact selected C and fresh D are checked by the finite plans below.
                # The legacy wider settings report cannot make E/F an admission gate.
                source_plans = settings_plans(self.source_settings, self.original_settings, self.authority,
                    boot_id=context['boot_id'])
                for plan in source_plans:
                    check_settings_source(plan, fresh)
                self._record('all-current-sources-verified',objects=len(self.plan['objects']))
                if any(r['kind'] in ('ap','audio') and r['action']!='NO_CHANGE' for r in self.plan['objects']):
                    prepare=getattr(backend,'prepare_current_runtime',None)
                    if self.result['camera_io'] and prepare is None:
                        raise ValueError('Restore requires actual current AP source runtime proof')
                    if prepare is not None:
                        try:prepare()
                        finally:
                            source_proof=getattr(backend,'source_load',None)
                            if source_proof is not None:self.result['source_load']=dict(source_proof)
                            separate=getattr(backend,'original_on_source_load',None)
                            if separate is not None:
                                self.result['original_on_source_load']=dict(separate)
                                self._record('separate-original-on-source-inspection',verified=separate.get('loaded_original_on_current_source_verified') is True)
                if any(r['kind']=='audio' and r['action']!='NO_CHANGE' for r in self.plan['objects']):
                    prepare=getattr(backend,'prepare_sound_runtime',None)
                    if self.result['camera_io'] and prepare is None:raise ValueError('Sound consumer profile missing')
                    if prepare is not None:prepare()
                programs=[r for r in self.plan['objects'] if r['kind'] in ('ap','cp') and r['action']!='NO_CHANGE']
                if programs and not verify_runtime:
                    source_plans=self._protect_look_consumers(backend,fresh,context)
                    targets={r['path']:read_private(r['original_path'],160*1024*1024) for r in programs}
                    self._operation(backend,'restore-original-program-diff',lambda:backend.restore_programs(programs,targets))
                    for row in programs:
                        # AP sound descriptors are restored atomically with sound C next.
                        if row['kind']=='cp':self._read(backend,row,row['target'],'program target')
                        self.expected[row['path']]=row['target']
                for row in self.plan['objects']:
                    if verify_runtime or row['kind']!='audio':continue
                    if row['action']=='NO_CHANGE' and not backend.sound_change_required():continue
                    # Program descriptors have been restored before the bank;
                    # the sound adapter must separately prove runtime consumers.
                    source=self._read(backend,row,self.expected[row['path']],'sound source')
                    target=read_private(row['original_path'],160*1024*1024)
                    self._operation(backend,'restore-original-sound-diff',lambda:backend.restore_sound(row,source,target))
                    self._read(backend,row,row['target'],'sound target');self.expected[row['path']]=row['target']
                if not verify_runtime:
                    self._restore_settings_kind(backend,source_plans,kind='looks',boot_id=context['boot_id'])
                for row in self.plan['objects']:
                    if verify_runtime or row['kind']!='resource' or row['action']=='NO_CHANGE':continue
                    source=self._read(backend,row,self.expected[row['path']],'resource source')
                    target=read_private(row['original_path'],16*1024*1024)
                    if len(source)<len(target):raise ValueError('Resource source is shorter than original')
                    if not source.startswith(target) or row.get('preferred_strategy')=='original-target-atomic':
                        inspection=backend.inspect_resource(row,source,target)
                        if type(inspection) is not dict or inspection.get('strategy') not in ('atomic','atomic-target','protected-delta','boundary'):
                            raise ValueError('Fresh resource strategy/identity evidence required')
                        self._record('resource-strategy',path=row['path'],inspection=inspection)
                        if inspection['strategy']=='boundary':
                            raise RequiredBoundary(inspection.get('reason','Runtime boundary required before prefix restore'))
                        if inspection['strategy']=='atomic-target':
                            self._operation(backend,'restore-original-resource-atomic',
                                lambda:backend.restore_resource_atomic(row,source,target,inspection),path=row['path'])
                            self._read(backend,row,row['target'],'atomic original full target')
                            self.expected[row['path']]=row['target']
                            continue
                        self._operation(backend,'restore-original-resource-prefix',
                            lambda:backend.restore_resource_prefix(row,source,target,inspection),path=row['path'])
                        intermediate=target+source[len(target):]
                        self._read(backend,row,diff._identity(intermediate),'resource prefix/complement')
                        self.expected[row['path']]=diff._identity(intermediate);source=intermediate
                    if len(source)>len(target):
                        # This requires separately established index/load and
                        # native mapping evidence; prefix equality is not it.
                        tail_receipt=self._operation(backend,'restore-original-resource-tail',
                            lambda:backend.restore_resource_tail(row,source,target),path=row['path'])
                        self._read(backend,row,row['target'],'resource full target')
                        self.expected[row['path']]=row['target']
                if not verify_runtime:
                    self._restore_settings_kind(backend,source_plans,kind='ap55',boot_id=context['boot_id'])
                verified=[]
                for index,row in enumerate(self.plan['objects']):
                    raw=self._read(backend,row,row['target'],'final original')
                    folder=self.output/'post';folder.mkdir(mode=0o700,exist_ok=True)
                    path=folder/('%03d.bin'%index)
                    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                    with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
                    verified.append(dict(path=str(path.relative_to(self.output)),target_path=row['target_path'],
                        **diff._identity(raw),projected_target_forecast=row['target'],C_D_verified=True,whole_F_hash_admission=False))
                final=backend.capture_settings();validate_snapshot(final)
                settings_archive.save_snapshot(final,self.output/'settings-final')
                check_settings_target(final, self.original_settings, self.authority, allow_saved_ram=verify_runtime)
                self.result['settings_C_verified'] = True
                self.result['E_F_observation_only'] = True
                self.result['verified_objects']=verified
                self.result['file_targets_readback_verified']=True
                self._record('all-projected-targets-readback',objects=len(self.plan['objects']))
                if verify_runtime:
                    proof=backend.verify_runtime_target()
                    if type(proof) is not dict or proof.get('C_loaded_verified') is not True:
                        raise RequiredBoundary('Original AP runtime adoption is not yet proved')
                    self.result['runtime_target_proof']=proof
                self._finish(backend)
            normal=backend.normal_return()
            if type(normal) is not dict or any(normal.get(k) is not True for k in
                ('service_exit_confirmed','normal_msc_verified','same_body_and_port')):
                raise ValueError('Service exit and same-body MSC return not fully proved')
            real=self.result['camera_io'] is True and self.result['simulation'] is False
            self.result.update(status='ALL_TARGETS_VERIFIED_REBOOT_PENDING' if real else 'SIMULATED_ALL_TARGETS_VERIFIED',
                all_targets_verified=real,scope_target_readback_complete=real,
                normal_return_verified=True,service_exit_confirmed=True,stop_safe=True,
                normal_return=normal,complete=False)
            if self.result['finalizer'].get('known_deferred_readonly') and real:
                self.result.update(status='ALL_TARGETS_READBACK_RO_PENDING',scope_target_readback_complete=False,all_targets_verified=False)
            if self.result['finalizer'].get('adoption_refused') and real:
                self.result.update(status='RUNTIME_BOUNDARY_REQUIRED',
                    error='WBI preparation had a known clean refusal; inspect diagnostic logs before the next adoption attempt')
            if verify_runtime and real and self.result['finalizer']['usr_readonly_verified']:
                self.result.update(status='POST_STARTUP_VERIFIED_AWAITING_USER_ACCEPTANCE',
                    post_boot_scope_verification_complete=True)
            self._record('awaiting-user-acceptance' if verify_runtime else 'awaiting-reboot-acceptance');return self.result
        except RequiredBoundary as error:
            # Native adapter must prove its known boundary and arrange exact
            # safe close separately; do not infer STOP from this exception.
            normal=backend.normal_return()
            known=type(normal) is dict and all(normal.get(k) is True for k in
                ('service_exit_confirmed','normal_msc_verified','same_body_and_port'))
            self.result.update(status='RUNTIME_BOUNDARY_REQUIRED' if known else 'STOP_UNKNOWN',error=str(error),complete=False,
                stop_safe=known,normal_return_verified=known,service_exit_confirmed=known,normal_return=normal)
            self._record('runtime-boundary-required',reason=str(error));return self.result
        except BaseException as error:
            io_attempted=getattr(backend,'camera_io_started',False) is True
            if io_attempted and self.result['camera_io'] is False:
                self.result.update(camera_io=None,simulation=False,camera_io_attempted=True)
            self.result.update(status='STOP_UNKNOWN' if self.attempted or io_attempted else 'STOPPED_PREFLIGHT',
                error=str(error),complete=False,all_targets_verified=False,scope_target_readback_complete=False,
                stop_safe=False,normal_return_verified=False,service_exit_confirmed=False,
                mutation_phase_attempted=self.attempted)
            self._record('failure',error_type=type(error).__name__)
            if isinstance(error,(KeyboardInterrupt,SystemExit)):raise
            raise BackupTargetJobError(str(error),self.result) from error
