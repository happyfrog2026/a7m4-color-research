"""Borrowed-backend original-backup coordinator, no discovery on import.

The production backend owns one exclusive authenticated USB session, native
freshness/space/RO/cleanup/STOP and MSC evidence. This coordinator independently
verifies complete source/target bytes and business settings, journals every
boundary and never retries. The default public execution gate remains HELD
until all production adapters are reviewed; injected offline runs are simulated.
"""
from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import re

from . import original_restore as diff
from .capture_inputs import read_private
from .settings_plan import validate_snapshot, plan_original_values, body_identity, AP55_COLLATERAL, METADATA_PROFILE
from . import settings_archive, native_ui
from .settings_job import check_full, _maps
from .settings_scope import settings_scope_freshness_report
from types import SimpleNamespace
from contextlib import contextmanager


class RestoreJobError(RuntimeError):
    def __init__(self,message,result):super().__init__(message);self.result=result


class RequiredBoundary(RuntimeError):
    """Known safe boundary must be explained by the concrete native adapter."""


class OriginalRestoreCoordinator:
    def __init__(self,current_capture,original_capture,output,*,post_startup_ap55=False):
        self.plan=diff.make_plan(current_capture,original_capture,post_startup_ap55=post_startup_ap55)
        self.post_startup_ap55=post_startup_ap55
        self.output=Path(output).absolute()
        if self.output.exists() or not self.output.parent.is_dir() or any(p.is_symlink() for p in (self.output,*self.output.parents)):
            raise ValueError('New real private restore job directory required')
        from .job_ownership import create_job_output
        create_job_output(self.output)
        self.receipt=self.output/'job.private.json'
        self.original_settings=settings_archive.load_snapshot(Path(original_capture).absolute().parent/'settings')
        self.source_settings=settings_archive.load_snapshot(Path(current_capture).absolute().parent/'settings')
        self.expected={r['path']:r['source'] for r in self.plan['objects']}
        self.events=[];self.attempted=False
        from .run_log import active_run_id
        self.result=dict(schema='a7m4-original-backup-restore-job/1',resource_profile='m4-602-six-language/1',plan_id=self.plan['plan_id'],run_id=active_run_id(),
            original_capture=self.plan['original_capture'],source_capture=self.plan['source_capture'],
            original_settings_evidence=self.plan['settings']['original_evidence'],
            original_direct_cp_evidence=self.plan['settings']['original_direct_cp'],
            body_binding=self.plan['body_binding'],receipt=str(self.receipt),status='HELD',
            camera_io=False,simulation=True,network_io=False,complete=False,
            all_targets_verified=False,full_file_restore_complete=False,
            functional_restore_complete=False,post_boot_full_file_verification_complete=False,
            user_boot_function_acceptance='NOT_PERFORMED',normal_return_verified=False,
            service_exit_confirmed=False,stop_safe=False,automatic_retry=False,
            fixed_round_count=False,events=self.events)
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
        diagnostic_event('original-restore-stage',stage=event,operation=facts.get('operation'),object_path=facts.get('path'))
        self.events.append(dict(index=len(self.events)+1,event=event,**facts))
        self._save('job.private.json',self.result)

    def _read(self,backend,row,identity,label):
        raw=backend.read_complete(row['target_path'])
        if type(raw) is not bytes or diff._identity(raw)!=identity:
            raise ValueError('Complete '+label+' EOF/SHA mismatch: '+row['path'])
        return raw

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
            diff.validate_plan(self.plan)
            if self.post_startup_ap55 and (not verify_runtime or self.plan['operation']!='NO_OP'):
                raise ValueError('AP55 post-startup exception is verification-only and cannot authorize WRITE/SAVE')
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
                for row in self.plan['objects']:self._read(backend,row,row['source'],'source')
                fresh=backend.capture_settings();validate_snapshot(fresh)
                settings_archive.save_snapshot(fresh,self.output/'settings-before')
                freshness=settings_scope_freshness_report(self.source_settings,fresh,operation='original-restore',
                    native_context=dict(process_id=context.get("process_id"),boot_id=context["boot_id"]))
                self._save('settings-freshness.json',freshness)
                self.result['settings_freshness']=freshness
                self._record('initial-settings-freshness-checked',stable=freshness['stable'])
                if not freshness['stable']:
                    raise ValueError('Protected settings changed since source capture: '+ '; '.join(freshness['errors'][:3]))
                # Captured source/original remain immutable business intent.
                # Subsequent strict readback guards bind this freshly admitted
                # live snapshot, never replay historical header generations.
                settings_reference=SimpleNamespace(baseline=fresh,identity=body_identity(fresh.serial),
                    groups=(),metadata_profile='strict-nonrecord-unchanged/1')
                settings_expected=_maps(fresh)
                settings_previous=fresh;settings_after_save=False;settings_ui_saved=False
                settings_mutation_started=False;settings_rebind_count=0
                def before_settings_mutation(current):
                    nonlocal settings_reference,settings_expected,settings_previous
                    nonlocal settings_after_save,settings_ui_saved,settings_rebind_count
                    if settings_mutation_started:return
                    settings_rebind_count+=1
                    if settings_rebind_count>3:raise ValueError('Pre-mutation settings observation bound exceeded')
                    report=settings_scope_freshness_report(settings_previous,current,operation='original-restore',
                        native_context=dict(process_id=context.get('process_id'),boot_id=context['boot_id']))
                    prefix='settings-pre-mutation-%02d'%settings_rebind_count
                    settings_archive.save_snapshot(settings_previous,self.output/(prefix+'-before'))
                    settings_archive.save_snapshot(current,self.output/(prefix+'-after'))
                    self._save(prefix+'.json',report)
                    if not report['stable']:
                        raise ValueError('Owned settings/dependencies changed before first mutation: '+ '; '.join(report['errors'][:3]))
                    settings_reference=SimpleNamespace(baseline=current,identity=body_identity(current.serial),
                        groups=(),metadata_profile='strict-nonrecord-unchanged/1')
                    settings_expected=_maps(current);settings_previous=current
                    settings_after_save=False;settings_ui_saved=False
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
                if programs:
                    targets={r['path']:read_private(r['original_path'],160*1024*1024) for r in programs}
                    self._operation(backend,'restore-original-program-diff',lambda:backend.restore_programs(programs,targets))
                    for row in programs:
                        self._read(backend,row,row['target'],'program target');self.expected[row['path']]=row['target']
                for row in self.plan['objects']:
                    if row['kind']!='audio' or row['action']=='NO_CHANGE':continue
                    # Program descriptors have been restored before the bank;
                    # the sound adapter must separately prove runtime consumers.
                    source=self._read(backend,row,self.expected[row['path']],'sound source')
                    target=read_private(row['original_path'],160*1024*1024)
                    self._operation(backend,'restore-original-sound-diff',lambda:backend.restore_sound(row,source,target))
                    self._read(backend,row,row['target'],'sound target');self.expected[row['path']]=row['target']
                for row in self.plan['objects']:
                    if row['kind']!='resource' or row['action']=='NO_CHANGE':continue
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
                        if self.result['camera_io']:
                            from . import original_ap_load
                            proof=tail_receipt.get('original_ap_load_proof',{})
                            raw=read_private(proof.get('native_report_path',''),original_ap_load.REPORT.size)
                            loaded=original_ap_load.parse_report(original_ap_load.make_plan(self.plan),raw,
                                bytes.fromhex(proof.get('nonce_hex','')),boot_id=context['boot_id'],pid=context['process_id'])
                            if not loaded['loaded_original_ap_verified']:
                                raise ValueError('Tail completion lacks independent original AP runtime proof')
                        self._read(backend,row,row['target'],'resource full target')
                        self.expected[row['path']]=row['target']
                # Original values are independently generated from original
                # Snapshot; no previous feature job or inverse plan is used.
                for kind in ('original-fl23','original-ap55'):
                    current=backend.capture_settings();validate_snapshot(current)
                    before_settings_mutation(current)
                    check_full(settings_reference,current,settings_expected,
                               after_save=settings_after_save,previous=settings_previous,native_ui_saved=settings_ui_saved)
                    current_diff=diff.settings_diff(current,self.original_settings,post_startup_ap55=self.post_startup_ap55)
                    selected=[r for r in current_diff['records'] if
                              ((r['chip'],r['key'])==diff.AP55)==(kind=='original-ap55')]
                    if not selected:continue
                    plan=plan_original_values(current,self.original_settings,kind=kind,
                        identity=body_identity(current.serial),boot_id=context['boot_id'],nonce=os.urandom(16).hex())
                    settings_mutation_started|=any(r.before_ram!=r.after_ram or r.before_saved!=r.after_saved for r in plan.records)
                    receipt=self._operation(backend,'restore-original-settings-values',lambda:backend.restore_settings(plan),kind=kind)
                    saved_groups=[group for group in plan.groups if any(
                        r.before_saved!=r.after_saved for r in plan.records if r.key>>16==group)]
                    if receipt.get('plan_id')!=plan.plan_id or receipt.get('saved_groups')!=saved_groups:
                        raise ValueError('Original settings receipt plan/SAVE groups differ')
                    after=backend.capture_settings();validate_snapshot(after)
                    expected=_maps(current)
                    for record in plan.records:
                        pair=record.chip,record.key
                        for plane in ('ram','saved'):
                            expected[plane][pair]=type(expected[plane][pair])(expected[plane][pair].attrs,getattr(record,'after_'+plane))
                    selected_pairs={(r.chip,r.key) for r in plan.records}
                    for group in saved_groups:
                        for pair,value in expected['ram'].items():
                            if pair[1]>>16!=group:continue
                            if (pair not in selected_pairs and value!=expected['saved'][pair]
                                    and not (kind=='original-ap55' and pair in AP55_COLLATERAL)
                                    and not (group==0x02CF and native_ui.diagnostic(pair,expected['ram']))):
                                raise ValueError('Unreviewed original SAVE collateral merge')
                            # SAVE happens before the selected RAM values are
                            # restored. Selected saved targets may intentionally
                            # differ from the final RAM plane.
                            if pair not in selected_pairs:
                                expected['saved'][pair]=value
                        expected['bin']=dict(expected['saved']);expected['bak']=dict(expected['saved'])
                    check_full(plan,after,expected,after_save=bool(saved_groups),native_ui_saved=0x02CF in saved_groups)
                    settings_reference=plan;settings_expected=expected
                    settings_previous=after;settings_after_save=bool(saved_groups)
                    settings_ui_saved|=0x02CF in saved_groups
                verified=[]
                for index,row in enumerate(self.plan['objects']):
                    raw=self._read(backend,row,row['target'],'final original')
                    folder=self.output/'post';folder.mkdir(mode=0o700,exist_ok=True)
                    path=folder/('%03d.bin'%index)
                    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                    with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
                    verified.append(dict(path=str(path.relative_to(self.output)),target_path=row['target_path'],**row['target']))
                final=backend.capture_settings();validate_snapshot(final)
                before_settings_mutation(final)
                check_full(settings_reference,final,settings_expected,
                           after_save=settings_after_save,previous=settings_previous,native_ui_saved=settings_ui_saved)
                settings_archive.save_snapshot(final,self.output/'settings-final')
                final_settings_diff=diff.settings_diff(final,self.original_settings,post_startup_ap55=self.post_startup_ap55)
                self.result['post_startup_settings_policy']=final_settings_diff['post_startup_settings_policy']
                if final_settings_diff['records']:
                    raise ValueError('Final original business values do not match')
                self.result['verified_objects']=verified
                self.result['file_targets_readback_verified']=True
                self._record('all-original-file-targets-readback',objects=len(self.plan['objects']))
                if verify_runtime:
                    proof=backend.verify_runtime_target()
                    if type(proof) is not dict or proof.get('loaded_original_ap_verified') is not True:
                        raise RequiredBoundary('Original AP runtime adoption is not yet proved')
                    self.result['runtime_target_proof']=proof
                self._finish(backend)
            normal=backend.normal_return()
            if type(normal) is not dict or any(normal.get(k) is not True for k in
                ('service_exit_confirmed','normal_msc_verified','same_body_and_port')):
                raise ValueError('Service exit and same-body MSC return not fully proved')
            real=self.result['camera_io'] is True and self.result['simulation'] is False
            self.result.update(status='ALL_TARGETS_VERIFIED_REBOOT_PENDING' if real else 'SIMULATED_ALL_TARGETS_VERIFIED',
                all_targets_verified=real,full_file_restore_complete=real,
                normal_return_verified=True,service_exit_confirmed=True,stop_safe=True,
                normal_return=normal,complete=False)
            if self.result['finalizer'].get('known_deferred_readonly') and real:
                self.result.update(status='ALL_TARGETS_READBACK_RO_PENDING',full_file_restore_complete=False,all_targets_verified=False)
            if self.result['finalizer'].get('adoption_refused') and real:
                self.result.update(status='RUNTIME_BOUNDARY_REQUIRED',
                    error='WBI preparation had a known clean refusal; inspect diagnostic logs before the next adoption attempt')
            if verify_runtime and real and self.result['finalizer']['usr_readonly_verified']:
                self.result.update(status='POST_STARTUP_VERIFIED_AWAITING_USER_ACCEPTANCE',
                    post_boot_full_file_verification_complete=True)
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
                error=str(error),complete=False,all_targets_verified=False,full_file_restore_complete=False,
                stop_safe=False,normal_return_verified=False,service_exit_confirmed=False,
                mutation_phase_attempted=self.attempted)
            self._record('failure',error_type=type(error).__name__)
            if isinstance(error,(KeyboardInterrupt,SystemExit)):raise
            raise RestoreJobError(str(error),self.result) from error
