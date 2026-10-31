"""Persisted selected-backup restoration across App starts and fresh captures."""
from hashlib import sha256
import json
import re
from pathlib import Path
from .capture_inputs import read_private
from .native_actions import _write, _json
from . import backup_target_scope
from .backup_target_execution import validate_for_job, reconstruct

PENDING=('RUNTIME_BOUNDARY_REQUIRED','ALL_TARGETS_VERIFIED_REBOOT_PENDING','ALL_TARGETS_READBACK_RO_PENDING',
    'POST_STARTUP_VERIFIED_AWAITING_USER_ACCEPTANCE')


def previous_receipt(path, scope):
    path=Path(path)
    if not path.is_absolute() or '..' in path.parts or str(path)!=str(path.absolute()) or path.name!='job.private.json':
        raise ValueError('Canonical producing job.private.json path required')
    raw=read_private(path,4*1024*1024);value=json.loads(raw)
    if (type(value) is not dict or type(value.get('backup_capture')) is not dict
        or value.get('schema')!='a7m4-backup-target-job/1' or value.get('resource_profile')!='m4-602-six-language/1' or value.get('status') not in PENDING
        or value.get('receipt')!=str(path) or value.get('model')!='ILCE-7M4' or value.get('firmware')!='6.02'
        or not isinstance(value.get('boot_id'),str) or re.fullmatch(r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}',value['boot_id']) is None
        or any(not isinstance(value.get(k),str) or re.fullmatch('[0-9a-f]{64}',value[k]) is None for k in ('plan_id','scope_plan_id'))
        or value.get('complete') is not False or value.get('install_history_required') is not False
        or value.get('E_F_observation_only') is not True or value.get('restores_entire_original_files') is not False
        or value.get('camera_io') is not True or value.get('simulation') is not False
        or any(value.get(k) is not True for k in ('normal_return_verified','service_exit_confirmed','stop_safe'))
        or value.get('body_binding')!=scope['body_binding']
        or any(value.get('backup_capture',{}).get(k)!=scope['backup_capture'].get(k) for k in ('receipt_sha256','archive_sha256','body_binding'))):
        raise ValueError('Previous backup-target checkpoint is not safely closed or binds a different selected backup')
    finalizer=value.get('finalizer',{})
    if (type(finalizer) is not dict or any(finalizer.get(k) is not True for k in ('exact_owned_cleanup_verified','native_context_healthy','safe_stop_allowed'))
        or not (finalizer.get('usr_readonly_verified') is True or finalizer.get('known_deferred_readonly') is True
            and finalizer.get('native_inputs_closed') is True and type(finalizer.get('wbi_adoption')) is dict and finalizer['wbi_adoption'].get('success') is True)):
        raise ValueError('Previous restore checkpoint has no verified safe native finalizer')
    return dict(value,path=str(path),checkpoint_sha256=sha256(raw).hexdigest())


def execute(current,backup,output,*,compiler=None,owner_uid=None,previous_job=None,
            verify_after_startup=False,startup_confirmed=False,backend_factory=None):
    from .backup_target_job import BackupTargetCoordinator
    from .backup_target_backend import BackupTargetBackend
    if previous_job:
        from .backup_target_resume import reconstruct as resume_projection
        projection=resume_projection(current,backup,previous_job)
    else:projection=reconstruct(current,backup)
    scope=projection.checked_plan()
    if scope['blockers']:raise ValueError('Selected backup layout is outside this release: '+str(scope['blockers'][:3]))
    prior=previous_receipt(previous_job,scope) if previous_job else None
    if (prior is not None and startup_confirmed is not True) or verify_after_startup and prior is None:
        raise ValueError('A safely closed checkpoint and fresh startup confirmation are required')
    coordinator=BackupTargetCoordinator(projection,output,verify_after_startup=verify_after_startup)
    if prior:
        coordinator.result['previous_checkpoint']=dict(path=prior['path'],sha256=prior['checkpoint_sha256'],status=prior['status'])
        coordinator.result['previous_boot_id']=prior.get('boot_id')
        coordinator.result['previous_consumer_safety']=prior.get('consumer_safety')
    coordinator.result['startup_confirmation_user_provided']=bool(startup_confirmed)
    backend=(backend_factory(coordinator) if backend_factory else BackupTargetBackend(coordinator.output,
        compiler=compiler,owner_uid=owner_uid,verify_only=verify_after_startup,authority=coordinator.authority))
    return coordinator.run(backend,ack_original=True,ack_backup=True,ack_brick=True,ack_risk=True,
        verify_runtime=verify_after_startup)


def record_acceptance(job,output,*,names=False,sound=False,shoot=False,playback=False):
    if not all(type(v) is bool and v for v in (names,sound,shoot,playback)):
        raise ValueError('Fresh names/icons, sound, shooting and playback observations are required')
    raw=read_private(job,4*1024*1024);value=json.loads(raw)
    if (value.get('schema')!='a7m4-backup-target-job/1'
        or value.get('status')!='POST_STARTUP_VERIFIED_AWAITING_USER_ACCEPTANCE'
        or value.get('camera_io') is not True or value.get('simulation') is not False
        or any(value.get(k) is not True for k in ('scope_target_readback_complete','normal_return_verified',
            'service_exit_confirmed','post_boot_scope_verification_complete','settings_C_verified'))
        or value.get('runtime_target_proof',{}).get('C_loaded_verified') is not True):
        raise ValueError('Post-startup scoped readback/runtime checkpoint is required before acceptance')
    authority=validate_for_job(json.loads(read_private(Path(job).parent/'plan.private.json',32*1024*1024)))
    execution=authority.checked_plan()
    if value.get('plan_id')!=execution['plan_id'] or value.get('backup_capture')!=execution['backup_capture']:
        raise ValueError('Acceptance checkpoint/selected target identity differs')
    expected={r['target_path']:r for r in execution['objects']};seen=set()
    from .backup_target_backend import BackupTargetBackend
    checker=BackupTargetBackend.__new__(BackupTargetBackend);checker.plan=execution;checker.authority=authority
    for row in value['verified_objects']:
        relative=row.get('path','');remote=row.get('target_path')
        if (not relative.startswith('post/') or any(p in ('','.','..') for p in relative.split('/'))
            or remote not in expected or remote in seen):raise ValueError('Invalid scoped readback inventory')
        seen.add(remote);actual=read_private(Path(job).parent/relative,160*1024*1024)
        if (len(actual)!=row.get('size') or sha256(actual).hexdigest()!=row.get('sha256')):
            raise ValueError('Retained readback evidence changed')
        checker.check_object(expected[remote],actual,target=True)
    if seen!=set(expected):raise ValueError('Incomplete retained scoped readback inventory')
    from .backup_target_settings import check_settings_target
    from . import settings_archive
    final=settings_archive.load_snapshot(Path(job).parent/'settings-final')
    original=settings_archive.load_snapshot(Path(execution['backup_capture']['receipt']).parent/'settings')
    check_settings_target(final,original,authority,allow_saved_ram=True)
    result=dict(schema='a7m4-backup-target-acceptance/1',status='USER_ACCEPTED_BACKUP_SCOPE_RESTORATION',
        checkpoint_sha256=sha256(raw).hexdigest(),checkpoint_path=str(Path(job).absolute()),
        body_binding=value['body_binding'],backup_capture=value['backup_capture'],complete=True,
        scope='registered feature-owned targets from selected original backup; current E/F retained',
        E_F_restored=False,restores_entire_original_files=False,
        user_observations=dict(names_icons=names,sound=sound,shoot=shoot,playback=playback),camera_io=False,network_io=False)
    _write(Path(output),_json(result));return result
