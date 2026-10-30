"""Persistence and post-startup acceptance for original-backup recovery.

Each USB round gets a new full capture and job; all rounds retain one original
endpoint. There is no fixed round count or selective feature uninstall.
"""
import json
from datetime import datetime,timezone
import os
from pathlib import Path
from hashlib import sha256
from .capture_inputs import read_private
from .native_actions import _write,_json
from .original_restore import make_plan

PENDING=('RUNTIME_BOUNDARY_REQUIRED','ALL_TARGETS_VERIFIED_REBOOT_PENDING','ALL_TARGETS_READBACK_RO_PENDING',
         'POST_STARTUP_VERIFIED_AWAITING_USER_ACCEPTANCE')


def previous_receipt(path,plan):
    raw=read_private(path,4*1024*1024);value=json.loads(raw)
    if ((value.get('schema')!='a7m4-original-backup-restore-job/1' or value.get('resource_profile')!='m4-602-six-language/1') or value.get('status') not in PENDING
            or value.get('camera_io') is not True or value.get('simulation') is not False
            or value.get('normal_return_verified') is not True or value.get('service_exit_confirmed') is not True
            or value.get('body_binding')!=plan['body_binding']
            or value.get('original_capture',{}).get('archive_sha256')!=plan['original_capture']['archive_sha256']
            or value.get('original_settings_evidence')!=plan['settings']['original_evidence']
            or value.get('original_direct_cp_evidence')!=plan['settings']['original_direct_cp']):
        raise ValueError('Previous restore checkpoint is not safely closed or has a different original endpoint')
    return dict(value,path=str(Path(path).absolute()),checkpoint_sha256=sha256(raw).hexdigest())


def execute(current,original,output,*,compiler=None,owner_uid=None,previous_job=None,
            verify_after_startup=False,startup_confirmed=False,backend_factory=None):
    if backend_factory is None and not verify_after_startup:
        raise ValueError('Legacy restore writes retired; use backup_target_flow.execute with ST consumer protection')
    from .original_restore_job import OriginalRestoreCoordinator
    from .original_restore_backend import OriginalRestoreBackend
    plan=make_plan(current,original,post_startup_ap55=verify_after_startup)
    prior=previous_receipt(previous_job,plan) if previous_job else None
    if verify_after_startup:
        if not startup_confirmed or prior is None:raise ValueError('Previous checkpoint and fresh startup confirmation required')
        if plan['operation']!='NO_OP' or plan['settings']['records']:
            raise ValueError('Current complete capture is not yet the original target; continue source-bound recovery first')
    coordinator=OriginalRestoreCoordinator(current,original,output,post_startup_ap55=verify_after_startup)
    if prior:
        coordinator.result['previous_checkpoint']=dict(path=prior['path'],sha256=prior['checkpoint_sha256'],status=prior['status'])
    coordinator.result['startup_confirmation_user_provided']=bool(verify_after_startup and startup_confirmed)
    backend=(backend_factory(coordinator) if backend_factory else OriginalRestoreBackend(coordinator.output,compiler=compiler,owner_uid=owner_uid,verify_only=verify_after_startup))
    return coordinator.run(backend,ack_original=True,ack_backup=True,ack_brick=True,ack_risk=True,
                           verify_runtime=verify_after_startup)


def record_acceptance(job,output,*,names=False,sound=False,shoot=False,playback=False):
    if not all(type(v) is bool and v for v in (names,sound,shoot,playback)):
        raise ValueError('Fresh user observations for names/icons, sound, shooting and playback are required')
    raw=read_private(job,4*1024*1024);value=json.loads(raw)
    if ((value.get('schema')!='a7m4-original-backup-restore-job/1' or value.get('resource_profile')!='m4-602-six-language/1')
            or value.get('status')!='POST_STARTUP_VERIFIED_AWAITING_USER_ACCEPTANCE'
            or value.get('camera_io') is not True or value.get('simulation') is not False
            or any(value.get(k) is not True for k in ('full_file_restore_complete','normal_return_verified',
                'service_exit_confirmed','post_boot_full_file_verification_complete'))
            or value.get('runtime_target_proof',{}).get('loaded_original_ap_verified') is not True
            or len(value.get('verified_objects',[]))!=11):
        raise ValueError('Post-startup complete readback/runtime checkpoint is required before acceptance')
    from . import original_restore as diff,settings_archive
    plan=diff.validate_plan(json.loads(read_private(Path(job).parent/'plan.private.json',16*1024*1024)))
    by_path={r['target_path']:r['target'] for r in plan['objects']}
    seen=set()
    for row in value['verified_objects']:
        relative=row.get('path','');parts=Path(relative).parts
        if (not relative.startswith('post/') or any(p in ('','..','.') for p in relative.split('/'))
                or row.get('target_path') not in by_path or row['target_path'] in seen):
            raise ValueError('Invalid final complete object inventory')
        seen.add(row['target_path'])
        expected=by_path[row['target_path']]
        actual=read_private(Path(job).parent/relative,160*1024*1024)
        if diff._identity(actual)!=expected or any(row.get(k)!=expected[k] for k in ('size','sha256')):
            raise ValueError('Retained complete original file readback changed')
    final=settings_archive.load_snapshot(Path(job).parent/'settings-final')
    original=settings_archive.load_snapshot(Path(value['original_capture']['receipt']).parent/'settings')
    settings_check=diff.settings_diff(final,original,post_startup_ap55=plan.get('settings_target_after_startup',False))
    if settings_check['records'] or settings_check['post_startup_settings_policy']!=value.get('post_startup_settings_policy'):
        raise ValueError('Retained original settings targets or post-startup policy differ')
    result=dict(schema='a7m4-original-restore-acceptance/1',status='USER_ACCEPTED_ORIGINAL_RESTORATION',
        checkpoint_sha256=sha256(raw).hexdigest(),checkpoint_path=str(Path(job).absolute()),
        body_binding=value['body_binding'],original_capture=value['original_capture'],
        post_startup_settings_policy=settings_check['post_startup_settings_policy'],
        acceptance_scope='original persistent business targets and explicitly allowed AP55 live endpoint; original transient RAM is not claimed reproduced',
        complete=True,accepted_at=datetime.now(timezone.utc).isoformat(),user_observations=dict(names_icons=names,sound=sound,shoot=shoot,playback=playback),
        machine_runtime_scope='AP expected windows, complete disk objects and business settings; physical function observations are user supplied',
        camera_io=False,network_io=False)
    _write(Path(output),_json(result));return result
