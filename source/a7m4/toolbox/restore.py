"""Explicit receipt-bound recovery of this tool's completed changes.

Looks restore has two user-initiated stages: programs/settings, normal power
cycle, then resources. No camera operation or retry is initiated by import.
"""
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import tempfile
import os
import uuid

from .capture_inputs import read_private
from .selection_ref import resolve_selection,read_selection
from .device_job import complete_capture,_execute
from . import settings_archive, gate_scope
from .settings_plan import plan_fixed_settings,plan_ap55,plan_manifest,inverse_plan


FLAGS=('camera_io','complete','verified','full_readback_verified','stop_safe','normal_return_verified',
       'service_exit_confirmed','native_sequence_complete')


def need(ok,text):
    if not ok:raise ValueError(text)


def completed_job(path,*,features=None):
    path=Path(path).absolute()
    if path.is_dir():path=path/'job.private.json'
    raw=read_private(path,2*1024*1024);value=json.loads(raw)
    need(path.name=='job.private.json' and value.get('receipt')==str(path)
         and value.get('schema')=='a7m4-toolbox-device-job/1'
         and value.get('status') in ('VERIFIED_APPLIED','VERIFIED_NO_CHANGE')
         and value.get('simulation') is False and all(value.get(k) is True for k in FLAGS),
         'Recovery requires a complete real applied job, never an offline plan or partial result')
    if features is not None:need(value.get('feature') in features,'This job type does not match the selected recovery')
    value['selection']=resolve_selection(value,path.parent);value.pop('selection_ref',None)
    rows=value.get('verified_objects',[])
    need(type(rows) is list and 0<len(rows)<=100,'Completed full readback objects missing')
    names=set()
    for row in rows:
        name=row.get('path')
        need(type(name) is str and name.startswith('post/') and '\\' not in name and ':' not in name
             and all(p not in ('','.','..') for p in name.split('/')) and name not in names,'Invalid recovery readback path')
        names.add(name);blob=read_private(path.parent/name,160*1024*1024)
        need(dict(size=len(blob),sha256=sha256(blob).hexdigest())=={k:row.get(k) for k in ('size','sha256')},'Completed readback file changed')
    normal=value.get('normal_return',{})
    need(normal.get('normal_msc_verified') is True and normal.get('same_body_and_port') is True,'Completed normal-return evidence missing')
    return path,value,sha256(raw).hexdigest()


def _unchanged_component(name,row,snapshot):
    ident={k:row[k] for k in ('size','sha256')}
    return dict(source=dict(path=str(snapshot/name),kind=row['kind'],**ident),target_path=row['target_path'],
                target=dict(ident),windows=[],append=dict(offset=row['size'],size=0,after_hex='',sha256=sha256(b'').hexdigest()))


def _forward_settings(job_root,kind,completion):
    manifest=json.loads(read_private(job_root/(kind+'-settings-plan.json'),65536))
    source=settings_archive.load_snapshot(job_root/(kind+'-settings-before'))
    factory={'ap55':plan_ap55,'fl23':plan_fixed_settings}[kind]
    forward=factory(source,identity=manifest['identity'],boot_id=manifest['boot_id'],nonce=manifest['nonce'])
    need(plan_manifest(forward)==manifest and completion.get('plan_id')==forward.plan_id,'Original selected settings plan changed')
    return forward


def looks_restore_plan(capture_path,previous_job):
    """Pure local proof and bounded stage plan; no generic manifest executor."""
    current,current_settings=complete_capture(capture_path)
    path,job,digest=completed_job(previous_job,features={'looks-install','restore-programs'})
    need(job['body_binding']==current['body_binding'],'Recovery job belongs to another body')
    stage=2 if job['feature']=='restore-programs' else 1
    stage1_job=job if stage==2 else None
    if stage==2:
        original_path,original,original_digest=completed_job(job['restore_of_job'],features={'looks-install'})
        need(original_digest==job['restore_of_job_sha256'],'Original restore job identity changed')
        need(original['body_binding']==current['body_binding'],'Original recovery body differs')
    else:original_path,original,original_digest=path,job,digest
    source_selection=read_selection(original_path.parent)
    need(set(source_selection.get('components',{})) == set(current['objects']),
         'Old 73-object in-flight restoration is not supported; select the original complete backup and replan from a fresh 11-object capture')
    need(source_selection==original.get('selection'),'Original fixed selection file/receipt differs')
    original_capture,_=complete_capture(source_selection['capture_receipt'])
    need(original_capture['body_binding']==current['body_binding'],'Original backup belongs to another body')
    # Rebuild the fixed feature plan from full originals and the exact retained
    # native project. Re-sealing arbitrary AP/CP windows cannot grant recovery.
    from .device_job import looks_selection
    with tempfile.TemporaryDirectory(prefix='a7m4-restore-fixed-proof-') as temporary:
        source_project=original_path.parent/'native-project'/'manifest.json'
        rebuilt=looks_selection(source_selection['capture_receipt'],source_selection['selection'],
             source_project if source_project.exists() else None,Path(temporary).resolve()/'plan',
             program_jobs=source_selection.get('source_admission',{}).get('previous_jobs',()),
             sound_job=source_selection.get('source_admission',{}).get('sound_job'))
    for key in ('profile','selection','components','program_stages','body_binding','capture_receipt'):
        need(rebuilt[key]==source_selection[key],'Original fixed plan no longer matches exact source/choice: '+key)
    need(original.get('program_stages')==source_selection['program_stages'],'Completed program stages differ')
    snapshot=Path(current['snapshot_dir'])
    components={name:_unchanged_component(name,row,snapshot) for name,row in current['objects'].items()}
    settings_factories=[]
    if stage==1:
        for name,c in source_selection['components'].items():
            need({k:current['objects'][name][k] for k in ('size','sha256')}==c['target'],'Current full endpoint differs from completed install; no implicit inverse')
        programs=list(reversed(source_selection['program_stages']))
        for name,role in (('appFw.so','ap'),('CPAPP-B.BIN','cp')):
            components[name]['target']={k:original_capture['objects'][name][k] for k in ('size','sha256')}
        completions={r['kind']:r for r in original.get('settings_results',[])}
        for kind in ('fl23','ap55'):
            if kind not in completions:continue
            forward=_forward_settings(original_path.parent,kind,completions[kind])
            completion=completions[kind]
            inverse_plan(forward,current_settings,boot_id=str(uuid.uuid4()),nonce=os.urandom(16).hex(),completion=completion)
            def factory(fresh,*,identity,boot_id,nonce,forward=forward,completion=completion):
                need(identity==forward.identity,'Recovery settings identity differs')
                return inverse_plan(forward,fresh,boot_id=boot_id,nonce=nonce,completion=completion)
            settings_factories.append((kind,factory))
        different_boot=None
    else:
        need(stage1_job.get('restore_stage')==1 and stage1_job.get('resources_restored') is False
             and isinstance(stage1_job.get('boot_id'),str),'Program restore stage/boot evidence missing')
        # The intervening backup must observe the exact stage1 complete outputs.
        expected=stage1_job['selection']['components']
        for name,c in expected.items():
            need({k:current['objects'][name][k] for k in ('size','sha256')}==c['target'],'Current endpoint differs from verified program-restore stage')
        restored_settings=settings_archive.load_snapshot(path.parent/'settings-after')
        # Normal power cycling changes native counters and boot bookkeeping.
        # Stage2 writes no settings: only the previously restored owned spans
        # must still match; every other current byte is preserved from backup.
        completions={r['kind']:r for r in original.get('settings_results',[])}
        for kind,completion in completions.items():
            forward=_forward_settings(original_path.parent,kind,completion)
            for record in forward.records:
                pair=record.chip,record.key
                for plane in ('ram','saved'):
                    old=getattr(restored_settings,plane).records[pair]
                    now=getattr(current_settings,plane).records[pair]
                    need(now.attrs==old.attrs and len(now.data)==len(old.data)
                         and all(now.data[a:b]==old.data[a:b] for a,b in record.spans),'Restored setting was changed after stage1')
        programs=[];different_boot=stage1_job['boot_id']
        for name,c in source_selection['components'].items():
            if c['source']['kind']!='resource' or c['inverse'] is None:continue
            inverse=c['inverse'];row=components[name]
            raw=read_private(snapshot/name,16*1024*1024);target=bytearray(raw)
            for window in inverse['windows']:
                at=window['offset'];before=bytes.fromhex(window['before_hex']);after=bytes.fromhex(window['after_hex'])
                need(target[at:at+len(before)]==before,'Resource recovery exact window differs')
                target[at:at+len(after)]=after
            need(dict(size=len(target),sha256=sha256(target).hexdigest())==inverse['target'],'Resource recovery complement differs')
            row.update(target=inverse['target'],windows=inverse['windows'])
    selection=dict(schema='a7m4-toolbox-restore-stage/1',capture_receipt=str(Path(capture_path).absolute()),
        body_binding=current['body_binding'],components=components,program_stages=programs,
        selection=dict(include_fl2=False,include_fl3=False,slots=[]),restore_stage=stage,
        original_capture_receipt=source_selection['capture_receipt'])
    fields=dict(restore_of_job=str(original_path),restore_of_job_sha256=original_digest,restore_stage=stage,
        resources_restored=stage==2,restore_complete=stage==2,normal_power_cycle_required_before_resources=stage==1,
        retained_resource_append_tails=True,calibration_replay=False,
        functional_restore_complete=stage==2,full_file_restore_complete=False,
        post_boot_full_file_verification_complete=False,
        restoration_scope='functional-only',tail_cleanup_state='NOT_STARTED',
        product_tail_cleanup_device_validation='NOT_PERFORMED')
    return dict(feature='restore-programs' if stage==1 else 'restore-resources',selection=selection,
        settings_factories=settings_factories,program_inverse=True,different_boot_from=different_boot,receipt_fields=fields)


def execute_restore(capture_path,previous_job,output,**kwargs):
    path=Path(previous_job).absolute()
    if path.is_dir():path/='job.private.json'
    feature=json.loads(read_private(path,2*1024*1024)).get('feature')
    if feature in ('looks-install','restore-programs'):
        recovery=looks_restore_plan(capture_path,path)
        return _execute(capture_path,recovery['selection']['selection'],None,output,_recovery=recovery,**kwargs)
    if feature=='electronic-sound-gate':
        recovery=gate_restore_plan(capture_path,path)
        return _execute(capture_path,recovery['selection']['selection'],None,output,_recovery=recovery,**kwargs)
    if feature in ('product-pin-first-install','product-pin-replacement'):
        from .pin_family_job import execute_product_inverse
        return execute_product_inverse(capture_path,path,output,**kwargs)
    raise ValueError('No restricted recovery adapter for this completed job type')


def gate_restore_plan(capture_path,previous_job):
    from .device_job import gate_selection
    current,current_settings=complete_capture(capture_path)
    path,job,digest=completed_job(previous_job,features={'electronic-sound-gate'})
    need(job['body_binding']==current['body_binding'],'Gate restore body differs')
    old=read_selection(path.parent)
    need(old==job.get('selection') and old.get('schema')=='a7m4-toolbox-gate-selection/1','Gate selection proof differs')
    need(old.get('source_basis')!=gate_scope.POLICY,
         '本作业使用新的C范围，不支持逐项撤销；有 Gate C capsule 时请使用 gate-c-restore 恢复明确的 Gate 累计C。其他功能尚不覆盖。')
    rebuilt=gate_scope.legacy_selection(old['capture_receipt'],old['gate']['gate']['desired_state'],program_jobs=old['gate'].get('program_jobs',()),sound_job=old['gate'].get('sound_job'))
    need(rebuilt==old and job['program_stages']==old['program_stages'],'Fixed gate source/choice no longer matches')
    original,_=complete_capture(old['capture_receipt']);snapshot=Path(current['snapshot_dir'])
    components={name:_unchanged_component(name,row,snapshot) for name,row in current['objects'].items()}
    for name,c in old['components'].items():
        need({k:current['objects'][name][k] for k in ('size','sha256')}==c['target'],'Current full gate endpoint differs')
        components[name]['target']={k:original['objects'][name][k] for k in ('size','sha256')}
    factories=[]
    for completion in job.get('settings_results',[]):
        need(completion['kind']=='ap55','Unexpected gate setting mutation')
        forward=_forward_settings(path.parent,'ap55',completion)
        inverse_plan(forward,current_settings,boot_id=str(uuid.uuid4()),nonce=os.urandom(16).hex(),completion=completion)
        def factory(fresh,*,identity,boot_id,nonce,forward=forward,completion=completion):
            need(identity==forward.identity,'Gate recovery body differs')
            return inverse_plan(forward,fresh,boot_id=boot_id,nonce=nonce,completion=completion)
        factories.append(('ap55',factory))
    selection=dict(schema='a7m4-toolbox-gate-restore/1',capture_receipt=str(Path(capture_path).absolute()),
        body_binding=current['body_binding'],components=components,program_stages=list(reversed(old['program_stages'])),
        selection=dict(include_fl2=False,include_fl3=False,slots=[]))
    return dict(feature='restore-sound-gate',selection=selection,program_inverse=True,settings_factories=factories,
        receipt_fields=dict(restore_complete=True,restore_of_job=str(path),restore_of_job_sha256=digest,calibration_replay=False))
