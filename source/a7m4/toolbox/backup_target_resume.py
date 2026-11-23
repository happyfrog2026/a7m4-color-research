"""Retained restore-job provenance for a known prefix-restored resource tail.

This never infers ownership from an inactive codec payload. The initial strict
scope, safely closed restore receipts, complete C readback, unchanged known tail
and fresh global references must agree. It is unrelated to installation history.
"""
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path

from . import backup_target_scope as scope
from . import backup_target_execution as execution
from .capture_inputs import read_private
from .looks_resource_restore import references

SCHEMA='a7m4-backup-target-resume-scope/1'
MAX_PLAN=32*1024*1024


def _canonical(value):
    if not isinstance(value,(str,Path)):raise ValueError('Canonical restore proof path required')
    path=Path(value)
    if not path.is_absolute() or '..' in path.parts or str(path)!=str(value) or len(str(path))>4096:
        raise ValueError('Restore proof path contains a traversal or is not canonical')
    return path


def _json_file(path,maximum):
    path=_canonical(path)
    raw=read_private(path,maximum)
    return json.loads(raw),dict(path=str(Path(path).absolute()),sha256=sha256(raw).hexdigest())


def _initial(prior):
    path=Path(prior['path']).parent/'plan.private.json'
    plan,ref=_json_file(path,MAX_PLAN)
    if (type(plan) is not dict or plan.get('schema')!=execution.SCHEMA or plan.get('plan_id')!=prior.get('plan_id')
        or sha256(execution._json({k:v for k,v in plan.items() if k!='plan_id'})).hexdigest()!=plan.get('plan_id')
        or plan.get('scope_plan_id')!=prior.get('scope_plan_id')):
        raise ValueError('Restore checkpoint and retained execution plan differ')
    embedded=plan.get('scope_plan',{})
    if embedded.get('schema')==SCHEMA:
        ref=embedded['initial_execution']
        plan,actual=_json_file(ref['path'],MAX_PLAN)
        if actual!=ref:raise ValueError('Initial restore authority changed')
    if plan.get('scope_plan',{}).get('schema')!=scope.SCHEMA:
        raise ValueError('A strict initial restore scope is required')
    authority=execution.validate_for_job(plan)
    return authority,ref


def _records(prior,selected):
    from .backup_target_flow import previous_receipt
    records={};seen=set();value=prior
    for _ in range(256):
        if value['checkpoint_sha256'] in seen:raise ValueError('Restore checkpoint cycle')
        seen.add(value['checkpoint_sha256'])
        for row in reversed(value.get('finalizer',{}).get('resource_checkpoints',[])):
            if row.get('scope_plan_id')!=value.get('scope_plan_id'):raise ValueError('Resource checkpoint belongs to another producing scope')
            path=_canonical(row.get('readback_path',''))
            if not path.is_absolute() or not path.is_relative_to(Path(value['path']).parent):
                raise ValueError('Resource readback escaped its producing restore job')
            raw=read_private(path,16*1024*1024)
            if (len(raw)!=row.get('readback_size') or sha256(raw).hexdigest()!=row.get('readback_sha256')
                or row.get('C_D_verified') is not True or row.get('backup_archive_sha256')!=selected['backup_capture']['archive_sha256']):
                raise ValueError('Retained resource C readback evidence changed')
            records.setdefault(row['target_path'],dict(row,checkpoint_sha256=value['checkpoint_sha256']))
        previous=value.get('previous_checkpoint')
        if previous is None:return records
        _canonical(previous['path'])
        next_value=previous_receipt(previous['path'],selected)
        if next_value['checkpoint_sha256']!=previous['sha256']:raise ValueError('Previous restore receipt changed')
        value=next_value
    raise ValueError('Restore checkpoint chain exceeds finite bound')


def rebuild_projection(current_capture,backup_capture,previous_job):
    from .backup_target_flow import previous_receipt
    base,targets=scope.rebuild_projection(current_capture,backup_capture)
    prior=previous_receipt(previous_job,base)
    initial,initial_ref=_initial(prior)
    old=initial.checked_plan()
    if any(old['backup_capture'].get(k)!=base['backup_capture'].get(k) for k in ('body_binding','receipt_sha256','archive_sha256')):
        raise ValueError('Initial restore authority binds a different selected backup')
    progress=_records(prior,base)
    initial_rows={r['target_path']:r for r in old['objects']}
    initial_resources={r['path']:r for r in old['scope_plan']['resources']['files']}
    current=execution.authenticated_current_capture(base['current_capture'])
    by_remote={r['target_path']:(name,r) for name,r in current['objects'].items()}
    repaired=[]
    for component in base['resources']['files']:
        path=component['path']
        if not component.get('blockers'):continue
        codes={r.get('code') for r in component['blockers']}
        if codes!={'RESOURCE_TAIL_LAYOUT_OR_REFERENCE_DEPENDENCY'}:continue
        before=initial_resources.get(path);record=progress.get(path)
        if before is None or record is None or record.get('phase')!='prefix':continue
        tail=before.get('tail',{})
        if tail.get('action')!='TRUNCATE_KNOWN_APPEND' or tail.get('layout',{}).get('verified') is not True:continue
        old_row=initial_rows[path]
        original=initial.payload(old_row,target=True);first=initial.payload(old_row,target=False)
        name,entry=by_remote[path]
        fresh=read_private(Path(current['snapshot_dir'])/name,16*1024*1024)
        if len(fresh)!=entry['size'] or sha256(fresh).hexdigest()!=entry['sha256']:raise ValueError('Fresh capture resource changed')
        if (len(fresh)!=len(first) or not len(original)<len(fresh)
            or fresh[len(original):]!=first[len(original):]
            or record.get('target_eof')!=len(original)
            or record.get('remaining_tail_sha256')!=sha256(first[len(original):]).hexdigest()):
            raise ValueError('Fresh resource tail is not the authenticated initial restore tail')
        retained=read_private(record['readback_path'],16*1024*1024)
        for lo,hi in before['owned_ranges']:
            hi=min(hi,len(original))
            if lo<hi and (fresh[lo:hi]!=original[lo:hi] or retained[lo:hi]!=original[lo:hi]):
                raise ValueError('Restored resource C no longer matches its safe checkpoint')
        # A foreign active reference, even into unchanged known codec bytes,
        # is a real D conflict and never becomes a checkpoint exception.
        references(path,fresh,len(original))
        target=bytearray(fresh[:len(original)])
        for lo,hi in before['owned_ranges']:
            hi=min(hi,len(original))
            if lo<hi:target[lo:hi]=original[lo:hi]
        target=bytes(target)
        scope.check_resource_D(before,fresh,target)
        replacement=deepcopy(before)
        replacement.update(source=scope.identity(fresh),target=scope.identity(target),source_eof=len(fresh),target_eof=len(target),
            windows=scope._windows(fresh,target,before['owned_ranges']),append_hex='',blockers=[],prefix_target=scope.identity(fresh))
        replacement['tail']=dict(tail,checkpoint_provenance=dict(checkpoint_sha256=record['checkpoint_sha256'],
            readback_sha256=record['readback_sha256'],initial_scope_plan_id=old['scope_plan_id']),
            active_registration_replaced_by_retained_restore_proof=True)
        component.clear();component.update(replacement);targets[path]=target;repaired.append(path)
    base=deepcopy(base)
    base['blockers']=[b for b in base['blockers'] if b.get('path') not in repaired]
    base['schema']=SCHEMA
    base['initial_execution']=initial_ref
    base['previous_checkpoint']=dict(path=prior['path'],sha256=prior['checkpoint_sha256'])
    base['resumed_resource_paths']=repaired
    base['changed_objects']=sorted(p for p,raw in targets.items() if scope.identity(raw)!=next(r['current'] for r in base['observations']['files'] if r['path']==p))
    base['operation']='RESTORE_SUPPORTED_BACKUP_SCOPE' if base['changed_objects'] or any(r['changed'] for r in base['settings']['records']) or base['blockers'] else 'NO_OP'
    base['ready_for_execution']=not base['blockers']
    for row in base['observations']['files']:row['projected']=scope.identity(targets[row['path']])
    base.pop('plan_id',None)
    base['plan_id']=sha256(scope._json(base)).hexdigest()
    return base,targets


def _victim(component,target):
    donor=component.get('layout',{}).get('playback_donor_id')
    if donor is None:return None
    from ..research.native_icons import _inspect_bank
    return dict(id=donor,start=_inspect_bank(target)['records'][donor]['start'])


def validated_projection(plan):
    if type(plan) is not dict or plan.get('schema')!=SCHEMA:raise ValueError('Finite restore-resume scope required')
    expected,targets=rebuild_projection(plan['current_capture']['receipt'],plan['backup_capture']['receipt'],plan['previous_checkpoint']['path'])
    if expected!=plan:raise ValueError('Restore-resume authority differs from rebuilt checkpoint and fresh capture')
    return plan,targets


def reconstruct(current,backup,previous):
    plan,targets=rebuild_projection(current,backup,previous)
    return execution.RebuiltProjection(plan,targets,_token=execution._VIEW_TOKEN)
