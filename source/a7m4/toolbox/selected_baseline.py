"""Original-baseline admission, using the registered restore C/D authority.

Historical or whole-file F equality never grants admission. A new install is
refused until every registered feature C and owned EOF matches the selected
original backup; live C/D is checked again before the first persistent write.
"""
from types import SimpleNamespace
from . import backup_target_execution as execution
from .backup_target_backend import BackupTargetBackend
from .backup_target_settings import check_settings_target
from . import settings_archive
from .capture_inputs import read_private
from pathlib import Path
from hashlib import sha256
import json

MESSAGE='每次需要修改前请先恢复到原始备份。当前已登记功能区域不处于所选原始基线。'


def require_original(plan):
    if (plan['blockers'] or plan['changed_objects'] or
            any(r['changed'] for r in plan['settings']['records'])):
        raise ValueError(MESSAGE)
    return plan


def prepare(current_capture, original_capture, output):
    view=execution.materialize(execution.reconstruct(current_capture,original_capture),output)
    require_original(view.checked_plan())
    return view


def check_live(view, channel, snapshot):
    plan=require_original(execution.authenticated_plan(view))
    adapter=SimpleNamespace(authority=view,plan=plan)
    observed={}
    for row in plan['objects']:
        raw=channel.file(row['target_path'])
        BackupTargetBackend.check_object(adapter,row,raw,target=True)
        observed[row['target_path']]=dict(size=len(raw),sha256=sha256(raw).hexdigest())
    ref=plan['backup_capture'];receipt=Path(ref['receipt'])
    raw=read_private(receipt,2*1024*1024)
    if sha256(raw).hexdigest()!=ref['receipt_sha256']:raise ValueError('Original backup receipt changed')
    saved=json.loads(raw)
    if saved['body_binding']!=plan['body_binding']:raise ValueError('Original backup body changed')
    original=settings_archive.load_snapshot(receipt.parent/'settings')
    check_settings_target(snapshot,original,view)
    return dict(schema='a7m4-selected-original-baseline-proof/1',
        scope_plan_id=plan['scope_plan_id'],original_capture=plan['backup_capture'],
        registered_C_D_verified=True,whole_F_hash_admission=False,
        E_F_observations=observed)
