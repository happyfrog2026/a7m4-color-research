"""Rebuilt execution view of the finite backup-target scope, never a 73-file diff.

The scope authority decides every target byte. This view materializes its
projected endpoints for the existing bounded native adapters; it grants no new
locations and never substitutes the selected backup's entire files for a target.
"""
from .. import resource_profile as device_scope
from hashlib import sha256
import json
import os
from pathlib import Path

from .capture_inputs import verified_capture, read_private
from . import original_restore as legacy, settings_archive

SCHEMA = 'a7m4-backup-target-execution/1'


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def _root(path):
    path = Path(path).absolute()
    if any(p.is_symlink() for p in (path, *path.parents)) or not path.is_dir():
        raise ValueError('Real private execution target directory required')
    return path


def authenticated_current_capture(reference):
    raw=read_private(reference['receipt'],2*1024*1024)
    if sha256(raw).hexdigest()!=reference['receipt_sha256']:
        raise ValueError('Authenticated current receipt changed')
    current=json.loads(raw)
    if current.get('normal_return_verified') is not True or current.get('body_binding')!=reference['body_binding']:
        raise ValueError('Current device admission differs from rebuilt authority')
    return dict(current,objects={name:row for name,row in current["objects"].items() if row["target_path"] in device_scope.READ_PATHS})


def _derive(scope, root, *, publish=False, _projection=None):
    from . import backup_target_scope as authority
    if _projection is None:
        if scope.get('schema')=='a7m4-backup-target-resume-scope/1':
            from .backup_target_resume import validated_projection
            scope,targets=validated_projection(scope)
        else:
            scope, targets = authority.validated_projection(scope)
    else:
        scope, targets = _projection
    # Only an internal rebuilt projection can skip another full reconstruction.
    current_ref, backup_ref = scope['current_capture'], scope['backup_capture']
    current=authenticated_current_capture(current_ref)
    root = _root(root)
    objects, changed, tails, blockers = [], [], [], list(scope.get('blockers', []))
    known = {row['target_path'] for row in current['objects'].values()}
    if not isinstance(targets, dict) or set(targets) - known:
        raise ValueError('Scope projection names an unregistered destination')
    for index, (name, before) in enumerate(current['objects'].items()):
        source_path = Path(current['snapshot_dir']) / name
        source = read_private(source_path, 160 * 1024 * 1024)
        if legacy._identity(source) != {k: before[k] for k in ('size', 'sha256')}:
            raise ValueError('Current complete source changed during projection')
        target = targets.get(before['target_path'], source)
        if type(target) is not bytes:
            raise ValueError('Scope target must be bytes')
        target_path = root / ('%03d.bin' % index)
        if publish:
            fd = os.open(target_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(target); stream.flush(); os.fsync(stream.fileno())
        elif read_private(target_path, 160 * 1024 * 1024) != target:
            raise ValueError('Materialized projection changed')
        row = dict(path=name, target_path=before['target_path'], kind=before['kind'],
            source_path=str(source_path), original_path=str(target_path),
            source=legacy._identity(source), target=legacy._identity(target), action='NO_CHANGE', windows=[])
        if source != target:
            changed.append(name)
            if before['kind'] == 'resource':
                component=next(c for c in scope['resources']['files'] if c['path']==before['target_path'])
                row['windows']=component['windows']
                row['preferred_strategy']='protected-delta'
            elif before['kind'] in ('ap','cp'):
                row['windows']=scope['program']['components'][before['kind']]['windows']
            else:
                row['windows']=scope['sound']['windows']
            if len(source) == len(target):
                row['action'] = 'RESTORE_EQUAL_LENGTH_DIFF'
            elif before['kind'] == 'resource' and len(source) > len(target):
                row.update(action='RESTORE_PREFIX_THEN_CONDITIONAL_TAIL',
                    prefix_already_original=source.startswith(target), intermediate=legacy._identity(target + source[len(target):]),
                    tail=dict(offset=len(target), **legacy._identity(source[len(target):])),
                    tail_ownership='SCOPE_AUTHORITY_AND_FRESH_NATIVE_REFERENCE_PROOF_REQUIRED')
                tails.append(name)
            elif before['kind'] == 'audio':
                row.update(action='RESTORE_SOUND_DIFF_AND_EOF', audio_descriptor_coordination_required=True)
            else:
                blockers.append(dict(path=name, reason='Projected size transition has no reviewed adapter'))
                row['action'] = 'UNSUPPORTED_SIZE_CHANGE'
        objects.append(row)
    # The scope's settings authority compares only registered C and required D.
    # Legacy settings_diff would reject unrelated historical F inventories.
    settings = scope['settings']
    value = dict(schema=SCHEMA, resource_profile=device_scope.ID, scope_plan=scope, scope_plan_id=scope['plan_id'],
        materialized_root=str(root), body_binding=current['body_binding'], firmware='6.02',
        source_capture=current_ref, original_capture=backup_ref, backup_capture=backup_ref,
        objects=objects, object_count=len(objects), changed_objects=changed, resource_tail_objects=tails,
        settings=settings, blockers=blockers, operation=scope['operation'],
        target_semantics='selected backup values within registered feature-owned locations; current complement retained',
        restores_entire_original_files=False, camera_io=False, network_io=False,
        device_ready=False, execution_available=False)
    value['plan_id'] = sha256(_json(value)).hexdigest()
    return value


def make_plan(scope_plan, output):
    root = Path(output).absolute()
    if root.exists() or any(p.is_symlink() for p in (root, *root.parents)):
        raise ValueError('New private projected-target directory required')
    root.mkdir(mode=0o700)
    if type(scope_plan) is RebuiltProjection:
        scope, targets = scope_plan._projection()
        return _derive(scope,root,publish=True,_projection=(scope,targets))
    return _derive(scope_plan, root, publish=True)


def validate_plan(plan):
    if type(plan) is not dict or plan.get('schema') != SCHEMA:
        raise ValueError('Backup-target execution authority required')
    rebuilt = _derive(plan['scope_plan'], plan['materialized_root'])
    if rebuilt != plan:
        raise ValueError('Backup-target execution view differs from rebuilt scope')
    return plan


_VIEW_TOKEN = object()


class ValidatedExecution:
    """One job's immutable authority; never cached by path or across boots.

    Construction fully rebuilds both archives. Subsequent local payload reads
    verify that item's authenticated SHA; live C/D observations remain fresh.
    """
    def __init__(self, plan, *, _token=None):
        if _token is not _VIEW_TOKEN:
            raise ValueError('A rebuilt execution authority is required')
        self._encoded = _json(plan)
        self._plan = json.loads(self._encoded)

    def checked_plan(self, candidate=None):
        if candidate is not None and _json(candidate) != self._encoded:
            raise ValueError('This job execution view changed')
        return json.loads(self._encoded)

    def payload(self, row, *, target):
        actual = next(r for r in self._plan['objects'] if r['path'] == row['path'])
        if row != actual:
            raise ValueError('Payload is outside this job authority')
        raw = read_private(row['original_path' if target else 'source_path'], 160 * 1024 * 1024)
        if legacy._identity(raw) != row['target' if target else 'source']:
            raise ValueError('Authenticated local payload changed')
        return raw


def materialize(scope_plan, output):
    plan = make_plan(scope_plan, output)
    return ValidatedExecution(plan, _token=_VIEW_TOKEN)


def authenticated_plan(value):
    return value.checked_plan() if type(value) is ValidatedExecution else validate_plan(value)


def authenticated_payload(authority, row, *, target):
    if type(authority) is ValidatedExecution:
        return authority.payload(row, target=target)
    plan = validate_plan(authority)
    if row not in plan['objects']:
        raise ValueError('Payload outside rebuilt execution authority')
    raw = read_private(row['original_path' if target else 'source_path'], 160 * 1024 * 1024)
    if legacy._identity(raw) != row['target' if target else 'source']:
        raise ValueError('Local payload changed')
    return raw


def validate_for_job(plan):
    return ValidatedExecution(validate_plan(plan), _token=_VIEW_TOKEN)


class RebuiltProjection:
    def __init__(self, plan, targets, *, _token=None):
        if _token is not _VIEW_TOKEN:raise ValueError('Internal reconstructed projection required')
        self._encoded=_json(plan)
        from types import MappingProxyType
        self._targets=MappingProxyType(dict(targets))
    def checked_plan(self):return json.loads(self._encoded)
    def _projection(self):return self.checked_plan(),dict(self._targets)


def reconstruct(current_capture,backup_capture):
    from . import backup_target_scope
    plan,targets=backup_target_scope.rebuild_projection(current_capture,backup_capture)
    return RebuiltProjection(plan,targets,_token=_VIEW_TOKEN)
