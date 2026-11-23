"""Pure selected installation forecast, bound to original C and frozen inputs."""
from hashlib import sha256
from pathlib import Path
import tempfile
from . import selected_config, selected_baseline, backup_target_execution as execution
from . import looks_program as lp, looks_resource_scope as lr, sound_scope as ss, gate_scope as gs
from .native_actions import _json
from .capture_inputs import read_private

SCHEMA='a7m4-selected-plan/1'


def _selection(value):return selected_config.load(value) if isinstance(value,(str,Path)) else selected_config.validate(value)


def _apply_program(images,ticket):
    for role,rows in ticket['C_targets'].items():
        target=bytearray(images[role])
        for row in rows:
            raw=bytes.fromhex(row['after_hex']);at=row['offset'];target[at:at+len(raw)]=raw
        images[role]=bytes(target)


def _plan(capture,selection,baseline):
    from . import cutoff_scope
    config=selection['draft'];filters=config['filters'];sound=config['sound']
    base=baseline.checked_plan();images={}
    if (base['source_capture']['receipt']!=str(Path(capture).absolute()) or
            base['backup_capture']['receipt_sha256']!=selection['original_capture']['sha256']):
        raise ValueError('Selected baseline source or original backup binding differs')
    from .backup_target_runtime import make_probe
    source_probe=make_probe(baseline,endpoint='source')
    for role,path in ss.PATHS.items():
        row=next(r for r in base['objects'] if r['target_path']==path)
        images[role]=execution.authenticated_payload(baseline,row,target=False)
    programs=[];sound_ticket=None;cutoff=None
    if sound['mode']=='none':gs.need(gs.state(images['cp'])=='disabled','静音配置要求原始电子声关闭基线；请先恢复到原始备份。')
    if sound['mode']=='prepared':
        gate=gs.program(images['ap'],images['cp'],'enabled')
        for role,component in (gate['components'] if gate else {}).items():
            target=bytearray(images[role])
            for w in component['windows']:
                raw=bytes.fromhex(w['after_hex']);at=w['offset'];target[at:at+len(raw)]=raw
            images[role]=bytes(target)
        cutoff=cutoff_scope.plan(images['ap'],images['cp'],sound['cutoff_seconds'])
        # Cutoff is the only additional finite program C; no arbitrary offsets.
        if cutoff['native_plan'] is not None:
            for role,component in cutoff['native_plan']['components'].items():
                target=bytearray(images[role])
                for w in component['windows']:
                    raw=bytes.fromhex(w['after_hex']);at=w['offset'];target[at:at+len(raw)]=raw
                images[role]=bytes(target)
        sound_ticket=ss.forward(images['ap'],images['cp'],images['bank'],selection['prepared_ref']['path'],selected=True)
        target=bytearray(images['ap'])
        for window in sound_ticket['ap_windows']:
            raw=bytes.fromhex(window['after_hex']);at=window['offset'];target[at:at+len(raw)]=raw
        images['ap']=bytes(target)
    if filters['fl23'] or filters['m9']:
        programs.append(lp.plan(images['ap'],images['cp'],config=dict(fl23=filters['fl23'],m9=filters['m9'],slot=1,display_name='M9')))
    resource_plan=None
    if filters['m9']:
        files={row['target_path']:execution.authenticated_payload(baseline,row,target=False) for row in base['objects'] if row['kind']=='resource'}
        resource_plan=lr.plan_forward(files,icon_project=selection['display_ref']['path'],owned_playback=False)
        if resource_plan['display']!=selection['display_ref']['display']:raise ValueError('Selected display projection differs')
    value=dict(schema=SCHEMA,selection_sha256=selection['selection_sha256'],profile='selected',
        body_binding=base['body_binding'],capture_receipt=str(Path(capture).absolute()),
        original_capture=selection['original_capture'],baseline_scope_plan_id=base['scope_plan_id'],
        baseline_registered_C_D_unchanged=True,source_runtime_probe=dict(plan_id=source_probe['plan_id'],window_count=len(source_probe['windows']),bytes=sum(len(bytes.fromhex(w['expected_hex'])) for w in source_probe['windows'])),program=programs,
        sound=sound_ticket,cutoff=cutoff,resource_files=len(resource_plan['files']) if resource_plan else 0,
        resource_plan_id=resource_plan['plan_id'] if resource_plan else None,
        display=selection['display_ref']['display'] if selection['display_ref'] else None,
        source_admission='original-baseline-C-and-fresh-D-only',E_F_gate_execution=False,
        cache_restore='NORMAL_REBUILD',camera_io=False,device_validation='NOT_PERFORMED')
    value['plan_id']=sha256(_json(value)).hexdigest();return value


def make_plan(capture,selection,*,baseline=None,selection_sha256=None):
    selection=_selection(selection)
    if selection_sha256 is not None and selection['selection_sha256']!=selection_sha256:
        raise ValueError('Final selection differs from the confirmed snapshot')
    if baseline is not None:return _plan(capture,selection,baseline)
    with tempfile.TemporaryDirectory(prefix='a7m4-selected-plan-',dir='/private/tmp') as folder:
        baseline=selected_baseline.prepare(capture,selection['original_capture']['path'],Path(folder)/'baseline')
        return _plan(capture,selection,baseline)
