"""Immutable final UI intent and asset bindings; no camera or host discovery.

Presets populate drafts only. The sealed selection always records the user's
final controls and exact prepared sound/display files, rather than a preset ID.
"""
from copy import deepcopy
from hashlib import sha256
import json
import math
from pathlib import Path

from .capture_inputs import read_private
from .native_actions import _json, _write
from . import sound_scope, looks_resource_scope

DRAFT_SCHEMA = 'a7m4-selected-draft/1'
SCHEMA = 'a7m4-selected-config/1'
MAXIMUM = 2 * 1024 * 1024
CUTOFFS = (0.125, 0.02)


def need(condition, message):
    if not condition:
        raise ValueError(message)


def _number(value, minimum, maximum):
    return type(value) in (int, float) and math.isfinite(value) and minimum <= value <= maximum


def draft(value):
    if isinstance(value, (str, Path)):
        value = json.loads(read_private(value, 65536))
    need(type(value) is dict and set(value) == {'schema', 'filters', 'sound'}
         and value['schema'] == DRAFT_SCHEMA, 'Exact final selection draft required')
    filters = value['filters']
    need(type(filters) is dict and set(filters) == {'fl23', 'm9'}
         and all(type(v) is bool for v in filters.values()), 'Explicit FL2/FL3 and M9 choices required')
    sound = value['sound']
    need(type(sound) is dict and sound.get('mode') in ('none', 'prepared'), 'Explicit silent or prepared sound required')
    if sound['mode'] == 'none':
        need(set(sound) == {'mode'}, 'Silent selection cannot carry unapplied sound controls')
    else:
        need(set(sound) == {'mode', 'gain_db', 'recock_enabled', 'recock_gap_ms', 'cutoff_seconds'},
             'Exact final sound controls required')
        need(_number(sound['gain_db'], -96, 24) and type(sound['recock_enabled']) is bool
             and _number(sound['recock_gap_ms'], 0, 80)
             and type(sound['cutoff_seconds']) in (int, float) and sound['cutoff_seconds'] in CUTOFFS,
             'Sound gain, recock gap or supported camera cutoff differs')
    return deepcopy(value)


def preset(index):
    need(type(index) is int and index in (1, 2, 3), 'One of the three convenience presets required')
    return dict(schema=DRAFT_SCHEMA, filters=dict(fl23=True, m9=index == 1),
                sound=(dict(mode='none') if index == 3 else
                       dict(mode='prepared', gain_db=0, recock_enabled=index == 1,
                            recock_gap_ms=40, cutoff_seconds=0.125)))


def _file_ref(path, maximum):
    need(isinstance(path, (str, Path)), 'Private input path required')
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts, 'Absolute private input path without traversal required')
    raw = read_private(path, maximum)
    return dict(path=str(path), size=len(raw), sha256=sha256(raw).hexdigest())


def _manifest(path):
    path = Path(path)
    return path / 'manifest.json' if path.is_dir() else path


def freeze(value, original_capture, *, prepared=None, native_project=None, output=None):
    value = draft(value)
    original = _file_ref(original_capture, MAXIMUM)
    prepared_ref = display_ref = None
    if value['sound']['mode'] == 'prepared':
        need(prepared is not None, 'Prepared final sound files required')
        manifest, clips = sound_scope.prepared(prepared, selected=True)
        controls = manifest['controls']
        for key in ('gain_db', 'recock_enabled', 'recock_gap_ms', 'cutoff_seconds'):
            need(controls[key] == value['sound'][key], 'Prepared sound no longer matches final UI control: ' + key)
        ref = _file_ref(_manifest(prepared).absolute(), MAXIMUM)
        prepared_ref = dict(path=str(Path(ref['path']).parent), manifest_bytes=ref['size'],
                            manifest_sha256=ref['sha256'],
                            native={role: dict(bytes=len(raw), sha256=sha256(raw).hexdigest())
                                    for role, raw in clips.items()})
    else:
        need(prepared is None, 'Silent selection cannot install an audio pack')
    if value['filters']['m9']:
        need(native_project is not None, 'Final Custom1 M9 name/icon project required')
        display = looks_resource_scope.project_display(native_project)
        ref = _file_ref(_manifest(native_project).absolute(), MAXIMUM)
        display_ref = dict(path=str(Path(ref['path']).parent), manifest_bytes=ref['size'],
                           manifest_sha256=ref['sha256'], display=display)
    else:
        need(native_project is None, 'Unselected M9 cannot install name/icon resources')
    selection = dict(schema=SCHEMA, draft=value, original_capture=original,
                     prepared_ref=prepared_ref, display_ref=display_ref,
                     camera_io=False, network_io=False,
                     requires_original_baseline=True, E_F_gate_execution=False)
    selection['selection_sha256'] = sha256(_json(selection)).hexdigest()
    if output is not None:
        path = Path(output)
        need(not path.exists(), 'New final selection output required')
        _write(path, _json(selection))
    return selection


def validate(value):
    fields = {'schema', 'draft', 'original_capture', 'prepared_ref', 'display_ref', 'camera_io',
              'network_io', 'requires_original_baseline', 'E_F_gate_execution', 'selection_sha256'}
    need(type(value) is dict and set(value) == fields and value.get('schema') == SCHEMA,
         'Exact frozen final selection schema required')
    original = value['original_capture']
    need(type(original) is dict and set(original) == {'path', 'size', 'sha256'}
         and isinstance(original['path'], str), 'Exact original backup reference required')
    for key, keys in (('prepared_ref', {'path', 'manifest_bytes', 'manifest_sha256', 'native'}),
                      ('display_ref', {'path', 'manifest_bytes', 'manifest_sha256', 'display'})):
        ref = value[key]
        need(ref is None or type(ref) is dict and set(ref) == keys and isinstance(ref['path'], str),
             'Exact frozen asset reference required: ' + key)
    encoded = {k: v for k, v in value.items() if k != 'selection_sha256'}
    need(value.get('selection_sha256') == sha256(_json(encoded)).hexdigest(), 'Final selection seal differs')
    expected = freeze(value['draft'], value['original_capture']['path'],
                      prepared=(value['prepared_ref']['path'] if value['prepared_ref'] is not None else None),
                      native_project=(value['display_ref']['path'] if value['display_ref'] is not None else None))
    need(value == expected, 'Final selection or bound sound/name/icon assets changed')
    return deepcopy(value)


def load(path):
    return validate(json.loads(read_private(path, MAXIMUM)))
