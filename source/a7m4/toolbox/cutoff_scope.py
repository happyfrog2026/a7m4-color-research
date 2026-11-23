"""Finite four-byte camera cutoff choice over the existing program worker.

No arbitrary threshold encoding, native change, transport or discovery. The
1/50 endpoint is an existing offline candidate, not a hardware-validated claim.
"""
from copy import deepcopy
from hashlib import sha256

from . import sound_scope as sound, program_worker as worker
from .capture_inputs import read_private
from .native_actions import _json

SCHEMA = 'a7m4-selected-sound-cutoff/1'
OFFSET = 3182020


def _seal(value):
    value = deepcopy(value)
    value.pop('plan_id', None)
    value['plan_id'] = sha256(_json(value)).hexdigest()
    return value


def plan(ap, cp, target_seconds):
    sound.need(type(target_seconds) in (int, float) and target_seconds in sound.CUTOFF_INSTRUCTIONS,
               'Only original 1/8 or the registered 1/50 candidate is supported')
    D = sound.dependencies(ap, cp, enabled=True, registered_cutoffs=True)
    before = cp[OFFSET:OFFSET + 4].hex()
    after = sound.CUTOFF_INSTRUCTIONS[target_seconds]
    target = cp[:OFFSET] + bytes.fromhex(after) + cp[OFFSET + 4:]
    window = dict(offset=OFFSET, before_hex=before, after_hex=after)
    native = None
    if before != after:
        native = worker.program_plan(dict(
            ap=dict(source=sound.identity(ap), target=sound.identity(ap), windows=[]),
            cp=dict(source=sound.identity(cp), target=sound.identity(target), windows=[window])),
            feature_id='selected-sound-cutoff-v1')
    return _seal(dict(schema=SCHEMA, target_seconds=target_seconds, C=window, D=D,
                      native_plan=native, E_F_gate_execution=False, camera_io=False,
                      hardware_validated_this_run=False))


def validate(value):
    sound.need(type(value) is dict and value.get('schema') == SCHEMA and _seal(value) == value,
               'Finite selected cutoff ticket integrity differs')
    sound.need(set(value) == {'schema', 'target_seconds', 'C', 'D', 'native_plan',
                             'E_F_gate_execution', 'camera_io', 'hardware_validated_this_run', 'plan_id'}
               and value['E_F_gate_execution'] is False and value['camera_io'] is False
               and value['hardware_validated_this_run'] is False, 'Selected cutoff authority differs')
    seconds = value['target_seconds']
    sound.need(type(seconds) in (int, float) and seconds in sound.CUTOFF_INSTRUCTIONS,
               'Unregistered cutoff target')
    row = value['C']
    sound.need(type(row) is dict and set(row) == {'offset', 'before_hex', 'after_hex'}
               and row['offset'] == OFFSET and row['before_hex'] in sound.CUTOFF_INSTRUCTIONS.values()
               and row['after_hex'] == sound.CUTOFF_INSTRUCTIONS[seconds], 'Cutoff must own exactly its four bytes')
    native = value['native_plan']
    if row['before_hex'] == row['after_hex']:
        sound.need(native is None, 'Unchanged cutoff cannot dispatch a worker')
    else:
        worker.validate_plan(native)
        sound.need(native['components']['ap']['windows'] == []
                   and native['components']['cp']['windows'] == [row]
                   and native['feature_id'] == 'selected-sound-cutoff-v1', 'Native cutoff window escaped C')
        for role in ('ap', 'cp'):
            c = native['components'][role]
            sound.need(c['source']['size'] == c['target']['size'] == sound.LIMITS[role], 'Cutoff program geometry differs')
    return deepcopy(value)


def check(value, images, *, target):
    value = validate(value)
    sound.dependencies(images['ap'], images['cp'], enabled=True, registered_cutoffs=True)
    expected = value['C']['after_hex' if target else 'before_hex']
    sound.need(images['cp'][OFFSET:OFFSET + 4].hex() == expected, 'Selected camera cutoff C differs')
    return dict(C_D_verified=True, E_F_gate_execution=False,
                observed_files={role: sound.identity(images[role]) for role in ('ap', 'cp')})


def build(value, output, *, compiler):
    value = validate(value)
    sound.need(value['native_plan'] is not None, 'Unchanged cutoff has no worker to build')
    return worker.build_program_worker(value['native_plan'], output, compiler=compiler)


class Protocol(worker.ProgramProtocol):
    def __init__(self, value):
        self.ticket = validate(value)
        sound.need(self.ticket['native_plan'] is not None, 'NOOP cutoff has no native protocol')
        super().__init__(self.ticket['native_plan'])

    def confirm(self, images):
        try:
            sound.need(self.state == 'READY' and self.pending is None and self.previous_mode in (0, 3),
                       'Completed cutoff native inspection required')
            result = check(self.ticket, images, target=self.previous_mode == 3)
            self.full_endpoint = 'target' if self.previous_mode == 3 else 'source'
            return result
        except BaseException:
            self.unknown()
            raise

    def confirm_readback(self, images):
        return self.confirm({role: read_private(images[role], 160 * 1024 * 1024) for role in ('ap', 'cp')})
