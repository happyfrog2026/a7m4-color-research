"""Scoped program readback barriers over the unchanged bounded native ABI."""
import os
from pathlib import Path
from .backup_target_execution import authenticated_plan as validate_plan, authenticated_payload
from .original_program_adapter import inverse_restore_view
from . import original_restore as byte_diff
from . import program_worker as worker, looks_program, sound_scope
from .capture_inputs import read_private
from .native_actions import NativeActions, _write


def batches(plan):
    plan=validate_plan(plan)
    rows={r['kind']:r for r in plan['objects'] if r['kind'] in ('ap','cp')}
    images={role:read_private(row['source_path'],160*1024*1024) for role,row in rows.items()}
    pending=[]
    for role,row in rows.items():
        target=bytearray(read_private(row['original_path'],160*1024*1024))
        if role=='ap':
            # The sound transaction owns its seven descriptors together with
            # bank C/EOF. Never split their restoration across program+sound.
            for at in sound_scope.AP_OFFSETS:target[at:at+4]=images[role][at:at+4]
        if len(target)!=len(images[role]):raise ValueError('Program geometry differs')
        from .backup_target_scope import _windows
        pending.extend((role,w) for w in _windows(images[role],bytes(target),plan['scope_plan']['program']['components'][role]['owned_ranges']))
    result=[]
    while pending:
        selected=[];total=ap=0
        while pending and len(selected)<worker.MAX_WINDOWS:
            role,w=pending[0];n=len(bytes.fromhex(w['before_hex']))
            if total+n>worker.MAX_TOTAL_BYTES or ap+(n if role=='ap' else 0)>worker.MAX_AP_BYTES:break
            pending.pop(0);selected.append((role,w));total+=n;ap+=n if role=='ap' else 0
        if not selected:raise ValueError('Program C batch exceeds native bound')
        target={role:bytearray(raw) for role,raw in images.items()};windows={role:[] for role in images}
        for role,w in selected:
            at=w['offset'];raw=bytes.fromhex(w['after_hex']);target[role][at:at+len(raw)]=raw;windows[role].append(w)
        value=worker.program_plan({role:dict(source=byte_diff._identity(images[role]),target=byte_diff._identity(bytes(target[role])),windows=windows[role])
            for role in ('ap','cp')},feature_id='backup-target-program-c-v1')
        result.append(value);images={role:bytes(raw) for role,raw in target.items()}
    return result


def check_dependencies(anchors,images):
    if type(anchors) is not list:raise ValueError('Explicit scope D anchors required')
    for row in anchors:
        role=row['role'];at=row['offset'];value=bytes.fromhex(row['hex'])
        if role not in ('ap','cp') or type(at) is not int or not value or len(value)!=row['size'] or not 0<=at<=len(images[role])-len(value):
            raise ValueError('Program scope D shape differs')
        if images[role][at:at+len(value)]!=value:raise ValueError('Program explicit D differs')
    return dict(D_verified=True)


class Protocol(worker.ProgramProtocol):
    def __init__(self,plan,*,dependencies,owned=None):
        from copy import deepcopy
        super().__init__(plan);self.D=deepcopy(dependencies);self.C=deepcopy(owned)

    def confirm_readback(self, images):
        try:
            if self.state != 'READY' or self.pending is not None or self.previous_mode not in (0, 3):
                raise ValueError('Complete native inspect is required')
            raw = {role: read_private(images[role], 160 * 1024 * 1024) for role in ('ap', 'cp')}
            check_dependencies(self.D,raw)
            side = 'after_hex' if self.previous_mode == 3 else 'before_hex'
            if self.C is not None:
                for role,rows in self.C.items():
                    for row in rows:
                        value=bytes.fromhex(row['before_hex' if self.previous_mode==3 else 'after_hex']);at=row['offset']
                        if raw[role][at:at+len(value)]!=value:raise ValueError('Program registered C barrier differs')
            for role, component in self.plan['components'].items():
                if len(raw[role]) != component['source']['size']:
                    raise ValueError('Program geometry changed')
                for row in component['windows']:
                    value = bytes.fromhex(row[side]); at = row['offset']
                    if raw[role][at:at + len(value)] != value:
                        raise ValueError('Program C readback differs')
            self.full_endpoint = 'target' if self.previous_mode == 3 else 'source'
            return dict(C_D_verified=True, E_F_gate_execution=False,
                observed_files={role: looks_program.identity(value) for role, value in raw.items()})
        except BaseException:
            self.unknown(); raise


class Adapter:
    def __init__(self, plan, channel, output, *, compiler, expected_process_id):
        self.authority=plan;self.plan = validate_plan(plan); self.channel = channel
        self.output = Path(output); self.output.mkdir(mode=0o700)
        self.compiler = compiler; self.pid = expected_process_id
        self.batches = batches(self.authority)

    def execute(self):
        results = []
        current={r['kind']:read_private(r['source_path'],160*1024*1024) for r in self.plan['objects'] if r['kind'] in ('ap','cp')}
        for index, transition in enumerate(self.batches):
            plan = inverse_restore_view(transition)
            root = self.output / ('%03d' % index); root.mkdir(mode=0o700)
            built = worker.build_program_worker(plan, root / 'build', compiler=self.compiler)
            from .build_scratch import discard_caches
            discard_caches(root / 'build')
            binary = read_private(built['worker']['path'], 65535)
            target={role:bytearray(raw) for role,raw in current.items()}
            for role,component in transition['components'].items():
                for window in component['windows']:
                    value=bytes.fromhex(window['after_hex']);at=window['offset'];target[role][at:at+len(value)]=value
            owned={role:[dict(offset=lo,before_hex=current[role][lo:hi].hex(),after_hex=bytes(target[role][lo:hi]).hex())
                for lo,hi in self.plan['scope_plan']['program']['components'][role]['owned_ranges']] for role in current}
            protocol = Protocol(plan,dependencies=self.plan['scope_plan']['program']['D'],owned=owned)
            actions = NativeActions(self.channel, root / 'native')
            def accept(raw):
                result = protocol.accept(raw)
                if result['pid'] != self.pid:
                    raise ValueError('Program native process changed')
                return result
            for mode in (3, 2, 0):
                actions.phase(binary, worker.REQUEST_PATH, protocol.request(mode, os.urandom(16)),
                    worker.RESULT_PATH, accept, report_bytes=worker.REPORT.size)
                if mode in (3, 0):
                    paths = {}
                    for role, remote in worker.PATHS.items():
                        path = root / ('%d-%s.bin' % (mode, role))
                        _write(path, self.channel.file(remote)); paths[role] = path
                    verified = protocol.confirm_readback(paths)
            actions.clean_packets()
            current={role:bytes(raw) for role,raw in target.items()}
            results.append(dict(plan_id=plan['plan_id'], readback=verified, restore_order='AP-before-CP'))
        return dict(complete=True, batches=results, C_D_verified=True, E_F_gate_execution=False)
