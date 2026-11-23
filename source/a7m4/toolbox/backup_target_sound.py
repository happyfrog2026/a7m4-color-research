"""Selected original sound C through the existing scoped sound native profile."""
import os
from pathlib import Path
import struct
from . import sound_scope as sound
from .backup_target_execution import authenticated_plan as validate_plan, authenticated_payload
from .capture_inputs import read_private
from .native_actions import NativeActions, _write, _json


def ticket(execution, images):
    authority=execution;execution=validate_plan(authority)
    rows={r['kind']:r for r in execution['objects'] if r['kind'] in ('ap','audio')}
    desired_ap=authenticated_payload(authority,rows['ap'],target=True)
    desired_bank=authenticated_payload(authority,rows['audio'],target=True)
    if len(desired_bank)!=sound.ORIGINAL_EOF or sound.words(desired_ap)!=[w.hex() for w in sound.STOCK_WORDS]:
        raise ValueError('This release restores only an original 77504-byte stock-descriptor sound backup')
    source_ap=authenticated_payload(authority,rows['ap'],target=False)
    words=[bytes.fromhex(w) for w in sound.words(source_ap)]
    if words==list(sound.STOCK_WORDS):
        if sound.words(images['ap'])==[w.hex() for w in sound.STOCK_WORDS] and len(images['bank'])==77504 and images['bank'][:256]==desired_bank[:256]:
            return None
        raise ValueError('Sound source has no registered installed descriptor endpoint')
    lengths=dict(ka=256,sha=(struct.unpack('<I',words[1])[0]>>5)&65535,kasha=(struct.unpack('<I',words[6])[0]>>5)&65535)
    r066=words==list(sound.pin_plan.AP_BEFORE)
    if not r066 and tuple(words)!=sound.pin_plan._ap_after(lengths):
        raise ValueError('Current sound descriptors have no reviewed runtime endpoint')
    original=dict(eof=77504,ap_words=[w.hex() for w in sound.STOCK_WORDS],head_hex=desired_bank[:256].hex(),
        installed_ap_words=[w.hex() for w in words],native_lengths=lengths)
    if r066:
        if execution['scope_plan']['sound'].get('source_layout')!='historical-r066-native-pin':
            raise ValueError('R066 source must be authenticated by the current scope')
        original['runtime_profile']=sound.R066_RESTORE_PROFILE
    return sound.validate(sound.restore(images['ap'],images['cp'],images['bank'],original))


def execute(execution,channel,output,*,compiler,pid):
    images=lambda:{r:channel.file(p) for r,p in sound.PATHS.items()}
    plan=ticket(execution,images())
    if plan is None:return dict(complete=True,C_D_verified=True,E_F_gate_execution=False,no_op=True)
    output=Path(output);output.mkdir(mode=0o700)
    _write(output/'ticket.json',_json(plan))
    built=sound.build(plan,output/'build',compiler=compiler)
    protocol=sound.Protocol(plan);actions=NativeActions(channel,output/'native')
    actions.upload_data({row['upload_path']:row['data'] for row in sound.packets(plan).values()},report_sizes=(sound.REPORT.size,))
    def accept(raw):
        result=protocol.accept(raw)
        if result['pid']!=pid:raise ValueError('Sound process identity changed')
        return result
    binary=read_private(built['worker']['path'],65535)
    for mode in (0,1,3):
        actions.phase(binary,sound.REQUEST_PATH,protocol.request(mode,os.urandom(16)),sound.REPORT_PATH,accept,report_bytes=sound.REPORT.size)
        if mode in (0,3):proof=protocol.confirm(images())
    actions.clean_packets()
    return dict(complete=True,C_D_verified=True,E_F_gate_execution=False,readback=proof)
