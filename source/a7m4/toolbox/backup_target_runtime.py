"""Fresh AP C/D disk+RAM window proof, never a whole-F hash admission."""
import os
from pathlib import Path
from . import original_ap_load as native
from .backup_target_execution import authenticated_plan, authenticated_payload
from hashlib import sha256
from .capture_inputs import read_private
from .native_actions import NativeActions, _write, _json


def make_probe(authority,*,endpoint='original'):
    plan=authenticated_plan(authority)
    if endpoint not in ('original','source'):raise ValueError('Unknown scoped AP endpoint')
    row=next(r for r in plan['objects'] if r['kind']=='ap')
    image=authenticated_payload(authority,row,target=endpoint=='original')
    ranges=[(r['offset'],r['offset']+len(bytes.fromhex(r['expected_hex']))) for r in native._ranges(plan,image)]
    ranges.extend(plan['scope_plan']['program']['components']['ap']['owned_ranges'])
    ranges.extend((d['offset'],d['offset']+d['size']) for d in plan['scope_plan']['program']['D'] if d['role']=='ap')
    merged=[]
    # JSON ownership ranges are lists; generated code/D ranges are tuples.
    # Normalize the pair container without changing any covered byte.
    for lo,hi in sorted((lo,hi) for lo,hi in ranges):
        if merged and lo<=merged[-1][1]:merged[-1]=(merged[-1][0],max(hi,merged[-1][1]))
        else:merged.append((lo,hi))
    windows=[dict(offset=at,expected_hex=image[at:min(at+512,hi)].hex()) for lo,hi in merged for at in range(lo,hi,512)]
    probe=dict(schema='a7m4-original-ap-load-plan/1',master_plan_id=plan['plan_id'],
        ap_target=row['target' if endpoint=='original' else 'source'],windows=windows)
    if endpoint=='source':probe['endpoint']='source'
    probe['plan_id']=sha256(native._json(probe)).hexdigest()
    return native.validate_probe_plan(probe)


def verify(plan, channel, output, *, compiler, boot_id, pid, endpoint='original', actions_factory=NativeActions):
    probe = make_probe(plan, endpoint=endpoint)
    output = Path(output); output.mkdir(mode=0o700)
    _write(output / 'probe.json', _json(probe))
    def check_disk():
        raw = channel.file('/usr/lib/appFw.so')
        if type(raw) is not bytes or len(raw) != probe['ap_target']['size']:
            raise ValueError('AP runtime probe disk geometry changed')
        for row in probe['windows']:
            value = bytes.fromhex(row['expected_hex']); at = row['offset']
            if raw[at:at + len(value)] != value:
                raise ValueError('AP C/D disk window differs')
    check_disk()
    binary = native.build(probe, output / 'build', compiler=compiler)
    nonce = os.urandom(16)
    request = native.REQUEST.pack(b'A7ALQ001', nonce, bytes.fromhex(probe['plan_id']), bytes(8))
    actions = actions_factory(channel, output / 'native')
    def accept(raw):
        _write(output / 'report.private.bin', raw)
        parsed = native.parse_report(probe, raw, nonce, boot_id=boot_id, pid=pid)
        loaded = parsed['loaded_current_ap_verified'] if endpoint == 'source' else parsed['loaded_original_ap_verified']
        return dict(parsed, schema='a7m4-backup-target-AP-C-loaded/1', C_loaded_verified=loaded,
            scope='registered-product-AP-C-and-explicit-load-geometry', whole_F_hash_admission=False,
            standard_original_AP_verified=False, standard_current_AP_verified=False)
    result = actions.phase(binary, native.REQUEST_PATH, request, native.RESULT_PATH, accept, report_bytes=native.REPORT.size)
    actions.clean_packets(); check_disk()
    return dict(result, native_report_path=str(output / 'report.private.bin'), nonce_hex=nonce.hex())
