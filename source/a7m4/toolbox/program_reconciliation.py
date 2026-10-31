"""Offline proof of one completed gate endpoint after a settings-guard refusal.

Never opens a device or changes a failed job. A fresh real complete capture
and a separately reviewed read-only closeout are required, then revalidated
on every lineage use. This is not a generic failed-job completion facility.
"""
from hashlib import sha256
import json
import struct
from pathlib import Path

from .capture_inputs import read_private
from . import program_worker as worker, settings_archive, settings_plan
from .capture_stability import capture_stability_report, settings_freshness_report
from .native_actions import _write, _json

NAME = 'program-reconciliation.private.json'
SCHEMA = 'a7m4-gate-readonly-reconciliation/1'
# This one-off closeout only read full targets/identity/scratch absence and STOP.
CLOSEOUT_SOURCE_SHA256 = '76393fac83a07c5c6d66f79288761fe75dfd9db2b8e28b29d61dbe0a761ba131'
ERROR = 'Unreviewed BK4 structural/header/generation change; preserve raw evidence and stop'


def need(value, message):
    if not value: raise ValueError(message)


def record(path):
    raw = read_private(path, 4*1024*1024)
    def unique(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result, 'Duplicate reconciliation evidence key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique), sha256(raw).hexdigest()


def _readonly_wire(root):
    """Exactly two complete captures, with no possible settings mutation intent."""
    wire=root/'settings-wire'
    need(sorted(p.name for p in wire.iterdir())==['%04d'%i for i in range(1,41)],
         'Exactly forty read-only settings journal entries required')
    need(not list(root.glob('*settings-journal*')), 'A settings mutation journal exists')
    fixed=[(0x603,5,b'\x01'),(0x603,5,b'\x00')]
    for path in ('/setting/BACKUP.BIN','/setting/BACKUP.BAK'):
        fixed.extend([(0x1001,0x400f,b'\0/tmp/jiritsu/../../'+path.lstrip('/').encode()+b'\0'),
                      (0x1001,0x4011,b'\0\xff\0')])
    fixed.extend([(0x603,0x40,struct.pack('<II',key,1)) for key in settings_plan.KEYS[:2]])
    fixed.extend([(0x603,1,struct.pack('<I',key)) for key in (settings_plan.SERIAL[1],settings_plan.AP55[1])])
    for base,first_seq in ((0,48),(20,356)):
        for i,(category,command,payload) in enumerate(fixed):
            pair=[]
            for index in (base+2*i+1,base+2*i+2):
                folder=wire/('%04d'%index);event,_=record(folder/'event.json')
                blob=read_private(folder/'bytes.bin',9*1024*1024)
                for key in ('request','wire','body','tail'):
                    if key not in event:continue
                    spec=event[key];raw=blob[spec['offset']:spec['offset']+spec['size']]
                    need(len(raw)==spec['size'] and sha256(raw).hexdigest()==spec['sha256'],
                         'Read-only journal part changed')
                spec=event['request'];request=blob[spec['offset']:spec['offset']+spec['size']]
                frame=struct.pack('<HH',category,command)+payload
                expected=struct.pack('<IHHBBBB',len(frame),0x40,first_seq+i,0,0,0,0)+frame
                operation=('full-settings' if command==5 else 'backing-select' if command==0x400f else 'backing-read' if command==0x4011 else 'fixed-record-read')
                need(event.get('operation')==operation and request==expected and event['category']==category and event['command']==command
                     and event['sequence']==first_seq+i,'Non-read or unexpected settings intent')
                pair.append(event)
            need(pair[0].get('verified') is not True and pair[1].get('verified') is True,
                 'Read-only capture lacks its complete response')


def _post_settings(root, base=20):
    """Read exactly the complete second capture in the original wire journal."""
    def body(index, operation, **facts):
        folder = root/'settings-wire'/('%04d'%index)
        event, _ = record(folder/'event.json')
        need(event.get('verified') is True and event.get('operation') == operation
             and all(event.get(k) == v for k,v in facts.items()), 'Post-settings wire role differs')
        blob = read_private(folder/'bytes.bin', 9*1024*1024)
        for key in ('request','wire','body','tail'):
            spec = event[key]
            raw = blob[spec['offset']:spec['offset']+spec['size']]
            need(len(raw) == spec['size'] and sha256(raw).hexdigest() == spec['sha256'],
                 'Post-settings wire bytes changed')
        spec = event['body']
        return blob[spec['offset']:spec['offset']+spec['size']]
    ram = body(base+2,'full-settings',memory=True)
    saved = body(base+4,'full-settings',memory=False)
    backing = [body(i,'backing-read',path=p) for i,p in
               ((base+8,'/setting/BACKUP.BIN'),(base+12,'/setting/BACKUP.BAK'))]
    need(all(raw[:4] == bytes(4) for raw in backing), 'Backing settings file status differs')
    cp = {key:body(i,'fixed-record-read',role='cp',key=key)
          for i,key in zip((base+14,base+16),settings_plan.KEYS[:2])}
    serial = body(base+18,'fixed-record-read',role='ap',key=settings_plan.SERIAL[1])
    direct = body(base+20,'fixed-record-read',role='ap',key=settings_plan.AP55[1])
    result = settings_plan.parse_snapshot(ram,saved,backing[0][4:],backing[1][4:],cp_live=cp,serial=serial)
    settings_plan.validate_snapshot(result)
    need(result.ram.records[settings_plan.AP55].data == direct == b'\x02', 'AP55 was not retained')
    return result


def _evaluate(failed_path, fresh_capture, closeout_folder):
    from .device_job import complete_capture
    from . import pin_sources as sources
    failed_path = Path(failed_path).absolute()
    need(failed_path.name == 'job.private.json', 'Original failed job path required')
    failed, failed_sha = record(failed_path)
    root = failed_path.parent
    need(failed.get('schema') == 'a7m4-toolbox-device-job/1'
         and failed.get('status') == 'STOP_UNKNOWN' and failed.get('error_type') == 'SettingsError'
         and failed.get('error') == ERROR and failed.get('feature') == 'electronic-sound-gate'
         and failed.get('camera_io') is True and failed.get('simulation',False) is False
         and failed.get('persistent_write_phase_attempted') is True
         and not failed.get('settings_results') and failed.get('resource_plans') == {},
         'Only the post-native gate settings-guard refusal may be reconciled')
    selection, selection_sha = record(root/'selection.json')
    need(selection == failed['selection'] and len(selection['program_stages']) == 1
         and selection['program_stages'] == failed['program_stages'], 'Single fixed gate selection differs')
    plan = worker.validate_plan(selection['program_stages'][0])
    source_path = Path(selection['capture_receipt']).absolute()
    source, original_settings = complete_capture(source_path)
    fresh, fresh_settings = complete_capture(fresh_capture)
    need(source['camera_io'] is True and fresh['camera_io'] is True
         and source['body_binding'] == fresh['body_binding'] == failed['body_binding'],
         'Real complete same-body captures required')
    need(set(source['objects']) == set(fresh['objects']) and len(source['objects']) == 11,
         'Complete current 11-object capture scope differs')
    before_images = sources.images(sources_paths(source))
    sources._gate_expected(plan,before_images)
    native = root/'program-0/native'
    need(sorted(p.name for p in native.glob('*-phase')) == ['002-phase','004-phase','006-phase'],
         'Unexpected extra program phase')
    protocol = worker.ProgramProtocol(plan)
    native_pins = []
    for ordinal, mode in ((2,0),(4,1),(6,3)):
        folder = native/('%03d-phase'%ordinal)
        intents = []
        for path in folder.glob('upload-*.intent.json'):
            intent, _ = record(path)
            if intent.get('path') == worker.REQUEST_PATH: intents.append((path,intent))
        need(len(intents) == 1, 'Exactly one owned native request required')
        path, intent = intents[0]
        request_path = path.with_name(path.name.replace('.intent.json','.bin'))
        request = read_private(request_path,worker.REQUEST.size)
        need(len(request) == intent['size'] == worker.REQUEST.size
             and sha256(request).hexdigest() == intent['sha256'], 'Native request changed')
        values = worker.REQUEST.unpack(request)
        need(protocol.request(mode,values[3]) == request, 'Original phase request/identity differs')
        report = read_private(folder/'report.bin',worker.REPORT.size)
        parsed = protocol.accept(report)
        need(parsed['pid'] == failed['native_process_id'], 'Original native process differs')
        if mode in (0,3):
            protocol.confirm_readback({role:root/'program-0'/('%d-%s.bin'%(mode,role)) for role in ('ap','cp')})
        native_pins.append(dict(mode=mode,request_sha256=sha256(request).hexdigest(),report_sha256=sha256(report).hexdigest()))
    role_for = {'appFw.so':'ap','CPAPP-B.BIN':'cp'}
    for name, old in source['objects'].items():
        new = fresh['objects'][name]
        expected = plan['components'][role_for[name]]['target'] if name in role_for else {
            k:old[k] for k in ('size','sha256')}
        need({k:new[k] for k in ('size','sha256')} == expected
             and new['target_path'] == old['target_path'], 'Fresh complete object differs: '+name)
    _readonly_wire(root)
    post = _post_settings(root)
    before = settings_archive.load_snapshot(root/'settings-before')
    need(settings_archive.same_snapshot(before,_post_settings(root,base=0)),
         'Initial complete wire capture and stored baseline differ')
    policies = dict(source_to_before=settings_freshness_report(original_settings,before),
        native_same_capture=capture_stability_report(before,post),
        before_to_fresh=settings_freshness_report(before,fresh_settings))
    need(all(v['stable'] for v in policies.values()), 'Unreviewed settings change in reconciliation evidence')
    closeout_folder = Path(closeout_folder).absolute()
    script = read_private(closeout_folder/'close_once.py',65536)
    need(sha256(script).hexdigest() == CLOSEOUT_SOURCE_SHA256, 'Reviewed read-only closeout required')
    config, config_sha = record(closeout_folder/'input.private.json')
    closeout, closeout_sha = record(closeout_folder/'attempt-1/result.private.json')
    pin = config['pins']['receipt']
    need(Path(pin['path']).absolute() == failed_path and pin['sha256'] == failed_sha
         and Path(config['source_capture']).absolute() == source_path,
         'Closeout original source/job binding differs')
    for spec in config['pins'].values():
        raw = read_private(spec['path'],4*1024*1024)
        need(sha256(raw).hexdigest() == spec['sha256'], 'Closeout original pin changed')
    expected_targets = {'/usr/lib/appFw.so':plan['components']['ap']['target'],
        '/cp/CPAPP-B.BIN':plan['components']['cp']['target'],
        '/cp/SysSound.bin':{k:source['objects']['extras/SysSound.bin'][k] for k in ('size','sha256')}}
    need(closeout.get('schema') == 'm4-completed-gate-independent-readonly-closeout/1'
         and closeout.get('status') == 'FORWARD_BYTES_AND_NORMAL_MSC_VERIFIED'
         and closeout.get('normal_msc_verified') is True and closeout.get('owned_scratch_absent') is True
         and closeout.get('camera_io') is True and closeout.get('persistent_device_writes') is False
         and closeout.get('settings_writes') == 0 and closeout.get('removed_owned') == []
         and closeout.get('verified_targets') == expected_targets
         and closeout.get('original_job_status_preserved') is True, 'Independent read-only closeout differs')
    events = closeout['events']
    need(events[0].get('helper_sha256') == CLOSEOUT_SOURCE_SHA256
         and [e['sequence'] for e in events if e['stage']=='EXCHANGE_VERIFIED'] == list(range(366,388))
         and sum(e['stage']=='SINGLE_STOP_INTENT' for e in events) == 1
         and events[-1]['stage'] == 'NORMAL_MSC_VERIFIED', 'Finite closeout sequence incomplete')
    _, fresh_sha = record(Path(fresh_capture))
    _, source_sha = record(source_path)
    return dict(body_binding=fresh['body_binding'],feature='electronic-sound-gate',stages=[plan],
        program_endpoint={'ap':plan['components']['ap']['target'],'cp_program':plan['components']['cp']['target']},
        bank=expected_targets['/cp/SysSound.bin'],
        evidence=dict(failed_receipt_sha256=failed_sha,selection_sha256=selection_sha,
            source_capture_sha256=source_sha,fresh_capture_sha256=fresh_sha,native=native_pins,
            closeout_input_sha256=config_sha,closeout_result_sha256=closeout_sha),
        settings_policies=policies,
        post_to_fresh_observation=dict(report=settings_freshness_report(post,fresh_settings),
            admission_basis=False,explanation="Two independently verified branches share the complete before baseline"))


def sources_paths(capture):
    root = Path(capture['snapshot_dir'])
    return dict(ap=root/'appFw.so',cp_program=root/'CPAPP-B.BIN',bank=root/'extras/SysSound.bin')


def create_reconciliation(failed_receipt, fresh_capture, closeout_folder, output):
    output = Path(output).absolute()
    need(output.name == NAME and output.parent.is_dir()
         and not any(p.is_symlink() for p in (output.parent,*output.parents)),
         'New explicit private reconciliation path required')
    refs = dict(failed_receipt=str(Path(failed_receipt).absolute()),fresh_capture=str(Path(fresh_capture).absolute()),
        closeout_folder=str(Path(closeout_folder).absolute()))
    evaluated = _evaluate(refs['failed_receipt'],refs['fresh_capture'],refs['closeout_folder'])
    proof = dict(schema=SCHEMA,status='RECONCILED_PROGRAM_ENDPOINT',camera_io=False,
        reconciliation_performed_write=False,original_job_status_preserved=True,
        refs=refs,evaluated=evaluated)
    _write(output,_json(proof))
    return proof


def verify_reconciliation(path, body):
    path = Path(path).absolute()
    need(path.name == NAME, 'Explicit reconciliation filename required')
    proof, digest = record(path)
    need(proof.get('schema') == SCHEMA and proof.get('status') == 'RECONCILED_PROGRAM_ENDPOINT'
         and proof.get('camera_io') is False and proof.get('reconciliation_performed_write') is False
         and proof.get('original_job_status_preserved') is True, 'Read-only reconciliation schema differs')
    refs = proof['refs']
    evaluated = _evaluate(refs['failed_receipt'],refs['fresh_capture'],refs['closeout_folder'])
    need(proof['evaluated'] == evaluated and evaluated['body_binding'] == body, 'Reconciliation evidence/body changed')
    return dict(receipt=str(path),receipt_sha256=digest,**{k:evaluated[k] for k in
        ('feature','stages','bank','program_endpoint')})
