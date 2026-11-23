"""Explicit fixed looks transaction over one exclusively owned USB session.

Planning/building is local. This module never runs on import. The public CLI
requires new per-operation acknowledgments before calling any executor.
"""
from contextlib import ExitStack
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import tempfile
from types import SimpleNamespace
import uuid

from .capture_inputs import verified_device_capture as verified_capture,read_private
from .job_ownership import create_job_output
from .selection_ref import reference as selection_reference
from .native_actions import NativeActions,_write,_json
from .native_channel import channel_class,LIBRARY
from .ownership import camera_lock,release_host_volumes,verify_normal_return
from .usb_read import ServiceSession,body_binding,VERSION_SHA256,LOADER_SHA256,_atomic_json,CAPTURE_TARGETS
from . import host_metadata,workspace,program_worker,resource_worker,resource_forward,settings_archive
from .settings_channel import SettingsChannel
from .settings_scope import settings_scope_freshness_report,sound_operation
from . import gate_scope,save_effects,gate_cumulative
from .original_wbi import OriginalWBI,load_sources as wbi_sources,report_bound as wbi_report_bound
from .settings_job import SettingsJob,check_full as check_settings_full,_maps as settings_maps,check_forward_C_D,observe_forward_F
from .settings_plan import plan_fixed_settings,plan_ap55,plan_manifest,inverse_plan,validate_fixed_prerequisites,needs_save


class DeviceJobError(RuntimeError):
    def __init__(self,message,result):super().__init__(message);self.result=result


class Journal:
    """Bytes are durable private files, then referenced from durable JSON."""
    def __init__(self,path):self.path=Path(path);self.path.mkdir(mode=0o700);self.index=0
    def __call__(self,event):
        self.index+=1;folder=self.path/('%04d'%self.index);folder.mkdir(mode=0o700);parts=[];size=[0];seen={}
        def encode(value):
            if type(value) is bytes:
                digest=sha256(value).hexdigest();key=(len(value),digest)
                if key not in seen:
                    seen[key]=size[0];parts.append(value);size[0]+=len(value)
                return dict(path='bytes.bin',offset=seen[key],size=len(value),sha256=digest)
            if isinstance(value,dict):return {str(k):encode(v) for k,v in value.items()}
            if isinstance(value,(tuple,list)):return [encode(v) for v in value]
            return value
        encoded=encode(event)
        if parts:_write(folder/'bytes.bin',b''.join(parts))
        _write(folder/'event.json',_json(encoded))


def complete_capture(path):
    capture=verified_capture(path)
    from .. import resource_profile as device_scope
    capture=dict(capture,objects={name:row for name,row in capture["objects"].items() if name in device_scope.OBJECTS})
    if capture.get('settings_capture_verified') is not True:
        raise ValueError('This installation requires the complete portable capture including RAM/saved/BIN/BAK/direct CP')
    settings=settings_archive.load_snapshot(Path(path).absolute().parent/'settings')
    if body_binding(settings.serial)!=capture['body_binding']:raise ValueError('Complete backup settings/body differs')
    return capture,settings


def freeze_native_project(project,output):
    from ..research import native_icons
    manifest,root=native_icons._project(project)
    folder=Path(output);folder.mkdir(mode=0o700)
    names={'manifest.json'}
    for row in manifest['assets']:
        names.update(row[k] for k in ('raw','compressed','png'))
    for relative in sorted(names):
        if (not isinstance(relative,str) or not relative or relative.startswith('/') or '\\' in relative or ':' in relative
                or any(p in ('','.','..') for p in relative.split('/'))):raise ValueError('Noncanonical native project asset path')
        source=root/relative
        target=folder/relative;target.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        _write(target,read_private(source,1024*1024))
    return folder/'manifest.json'


def looks_selection(capture_path,selection,native_project,output,*,program_jobs=(),sound_job=None):
    from .looks import plan_looks
    capture,settings=complete_capture(capture_path)
    # Match the existing fresh-device checks using the selected local backup.
    # Placeholder bindings are discarded; execution still requires fresh ones.
    plan_ap55(settings,identity=capture['body_binding']['serial_sha256'],
              boot_id=str(uuid.uuid4()),nonce=os.urandom(16).hex())
    if selection.get('include_fl2')!=selection.get('include_fl3'):
        raise ValueError('This fixed release installs FL2 and FL3 together; select both or preserve both')
    if selection.get('include_fl2') or selection.get('include_fl3'):
        validate_fixed_prerequisites(settings)
    result=plan_looks(Path(capture['snapshot_dir']),selection,native_project,output,
        previous_jobs=program_jobs,sound_job=sound_job,capture=capture_path)
    result['capture_receipt']=str(Path(capture_path).absolute())
    result['body_binding']=capture['body_binding']
    # The pure looks planner supplies program_stages for stock bootstrap.
    result['program_stages']=result.get('program_stages') or ([result['program']] if result.get('program') else [])
    return result


def _validate_full_plan(capture,planned,*,inverse=False):
    """Bind the complete 11-object source and every program stage locally."""
    objects=capture.get('objects',{})
    components=planned.get('components',{})
    stages=planned.get('program_stages')
    if (type(objects) is not dict or set(objects)!=set(CAPTURE_TARGETS)
            or type(components) is not dict or set(components)!=set(objects)
            or type(stages) is not list or len(stages)>8):
        raise ValueError('Complete 11-object plan/capture scope and bounded program stages required')
    snapshot=Path(capture['snapshot_dir']).absolute()
    for name,definition in CAPTURE_TARGETS.items():
        row,component=objects[name],components[name]
        if type(row) is not dict or type(component) is not dict:
            raise ValueError('Malformed complete object plan: '+name)
        source=component.get('source',{})
        if (type(source) is not dict or row.get('target_path')!=definition['target_path']
                or row.get('kind')!=definition['kind']
                or component.get('target_path')!=definition['target_path']
                or source.get('path')!=str(snapshot/name) or source.get('kind')!=definition['kind']
                or any(source.get(key)!=row.get(key) for key in ('size','sha256'))):
            raise ValueError('Complete source path/kind/identity differs: '+name)
        source_id={key:source[key] for key in ('size','sha256')}
        target=program_worker._identity(component.get('target'))
        program_worker._identity(source_id)
        if definition['kind']=='audio' and target!=source_id:
            raise ValueError('This coordinator cannot modify audio objects')
        append=component.get('append',{})
        if type(append) is not dict:
            raise ValueError('Complete append description missing: '+name)
        extra=resource_worker.hx(append.get('after_hex'))
        if (append.get('offset')!=source_id['size'] or append.get('size')!=len(extra)
                or append.get('sha256')!=sha256(extra).hexdigest()):
            raise ValueError('Complete append identity/offset differs: '+name)
        if definition['kind'] in ('ap','cp','audio') and extra:
            raise ValueError('Program/audio append is outside this coordinator')
        if definition['kind']=='audio' and component.get('windows')!=[]:
            raise ValueError('Audio mutation windows are outside this coordinator')
        if definition['kind']=='resource':
            if source_id!=target:
                # The executor selects mutations by SHA; size-only changes
                # with an unchanged digest must never be silently omitted.
                if source_id['sha256']==target['sha256']:
                    raise ValueError('Inconsistent resource target size/SHA')
                resource=resource_worker.from_component(component)
                raw=read_private(snapshot/name,resource_worker.LIMIT)
                if dict(size=len(raw),sha256=sha256(raw).hexdigest())!=source_id:
                    raise ValueError('Complete local resource source changed: '+name)
                target_raw=bytearray(raw)
                for window in resource['windows']:
                    at=window['offset'];before=bytes.fromhex(window['before_hex'])
                    if target_raw[at:at+len(before)]!=before:
                        raise ValueError('Complete local resource preimage differs: '+name)
                    target_raw[at:at+len(before)]=bytes.fromhex(window['after_hex'])
                target_raw.extend(extra)
                if dict(size=len(target_raw),sha256=sha256(target_raw).hexdigest())!=target:
                    raise ValueError('Complete local resource target/complement differs: '+name)
            elif (component.get('windows')!=[] or component.get('append',{}).get('after_hex')!=''):
                raise ValueError('Unchanged resource contains a mutation')
    chain={role:{key:objects[name][key] for key in ('size','sha256')}
           for role,name in (('ap','appFw.so'),('cp','CPAPP-B.BIN'))}
    images={role:read_private(snapshot/name,160*1024*1024)
            for role,name in (('ap','appFw.so'),('cp','CPAPP-B.BIN'))} if stages else {}
    if any(dict(size=len(raw),sha256=sha256(raw).hexdigest())!=chain[role] for role,raw in images.items()):
        raise ValueError('Complete local program source changed during planning')
    for stage in stages:
        program_worker.validate_plan(stage)
        for role in ('ap','cp'):
            start,end=('target','source') if inverse else ('source','target')
            if stage['components'][role][start]!=chain[role]:
                raise ValueError('Complete program stage source chain differs: '+role)
            raw=bytearray(images[role])
            for window in stage['components'][role]['windows']:
                at=window['offset'];before=bytes.fromhex(window['after_hex' if inverse else 'before_hex'])
                after=bytes.fromhex(window['before_hex' if inverse else 'after_hex'])
                if raw[at:at+len(before)]!=before:
                    raise ValueError('Complete local program stage preimage differs: '+role)
                raw[at:at+len(after)]=after
            if dict(size=len(raw),sha256=sha256(raw).hexdigest())!=stage['components'][role][end]:
                raise ValueError('Complete local program stage target/complement differs: '+role)
            images[role]=bytes(raw)
            chain[role]=stage['components'][role][end]
    if any(components[name]['target']!=chain[role]
           for role,name in (('ap','appFw.so'),('cp','CPAPP-B.BIN'))):
        raise ValueError('Complete final program target differs from stage chain')


def _native_protocol(base,plan,process,receipt):
    """Keep each real finite protocol and bind one PID across all helpers."""
    class BoundProtocol(base):
        def accept(self,raw):
            value=super().accept(raw)
            pid=value['pid']
            if process['pid'] is not None and process['pid']!=pid:
                self.unknown()
                raise ValueError('Native process identity changed across helpers: STOP_UNKNOWN')
            process['pid']=pid;receipt['native_process_id']=pid
            return value
    return BoundProtocol(plan)


def _execute(capture_path,selection,native_project,output,*,compiler=None,
                  survey=host_metadata.survey,runner=None,lock=camera_lock,
                  session_factory=None,actions_factory=NativeActions,_recovery=None,program_jobs=(),sound_job=None,_gate_wbi_factory=OriginalWBI):
    """Install the fixed restricted plan, then verify every complete endpoint.

    No automatic retry/inverse occurs after any upload or settings mutation.
    Reboot, native setting adoption and photographic checks remain user tests.
    """
    import subprocess
    runner=runner or subprocess.run;compiler=compiler or shutil.which('zig')
    capture,original_settings=complete_capture(capture_path)
    root=create_job_output(output);receipt=root/'job.private.json'
    result=dict(schema='a7m4-toolbox-device-job/1',feature='looks-install',status='PREPARING_LOCAL',
        camera_io=False,network_io=False,simulation=False,complete=False,verified=False,
        full_readback_verified=False,stop_safe=False,normal_return_verified=False,
        service_exit_confirmed=False,native_sequence_complete=False,camera_applied=False,
        receipt=str(receipt),body_binding=capture['body_binding'],backup_archive_sha256=capture['archive_sha256'],
        automatic_retry=False,automatic_inverse=False,activation_requires_user_power_cycle=True,
        physical_camera_acceptance='NOT_PERFORMED',settings_metadata_profile_validation='NEW_SOFTWARE_CANDIDATE_PHYSICAL_NOT_PERFORMED')
    _atomic_json(receipt,result)
    if _recovery is not None:
        result['feature']=_recovery['feature']
        result.update(_recovery['receipt_fields'])
        # Planned completion claims must remain false until normal return.
        for key in ('restore_complete','resources_restored','functional_restore_complete',
                    'full_file_restore_complete','post_boot_full_file_verification_complete'):
            if key in result:result[key]=False
    session=channel=actions=settings_channel=None;history=[];mutated=False;released=None
    native_absence_verified=False
    adoption_pending=False;gate_wbi=None
    fresh_gate_scope=bool(_recovery is not None and _recovery.get('fresh_gate_scope'))
    restoring_gate_C=bool(_recovery is not None and _recovery.get('restore_gate_C'))
    capsule=None
    try:
        selected=_recovery is None and any(r.get('selected') for r in selection.get('slots',[]))
        frozen=freeze_native_project(native_project,root/'native-project') if selected else None
        planned=looks_selection(capture_path,selection,frozen,root/'looks',program_jobs=program_jobs,sound_job=sound_job) if _recovery is None else _recovery['selection']
        _validate_full_plan(capture,planned,inverse=bool(_recovery is not None and _recovery.get('program_inverse')))
        if fresh_gate_scope:
            capsule=gate_cumulative.Capsule(root,capture['body_binding'],parent=_recovery.get('C_parent'),
                result=result,restoring=restoring_gate_C)
        result['complete_plan_source_scope_verified']=True
        selected_bytes=_json(planned)
        _write(root/('initial-local-plan.json' if fresh_gate_scope else 'selection.json'),selected_bytes)
        if not fresh_gate_scope and len(selected_bytes)>256*1024:result['selection_ref']=selection_reference(selected_bytes)
        else:result['selection']=planned
        stages=planned['program_stages'];result['program_stages']=stages
        components=planned['components']
        changed_resources=[(name,c) for name,c in components.items()
            if c['source']['kind']=='resource' and c['source']['sha256']!=c['target']['sha256']]
        resource_sources={name:read_private(Path(capture['snapshot_dir'])/name,16*1024*1024) for name,c in changed_resources}
        allocation=[resource_forward.allocation_evidence(c,resource_sources[name]) for name,c in changed_resources]
        resources={name:resource_forward.from_component(c,resource_sources[name],pending=allocation[j:])
            for j,(name,c) in enumerate(changed_resources)}
        settings_requested=selection['include_fl2'] or selection['include_fl3']
        persistent_scope=bool(resources or stages or settings_requested
            or (_recovery is not None and _recovery['settings_factories']))
        result['resource_plans']={}
        if resources:
            plan_folder=root/'resource-plans';plan_folder.mkdir(mode=0o700)
            for i,(name,plan) in enumerate(resources.items()):
                raw=_json(plan);relative='resource-plans/%03d.json'%i;_write(root/relative,raw)
                result['resource_plans'][name]=dict(plan_id=plan['plan_id'],target_path=plan['target_path'],
                    source=plan['source'],target=plan['target'],replacement=plan['replacement'],
                    plan_ref=dict(path=relative,size=len(raw),sha256=sha256(raw).hexdigest()))
        with tempfile.TemporaryDirectory(prefix='a7m4-looks-build-') as temporary:
            build_root=Path(temporary).resolve();programs=[];resource_builds={}
            for j,plan in enumerate([] if fresh_gate_scope else stages):
                built=program_worker.build_program_worker(plan,build_root/('program-%d'%j),compiler=compiler)
                if built.get('worker_built') is not True:raise ValueError('Offline program helper build unavailable')
                programs.append((plan,Path(built['worker']['path']).read_bytes()))
            for j,(name,plan) in enumerate(resources.items()):
                built=resource_forward.build_resource_worker(plan,build_root/('resource-%d'%j),compiler=compiler)
                resource_builds[name]=Path(built['worker']['path']).read_bytes()
            if verified_capture(capture_path)!=capture:raise ValueError('Complete backup changed while helpers were built')
            with lock():
                released=release_host_volumes(root,survey=survey,runner=runner);result['host_release']=released
                reads={r['target_path']:(gate_scope.BOUNDS[r['kind']] if fresh_gate_scope else
                    max(r['size'],components[name]['target']['size'])) for name,r in capture['objects'].items()}
                reads.update({'/version.txt':4096,'/usr/lib/libJiritsu.so':160*1024*1024,
                    '/usr/share/avsystemsound/custom.txt':65535,'/tmp/jbusy':64})
                owned={LIBRARY:65535,workspace.REQUEST_PATH:64,workspace.REPORT_PATH:workspace.REPORT.size,
                    program_worker.REQUEST_PATH:program_worker.REQUEST.size,program_worker.RESULT_PATH:program_worker.REPORT.size,
                    resource_worker.REQUEST_PATH:resource_worker.REQUEST.size,resource_worker.RESULT_PATH:resource_worker.REPORT.size,
                    resource_forward.REQUEST_PATH:resource_forward.REQUEST.size,resource_forward.RESULT_PATH:resource_forward.REPORT_BYTES}
                if fresh_gate_scope:
                    for wire in wbi_sources()[:2]:
                        owned.update({wire.REQUEST:wire.REQUEST_BYTES,wire.RESULT:wbi_report_bound(wire),wire.PENDING:wbi_report_bound(wire)})
                native=channel_class(reads,owned)
                session=(session_factory(native,released) if session_factory else ServiceSession(
                    channel_factory=native,expected_usb_serial=released['camera']['usb_serial']))
                with session as channel,ExitStack() as finalizer:
                    def preflight_exit():
                        safe=all(getattr(a,'safe_read_only_abort',False) for a in history)
                        if native_absence_verified and not mutated and safe and channel.healthy:channel.allow_clean_stop()
                    finalizer.callback(preflight_exit)
                    result['camera_io']=getattr(session,'camera_io',True);result['simulation']=result['camera_io'] is False
                    # This also covers settings-only and true-NOOP jobs, which
                    # never instantiate NativeActions. A stale native object
                    # cannot imply exclusive ownership or authorize STOP.
                    for path in (*owned,'/tmp/jbusy'):
                        if channel.peek(path) is not None:
                            channel.healthy=False;channel.safe_to_stop=False
                            result['foreign_native_state']=path
                            raise ValueError('Unowned or stale native state; preserve and stop: '+path)
                    native_absence_verified=True
                    native_process={'pid':None,'boot_id':None}
                    identity_actions=actions_factory(channel,root/'identity-native');history.append(identity_actions)
                    def identity():
                        if sha256(channel.file('/version.txt')).hexdigest()!=VERSION_SHA256 or sha256(channel.file('/usr/lib/libJiritsu.so')).hexdigest()!=LOADER_SHA256:
                            raise ValueError('Fresh complete firmware/loader baseline differs')
                        channel.settings(False)
                        if body_binding(channel.serial())!=capture['body_binding']:raise ValueError('Current body differs from complete backup')
                        measured=identity_actions.probe()
                        if type(measured) is not dict:
                            channel.healthy=False;channel.safe_to_stop=False
                            raise ValueError('Missing complete native identity measurement: STOP_UNKNOWN')
                        pid=measured.get('process_id');boot=measured.get('boot_id')
                        unit=measured.get('allocation_unit');available=measured.get('available_bytes')
                        try:
                            valid=(type(pid) is int and pid>0 and type(boot) is str
                                and str(uuid.UUID(boot))==boot and uuid.UUID(boot).int!=0
                                and type(unit) is int and 0<unit<=1048576
                                and type(available) is int and 0<=available<=2**63-1
                                and measured.get('fresh_measurement') is True
                                and measured.get('bootstrap_probe_only') is True)
                        except (ValueError,TypeError,AttributeError):valid=False
                        if (not valid or native_process['pid'] not in (None,pid)
                                or native_process['boot_id'] not in (None,boot)):
                            channel.healthy=False;channel.safe_to_stop=False
                            raise ValueError('Native process/kernel boot identity changed or invalid: STOP_UNKNOWN')
                        native_process.update(pid=pid,boot_id=boot)
                        result['native_process_id']=pid;result['boot_id']=boot
                        result.setdefault('initial_native_identity',measured)
                        if persistent_scope:
                            minimum=workspace.RESERVE+unit
                            result['persistent_workspace_preflight']=dict(available_bytes=available,
                                allocation_unit=unit,minimum_required_bytes=minimum,
                                fresh_measurement=True,verified=available>=minimum)
                            if available<minimum:
                                raise ValueError('Fresh workspace reserve must retain 8 MiB plus one allocation unit before persistent operations')
                    identity()
                    if channel.peek('/usr/share/avsystemsound/custom.txt') is not None:raise ValueError('Legacy CSV route present; no combined install is admitted')
                    boot_id=native_process['boot_id']
                    if _recovery is not None and _recovery.get('different_boot_from')==boot_id:
                        raise ValueError('Resource restoration requires a normal power cycle after program restoration; no resource was changed')
                    # Job's identity bind now precedes every complete guard,
                    # rather than performing another native probe after it.
                    wire=Journal(root/'settings-wire');settings_channel=SettingsChannel(channel,intent=wire,reply=wire)
                    fresh=settings_channel.capture()
                    settings_archive.save_snapshot(fresh,root/'settings-before')
                    if fresh_gate_scope or _recovery is not None and _recovery.get('feature')=='electronic-sound-gate':
                        operation_scope=sound_operation(fresh,restore_ap55=fresh_gate_scope and _recovery.get('feature')=='restore-sound-gate')
                    else:
                        operation_scope='looks' if settings_requested or _recovery is not None else sound_operation(fresh)
                    def scope_freshness(before,after):
                        return (gate_cumulative.settings_freshness(before,after,planned['C_originals']) if restoring_gate_C else
                            settings_scope_freshness_report(before,after,operation=operation_scope,
                                native_context=dict(process_id=native_process['pid'],boot_id=boot_id)))
                    freshness=scope_freshness(original_settings,fresh)
                    _write(root/'settings-freshness.json',_json(freshness))
                    result['settings_freshness']=freshness
                    if not freshness['stable']:raise ValueError('Protected settings changed since backup: '+ '; '.join(freshness['errors'][:3]))
                    settings_reference=SimpleNamespace(baseline=fresh,identity=capture['body_binding']['serial_sha256'],
                        groups=(),metadata_profile='strict-nonrecord-unchanged/1')
                    settings_expected=settings_maps(fresh);settings_previous=fresh;settings_after_save=False;settings_ui_saved=False
                    settings_rebind_done=False
                    def pre_settings_native_catchup(current):
                        nonlocal settings_reference,settings_expected,settings_previous,settings_rebind_done
                        if settings_rebind_done:return
                        if fresh_gate_scope:
                            check_forward_C_D(settings_reference,current,settings_expected)
                            changes=observe_forward_F(current,settings_expected)
                            _write(root/'forward-settings-before-write-observations.json',_json(changes))
                            settings_rebind_done=True
                            return
                        # This function is invoked only before the first settings
                        # factory or, with no factories, at the final read guard.
                        # A native program/resource change is not a settings SAVE.
                        report=settings_scope_freshness_report(settings_previous,current,operation=operation_scope)
                        report.update(authorizes_device_write=False,settings_writes_before=0,
                            policy_scope='same-capture-before-first-settings-mutation')
                        settings_archive.save_snapshot(current,root/'settings-after-native-before-first-mutation')
                        _write(root/'settings-native-catchup.json',_json(report))
                        if not report['stable']:
                            raise ValueError('Unreviewed pre-settings native catchup: '+ '; '.join(report['errors'][:3]))
                        settings_reference=SimpleNamespace(baseline=current,identity=capture['body_binding']['serial_sha256'],
                            groups=(),metadata_profile='strict-nonrecord-unchanged/1')
                        settings_expected=settings_maps(current);settings_previous=current;settings_rebind_done=True
                        result['pre_settings_native_catchup']=report
                    # Prove every source before the first persistent operation.
                    pre=root/'pre';pre.mkdir(mode=0o700)
                    def observe_file(row):
                        raw=(channel.file(row['target_path']) if row['kind'] in ('ap','cp') else channel.peek(row['target_path']))
                        return (b'', 'unavailable') if raw is None else (raw,'present')
                    fresh_files={};fresh_bytes=0
                    for name,row in capture['objects'].items():
                        if fresh_gate_scope:raw,observed_state=observe_file(row)
                        else:raw=channel.file(row['target_path'])
                        if fresh_gate_scope:
                            fresh_bytes+=len(raw)
                            if not 0<=len(raw)<=gate_scope.BOUNDS[row['kind']] or fresh_bytes>gate_scope.MAX_BASELINE:
                                raise ValueError('Current Gate preimage exceeds bounded local/protocol capacity')
                            target=pre/name;target.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
                            _write(target,raw)
                            fresh_files[name]=dict(size=len(raw),sha256=sha256(raw).hexdigest(),observed_state=observed_state)
                        elif len(raw)!=row['size'] or sha256(raw).hexdigest()!=row['sha256']:
                            raise ValueError('Fresh complete source differs: '+name)
                    if fresh_gate_scope:
                        planned=gate_scope.rebind(planned,capture,pre,fresh_files,boot_id=boot_id)
                        components=planned['components'];stages=planned['program_stages']
                        result['selection']=planned;result['program_stages']=stages
                        selected_bytes=_json(planned);_write(root/'initial-fresh-plan.json',selected_bytes)
                        if len(selected_bytes)>256*1024:
                            result.pop('selection',None);result['selection_ref']=selection_reference(selected_bytes)
                        _write(root/'current-source-CDEF.json',_json(planned['current_source']))
                        def gate_runtime():
                            identity()
                            return dict(process_id=native_process['pid'],boot_id=native_process['boot_id'],fresh=True)
                        for j,program_plan in enumerate(stages):
                            built=program_worker.build_program_worker(program_plan,build_root/('fresh-program-%d'%j),compiler=compiler)
                            if built.get('worker_built') is not True:raise ValueError('Fresh-source Gate helper build unavailable')
                            programs.append((program_plan,Path(built['worker']['path']).read_bytes()))
                        preview=_recovery['settings_factories'][0][1](fresh,identity=capture['body_binding']['serial_sha256'],
                            boot_id=boot_id,nonce=os.urandom(16).hex()) if _recovery['settings_factories'] else None
                        if preview is not None:
                            settings_reference=preview
                            result['AP55_preflight']=plan_manifest(preview)
                        if stages or preview is not None and (any(r.before_ram!=r.after_ram or r.before_saved!=r.after_saved for r in preview.records)
                                or any(needs_save(preview,g) for g in preview.groups)):
                            gate_wbi=_gate_wbi_factory(channel,root/'startup-adoption',compiler=compiler,
                                runtime_evidence=gate_runtime,actions_factory=actions_factory)
                    def bind_latest_gate_source(source_paths=None,endpoint=None,ticket=None):
                        nonlocal planned,components,stages,settings_reference,settings_expected,settings_previous
                        latest=root/'pre-before-first-C';latest.mkdir(mode=0o700)
                        source_paths=source_paths or {}
                        latest_files={};count=0
                        for name,row in capture['objects'].items():
                            role={'appFw.so':'ap','CPAPP-B.BIN':'cp'}.get(name)
                            if role in source_paths:
                                path=Path(source_paths[role]);raw=read_private(path,gate_scope.BOUNDS[row['kind']])
                            else:
                                raw,observed_state=observe_file(row);path=latest/name
                                path.parent.mkdir(mode=0o700,parents=True,exist_ok=True);_write(path,raw)
                            count+=len(raw)
                            if not 0<=len(raw)<=gate_scope.BOUNDS[row['kind']] or count>gate_scope.MAX_BASELINE:
                                raise ValueError('Latest Gate baseline exceeds bounded local/protocol capacity')
                            identity_now=dict(size=len(raw),sha256=sha256(raw).hexdigest())
                            latest_files[name]=dict(identity_now,path=str(path),observed_state='present' if role in source_paths else observed_state)
                            component=components[name]
                            component['source']=dict(path=str(path),kind=row['kind'],**identity_now)
                            component['target']=dict(identity_now)
                            component['append']=dict(offset=len(raw),size=0,after_hex='',sha256=sha256(b'').hexdigest())
                        if endpoint is not None:
                            planned['gate']['program']=endpoint;planned['program_stages']=[endpoint]
                            latest_ap=read_private(Path(source_paths['ap']),gate_scope.BOUNDS['ap'])
                            latest_cp=read_private(Path(source_paths['cp']),gate_scope.CP_SIZE)
                            planned['gate']['source_admission']['dependencies']=gate_scope.dependencies(latest_ap,latest_cp)
                            planned['native_program_tickets']=[ticket]
                            for role,name in (('ap','appFw.so'),('cp','CPAPP-B.BIN')):
                                components[name]['target']=endpoint['components'][role]['target']
                            planned['program_stage_binding']=dict(native_ticket_id=ticket['plan_id'],
                                semantic_endpoint_id=endpoint['plan_id'],C_windows_equal=True,
                                native_ack_uses_original_ticket_only=True,initial_F_admission=False)
                        else:
                            ap=read_private(Path(latest_files['appFw.so']['path']),gate_scope.BOUNDS['ap'])
                            cp=read_private(Path(latest_files['CPAPP-B.BIN']['path']),gate_scope.CP_SIZE)
                            gate_scope.dependencies(ap,cp)
                            if not restoring_gate_C and gate_scope.state(cp)!=planned['gate']['gate']['current_state']:
                                raise ValueError('Gate C changed before first setting write')
                            if restoring_gate_C:gate_scope.check_target(planned,cp)
                        current=settings_channel.capture()
                        report=scope_freshness(original_settings,current)
                        if not report['stable']:raise ValueError('Gate C or necessary settings D changed before first write')
                        preview=_recovery['settings_factories'][0][1](current,identity=capture['body_binding']['serial_sha256'],
                            boot_id=boot_id,nonce=os.urandom(16).hex()) if _recovery['settings_factories'] else None
                        if preview is not None:settings_reference=preview
                        else:settings_reference=SimpleNamespace(baseline=current,identity=capture['body_binding']['serial_sha256'],
                            groups=(),metadata_profile='strict-nonrecord-unchanged/1')
                        settings_expected=settings_maps(current);settings_previous=current
                        settings_archive.save_snapshot(current,root/'settings-before-first-C')
                        planned['current_source']['latest_before_first_C']=dict(files=latest_files,
                            settings_raw_sha256={p:sha256(getattr(current,p).raw).hexdigest() for p in ('ram','saved','bin','bak')},
                            F_admission=False,atomic_snapshot=False)
                        stages=planned['program_stages'];result['program_stages']=stages
                        result['selection']=planned;result.pop('selection_ref',None)
                        encoded=_json(planned);_write(root/'selection.json',encoded)
                        if len(encoded)>256*1024:
                            result.pop('selection',None);result['selection_ref']=selection_reference(encoded)
                        _write(root/'before-first-C-baseline.json',_json(planned['current_source']['latest_before_first_C']))
                        if endpoint is not None:gate_scope.verify_ticket_binding(planned,root)
                    if _recovery is None:
                        # Feasibility precedes every persistent resource,
                        # program or setting operation. Never discover a fixed
                        # settings guard failure only after writing programs.
                        preview=plan_ap55(fresh,identity=capture['body_binding']['serial_sha256'],
                            boot_id=boot_id,nonce=os.urandom(16).hex())
                        result['AP55_preflight']=plan_manifest(preview)
                        if settings_requested:
                            result['FL23_preflight']=validate_fixed_prerequisites(fresh)
                    result['status']='FRESH_COMPLETE_SOURCE_VERIFIED';_atomic_json(receipt,result)
                    # Inspect every fixed resource and preserve its complete
                    # source before any persistent resource/program/settings
                    # write. Each apply still revalidates stat/maps/runtime and
                    # the entire remaining allocation proof in native code.
                    resource_transactions=[]
                    for j,(name,plan) in enumerate(resources.items()):
                        protocol=_native_protocol(resource_forward.ResourceProtocol,plan,native_process,result)
                        folder=root/('resource-%03d'%j);folder.mkdir(mode=0o700)
                        actions=actions_factory(channel,folder/'native');history.append(actions)
                        request=protocol.request(0,os.urandom(16))
                        actions.phase(resource_builds[name],resource_forward.REQUEST_PATH,request,
                            resource_forward.RESULT_PATH,protocol.accept,report_bytes=resource_forward.REPORT_BYTES)
                        path=folder/'source.bin';_write(path,channel.file(plan['target_path']));protocol.confirm_readback(path)
                        resource_transactions.append((name,plan,protocol,folder,actions))
                    result['all_resource_inspections_complete']=True
                    _atomic_json(receipt,result)
                    for name,plan,protocol,folder,actions in resource_transactions:
                        for mode in (1,3):
                            request=protocol.request(mode,os.urandom(16))
                            if mode==1:mutated=True
                            actions.phase(resource_builds[name],resource_forward.REQUEST_PATH,request,
                                resource_forward.RESULT_PATH,protocol.accept,report_bytes=resource_forward.REPORT_BYTES)
                            if mode==3:
                                path=folder/'target.bin';_write(path,channel.file(plan['target_path']));protocol.confirm_readback(path)
                        actions.clean_packets()
                    for j,(plan,binary) in enumerate(programs):
                        protocol=_native_protocol((gate_cumulative.RestoreProtocol if restoring_gate_C else gate_scope.GateProtocol)
                            if fresh_gate_scope else program_worker.ProgramProtocol,plan,native_process,result)
                        folder=root/('program-%d'%j);folder.mkdir(mode=0o700)
                        if fresh_gate_scope:_write(folder/'native-ticket-plan.json',_json(plan))
                        actions=actions_factory(channel,folder/'native');history.append(actions)
                        inverse=bool(_recovery is not None and _recovery.get('program_inverse'))
                        for mode in ((3,2,0) if inverse else (0,1,3)):
                            request=protocol.request(mode,os.urandom(16))
                            if mode in (1,2):mutated=True
                            def record_C_dispatch():
                                capsule.program_dispatch(plan,request)
                                _atomic_json(receipt,result)
                            actions.phase(binary,program_worker.REQUEST_PATH,request,program_worker.RESULT_PATH,
                                protocol.accept,report_bytes=program_worker.REPORT.size,
                                **({'before_dispatch':record_C_dispatch} if fresh_gate_scope and mode==1 else {}))
                            if mode in (0,3):
                                paths={}
                                for role,remote in program_worker.PATHS.items():
                                    path=folder/('%d-%s.bin'%(mode,role));_write(path,channel.file(remote));paths[role]=path
                                protocol.confirm_readback(paths)
                                if fresh_gate_scope and mode==3:
                                    capsule.confirmed('cp');_atomic_json(receipt,result)
                                if fresh_gate_scope and mode==0:
                                    bind_latest_gate_source(paths,protocol.endpoint_plan,plan)
                        actions.clean_packets()
                    if fresh_gate_scope and not programs:bind_latest_gate_source()
                    settings_results=[]
                    factories=((([('ap55',plan_ap55)] if resources or stages or settings_requested else [])
                                +([('fl23',plan_fixed_settings)] if settings_requested else []))
                               if _recovery is None else _recovery['settings_factories'])
                    for kind,factory in factories:
                        current=settings_channel.capture();nonce=os.urandom(16).hex()
                        if not settings_results:pre_settings_native_catchup(current)
                        if fresh_gate_scope:
                            check_forward_C_D(settings_reference,current,settings_expected)
                            observe_forward_F(current,settings_expected)
                        else:
                            check_settings_full(settings_reference,current,settings_expected,
                                after_save=settings_after_save,previous=settings_previous,native_ui_saved=settings_ui_saved)
                        plan=factory(current,identity=capture['body_binding']['serial_sha256'],boot_id=boot_id,nonce=nonce)
                        # A restore can rebind registered C after the initial
                        # preview. Prepare adoption before this newly necessary
                        # WRITE/SAVE, without rebuilding an existing helper.
                        if fresh_gate_scope and gate_wbi is None and (
                                any(r.before_ram!=r.after_ram for r in plan.records)
                                or any(needs_save(plan,g) for g in plan.groups)):
                            gate_wbi=_gate_wbi_factory(channel,root/'startup-adoption',compiler=compiler,
                                runtime_evidence=gate_runtime,actions_factory=actions_factory)
                        settings_archive.save_snapshot(current,root/(kind+'-settings-before'))
                        _write(root/(kind+'-settings-plan.json'),_json(plan_manifest(plan)))
                        def binding(p):
                            identity()
                            return dict(identity=p.identity,boot_id=p.boot_id,nonce=p.nonce,model='ILCE-7M4',firmware='6.02',exclusive_owner=True)
                        journal=Journal(root/(kind+'-settings-journal'))
                        job=SettingsJob(settings_channel,bind=binding,journal=journal,
                            forward_observation_only=fresh_gate_scope)
                        if fresh_gate_scope:
                            def settings_C_dispatch(observation):
                                capsule.settings_dispatch(plan,observation)
                                _atomic_json(receipt,result)
                            settings_channel.before_mutation_dispatch=settings_C_dispatch
                        proof=dict(schema='a7m4-toolbox-settings-release/1',plan_id=plan.plan_id,identity=plan.identity,
                            boot_id=plan.boot_id,nonce=plan.nonce,backup_verified=True,program_dependencies_verified=True,
                            user_risk_confirmation_fresh=True,release_gate='RELEASED')
                        job.release(plan,proof)
                        try:
                            settings_results.append(job.execute(plan))
                            if fresh_gate_scope:
                                capsule.confirmed('ap55');_atomic_json(receipt,result)
                        finally:mutated|=bool(getattr(job,'mutation_attempted',False))
                        settings_reference=plan;settings_expected=settings_maps(job.verified_snapshot)
                        settings_previous=job.verified_snapshot;settings_after_save=job.saves>0
                        settings_ui_saved|=0x02CF in job.saved_groups
                        after=settings_channel.capture()
                        if fresh_gate_scope:
                            check_forward_C_D(settings_reference,after,settings_expected)
                            observe_forward_F(after,settings_expected)
                        else:
                            check_settings_full(settings_reference,after,settings_expected,
                                after_save=settings_after_save,previous=settings_previous,native_ui_saved=settings_ui_saved)
                        settings_previous=after
                        settings_archive.save_snapshot(after,root/(kind+'-settings-after'))
                    result['settings_results']=settings_results
                    post=root/'post';post.mkdir(mode=0o700);verified_objects=[];files={}
                    roles={'appFw.so':('ap','ap.bin'),'CPAPP-B.BIN':('cp_program','cp_program.bin'),'extras/SysSound.bin':('bank','bank.bin')}
                    for name,component in components.items():
                        if fresh_gate_scope:raw,observed_state=observe_file(capture['objects'][name])
                        else:raw=channel.file(component['target_path']);observed_state='present'
                        expected=component['target']
                        actual=dict(size=len(raw),sha256=sha256(raw).hexdigest())
                        if not fresh_gate_scope and actual!=expected:raise ValueError('Final complete endpoint differs: '+name)
                        if fresh_gate_scope:
                            result.setdefault('forward_file_observations',[]).append(dict(name=name,expected=expected,actual=actual,
                                F_differs=actual!=expected,observed_state=observed_state,gate_execution=False))
                        relative='post/'+(roles[name][1] if name in roles else name)
                        path=root/relative;path.parent.mkdir(mode=0o700,parents=True,exist_ok=True);_write(path,raw)
                        verified_objects.append(dict(path=relative,**(actual if fresh_gate_scope else expected)))
                        if name in roles:files[roles[name][0]]=actual if fresh_gate_scope else expected
                    identity()
                    # All 11 complete object reads and the final identity check
                    # precede this last settings guard. Never absorb an
                    # unplanned value into a new factory/capture baseline.
                    final_settings=settings_channel.capture()
                    if not factories:pre_settings_native_catchup(final_settings)
                    if fresh_gate_scope:
                        check_forward_C_D(settings_reference,final_settings,settings_expected)
                        final_F=observe_forward_F(final_settings,settings_expected)
                        _write(root/'forward-settings-final-observations.json',_json(final_F))
                    else:
                        check_settings_full(settings_reference,final_settings,settings_expected,
                            after_save=settings_after_save,previous=settings_previous,native_ui_saved=settings_ui_saved)
                    settings_archive.save_snapshot(final_settings,root/'settings-after')
                    result['verified_objects']=verified_objects
                    if fresh_gate_scope:
                        final_ap=read_private(post/'ap.bin',gate_scope.BOUNDS['ap'])
                        final_cp=read_private(post/'cp_program.bin',gate_scope.CP_SIZE)
                        gate_scope.dependencies(final_ap,final_cp)
                        gate_scope.check_target(planned,final_cp)
                        normalization=gate_scope.observed_normalization(planned,final_ap,final_cp)
                        observations=dict(schema='gate-forward-observations/1',acceptance_scope='C-and-explicit-D-only',
                            E_F_gate_execution=False,files=result.get('forward_file_observations',[]),
                            observed_program_endpoints={'ap':files['ap'],'cp_program':files['cp_program']},
                            source_normalization_stages=normalization,normalization_is_native_execution_claim=False)
                        observed_raw=_json(observations);_write(root/'gate-forward-observations.json',observed_raw)
                        result['gate_observations_ref']=dict(path='gate-forward-observations.json',size=len(observed_raw),sha256=sha256(observed_raw).hexdigest())
                        result['readback']=dict(validation_scope='C-D-only-E-F-observations/1',scoped_objects_read=True,object_count=len(verified_objects),
                            C_D_verified=True,E_F_observed=True,F_gate_execution=False,files=files,
                            semantic_whole_target_verified=False,settings_C_D_verified=True)
                    else:
                        result['readback']=dict(scoped_objects_verified=True,files=files,
                            settings_full_verified=True,settings_untouched_verified=not any(r['mutation_attempted'] for r in settings_results))
                    if fresh_gate_scope:
                        if mutated:
                            result['startup_adoption_prerequisites']=dict(full_programs_read=True,C_D_verified=True,
                                F_comparison_gate=False)
                            adoption=gate_wbi.adopt(program_fullpost_verified=True,approval_verified=True,no_ssh_started=True)
                            result['startup_adoption']=adoption
                            _write(root/'startup-adoption-result.json',_json(adoption))
                            if adoption.get('success') is not True:
                                if adoption.get('known_clean_refusal') is True:adoption_pending=True
                                else:raise ValueError('Gate startup adoption outcome not confirmed; no replay')
                            result['supporting_C_writes']=(dict(kind='VENDOR_DROP_AND_MODE0',
                                native_logical_WBI_header_bytes=512,header_preimage_report_sha256=adoption.get('prepare_report_sha256'),
                                header_preimage_section=9,header_target='vendor invalidation of logical first512',
                                vendor_drop_command='1',mode_target='0',mode_preimage_report_sha256=adoption.get('prepare_report_sha256'),
                                mode_preimage_section=3,NOR_or_trust_write=False)
                                if adoption.get('kind')=='VENDOR_DROP_AND_MODE0' else dict(kind=adoption.get('kind'),writes=0))
                        else:
                            result['startup_adoption']=dict(kind='NOT_PERFORMED_NO_CHANGE',performed=False,
                                running_target_proven=False,physical_persistence_verified=False)
                    channel.allow_clean_stop()
                    result.update(status='VERIFIED_AWAITING_SERVICE_EXIT',full_readback_verified=True,stop_safe=True,native_sequence_complete=not adoption_pending)
                    _atomic_json(receipt,result)
                if not getattr(session,'stop_succeeded',False) or not getattr(session,'resources_disposed',False):raise RuntimeError('Service exit not fully confirmed')
                result['normal_return']=verify_normal_return(released,survey=survey,runner=runner)
                if _recovery is not None and not result['simulation'] and not adoption_pending:
                    result.update(_recovery['receipt_fields'])
                if restoring_gate_C:
                    result['Gate_C_total_restored']=not adoption_pending
                    result['restore_scope']='Gate-only-explicit-history'
                    result['E_F_restored']=False
                result.update(status=('SIMULATED_' if result['simulation'] else '')+('VERIFIED_DISK_TARGETS_ADOPTION_PENDING' if adoption_pending
                    else 'VERIFIED_APPLIED' if mutated else 'VERIFIED_NO_CHANGE'),
                    complete=not adoption_pending,verified=not adoption_pending,normal_return_verified=True,service_exit_confirmed=True,
                    camera_applied=mutated and result['camera_io'] is True)
                if adoption_pending:result['error']='磁盘与设置目标已完整读回，启动采用未完成；已安全退出，请重新备份当前状态并查看报告，不自动重试。' 
                _atomic_json(receipt,result);return result
    except BaseException as error:
        if session is not None:result['camera_io']=getattr(session,'camera_io',True)
        clean=False
        safe=native_absence_verified and not mutated and all(getattr(a,'safe_read_only_abort',False) for a in history)
        if session is not None and safe and getattr(session,'stop_succeeded',False) and getattr(session,'resources_disposed',False):
            try:result['normal_return']=verify_normal_return(released,survey=survey,runner=runner);clean=True
            except (ValueError,RuntimeError,OSError):pass
        result.update(status='STOPPED_PREFLIGHT_NORMAL_RETURN' if clean else 'STOP_UNKNOWN' if result['camera_io'] else 'STOPPED_LOCAL',
            complete=False,verified=False,camera_applied=None if mutated else False,error=str(error),
            error_type=type(error).__name__,stop_safe=clean,normal_return_verified=clean,persistent_write_phase_attempted=mutated)
        _atomic_json(receipt,result)
        if isinstance(error,(KeyboardInterrupt,SystemExit)):raise
        raise DeviceJobError(str(error),result) from error


def execute_looks(capture_path,selection,native_project,output,**kwargs):
    return _execute(capture_path,selection,native_project,output,**kwargs)


def gate_selection(capture_path,state,*,program_jobs=(),sound_job=None):
    """Local C/D-only Gate plan; historical F is backup evidence, not admission."""
    from .policy import sound_state
    capture,settings=complete_capture(capture_path)
    state=sound_state(state)
    planned=gate_scope.local_selection(capture_path,capture,state,program_jobs=program_jobs,sound_job=sound_job)
    if planned['program_stages'] or state=='enabled':
        plan_ap55(settings,identity=capture['body_binding']['serial_sha256'],boot_id=str(uuid.uuid4()),
            nonce=os.urandom(16).hex(),save_effects_policy=save_effects.NATIVE51)
    return planned


def execute_gate(capture_path,state,output,*,program_jobs=(),sound_job=None,C_capsule=None,**kwargs):
    planned=gate_selection(capture_path,state,program_jobs=program_jobs,sound_job=sound_job)
    parent=(gate_cumulative.load(C_capsule,planned['body_binding']) if C_capsule is not None else
        gate_cumulative.parent_from_jobs(program_jobs,planned['body_binding']))
    recovery=dict(feature='electronic-sound-gate',selection=planned,receipt_fields={},program_inverse=False,
        fresh_gate_scope=planned.get('source_basis')==gate_scope.POLICY,C_parent=parent,
        settings_factories=[('ap55',lambda fresh,**binding:plan_ap55(fresh,**binding,save_effects_policy=save_effects.NATIVE51))]
            if planned['program_stages'] or state=='enabled' else [])
    return _execute(capture_path,planned['selection'],None,output,_recovery=recovery,**kwargs)


def gate_C_restore_selection(capture_path,capsule_path):
    """Local Gate-only cumulative plan; not legacy original/inverse planning."""
    capture,settings=complete_capture(capture_path)
    capsule=gate_cumulative.load(capsule_path,capture['body_binding'])
    planned=gate_cumulative.local_selection(capture_path,capture,capsule)
    if 'ap55' in capsule['originals']:
        gate_cumulative.settings_plan(settings,capsule['originals'],identity=capture['body_binding']['serial_sha256'],
            boot_id=str(uuid.uuid4()),nonce=os.urandom(16).hex())
    return planned,capsule


def execute_gate_C_restore(capture_path,capsule_path,output,**kwargs):
    planned,capsule=gate_C_restore_selection(capture_path,capsule_path)
    factories=([('ap55',lambda fresh,**binding:gate_cumulative.settings_plan(fresh,capsule['originals'],**binding))]
        if 'ap55' in capsule['originals'] else [])
    recovery=dict(feature='gate-C-total-restore',selection=planned,receipt_fields={},program_inverse=False,
        fresh_gate_scope=True,restore_gate_C=True,C_parent=capsule,settings_factories=factories)
    return _execute(capture_path,planned['selection'],None,output,_recovery=recovery,**kwargs)
