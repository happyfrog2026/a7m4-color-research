"""Three finite feature jobs; one service owner and an explicit C checkpoint.

Imports and plan_forward are local-only. Execute entry points require the
outer CLI's fresh risk/backup approval. This module never grants that approval.
"""
from contextlib import ExitStack
from hashlib import sha256
from pathlib import Path
import shutil
import json
import subprocess
import tempfile
import uuid

from . import feature_cumulative as fc, feature_profiles as fp, feature_stages as fs
from . import looks_program as lp, looks_resource_scope as lr, looks_resource_restore as rr
from . import sound_scope as ss, program_worker, workspace, host_metadata, settings_archive
from . import original_ap_load as load_wire
from .capture_inputs import read_private, verified_device_capture as verified_capture
from .device_job import complete_capture, Journal, freeze_native_project
from .job_ownership import create_job_output
from .native_actions import NativeActions, _write
from .native_channel import channel_class, LIBRARY
from .original_wbi import OriginalWBI, load_sources as wbi_sources, report_bound
from .ownership import camera_lock, release_host_volumes, verify_normal_return
from .settings_channel import SettingsChannel
from .usb_read import ServiceSession, body_binding, VERSION_SHA256, LOADER_SHA256, _atomic_json

CUSTOM='/usr/share/avsystemsound/custom.txt'


class FeatureJobError(RuntimeError):
    def __init__(self,message,result):super().__init__(message);self.result=result


def plan_forward(capture_path,profile,*,native_project=None,prepared=None):
    config=fp.fixed_config(profile);capture,settings=complete_capture(capture_path)
    root=Path(capture['snapshot_dir'])
    images={r:read_private(root/n,ss.LIMITS[r]) for r,n in dict(ap='appFw.so',cp='CPAPP-B.BIN').items()}
    program=lp.plan(images['ap'],images['cp'],config=config)
    paths={row['target_path']:root/name for name,row in capture['objects'].items()}
    resources=lr.plan_resources({p:read_private(paths[p],16*1024*1024) for p in lr.PATHS} if config['m9'] else {},
        None,config,native_project)
    if config['sound']:
        ss.prepared(prepared)
        # Local forecast only. Physical Gate state must be freshly proved by
        # the runtime before the sound helper is even planned for dispatch.
        ss.dependencies(images['ap'],images['cp'])
    return dict(schema='a7m4-fixed-feature-selection/1',profile=profile,config=config,
        body_binding=capture['body_binding'],capture_receipt=str(Path(capture_path).absolute()),
        program=program,resource_files=len(resources['files']),resource_plan_id=resources['plan_id'],
        display=resources.get('display'),
        source_admission='fresh-C-D-only',E_F_gate_execution=False,cache_restore='NORMAL_REBUILD',
        camera_io=False,device_validation='not-performed',color_calibration='DEFERRED')


def execute_forward(capture_path,profile,output,*,native_project=None,prepared=None,**kwargs):
    selection=plan_forward(capture_path,profile,native_project=native_project,prepared=prepared)
    return _execute(capture_path,output,selection=selection,native_project=native_project,prepared=prepared,**kwargs)


def plan_restore(capture_path,capsule_path,*,previous_job=None):
    capture,_=complete_capture(capture_path);parent=fc.load(capsule_path,capture['body_binding'],fc.leaf_validators())
    selection=dict(schema='a7m4-fixed-feature-restore-selection/1',profile=parent['profile'],
        body_binding=capture['body_binding'],capsule_sha256=parent['capsule_sha256'],camera_io=False,
        E_F_restored=False,cache_restore='NORMAL_REBUILD',device_validation='not-performed')
    if previous_job is not None:
        previous=json.loads(read_private(Path(previous_job),fc.MAXIMUM));checkpoint=previous.get('checkpoint')
        ref=previous.get('C_capsule_ref',{})
        fc.need(previous.get('schema')=='a7m4-toolbox-device-job/1' and previous.get('body_binding')==capture['body_binding']
            and previous.get('profile')==parent['profile'] and previous.get('complete') is False
            and all(previous.get(k) is True for k in ('normal_return_verified','service_exit_confirmed','stop_safe'))
            and type(checkpoint) is dict and checkpoint.get('stage')=='RESOURCE_RESTORE_BOUNDARY_REQUIRED'
            and checkpoint.get('complete') is False and checkpoint.get('union_C_restored') is False,
            'Only a normal-MSC verified resource checkpoint may resume')
        raw=read_private(Path(capsule_path),fc.MAXIMUM)
        fc.need(ref.get('path')==fc.FILENAME and ref.get('size')==len(raw) and ref.get('sha256')==sha256(raw).hexdigest()
            and Path(capsule_path).absolute()==Path(previous_job).absolute().parent/fc.FILENAME,
            'Checkpoint does not bind this exact durable union capsule')
        boot=previous.get('boot_id');fc.need(type(boot) is str and str(uuid.UUID(boot))==boot,'Checkpoint fresh boot binding missing')
        selection.update(previous_job=str(Path(previous_job).absolute()),previous_boot_id=boot,
            requires_new_boot_evidence=checkpoint.get('requires_new_boot_evidence') is True)
    return selection


def execute_restore(capture_path,capsule_path,output,**kwargs):
    if kwargs.get('_stages_factory') is None:
        raise ValueError('Legacy feature restore writes retired; use backup_target_flow.execute from the original backup')
    selection=plan_restore(capture_path,capsule_path)
    parent=fc.load(capsule_path,selection['body_binding'],fc.leaf_validators())
    return _execute(capture_path,output,selection=selection,parent=parent,**kwargs)


def execute_resume(capture_path,capsule_path,checkpoint_path,output,**kwargs):
    if kwargs.get('_stages_factory') is None:
        raise ValueError('Legacy feature restore writes retired; use backup_target_flow.execute from the original backup')
    selection=plan_restore(capture_path,capsule_path,previous_job=checkpoint_path)
    parent=fc.load(capsule_path,selection['body_binding'],fc.leaf_validators())
    return _execute(capture_path,output,selection=selection,parent=parent,resume=True,**kwargs)


def native_inventory():
    """Exact wire maxima, independent of the helpers' allocation reserve.

    Both tail parsers require len(report) == 544 + preimage_bytes, with
    preimage_bytes <= 61440. Their 65536 allocation budget is not a wire size
    or an exception to NativeChannel's strictly smaller upload inventory.
    """
    owned={LIBRARY:65535,workspace.REQUEST_PATH:64,workspace.REPORT_PATH:workspace.REPORT.size,
        ss.REQUEST_PATH:ss.REQUEST.size,ss.REPORT_PATH:ss.REPORT.size,
        '/tmp/jiritsu/m4.sound-scope.source.bin':33328,'/tmp/jiritsu/m4.sound-scope.target.bin':33328,
        program_worker.REQUEST_PATH:program_worker.REQUEST.size,program_worker.RESULT_PATH:program_worker.REPORT.size,
        load_wire.REQUEST_PATH:load_wire.REQUEST.size,load_wire.RESULT_PATH:load_wire.REPORT.size,
        **lr.owned_paths(),**rr.owned_paths()}
    for worker in (rr.load_helper('tail-restore')[0],rr.original_tail):
        wire_max=worker.MIN_REPORT+worker.MAX_PREIMAGE_BYTES
        fc.need(0<wire_max<65536 and wire_max<=worker.MAX_REPORT,'Tail codec wire maximum exceeds finite inventory')
        owned[worker.RESULT_PATH]=wire_max
    for wire in wbi_sources()[:2]:owned.update({wire.REQUEST:wire.REQUEST_BYTES,wire.RESULT:report_bound(wire),wire.PENDING:report_bound(wire)})
    reads={ss.PATHS[r]:n for r,n in ss.LIMITS.items()};reads.update({p:16*1024*1024 for p in lr.PATHS})
    reads.update({'/version.txt':4096,'/usr/lib/libJiritsu.so':160*1024*1024,CUSTOM:65535,'/tmp/jbusy':64})
    return reads,owned


def _execute(capture_path,output,*,selection,parent=None,resume=False,native_project=None,prepared=None,compiler=None,
             survey=host_metadata.survey,runner=None,lock=camera_lock,session_factory=None,
             actions_factory=NativeActions,_wbi_factory=OriginalWBI,
             _stages_factory=None,_operation_feature=None):
    capture,_=complete_capture(capture_path);root=create_job_output(output);receipt=root/'job.private.json'
    compiler=compiler or shutil.which('zig');runner=runner or subprocess.run
    result=dict(schema='a7m4-toolbox-device-job/1',feature=_operation_feature or ('fixed-feature-C-restore' if parent else 'fixed-feature-install'),
        profile=selection['profile'],selection=selection,body_binding=capture['body_binding'],receipt=str(receipt),
        status='PREPARING_LOCAL',camera_io=False,simulation=False,complete=False,verified=False,
        E_F_restored=False,E_F_gate_execution=False,persistent_write_phase_attempted=False,
        normal_return_verified=False,service_exit_confirmed=False,stop_safe=False,union_C_restored=False)
    commit=lambda:_atomic_json(receipt,result)
    commit();session=channel=stages=None;released=None;history=[];owned_clean=False
    reads,owned=native_inventory()
    def safe_abort():
        actions=history+(stages.history if stages else [])
        return owned_clean and not (stages and stages.mutated) and all(a.safe_read_only_abort for a in actions)
    try:
        fc.need(verified_capture(capture_path)==capture,'Selected complete backup changed before entry')
        # All resource asset bytes are privately frozen before service entry.
        project=freeze_native_project(native_project,root/'icons') if native_project is not None else None
        if selection.get('display') is not None:
            fc.need(project is not None and lr.project_display(project)==selection['display'],
                '显示名称或图标清单在确认后改变；尚未进入相机操作，请重新准备。')
        with tempfile.TemporaryDirectory(prefix='a7m4-features-build-') as tmp,lock():
            released=release_host_volumes(root,survey=survey,runner=runner);result['host_release']=released
            native=channel_class(reads,owned)
            session=(session_factory(native,released) if session_factory else ServiceSession(channel_factory=native,
                expected_usb_serial=released['camera']['usb_serial']))
            with session as channel,ExitStack() as finalizer:
                def abort_stop():
                    if safe_abort() and channel.healthy:channel.allow_clean_stop()
                finalizer.callback(abort_stop)
                result['camera_io']=getattr(session,'camera_io',True);result['simulation']=result['camera_io'] is False
                for path in (*owned,'/tmp/jbusy',CUSTOM):fc.need(channel.peek(path) is None,'Foreign/stale exact job path: '+path)
                owned_clean=True
                identity_action=actions_factory(channel,root/'identity-native');history.append(identity_action);bound={}
                def identity():
                    fc.need(sha256(channel.file('/version.txt')).hexdigest()==VERSION_SHA256,'未匹配支持的6.02构建；已停止，不可通过用户确认绕过。')
                    fc.need(sha256(channel.file('/usr/lib/libJiritsu.so')).hexdigest()==LOADER_SHA256,'必要运行库构建不符；已停止。')
                    channel.settings(False);fc.need(body_binding(channel.serial())==capture['body_binding'],'Fresh body differs')
                    result['device_identity_observation']=dict(model='ILCE-7M4',firmware_version='6.02',verified=True,
                        source='fresh normal USB product + version and loader SHA + matching own-body serial')
                    m=identity_action.probe();pid=m.get('process_id');boot=m.get('boot_id');unit=m.get('allocation_unit');available=m.get('available_bytes')
                    fc.need(type(pid) is int and pid>0 and type(boot) is str and str(uuid.UUID(boot))==boot and uuid.UUID(boot).int!=0
                        and m.get('fresh_measurement') is True and m.get('bootstrap_probe_only') is True
                        and type(unit) is int and 0<unit<=1048576 and type(available) is int and available>=workspace.RESERVE+unit,
                        'Fresh PID/boot/workspace D differs')
                    now=dict(process_id=pid,boot_id=boot)
                    fc.need(not bound or bound==now,'Process or boot changed during feature job')
                    bound.update(now);result.update(native_process_id=pid,boot_id=boot);return dict(now,fresh=True)
                now=identity()
                if resume and selection.get('requires_new_boot_evidence'):
                    fc.need(now['boot_id']!=selection['previous_boot_id'],'Resume requires a new camera boot after the verified MSC checkpoint')
                wire=Journal(root/'settings-wire');settings_channel=SettingsChannel(channel,intent=wire,reply=wire)
                before={r:channel.file(p) for r,p in ss.PATHS.items()}
                settings_archive.save_snapshot(settings_channel.capture(),root/'settings-before')
                stages=(_stages_factory or fs.Stages)(channel,root,Path(tmp).resolve(),capture['body_binding'],selection['profile'],
                    identity=identity,settings_channel=settings_channel,result=result,receipt_commit=commit,
                    compiler=compiler,parent=parent,actions_factory=actions_factory)
                # Prepare WBI before the first possible C dispatch. It is
                # adopted only after all completed-stage C/D barriers pass.
                wbi=_wbi_factory(channel,root/'startup-adoption',compiler=compiler,runtime_evidence=identity,actions_factory=actions_factory)
                stage=(stages.restore_consumers() if parent else stages.forward(prepared=prepared,native_project=project))
                if resume:
                    def resource_runtime():
                        original=stages.child('looks-program')
                        fc.need(original is not None,'Resource resume requires the retained program C ledger')
                        fresh=identity();images=stages.images()
                        lp.check_restored(images['ap'],images['cp'],original)
                        del images
                        def proof_actions(channel,output):
                            action=actions_factory(channel,output);history.append(action);return action
                        stages.index+=1;folder=root/('loaded-C-%03d'%stages.index)
                        proof=lp.verify_loaded_C_borrowed(channel,folder,originals=original,compiler=compiler,
                            boot_id=fresh['boot_id'],pid=fresh['process_id'],actions_factory=proof_actions)
                        # Classify only the unchanged, parsed maps/mem reader,
                        # after exact packet/library cleanup. This grants no STOP.
                        action=history[-1]
                        fc.need(proof.get('cleanup_safe') is True and proof.get('no_memory_write') is True and proof.get('no_COW') is True
                            and not action.failed and not action.unknown_remote_state and not action.owned and channel.healthy
                            and all(channel.peek(p) is None for p in (LIBRARY,load_wire.REQUEST_PATH,load_wire.RESULT_PATH)),
                            'Scoped loaded-C proof cleanup is unknown')
                        action.feature_attempted=False;action.inspection_complete=True
                        result.setdefault('loaded_C_proofs',[]).append(proof)
                        if proof.get('loaded_earliest_owned_AP_C_verified') is not True:
                            fc.need(proof.get('native_status')==-84,'Loaded-C inspection failed without a proved RAM endpoint mismatch')
                            raise rr.RequiredBoundary('Earliest owned AP C is not proved loaded; keep resource EOF',
                                reason='EARLIEST_OWNED_AP_C_NOT_LOADED',details=dict(report_sha256=proof['report_sha256']))
                        return dict(body_binding=capture['body_binding'],boot_id=fresh['boot_id'],process_id=fresh['process_id'],fresh=True,
                            original_backup_sha256=sha256(read_private(Path(capture_path),fc.MAXIMUM)).hexdigest(),
                            load_proof=dict(C_loaded_verified=True,fresh=True,boot_id=fresh['boot_id'],process_id=fresh['process_id'],
                                report_sha256=proof['report_sha256']))
                    try:stage=stages.resume_resources(resource_runtime)
                    except rr.RequiredBoundary as boundary_error:
                        stage=dict(boundary_error.checkpoint,stage='RESOURCE_RESTORE_BOUNDARY_REQUIRED')
                result['stage_result']=stage
                post=stages.images();identity();folder=root/'post';folder.mkdir(mode=0o700)
                for role,raw in post.items():_write(folder/(role+'.bin'),raw)
                after_settings=settings_channel.capture();stages.verify_final(post,after_settings)
                settings_archive.save_snapshot(after_settings,root/'settings-after')
                result['verified_objects']=[dict(path='post/'+r+'.bin',**ss.identity(raw)) for r,raw in post.items()]
                result['E_F_observations']=dict(full_file_hashes=dict(before={r:ss.identity(v) for r,v in before.items()},
                    after={r:ss.identity(v) for r,v in post.items()}),equality_used_for_admission=False,whole_target_equality_claimed=False)
                result['readback']=dict(validation_scope='C-D-only-E-F-observations/1',objects3_read=True,
                    C_D_verified=True,settings_C_D_verified=True,E_F_observed=True,F_gate_execution=False,
                    semantic_whole_target_verified=False,files={r:ss.identity(v) for r,v in post.items()})
                adoption=(wbi.adopt(program_fullpost_verified=True,approval_verified=True,no_ssh_started=True) if stages.mutated
                    else dict(success=True,kind='NOT_PERFORMED_NO_CHANGE',running_target_proven=False))
                result['startup_adoption']=adoption
                fc.need(adoption.get('success') is True or adoption.get('known_clean_refusal') is True,'Startup adoption unknown')
                boundary=stage['stage']=='RESOURCE_RESTORE_BOUNDARY_REQUIRED'
                pending=adoption.get('success') is not True
                result.update(native_sequence_complete=not boundary,full_readback_verified=True,checkpoint=stage if boundary else None)
                channel.allow_clean_stop();result['stop_safe']=True;commit()
            fc.need(getattr(session,'stop_succeeded',False) and getattr(session,'resources_disposed',False),'Feature service exit incomplete')
            result['normal_return']=verify_normal_return(released,survey=survey,runner=runner)
            result.update(status=('SIMULATED_' if result['simulation'] else '')+('RESOURCE_RESTORE_BOUNDARY_REQUIRED' if boundary else
                'VERIFIED_DISK_TARGETS_ADOPTION_PENDING' if pending else 'VERIFIED_APPLIED' if stages.mutated else 'VERIFIED_NO_CHANGE'),
                complete=not boundary and not pending,verified=not boundary and not pending,
                normal_return_verified=True,service_exit_confirmed=True,union_C_restored=parent is not None and not boundary and not pending,
                persistent_write_phase_attempted=stages.mutated,camera_applied=stages.mutated and result['camera_io'] is True)
            commit();return result
    except BaseException as error:
        clean=False
        if safe_abort() and session is not None and getattr(session,'stop_succeeded',False) and getattr(session,'resources_disposed',False) and released is not None:
            try:result['normal_return']=verify_normal_return(released,survey=survey,runner=runner);clean=True
            except (OSError,ValueError,RuntimeError):pass
        if channel is not None and not clean:channel.healthy=False;channel.safe_to_stop=False
        result.update(status='STOPPED_PREFLIGHT_NORMAL_RETURN' if clean else 'STOP_UNKNOWN' if result['camera_io'] else 'STOPPED_LOCAL',
            complete=False,verified=False,stop_safe=clean,normal_return_verified=clean,service_exit_confirmed=clean,
            error=str(error),error_type=type(error).__name__)
        commit()
        if isinstance(error,(KeyboardInterrupt,SystemExit)):raise
        raise FeatureJobError(str(error),result) from error
