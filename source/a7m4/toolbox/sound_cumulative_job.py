"""First-stock sound and explicit Gate+sound union restore coordinator.

One bounded service session. C/D controls execution; E/F is retained only as
observation. Unknown outcomes never authorize replay, inverse or healthy STOP.
"""
from hashlib import sha256
from contextlib import ExitStack
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import uuid

from . import sound_scope as ss, sound_cumulative as sc, gate_cumulative as gc, gate_scope
from . import program_worker, workspace, host_metadata, settings_archive, settings_plan
from .capture_inputs import read_private, verified_device_capture as verified_capture
from .device_job import complete_capture, Journal
from .job_ownership import create_job_output
from .native_actions import NativeActions, _write, _json
from .native_channel import channel_class, LIBRARY
from .ownership import camera_lock, release_host_volumes, verify_normal_return
from .original_wbi import OriginalWBI, load_sources as wbi_sources, report_bound
from .settings_channel import SettingsChannel
from .settings_job import SettingsJob, observe_forward_F, _maps as settings_maps
from .usb_read import ServiceSession, body_binding, VERSION_SHA256, LOADER_SHA256, _atomic_json

CUSTOM='/usr/share/avsystemsound/custom.txt'
SNAPSHOTS=dict(ap='appFw.so',cp='CPAPP-B.BIN',bank='extras/SysSound.bin')


class SoundUnionJobError(RuntimeError):
    def __init__(self,message,result):super().__init__(message);self.result=result


def _capture_images(capture):
    return {r:read_private(Path(capture['snapshot_dir'])/name,ss.LIMITS[r]) for r,name in SNAPSHOTS.items()}


def plan_sound_scope(capture_path,prepared_pack,gate_capsule):
    capture,_=complete_capture(capture_path);gate=gc.load(gate_capsule,capture['body_binding'])
    manifest,clips=ss.prepared(prepared_pack);images=_capture_images(capture)
    ss.dependencies(images['ap'],images['cp'])
    ss.need(ss.words(images['ap'])==[w.hex() for w in ss.STOCK_WORDS] and len(images['bank'])==ss.ORIGINAL_EOF,
            'First scoped sound plan requires original sound C/EOF in the selected backup')
    return dict(schema='a7m4-scoped-sound-selection/1',body_binding=capture['body_binding'],
        capture_receipt=str(Path(capture_path).absolute()),prepared_pack=str(Path(prepared_pack).absolute()),
        gate_capsule_sha256=gate['capsule_sha256'],controls=manifest['controls'],
        source_head_sha256=sha256(images['bank'][:256]).hexdigest(),
        audio_Kasha_internal_pair_seconds=.02,body_shutter_split_seconds=.125,body_cutoff_write=False,
        native_lengths={r:len(v) for r,v in clips.items()},requires_fresh_Gate_enabled=True,
        source_admission='fresh-C-D-only',C=dict(AP_bytes=28,bank_head=256,owned_tail=[77504,110528],EOF=[77504,110528]),
        E_F_gate_execution=False,cache_restore='NORMAL_REBUILD',camera_io=False,device_validation='not-performed')


def plan_union_restore(capture_path,capsule_path):
    capture,_=complete_capture(capture_path);capsule=sc.load(capsule_path,capture['body_binding'])
    images=_capture_images(capture);ss.dependencies(images['ap'],images['cp'])
    return dict(schema='a7m4-gate-sound-C-restore-selection/1',body_binding=capture['body_binding'],
        capture_receipt=str(Path(capture_path).absolute()),capsule_sha256=capsule['capsule_sha256'],
        coverage='Gate-plus-first-stock-sound-explicit-dispatch-history',
        C=dict(gate=capsule['gate']['originals'],sound=capsule['sound_original']),
        E_F_restored=False,cache_restore='NORMAL_REBUILD',camera_io=False,device_validation='not-performed')


def _settings(snapshot,originals,*,forward=False,expected=None):
    report=gc.settings_freshness(snapshot,snapshot,originals)
    ss.need(report['stable'],'Sound C/D settings geometry differs: '+';'.join(report['errors']))
    if forward:
        ss.need(all(getattr(snapshot,p).records[settings_plan.AP55]==settings_plan.Value(0,b'\2')
            for p in ('ram','saved','bin','bak')),'Sound requires already enabled AP55=02; enable Gate first')
    if expected is not None:
        ss.need(all(getattr(snapshot,p).records[settings_plan.AP55].data==h for p,h in expected.items()),'Union AP55 C endpoint changed')


def execute_scoped_sound(capture_path,prepared_pack,output,*,gate_capsule,**kwargs):
    selection=plan_sound_scope(capture_path,prepared_pack,gate_capsule)
    capture,_=complete_capture(capture_path);gate=gc.load(gate_capsule,capture['body_binding'])
    return _execute(capture_path,output,selection=selection,prepared_pack=prepared_pack,gate=gate,**kwargs)


def execute_union_restore(capture_path,capsule_path,output,**kwargs):
    selection=plan_union_restore(capture_path,capsule_path)
    return _execute(capture_path,output,selection=selection,parent=sc.load(capsule_path,selection['body_binding']),**kwargs)


def _execute(capture_path,output,*,selection,prepared_pack=None,gate=None,parent=None,compiler=None,
             survey=host_metadata.survey,runner=None,lock=camera_lock,session_factory=None,
             actions_factory=NativeActions,_wbi_factory=OriginalWBI):
    capture,_=complete_capture(capture_path);restoring=parent is not None
    root=create_job_output(output);receipt=root/'job.private.json';runner=runner or subprocess.run
    compiler=compiler or shutil.which('zig')
    result=dict(schema='a7m4-toolbox-device-job/1',feature='gate-sound-C-total-restore' if restoring else 'scoped-sound-first-install',
        status='PREPARING_LOCAL',body_binding=capture['body_binding'],receipt=str(receipt),selection=selection,
        camera_io=False,simulation=False,complete=False,verified=False,full_readback_verified=False,stop_safe=False,
        normal_return_verified=False,service_exit_confirmed=False,native_sequence_complete=False,
        persistent_write_phase_attempted=False,E_F_restored=False,E_F_gate_execution=False,
        installed_cutoff='unchanged-1/8',activation_requires_user_power_cycle=True)
    capsule=sc.Capsule(root,capture['body_binding'],gate=gate,parent=parent,result=result)
    _atomic_json(receipt,result)
    session=channel=None;history=[];mutated=False;released=None;owned_clean=False;protocols=[]
    # Fixed names keep the complete temporary inventory known before entry;
    # their packet bodies still carry the immutable fresh native ticket ID.
    owned={LIBRARY:65535,workspace.REQUEST_PATH:64,workspace.REPORT_PATH:workspace.REPORT.size,
        ss.REQUEST_PATH:ss.REQUEST.size,ss.REPORT_PATH:ss.REPORT.size,
        '/tmp/jiritsu/m4.sound-scope.source.bin':33328,'/tmp/jiritsu/m4.sound-scope.target.bin':33328,
        program_worker.REQUEST_PATH:program_worker.REQUEST.size,program_worker.RESULT_PATH:program_worker.REPORT.size}
    for wire in wbi_sources()[:2]:owned.update({wire.REQUEST:wire.REQUEST_BYTES,wire.RESULT:report_bound(wire),wire.PENDING:report_bound(wire)})
    reads={ss.PATHS[r]:n for r,n in ss.LIMITS.items()}
    reads.update({'/version.txt':4096,'/usr/lib/libJiritsu.so':160*1024*1024,CUSTOM:65535,'/tmp/jbusy':64})
    def safe_abort():return owned_clean and not mutated and all(getattr(a,'safe_read_only_abort',False) for a in history)
    try:
        ss.need(verified_capture(capture_path)==capture,'Selected complete backup changed before entry')
        with tempfile.TemporaryDirectory(prefix='a7m4-sound-scope-build-') as tmp,lock():
            build_root=Path(tmp).resolve()
            released=release_host_volumes(root,survey=survey,runner=runner);result['host_release']=released
            native=channel_class(reads,owned)
            session=(session_factory(native,released) if session_factory else ServiceSession(channel_factory=native,expected_usb_serial=released['camera']['usb_serial']))
            with session as channel,ExitStack() as finalizer:
                def abort_stop():
                    if safe_abort() and channel.healthy:channel.allow_clean_stop()
                finalizer.callback(abort_stop)
                result['camera_io']=getattr(session,'camera_io',True);result['simulation']=result['camera_io'] is False
                for path in (*owned,'/tmp/jbusy',CUSTOM):ss.need(channel.peek(path) is None,'Foreign/stale exact job path: '+path)
                owned_clean=True
                identity_action=actions_factory(channel,root/'identity-native');history.append(identity_action)
                native_identity={}
                def identity():
                    ss.need(sha256(channel.file('/version.txt')).hexdigest()==VERSION_SHA256
                        and sha256(channel.file('/usr/lib/libJiritsu.so')).hexdigest()==LOADER_SHA256,'Exact firmware/loader D differs')
                    channel.settings(False);ss.need(body_binding(channel.serial())==capture['body_binding'],'Fresh body differs')
                    m=identity_action.probe();pid=m.get('process_id');boot=m.get('boot_id');unit=m.get('allocation_unit');available=m.get('available_bytes')
                    ss.need(type(pid) is int and pid>0 and type(boot) is str and str(uuid.UUID(boot))==boot
                        and uuid.UUID(boot).int!=0 and m.get('fresh_measurement') is True and m.get('bootstrap_probe_only') is True
                        and type(unit) is int and 0<unit<=1048576 and type(available) is int and available>=workspace.RESERVE+unit,
                        'Fresh sound PID/boot/workspace D differs')
                    now=dict(process_id=pid,boot_id=boot)
                    ss.need(not native_identity or native_identity==now,'Sound PID/boot changed')
                    native_identity.update(now);result.update(native_process_id=pid,boot_id=boot)
                    return dict(now,fresh=True)
                identity()
                def observe(label):
                    folder=root/label;folder.mkdir(mode=0o700)
                    images={r:channel.file(path) for r,path in ss.PATHS.items()}
                    for r,raw in images.items():_write(folder/(r+'.bin'),raw)
                    return images
                current=observe('pre');ss.dependencies(current['ap'],current['cp'],enabled=None if restoring else True)
                if not restoring:ss.need(sha256(current['bank'][:256]).hexdigest()==selection['source_head_sha256'],
                    'Fresh first sound Ka C differs from selected original backup')
                wire=Journal(root/'settings-wire');settings_channel=SettingsChannel(channel,intent=wire,reply=wire)
                before=settings_channel.capture();settings_archive.save_snapshot(before,root/'settings-before')
                gate_originals=capsule.value['gate']['originals'];_settings(before,gate_originals,forward=not restoring)
                # Fresh registered C may differ from an old capture and may be
                # partial after an explicit failed transaction. F is not bound.
                sound_plan=(ss.restore(current['ap'],current['cp'],current['bank'],capsule.value['sound_original'])
                    if restoring and capsule.value['sound_original'] is not None else
                    ss.forward(current['ap'],current['cp'],current['bank'],prepared_pack) if not restoring else None)
                sound_needed=(sound_plan is not None and (any(w['before_hex']!=w['after_hex'] for w in sound_plan['ap_windows'])
                    or any(sound_plan['bank']['before_'+k]!=sound_plan['bank']['after_'+k] for k in ('head_hex','tail_hex'))
                    or sound_plan['bank']['source_eof']!=sound_plan['bank']['target_eof']))
                if sound_plan is not None:_write(root/'sound-plan.json',_json(sound_plan))
                sound_build=ss.build(sound_plan,build_root/'sound',compiler=compiler) if sound_needed else None
                cp_plan=gc.cp_program(current['ap'],current['cp'],gate_originals) if restoring else None
                cp_build=program_worker.build_program_worker(cp_plan,build_root/'gate',compiler=compiler) if cp_plan else None
                if cp_build is not None:ss.need(cp_build.get('worker_built') is True,'Fresh Gate restoration build failed')
                setting_plan=(gc.settings_plan(before,gate_originals,identity=capture['body_binding']['serial_sha256'],
                    boot_id=native_identity['boot_id'],nonce=os.urandom(16).hex()) if restoring and 'ap55' in gate_originals else None)
                settings_needed=setting_plan is not None and (any(r.before_ram!=r.after_ram or r.before_saved!=r.after_saved for r in setting_plan.records)
                    or any(settings_plan.needs_save(setting_plan,g) for g in setting_plan.groups))
                wbi=_wbi_factory(channel,root/'startup-adoption',compiler=compiler,runtime_evidence=identity,actions_factory=actions_factory) if sound_needed or cp_plan or settings_needed else None
                if sound_needed:
                    protocol=ss.Protocol(sound_plan);protocols.append(protocol)
                    a=actions_factory(channel,root/'sound-native');history.append(a)
                    a.upload_data({r['upload_path']:r['data'] for r in ss.packets(sound_plan).values()},report_sizes=(ss.REPORT.size,))
                    for mode in (0,1,3):
                        request=protocol.request(mode,os.urandom(16))
                        def dispatch():
                            nonlocal mutated
                            if not restoring:capsule.dispatch(sound_plan,request)
                            else:_write(root/'sound-restore-dispatch-intent.json',_json(dict(plan_id=sound_plan['plan_id'],request_sha256=sha256(request).hexdigest(),outcome='ATTEMPTED_UNKNOWN')))
                            mutated=True;result['persistent_write_phase_attempted']=True
                            _atomic_json(receipt,result)
                        a.phase(read_private(Path(sound_build['worker']['path']),65535),ss.REQUEST_PATH,request,ss.REPORT_PATH,
                            protocol.accept,report_bytes=ss.REPORT.size,**({'before_dispatch':dispatch} if mode==1 else {}))
                        ss.need(protocol.identities[-1]==native_identity['process_id'],'Sound report PID differs from current boot')
                        if mode in (0,3):protocol.confirm(observe('sound-inspect-'+str(mode)))
                        if mode==3 and not restoring:capsule.confirmed();_atomic_json(receipt,result)
                    a.clean_packets()
                if cp_plan is not None:
                    protocol=gc.RestoreProtocol(cp_plan);protocols.append(protocol)
                    a=actions_factory(channel,root/'gate-native');history.append(a)
                    for mode in (0,1,3):
                        request=protocol.request(mode,os.urandom(16))
                        def cp_dispatch():
                            nonlocal mutated
                            _write(root/'gate-restore-dispatch-intent.json',_json(dict(plan_id=cp_plan['plan_id'],request_sha256=sha256(request).hexdigest(),outcome='ATTEMPTED_UNKNOWN')))
                            mutated=True;result['persistent_write_phase_attempted']=True;_atomic_json(receipt,result)
                        a.phase(read_private(Path(cp_build['worker']['path']),65535),program_worker.REQUEST_PATH,request,program_worker.RESULT_PATH,
                            protocol.accept,report_bytes=program_worker.REPORT.size,**({'before_dispatch':cp_dispatch} if mode==1 else {}))
                        ss.need(protocol.identity[0]==native_identity['process_id'],'Gate native PID differs')
                        if mode in (0,3):
                            folder=root/('gate-inspect-'+str(mode));folder.mkdir(mode=0o700);paths={}
                            for r in ('ap','cp'):
                                p=folder/(r+'.bin');_write(p,channel.file(ss.PATHS[r]));paths[r]=p
                            protocol.confirm_readback(paths)
                    a.clean_packets()
                result['settings_results']=[]
                if setting_plan is not None:
                    fresh=settings_channel.capture();_settings(fresh,gate_originals)
                    setting_plan=gc.settings_plan(fresh,gate_originals,identity=capture['body_binding']['serial_sha256'],boot_id=native_identity['boot_id'],nonce=os.urandom(16).hex())
                    if wbi is None and (any(r.before_ram!=r.after_ram or r.before_saved!=r.after_saved for r in setting_plan.records)
                            or any(settings_plan.needs_save(setting_plan,g) for g in setting_plan.groups)):
                        wbi=_wbi_factory(channel,root/'startup-adoption',compiler=compiler,runtime_evidence=identity,actions_factory=actions_factory)
                    def bind(p):return dict(identity=p.identity,boot_id=identity()['boot_id'],nonce=p.nonce,model='ILCE-7M4',firmware='6.02',exclusive_owner=True)
                    job=SettingsJob(settings_channel,bind=bind,journal=Journal(root/'ap55-journal'),forward_observation_only=True)
                    job.release(setting_plan,dict(schema='a7m4-toolbox-settings-release/1',plan_id=setting_plan.plan_id,identity=setting_plan.identity,boot_id=setting_plan.boot_id,
                        nonce=setting_plan.nonce,backup_verified=True,program_dependencies_verified=True,user_risk_confirmation_fresh=True,release_gate='RELEASED'))
                    try:result['settings_results'].append(job.execute(setting_plan))
                    finally:mutated|=job.mutation_attempted;result['persistent_write_phase_attempted']|=job.mutation_attempted
                post=observe('post');identity()
                if sound_plan is not None:ss.check(sound_plan,post,target=True)
                if restoring:gc.check_cp_target(post['cp'],gate_originals)
                else:ss.dependencies(post['ap'],post['cp'],enabled=True)
                after=settings_channel.capture();settings_archive.save_snapshot(after,root/'settings-after')
                expected={p:getattr(before,p).records[settings_plan.AP55].data for p in ('ram','saved','bin','bak')}
                if restoring and 'ap55' in gate_originals:
                    row=gate_originals['ap55'];expected=dict(ram=bytes.fromhex(row['ram_hex']),**{p:bytes.fromhex(row['saved_hex']) for p in ('saved','bin','bak')})
                _settings(after,gate_originals,forward=not restoring,expected=expected)
                names=dict(ap='ap',cp='cp_program',bank='bank')
                observed={names[r]:ss.identity(raw) for r,raw in post.items()}
                result['verified_objects']=[dict(path='post/'+r+'.bin',**ss.identity(raw)) for r,raw in post.items()]
                result['E_F_observations']=dict(settings=observe_forward_F(after,settings_maps(before)),
                    full_file_hashes=dict(before={r:ss.identity(raw) for r,raw in current.items()},after={r:ss.identity(raw) for r,raw in post.items()}),
                    equality_used_for_admission=False,whole_target_equality_claimed=False)
                result['readback']=dict(validation_scope='C-D-only-E-F-observations/1',objects3_read=True,C_D_verified=True,
                    settings_C_D_verified=True,E_F_observed=True,F_gate_execution=False,semantic_whole_target_verified=False,files=observed)
                result['full_readback_verified']=True;result['native_sequence_complete']=True
                adoption=wbi.adopt(program_fullpost_verified=True,approval_verified=True,no_ssh_started=True) if mutated else dict(success=True,kind='NOT_PERFORMED_NO_CHANGE',running_target_proven=False)
                result['startup_adoption']=adoption
                result['supporting_C_writes']=(dict(kind='VENDOR_DROP_AND_MODE0',native_logical_WBI_header_bytes=512,
                    header_preimage_report_sha256=adoption.get('prepare_report_sha256'),header_preimage_section=9,
                    mode_target='0',cache_restore='NORMAL_REBUILD',NOR_or_trust_write=False)
                    if adoption.get('kind')=='VENDOR_DROP_AND_MODE0' else dict(kind=adoption.get('kind'),writes=0))
                ss.need(adoption.get('success') is True or adoption.get('known_clean_refusal') is True,'Startup adoption outcome unknown')
                pending=adoption.get('success') is not True
                channel.allow_clean_stop();result['stop_safe']=True
                _atomic_json(receipt,result)
            ss.need(getattr(session,'stop_succeeded',False) and getattr(session,'resources_disposed',False),'Sound service exit incomplete')
            result['normal_return']=verify_normal_return(released,survey=survey,runner=runner)
            result.update(status=('SIMULATED_' if result['simulation'] else '')+('VERIFIED_DISK_TARGETS_ADOPTION_PENDING' if pending else 'VERIFIED_APPLIED' if mutated else 'VERIFIED_NO_CHANGE'),
                complete=not pending,verified=not pending,normal_return_verified=True,service_exit_confirmed=True,native_sequence_complete=not pending,
                camera_applied=mutated and result['camera_io'] is True,union_C_restored=restoring and not pending,
                coverage='Gate-plus-first-stock-sound-explicit-dispatch-history')
            _atomic_json(receipt,result);return result
    except BaseException as error:
        for p in protocols:p.unknown()
        if channel is not None and not safe_abort():channel.healthy=False;channel.safe_to_stop=False
        clean=False
        if (safe_abort() and session is not None and getattr(session,'stop_succeeded',False)
                and getattr(session,'resources_disposed',False) and released is not None):
            try:result['normal_return']=verify_normal_return(released,survey=survey,runner=runner);clean=True
            except (OSError,ValueError,RuntimeError):pass
        result.update(status='STOPPED_PREFLIGHT_NORMAL_RETURN' if clean else 'STOP_UNKNOWN' if result['camera_io'] else 'STOPPED_LOCAL',complete=False,verified=False,
            camera_applied=None if mutated else False,error=str(error),error_type=type(error).__name__,persistent_write_phase_attempted=mutated)
        result.update(stop_safe=clean,normal_return_verified=clean,service_exit_confirmed=clean)
        _atomic_json(receipt,result)
        if isinstance(error,(KeyboardInterrupt,SystemExit)):raise
        raise SoundUnionJobError(str(error),result) from error
