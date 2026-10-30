"""Bound sound-gate transaction coordinator; no I/O happens on import.

Only the fixed native electronic-sound selector/gate is admitted here. Generic
program plans are not a public device API. Fresh complete host readback and
same-body backup checks remain mandatory even when the desired gate is a no-op.
"""
from contextlib import ExitStack
from hashlib import sha256
import json
from pathlib import Path
import shutil
import tempfile

from ..research.sound import native_sound_plan
from .capture_inputs import verified_device_capture as verified_capture
from .native_actions import NativeActions,_write,_json
from .native_channel import channel_class,LIBRARY
from .ownership import camera_lock,release_host_volumes,verify_normal_return
from . import host_metadata,workspace
from .policy import sound_state
from .job_ownership import create_job_output
from .usb_read import (ServiceSession,body_binding,VERSION_SHA256,LOADER_SHA256,
                       _atomic_json)


class ProgramJobError(RuntimeError):
    def __init__(self,text,result):
        super().__init__(text);self.result=result


def sound_gate_plan(capture_path,desired_state):
    """Pure local content plan, admitted by complete known image identities."""
    state=sound_state(desired_state)
    capture=verified_capture(capture_path)
    snapshot=Path(capture['snapshot_dir'])
    gate=native_sound_plan(snapshot/'appFw.so',snapshot/'CPAPP-B.BIN',state)
    # Gate-only operations preserve the bank. A known AP cannot make an
    # unrelated/corrupt bank safe simply because its filename was captured.
    bank=capture['objects']['extras/SysSound.bin']
    expected=('d8d7ce8eae9442c0c51c2f5bec608bc228d2acdf8bc5b69b484620b9c94bbe06'
              if gate['profile_id']=='r066-fixed-pin' else
              'dae3d18d37b85a22398573f04090a4a95a97052380f4b2b4402a374516399dfb')
    if bank['sha256']!=expected:raise ValueError('Gate source sound bank is not an admitted complete endpoint')
    from .program_worker import program_plan
    components={}
    for role in ('ap','cp'):
        source={key:gate['source'][role][key] for key in ('size','sha256')}
        target={key:gate['target'][role][key] for key in ('size','sha256')}
        windows=[] if role=='ap' or gate['cp_plan'] is None else [
            {key:row[key] for key in ('offset','before_hex','after_hex')} for row in gate['cp_plan']['windows']]
        components[role]=dict(source=source,target=target,windows=windows)
    plan=None if gate['cp_plan'] is None else program_plan(components,feature_id='electronic-sound-gate')
    return dict(schema='a7m4-toolbox-sound-gate/1',capture_receipt=str(Path(capture_path).absolute()),
                body_binding=capture['body_binding'],gate=gate,program=plan,
                camera_io=False,device_validation='not-performed',device_execution_ready=False)


def execute_sound_gate(capture_path,desired_state,output,*,compiler=None,
                       survey=host_metadata.survey,runner=None,lock=camera_lock,
                       session_factory=None,actions_factory=NativeActions):
    """Explicit caller authorization is checked by the public CLI before entry.

    All build artifacts come from this process's recomputed fixed plan, not a
    user-supplied generic patch manifest or executable. No hardware is touched
    until the existing complete backup, scope and offline build are verified.
    """
    import subprocess
    from . import program_worker as worker
    runner=runner or subprocess.run
    compiler=compiler or shutil.which('zig')
    selection=sound_gate_plan(capture_path,desired_state)
    capture=verified_capture(capture_path)
    root=Path(output).absolute()
    if root.exists() or not root.parent.is_dir() or any(p.is_symlink() for p in (root,*root.parents)):
        raise ValueError('New nonredirected explicit device job output required')
    root=create_job_output(root)
    receipt=root/'job.private.json'
    result=dict(schema='a7m4-toolbox-device-job/1',feature='electronic-sound-gate',
                status='PREPARING_LOCAL',camera_io=False,network_io=False,
                complete=False,verified=False,full_readback_verified=False,stop_safe=False,
                receipt=str(receipt),body_binding=capture['body_binding'],
                backup_archive_sha256=capture['archive_sha256'],selection=selection,
                device_validation='not-performed',automatic_retry=False,automatic_inverse=False)
    _atomic_json(receipt,result)
    session=channel=actions=None
    try:
        plan=selection['program']
        with tempfile.TemporaryDirectory(prefix='a7m4-gate-build-') as temporary:
            bundle=None
            binary=None
            if plan is not None:
                bundle=worker.build_program_worker(plan,Path(temporary).resolve()/'worker',compiler=compiler)
                if bundle.get('worker_built') is not True:
                    raise ValueError('Native worker was not built: '+str(bundle.get('blockers',bundle.get('status'))))
                binary=Path(bundle['worker']['path']).read_bytes()
                if sha256(binary).hexdigest()!=bundle['worker']['sha256']:
                    raise ValueError('Fresh worker build identity differs')
                _write(root/'plan.json',_json(plan));_write(root/'worker.so',binary)
            with lock():
                released=release_host_volumes(root,survey=survey,runner=runner)
                result['host_release']=released
                reads={'/version.txt':4096,'/usr/lib/libJiritsu.so':160*1024*1024,
                       '/usr/lib/appFw.so':98212632,'/cp/CPAPP-B.BIN':16236816,
                       '/cp/SysSound.bin':131072,'/usr/share/avsystemsound/custom.txt':65535}
                owned={LIBRARY:65535,workspace.REQUEST_PATH:64,workspace.REPORT_PATH:workspace.REPORT.size}
                if bundle:
                    owned[bundle['request']['path']]=worker.REQUEST.size;owned[bundle['report']['path']]=worker.REPORT.size
                native=channel_class(reads,owned)
                session=(session_factory(native,released) if session_factory else
                    ServiceSession(channel_factory=native,expected_usb_serial=released['camera']['usb_serial']))
                with session as channel, ExitStack() as preflight_exit:
                    def finish_read_only_preflight():
                        if (actions is None or getattr(actions,'safe_read_only_abort',False)) and channel.healthy:
                            channel.allow_clean_stop()
                    preflight_exit.callback(finish_read_only_preflight)
                    result['camera_io']=getattr(session,'camera_io',True)
                    result['status']='VERIFYING_FRESH_SOURCE';_atomic_json(receipt,result)
                    def identity():
                        if sha256(channel.file('/version.txt')).hexdigest()!=VERSION_SHA256:
                            raise ValueError('Fresh complete firmware version differs')
                        if sha256(channel.file('/usr/lib/libJiritsu.so')).hexdigest()!=LOADER_SHA256:
                            raise ValueError('Fresh complete service loader differs')
                        channel.settings(False)
                        if body_binding(channel.serial())!=capture['body_binding']:
                            raise ValueError('Current body differs from complete backup')
                    identity()
                    if channel.peek('/usr/share/avsystemsound/custom.txt') is not None:
                        raise ValueError('Retired CSV sound route is present; preserve it and stop without program writes')
                    # AP55 selects CP file loading. Do not turn a historical
                    # source-00 observation into an implicit settings write.
                    if plan is not None and channel.read_ap55()!=b'\x02':
                        raise ValueError('CP file-loader prerequisite AP55=02 is absent; no setting was changed')
                    def readback(label,endpoint):
                        folder=root/label;folder.mkdir(mode=0o700)
                        paths={}
                        for role,remote in (('ap','/usr/lib/appFw.so'),('cp','/cp/CPAPP-B.BIN')):
                            raw=channel.file(remote)
                            path=folder/(role+'.bin');_write(path,raw);paths[role]=path
                            expected=selection['gate']['source' if endpoint=='source' else 'target'][role]
                            if len(raw)!=expected['size'] or sha256(raw).hexdigest()!=expected['sha256']:
                                raise ValueError('Fresh complete '+endpoint+' image differs: '+role)
                        bank=channel.file('/cp/SysSound.bin')
                        if sha256(bank).hexdigest()!=capture['objects']['extras/SysSound.bin']['sha256']:
                            raise ValueError('Sound bank changed during gate-only job')
                        return paths
                    current=readback('pre','source')
                    if plan is not None:
                        protocol=worker.ProgramProtocol(plan)
                        actions=actions_factory(channel,root/'native-actions')
                        for mode in (0,1,3):
                            request=protocol.request(mode,__import__('os').urandom(16))
                            actions.phase(binary,bundle['request']['path'],request,bundle['report']['path'],
                                          protocol.accept,report_bytes=worker.REPORT.size)
                            if mode in (0,3):
                                current=readback('inspect-'+str(mode),'source' if mode==0 else 'target')
                                verified=protocol.confirm_readback(current)
                        result['readback']=verified
                        actions.clean_packets()
                    else:
                        readback('unchanged','source')
                    identity()
                    channel.allow_clean_stop()
                    result.update(status='VERIFIED_AWAITING_SERVICE_EXIT',full_readback_verified=True,stop_safe=True)
                    _atomic_json(receipt,result)
                if isinstance(session,ServiceSession) and (not session.stop_succeeded or not session.resources_disposed):
                    raise RuntimeError('Service exit did not fully complete')
                result['normal_return']=verify_normal_return(released,survey=survey,runner=runner)
                result.update(status='VERIFIED_APPLIED' if plan else 'VERIFIED_NO_CHANGE',complete=True,verified=True,
                              normal_return_verified=True,service_exit_confirmed=True,
                              camera_applied=plan is not None and result['camera_io'] is True)
                if result['camera_io'] is False:
                    result['status']='SIMULATED_'+result['status']
                _atomic_json(receipt,result)
                return result
    except BaseException as error:
        if session is not None:
            result['camera_io']=getattr(session,'camera_io',True)
        read_only_abort=actions is None or getattr(actions,'safe_read_only_abort',False)
        if channel is not None and read_only_abort:
            result['preflight_only']=True
        clean_preflight=False
        if session is not None and read_only_abort and getattr(session,'stop_succeeded',False):
            try:
                result['normal_return']=verify_normal_return(released,survey=survey,runner=runner)
                clean_preflight=True
            except (ValueError,RuntimeError,OSError):
                pass
        result.update(status='STOP_UNKNOWN' if result['camera_io'] else 'STOPPED_LOCAL',
                      complete=False,verified=False,error=str(error),error_type=type(error).__name__,
                      stop_safe=clean_preflight,normal_return_verified=clean_preflight)
        if clean_preflight:result['status']='STOPPED_PREFLIGHT_NORMAL_RETURN'
        _atomic_json(receipt,result)
        if isinstance(error,(KeyboardInterrupt,SystemExit)):raise
        raise ProgramJobError(str(error),result) from error
