"""Explicit macOS camera ownership; imports and injected tests do no device I/O.

Host registry metadata is used only when a caller starts an explicit operation.
No USB backend, reset, forced unmount, raw disk open, or permanent privilege is
provided here. A successful service exit must still be verified by its caller.
"""
from __future__ import annotations

from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import time

from . import host_metadata as host


class OwnershipError(RuntimeError):
    pass


def _need(value, message):
    if not value:
        raise OwnershipError(message)


@contextmanager
def camera_lock(*, paths=None, owner_uid=None):
    """Hold the shared fixed lock and the older toolkit's per-user lock.

    Lock files are never unlinked: unlinking a held inode permits a second
    process to acquire a different file with the same name. Reject symlinks,
    hard links and nonregular files before acquiring either lock.
    """
    names = paths if paths is not None else (
        Path('/private/tmp/a7m4-toolkit.lock'),
        Path(tempfile.gettempdir()) / 'a7m4-toolkit.lock',
    )
    opened = []
    locked_inodes = set()
    try:
        for path in dict.fromkeys(Path(p).absolute() for p in names):
            flags=os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK
            fd = os.open(path, flags, 0o666)
            opened.append(fd)
            info = os.fstat(fd)
            _need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size == 0,
                  '相机锁必须为唯一普通文件。')
            _need(info.st_uid in (0, os.getuid(), owner_uid), '相机锁属于其他用户。')
            # An empty advisory lock contains no data. Explicit mode is needed
            # after a root GUI job, otherwise umask leaves a permanent 0644
            # root file that prevents later ordinary-user toolkit instances.
            if info.st_uid==os.geteuid() or os.geteuid()==0:
                os.fchmod(fd,0o666)
            # macOS root tempdir may be /tmp, an alias of /private/tmp.
            # One scope must not flock the same inode twice on separate FDs.
            identity = (info.st_dev, info.st_ino)
            if identity in locked_inodes:
                continue
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise OwnershipError('另一个工具进程正在使用相机。') from error
            locked_inodes.add(identity)
        yield
    finally:
        for fd in reversed(opened):
            os.close(fd)


def _summary(receipt):
    _need(receipt.get('schema') == host.SCHEMA and receipt.get('read_only') is True,
          '宿主存储检查格式不符。')
    value = receipt['metadata']
    _need(host.digest(host._canonical(value)) == receipt.get('metadata_sha256'),
          '宿主存储检查摘要不符。')
    return value


def _same_body(before, after, *, enumerated=False):
    keys = ('model', 'vendor_id', 'product_id', 'location_id', 'usb_serial')
    _need(all(before.get(k) == after.get(k) for k in keys), '相机身份或物理连接位置发生变化。')
    if not enumerated:
        _need(before == after, '相机枚举身份发生变化。')


def release_host_volumes(output, *, survey=host.survey, runner=subprocess.run):
    """Release only whole disks in a freshly stable, unique A7 IV subtree.

    The destination is checked before the first unmount. Each mutation gets a
    fresh identity check, then all mounted states are verified again. Failure
    never triggers an unmount retry or an operation against a replacement disk.
    """
    destination = Path(output).absolute()
    _need('..' not in destination.parts, '输出目录必须为规范绝对路径。')
    for parent in (destination, *destination.parents):
        _need(not parent.is_symlink(), '输出目录不得经过符号链接。')
    _need(not destination.is_relative_to('/Volumes'), '备份目录不能位于外接相机卷。')
    first = _summary(survey(runner=runner))
    camera = first['camera']
    _need(isinstance(camera.get('usb_serial'), str) and camera['usb_serial'],
          '宿主相机缺少可与 USB 服务入口核对的序列号。')
    media = first['media']
    for row in media:
        mount = row['diskutil'].get('MountPoint')
        if mount:
            _need(not destination.is_relative_to(Path(mount)), '输出目录位于将卸载的相机卷。')
    unmounted = []
    for row in media:
        if row['registry']['whole'] is not True:
            continue
        name = row['registry']['device_identifier']
        current = _summary(survey(runner=runner))
        _same_body(camera, current['camera'])
        _need([r['registry'] for r in current['media']] == [r['registry'] for r in media],
              '相机存储子树发生变化；停止，不使用旧磁盘编号。')
        bound = [r for r in current['media'] if r['registry']['parent_whole_disk'] == name]
        _need(bound and all(r['diskutil'].get('Internal') is False
                           and r['diskutil'].get('BusProtocol') == 'USB' for r in bound),
              '不能确认同一相机的外接 USB 卷。')
        if not any(r['diskutil'].get('Mounted') is True or r['diskutil'].get('MountPoint') for r in bound):
            continue
        command = ['/usr/sbin/diskutil', 'unmountDisk', '/dev/' + name]
        try:
            result = runner(command, capture_output=True, check=False, timeout=60)
        except (OSError, subprocess.SubprocessError) as error:
            raise OwnershipError('相机卷卸载结果未知；停止，不自动重试。') from error
        _need(result.returncode == 0, '相机卷无法正常卸载；停止，不强制卸载。')
        unmounted.append(name)
    final = _summary(survey(runner=runner))
    _same_body(camera, final['camera'])
    _need([r['registry'] for r in final['media']] == [r['registry'] for r in media],
          '释放后的存储身份发生变化。')
    _need(all(not r['diskutil'].get('MountPoint') and r['diskutil'].get('Mounted') is not True
              for r in final['media']), '相机仍有挂载卷；尚未启动 USB 服务。')
    return {'schema': 'a7m4-toolbox-host-release/1', 'camera': camera,
            'unmounted_whole_disks': unmounted, 'host_io': True, 'camera_io': False,
            'all_camera_volumes_unmounted': True}


def verify_normal_return(released, *, survey=None, runner=subprocess.run, deadline=60, pause=time.sleep, clock=time.monotonic):
    """Only bounded OS identity observations, never another service/auth/STOP."""
    if survey is host.survey:survey=None
    end=clock()+min(60,max(0,deadline));attempts=0
    while True:
        if clock()>=end:raise host.ToolError('HOST_DEADLINE','等待正常 MSC 返回已到时，备份数据保留；请完成系统允许后再确认。',dict(attempts=attempts))
        attempts+=1
        try:
            observed=(host.identity_survey(runner=runner,deadline=end,clock=clock) if survey is None else survey(runner=runner))
            if clock()>end:raise host.ToolError('HOST_DEADLINE','MSC 观察已超过本次等待预算。')
            after=_summary(observed)
            _same_body(released['camera'],after['camera'],enumerated=True)
            return dict(normal_msc_verified=True,same_body_and_port=True,camera=after['camera'],
                        camera_io=False,host_io=True,observed_at=observed.get('created'),attempts=attempts)
        except host.ToolError as error:
            from .run_log import event
            event('host-return-observation',code=error.code,details=error.details)
            if clock()>=end:
                raise host.ToolError('HOST_DEADLINE','等待正常 MSC 返回已到时；备份数据保留。',dict(last_code=error.code,last_details=error.details)) from error
            if error.code not in ('HOST_EMPTY','NO_DEVICE','MODEL_PENDING','MODE_PENDING'):raise
            pause(min(.25,max(0,end-clock())))


def capture_with_ownership(output, *, capture=None, survey=host.survey,
                           runner=subprocess.run, lock=camera_lock):
    """One explicit capture, serialized from host release through normal return."""
    destination=Path(output).absolute()
    _need('..' not in destination.parts and not destination.exists() and not destination.is_symlink()
          and destination.parent.is_dir(), '请使用真实父目录下尚不存在的新备份目录。')
    _need(all(not p.is_symlink() for p in destination.parents), '备份目录不得经过符号链接。')
    real_capture = capture is None
    if real_capture:
        from .usb_read import capture_backup
        capture = capture_backup
    with lock():
        released = release_host_volumes(output, survey=survey, runner=runner)
        try:
            if real_capture:
                from .usb_read import ServiceSession
                result = capture(output, session_factory=lambda: ServiceSession(
                    expected_usb_serial=released['camera']['usb_serial']),full_settings=True)
            else:
                result = capture(output)
        except Exception as error:
            from .usb_read import CaptureError, _atomic_json
            result = error.result if isinstance(error,CaptureError) else None
            cleanup = result.get('logical_refusal_cleanup',{}) if isinstance(result,dict) else {}
            exit = result.get('service_exit',{}) if isinstance(result,dict) else {}
            if (isinstance(error,CaptureError) and result.get('status')=='FAILED_PARTIAL'
                    and result.get('complete') is False and result.get('verified') is False
                    and result.get('settings_capture_verified') is False
                    and result.get('persistent_device_writes') is False
                    and result.get('error_type')=='USBReadError'
                    and result.get('stable_object_count')==11 and result.get('stop_safe') is True
                    and cleanup.get('complete_file_count')==11
                    and result.get('settings_stability',{}).get('stable') is False
                    and cleanup.get('profile')=='late-read-capture-logical-refusal/1'
                    and cleanup.get('refusal_code')=='CHANGED'
                    and all(cleanup.get(k) is True for k in ('eligible','full_baselines_verified','fresh_serial_verified'))
                    and all(exit.get(k) is True for k in ('stop_attempted','stop_succeeded','resources_disposed'))):
                result['host_release']=released
                try:
                    result['normal_return']=verify_normal_return(released,survey=None if survey is host.survey else survey,runner=runner)
                    result['normal_return_verified']=True
                except (host.ToolError,OwnershipError,OSError) as return_error:
                    result['normal_return_verified']=False
                    result['logical_refusal_normal_return_error']=str(return_error)
                _atomic_json(Path(result['receipt']),result)
            # Refusal stays a failure, never an archive/portable creation path.
            raise
        # Reaching this point requires the capture's healthy StopSenser and
        # complete archive verification. Never enter a new session on failure.
        result['host_release'] = released
        try:
            result['normal_return'] = verify_normal_return(released, survey=None if survey is host.survey else survey, runner=runner)
        except (host.ToolError, OwnershipError, OSError) as error:
            result.update(status='VERIFIED_BACKUP_EXIT_UNCONFIRMED', normal_return_verified=False,
                          error=str(error), camera_io=True)
            failure = OwnershipError('备份已校验，但普通 MSC 返回未确认；停止并保留结果。')
            failure.result = result
            from .usb_read import _atomic_json
            result['host_return_error']=dict(code=getattr(error,'code',type(error).__name__),details=getattr(error,'details',{}))
            _atomic_json(Path(result['receipt']), result)
            if result.get('settings_capture_verified') is True:
                try:
                    from .settings_archive import create_portable
                    result['portable_archive']=create_portable(result,allow_unconfirmed=True)
                except (ValueError,OSError) as export_error:result['portable_export_error']=str(export_error)
                _atomic_json(Path(result['receipt']),result)
            raise failure from error
        result['normal_return_verified'] = True
        if result.get('settings_capture_verified') is True:
            from .settings_archive import create_portable
            result['portable_archive']=create_portable(result)
        from .usb_read import _atomic_json
        _atomic_json(Path(result['receipt']), result)
        return result
