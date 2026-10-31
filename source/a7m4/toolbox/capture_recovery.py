"""Local data salvage and explicit OS-only follow-up; never a service session."""
from datetime import datetime,timezone
from hashlib import sha256
from pathlib import Path
import json
import os
import subprocess
import tempfile

from .capture_inputs import read_private,verified_capture_data,verified_capture
from . import settings_archive as archive,host_metadata as host
from .native_actions import _write,_json
from .ownership import verify_normal_return,camera_lock,OwnershipError


def data_capture(path):
    path=Path(path).absolute();value=verified_capture_data(path);root=path.parent
    archive.need(value.get('settings_capture_verified') is True,'完整设置数据尚未核验，不能接纳为完整备份。')
    settings=archive.load_snapshot(root/'settings')
    from .usb_read import body_binding,VERSION_SHA256,LOADER_SHA256
    archive.need(body_binding(settings.serial)==value['body_binding'],'设置与机身身份不符。')
    archive.need(sha256(read_private(root/'evidence/version.txt',4096)).hexdigest()==VERSION_SHA256
                 and sha256(read_private(root/'evidence/libJiritsu.so',160*1024*1024)).hexdigest()==LOADER_SHA256,'版本或加载库原件不符。')
    stability=value.get('settings_stability')
    if stability is not None:
        archive.need(type(stability) is dict,'设置 scope 证据格式不符。')
        from .settings_scope import CAPTURE_PROFILE,capture_scope_report
        if stability.get('profile')==CAPTURE_PROFILE:
            after=root/('settings-after' if value.get('portable_import') else 'evidence/settings-after')
            archive.need(_json(capture_scope_report(settings,archive.load_snapshot(after)))==_json(stability),'两份完整设置与 scope 报告不符。')
        else:
            archive.need(stability.get('stable') is True,'设置完整性／稳定性证据不足。')
    return value


def export_capture(receipt,output):
    receipt=Path(receipt).absolute();before=read_private(receipt,2*1024*1024);value=data_capture(receipt)
    result=archive.create_portable(value,allow_unconfirmed=True,output=output)
    archive.need(read_private(receipt,2*1024*1024)==before,'源备份收据在导出期间改变。')
    return dict(schema='a7m4-capture-local-save/1',complete=True,verified=True,data_integrity_verified=True,
        normal_return_verified=value['normal_return_verified'],device_admission=False,camera_io=False,host_io=False,
        source_receipt=str(receipt),source_receipt_sha256=sha256(before).hexdigest(),portable_archive=result)


def adopt_after_host_return(receipt,output,*,runner=subprocess.run,survey=None,lock=camera_lock):
    """New receipt, new time and proof; source receipt is never rewritten."""
    receipt=Path(receipt).absolute();root=Path(output).absolute()
    archive.need(not root.exists() and root.parent.is_dir() and not any(p.is_symlink() for p in (root,*root.parents)),'接纳目录必须是新的本机私有目录。')
    before=read_private(receipt,2*1024*1024);value=data_capture(receipt)
    service=value.get('service_exit') or {}
    archive.need(type(service) is dict and value.get('stop_safe') is True and all(service.get(k) is True for k in ('stop_attempted','stop_succeeded','resources_disposed')),
                 '未有明确 STOP 与释放完成证据；只能本地保存，不能据此接纳。')
    released=value.get('host_release') or {}
    archive.need(type(released) is dict and released.get('schema')=='a7m4-toolbox-host-release/1' and isinstance(released.get('camera'),dict)
                 and bool(released['camera'].get('usb_serial')),'缺少原 USB 机身／端口绑定；只能本地保存。')
    proof=dict(schema='a7m4-host-return-followup/1',created=datetime.now(timezone.utc).isoformat(),
        source_receipt_sha256=sha256(before).hexdigest(),body_binding=value['body_binding'],
        historical_normal_return_verified=value['normal_return_verified'],camera_protocol_requests=0,camera_io=False,normal_return_verified=False)
    proof_path=root.parent/'host-return.private.json'
    with lock():
        try:proof['observation']=verify_normal_return(released,runner=runner,survey=survey)
        except (host.ToolError,OSError,ValueError,OwnershipError) as error:
            proof['error']=dict(code=getattr(error,'code',type(error).__name__),message=str(error),details=getattr(error,'details',{}))
            _write(proof_path,_json(proof));raise
        proof['normal_return_verified']=True
        archive.need(read_private(receipt,2*1024*1024)==before,'源备份收据在连接确认期间改变。')
        _write(proof_path,_json(proof))
        # A separate private destination avoids adding trust to the old failed
        # receipt. All archive members are reverified locally during import.
        with tempfile.TemporaryDirectory(prefix='capture-adopt-',dir=root.parent) as temporary:
            portable=Path(temporary).resolve()/'capture.a7capture'
            archive.create_portable(value,allow_unconfirmed=True,output=portable)
            packaged=archive.verify_portable(portable)['metadata']
            if packaged['schema']=='a7m4-portable-capture/3':
                archive.need(packaged['capture_history']['source_receipt_sha256']==proof['source_receipt_sha256'],
                             '归档的源收据身份与本次宿主收尾证明不一致。')
            imported=archive.import_portable(portable,root)
        target=Path(imported['receipt']);new=json.loads(read_private(target,2*1024*1024))
        history=root/'history';history.mkdir(mode=0o700)
        _write(history/'source-capture.private.json',before)
        _write(root/'host-return.private.json',_json(proof))
        new.update(status='VERIFIED_BACKUP',normal_return_verified=True,stop_safe=True,model='ILCE-7M4',
            service_exit=service,host_release=released,normal_return=proof['observation'],
            source_receipt_sha256=proof['source_receipt_sha256'],historical_normal_return_verified=value['normal_return_verified'],
            historical_capture_status=value['status'],source_origin='locally-verified-data-plus-explicit-host-return-proof',
            host_return_proof_sha256=sha256(_json(proof)).hexdigest())
        new['historical_error']=new.pop('error',None)
        new['historical_host_return_error']=new.pop('host_return_error',None)
        source_archive=new.pop('portable_source',None)
        if source_archive:new['adoption_local_archive_sha256']=source_archive['sha256']
        archive.need(read_private(receipt,2*1024*1024)==before,'源收据在归档／导入期间改变；未发布新的准入收据。')
        from .usb_read import _atomic_json
        _atomic_json(target,new);verified_capture(target)
    return dict(schema='a7m4-capture-adopt/1',complete=True,verified=True,data_integrity_verified=True,
        normal_return_verified=True,camera_io=False,host_io=True,receipt=str(target),snapshot_dir=new['snapshot_dir'],
        archive=new['archive'],source_receipt_unchanged=True,proof=str(root/'host-return.private.json'))
