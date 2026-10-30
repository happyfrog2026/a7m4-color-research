"""Portable private capture container and complete settings evidence.

The nested 73-object archive keeps its existing strict format. Settings are
preserved completely, including direct CP reads, but restoration is restricted
to selected owned spans/records; calibration is never blindly replayed.
"""
from .. import resource_profile as device_scope
from hashlib import sha256
import json
import os
from pathlib import Path
import tempfile
import zipfile

from .capture_inputs import read_private
from .native_actions import _write,_json
from .settings_plan import parse_snapshot,validate_snapshot,SERIAL,KEYS
from .bk4 import bk4_rows
from .import_progress import ImportProgress,notify
from ..research import backup

FILES=('ram.bin','saved.bin','BACKUP.BIN','BACKUP.BAK','CP-02a40001.bin','CP-02a4000d.bin')
SCOPE_REPORT='evidence/settings-scope.json'
SCOPE_MEMBERS={'settings-after/manifest.json',*('settings-after/'+name for name in FILES),SCOPE_REPORT}
BOUNDS={name:8*1024*1024 for name in FILES}
BOUNDS.update({'CP-02a40001.bin':8192,'CP-02a4000d.bin':28672})


def need(ok,text):
    if not ok:raise ValueError(text)


def ident(raw):return dict(size=len(raw),sha256=sha256(raw).hexdigest())


def snapshot_bytes(snapshot):
    validate_snapshot(snapshot)
    return dict(zip(FILES,[snapshot.ram.raw,snapshot.saved.raw,snapshot.bin.raw,snapshot.bak.raw,
                          *[dict(snapshot.direct_cp)[key] for key in KEYS[:2]]]))


def save_snapshot(snapshot,output):
    folder=Path(output);need(not folder.exists() and folder.parent.is_dir(),'New settings capture directory required')
    folder.mkdir(mode=0o700);raws=snapshot_bytes(snapshot)
    rows={}
    for name,raw in raws.items():
        need(0<len(raw)<=BOUNDS[name],'Settings capture size differs')
        _write(folder/name,raw);rows[name]=ident(raw)
    result=dict(schema='a7m4-settings-capture/1',files=rows,
                serial_binding=sha256(snapshot.serial.hex().encode()).hexdigest(),
                calibration_replay=False,blind_full_settings_restore=False)
    _write(folder/'manifest.json',_json(result));return result


def load_snapshot(folder):
    folder=Path(folder).absolute();manifest=json.loads(read_private(folder/'manifest.json',32768))
    need(manifest.get('schema')=='a7m4-settings-capture/1' and set(manifest.get('files',{}))==set(FILES),'Complete settings inventory required')
    raws={name:read_private(folder/name,BOUNDS[name]) for name in FILES}
    need(all(ident(raw)==manifest['files'][name] for name,raw in raws.items()),'Settings capture full identity differs')
    row=bk4_rows(raws['ram.bin'])[0]['records'].get(SERIAL[1]);need(row and row['size']==4,'Settings lack serial binding')
    serial=raws['ram.bin'][row['offset']:row['offset']+4]
    need(sha256(serial.hex().encode()).hexdigest()==manifest.get('serial_binding'),'Settings serial binding differs')
    result=parse_snapshot(raws['ram.bin'],raws['saved.bin'],raws['BACKUP.BIN'],raws['BACKUP.BAK'],
        cp_live={key:raws[name] for key,name in zip(KEYS[:2],FILES[-2:])},serial=serial)
    validate_snapshot(result);return result


def same_snapshot(a,b):
    return snapshot_bytes(a)==snapshot_bytes(b) and a.serial==b.serial


def create_portable(capture, *, allow_unconfirmed=False, output=None):
    """After confirmed service exit/MSC return, package complete local files."""
    root=Path(capture['receipt']).parent
    data_only=(allow_unconfirmed and capture.get('status')=='VERIFIED_BACKUP_EXIT_UNCONFIRMED' and capture.get('normal_return_verified') is False)
    need((capture.get('status')=='VERIFIED_BACKUP' and capture.get('normal_return_verified') is True or data_only)
         and all(capture.get(k) is True for k in ('complete','verified','archive_verified','settings_capture_verified')),'Complete capture data required; unconfirmed exit must remain explicit')
    snap=load_snapshot(root/'settings');need(sha256(snap.serial.hex().encode()).hexdigest()==capture['body_binding']['serial_sha256'],'Settings/body differs')
    expected=backup.verify_backup(root/'original.a7backup')
    need(expected['archive_sha256']==capture['archive_sha256'] and expected['archive_size']==capture['archive_size'],'Core backup differs')
    members={'original.a7backup':root/'original.a7backup','settings/manifest.json':root/'settings'/'manifest.json'}
    members.update({'settings/'+name:root/'settings'/name for name in FILES})
    members.update({'evidence/'+name:root/'evidence'/name for name in ('version.txt','libJiritsu.so')})
    from .settings_scope import CAPTURE_PROFILE,capture_scope_report
    stability=capture.get('settings_stability')
    scoped=stability is not None and stability.get('profile')==CAPTURE_PROFILE
    if scoped:
        after_root=root/('settings-after' if capture.get('portable_import') else 'evidence/settings-after')
        recomputed=capture_scope_report(snap,load_snapshot(after_root))
        need(_json(recomputed)==_json(stability),'Scoped capture report differs from complete before/after originals')
        report=root/SCOPE_REPORT
        if report.exists():need(read_private(report,2*1024*1024)==_json(recomputed),'Scoped observation file differs')
        else:_write(report,_json(recomputed))
        members.update({'settings-after/manifest.json':after_root/'manifest.json',SCOPE_REPORT:report})
        members.update({'settings-after/'+name:after_root/name for name in FILES})
    rows={}
    for name,path in members.items():
        with path.open('rb') as stream:rows[name]=dict(size=path.stat().st_size,sha256=__import__('hashlib').file_digest(stream,'sha256').hexdigest())
    current_scope=capture.get('schema')==device_scope.CAPTURE_SCHEMA
    need(not current_scope or scoped,'Current capture requires scoped settings evidence')
    base_schema='a7m4-portable-capture/4' if current_scope else 'a7m4-portable-capture/2' if scoped else 'a7m4-portable-capture/1'
    meta=dict(schema='a7m4-portable-capture/3' if data_only else base_schema,body_binding=capture['body_binding'],firmware_version='6.02',
              camera_io=capture['camera_io'],normal_return_verified=not data_only,settings_capture_verified=True,
              complete=True,verified=True,files=rows,
              restoration='owned program/resource/audio windows and selected settings spans only',
              whole_chip_recovery=False,calibration_replay=False)
    if current_scope:meta['resource_profile']=device_scope.ID
    if data_only:
        meta.update(base_schema=base_schema,data_integrity_verified=True,origin_status=capture['status'],
            capture_history=dict(normal_return_verified=False,error=capture.get('error'),
                host_return_error=capture.get('host_return_error'),service_exit=capture.get('service_exit'),
                stop_safe=capture.get('stop_safe'),host_release=capture.get('host_release'),
                source_receipt_sha256=sha256(read_private(Path(capture['receipt']),2*1024*1024)).hexdigest()))
    if stability is not None:
        need(scoped or stability.get('stable') is True and stability.get('profile') in ('m4-602-read-capture-stability/1','m4-602-read-capture-stability/2','m4-602-read-capture-stability/3'),
             'Settings stability report incomplete')
        meta['settings_stability']=dict(profile=stability['profile'],raw_equal=stability['raw_equal'],
            report_sha256=sha256(_json(stability)).hexdigest(),
            original_complete_raw_preserved=True,restoration='owned-spans-only')
        if scoped:
            meta['settings_stability'].update(settings_applicability=stability['settings_applicability'],
                capture_integrity_verified=True,full_snapshot_static=False,atomic_snapshot=False)
    path=Path(output).absolute() if output is not None else root/'original.a7capture'
    need(path.parent.is_dir() and not any(p.is_symlink() for p in (path,*path.parents)),'Portable destination redirected or missing')
    fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w+b') as stream:
        with zipfile.ZipFile(stream,'w',compression=zipfile.ZIP_STORED,allowZip64=True) as archive:
            archive.writestr('capture.json',_json(meta))
            for name,source in members.items():archive.write(source,name)
        stream.flush();os.fsync(stream.fileno())
    result=verify_portable(path)
    need(result['body_binding']==capture['body_binding'],'Portable backup body differs')
    need(result['core']['archive_sha256']==capture['archive_sha256'] and result['core']['archive_size']==capture['archive_size'],
         'Portable core changed while packaging selected capture data')
    return dict(path=str(path),size=path.stat().st_size,sha256=result['archive_sha256'],verified=True,
                schema=meta['schema'],settings_capture_verified=True)


def _members(archive):
    infos=archive.infolist();names=[i.filename for i in infos]
    expected={'capture.json','original.a7backup','settings/manifest.json',*('settings/'+n for n in FILES),
              'evidence/version.txt','evidence/libJiritsu.so'}
    need(len(names)==len(set(names)) and set(names) in (expected,expected|SCOPE_MEMBERS),'Portable backup member inventory differs')
    total=0
    for info in infos:
        maximum=(backup.MAX_TOTAL_BYTES+backup.MAX_MANIFEST_BYTES if info.filename=='original.a7backup' else
                 160*1024*1024 if info.filename=='evidence/libJiritsu.so' else
                 2*1024*1024 if info.filename in ('capture.json',SCOPE_REPORT) else
                 BOUNDS.get(info.filename.removeprefix('settings/').removeprefix('settings-after/'),32768))
        need(0<info.file_size<=maximum and info.compress_type==zipfile.ZIP_STORED and not info.flag_bits&1
             and not info.is_dir() and info.compress_size==info.file_size,'Unexpected portable backup encoding/size')
        total+=info.file_size
    need(total<=backup.MAX_TOTAL_BYTES+200*1024*1024,'Portable backup exceeds complete scope bound')
    return set(names)


def _read_archive(path,destination,*,progress=None):
    """Read only fixed member names; never extract paths supplied by archive."""
    path=Path(path).absolute();need(not any(p.is_symlink() for p in (path,*path.parents)),'Redirected archive refused')
    flags=os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK
    notify(progress,'READ_OUTER_ARCHIVE')
    with os.fdopen(os.open(path,flags),'rb') as stream:
        before=os.fstat(stream.fileno());need(__import__('stat').S_ISREG(before.st_mode),'Regular portable backup required')
        with zipfile.ZipFile(stream) as archive:
            names=_members(archive);meta=json.loads(archive.read('capture.json'))
            data_only=meta.get('schema')=='a7m4-portable-capture/3'
            base_schema=meta.get('base_schema') if data_only else meta.get('schema')
            modern=base_schema in ('a7m4-portable-capture/2','a7m4-portable-capture/4')
            if data_only:
                history=meta.get('capture_history')
                need(base_schema in ('a7m4-portable-capture/1','a7m4-portable-capture/2','a7m4-portable-capture/4') and meta.get('data_integrity_verified') is True
                     and meta.get('normal_return_verified') is False and meta.get('origin_status')=='VERIFIED_BACKUP_EXIT_UNCONFIRMED'
                     and type(history) is dict and history.get('normal_return_verified') is False
                     and type(history.get('source_receipt_sha256')) is str and len(history['source_receipt_sha256'])==64,
                     'Unconfirmed capture history missing')
            need(meta.get('schema') in ('a7m4-portable-capture/1','a7m4-portable-capture/2','a7m4-portable-capture/3','a7m4-portable-capture/4')
                 and bool(SCOPE_MEMBERS.intersection(names))==modern
                 and set(meta.get('files',{}))==names-{'capture.json'}
                 and meta.get('complete') is True and meta.get('verified') is True
                 and (meta.get('normal_return_verified') is True or data_only) and meta.get('settings_capture_verified') is True
                 and meta.get('firmware_version')=='6.02','Portable backup manifest incomplete')
            members=sorted(names-{'capture.json'});copied=0;copied_bytes=0
            total_bytes=sum(archive.getinfo(name).file_size for name in members)
            notify(progress,'READ_OUTER_ARCHIVE',objects_done=0,objects_total=len(members),bytes_done=0,bytes_total=total_bytes)
            for name in members:
                target=destination/name;target.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
                h=sha256();count=0
                fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                with archive.open(name) as source,os.fdopen(fd,'wb') as output:
                    while chunk:=source.read(1024*1024):
                        output.write(chunk);h.update(chunk);count+=len(chunk);copied_bytes+=len(chunk)
                        notify(progress,'READ_OUTER_ARCHIVE',objects_done=copied,objects_total=len(members),bytes_done=copied_bytes,bytes_total=total_bytes)
                    output.flush();os.fsync(output.fileno())
                need(dict(size=count,sha256=h.hexdigest())==meta['files'][name],'Portable backup member differs: '+name)
                copied+=1
                notify(progress,'READ_OUTER_ARCHIVE',objects_done=copied,objects_total=len(members),bytes_done=copied_bytes,bytes_total=total_bytes,force=copied==len(members))
        after=os.fstat(stream.fileno())
        need((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==
             (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns),'Portable backup changed during read')
        notify(progress,'HASH_OUTER_ARCHIVE',bytes_done=0,bytes_total=before.st_size)
        stream.seek(0);digest=__import__('hashlib').file_digest(stream,'sha256').hexdigest()
        notify(progress,'HASH_OUTER_ARCHIVE',bytes_done=before.st_size,bytes_total=before.st_size,force=True)
    notify(progress,'VERIFY_CORE_ARCHIVE')
    core=backup.verify_backup(destination/'original.a7backup')
    current_scope=base_schema=='a7m4-portable-capture/4'
    need(core['scope_id']==(device_scope.ARCHIVE_SCOPE if current_scope else backup.SCOPE_ID)
         and core['object_count']==(device_scope.COUNT if current_scope else 73)
         and (meta.get('resource_profile')==device_scope.ID if current_scope else 'resource_profile' not in meta),'Portable core scope differs')
    notify(progress,'VERIFY_CORE_ARCHIVE',objects_done=core['object_count'],objects_total=core['object_count'],force=True)
    notify(progress,'VERIFY_SETTINGS')
    settings=load_snapshot(destination/'settings')
    if (meta['base_schema'] if meta['schema']=='a7m4-portable-capture/3' else meta['schema']) in ('a7m4-portable-capture/2','a7m4-portable-capture/4'):
        from .settings_scope import CAPTURE_PROFILE,capture_scope_report
        scope=capture_scope_report(settings,load_snapshot(destination/'settings-after'))
        need(read_private(destination/SCOPE_REPORT,2*1024*1024)==_json(scope),
             'Scoped observation is not reproducible from both complete settings originals')
        stated=meta.get('settings_stability',{})
        need(stated.get('profile')==CAPTURE_PROFILE and stated.get('report_sha256')==sha256(_json(scope)).hexdigest()
             and stated.get('raw_equal') is scope['raw_equal']
             and stated.get('settings_applicability') is scope['settings_applicability']
             and stated.get('capture_integrity_verified') is True and stated.get('full_snapshot_static') is False
             and stated.get('atomic_snapshot') is False,'Scoped applicability/integrity claims differ')
    from .usb_read import body_binding,VERSION_SHA256,LOADER_SHA256
    need(body_binding(settings.serial)==meta['body_binding'],'Portable settings/body binding differs')
    need(ident(read_private(destination/'evidence'/'version.txt',4096))['sha256']==VERSION_SHA256
         and ident(read_private(destination/'evidence'/'libJiritsu.so',160*1024*1024))['sha256']==LOADER_SHA256,'Portable firmware/service baseline differs')
    return dict(schema='a7m4-portable-verification/1',complete=True,verified=True,body_binding=meta['body_binding'],
                archive_sha256=digest,core=core,settings_capture_verified=True,camera_io=False,metadata=meta)


def verify_portable(path):
    with tempfile.TemporaryDirectory(prefix='a7m4-verify-capture-') as temporary:
        return _read_archive(path,Path(temporary).resolve())


def import_portable(path,output,*,progress=None):
    """Import with optional presentation, retaining every existing validator.

    A bounded ``output/import-progress.json`` is written automatically. An
    optional callback receives its published dicts. Neither can grant device
    admission or change the result; stdout remains the caller's final JSON.
    """
    root=Path(output).absolute()
    need(not root.exists() and root.parent.is_dir() and not any(p.is_symlink() for p in (root,*root.parents)),
         'New nonredirected import destination required')
    root.mkdir(mode=0o700)
    reporter=ImportProgress(root,callback=progress)
    reporter.emit('PREPARING')
    try:
        result=_import_portable(path,root,progress=reporter.emit)
    except BaseException as error:
        reporter.emit('FAILED',error_type=type(error).__name__,force=True)
        raise
    reporter.emit('COMPLETE',force=True)
    return result


def _import_portable(path,root,*,progress):
    verification=_read_archive(path,root,progress=progress)
    snapshot=root/'snapshot';snapshot.mkdir(mode=0o700);objects={}
    notify(progress,'VERIFY_NESTED_ARCHIVE',objects_total=verification['core']['object_count'])
    with backup._verified(root/'original.a7backup') as (archive,_,rows,core):
        current_scope=core['scope_id']==device_scope.ARCHIVE_SCOPE
        definitions=device_scope.OBJECTS if current_scope else dict(backup.REQUIRED_OBJECTS,**{'extras/SysSound.bin':device_scope.OBJECTS['extras/SysSound.bin']})
        need(set(r['path'] for r in rows)==set(definitions),'Portable core scope differs')
        copied=0;copied_bytes=0;total_bytes=sum(row['size'] for row in rows)
        notify(progress,'EXTRACT_SNAPSHOT',objects_done=0,objects_total=len(rows),bytes_done=0,bytes_total=total_bytes)
        for row in rows:
            need(row['state']=='present','Portable core requires all complete objects')
            target=snapshot/row['path'];target.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
            fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            with archive.open(row['archive_path']) as source,os.fdopen(fd,'wb') as output_file:
                while chunk:=source.read(1024*1024):
                    output_file.write(chunk);copied_bytes+=len(chunk)
                    notify(progress,'EXTRACT_SNAPSHOT',objects_done=copied,objects_total=len(rows),bytes_done=copied_bytes,bytes_total=total_bytes)
                output_file.flush();os.fsync(output_file.fileno())
            objects[row['path']]={k:row[k] for k in ('target_path','kind','size','sha256')};objects[row['path']]['stable']=True
            copied+=1
            notify(progress,'EXTRACT_SNAPSHOT',objects_done=copied,objects_total=len(rows),bytes_done=copied_bytes,bytes_total=total_bytes,force=copied==len(rows))
    _write(snapshot/'inventory.json',_json(dict(schema=backup.INVENTORY_SCHEMA,extra_objects=[] if current_scope else [
        dict(path='extras/SysSound.bin',target_path='/cp/SysSound.bin',state='present',kind='audio')])))
    meta=verification['metadata'];receipt=root/'capture.private.json'
    value=dict(schema=device_scope.CAPTURE_SCHEMA if current_scope else 'a7m4-toolbox-usb-backup/1',status='VERIFIED_BACKUP' if meta['normal_return_verified'] else 'VERIFIED_BACKUP_EXIT_UNCONFIRMED',complete=True,verified=True,
        archive_verified=True,normal_return_verified=meta['normal_return_verified'],settings_capture_verified=True,
        expected_object_count=len(objects),captured_object_count=len(objects),stable_object_count=len(objects),
        body_binding=meta['body_binding'],firmware_version='6.02',
        receipt=str(receipt),archive=str(root/'original.a7backup'),snapshot_dir=str(snapshot),
        archive_sha256=core['archive_sha256'],archive_size=core['archive_size'],objects=objects,
        portable_import=True,source_origin='unsigned-self-consistent-portable-capture',
        camera_io=False,current_camera_state_observed=False,
        historical_capture_camera_io=meta.get('camera_io'),
        portable_source=dict(path=str(Path(path).absolute()),sha256=verification['archive_sha256']),
        normal_return=dict(historical_only=True,current_camera_observed=False),
        service_exit=dict(historical_only=True,current_camera_observed=False))
    if current_scope:value['resource_profile']=device_scope.ID
    if (meta['base_schema'] if meta['schema']=='a7m4-portable-capture/3' else meta['schema']) in ('a7m4-portable-capture/2','a7m4-portable-capture/4'):
        from .settings_scope import capture_scope_report
        value['settings_stability']=capture_scope_report(load_snapshot(root/'settings'),load_snapshot(root/'settings-after'))
        value['settings_applicability']=dict(owned_scope_stable=value['settings_stability']['stable'],authorizes_device_write=False)
    if meta['schema']=='a7m4-portable-capture/3':
        history=meta['capture_history'];value['capture_history']=history
        value.update(host_release=history.get('host_release'),service_exit=history.get('service_exit'),
                     stop_safe=history.get('stop_safe'),error=history.get('error'),host_return_error=history.get('host_return_error'))
    _write(receipt,_json(value))
    from .capture_inputs import verified_capture,verified_capture_data
    notify(progress,'VERIFY_IMPORTED_FILES',objects_total=len(objects))
    (verified_capture if value['normal_return_verified'] else verified_capture_data)(receipt)
    notify(progress,'VERIFY_IMPORTED_FILES',objects_done=len(objects),objects_total=len(objects),force=True)
    return dict(schema='a7m4-portable-import/1',complete=True,verified=True,camera_io=False,
        receipt=str(receipt),snapshot_dir=str(snapshot),archive=str(root/'original.a7backup'),body_binding=meta['body_binding'],
        normal_return_verified=meta['normal_return_verified'],data_integrity_verified=True)
