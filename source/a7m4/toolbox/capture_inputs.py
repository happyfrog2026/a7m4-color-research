"""Verify an existing complete capture without importing any device backend."""
from hashlib import sha256
import json
import os
from pathlib import Path
import stat

from ..research import backup
from .. import resource_profile as device_scope


def read_private(path,maximum):
    path=Path(path).absolute()
    if any(p.is_symlink() for p in (path,*path.parents)):
        raise ValueError('Redirected capture input refused')
    before=path.stat()
    if not stat.S_ISREG(before.st_mode) or not 0<before.st_size<=maximum:
        raise ValueError('Capture input must be a bounded regular file')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        opened=os.fstat(stream.fileno())
        if (opened.st_dev,opened.st_ino)!=(before.st_dev,before.st_ino) or not stat.S_ISREG(opened.st_mode):
            raise ValueError('Capture input changed while opening')
        raw=stream.read(maximum+1)
        after=os.fstat(stream.fileno())
    if len(raw)>maximum:
        raise ValueError('Capture input exceeds its read bound')
    if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns):
        raise ValueError('Capture input changed while reading')
    return raw


def _verified_capture(path, *, require_normal_return=True):
    path=Path(path).absolute()
    value=json.loads(read_private(path,2*1024*1024))
    definitions=device_scope.capture_definitions(value,backup.REQUIRED_OBJECTS)
    count=len(definitions)
    if (path.name!='capture.private.json'
            or value.get('status') not in (('VERIFIED_BACKUP',) if require_normal_return else ('VERIFIED_BACKUP','VERIFIED_BACKUP_EXIT_UNCONFIRMED'))
            or any(value.get(k) is not True for k in ('complete','verified','archive_verified'))
            or (require_normal_return and value.get('normal_return_verified') is not True)
            or (not require_normal_return and type(value.get('normal_return_verified')) is not bool)
            or (not require_normal_return and (value.get('status')=='VERIFIED_BACKUP') != (value.get('normal_return_verified') is True))
            or any(value.get(k)!=count for k in ('expected_object_count','captured_object_count','stable_object_count'))):
        raise ValueError('A complete verified scope-bound capture with confirmed service exit is required')
    for field,expected in (('receipt',path),('archive',path.parent/'original.a7backup'),
                           ('snapshot_dir',path.parent/'snapshot')):
        if value.get(field)!=str(expected):raise ValueError('Capture output path binding differs')
    binding=value.get('body_binding',{})
    if (binding.get('model')!='ILCE-7M4' or binding.get('scheme')!='ap-00e70003-hex-text-sha256'
            or not isinstance(binding.get('serial_sha256'),str) or len(binding['serial_sha256'])!=64):
        raise ValueError('Capture body binding is missing')
    with backup._verified(Path(value['archive'])) as (_,_,archive_objects,archive):
        archive_rows={row['path']:dict(row) for row in archive_objects}
    expected_scope=device_scope.ARCHIVE_SCOPE if value['schema']==device_scope.CAPTURE_SCHEMA else backup.SCOPE_ID
    if archive['scope_id']!=expected_scope:raise ValueError('Capture and archive scope identities differ')
    if (archive['verified'] is not True or archive['complete'] is not True or archive['object_count']!=count
            or archive['archive_sha256']!=value.get('archive_sha256')
            or archive['archive_size']!=value.get('archive_size')):
        raise ValueError('Complete backup archive identity differs from capture')
    for name,row in value.get('objects',{}).items():
        if name not in definitions:
            raise ValueError('Unexpected capture object')
        if row.get('stable') is not True:raise ValueError('Unstable backup object')
        archived=archive_rows.get(name)
        definition=definitions[name]
        if (not archived or archived['state']!='present'
                or any(archived.get(key)!=row.get(key) for key in ('target_path','kind','size','sha256'))
                or any(row.get(key)!=definition[key] for key in ('target_path','kind'))):
            raise ValueError('Archive, capture and snapshot object identities differ: '+name)
        raw=read_private(path.parent/'snapshot'/name,160*1024*1024)
        if len(raw)!=row.get('size') or sha256(raw).hexdigest()!=row.get('sha256'):
            raise ValueError('Captured snapshot object differs: '+name)
    if set(value.get('objects',{}))!=set(definitions):
        raise ValueError('Capture inventory is incomplete')
    if set(archive_rows)!=set(value['objects']):
        raise ValueError('Archive does not contain the same complete capture scope')
    return value


def verified_capture(path):
    """Legacy device admission stays strict about confirmed normal return."""
    return _verified_capture(path)


def verified_capture_data(path):
    """Local data integrity only; does not grant any device operation."""
    return _verified_capture(path,require_normal_return=False)


def verified_device_capture(path):
    """Fully verify the original archive first, then expose only current device files.

    Receipt and archive hashes/schema/identity remain the original ones. This is
    an execution view, never a replacement receipt or a rewritten old archive.
    """
    from ..resource_profile import OBJECTS
    value = verified_capture(path)
    return dict(value, objects={name:row for name,row in value['objects'].items() if name in OBJECTS})
