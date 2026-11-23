"""Source-only forward closure, imported only after complete pinned verification."""
from hashlib import sha256
import json
from pathlib import Path
import types
from .capture_inputs import read_private

SOURCE_ROOT=Path(__file__).with_name('restore_closure')/'source'
MANIFEST_SHA256='7bf9f2464315c4cc760ce31f5ff5374c92c19661e67b138b839acdd90c562539'


def verify_closure():
    raw=read_private(SOURCE_ROOT/'closure-source-manifest.json',32768)
    if sha256(raw).hexdigest()!=MANIFEST_SHA256:raise ValueError('Forward closure source manifest changed')
    manifest=json.loads(raw)
    if len(manifest['files'])!=16:raise ValueError('Exact16-file source closure required')
    files={}
    for row in manifest['files']:
        path=row['path']
        if path.startswith('/') or any(p in ('','.','..') for p in path.split('/')) or path in files:
            raise ValueError('Invalid closure source path')
        data=read_private(SOURCE_ROOT/path,128*1024)
        if len(data)!=row['size'] or sha256(data).hexdigest()!=row['sha256']:raise ValueError('Forward closure source file changed')
        files[path]=data
    return files


def load_ro():
    files=verify_closure();name='usr-ro/worker.py'
    module=types.ModuleType('a7m4_portable_original_usr_ro');module.__file__=str(SOURCE_ROOT/name)
    exec(compile(files[name],module.__file__,'exec'),module.__dict__)
    return module
