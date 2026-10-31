"""Load only the explicitly frozen restoration helper source allowlist."""
from hashlib import sha256
import json
from pathlib import Path
import sys
import types

from .capture_inputs import read_private

SOURCE_ROOT=Path(__file__).with_name('restore_helpers')/'source'
MANIFEST_SHA256='fbbab472f4439bdf48bdc55feb621435a11c2216be229c4cdae3e2b817c78bbe'


def verify_source():
    raw=read_private(SOURCE_ROOT/'restore-helpers-source-manifest.json',65536)
    if sha256(raw).hexdigest()!=MANIFEST_SHA256:raise ValueError('Frozen restoration source manifest differs')
    manifest=json.loads(raw);rows=manifest['files']
    if len(rows)!=27:raise ValueError('Frozen restoration source inventory differs')
    result={}
    for row in rows:
        relative=Path(row['path'])
        if relative.is_absolute() or '..' in relative.parts:raise ValueError('Unsafe restoration source path')
        blob=read_private(SOURCE_ROOT/relative,256*1024)
        if len(blob)!=row['size'] or sha256(blob).hexdigest()!=row['sha256']:
            raise ValueError('Frozen restoration source differs: '+str(relative))
        result[row['path']]=blob
    return result


def load_helper(kind):
    if kind not in ('tail-restore','resource-delta','original-atomic'):raise ValueError('Unknown restoration helper')
    files=verify_source();package_name='_a7m4_reviewed_'+kind.replace('-','_')
    package=types.ModuleType(package_name);package.__path__=[str(SOURCE_ROOT/kind)]
    sys.modules[package_name]=package
    modules=[]
    for name in (('worker',) if kind=='original-atomic' else ('worker','session')):
        path=SOURCE_ROOT/kind/(name+'.py');module=types.ModuleType(package_name+'.'+name)
        module.__file__=str(path);module.__package__=package_name
        sys.modules[module.__name__]=module;setattr(package,name,module)
        # Compile only already hashed in-memory source; session's relative
        # worker import resolves to the same verified in-memory module.
        exec(compile(files[kind+'/'+name+'.py'],str(path),'exec'),module.__dict__)
        modules.append(module)
    return tuple(modules)
