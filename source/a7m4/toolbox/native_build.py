"""Offline reproducible build for fixed, data-free toolbox native helpers."""
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import subprocess

from ..research.pin_plan import _validate_elf
from .workspace import SOURCE


def build_workspace_probe(output, *, compiler=None):
    folder=Path(output).absolute()
    if folder.exists() or not folder.parent.is_dir() or any(p.is_symlink() for p in (folder,*folder.parents)):
        raise ValueError('New nonredirected helper build output required')
    command=[os.fspath(compiler or shutil.which('zig') or '')]
    if not command[0]:raise ValueError('Offline Zig 0.13.0 required; no download is attempted')
    folder.mkdir(mode=0o700)
    environment=dict(os.environ,ZIG_GLOBAL_CACHE_DIR=str(folder/'global-cache'),ZIG_LOCAL_CACHE_DIR=str(folder/'local-cache'))
    source=SOURCE.read_bytes()
    identity=sha256(source).digest()
    header=('static const B probe_identity[32]={'+','.join(map(str,identity))+'};\n').encode()
    (folder/'probe_identity.h').write_bytes(header)
    version=subprocess.run(command+['version'],capture_output=True,text=True,check=True,timeout=30,env=environment).stdout.strip()
    if version!='0.13.0':raise ValueError('Reviewed Zig 0.13.0 required')
    flags=['cc','-target','aarch64-linux-gnu','-std=c11','-O2','-ffreestanding','-fno-builtin',
        '-Wall','-Wextra','-Werror','-shared','-fPIC','-fno-stack-protector','-fno-unwind-tables',
        '-fno-asynchronous-unwind-tables','-nostdlib','-g0','-Wl,--strip-debug','-Wl,--no-undefined',
        '-Wl,--build-id=none','-Wl,-Bsymbolic','-Wl,-z,noexecstack','-I',str(folder)]
    binaries=[]
    for name in ('workspace-probe.so','workspace-probe-repeat.so'):
        path=folder/name
        subprocess.run(command+flags+[str(SOURCE),'-o',str(path)],capture_output=True,check=True,timeout=180,env=environment)
        raw=path.read_bytes()
        if not 0<len(raw)<65536:raise ValueError('Native helper violates strict upload bound')
        _validate_elf(raw)
        path.chmod(0o600);binaries.append(raw)
    if binaries[0]!=binaries[1] or SOURCE.read_bytes()!=source:
        raise ValueError('Double build/source identity failed')
    result=dict(schema='a7m4-workspace-probe-build/1',status='BUILT_OFFLINE_NOT_DEVICE_VALIDATED',
                source_sha256=identity.hex(),header_sha256=sha256(header).hexdigest(),
                binary_sha256=sha256(binaries[0]).hexdigest(),binary_bytes=len(binaries[0]),
                compiler='Zig 0.13.0',double_build_identical=True,elf=_validate_elf(binaries[0]),
                camera_io=False,network_io=False,persistent_device_writes=False,
                device_validation='not-performed',bootstrap_upload_not_prebudgeted=True)
    (folder/'build.json').write_text(json.dumps(result,indent=2)+'\n')
    return result
