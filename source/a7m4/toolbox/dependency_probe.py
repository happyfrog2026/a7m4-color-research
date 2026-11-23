"""Load local native dependencies without creating a USB backend or device.

This is a loadability check, never a Gatekeeper override or a device grant.
"""
from pathlib import Path
import ctypes
import hashlib
import importlib
import json
import platform
import subprocess
import sys
import traceback

SCHEMA = 'a7m4-native-dependency-probe/1'
MESSAGE = 'Mac 本地依赖无法加载或被系统拦截；未发送相机协议请求。请查看诊断日志。'


def _native_metadata(path):
    """Read identity/policy metadata only; codesign validity is not trust."""
    row=dict(path=str(path),exists=path.is_file(),quarantine_present=None,provenance_present=None)
    if not row['exists']:return row
    try:
        row['bytes']=path.stat().st_size
        if row['bytes']<=64*1024*1024:row['sha256']=hashlib.sha256(path.read_bytes()).hexdigest()
        if sys.platform=='darwin':
            result=subprocess.run(['/usr/bin/codesign','--verify','--strict','--arch','arm64',str(path)],
                capture_output=True,text=True,timeout=15)
            row['arm64_codesign_integrity']='VALID' if result.returncode==0 else 'INVALID'
            row['codesign_diagnostic']=result.stderr
            attrs=subprocess.run(['/usr/bin/xattr',str(path)],capture_output=True,text=True,timeout=5)
            if attrs.returncode==0:
                names=set(attrs.stdout.splitlines())
                row.update(quarantine_present='com.apple.quarantine' in names,provenance_present='com.apple.provenance' in names)
        row['system_trust']='NOT_INFERRED_FROM_CODESIGN'
    except (OSError,subprocess.SubprocessError) as error:row['metadata_error']=str(error)
    return row


def _cause(error):
    rows=[];seen=set()
    while error is not None and id(error) not in seen and len(rows)<8:
        seen.add(id(error))
        rows.append(dict(type=type(error).__name__,message=str(error),
            frames=[dict(file=f.filename,line=f.lineno,function=f.name)
                    for f in traceback.extract_tb(error.__traceback__)[-12:]]))
        error=error.__cause__ or error.__context__
    return rows


def system_metadata():
    build=None
    if sys.platform=='darwin':
        try:build=subprocess.check_output(['/usr/bin/sw_vers','-buildVersion'],text=True,timeout=5).strip()
        except (OSError,subprocess.SubprocessError):pass
    return dict(platform=platform.system(),kernel=platform.release(),architecture=platform.machine(),
        macos=platform.mac_ver()[0],os_build=build,python=sys.version,executable=sys.executable)


def probe(*, vendor=None, include_optional_aes=False):
    candidate=Path(__file__).resolve().parents[3]/'vendor'
    vendor=Path(vendor).resolve() if vendor is not None else candidate.resolve() if candidate.is_dir() else None
    native_files=[]
    if vendor is not None:
        native_files=[_native_metadata(vendor/name) for name in (
            'Cryptodome/Hash/_SHA256.abi3.so','Cryptodome/Cipher/_raw_aes.abi3.so',
            'Cryptodome/Cipher/_raw_aesni.abi3.so','Cryptodome/Cipher/_raw_ecb.abi3.so',
            'Cryptodome/Util/_cpuid_c.abi3.so','libusb_package/libusb-1.0.dylib')]
    checks=[]
    def module(name):
        value=importlib.import_module(name)
        origin=Path(value.__file__).resolve()
        if vendor is not None and not origin.is_relative_to(vendor):
            raise ValueError('Dependency origin is outside the bundled vendor: '+str(origin))
        return value,origin
    def check(name,action,*,required=True):
        try:checks.append(dict(name=name,required=required,ready=True,**action()))
        except Exception as error:checks.append(dict(name=name,required=required,ready=False,causes=_cause(error)))
    def sha():
        value=hashlib.sha256(b'abc')
        if value.hexdigest()!='ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad':
            raise ValueError('SHA256 known-answer test failed')
        implementation=sys.modules.get(type(value).__module__)
        origin=getattr(getattr(implementation,'__spec__',None),'origin',None)
        return dict(module_path=hashlib.__file__,implementation_module=type(value).__module__,implementation_origin=origin,
            constructor_module=hashlib.sha256.__module__,provider='Python standard library',known_answer='SHA256 abc')
    def aes():
        value,path=module('Cryptodome.Cipher.AES')
        # FIPS-197 AES-128 example; exercise encrypt and decrypt native paths.
        key=bytes.fromhex('000102030405060708090a0b0c0d0e0f')
        plain=bytes.fromhex('00112233445566778899aabbccddeeff')
        cipher=bytes.fromhex('69c4e0d86a7b0430d8cdb78070b4c55a')
        if value.new(key,value.MODE_ECB).encrypt(plain)!=cipher or value.new(key,value.MODE_ECB).decrypt(cipher)!=plain:
            raise ValueError('AES128 known-answer test failed')
        return dict(module_path=str(path),known_answer='FIPS197 AES128 encrypt/decrypt')
    def usb_library():
        value,path=module('libusb_package')
        # No find_library fallback, backend construction, libusb_init or USB API.
        name={'darwin':'libusb-1.0.dylib','linux':'libusb-1.0.so','win32':'libusb-1.0.dll'}.get(sys.platform)
        if name is None:raise ValueError('Unsupported dependency probe platform')
        library=path.parent/name
        if library.is_symlink() or not library.is_file():raise ValueError('Bundled libusb library missing or redirected: '+str(library))
        library=library.resolve()
        ctypes.CDLL(str(library))
        return dict(module_path=str(path),library_path=str(library),operation='dlopen only; no symbols called')
    check('SHA256',sha);check('libusb-dlopen',usb_library)
    # AES is not consumed by this PMCA service closure. Never load it on the
    # default readiness path or let an optional diagnostic block that path.
    if include_optional_aes:check('AES128',aes,required=False)
    ready=all(row['ready'] for row in checks if row['required'])
    return dict(schema=SCHEMA,status='LOCAL_DEPENDENCIES_READY' if ready else 'LOCAL_DEPENDENCIES_NOT_READY',
        ready=ready,camera_io=False,usb_backend_created=False,usb_initialized=False,
        camera_protocol_requests_sent=False,checks=checks,native_files=native_files,vendor_path=str(vendor) if vendor else None,
        system=system_metadata(),
        error=None if ready else MESSAGE)


def main():
    value=probe();print(json.dumps(value,ensure_ascii=False,allow_nan=False))
    return 0 if value['ready'] else 2
