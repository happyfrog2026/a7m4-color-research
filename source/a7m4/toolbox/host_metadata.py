"""Read-only macOS metadata survey of media under one normal USB A7 IV.

Only ioreg and diskutil info -plist run. No USB library, camera protocol,
mount/unmount, device open, raw read, format or storage write is provided.
The sole output is a new private host JSON receipt, never a camera volume.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import plistlib
import re
import subprocess
import sys
import time
from xml.parsers.expat import ExpatError

from hashlib import sha256

class ToolError(ValueError):
    def __init__(self, code, message, details=None):
        self.code = code
        self.details = details or {}
        super().__init__(message)

def digest(data):
    return sha256(data).hexdigest()

def require(value, code, message):
    if not value:
        raise ToolError(code, message)

MODEL = "ILCE-7M4"
VENDOR = 0x054c
MSC_PID = 0x0da5
SCHEMA = "a7m4-macos-storage-survey/1"
IOREG = ("/usr/sbin/ioreg", "-p", "IOService", "-r", "-c", "IOUSBHostDevice", "-l", "-a")
# ioreg(8): -d1 shows each matching subtree root only, without children.
IDENTITY_IOREG = IOREG + ('-d', '1')
DISKUTIL = ("/usr/sbin/diskutil", "info", "-plist")
BSD_NAME = re.compile(r"disk[0-9]+(?:s[0-9]+)*")
INFO_FIELDS = (
    "DeviceIdentifier", "DeviceNode", "ParentWholeDisk", "WholeDisk", "TotalSize", "IOKitSize", "Size", "DiskSize", "Internal", "BusProtocol",
    "FilesystemType", "FilesystemName", "FilesystemUserVisibleName", "Content", "Mounted", "MountPoint",
    "VolumeName", "VolumeUUID", "DiskUUID", "MediaUUID", "FreeSpace", "VolumeFreeSpace", "VolumeTotalSpace", "VolumeSize",
    "FilesystemBlockSize", "AllocationBlockSize", "DeviceBlockSize", "VolumeAllocationBlockSize",
    "Writable", "WritableMedia", "ReadOnlyMedia", "ReadOnlyVolume", "RemovableMedia",
    "MediaType", "OpticalDeviceType", "OpticalMediaType",
)


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _children(node):
    children = node.get("IORegistryEntryChildren", [])
    require(isinstance(children, list) and all(isinstance(c, dict) for c in children),
            "REGISTRY", "Malformed IORegistry children")
    return children


def _walk(tree):
    if isinstance(tree, list):
        for row in tree:
            yield from _walk(row)
    else:
        require(isinstance(tree, dict), "REGISTRY", "Malformed IORegistry node")
        yield tree
        for child in _children(tree):
            yield from _walk(child)


def _positive(value, label):
    require(type(value) is int and value > 0, "METADATA", "Missing or invalid " + label)
    return value


def _camera_identity(node):
    name=node.get('USB Product Name');pid=node.get('idProduct')
    observed=dict(product_name=name if isinstance(name,str) else None,product_id=pid if type(pid) is int else None,
                  vendor_id=node.get('idVendor'),location_id=node.get('locationID'))
    def refuse(code,message):raise ToolError(code,message,dict(observed=observed))
    if pid==0x0336:
        refuse('MODE_PENDING','索尼 USB 设备仍在服务模式，尚不能确认为目标机身的正常 MSC 身份。')
    if name not in (None,'',MODEL,'USB Bus-powered Device'):
        refuse('MODEL','检测到的索尼设备型号不是 ILCE-7M4。')
    if name in (None,'','USB Bus-powered Device'):
        refuse('MODE_PENDING' if pid==0x0336 else 'MODEL_PENDING',
               '设备描述尚未就绪或当前为供电／非 MSC 状态；请完成 Mac 的“允许配件连接”并选择 MSC。')
    if pid!=MSC_PID:
        refuse('MODE_PENDING' if pid==0x0336 else 'MODE','相机仍在服务模式或非 MSC 模式，请等待正常大容量存储返回。')
    result = dict(model=MODEL, vendor_id=VENDOR, product_id=MSC_PID,
                  registry_id=_positive(node.get("IORegistryEntryID"), "camera registry identity"),
                  location_id=_positive(node.get("locationID"), "camera USB location"))
    require(result["location_id"] <= 0xffffffff, "METADATA", "Invalid USB location width")
    serial = node.get("USB Serial Number")
    if serial is not None:
        require(isinstance(serial, str) and len(serial) <= 4096, "METADATA", "Invalid private USB identity")
        result["usb_serial"] = serial
    return result


def _media(camera):
    media = {}

    def collect(node, parent=None, root=False):
        # A distinct nested USB device is not this camera's storage function.
        if not root and node.get("IOObjectClass") == "IOUSBHostDevice":
            return
        if node.get("IOObjectClass") == "IOMedia" and node.get("BSD Name"):
            name = node["BSD Name"]
            require(isinstance(name, str) and BSD_NAME.fullmatch(name), "MEDIA", "Unexpected camera BSD identifier")
            whole = node.get("Whole")
            require(type(whole) is bool, "MEDIA", "Media whole/partition state is missing")
            if whole:
                require(re.fullmatch(r"disk[0-9]+", name), "MEDIA", "Whole media has a partition identifier")
                parent = name
            else:
                require(parent is not None and name.startswith(parent + "s"),
                        "MEDIA", "Partition is outside a camera whole-media parent")
            row = dict(device_identifier=name, parent_whole_disk=parent, whole=whole,
                       registry_id=_positive(node.get("IORegistryEntryID"), "media registry identity"),
                       total_size=_positive(node.get("Size"), "IORegistry media capacity"))
            if "Base" in node:
                require(type(node["Base"]) is int and node["Base"] >= 0, "MEDIA", "Invalid partition base")
                row["base"] = node["Base"]
            require(name not in media or media[name] == row, "MEDIA", "Conflicting duplicate camera media")
            media[name] = row
        for child in _children(node):
            collect(child, parent)

    collect(camera, root=True)
    require(len(media) <= 64, "MEDIA", "Unexpected number of camera media entries")
    for row in media.values():
        parent = media.get(row["parent_whole_disk"])
        require(parent is not None and parent["whole"], "MEDIA", "Camera partition lacks a verified whole disk")
        require(row["total_size"] <= parent["total_size"], "MEDIA", "Partition exceeds its whole-media size")
        if not row["whole"] and "base" in row:
            require(row["base"] + row["total_size"] <= parent["total_size"], "MEDIA", "Partition extent exceeds camera media")
    return [media[name] for name in sorted(media)]


def parse_registry(tree):
    # ioreg -r may repeat one camera under its hub and as its own root.
    # Deduplicate only a matching registry object, never different devices.
    cameras = {}
    for node in _walk(tree):
        if node.get("IOObjectClass") == "IOUSBHostDevice" and node.get("idVendor") == VENDOR:
            key = _positive(node.get("IORegistryEntryID"), "Sony registry identity")
            cameras.setdefault(key, []).append(node)
    if not cameras:raise ToolError('NO_DEVICE','未发现索尼相机；请检查数据线、MSC 和 Mac 的“允许配件连接”。',dict(sony_device_count=0))
    if len(cameras)!=1:raise ToolError('MULTIPLE_DEVICES','发现多个索尼 USB 设备，请只连接目标相机。',dict(sony_device_count=len(cameras)))
    copies = next(iter(cameras.values()))
    snapshots = [dict(camera=_camera_identity(node), media=_media(node)) for node in copies]
    require(all(value == snapshots[0] for value in snapshots), "UNSTABLE", "Duplicate camera registry views disagree")
    return snapshots[0]


def validate_info(info, medium):
    require(isinstance(info, dict), "DISK", "diskutil did not return an information dictionary")
    name, whole = medium["device_identifier"], medium["whole"]
    require(info.get("DeviceIdentifier") == name and info.get("WholeDisk") is whole,
            "DISK", "diskutil media identity or whole/partition state differs from IORegistry")
    require(info.get("Internal") is False and info.get("BusProtocol") == "USB",
            "DISK", "Selected camera media is not an external USB disk")
    # On an actual exFAT/FAT partition TotalSize can be filesystem capacity,
    # smaller than its IOMedia extent. Bind device bytes via IOKitSize/Size;
    # do not reject valid media or relabel a filesystem size as device size.
    size_key = next((key for key in ("IOKitSize", "Size", "DiskSize") if key in info), None)
    require(size_key is not None and type(info[size_key]) is int and info[size_key] == medium["total_size"],
            "DISK", "diskutil device capacity differs from IORegistry or lacks an independent size")
    if "DeviceNode" in info:
        require(info["DeviceNode"] == "/dev/" + name, "DISK", "diskutil device node differs")
    if whole:
        require(info.get("ParentWholeDisk") in (None, name), "DISK", "Whole disk has an unexpected parent")
    else:
        require(info.get("ParentWholeDisk") == medium["parent_whole_disk"],
                "DISK", "Partition parent differs from its camera registry subtree")
    selected = {key: info[key] for key in INFO_FIELDS if key in info}
    for key, value in selected.items():
        require(type(value) in (str, int, bool) and (not isinstance(value, str) or len(value) <= 8192),
                "DISK", "Unsupported selected disk metadata value")
    for key in ("FreeSpace", "VolumeFreeSpace", "VolumeTotalSpace", "VolumeSize", "TotalSize", "IOKitSize", "Size", "DiskSize",
                "FilesystemBlockSize", "AllocationBlockSize", "DeviceBlockSize", "VolumeAllocationBlockSize"):
        if key in selected:
            require(type(selected[key]) is int and selected[key] >= 0,
                    "DISK", "Invalid filesystem size/free-space metadata")
    for key in ("FilesystemType", "FilesystemName", "FilesystemUserVisibleName", "MountPoint", "VolumeName", "VolumeUUID"):
        if key in selected:
            require(isinstance(selected[key], str), "DISK", "Invalid textual filesystem metadata")
    if "Mounted" in selected:
        require(type(selected["Mounted"]) is bool, "DISK", "Invalid mounted-state metadata")
        require(not selected.get("MountPoint") or selected["Mounted"], "DISK", "Mount point contradicts unmounted state")
    return selected


def _command(command, runner, *, stage='host-metadata', deadline=None, clock=time.monotonic):
    # Fixed commands only. Identity waits pass one absolute shared deadline.
    from .run_log import event, clean
    start=clock();remaining=None if deadline is None else deadline-start
    details=dict(command=list(command),stage=stage,returncode=None,stdout_type=None,stdout_bytes=None,elapsed_seconds=0,stderr_tail='')
    def failed(code,message,error=None):
        details['elapsed_seconds']=max(0,clock()-start)
        event('host-command-error',code=code,**details)
        failure=ToolError(code,message,dict(details))
        if error is not None:raise failure from error
        raise failure
    if remaining is not None and remaining<=0:failed('HOST_DEADLINE','等待相机连接状态已到时；未重新打开相机服务。')
    try:
        result=runner(list(command),capture_output=True,check=False,timeout=min(20,remaining) if remaining is not None else 20)
    except (OSError,subprocess.SubprocessError) as error:
        raw=getattr(error,'stdout',None);stderr=getattr(error,'stderr',b'') or b''
        details.update(stdout_type=type(raw).__name__,stdout_bytes=len(raw) if isinstance(raw,(str,bytes)) else None,
            stderr_tail=clean(stderr[-2048:].decode('utf-8',errors='replace') if isinstance(stderr,bytes) else str(stderr)[-2048:]))
        failed('HOST_TIMEOUT' if isinstance(error,subprocess.TimeoutExpired) else 'HOST_COMMAND','Mac 宿主状态命令未能完成。',error)
    raw=result.stdout;stderr=getattr(result,'stderr',b'') or b''
    details.update(returncode=result.returncode,stdout_type=type(raw).__name__,stdout_bytes=len(raw) if isinstance(raw,(str,bytes)) else None,
        stderr_tail=clean(stderr[-2048:].decode('utf-8',errors='replace') if isinstance(stderr,bytes) else str(stderr)[-2048:]))
    if result.returncode!=0:failed('HOST_COMMAND','Mac 宿主状态命令返回失败。')
    if not isinstance(raw,bytes):failed('HOST_TYPE','Mac 状态响应类型不符。')
    if not raw:failed('HOST_EMPTY','Mac 暂未提供设备状态；请保持解锁并完成“允许配件连接”。')
    if len(raw)>16*1024*1024:failed('HOST_OVERSIZE','Mac 状态响应超过 16 MiB 边界，已停止。')
    try:value=plistlib.loads(raw)
    except (ValueError,plistlib.InvalidFileException,ExpatError) as error:failed('HOST_INVALID_PLIST','Mac 状态响应不是有效 plist。',error)
    details['elapsed_seconds']=max(0,clock()-start);event('host-command-result',**details)
    return value,digest(raw)


def identity_survey(*,runner=subprocess.run,deadline=None,clock=time.monotonic):
    """Two shallow OS identity observations; no diskutil or USB library."""
    def identity(tree):
        nodes={}
        for node in _walk(tree):
            if node.get('IOObjectClass')=='IOUSBHostDevice' and node.get('idVendor')==VENDOR:
                key=_positive(node.get('IORegistryEntryID'),'Sony registry identity')
                nodes.setdefault(key,[]).append(node)
        if not nodes:raise ToolError('NO_DEVICE','未发现索尼相机，请检查数据线、MSC 和 Mac 的“允许配件连接”。',dict(sony_device_count=0))
        if len(nodes)!=1:raise ToolError('MULTIPLE_DEVICES','发现多个索尼 USB 设备，请只连接目标相机。',dict(sony_device_count=len(nodes)))
        copies=[_camera_identity(node) for node in next(iter(nodes.values()))];require(all(v==copies[0] for v in copies),'UNSTABLE','USB 身份观察发生变化。')
        return copies[0]
    first,one=_command(IDENTITY_IOREG,runner,stage='identity-before',deadline=deadline,clock=clock)
    before=identity(first)
    second,two=_command(IDENTITY_IOREG,runner,stage='identity-after',deadline=deadline,clock=clock)
    after=identity(second);require(before==after,'UNSTABLE','USB 身份或端口在检查期间改变。')
    if deadline is not None and clock()>deadline:
        raise ToolError('HOST_DEADLINE','只读连接检查已超过本次等待预算。',dict(stage='identity-after',command=list(IDENTITY_IOREG)))
    metadata=dict(camera=after,media=[],ioreg_before_sha256=one,ioreg_after_sha256=two,identity_only=True)
    return dict(schema=SCHEMA,created=datetime.now(timezone.utc).isoformat(),read_only=True,camera_protocol_requests=0,
                metadata=metadata,metadata_sha256=digest(_canonical(metadata)))


def survey(*, runner=subprocess.run):
    before_tree, before_sha = _command(IOREG, runner, stage="topology-before")
    before = parse_registry(before_tree)
    disks = []
    for medium in before["media"]:
        value, raw_sha = _command(DISKUTIL + ("/dev/" + medium["device_identifier"],), runner, stage="disk-info:"+medium["device_identifier"])
        disks.append(dict(registry=medium, diskutil=validate_info(value, medium), diskutil_plist_sha256=raw_sha))
    after_tree, after_sha = _command(IOREG, runner, stage="topology-after")
    after = parse_registry(after_tree)
    require(before == after, "UNSTABLE", "Camera position, identity or media changed during host metadata survey")
    metadata = dict(camera=before["camera"], media=disks, stable_snapshot=after,
                    ioreg_before_sha256=before_sha, ioreg_after_sha256=after_sha)
    return dict(schema=SCHEMA, created=datetime.now(timezone.utc).isoformat(),
                read_only=True, camera_protocol_requests=0, metadata=metadata,
                metadata_sha256=digest(_canonical(metadata)),
                omissions=["camera-side SD slot/mount identity", "camera-side filesystem driver support",
                           "file write/backup throughput", "raw device contents", "firmware/CP NOR coverage"])

