"""Explicit ordinary-USB read capture, with no import-time device activity.

ServiceSession/ReadChannel are adapted from a7m4/service_read.py (MIT,
A7M4 Fastboot Toolkit contributors), source SHA-256
473202e636c0842c34d30c7c4e5c6d629b447e0fa07365bddbb4b1dc6bbb3472.
Serial binding follows a7m4/checkpoint.py (source SHA-256
 d9133307e2350fb508661347a1cfc22c854fea52eb79af31df4f54c6bbef9a82).
Only ServiceSession.__enter__ imports PMCA/PyUSB and discovers USB. This
module has no native worker, SET_FILE2, write/save-settings, memory, or block
write operation. Caller owns explicit user authorization, hardware exclusion,
and release of the same camera's mounted MSC volumes before real entry.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import importlib
import json
import os
from pathlib import Path
import stat
import struct
import sys
import time
import uuid
import traceback
from typing import Callable

from ..research import backup
from .run_log import event, clean

MODEL = "ILCE-7M4"
SERIAL_SCHEME = "ap-00e70003-hex-text-sha256"
MAX_FILE = 160 * 1024 * 1024
MAX_TOTAL = backup.MAX_TOTAL_BYTES
MAX_TRANSFER = 0x100000
HEADER = struct.Struct("<IHHBBBB")
from .. import resource_profile as device_scope

CAPTURE_TARGETS = {path: dict(row) for path, row in device_scope.OBJECTS.items()}
CAPTURE_TARGETS["extras/SysSound.bin"] = {"target_path": "/cp/SysSound.bin", "kind": "audio"}
EVIDENCE_TARGETS = {"version.txt": "/version.txt", "libJiritsu.so": "/usr/lib/libJiritsu.so"}
READ_TARGETS = frozenset(row["target_path"] for row in CAPTURE_TARGETS.values()) | frozenset(EVIDENCE_TARGETS.values())
# Full retained 6.02 version.txt identity. Its content is a build identifier,
# not the UTF-8 text "6.02". Pinning avoids inventing a firmware parser.
VERSION_SHA256 = "b5377b8e08ba1f7a1105bcb6af07187414a5493a3d4622f02b7ad8a2578c87e5"
LOADER_SHA256 = "3b19665f84bcd1b837a3b9377b40a91893010ff9732be71a430f3d0265c72c69"
PMCA_SOURCE = {
    "url": "https://github.com/ma1co/Sony-PMCA-RE", "license": "MIT",
    "copyright": "Copyright (c) 2015 ma1co", "destination": "third_party/pmca",
    "embedded_source_credit": "pmca/usb/crypto.py credits https://github.com/ajalt/python-sha1",
    "files_sha256": {
        "LICENSE.txt": "a485f27d0b22eb7fd9b9419795695d0a1750ea32c961d11c1dd8ddade564dedf",
        "pmca/__init__.py": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "pmca/util/__init__.py": "1bf318b75faf450011123ce430becc87aec8a7a161765afe38c498cdd20cbacf",
        "pmca/usb/__init__.py": "db2fd3d0dfa2e6f315a14291be8951a5092875e8e5858183cabf2cec46a0fcda",
        "pmca/usb/sony.py": "b3acf2450a8a7827228988d47d8a0da16e20ef341450027d21cb0579ca66ae51",
        "pmca/usb/constants.py": "94bf081d3c1a51a60cf8fc214dce25a491413d4d786716460fde3fba832eb692",
        "pmca/usb/crypto.py": "74660a42235f7efac6f47f38e2151049647bd0bc61ed6eb0763538815b2b6886",
        "pmca/usb/driver/__init__.py": "dd7d53720a5a12bf87954e687f939fc71d9b1f30428faea4ba7eb217a0e788a4",
        "pmca/usb/driver/generic/__init__.py": "24cda5b97dcd7e5ff4c6af0e0a8d66900688ef2ba09dc0fb53c42ab6b8c69123",
        "pmca/usb/driver/generic/libusb.py": "1c80cfaa0692cf308bd086edc9a9bad3691804b50182993c1dd960c932daa1df",
    },
    "runtime_dependencies": ["pyusb", "libusb-package (libusb runtime)", "Python stdlib hashlib (SHA256)"],
}


class USBReadError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class CaptureError(USBReadError):
    """A partial capture is retained; result contains its private receipt."""
    def __init__(self, message: str, result: dict):
        super().__init__("CAPTURE_PARTIAL", message)
        self.result = result


def require(condition, code, message):
    if not condition:
        raise USBReadError(code, message)


def bundled_pmca_root() -> Path:
    """Locate the reviewed sibling source tree without importing or scanning it."""
    return Path(__file__).resolve().parents[2] / "third_party" / "pmca"


def check_pmca_sources(pmca_root: Path | None = None) -> dict:
    """Verify the small reviewed source closure; safe for a local doctor check.

    This checks files and hashes only. It does not import PMCA, PyUSB, crypto,
    or libusb, and says nothing about a camera's current state.
    """
    root = Path(pmca_root) if pmca_root is not None else bundled_pmca_root()
    errors, files = [], {}
    for relative, expected in PMCA_SOURCE["files_sha256"].items():
        try:
            path = root
            require(not root.is_symlink(), "PATH", "PMCA source root must not be a symbolic link")
            for part in relative.split("/"):
                path = path / part
                require(not path.is_symlink(), "PATH", "PMCA source must not contain symbolic links")
            require(path.stat().st_size <= 2 * 1024 * 1024, "SIZE", "Oversized PMCA source file")
            row = _local_identity(path)
            require(row["sha256"] == expected, "INTEGRITY", "PMCA source SHA-256 differs")
            files[relative] = row
        except (OSError, USBReadError) as exc:
            errors.append({"path": relative, "error": str(exc)})
    return {"schema": "a7m4-toolbox-pmca-sources/1", "ready": not errors,
            "source_file_count": len(files), "expected_file_count": len(PMCA_SOURCE["files_sha256"]),
            "files": files, "errors": errors, "camera_io": False, "network_io": False}


def _claim_interface(device, util, stage=None):
    # The caller has identified this camera and released its mounted volumes.
    # macOS storage ownership can remain after unmounting. Detach only this
    # interface, once, before authentication; never reset or retry the device.
    if stage: stage("kernel-driver-status")
    try:
        active = device.is_kernel_driver_active(0)
    except NotImplementedError:
        active = False
    if active:
        if stage: stage("kernel-driver-detach")
        device.detach_kernel_driver(0)
    if stage: stage("claim-interface")
    util.claim_interface(device, 0)


def _authenticate(auth, phase, stage=None):
    try:
        if stage: stage("auth-start")
        auth.start()
        if stage: stage("auth-authenticate")
        auth.authenticate()
    except USBReadError:
        raise
    except Exception as error:
        raise USBReadError("AUTH", phase + " authentication failed; no retry attempted. Inspect camera state before reconnecting.") from error


class ReadChannel:
    def __init__(self, driver, paths=(), begin=None):
        self.driver, self.begin = driver, begin or (lambda: None)
        require(set(paths) <= READ_TARGETS, "SCOPE", "Unknown capture read path")
        self.paths = set(READ_TARGETS)
        self.sequence, self.healthy = 1, True
        self.last_verified_sequence = None
        self.last_verified_reply = None
        self.verified_frame_observer = None
        self._settings_serial = None

    def _exact(self, length):
        result, empty = bytearray(), 0
        while len(result) < length:
            value = bytes(self.driver.read(min(4096, length - len(result))))
            require(len(value) <= length - len(result), "PROTOCOL", "USB reply exceeds requested length")
            if not value:
                empty += 1
                require(empty <= 64, "PROTOCOL", "Too many empty transfers")
                continue
            empty = 0
            result.extend(value)
        return bytes(result)

    def _exchange(self, function, data, limit, success=0, *, request_limit=1024):
        require(self.healthy, "PROTOCOL", "Channel failed; no further request sent")
        require(type(request_limit) is int and 0 < request_limit <= MAX_TRANSFER
                and 0 < len(data) <= request_limit and 0 < limit <= MAX_FILE + 4,
                "BOUNDS", "Invalid read request bounds")
        self.begin()
        self.healthy = False
        packet = HEADER.pack(len(data), function, self.sequence, 0, 0, 0, 0) + data
        self.driver.write(packet)
        output, remaining = bytearray(), None
        wire_digest = hashlib.sha256()
        while True:
            wire_header = self._exact(HEADER.size)
            wire_digest.update(wire_header)
            size, pfunc, seq, _, _, _, status = HEADER.unpack(wire_header)
            require(pfunc == function and seq == self.sequence and status == success,
                    "PROTOCOL", "Unexpected service response header")
            require(0 < size <= limit - len(output) and (remaining is None or size == remaining),
                    "BOUNDS", "Unexpected service response length")
            count = min(size, MAX_TRANSFER)
            # File/settings replies are length delimited. Some firmware sends
            # ZLPs and some omits the final one. _exact consumes empty transfers
            # while waiting for declared bytes; an eager terminator read here
            # can time out or discard real data. Direct CP READ40 is outside
            # this channel's fixed command set and has a separate contract.
            part = self._exact(count)
            wire_digest.update(part)
            output.extend(part)
            remaining = size - count
            if not remaining:
                break
        self.last_verified_sequence = self.sequence
        self.last_verified_reply = dict(sequence=self.sequence, function=function,
            request_sha256=hashlib.sha256(packet).hexdigest(), reply_bytes=len(output),
            reply_sha256=hashlib.sha256(output).hexdigest(), wire_sha256=wire_digest.hexdigest())
        self.sequence = (self.sequence + 1) & 0xffff
        # The frame is complete even if its higher-level result is refused.
        # Journal failure leaves the channel unhealthy and never replays I/O.
        if self.verified_frame_observer is not None:
            self.verified_frame_observer(dict(self.last_verified_reply))
        self.healthy = True
        return bytes(output)

    def _adjust(self, category, command, data, limit):
        # Fixed read operations only. SET_FILE_PATH selects a read source; it
        # does not create/write that file. SET_FILE2 is deliberately absent.
        require((category, command) in {(0x1001, 0x400f), (0x1001, 0x4011),
                                       (0x603, 1), (0x603, 5)},
                "READ_ONLY", "Command is not part of the read-only capture API")
        return self._exchange(0x40, struct.pack("<HH", category, command) + data, limit)

    def hasp(self):
        return self._exchange(0x10, struct.pack("<HHB", 0, 0x1f, 0), 4096, success=1)

    def serial(self):
        if self._settings_serial is None:
            self.settings(True)
        value = self._adjust(0x603, 1, struct.pack("<I", 0x00e70003), 4)
        require(len(value) == 4 and value == self._settings_serial,
                "IDENTITY", "AP serial read does not match the validated settings record")
        return value

    def settings(self, memory):
        require(type(memory) is bool, "PARAMS", "Settings source must be memory or saved")
        value = self._adjust(0x603, 5, bytes([int(memory)]), 32 * 1024 * 1024)
        from .bk4 import bk4_rows
        rows = bk4_rows(value)
        record = rows[0]["records"].get(0x00e70003)
        require(record and record["size"] == 4, "IDENTITY", "Settings lack the AP serial record")
        self._settings_serial = value[record["offset"]:record["offset"] + 4]
        return value

    def file(self, path, maximum=MAX_FILE):
        require(path in self.paths and ".." not in path and "\0" not in path,
                "SCOPE", "Remote file is outside the capture inventory")
        require(type(maximum) is int and 0 < maximum <= MAX_FILE, "BOUNDS", "Invalid file read bound")
        selected = self._adjust(0x1001, 0x400f, b"\0../../" + path.lstrip("/").encode() + b"\0", 4)
        require(selected == bytes(4), "FILE", "File selection failed")
        response = self._adjust(0x1001, 0x4011, b"\0\xff\0", maximum + 4)
        require(len(response) >= 4 and response[:4] == bytes(4), "FILE", "Jiritsu read failed")
        return response[4:]


class ServiceSession:
    """Experimental explicit-device entry; no retries or automatic rescue.

    Normal USB model and physical port are checked before service entry.
    Existing service-only devices are refused because their model is unknown.
    macOS users must release camera storage volumes before claiming USB.
    """
    def __init__(self, pmca_root=None, resources=(), *, channel_factory=ReadChannel, paths=(), expected_usb_serial=None):
        resources, paths = tuple(resources), tuple(paths)
        self.pmca_root = Path(pmca_root) if pmca_root is not None else bundled_pmca_root()
        require(set(resources) <= set(device_scope.RESOURCES), "SCOPE", "Unknown resource name")
        require(all(isinstance(path, str) and path.startswith("/") and "\0" not in path
                    and "\\" not in path and not any(part in ("", ".", "..") for part in path[1:].split("/"))
                    for path in paths), "PATH", "Noncanonical explicit channel path")
        self.paths = ["/usr/share/app/" + name for name in resources] + list(paths)
        if channel_factory is ReadChannel:
            require(set(self.paths) <= READ_TARGETS, "SCOPE", "Default read channel cannot expand its fixed capture scope")
        self.stop_attempted = self.stop_succeeded = self.resources_disposed = False
        self.camera_io = False
        self.device = self.auth = self.reader = None
        self.channel_factory = channel_factory
        require(expected_usb_serial is None or isinstance(expected_usb_serial, str)
                and 0 < len(expected_usb_serial) <= 4096, "IDENTITY", "Invalid expected host USB serial")
        self.expected_usb_serial = expected_usb_serial
        self.entry_stage = "not-started"
        self.entry_error = None

    def _stage(self, stage):
        self.entry_stage = stage
        event("usb-entry-stage", stage=stage, pid=os.getpid(), euid=os.geteuid())

    def __enter__(self):
        try:
            return self._enter()
        except BaseException as error:
            causes, seen, current = [], set(), error
            while current is not None and id(current) not in seen and len(causes) < 4:
                seen.add(id(current))
                causes.append(dict(type=type(current).__name__, message=clean(str(current)),
                    errno=getattr(current, "errno", None) if isinstance(getattr(current, "errno", None), int) else None,
                    backend_error_code=getattr(current, "backend_error_code", None) if isinstance(getattr(current, "backend_error_code", None), int) else None,
                    frames=[dict(file=Path(frame.filename).name, function=frame.name, line=frame.lineno)
                            for frame in traceback.extract_tb(current.__traceback__)[-8:]]))
                current = current.__cause__ or current.__context__
            self.entry_error = dict(stage=self.entry_stage, causes=causes)
            event("usb-entry-failed", **self.entry_error)
            raise

    def _enter(self):
        self._stage("dependencies")
        require((self.pmca_root / "pmca/usb/sony.py").is_file(), "DEPENDENCY", "Supply a Sony-PMCA-RE source checkout")
        require(check_pmca_sources(self.pmca_root)["ready"], "DEPENDENCY", "Bundled PMCA source/license identities are missing or changed")
        require("pmca" not in sys.modules, "DEPENDENCY", "Use a fresh process; another PMCA package is already loaded")
        sys.path.insert(0, str(self.pmca_root))
        usb = importlib.import_module("usb.core")
        util = importlib.import_module("usb.util")
        libusb = importlib.import_module("usb.backend.libusb1")
        generic = importlib.import_module("pmca.usb.driver.generic")
        backend_module = importlib.import_module("pmca.usb.driver.generic.libusb")
        sony = importlib.import_module("pmca.usb.sony")
        self.util = util
        # Optional wheels can supply libusb without a global installation.
        self._stage("backend-create")
        try:
            package = importlib.import_module("libusb_package")
            backend = libusb.get_backend(find_library=package.find_library)
        except ImportError:
            backend = libusb.get_backend()
        require(backend is not None, "DEPENDENCY", "libusb runtime is missing")
        self.camera_io = True
        self._stage("normal-enumeration")
        devices = list(usb.find(find_all=True, idVendor=0x054c, backend=backend))
        require(len(devices) == 1, "DEVICE", "Connect exactly one Sony camera in normal Mass Storage mode")
        dev = devices[0]
        try:
            self._stage("normal-product-descriptor")
            require(dev.idProduct != 0x0336 and util.get_string(dev, dev.iProduct) == MODEL,
                    "MODEL", "Normal USB product must be ILCE-7M4")
            self._stage("normal-active-configuration")
            interface = dev.get_active_configuration()[(0, 0)]
            require(interface.bInterfaceClass == 8, "MODE", "Choose USB Mass Storage on the camera")
            if self.expected_usb_serial is not None:
                self._stage("normal-serial-descriptor")
                require(dev.iSerialNumber and util.get_string(dev, dev.iSerialNumber) == self.expected_usb_serial,
                        "IDENTITY", "USB body differs from the freshly released host storage device")
            self._stage("normal-port-identity")
            port = (dev.bus, tuple(dev.port_numbers or ()))
            require(port[1], "IDENTITY", "Cannot establish the camera's physical USB port")
        except BaseException:
            util.dispose_resources(dev)
            raise

        class Bounded(backend_module.UsbBackend):
            def __init__(self, device):
                super().__init__(device)
                self.reset_budget()

            def reset_budget(self, seconds=180):
                self.deadline = time.monotonic() + seconds

            def reset(self):
                # PMCA's UsbDevice constructor calls driver.reset(). Ownership
                # was handled explicitly before construction; do not detach a
                # second time or issue a physical USB reset here.
                return None

            def timeout(self):
                left = int((self.deadline - time.monotonic()) * 1000)
                require(left > 0, "TIMEOUT", "Service read deadline exceeded")
                return min(left, 10000)

            def read(self, ep, length, timeout=None):
                return bytes(self.dev.read(ep, length, timeout=min(self.timeout(), timeout or 10000)))

            def write(self, ep, data):
                count = self.dev.write(ep, data, timeout=self.timeout())
                require(count == len(data), "PROTOCOL", "Short USB write; do not retry")

        try:
            _claim_interface(dev, util, lambda stage: self._stage("normal-"+stage))
            self._stage("normal-auth-device")
            auth = sony.SonySenserAuthDevice(generic.GenericUsbDriver(Bounded(dev)))
            _authenticate(auth, "Normal USB", lambda stage: self._stage("normal-"+stage))
        finally:
            util.dispose_resources(dev)
        deadline = time.monotonic() + 25
        self._stage("service-enumeration")
        while time.monotonic() < deadline:
            found = list(usb.find(find_all=True, idVendor=0x054c, idProduct=0x0336, backend=backend))
            require(len(found) <= 1, "DEVICE", "More than one service camera found")
            if found:
                self.device = found[0]
                break
            time.sleep(0.25)
        require(self.device is not None, "TIMEOUT", "Service device did not appear; no authentication retry attempted")
        try:
            self._stage("service-port-identity")
            require((self.device.bus, tuple(self.device.port_numbers or ())) == port,
                    "IDENTITY", "Service camera moved to another USB port")
            _claim_interface(self.device, util, lambda stage: self._stage("service-"+stage))
            self._stage("service-auth-device")
            transport = Bounded(self.device)
            driver = generic.GenericUsbDriver(transport)
            auth = sony.SonySenserAuthDevice(driver)
            _authenticate(auth, "Service USB", lambda stage: self._stage("service-"+stage))
            self.auth = auth
            self.reader = self.channel_factory(driver, self.paths, transport.reset_budget)
            self._stage("service-hasp")
            self.reader.hasp()
            self._stage("ready")
            return self.reader
        except BaseException:
            util.dispose_resources(self.device)
            self.resources_disposed = True
            self.device = None
            raise

    def __exit__(self, *args):
        try:
            if (self.auth is not None and self.reader is not None and self.reader.healthy
                    and getattr(self.reader, "safe_to_stop", True)):
                self.stop_attempted = True
                try:
                    self.auth.stop()
                except BaseException:
                    self.reader.healthy = False
                    try:
                        self.reader.safe_to_stop = False
                    except (AttributeError, TypeError):
                        pass  # A derived channel may expose a computed property.
                    raise
                self.stop_succeeded = True
        finally:
            if self.device is not None:
                self.util.dispose_resources(self.device)
                self.resources_disposed = True


def body_binding(serial: bytes) -> dict:
    """Hash AP serial's hex text, matching the retained checkpoint scheme."""
    require(isinstance(serial, bytes) and len(serial) == 4
            and serial not in (bytes(4), b"\xff" * 4),
            "IDENTITY", "Missing usable AP serial property")
    return {"model": MODEL, "scheme": SERIAL_SCHEME,
            "serial_sha256": hashlib.sha256(serial.hex().encode("ascii")).hexdigest()}


def _new_destination(value: Path) -> Path:
    path = Path(value).absolute()
    require(".." not in path.parts, "PATH", "Choose a canonical new destination")
    require(not path.exists() and not path.is_symlink(), "EXISTS", "Choose a new backup directory")
    require(path.parent.is_dir(), "PATH", "The backup destination parent must already exist")
    for parent in (path.parent, *path.parents):
        require(not parent.is_symlink(), "PATH", "Backup destination must not cross a symbolic link")
    from .job_ownership import create_job_output
    path = create_job_output(path)
    return path


def _atomic_json(path: Path, value: dict) -> None:
    temporary = path.with_name("." + path.name + "." + uuid.uuid4().hex + ".tmp")
    try:
        _write_original(temporary, (json.dumps(value, ensure_ascii=False, sort_keys=True,
                                              indent=2, allow_nan=False) + "\n").encode())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _local_identity(path: Path) -> dict:
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode), "PATH", "Captured original must be a regular file")
    signature = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        opened = os.fstat(stream.fileno())
        require(signature(before) == signature(opened) and stat.S_ISREG(opened.st_mode),
                "CHANGED", "Captured local original changed while opening")
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
        require(signature(opened) == signature(os.fstat(stream.fileno())),
                "CHANGED", "Captured local original changed while hashing")
    return {"size": before.st_size, "sha256": digest}


def _write_original(path: Path, data: bytes) -> dict:
    require(isinstance(data, bytes) and len(data) <= MAX_FILE, "SIZE", "Invalid captured byte length")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(path, flags, 0o600), "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    expected = {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    require(_local_identity(path) == expected, "INTEGRITY", "Host storage readback differs from captured bytes")
    return expected


def _read_file(reader, path: str, maximum: int = MAX_FILE) -> bytes:
    data = reader.file(path, maximum)
    require(isinstance(data, bytes) and 0 < len(data) <= maximum,
            "SIZE", "Empty, invalid, or oversized read: " + path)
    return data


def _can_stop(reader) -> bool:
    return reader is not None and getattr(reader, "healthy", False) is True and getattr(reader, "safe_to_stop", True) is True


def capture_backup(destination: Path, *, session_factory: Callable | None = None, full_settings=False) -> dict:
    """Double-read the fixed 11-file scope into a fresh private host directory.

    ``session_factory`` is a zero-argument context-manager factory whose enter
    returns file(path, maximum), settings(memory), serial() and healthy. It may
    expose camera_io=False for a simulated channel. Default entry is the only
    path that lazily loads and opens the bundled PMCA backend. A real caller
    must first hold exclusive hardware ownership and release matching MSC
    volumes. This function neither discovers mount points nor unmounts disks.

    Source files are preserved in snapshot/. Settings/version/loader evidence
    is separate and is not restorable coverage. A .a7backup is created only
    after healthy session exit; it is independently reopened and fully hashed.
    Any ordinary failure raises CaptureError with result, after persisting a
    FAILED_PARTIAL receipt. Nothing is retried, overwritten, or deleted.
    """
    root = _new_destination(destination)
    snapshot, evidence = root / "snapshot", root / "evidence"
    snapshot.mkdir(mode=0o700)
    evidence.mkdir(mode=0o700)
    receipt_path = root / "capture.private.json"
    result = {
        "schema": device_scope.CAPTURE_SCHEMA, "resource_profile": device_scope.ID, "status": "CAPTURING_PARTIAL",
        "created_at": datetime.now(timezone.utc).isoformat(), "model": MODEL,
        "complete": False, "verified": False, "archive_verified": False,
        "camera_io": False, "network_io": False, "persistent_device_writes": False,
        "device_execution_ready": False, "recovery_ready": False,
        "stop_safe": False, "destination": str(root), "receipt": str(receipt_path),
        "snapshot_dir": str(snapshot), "transport": "ordinary-usb-read-session",
        "expected_object_count": device_scope.COUNT, "captured_object_count": 0, "stable_object_count": 0,
        "objects": {}, "evidence": {},
        "settings": {"covered_by_archive": False, "restore_supported": False, "stable": False},
        "custom_csv": {"status": "NOT_OBSERVED", "covered_by_archive": False, "absence_proven": False},
        "scope": "AP, CP program, six language files, two icon banks, and SysSound.bin",
        "atomic_cross_file_snapshot": False,
        "remote_modes_observed": False,
        "not_covered": ["settings restoration", "custom CSV presence or absence", "whole eMMC and boot partitions",
                        "physical CP NOR", "other MCU/OTP/hidden storage", "calibration restoration",
                        "nonboot independent recovery"],
    }
    _atomic_json(receipt_path, result)
    session = reader = None
    capture_verified = False
    try:
        require(len(CAPTURE_TARGETS) == device_scope.COUNT, "SCOPE", "Capture inventory differs from the fixed 11-object scope")
        session = session_factory() if session_factory is not None else ServiceSession()
        result["camera_io"] = getattr(session, "camera_io", True) is not False
        _atomic_json(receipt_path, result)
        with session as reader:
            result["camera_io"] = getattr(session, "camera_io", True) is not False
            for name, remote in EVIDENCE_TARGETS.items():
                maximum = 4096 if name == "version.txt" else MAX_FILE
                data = _read_file(reader, remote, maximum)
                expected = VERSION_SHA256 if name == "version.txt" else LOADER_SHA256
                row = _write_original(evidence / name, data)
                result["evidence"][name] = {"target_path": remote, "path": "evidence/" + name, **row}
                require(row["sha256"] == expected, "BASELINE", "Unrecognized 6.02 service baseline: " + name)
            result["firmware_version"] = "6.02"
            result["version_source"] = "complete /version.txt SHA-256; build identity, not a displayed-version parser"
            for name, memory in (("settings-ram", True), ("settings-saved", False)):
                data = reader.settings(memory)
                require(isinstance(data, bytes) and 0 < len(data) <= 32 * 1024 * 1024,
                        "SIZE", "Invalid settings evidence")
                result["evidence"][name] = {"path": "evidence/" + name + ".bin",
                                            **_write_original(evidence / (name + ".bin"), data)}
            result["body_binding"] = body_binding(reader.serial())
            complete_settings=None
            if full_settings:
                from .settings_channel import SettingsChannel
                from .settings_archive import save_snapshot
                journal=evidence/'settings-wire';journal.mkdir(mode=0o700)
                serial=[0]
                def settings_journal(event):
                    serial[0]+=1
                    row={}
                    for key,value in event.items():
                        if isinstance(value,bytes):
                            name='%04d-%s.bin'%(serial[0],key)
                            row[key]={"path":"evidence/settings-wire/"+name,**_write_original(journal/name,value)}
                        else:row[key]=value
                    _atomic_json(journal/('%04d.json'%serial[0]),row)
                settings_channel=SettingsChannel(reader,intent=settings_journal,reply=settings_journal)
                complete_settings=settings_channel.capture()
                require(body_binding(complete_settings.serial)==result['body_binding'],'IDENTITY','Complete settings body differs')
                result['settings_capture']=save_snapshot(complete_settings,root/'settings')
                result['settings_capture_verified']=False
            _atomic_json(receipt_path, result)
            _atomic_json(snapshot / "inventory.json", {"schema": backup.INVENTORY_SCHEMA, "extra_objects": []})
            total = 0
            for name, definition in sorted(CAPTURE_TARGETS.items()):
                data = _read_file(reader, definition["target_path"])
                total += len(data)
                require(total <= MAX_TOTAL, "SIZE", "Capture exceeds total host byte budget")
                result["objects"][name] = {**definition, **_write_original(snapshot / name, data), "stable": False}
                del data
                result["captured_object_count"] += 1
                _atomic_json(receipt_path, result)
            for name, definition in sorted(CAPTURE_TARGETS.items()):
                data = _read_file(reader, definition["target_path"])
                row = result["objects"][name]
                require((len(data), hashlib.sha256(data).hexdigest()) == (row["size"], row["sha256"]),
                        "CHANGED", "File changed between complete capture passes: " + name)
                del data
                row["stable"] = True
                result["stable_object_count"] += 1
                _atomic_json(receipt_path, result)
            for name, remote in EVIDENCE_TARGETS.items():
                data = _read_file(reader, remote, 4096 if name == "version.txt" else MAX_FILE)
                row = result["evidence"][name]
                require((len(data), hashlib.sha256(data).hexdigest()) == (row["size"], row["sha256"]),
                        "CHANGED", "Service baseline changed during capture: " + name)
            stable_settings = []
            for name, memory in (("settings-ram", True), ("settings-saved", False)):
                data = reader.settings(memory)
                require(isinstance(data, bytes) and 0 < len(data) <= 32 * 1024 * 1024,
                        "SIZE", "Invalid final settings evidence")
                after = _write_original(evidence / (name + "-after.bin"), data)
                result["evidence"][name + "-after"] = {"path": "evidence/" + name + "-after.bin", **after}
                before = result["evidence"][name]
                stable_settings.append((after["size"], after["sha256"]) == (before["size"], before["sha256"]))
            result["settings"]["stable"] = all(stable_settings)
            if complete_settings is not None:
                from .settings_archive import save_snapshot
                from .settings_scope import capture_scope_report
                final_settings=settings_channel.capture()
                result['settings_capture_after']=save_snapshot(final_settings,evidence/'settings-after')
                stability=capture_scope_report(complete_settings,final_settings)
                _atomic_json(evidence/'settings-stability.json',stability)
                result['settings_stability']=stability
                result['settings_applicability']=dict(owned_scope_stable=stability['settings_applicability'],
                    authorizes_device_write=False,operation_must_revalidate_fresh=True)
                result['settings_capture_verified']=True
                result['settings'].update(stable=stability['raw_equal'],full_snapshot_static=False,atomic_snapshot=False,
                    owned_scope_stable=stability['stable'],covered_by_portable_archive=True,
                    restore_supported='selected-owned-spans-only',calibration_replay=False)
                require(reader.healthy and settings_channel.healthy,'PROTOCOL','Settings capture channel is unhealthy')
                reader.safe_to_stop=False
            require(body_binding(reader.serial()) == result["body_binding"], "IDENTITY", "Body changed during capture")
            if complete_settings is not None:
                require(reader.healthy and settings_channel.healthy,'PROTOCOL','Final identity channel is unhealthy')
                reader.safe_to_stop=True
            require(_can_stop(reader), "PROTOCOL", "Capture channel is not healthy for a bounded service exit")
            result["stop_safe"] = True
            capture_verified = True
            _atomic_json(receipt_path, result)
        require(capture_verified and result["stable_object_count"] == device_scope.COUNT,
                "INTEGRITY", "Session did not finish all identity and complete-object checks")
        result["service_exit"] = {
            "stop_attempted": getattr(session, "stop_attempted", None),
            "stop_succeeded": getattr(session, "stop_succeeded", None),
            "resources_disposed": getattr(session, "resources_disposed", None),
        }
        if isinstance(session, ServiceSession):
            require(session.stop_succeeded and session.resources_disposed,
                    "EXIT", "Service exit was not fully confirmed")
        result["status"] = "VERIFYING_LOCAL_ARCHIVE"
        _atomic_json(receipt_path, result)
        archive = root / "original.a7backup"
        backup.create_backup(snapshot, archive, profile=device_scope.ID)
        verified = backup.verify_backup(archive)
        require(verified["complete"] is True and verified["verified"] is True
                and verified["object_count"] == verified["present_object_count"] == device_scope.COUNT,
                "INTEGRITY", "Reopened archive differs from the complete 11-object capture")
        result.update(status="VERIFIED_BACKUP", complete=True, verified=True, archive_verified=True,
                      archive=str(archive), archive_sha256=verified["archive_sha256"],
                      archive_size=verified["archive_size"], archive_verification=verified)
        _atomic_json(receipt_path, result)
        return result
    except BaseException as exc:
        stop_unknown = (session is not None and getattr(session, "stop_attempted", False)
                        and getattr(session, "stop_succeeded", False) is not True)
        entry_error = getattr(session, "entry_error", None)
        description = ("USB entry ["+entry_error["stage"]+"]: " if entry_error else "") + str(exc)
        result.update(status="FAILED_PARTIAL", complete=False, verified=False,
                      stop_safe=_can_stop(reader) and not stop_unknown, error_type=type(exc).__name__, error=description)
        if entry_error:
            result["usb_entry_error"] = entry_error
            result["usb_entry_stage"] = entry_error["stage"]
        if session is not None:
            result["camera_io"] = getattr(session, "camera_io", True) is not False
            result["service_exit"] = {
                "stop_attempted": getattr(session, "stop_attempted", None),
                "stop_succeeded": getattr(session, "stop_succeeded", None),
                "resources_disposed": getattr(session, "resources_disposed", None),
            }
        _atomic_json(receipt_path, result)
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        raise CaptureError("Backup capture is partial: " + str(exc), result) from exc
