"""Bounded host transport contract, with an explicitly simulated backend.

Importing this module creates no backend and performs no device discovery.
There is intentionally no Sony/USB/SSH implementation here. A concrete backend
must enforce the supplied timeout in its blocking I/O. Python cannot interrupt
an arbitrary backend that ignores that contract.

``read_chunk`` describes a HOST interface, not a camera offset command. An
adapter may cache a bounded full-file GET on the Mac, then serve host chunks.
Its identity token must describe that capture honestly; it must not pretend to
have observed camera inode/atomic-snapshot guarantees absent from its protocol.
Upload acknowledgements are transport evidence, never installation success.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import threading
import time
from types import MappingProxyType
from typing import Any, Callable, Iterable, Mapping, Protocol, runtime_checkable

MIN_FREE_BYTES = 8 * 1024 * 1024
MAX_UPLOAD_BYTES = 65535
MAX_CHUNK_BYTES = 1024 * 1024
MAX_FILE_BYTES = 512 * 1024 * 1024
MAX_TIMEOUT_SECONDS = 300
PER_CALL_SECONDS = 30


class TransportError(RuntimeError):
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


def _need(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise TransportError(code, message)


def _integer(value: Any, low: int, high: int, name: str) -> int:
    _need(type(value) is int and low <= value <= high, "BOUNDS", f"Invalid {name}")
    return value


def _timeout(value: Any) -> float:
    _need(type(value) in (int, float) and math.isfinite(value)
          and 0 < value <= MAX_TIMEOUT_SECONDS, "BOUNDS", "Invalid timeout")
    return float(value)


def _remote(value: Any) -> str:
    _need(type(value) is str and 1 < len(value) <= 512 and value.startswith("/")
          and "\\" not in value and all(32 <= ord(c) < 127 for c in value)
          and all(p not in ("", ".", "..") for p in value[1:].split("/")),
          "PATH", "Remote path must be an exact absolute file path")
    return value


def _operation(value: Any) -> str:
    _need(type(value) is str and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", value) is not None,
          "OPERATION", "Invalid single-use operation ID")
    return value


def _hash(value: Any) -> str:
    _need(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None,
          "HASH", "Expected a complete lowercase SHA-256")
    return value


@dataclass(frozen=True)
class FileInfo:
    size: int
    identity: str
    regular: bool = True


@dataclass(frozen=True)
class SpaceInfo:
    available_bytes: int
    allocation_unit: int
    identity: str


@dataclass(frozen=True)
class UploadAck:
    bytes_sent: int
    acknowledged: bool


@runtime_checkable
class Channel(Protocol):
    """Already explicitly connected backend. No generic execute/scan API.

    stat/read_chunk must bind chunks to the supplied capture identity and fail
    if it changes. free_space must take a NEW real measurement, not return an
    old receipt or a configured estimate. If unavailable it must raise.
    close releases host resources only; it must not send STOP/reset/reboot.
    """
    mode: str  # Exactly DEVICE or SIMULATED.

    def stat(self, path: str, *, timeout: float) -> FileInfo: ...
    def read_chunk(self, path: str, offset: int, count: int, *, identity: str,
                   timeout: float) -> bytes: ...
    def free_space(self, *, timeout: float) -> SpaceInfo: ...
    def upload(self, path: str, contents: bytes, *, timeout: float) -> UploadAck: ...
    def close(self) -> None: ...


class Journal(Protocol):
    mode: str

    def claim(self, operation_id: str, record: dict) -> None: ...
    def record(self, operation_id: str, record: dict) -> None: ...


def _json(record: dict) -> bytes:
    raw = (json.dumps(record, ensure_ascii=True, allow_nan=False,
                      sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    _need(len(raw) <= 65536, "JOURNAL", "Journal record is too large")
    return raw


class FileJournal:
    """Durable, exclusive operation claims, also effective across sessions.

    Existing claims are never resumed/replayed. Each operation has one private
    JSONL file. The caller owns lifecycle/receipt retention and a host job lock.
    """
    mode = "DURABLE"

    def __init__(self, directory: str | os.PathLike):
        root = Path(directory)
        if not root.exists() and not root.is_symlink():
            root.mkdir(mode=0o700)
        info = root.lstat()
        _need(stat.S_ISDIR(info.st_mode) and not root.is_symlink()
              and info.st_mode & 0o077 == 0 and info.st_uid == os.getuid(),
              "JOURNAL", "Journal must be an owned private real directory")
        self.directory = root.resolve(strict=True)
        self.identity = (info.st_dev, info.st_ino)
        self._lock = threading.Lock()

    def _write(self, operation_id: str, record: dict, *, claim: bool) -> None:
        name = _operation(operation_id) + ".jsonl"
        raw = _json(record)
        with self._lock:
            flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
            parent = os.open(self.directory, flags)
            try:
                info = os.fstat(parent)
                _need((info.st_dev, info.st_ino) == self.identity,
                      "JOURNAL", "Journal directory identity changed")
                flags = os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
                flags |= os.O_CREAT | os.O_EXCL if claim else os.O_APPEND
                try:
                    fd = os.open(name, flags, 0o600, dir_fd=parent)
                except FileExistsError as exc:
                    raise TransportError("REPLAY", "Operation already claimed; never replay it") from exc
                try:
                    item = os.fstat(fd)
                    _need(stat.S_ISREG(item.st_mode) and item.st_nlink == 1
                          and item.st_uid == os.getuid() and item.st_mode & 0o077 == 0
                          and item.st_size + len(raw) <= 1024 * 1024,
                          "JOURNAL", "Unsafe or oversized journal file")
                    view = memoryview(raw)
                    while view:
                        count = os.write(fd, view)
                        _need(count > 0, "JOURNAL", "Short journal write")
                        view = view[count:]
                    os.fsync(fd)
                finally:
                    os.close(fd)
                os.fsync(parent)
            finally:
                os.close(parent)

    def claim(self, operation_id: str, record: dict) -> None:
        self._write(operation_id, record, claim=True)

    def record(self, operation_id: str, record: dict) -> None:
        self._write(operation_id, record, claim=False)


class MemoryJournal:
    """SIMULATED only; never admitted for DEVICE mutations."""
    mode = "SIMULATED"

    def __init__(self):
        self.entries: dict[str, list[dict]] = {}

    def claim(self, operation_id: str, record: dict) -> None:
        _operation(operation_id)
        _need(operation_id not in self.entries, "REPLAY", "Operation already claimed")
        self.entries[operation_id] = [json.loads(_json(record))]

    def record(self, operation_id: str, record: dict) -> None:
        _need(operation_id in self.entries, "JOURNAL", "Operation has no claim")
        self.entries[operation_id].append(json.loads(_json(record)))


class Session:
    """Bounded scopes on one channel; exceptions after I/O poison the session.

    READY -> STOP_UNKNOWN on any uncertain backend/protocol/journal outcome.
    No reconnect, automatic inverse, retry, or device STOP is implemented.
    """
    def __init__(self, channel: Channel, journal: Journal | None = None, *,
                 read_paths: Iterable[str] = (), upload_paths: Iterable[str] = (),
                 clock: Callable[[], float] = time.monotonic, max_calls: int = 16384):
        _need(getattr(channel, "mode", None) in ("DEVICE", "SIMULATED"),
              "BACKEND", "Backend must declare DEVICE or SIMULATED")
        self.channel, self.journal = channel, journal
        self.mode = channel.mode
        self.read_paths = frozenset(_remote(p) for p in read_paths)
        self.upload_paths = frozenset(_remote(p) for p in upload_paths)
        _need(len(self.read_paths) <= 1024 and len(self.upload_paths) <= 128,
              "SCOPE", "Too many scoped paths")
        self.clock, self.max_calls = clock, _integer(max_calls, 1, 65536, "call budget")
        self.calls = 0
        self.state = "READY"
        self._lock = threading.Lock()

    @classmethod
    def connect(cls, factory: Callable[..., Channel], *, selection: Mapping[str, str],
                timeout: float = 30, **kwargs) -> Session:
        """The only factory entry; invoke only after an explicit connect action."""
        timeout = _timeout(timeout)
        _need(isinstance(selection, Mapping) and 0 < len(selection) <= 16
              and all(type(k) is str and type(v) is str and 0 < len(k) <= 64
                      and 0 < len(v) <= 512 for k, v in selection.items()),
              "SELECTION", "Explicit bounded device selection is required")
        # No discovery/default selector, retry or fallback is hidden here.
        start = time.monotonic()
        channel = factory(selection=MappingProxyType(dict(selection)), timeout=timeout)
        session = cls(channel, **kwargs)
        if time.monotonic() - start >= timeout:
            session.state = "STOP_UNKNOWN"
            raise TransportError("TIMEOUT", "Explicit connection exceeded its deadline")
        return session

    def _enter(self) -> None:
        _need(self.state == "READY", "STOP_UNKNOWN", "Session is closed/unknown; no further I/O")
        _need(self._lock.acquire(blocking=False), "BUSY", "Do not interleave session operations")

    def _invoke(self, method: str, deadline: float, *args, **kwargs):
        try:
            _need(self.state == "READY" and self.calls < self.max_calls,
                  "CALL_BUDGET", "Session call budget exhausted")
            left = deadline - self.clock()
            _need(left > 0, "TIMEOUT", "Operation deadline expired")
            self.calls += 1
            result = getattr(self.channel, method)(*args, timeout=min(left, PER_CALL_SECONDS), **kwargs)
            _need(self.clock() < deadline, "TIMEOUT", "Backend exceeded operation deadline")
            return result
        except BaseException:
            self.state = "STOP_UNKNOWN"
            raise

    def _info(self, value: Any) -> FileInfo:
        _need(type(value) is FileInfo and type(value.regular) is bool and value.regular
              and type(value.size) is int and 0 <= value.size <= MAX_FILE_BYTES
              and type(value.identity) is str and 0 < len(value.identity) <= 1024,
              "PROTOCOL", "Backend returned unsafe file metadata")
        return value

    def measure_space(self, *, timeout: float = 30) -> SpaceInfo:
        deadline = self.clock() + _timeout(timeout)
        self._enter()
        try:
            return self._space(self._invoke("free_space", deadline))
        except BaseException:
            self.state = "STOP_UNKNOWN"
            raise
        finally:
            self._lock.release()

    @staticmethod
    def _space(value: Any) -> SpaceInfo:
        _need(type(value) is SpaceInfo and type(value.available_bytes) is int
              and 0 <= value.available_bytes <= 2**63 - 1
              and type(value.allocation_unit) is int and 1 <= value.allocation_unit <= MAX_CHUNK_BYTES
              and type(value.identity) is str and 0 < len(value.identity) <= 1024,
              "PROTOCOL", "Fresh space measurement unavailable or invalid")
        return value

    def download_file(self, remote_path: str, destination: str | os.PathLike, *,
                      expected_size: int | None = None, expected_sha256: str | None = None,
                      maximum_size: int = MAX_FILE_BYTES, chunk_bytes: int = 256 * 1024,
                      timeout: float = 180) -> dict:
        path = _remote(remote_path)
        _need(path in self.read_paths, "SCOPE", "Read path is not explicitly scoped")
        _integer(maximum_size, 0, MAX_FILE_BYTES, "maximum file size")
        if expected_size is not None:
            _integer(expected_size, 0, maximum_size, "expected file size")
        if expected_sha256 is not None:
            _hash(expected_sha256)
        _integer(chunk_bytes, 1, MAX_CHUNK_BYTES, "host chunk size")
        deadline = self.clock() + _timeout(timeout)
        destination = Path(destination)
        _need(destination.name not in ("", ".", "..") and not destination.exists()
              and not destination.is_symlink(), "EXISTS", "Destination already exists or is unsafe")
        parent_path = destination.parent
        _need(parent_path.is_dir() and not parent_path.is_symlink(), "PATH", "Use a real existing output directory")
        self._enter()
        parent = fd = None
        try:
            info = self._info(self._invoke("stat", deadline, path))
            _need(info.size <= maximum_size and (expected_size is None or info.size == expected_size),
                  "SIZE", "Remote file size differs or exceeds the bound")
            parent = os.open(parent_path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                             | getattr(os, "O_NOFOLLOW", 0))
            partial = destination.name + ".partial"
            fd = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                         | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=parent)
            digest, offset, chunks = hashlib.sha256(), 0, 0
            while offset < info.size:
                count = min(chunk_bytes, info.size - offset)
                raw = self._invoke("read_chunk", deadline, path, offset, count, identity=info.identity)
                _need(type(raw) is bytes and len(raw) == count,
                      "SHORT_READ", "Backend did not return the exact bounded host chunk")
                view = memoryview(raw)
                while view:
                    written = os.write(fd, view)
                    _need(written > 0, "LOCAL_WRITE", "Short local backup write")
                    view = view[written:]
                digest.update(raw)
                offset += count
                chunks += 1
            after = self._info(self._invoke("stat", deadline, path))
            _need(after == info, "SOURCE_CHANGED", "Remote capture identity changed")
            actual_sha = digest.hexdigest()
            _need(expected_sha256 is None or actual_sha == expected_sha256,
                  "HASH", "Complete file SHA-256 differs")
            os.fsync(fd)
            os.close(fd)
            fd = None
            # Hard-link publication is atomic and refuses a destination that
            # appeared during the read. rename/replace would overwrite it.
            os.link(partial, destination.name, src_dir_fd=parent, dst_dir_fd=parent,
                    follow_symlinks=False)
            os.fsync(parent)
            os.unlink(partial, dir_fd=parent)
            os.fsync(parent)
            return {"mode": self.mode, "simulation": self.mode == "SIMULATED",
                    "status": "COMPLETE_LOCAL_READBACK", "size": offset,
                    "sha256": actual_sha, "expected_sha256_verified": expected_sha256 is not None,
                    "capture_identity": info.identity, "host_chunks": chunks,
                    "atomic_camera_snapshot_claimed": False}
        except BaseException:
            # Keep .partial for inspection; it is never a completed backup.
            self.state = "STOP_UNKNOWN"
            raise
        finally:
            if fd is not None:
                os.close(fd)
            if parent is not None:
                os.close(parent)
            self._lock.release()

    def upload_once(self, remote_path: str, contents: bytes, *, operation_id: str,
                    expected_sha256: str, reserve_bytes: int = 0, timeout: float = 30) -> dict:
        path, operation_id = _remote(remote_path), _operation(operation_id)
        _need(path in self.upload_paths, "SCOPE", "Upload path is not explicitly scoped")
        _need(type(contents) is bytes and 0 < len(contents) <= MAX_UPLOAD_BYTES,
              "BOUNDS", "Every uploaded file must be strictly smaller than 65536 bytes")
        _need(hashlib.sha256(contents).hexdigest() == _hash(expected_sha256),
              "HASH", "Upload differs from the caller's complete content pin")
        _integer(reserve_bytes, 0, 2**63 - 1, "remaining allocation reserve")
        _need(self.journal is not None and (self.mode == "SIMULATED"
              or self.journal.mode == "DURABLE"), "JOURNAL", "DEVICE uploads require a durable journal")
        deadline = self.clock() + _timeout(timeout)
        self._enter()
        try:
            try:
                self.journal.claim(operation_id, {"event": "CLAIMED", "mode": self.mode,
                    "path": path, "size": len(contents), "sha256": expected_sha256,
                    "automatic_replay_allowed": False})
            except TransportError as exc:
                if exc.code == "REPLAY":
                    raise
                self.state = "STOP_UNKNOWN"
                raise
            except BaseException:
                self.state = "STOP_UNKNOWN"
                raise
            try:
                space = self._space(self._invoke("free_space", deadline))
                allocation = ((len(contents) + space.allocation_unit - 1) // space.allocation_unit) * space.allocation_unit
                reserve_allocation = ((reserve_bytes + space.allocation_unit - 1)
                                      // space.allocation_unit) * space.allocation_unit
                required = MIN_FREE_BYTES + allocation + reserve_allocation
                if space.available_bytes < required:
                    self.journal.record(operation_id, {"event": "NOT_SENT_INSUFFICIENT_SPACE",
                        "available_bytes": space.available_bytes, "required_bytes": required})
                    raise TransportError("SPACE", "Fresh free space does not preserve 8 MiB plus upload/reserves")
                self.journal.record(operation_id, {"event": "MUTATION_INTENT", "path": path,
                    "size": len(contents), "sha256": expected_sha256,
                    "space_identity": space.identity, "available_bytes": space.available_bytes,
                    "required_bytes": required, "reserve_bytes": reserve_bytes,
                    "reserve_allocation_bytes": reserve_allocation})
                ack = self._invoke("upload", deadline, path, contents)
                _need(type(ack) is UploadAck and type(ack.bytes_sent) is int
                      and ack.bytes_sent == len(contents) and ack.acknowledged is True,
                      "ACK", "Upload acknowledgement is incomplete or invalid")
                result = {"event": "ACKNOWLEDGED", "mode": self.mode,
                          "simulation": self.mode == "SIMULATED", "path": path,
                          "size": len(contents), "sha256": expected_sha256,
                          "installation_verified": False, "operation_id": operation_id}
                self.journal.record(operation_id, result)
                return result
            except TransportError as exc:
                if exc.code == "SPACE" and self.state == "READY":
                    raise  # Known no-upload result, but the claim stays consumed.
                self.state = "STOP_UNKNOWN"
                raise
            except BaseException:
                self.state = "STOP_UNKNOWN"
                raise
        finally:
            self._lock.release()

    def close(self) -> None:
        _need(self._lock.acquire(blocking=False), "BUSY", "Operation is still active")
        try:
            if self.state != "CLOSED":
                self.state = "CLOSED"
                self.channel.close()  # Resource release only; never protocol STOP.
        finally:
            self._lock.release()


class FakeChannel:
    """In-memory SIMULATED backend with observable calls and one-shot faults."""
    mode = "SIMULATED"

    def __init__(self, files: Mapping[str, bytes] | None = None, *,
                 free_bytes: int = 32 * 1024 * 1024, allocation_unit: int = 4096):
        self.files: dict[str, bytes] = {}
        self.versions: dict[str, int] = {}
        self.calls: list[dict] = []
        self.free_bytes = _integer(free_bytes, 0, 2**63 - 1, "simulated free space")
        self.allocation_unit = _integer(allocation_unit, 1, MAX_CHUNK_BYTES, "allocation unit")
        self.closed = False
        self._faults: dict[str, tuple[bool, BaseException]] = {}
        for path, value in (files or {}).items():
            self.replace_file(path, value)

    def replace_file(self, path: str, contents: bytes) -> None:
        path = _remote(path)
        _need(type(contents) is bytes, "BOUNDS", "Simulated file must be immutable bytes")
        self.files[path] = contents
        self.versions[path] = self.versions.get(path, 0) + 1

    def fail_next(self, operation: str, *, after: bool = False,
                  exception: BaseException | None = None) -> None:
        _need(operation in {"stat", "read_chunk", "free_space", "upload"}, "FAULT", "Unknown fake operation")
        self._faults[operation] = (after, exception or TimeoutError("SIMULATED injected failure"))

    def _begin(self, operation: str, timeout: float, **values) -> None:
        _timeout(timeout)
        _need(not self.closed, "CLOSED", "SIMULATED channel closed")
        self.calls.append({"mode": "SIMULATED", "operation": operation, "timeout": timeout, **values})
        fault = self._faults.get(operation)
        if fault is not None and not fault[0]:
            del self._faults[operation]
            raise fault[1]

    def _end(self, operation: str) -> None:
        fault = self._faults.get(operation)
        if fault is not None:
            del self._faults[operation]
            raise fault[1]

    def _identity(self, path: str) -> str:
        return f"SIMULATED:{path}:{self.versions[path]}"

    def stat(self, path: str, *, timeout: float) -> FileInfo:
        self._begin("stat", timeout, path=path)
        result = FileInfo(len(self.files[path]), self._identity(path))
        self._end("stat")
        return result

    def read_chunk(self, path: str, offset: int, count: int, *, identity: str, timeout: float) -> bytes:
        self._begin("read_chunk", timeout, path=path, offset=offset, count=count)
        _need(identity == self._identity(path), "SOURCE_CHANGED", "SIMULATED source changed")
        result = self.files[path][offset:offset + count]
        self._end("read_chunk")
        return result

    def free_space(self, *, timeout: float) -> SpaceInfo:
        self._begin("free_space", timeout)
        result = SpaceInfo(self.free_bytes, self.allocation_unit,
                           f"SIMULATED:space:{len(self.calls)}")
        self._end("free_space")
        return result

    def upload(self, path: str, contents: bytes, *, timeout: float) -> UploadAck:
        self._begin("upload", timeout, path=path, size=len(contents), sha256=hashlib.sha256(contents).hexdigest())
        self.replace_file(path, contents)
        self.free_bytes -= math.ceil(len(contents) / self.allocation_unit) * self.allocation_unit
        self._end("upload")
        return UploadAck(len(contents), True)

    def close(self) -> None:
        self.calls.append({"mode": "SIMULATED", "operation": "close"})
        self.closed = True


def doctor() -> dict:
    """Host-only capability declaration, without imports/discovery/probes."""
    return {"schema": "a7m4-toolbox-transport-doctor/1", "camera_io": False,
            "device_enumeration": False, "real_backend_included": False,
            "fake_channel": "SIMULATED", "max_upload_bytes": MAX_UPLOAD_BYTES,
            "minimum_free_bytes": MIN_FREE_BYTES,
            "fresh_space_required": True, "automatic_replay_allowed": False}
