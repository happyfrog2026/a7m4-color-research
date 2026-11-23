"""Local dependency and packaged-asset checks, with no device discovery."""
from __future__ import annotations

import hashlib
import importlib
import io
import json
from pathlib import Path
import platform
import sys


def check_environment() -> dict:
    checks = []
    def record(name, available, detail):
        checks.append({"name": name, "available": bool(available), "detail": detail})
    record("Python", sys.version_info >= (3, 11), platform.python_version())
    try:
        numpy = importlib.import_module("numpy")
        result = numpy.linalg.lstsq(numpy.eye(2), numpy.array([1., 2.]), rcond=None)[0]
        record("NumPy", int(numpy.__version__.split(".")[0]) >= 2 and result.tolist() == [1., 2.], numpy.__version__)
    except (ImportError, OSError, ValueError, RuntimeError) as exc:
        record("NumPy", False, str(exc))
    try:
        image = importlib.import_module("PIL.Image")
        data = io.BytesIO()
        image.new("RGBA", (2, 2), (10, 20, 30, 255)).save(data, format="PNG")
        data.seek(0)
        with image.open(data) as decoded:
            available = decoded.size == (2, 2) and decoded.convert("RGBA").getpixel((0, 0)) == (10, 20, 30, 255)
        record("Pillow", available, importlib.import_module("PIL").__version__)
    except (ImportError, OSError, ValueError, RuntimeError) as exc:
        record("Pillow", False, str(exc))
    assets = Path(__file__).with_name("data") / "assets"
    try:
        manifest = json.loads((assets / "manifest.json").read_text(encoding="utf-8"))
        rows = manifest["files"]
        names = set()
        for row in rows:
            name = row["path"]
            if (not isinstance(name, str) or Path(name).name != name or name in names
                    or name in (".", "..") or (assets / name).is_symlink()):
                raise ValueError("Invalid packaged asset path")
            names.add(name)
            raw = (assets / name).read_bytes()
            if len(raw) != row["bytes"] or hashlib.sha256(raw).hexdigest() != row["sha256"]:
                raise ValueError("Packaged artwork/audio differs from its index")
        if not rows:
            raise ValueError("Packaged artwork/audio index is empty")
        record("内置声音与位图", True, f"{len(rows)} files verified")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        record("内置声音与位图", False, str(exc))
    try:
        from .native_icons import check_templates
        templates = check_templates()
        record("原生图标模板", True, templates)
    except (ImportError, OSError, ValueError, KeyError, TypeError, RuntimeError) as exc:
        record("原生图标模板", False, str(exc))
    try:
        from .native_audio_codec import encode_filter0, decode_filter0
        block = encode_filter0([0, 64, -64])
        decoded = decode_filter0(block)
        record("原生声音编解码", len(block) == 64 and decoded[:3] == [0, 64, -64],
               "filter0 local encode/decode; 24 kHz production assumption only")
    except (ImportError, OSError, ValueError, RuntimeError) as exc:
        record("原生声音编解码", False, str(exc))
    ready = all(row["available"] for row in checks)
    return {
        "schema": "a7m4-local-environment/1",
        "status": "LOCAL_READY" if ready else "LOCAL_DEPENDENCY_MISSING",
        "ready_for_local_work": ready,
        "checks": checks,
        "platform": {"system": platform.system(), "architecture": platform.machine(), "python": platform.python_version()},
        "camera_tests": "HELD",
        "device_execution_ready": False,
        "deployment_readiness": importlib.import_module("a7m4.research.offline").deployment_readiness(),
        "camera_io": False,
        "network_io": False,
        "automatic_downloads": False,
        "scope": "Local preparation only. USB/SSH is not enumerated, opened or tested by this check.",
    }
