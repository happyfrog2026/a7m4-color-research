"""Read-only source/binary/contract inventory for release helpers."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
import stat


def helper_inventory(*, verify: bool = False) -> dict:
    root = Path(__file__).resolve().parents[2]
    catalogue = Path(__file__).with_name("data") / "helpers.json"
    if not catalogue.is_file():
        return {"schema": "a7m4-helper-inventory/1", "status": "PENDING_HELPER_CATALOGUE",
                "verified": False, "helpers": [], "camera_io": False, "internet_uploads": False}
    data = json.loads(catalogue.read_text(encoding="utf-8"))
    if data.get("schema") != "a7m4-toolbox-helper-catalogue/1" or not isinstance(data.get("files"), list):
        raise ValueError("Invalid packaged helper catalogue")
    rows = []
    for item in data["files"]:
        relative = item.get("path")
        if (not isinstance(relative, str) or not relative or "\\" in relative
                or PurePosixPath(relative).is_absolute() or ".." in PurePosixPath(relative).parts
                or str(PurePosixPath(relative)) != relative):
            raise ValueError("Noncanonical helper catalogue path")
        result = dict(item)
        if verify:
            path = root
            for part in PurePosixPath(relative).parts:
                path = path / part
                if path.is_symlink():
                    raise ValueError("Symlink helper resource refused")
            before = path.stat()
            if not stat.S_ISREG(before.st_mode) or not 0 <= before.st_size <= 64 * 1024 * 1024:
                raise ValueError("Helper resource is not a bounded regular file")
            with path.open("rb") as stream:
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
            after = path.stat()
            signature = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
            if signature(before) != signature(after):
                raise ValueError("Helper resource changed while verifying")
            result["verified"] = before.st_size == item["bytes"] and digest == item["sha256"]
            if not result["verified"]:
                raise ValueError("Helper resource differs from its release identity: " + relative)
        rows.append(result)
    return {"schema": "a7m4-helper-inventory/1", "status": "VERIFIED" if verify else "INVENTORY_ONLY",
            "verified": verify, "helpers": data.get("helpers", []), "files": rows,
            "camera_io": False, "internet_uploads": False,
            "device_execution_is_not_established_by_file_integrity": True}
