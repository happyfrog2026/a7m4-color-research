"""Small, indexed local sound recipes; no firmware or device adapters."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path

from .offline import PlanError

_ASSETS = Path(__file__).with_name("data") / "assets"
_RECIPES = {
    "factory": {"name": "原厂电子快门 · 本地重合成", "ka": "factory-ka.wav", "sha_dry": "factory-sha.wav", "recock": False},
    "dry": {"name": "干脆双帘 · 合成样例", "ka": "dry-ka.wav", "sha_dry": "dry-sha.wav", "recock": False},
    "soft": {"name": "低沉短促 · 合成样例", "ka": "soft-ka.wav", "sha_dry": "soft-sha.wav", "recock": False},
    "m9": {"name": "M9 · 无上弦 · 本地重合成", "ka": "factory-ka.wav", "sha_dry": "m9-sha-dry.wav", "recock": False},
    "m9-recock": {"name": "M9 · 上弦 · 本地重合成", "ka": "factory-ka.wav", "sha_dry": "m9-sha-dry.wav", "recock": True},
}


def sound_presets() -> list[dict]:
    return [{"id": key, "name": value["name"], "recock_enabled": value["recock"],
             "status": "LOCAL_RECOMPOSITION_NOT_DEVICE_ACCEPTED", "camera_io": False}
            for key, value in _RECIPES.items()]


def _asset(name: str) -> str:
    rows = json.loads((_ASSETS / "manifest.json").read_text(encoding="utf-8"))["files"]
    matches = [row for row in rows if row["path"] == name]
    path = _ASSETS / name
    if len(matches) != 1 or path.is_symlink() or not path.is_file():
        raise PlanError("Missing indexed local sound asset")
    raw = path.read_bytes()
    if len(raw) != matches[0]["bytes"] or hashlib.sha256(raw).hexdigest() != matches[0]["sha256"]:
        raise PlanError("Local sound asset differs from its exact index")
    return str(path.absolute())


def resolve_sound_project_presets(config: dict, config_dir: str | Path | None = None) -> dict:
    """Expand explicit named presets before the new schema's strict parser.

    KA in the synthetic examples has an explicit visible 248-sample crop.
    A preset is a new composition, never a claim to reproduce installed R066.
    """
    if not isinstance(config, dict) or config.get("schema") != "a7m4-pin-sound-project/1":
        raise PlanError("Unsupported PIN sound project schema")
    value = deepcopy(config)
    key = value.pop("preset", None)
    if key is not None and key not in _RECIPES:
        raise PlanError("Unknown local sound preset")
    recipe = _RECIPES.get(key)
    clips = value.setdefault("clips", {})
    if not isinstance(clips, dict):
        raise PlanError("Sound clips must be an object")
    if recipe:
        for role in ("ka", "sha_dry"):
            if role not in clips:
                clips[role] = {"path": _asset(recipe[role])}
                if role == "ka" and key in ("dry", "soft"):
                    clips[role].update(end_seconds=248 / 24000, fade_out_ms=1)
        if recipe["recock"]:
            clips.setdefault("recock", {"path": _asset("m9-recock.wav")})
        value.setdefault("recock", {"enabled": recipe["recock"], "gap_ms": 40})
    aliases = {"r065-accepted-ka": "factory-ka.wav", "leica-m9-sha": "m9-sha-dry.wav",
               "leica-m9-recock-motor": "m9-recock.wav"}
    for role, clip in clips.items():
        if isinstance(clip, dict) and "preset_asset" in clip:
            if clip["preset_asset"] not in aliases or "path" in clip:
                raise PlanError("Unknown or ambiguous preset sound asset")
            name = aliases[clip.pop("preset_asset")]
            clip["path"] = _asset(name)
    return value
