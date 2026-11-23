"""Command-line entry point for the offline internal research kit."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

from . import __version__
from .offline import baseline_metadata, inspect_image, load_manifest, plan_changes


def write_new_json(path: Path, value: dict) -> None:
    """Keep existing results intact, including when a symlink is supplied."""
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write("\n")


def demo(output: Path) -> dict:
    """Run a complete, local example using only invented bytes and artwork."""
    from .icons import build_icons

    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    source = bytes(range(64))
    (output / "synthetic-source.bin").write_bytes(source)
    manifest = {
        "schema": "a7m4-offline-plan/1",
        "source": {"path": "synthetic-source.bin", "kind": "synthetic", "size": len(source),
                   "sha256": hashlib.sha256(source).hexdigest()},
        "windows": [{"offset": 8, "before_hex": "08090a0b", "after_hex": "a0a1a2a3"}],
        "append_hex": "c0ffee",
        "space": {"explicit_user_offline_measurement": True, "measurement_is_synthetic": True,
                  "measured_free_bytes": 16777216, "reserved_bytes": 0,
                  "uploads": [{"name": "synthetic-worker.bin", "size": 4096}]},
    }
    write_new_json(output / "plan-input.json", manifest)
    inspection = inspect_image(output / "synthetic-source.bin", "synthetic")
    write_new_json(output / "inspection.json", inspection)
    plan = plan_changes(manifest, base_dir=output)
    write_new_json(output / "plan-result.json", plan)
    icons = {"schema": "a7m4-icons/1", "slots": [
        {"slot": slot, "text": name} for slot, name in enumerate(("po", "fl", "m9", "bw"), 1)]}
    write_new_json(output / "icons-input.json", icons)
    build_icons(icons, output / "icons", config_dir=output)
    receipt = {
        "schema": "a7m4-research-demo/1", "status": "COMPLETED_SYNTHETIC_DEMO",
        "camera_io": False, "network_io": False, "installable": False,
        "free_space_is_synthetic": True, "output": str(output.absolute()),
        "gallery": str((output / "icons/gallery.html").absolute()),
        "plan": "plan-result.json", "inspection": "inspection.json",
        "note": "Invented bytes and artwork; this does not validate installation or camera behavior.",
    }
    write_new_json(output / "receipt.json", receipt)
    return receipt


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="A7 IV 6.02 工具箱；当前设备回归保持关闭。")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)
    inspect = sub.add_parser("inspect", help="核对本地 AP/CP 文件身份")
    inspect.add_argument("image", type=Path)
    inspect.add_argument("--kind", choices=("ap", "cp", "synthetic"), required=True)
    inspect.add_argument("--output", type=Path)
    plan = sub.add_parser("plan", help="验证本地精确变更，计算逆计划和空间预算")
    plan.add_argument("manifest", type=Path)
    plan.add_argument("--output", type=Path)
    sound = sub.add_parser("sound-plan", help="按完整 AP/CP 配对生成原厂短音启用／撤销离线计划")
    sound.add_argument("--ap", type=Path, required=True)
    sound.add_argument("--cp", type=Path, required=True)
    sound.add_argument("--state", choices=("enabled", "disabled"), required=True)
    sound.add_argument("--output", type=Path)
    sub.add_parser("doctor", help="实际检查本地依赖与内置资源，不枚举相机")
    audio = sub.add_parser("audio-prepare", help="检查并保存 KA/SHA/KA-SHA 本地声音项目")
    audio.add_argument("config", type=Path)
    audio.add_argument("--output", type=Path, required=True)
    sub.add_parser("pin-sound-presets", help="列出本地重合成音色；不代表新内容已上机验收")
    pin_audio = sub.add_parser("pin-sound-prepare", help="裁切、合成并编码原生声音，预览由最终编码解码")
    pin_audio.add_argument("config", type=Path)
    pin_audio.add_argument("--output", type=Path, required=True)
    pin_check = sub.add_parser("pin-sound-verify", help="完整校验本地原生声音包及解码预览")
    pin_check.add_argument("project", type=Path)
    pin_preview = sub.add_parser("pin-sound-preview", help="从已核对的最终原生声音生成整组试听")
    pin_preview.add_argument("project", type=Path)
    pin_preview.add_argument("--shutter-seconds", type=float, required=True)
    pin_preview.add_argument("--output", type=Path, required=True)
    pin_plan = sub.add_parser("pin-sound-plan", help="基于完整本地R066前像生成精确范围和逆操作计划")
    pin_plan.add_argument("--project", type=Path, required=True)
    pin_plan.add_argument("--cutoff", type=int, choices=(50,))
    pin_inverse = sub.add_parser("pin-sound-inverse", help="核对完整当前前像并生成精确逆计划")
    pin_inverse.add_argument("plan", type=Path)
    pin_readback = sub.add_parser("pin-sound-readback", help="在Mac核对完整读回，绝不连接相机")
    pin_readback.add_argument("plan", type=Path)
    pin_readback.add_argument("--direction", choices=("forward", "inverse"), default="forward")
    for command in (pin_plan, pin_inverse, pin_readback):
        command.add_argument("--ap", type=Path, required=True)
        command.add_argument("--cp-program", type=Path, required=True)
        command.add_argument("--bank", type=Path, required=True)
        command.add_argument("--output", type=Path)
    pin_workers = sub.add_parser("pin-sound-workers", help="离线构建有界数据包与来源绑定helper；不执行")
    pin_workers.add_argument("plan", type=Path)
    pin_workers.add_argument("--output", type=Path, required=True)
    pin_workers.add_argument("--compiler", type=Path, help="已有离线 Zig 0.13.0；不自动下载")
    wav = sub.add_parser("wav-inspect", help="核对本地 WAV 音频参数")
    wav.add_argument("audio", type=Path)
    wav.add_argument("--output", type=Path)
    backup = sub.add_parser("backup-create", help="从完整本地快照创建可恢复备份包")
    backup.add_argument("snapshot", type=Path)
    backup.add_argument("--output", type=Path, required=True)
    backup_check = sub.add_parser("backup-verify", help="校验备份包的全部对象和恢复范围")
    backup_check.add_argument("archive", type=Path)
    backup_check.add_argument("--output", type=Path)
    restore = sub.add_parser("restore-plan", help="将备份与当前本地快照完整比较，不执行设备恢复")
    restore.add_argument("archive", type=Path)
    restore.add_argument("--snapshot", type=Path, required=True)
    restore.add_argument("--output", type=Path)
    icons = sub.add_parser("icons", help="生成原创合成图标预览")
    icons.add_argument("config", type=Path)
    icons.add_argument("--output", type=Path, required=True)
    native_icons = sub.add_parser("native-icons", help="生成原生压缩图标；PNG 由最终载荷解码生成")
    native_icons.add_argument("config", type=Path)
    native_icons.add_argument("--output", type=Path, required=True)
    icon_banks = sub.add_parser("native-icon-banks", help="对本地完整图标库生成追加资源与精确引用计划")
    icon_banks.add_argument("--bank23", type=Path, required=True)
    icon_banks.add_argument("--bank32", type=Path, required=True)
    icon_banks.add_argument("--project", type=Path, required=True)
    icon_banks.add_argument("--output", type=Path, required=True)
    example = sub.add_parser("demo", help="一键运行合成例子")
    example.add_argument("output", type=Path)
    sub.add_parser("status", help="显示已记录的功能边界与身份基线")
    args = parser.parse_args(argv)
    try:
        if args.command == "inspect":
            result = inspect_image(args.image, args.kind)
        elif args.command == "plan":
            result = plan_changes(load_manifest(args.manifest), base_dir=args.manifest.absolute().parent)
        elif args.command == "sound-plan":
            from .sound import native_sound_plan
            result = native_sound_plan(args.ap, args.cp, args.state)
        elif args.command == "doctor":
            from .doctor import check_environment
            result = check_environment()
        elif args.command == "audio-prepare":
            from .audio import prepare_audio
            result = prepare_audio(load_manifest(args.config), args.output, config_dir=args.config.absolute().parent)
        elif args.command == "pin-sound-presets":
            from .pin_presets import sound_presets
            result = {"schema": "a7m4-pin-sound-presets/1", "presets": sound_presets(), "camera_io": False}
        elif args.command == "pin-sound-prepare":
            from .pin_audio import prepare_sound_project
            result = prepare_sound_project(load_manifest(args.config), args.output, config_dir=args.config.absolute().parent)
        elif args.command == "pin-sound-verify":
            from .pin_audio import validate_prepared_pack
            result = validate_prepared_pack(args.project)
        elif args.command == "pin-sound-preview":
            from .pin_audio import preview_sound
            result = preview_sound(args.project, args.shutter_seconds, args.output)
        elif args.command in ("pin-sound-plan", "pin-sound-inverse", "pin-sound-readback"):
            from .pin_plan import plan_pin_install, plan_pin_inverse, verify_full_readback
            images = {"ap": args.ap, "cp_program": args.cp_program, "bank": args.bank}
            if args.command == "pin-sound-plan":
                result = plan_pin_install(images, args.project, requested_cutoff=args.cutoff)
            elif args.command == "pin-sound-inverse":
                result = plan_pin_inverse(load_manifest(args.plan), images)
            else:
                result = verify_full_readback(load_manifest(args.plan), images, direction=args.direction)
        elif args.command == "pin-sound-workers":
            from .pin_plan import build_pin_workers
            result = build_pin_workers(load_manifest(args.plan), args.output, compiler=args.compiler)
        elif args.command == "wav-inspect":
            from .audio import inspect_wav
            result = inspect_wav(args.audio)
        elif args.command == "backup-create":
            from .backup import create_backup
            from ..resource_profile import ID as resource_profile
            from ..toolbox.output_space import warn
            warn(args.output)
            result = create_backup(args.snapshot, args.output, profile=resource_profile)
        elif args.command == "backup-verify":
            from .backup import verify_backup
            result = verify_backup(args.archive)
        elif args.command == "restore-plan":
            from .backup import plan_restore
            result = plan_restore(args.archive, args.snapshot)
        elif args.command == "icons":
            from .icons import build_icons
            result = build_icons(load_manifest(args.config), args.output, config_dir=args.config.absolute().parent)
        elif args.command == "native-icons":
            from .native_icons import generate_native_icons
            result = generate_native_icons(load_manifest(args.config), args.output, config_dir=args.config.absolute().parent)
        elif args.command == "native-icon-banks":
            from .native_icons import build_native_bank_plan
            result = build_native_bank_plan(args.bank23, args.bank32, args.project, args.output)
        elif args.command == "demo":
            result = demo(args.output)
        else:
            result = baseline_metadata()
        if getattr(args, "output", None) is not None and args.command in ("inspect", "plan", "sound-plan", "wav-inspect", "backup-verify", "restore-plan", "pin-sound-plan", "pin-sound-inverse", "pin-sound-readback"):
            write_new_json(args.output, result)
        print(json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False))
        failed = args.command == "doctor" and not result["ready_for_local_work"]
        if args.command in ("backup-create", "backup-verify"):
            failed = not (result.get("verified") is True and result.get("complete") is True)
        if args.command == "pin-sound-workers":
            failed = result.get("worker_built") is not True
        return 2 if failed else 0
    except (ValueError, OSError, RuntimeError, ImportError) as exc:
        print(json.dumps({"status": "STOPPED_LOCAL_INPUT", "error": str(exc),
                          "camera_io": False, "network_io": False}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
