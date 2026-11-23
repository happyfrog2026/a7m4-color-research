"""One JSON CLI entry point for the toolbox and the bundled Mac GUI.

Local commands never discover a device. Device operations require the explicit
``driver`` namespace and their declared execution/preparation gates.
"""
from __future__ import annotations

import argparse
import contextlib
import importlib.metadata
import io
import json
from pathlib import Path
import sys

from . import __version__


LOCAL_COMMANDS = frozenset({
    "inspect", "sound-plan", "pin-sound-presets", "pin-sound-prepare", "pin-sound-verify",
    "pin-sound-preview", "pin-sound-plan", "pin-sound-inverse", "pin-sound-readback",
    "pin-sound-workers", "wav-inspect", "audio-prepare", "backup-create", "backup-verify",
    "restore-plan", "native-icons", "native-icon-banks",
})


def emit(value: dict) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False))


def status() -> dict:
    return {
        "schema": "a7m4-toolbox-status/1", "version": __version__, "build": 62,
        "forward_observation_scope": {"converted": ["electronic-sound-gate"], "E_F_control_flow": False, "other_forward": "LEGACY_PENDING_CONVERSION"},
        "cumulative_C_restore": {"requested_contract": "undo-union-of-tool-forward-C", "implemented": "Gate-only-explicit-history",
            "other_features": "NOT_SUPPORTED_BY_GATE_CAPSULE", "physical_validation": "NOT_PERFORMED",
                                 "legacy_original_restore_is_full_C_total": False},
        "backup_target_restore": {"target": "selected pre-modification .a7capture supported C",
            "installation_history_required": False, "current_capture_required": "fresh same-body complete capture; GUI reads automatically",
            "E_F_gate_execution": False, "E_F_restored": False, "original_sound_target_eof": 77504,
            "checkpoint": "selected-backup binding and actual readback plus fresh boot", "physical_validation": "NOT_PERFORMED"},
        "selected_install": {"selection_schema": "a7m4-selected-config/1", "presets_fill_values_only": True,
            "requires_original_baseline": True, "requires_loaded_AP_C_D": True, "cumulative_update": False,
            "final_sound_and_display_assets_bound": True, "sound_none": "silent-original-baseline",
            "camera_cutoffs_seconds": [0.125, 0.02], "preset_cutoff_seconds": 0.125,
            "fixed_KASHA_internal_delay_seconds": 0.02, "E_F_gate_execution": False,
            "physical_validation": "NOT_PERFORMED"},
        "model": "ILCE-7M4", "firmware": "6.02", "camera_io": False,
        "current_camera_state_observed": False, "internet_uploads": False,
        "policy": {"filter_uploads": False, "custom_filter_recipes": ["m9"],
                   "historical_m9_slot": 4, "custom_m9_target_slot": 1, "other_custom_slots": "preserved", "runtime_slots": 4,
                   "sound_import": True, "custom_display_icons": True},
        "recorded_baseline": "R066 fixed PIN accepted; future jobs require fresh complete identities",
        "recorded_body_cutoff": "approximately1/8",
        "new_project_cutoff_default": "1/50 local preparation",
        "historical_acceptance_does_not_cover_new_executor": True,
        "driver_readiness": {"usb_backup_coordinator_ready": True,
                             "electronic_sound_gate_coordinator_ready": True,
                             "persistent_write_coordinator_ready": True,
                             "full_file_tail_cleanup_coordinator_ready": True,
                             "post_boot_full_file_verification_coordinator_ready": True},
        "original_backup_restore": {
            "target": "selected earliest complete pre-modification backup",
            "diff_planner_ready": True, "coordinator_ready": True,
            "fixed_round_count": False, "device_validation": "NOT_PERFORMED"},
        "diagnostic_logs": {"automatic": True, "user_export": True, "folder": "~/Library/Logs/A7M4 Toolbox/", "automatic_upload": False},
        "new_backup_coordinator_device_validation": "not-performed; explicit regression is required",
    }


def doctor() -> dict:
    from ..research.doctor import check_environment
    from .usb_read import check_pmca_sources
    result = check_environment()
    result.update(schema="a7m4-toolbox-doctor/1", version=__version__, camera_io=False,
                  current_camera_state_observed=False, internet_uploads=False)
    usb = []
    for name in ("pyusb", "libusb-package", "importlib_resources"):
        try:
            usb.append({"distribution": name, "version": importlib.metadata.version(name), "installed": True})
        except importlib.metadata.PackageNotFoundError:
            usb.append({"distribution": name, "installed": False})
    try:
        pmca = check_pmca_sources()
        pmca_ok = pmca.get("ready") is True
    except (OSError, ValueError) as error:
        pmca, pmca_ok = {"verified": False, "error": str(error)}, False
    result["usb_dependencies"] = usb
    from .dependency_probe import probe
    native = probe()
    result["native_dependencies"] = native
    result["pmca_sources"] = pmca
    result["ready_for_explicit_usb_session"] = pmca_ok and all(row["installed"] for row in usb) and native['ready']
    result["usb_backend_created"] = False
    if not native['ready']:
        result.update(status='LOCAL_DEPENDENCIES_NOT_READY',ready_for_local_work=False,error=native['error'])
    result["note"] = "实际加载本地加密及 USB 动态库；不创建 USB backend，不初始化、枚举或连接相机。"
    return result


def _driver_parser(parser):
    sub = parser.add_subparsers(dest="operation", required=True)
    sub.add_parser("status", help="发行范围与历史基线；不检测相机")
    sub.add_parser("doctor", help="检查本地运行依赖；不创建 USB backend")
    diagnostics=sub.add_parser('diagnostics-export',help='导出全部仍存的本地历史日志和安全详细报告；不连接相机')
    diagnostics.add_argument('--output',type=Path,required=True)
    connection=sub.add_parser('connection-check',help='只读检查 macOS USB 身份；不卸载、不打开相机服务')
    connection.add_argument('--output',type=Path)
    for name in ('capture-inspect','capture-export','capture-adopt'):
        local=sub.add_parser(name,help='本地核验／导出或显式宿主收尾；不重新读取相机文件')
        local.add_argument('--capture',type=Path,required=True)
        if name!='capture-inspect':local.add_argument('--output',type=Path,required=True)
    sub.add_parser("tail-restore-status", help="查看完整文件尾部收尾的接入状态；不检测设备")
    scoped=sub.add_parser('backup-target-plan',help='从所选原始备份生成已支持功能区域的恢复计划；不连接相机')
    scoped.add_argument('--capture',type=Path,required=True)
    scoped.add_argument('--original-capture',type=Path,required=True)
    scoped.add_argument('--output',type=Path)
    scoped.add_argument('--previous-job',type=Path)
    for name in ('backup-target-restore','backup-target-verify'):
        restore=sub.add_parser(name,help='从所选原始备份恢复功能区域／启动后只读核验；不依赖安装历史')
        for arg in ('capture','original-capture','output'):restore.add_argument('--'+arg,type=Path,required=True)
        restore.add_argument('--previous-job',type=Path)
        restore.add_argument('--compiler',type=Path)
        restore.add_argument('--job-owner-uid',type=int);restore.add_argument('--job-owner-gid',type=int)
        for flag in ('execute','battery-confirmed','msc-confirmed','ack-original','ack-backup','ack-brick','ack-risk','startup-confirmed'):
            restore.add_argument('--'+flag,action='store_true')
    acceptance=sub.add_parser('backup-target-acceptance',help='本地记录已核验备份恢复的用户功能观察；不连接相机')
    acceptance.add_argument('--job',type=Path,required=True);acceptance.add_argument('--output',type=Path,required=True)
    for flag in ('names-confirmed','sound-confirmed','shoot-confirmed','playback-confirmed'):
        acceptance.add_argument('--'+flag,action='store_true')
    original = sub.add_parser("original-restore-plan", help="对比当前完整备份与最初备份；只生成自适应恢复计划")
    original.add_argument('--capture',type=Path,required=True)
    original.add_argument('--original-capture',type=Path,required=True)
    original.add_argument('--output',type=Path)
    original.add_argument('--previous-job',type=Path)
    for name in ('original-restore','original-verify'):
        restore=sub.add_parser(name,help='恢复最初完整备份／启动后完整只读核验；须明确启动')
        for arg in ('capture','original-capture','output'):
            restore.add_argument('--'+arg,type=Path,required=True)
        restore.add_argument('--previous-job',type=Path)
        restore.add_argument('--compiler',type=Path)
        restore.add_argument('--job-owner-uid',type=int);restore.add_argument('--job-owner-gid',type=int)
        for flag in ('execute','battery-confirmed','msc-confirmed','ack-original','ack-backup','ack-brick','ack-risk','startup-confirmed'):
            restore.add_argument('--'+flag,action='store_true')
    acceptance=sub.add_parser('original-acceptance',help='本地记录已核验恢复的用户功能观察；不连接相机')
    acceptance.add_argument('--job',type=Path,required=True);acceptance.add_argument('--output',type=Path,required=True)
    for flag in ('names-confirmed','sound-confirmed','shoot-confirmed','playback-confirmed'):
        acceptance.add_argument('--'+flag,action='store_true')
    filters = sub.add_parser("validate-filters", help="验证仅 M9 的固定四槽配置，不接触设备")
    filters.add_argument("config", type=Path)
    helpers = sub.add_parser("helpers", help="列出并验证随包 helper 内容")
    helpers.add_argument("--verify", action="store_true")
    capture = sub.add_parser("backup", help="显式从普通 MSC 服务读取并验证11对象备份")
    capture.add_argument("--output", type=Path, required=True)
    capture.add_argument("--execute", action="store_true", help="明确请求本次普通 USB 只读会话")
    capture.add_argument("--battery-confirmed", action="store_true")
    capture.add_argument("--msc-confirmed", action="store_true")
    capture.add_argument("--job-owner-uid", type=int)
    capture.add_argument("--job-owner-gid", type=int)
    local = sub.add_parser("restore-plan", help="校验本地备份并比较恢复范围；不执行恢复")
    local.add_argument("archive", type=Path)
    local.add_argument("--snapshot", type=Path, required=True)
    local.add_argument("--output", type=Path)
    reconcile=sub.add_parser('reconcile-gate',help='本地只读核对已完成程序段；不连接设备或修改失败记录')
    for name in ('failed-receipt','fresh-capture','closeout-folder','output'):
        reconcile.add_argument('--'+name,type=Path,required=True)
    gate_plan=sub.add_parser("sound-gate-plan",help="从已验证机身备份生成固定声音开关计划；不连接设备")
    gate_plan.add_argument("--capture",type=Path,required=True,help="完整备份的 capture.private.json")
    gate_plan.add_argument("--state",choices=("enabled","disabled"),required=True)
    gate_plan.add_argument("--output",type=Path)
    gate_plan.add_argument("--program-job",type=Path,action="append",default=[])
    gate_plan.add_argument("--sound-job",type=Path)
    gate=sub.add_parser("sound-gate",help="显式执行固定电子快门声开关；新协调器尚待机身回归")
    gate.add_argument("--capture",type=Path,required=True)
    gate.add_argument("--state",choices=("enabled","disabled"),required=True)
    gate.add_argument('--program-job',type=Path,action='append',default=[])
    gate.add_argument('--sound-job',type=Path)
    gate.add_argument('--c-capsule',dest='C_capsule',type=Path,help='延续明确的 Gate 累计 C 原件链')
    for name in ('features-plan','features','feature-c-restore-plan','feature-c-restore'):
        feature=sub.add_parser(name,help='三套固定功能的本地计划／显式执行和实际累计 C 恢复')
        feature.add_argument('--capture',type=Path,required=True)
        if name.startswith('features'):
            feature.add_argument('--profile',choices=('fl23','custom1-m9','all-current'),required=True)
            feature.add_argument('--native-project',type=Path)
            feature.add_argument('--prepared',type=Path)
        else:
            feature.add_argument('--capsule',type=Path,required=True)
            feature.add_argument('--previous-job',type=Path)
        if not name.endswith('-plan'):
            feature.add_argument('--output',type=Path,required=True);feature.add_argument('--compiler',type=Path)
            feature.add_argument('--job-owner-uid',type=int);feature.add_argument('--job-owner-gid',type=int)
            for flag in ('execute','battery-confirmed','msc-confirmed','ack-backup','ack-brick','ack-risk'):
                feature.add_argument('--'+flag,action='store_true')
    for name in ('sound-scoped-plan','sound-scoped','sound-c-restore-plan','sound-c-restore'):
        scoped=sub.add_parser(name,help='首次原厂声音 C/D 安装／Gate与声音累计 C 恢复')
        scoped.add_argument('--capture',type=Path,required=True)
        if name.startswith('sound-scoped'):
            scoped.add_argument('--prepared',type=Path,required=True)
            scoped.add_argument('--gate-capsule',type=Path,required=True)
        else:scoped.add_argument('--capsule',type=Path,required=True)
        if not name.endswith('-plan'):
            scoped.add_argument('--output',type=Path,required=True);scoped.add_argument('--compiler',type=Path)
            scoped.add_argument('--job-owner-uid',type=int);scoped.add_argument('--job-owner-gid',type=int)
            for flag in ('execute','battery-confirmed','msc-confirmed','ack-backup','ack-brick','ack-risk'):
                scoped.add_argument('--'+flag,action='store_true')
    for name in ('gate-c-restore-plan','gate-c-restore'):
        restore=sub.add_parser(name,help='只恢复 Gate 显式累计 C；E/F 仅观察，不走完整原厂恢复')
        restore.add_argument('--capture',type=Path,required=True)
        restore.add_argument('--capsule',type=Path,required=True)
        if name=='gate-c-restore':
            restore.add_argument('--output',type=Path,required=True);restore.add_argument('--compiler',type=Path)
            restore.add_argument('--job-owner-uid',type=int);restore.add_argument('--job-owner-gid',type=int)
            for flag in ('execute','battery-confirmed','msc-confirmed','ack-backup','ack-brick','ack-risk'):
                restore.add_argument('--'+flag,action='store_true')
    for name in ('portable-verify','portable-import'):
        portable=sub.add_parser(name,help='校验／导入完整便携备份；不连接设备')
        portable.add_argument('archive',type=Path)
        if name=='portable-import':portable.add_argument('--output',type=Path,required=True)
    for name in ('looks-plan','looks'):
        look=sub.add_parser(name,help='固定 FL2／FL3、自定义1 M9与原生显示')
        look.add_argument('--capture',type=Path,required=True)
        look.add_argument('--config',type=Path,required=True)
        look.add_argument('--native-project',type=Path)
        look.add_argument('--output',type=Path,required=True)
        look.add_argument('--program-job',type=Path,action='append',default=[])
        look.add_argument('--sound-job',type=Path)
        if name=='looks':
            look.add_argument('--compiler',type=Path)
            for flag in ('execute','battery-confirmed','msc-confirmed','ack-backup','ack-brick','ack-risk'):
                look.add_argument('--'+flag,action='store_true')
            look.add_argument('--job-owner-uid',type=int);look.add_argument('--job-owner-gid',type=int)
    freeze=sub.add_parser('selected-freeze',help='封存最终选择和本地原始备份、声音、图标身份；不连接相机')
    freeze.add_argument('--draft',type=Path,required=True)
    freeze.add_argument('--original-capture',type=Path,required=True)
    freeze.add_argument('--prepared',type=Path);freeze.add_argument('--native-project',type=Path)
    freeze.add_argument('--output',type=Path,required=True)
    for name in ('selected-plan','selected-install'):
        selected=sub.add_parser(name,help='原始基线上的最终选择计划／安装')
        selected.add_argument('--capture',type=Path,required=True)
        selected.add_argument('--selection',type=Path,required=True)
        selected.add_argument('--selection-sha256',required=True)
        selected.add_argument('--output',type=Path,required=name=='selected-install')
        if name=='selected-install':
            selected.add_argument('--compiler',type=Path)
            for flag in ('execute','battery-confirmed','msc-confirmed','ack-backup','ack-brick','ack-risk'):
                selected.add_argument('--'+flag,action='store_true')
            selected.add_argument('--job-owner-uid',type=int);selected.add_argument('--job-owner-gid',type=int)
    for name in ('sound','sound-plan','restore','restore-job-plan'):
        operation=sub.add_parser(name,help='受限声音应用／备份恢复；计划命令只处理本地文件')
        operation.add_argument('--capture',type=Path,required=True)
        if name in ('sound','sound-plan'):
            operation.add_argument('--prepared',type=Path,required=True)
            operation.add_argument('--previous-job',type=Path)
            operation.add_argument('--program-job',type=Path,action='append',default=[])
        else:operation.add_argument('--previous-job',type=Path,required=True)
        if name in ('sound','restore'):
            operation.add_argument('--output',type=Path,required=True);operation.add_argument('--compiler',type=Path)
            for flag in ('execute','battery-confirmed','msc-confirmed','ack-backup','ack-brick','ack-risk'):
                operation.add_argument('--'+flag,action='store_true')
            operation.add_argument('--job-owner-uid',type=int);operation.add_argument('--job-owner-gid',type=int)
    gate.add_argument("--output",type=Path,required=True)
    gate.add_argument("--compiler",type=Path)
    for name in ("execute","battery-confirmed","msc-confirmed","ack-backup","ack-brick","ack-risk"):
        gate.add_argument("--"+name,action="store_true")
    gate.add_argument("--job-owner-uid",type=int)
    gate.add_argument("--job-owner-gid",type=int)


def main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    # Existing native audio/icon pages keep their local command API. The new
    # public driver deliberately omits generic byte-patch and CUBE entry points.
    if args and args[0] in LOCAL_COMMANDS:
        from ..research.__main__ import main as local_main
        return local_main(args)
    parser = argparse.ArgumentParser(description="A7 IV 工具箱：共用 GUI／CLI driver。")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("status", help="查看功能范围和历史状态，不检测设备")
    sub.add_parser("doctor", help="检查本地依赖，不检测设备")
    _driver_parser(sub.add_parser("driver", help="受限设备作业与本地准备接口"))
    parsed = parser.parse_args(args)
    io_state = False
    completed_result = None
    if getattr(parsed, 'output', None) is not None:
        from .output_space import warn
        warn(parsed.output, capture=getattr(parsed, 'capture', None), operation=getattr(parsed, 'operation', None))
    try:
        if parsed.command == "status" or getattr(parsed, "operation", None) == "status":
            result = status()
        elif parsed.command == "doctor" or getattr(parsed, "operation", None) == "doctor":
            result = doctor()
        elif parsed.operation=='selected-freeze':
            from . import selected_config
            from .capture_inputs import read_private
            draft=json.loads(read_private(parsed.draft,65536))
            result=selected_config.freeze(draft,parsed.original_capture,prepared=parsed.prepared,
                native_project=parsed.native_project,output=parsed.output)
        elif parsed.operation=='selected-plan':
            from .selected_plan import make_plan
            result=make_plan(parsed.capture,parsed.selection,selection_sha256=parsed.selection_sha256)
            if parsed.output:
                from .native_actions import _write,_json
                _write(parsed.output,_json(result))
        elif parsed.operation=='selected-install':
            if not all(getattr(parsed,name) for name in ('execute','battery_confirmed','msc_confirmed','ack_backup','ack_brick','ack_risk')):
                raise ValueError('本次应用须确认原始备份、电量、MSC、本次执行、变砖风险及自行承担风险；尚未检测相机。')
            from .selected_job import execute
            from .job_ownership import result_owner
            from .ownership import camera_lock
            with result_owner(parsed.output,parsed.job_owner_uid,parsed.job_owner_gid):
                with contextlib.redirect_stdout(io.StringIO()):
                    io_state=False # Post-entry failures carry the shared lifecycle result; bare failures here are local preflight.
                    result=execute(parsed.capture,parsed.selection,parsed.output,selection_sha256=parsed.selection_sha256,compiler=parsed.compiler,
                        lock=lambda:camera_lock(owner_uid=parsed.job_owner_uid))
                    completed_result=result
        elif parsed.operation=='diagnostics-export':
            from .diagnostics_archive import export_archive
            result=export_archive(parsed.output,app_metadata=dict(version=__version__))
        elif parsed.operation=='connection-check':
            from . import host_metadata as host
            import time
            observation=host.identity_survey(deadline=time.monotonic()+60)
            result=dict(schema='a7m4-host-connection-check/1',status='MSC_OBSERVED',connected=True,
                model=observation['metadata']['camera']['model'],firmware_verified=False,
                camera_io=False,host_io=True,camera_protocol_requests=0,observation=observation)
            if parsed.output:
                from .native_actions import _write,_json
                _write(parsed.output,_json(result))
        elif parsed.operation in ('capture-inspect','capture-export','capture-adopt'):
            from . import capture_recovery as recovery
            if parsed.operation=='capture-export':result=recovery.export_capture(parsed.capture,parsed.output)
            elif parsed.operation=='capture-adopt':result=recovery.adopt_after_host_return(parsed.capture,parsed.output)
            else:
                value=recovery.data_capture(parsed.capture)
                result=dict(schema='a7m4-capture-data/1',complete=True,verified=True,data_integrity_verified=True,
                    normal_return_verified=value['normal_return_verified'],origin_status=value['status'],
                    receipt=str(parsed.capture.absolute()),archive=value['archive'],snapshot_dir=value['snapshot_dir'],
                    camera_io=False,host_io=False,device_admission=False)
        elif parsed.operation == 'reconcile-gate':
            from .program_reconciliation import create_reconciliation
            result=create_reconciliation(parsed.failed_receipt,parsed.fresh_capture,parsed.closeout_folder,parsed.output)
        elif parsed.operation == "tail-restore-status":
            from .tail_cleanup import integration_status
            result = integration_status()
        elif parsed.operation=='backup-target-plan':
            from .backup_target_scope import make_plan
            if parsed.previous_job:
                from .backup_target_resume import rebuild_projection
                result,_=rebuild_projection(parsed.capture,parsed.original_capture,parsed.previous_job)
            else:result=make_plan(parsed.capture,parsed.original_capture)
            if parsed.output:
                from .native_actions import _write,_json
                _write(parsed.output,_json(result))
        elif parsed.operation in ('backup-target-restore','backup-target-verify'):
            flags=('execute','battery_confirmed','msc_confirmed','ack_original','ack_backup','ack_brick','ack_risk')
            if not all(getattr(parsed,name) for name in flags):
                raise ValueError('请确认所选原始备份、电量、MSC、本次执行、变砖风险及自行承担风险；尚未检测相机。')
            from .job_ownership import result_owner
            from .backup_target_flow import execute
            with result_owner(parsed.output,parsed.job_owner_uid,parsed.job_owner_gid):
                with contextlib.redirect_stdout(io.StringIO()):
                    io_state=None
                    result=execute(parsed.capture,parsed.original_capture,parsed.output,compiler=parsed.compiler,
                        owner_uid=parsed.job_owner_uid,previous_job=parsed.previous_job,
                        verify_after_startup=parsed.operation=='backup-target-verify',startup_confirmed=parsed.startup_confirmed)
                    completed_result=result
        elif parsed.operation=='backup-target-acceptance':
            from .backup_target_flow import record_acceptance
            result=record_acceptance(parsed.job,parsed.output,names=parsed.names_confirmed,sound=parsed.sound_confirmed,
                shoot=parsed.shoot_confirmed,playback=parsed.playback_confirmed)
        elif parsed.operation == "original-restore-plan":
            from .original_restore import make_plan
            result = make_plan(parsed.capture, parsed.original_capture)
            if parsed.previous_job:
                from .original_restore_flow import previous_receipt
                previous_receipt(parsed.previous_job, result)
            if parsed.output:
                with parsed.output.open('x',encoding='utf-8') as stream:
                    json.dump(result,stream,ensure_ascii=False,indent=2,allow_nan=False)
                    stream.write('\n')
        elif parsed.operation in ('original-restore','original-verify'):
            if parsed.operation=='original-restore':
                raise ValueError('旧恢复写入口已停用：请使用 backup-target-restore（先保存ST并验证运行模型，再撤程序）。离线原始恢复计划仍可使用；尚未访问相机。')
            flags=('execute','battery_confirmed','msc_confirmed','ack_original')
            if parsed.operation=='original-restore':flags+=('ack_backup','ack_brick','ack_risk')
            else:flags+=('startup_confirmed',)
            if not all(getattr(parsed,name) for name in flags):
                raise ValueError('请重新确认本次电量、MSC、最初备份与执行；写入还须确认备份、变砖风险及自行承担风险。尚未检测相机。')
            from .job_ownership import result_owner
            from .original_restore_flow import execute
            with result_owner(parsed.output,parsed.job_owner_uid,parsed.job_owner_gid):
                with contextlib.redirect_stdout(io.StringIO()):
                    io_state=None
                    result=execute(parsed.capture,parsed.original_capture,parsed.output,compiler=parsed.compiler,
                        owner_uid=parsed.job_owner_uid,previous_job=parsed.previous_job,
                        verify_after_startup=parsed.operation=='original-verify',startup_confirmed=parsed.startup_confirmed)
                    completed_result=result
        elif parsed.operation=='original-acceptance':
            from .original_restore_flow import record_acceptance
            result=record_acceptance(parsed.job,parsed.output,names=parsed.names_confirmed,sound=parsed.sound_confirmed,
                shoot=parsed.shoot_confirmed,playback=parsed.playback_confirmed)
        elif parsed.operation == "validate-filters":
            from .policy import filter_selection
            value = json.loads(parsed.config.read_text(encoding="utf-8"))
            result = {"schema": "a7m4-filter-validation/1", "verified": True,
                      "selection": filter_selection(value), "camera_io": False}
        elif parsed.operation == "helpers":
            from .helpers import helper_inventory
            result = helper_inventory(verify=parsed.verify)
        elif parsed.operation == "backup":
            if not (parsed.execute and parsed.battery_confirmed and parsed.msc_confirmed):
                raise ValueError("本次读取需明确 --execute、--battery-confirmed 和 --msc-confirmed；尚未检测相机。")
            from .ownership import capture_with_ownership, camera_lock
            from .job_ownership import result_owner
            # Third-party auth may print progress; keep stdout one JSON result.
            # The process-local log is held in memory and never uploaded.
            log = io.StringIO()
            with result_owner(parsed.output, parsed.job_owner_uid, parsed.job_owner_gid):
                with contextlib.redirect_stdout(log):
                    io_state = None
                    result = capture_with_ownership(parsed.output,
                        lock=lambda: camera_lock(owner_uid=parsed.job_owner_uid))
                    completed_result = result
        elif parsed.operation == "restore-plan":
            from ..research.backup import plan_restore
            result = plan_restore(parsed.archive, parsed.snapshot)
            if parsed.output:
                with parsed.output.open("x", encoding="utf-8") as stream:
                    json.dump(result, stream, ensure_ascii=False, indent=2, allow_nan=False)
                    stream.write("\n")
        elif parsed.operation == "sound-gate-plan":
            from .device_job import gate_selection
            result=gate_selection(parsed.capture,parsed.state,program_jobs=parsed.program_job,sound_job=parsed.sound_job)
            if parsed.output:
                with parsed.output.open("x",encoding="utf-8") as stream:
                    json.dump(result,stream,ensure_ascii=False,indent=2,allow_nan=False)
                    stream.write("\n")
        elif parsed.operation in ('portable-verify','portable-import'):
            from .settings_archive import verify_portable,import_portable
            result=verify_portable(parsed.archive) if parsed.operation=='portable-verify' else import_portable(parsed.archive,parsed.output)
        elif parsed.operation in ('looks-plan','looks'):
            from .device_job import looks_selection,execute_looks
            from .policy import filter_selection
            from .capture_inputs import read_private
            selection=filter_selection(json.loads(read_private(parsed.config,65536)))
            if parsed.operation=='looks-plan':
                result=looks_selection(parsed.capture,selection,parsed.native_project,parsed.output,
                    program_jobs=parsed.program_job,sound_job=parsed.sound_job)
            else:
                if not all(getattr(parsed,name) for name in ('execute','battery_confirmed','msc_confirmed','ack_backup','ack_brick','ack_risk')):
                    raise ValueError('本次应用须重新确认电量、MSC、已完成备份、可能变砖以及自行承担所有风险；尚未检测相机。')
                from .job_ownership import result_owner
                from .ownership import camera_lock
                with result_owner(parsed.output,parsed.job_owner_uid,parsed.job_owner_gid):
                    with contextlib.redirect_stdout(io.StringIO()):
                        io_state=None
                        result=execute_looks(parsed.capture,selection,parsed.native_project,parsed.output,compiler=parsed.compiler,
                            program_jobs=parsed.program_job,sound_job=parsed.sound_job,
                            lock=lambda:camera_lock(owner_uid=parsed.job_owner_uid))
                        completed_result=result
        elif parsed.operation in ('sound-plan','sound','restore-job-plan','restore'):
            if parsed.operation=='sound-plan':
                from .pin_family_job import product_sound_plan
                result=product_sound_plan(parsed.capture,parsed.prepared,previous_job=parsed.previous_job,program_jobs=parsed.program_job)
            elif parsed.operation=='restore-job-plan':
                from .restore import looks_restore_plan,gate_restore_plan
                from .capture_inputs import read_private
                path=parsed.previous_job/'job.private.json' if parsed.previous_job.is_dir() else parsed.previous_job
                feature=json.loads(read_private(path,2*1024*1024)).get('feature')
                if feature in ('product-pin-first-install','product-pin-replacement'):
                    from .pin_family_job import product_inverse_plan
                    result=product_inverse_plan(parsed.capture,path)
                else:
                    planned=gate_restore_plan(parsed.capture,path) if feature=='electronic-sound-gate' else looks_restore_plan(parsed.capture,path)
                    result={k:v for k,v in planned.items() if k!='settings_factories'}
                    result.update(camera_io=False,settings_kinds=[kind for kind,_ in planned['settings_factories']],device_validation='not-performed')
            else:
                if not all(getattr(parsed,name) for name in ('execute','battery_confirmed','msc_confirmed','ack_backup','ack_brick','ack_risk')):
                    raise ValueError('本次操作须重新确认电量、MSC、已完成备份、可能变砖和自行承担所有风险；尚未检测相机。')
                from .job_ownership import result_owner
                from .ownership import camera_lock
                with result_owner(parsed.output,parsed.job_owner_uid,parsed.job_owner_gid):
                    with contextlib.redirect_stdout(io.StringIO()):
                        io_state=None
                        if parsed.operation=='sound':
                            from .pin_family_job import execute_product_sound
                            result=execute_product_sound(parsed.capture,parsed.prepared,parsed.output,compiler=parsed.compiler,
                                previous_job=parsed.previous_job,program_jobs=parsed.program_job,
                                lock=lambda:camera_lock(owner_uid=parsed.job_owner_uid))
                        else:
                            from .restore import execute_restore
                            result=execute_restore(parsed.capture,parsed.previous_job,parsed.output,compiler=parsed.compiler,
                                lock=lambda:camera_lock(owner_uid=parsed.job_owner_uid))
                        completed_result=result
        elif parsed.operation in ('sound-scoped-plan','sound-c-restore-plan'):
            from .sound_cumulative_job import plan_sound_scope,plan_union_restore
            result=(plan_sound_scope(parsed.capture,parsed.prepared,parsed.gate_capsule) if parsed.operation=='sound-scoped-plan'
                else plan_union_restore(parsed.capture,parsed.capsule))
        elif parsed.operation in ('features-plan','feature-c-restore-plan'):
            from . import feature_job
            result=(feature_job.plan_forward(parsed.capture,parsed.profile,native_project=parsed.native_project,
                prepared=parsed.prepared) if parsed.operation=='features-plan' else
                feature_job.plan_restore(parsed.capture,parsed.capsule,previous_job=parsed.previous_job))
        elif parsed.operation in ('features','feature-c-restore'):
            if parsed.operation=='feature-c-restore':
                raise ValueError('旧逐功能恢复写入口已停用：请从原始备份使用 backup-target-restore；尚未访问相机。')
            if not all(getattr(parsed,name) for name in ('execute','battery_confirmed','msc_confirmed','ack_backup','ack_brick','ack_risk')):
                raise ValueError('本次应用须确认电量、MSC、已完成备份、变砖风险及自行承担风险；尚未检测相机。')
            from . import feature_job
            from .job_ownership import result_owner
            from .ownership import camera_lock
            with result_owner(parsed.output,parsed.job_owner_uid,parsed.job_owner_gid):
                with contextlib.redirect_stdout(io.StringIO()):
                    io_state=None
                    common=dict(compiler=parsed.compiler,lock=lambda:camera_lock(owner_uid=parsed.job_owner_uid))
                    if parsed.operation=='features':
                        result=feature_job.execute_forward(parsed.capture,parsed.profile,parsed.output,
                            native_project=parsed.native_project,prepared=parsed.prepared,**common)
                    elif parsed.previous_job is not None:
                        result=feature_job.execute_resume(parsed.capture,parsed.capsule,parsed.previous_job,parsed.output,**common)
                    else:
                        result=feature_job.execute_restore(parsed.capture,parsed.capsule,parsed.output,**common)
                    completed_result=result
        elif parsed.operation in ('sound-scoped','sound-c-restore'):
            if not all(getattr(parsed,name) for name in ('execute','battery_confirmed','msc_confirmed','ack_backup','ack_brick','ack_risk')):
                raise ValueError('本次应用须确认电量、MSC、已完成备份、变砖风险及自行承担风险；尚未检测相机。')
            from .sound_cumulative_job import execute_scoped_sound,execute_union_restore
            from .job_ownership import result_owner
            from .ownership import camera_lock
            with result_owner(parsed.output,parsed.job_owner_uid,parsed.job_owner_gid):
                with contextlib.redirect_stdout(io.StringIO()):
                    io_state=None
                    common=dict(compiler=parsed.compiler,lock=lambda:camera_lock(owner_uid=parsed.job_owner_uid))
                    result=(execute_scoped_sound(parsed.capture,parsed.prepared,parsed.output,gate_capsule=parsed.gate_capsule,**common)
                        if parsed.operation=='sound-scoped' else execute_union_restore(parsed.capture,parsed.capsule,parsed.output,**common))
                    completed_result=result
        elif parsed.operation=='gate-c-restore-plan':
            from .device_job import gate_C_restore_selection
            result,_=gate_C_restore_selection(parsed.capture,parsed.capsule)
            result.update(camera_io=False,device_validation='not-performed',coverage='Gate-only-explicit-history')
        elif parsed.operation in ("sound-gate",'gate-c-restore'):
            if not all(getattr(parsed,name) for name in
                       ("execute","battery_confirmed","msc_confirmed","ack_backup","ack_brick","ack_risk")):
                raise ValueError("本次写入须明确确认电量、MSC、已完成备份、可能无法开机及自行承担风险；尚未检测相机。")
            from .device_job import execute_gate,execute_gate_C_restore
            from .job_ownership import result_owner
            from .ownership import camera_lock
            with result_owner(parsed.output,parsed.job_owner_uid,parsed.job_owner_gid):
                with contextlib.redirect_stdout(io.StringIO()):
                    io_state=None
                    common=dict(compiler=parsed.compiler,lock=lambda:camera_lock(owner_uid=parsed.job_owner_uid))
                    if parsed.operation=='sound-gate':
                        result=execute_gate(parsed.capture,parsed.state,parsed.output,
                            program_jobs=parsed.program_job,sound_job=parsed.sound_job,
                            **({'C_capsule':parsed.C_capsule} if parsed.C_capsule is not None else {}),**common)
                    else:result=execute_gate_C_restore(parsed.capture,parsed.capsule,parsed.output,**common)
                    completed_result=result
        else:
            raise ValueError("不支持的 driver 操作。")
        emit(result)
        return 0
    except (OSError, ValueError, RuntimeError) as error:
        partial = getattr(error, "result", None)
        if not isinstance(partial, dict) and completed_result is not None:
            partial = {**completed_result, "status": "STOPPED_RESULT_DELIVERY",
                       "error": str(error), "result_delivery_confirmed": False}
        result = partial if isinstance(partial, dict) else {
            "schema": "a7m4-toolbox-error/1", "status": "STOPPED_INPUT_OR_DEPENDENCY",
            "error": str(error), "camera_io": io_state, "internet_uploads": False,
        }
        from .host_metadata import ToolError
        if isinstance(error,ToolError):
            result['host_error']=dict(code=error.code,details=error.details)
            from .run_log import event
            event('host-observation-error',code=error.code,details=error.details)
        emit(result)
        return 2
