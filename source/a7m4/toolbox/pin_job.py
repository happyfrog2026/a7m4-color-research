"""Source-bound PIN sound coordinator over an explicitly opened USB session.

Only a newly verified R066 backup and a validated prepared sound pack are
accepted. Replacement requires an explicitly selected completed previous job,
then plans inverse-to-R066 before the new forward. No user patch manifest,
existing bound worker, failure inverse or cutoff change is accepted. Public CLI/GUI owns
fresh user risk authorization before calling execute_pin_sound.
"""
from contextlib import ExitStack
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import tempfile

from ..research import pin_audio, pin_plan as pin
from .capture_inputs import read_private, verified_device_capture as verified_capture
from .native_actions import NativeActions, _write, _json
from .native_channel import channel_class, LIBRARY
from .ownership import camera_lock, release_host_volumes, verify_normal_return
from . import host_metadata, workspace
from .usb_read import ServiceSession, body_binding, VERSION_SHA256, LOADER_SHA256, _atomic_json

CUSTOM_CSV = "/usr/share/avsystemsound/custom.txt"
SNAPSHOT_PATHS = {"ap": "appFw.so", "cp_program": "CPAPP-B.BIN", "bank": "extras/SysSound.bin"}


class PinJobError(RuntimeError):
    def __init__(self, text, result):
        super().__init__(text)
        self.result = result


class UnsupportedPinSource(ValueError):
    code = "UNSUPPORTED_SOURCE_OR_REPLACEMENT"


def _source_paths(capture):
    root = Path(capture["snapshot_dir"])
    return {role: root / relative for role, relative in SNAPSHOT_PATHS.items()}


def _json_record(path):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("Duplicate key in previous PIN record")
            value[key] = item
        return value
    def reject(value):
        raise ValueError("Nonfinite previous PIN record")
    raw = read_private(path, 2 * 1024 * 1024)
    value = json.loads(raw, object_pairs_hook=unique, parse_constant=reject)
    if not isinstance(value, dict):
        raise ValueError("Previous PIN record must be an object")
    return value, sha256(raw).hexdigest()


def _previous_job(previous_job, capture):
    if not isinstance(previous_job, (str, os.PathLike)):
        raise ValueError("Previous job must be a completed local job path")
    path = Path(previous_job).absolute()
    if path.is_dir():
        path = path / "job.private.json"
    if path.name != "job.private.json":
        raise ValueError("Previous PIN job receipt filename differs")
    record, digest = _json_record(path)
    flags = ("camera_io", "camera_applied", "complete", "verified", "full_readback_verified",
             "stop_safe", "normal_return_verified", "service_exit_confirmed", "native_sequence_complete")
    if (record.get("schema") != "a7m4-toolbox-device-job/1" or record.get("status") != "VERIFIED_APPLIED"
            or record.get("feature") not in ("pin-sound-first-install", "pin-sound-replacement")
            or record.get("simulation") is not False or any(record.get(key) is not True for key in flags)
            or record.get("receipt") != str(path)):
        raise ValueError("Only a complete real VERIFIED_APPLIED previous PIN job supports replacement")
    if record.get("body_binding") != capture["body_binding"]:
        raise ValueError("Previous PIN job belongs to a different body")
    selection = record.get("selection", {})
    normal = record.get("normal_return", {})
    if (not isinstance(selection, dict) or not isinstance(record.get("build"), dict)
            or not isinstance(normal, dict) or normal.get("normal_msc_verified") is not True
            or normal.get("same_body_and_port") is not True):
        raise ValueError("Previous PIN complete session/MSC evidence is missing")
    plan, _ = _json_record(path.parent / "plan.json")
    build = record.get("build", {})
    if (selection.get("plan") != plan or selection.get("body_binding") != capture["body_binding"]
            or build.get("content_plan_id", build.get("plan_id")) != plan.get("plan_id")):
        raise ValueError("Previous PIN forward plan/receipt binding differs")
    if record["feature"] == "pin-sound-first-install" and build.get("plan_id") != plan.get("plan_id"):
        raise ValueError("Previous first-install wire plan identity differs")
    if record["feature"] == "pin-sound-replacement":
        from . import pin_rebase
        runtime, _ = _json_record(path.parent / "runtime-rebase.json")
        pin_rebase.validate_runtime_rebase(runtime)
        if runtime["content_plan"] != plan or runtime["plan_id"] != build.get("plan_id"):
            raise ValueError("Previous replacement runtime/full plan identity differs")
    if (plan.get("direction") != "forward" or not isinstance(plan.get("cutoff"), dict)
            or plan["cutoff"].get("requested") is not None):
        raise ValueError("Previous PIN plan must be an original no-cutoff forward plan")
    # This independently validates every R066 source/complement/owned byte and
    # the NEW backup's full exact target. A re-sealed JSON digest is insufficient.
    inverse = pin.plan_pin_inverse(plan, _source_paths(capture))
    if plan["components"]["cp_program"]["source"] != plan["components"]["cp_program"]["target"]:
        raise ValueError("Previous PIN CP gate/looks/cutoff drift is not admitted")
    retained = {role: read_private(path.parent / "post" / (role + ".bin"), 160 * 1024 * 1024)
                for role in pin.ROLES}
    checked = pin.verify_full_readback(plan, retained)
    if record.get("readback") != checked:
        raise ValueError("Previous complete full-readback receipt differs")
    baseline = pin.materialize_pin_plan(inverse, _source_paths(capture))
    return dict(receipt=str(path), receipt_sha256=digest, plan_id=plan["plan_id"],
                forward_plan=plan, inverse_plan=inverse, baseline=baseline)


def _selection(capture_path, prepared_pack, requested_cutoff, previous_job=None):
    if requested_cutoff is not None:
        raise ValueError("PIN first install leaves the body cutoff near 1/8; 1/50 is preview only")
    if not isinstance(prepared_pack, (str, os.PathLike)):
        raise ValueError("A complete local prepared PIN pack path is required; generic manifests are not accepted")
    capture = verified_capture(capture_path)
    previous = _previous_job(previous_job, capture) if previous_job is not None else None
    if previous is None:
        for role, relative in SNAPSHOT_PATHS.items():
            row = capture["objects"][relative]
            if {key: row[key] for key in ("size", "sha256")} != pin.BASELINE[role]:
                raise UnsupportedPinSource("First install requires complete R066; replacement requires an exact completed previous_job")
    prepared = pin_audio.validate_prepared_pack(prepared_pack)
    plan = pin.plan_pin_install(previous["baseline"] if previous else _source_paths(capture), prepared, requested_cutoff=None)
    if plan["cutoff"]["requested"] is not None or plan["components"]["cp_program"]["source"] != plan["components"]["cp_program"]["target"]:
        raise ValueError("This PIN coordinator never changes the CP-program cutoff")
    runtime = None
    if previous:
        from . import pin_rebase
        runtime = pin_rebase.runtime_rebase_plan(previous["forward_plan"], plan)
    return capture, dict(schema="a7m4-toolbox-pin-sound-selection/1", plan=plan, runtime_rebase=runtime,
        capture_receipt=str(Path(capture_path).absolute()), body_binding=capture["body_binding"],
        prepared_pack_sha256=plan["prepared_pack_sha256"], camera_io=False, network_io=False,
        device_execution_ready=False, dynamic_device_validation="NOT_PERFORMED",
        replacement_supported=True, replacement_requested=previous is not None,
        running_memory_policy="R066-source-or-selected-previous-target-only",
        previous=({key: previous[key] for key in ("receipt", "receipt_sha256", "plan_id")} if previous else None),
        previous_forward_plan=previous["forward_plan"] if previous else None,
        explicit_inverse_plan=previous["inverse_plan"] if previous else None,
        planned_sequence=(["previous-inverse-3-2-0", "new-forward-0-1-3"] if previous else ["new-forward-0-1-3"]),
        cutoff=dict(requested=None, body="unchanged-approximately-1/8",
                    preview_seconds=plan["cutoff"]["preview_cutoff_seconds"],
                    preview_matches_body=plan["cutoff"]["preview_matches_planned_installed_cutoff"],
                    notice_required=plan["cutoff"]["requires_cutoff_difference_notice"]))


def pin_sound_plan(capture_path, prepared_pack, *, requested_cutoff=None, previous_job=None):
    """Host-only complete backup/pack admission; never creates a session."""
    return _selection(capture_path, prepared_pack, requested_cutoff, previous_job)[1]


def _freeze_build(plan, compiler, root, runtime_plan=None):
    """Compile the current plan here; never accept an old user worker/bundle."""
    with tempfile.TemporaryDirectory(prefix="a7m4-pin-build-") as temporary:
        directory = Path(temporary).resolve() / "worker"
        if runtime_plan is not None:
            from . import pin_rebase
            pin_rebase.validate_runtime_rebase(runtime_plan)
            if runtime_plan["content_plan"] != plan:
                raise ValueError("Runtime rebase does not bind this exact content plan")
            bundle = pin_rebase.build_rebase_worker(runtime_plan, directory, compiler=compiler)
            expected_id, source_pin, worker_name = runtime_plan["plan_id"], pin_rebase.SOURCE_SHA256, "pin-rebase.so"
            request_path, report_path = pin_rebase.REQUEST_PATH, pin_rebase.REPORT_PATH
            packet_prefix = "m4.rebase."
        else:
            bundle = pin.build_pin_workers(plan, directory, compiler=compiler)
            expected_id, source_pin, worker_name = plan["plan_id"], pin.NATIVE_SOURCE_SHA256, "pin-worker.so"
            request_path, report_path = "/tmp/jiritsu/m4.pin-dynamic.request", "/tmp/jiritsu/m4.pin-dynamic.result"
            packet_prefix = "m4.pin."
        if (bundle.get("worker_built") is not True
                or bundle.get("status") != "BUILT_OFFLINE_NOT_DEVICE_VALIDATED"
                or bundle.get("plan_id") != expected_id):
            raise ValueError("PIN worker was not built: " + str(bundle.get("blockers", bundle.get("status"))))
        worker = bundle["worker"]
        if (worker.get("file") != worker_name or worker.get("source_sha256") != source_pin
                or worker.get("double_build_identical") is not True
                or bundle["request"].get("bytes") != 64 or bundle["report"].get("bytes") != 184):
            raise ValueError("Fresh PIN build source/ABI binding differs")
        binary = read_private(directory / worker["file"], 65535)
        if len(binary) != worker["size"] or sha256(binary).hexdigest() != worker["sha256"]:
            raise ValueError("Fresh complete PIN worker bytes differ")
        if (bundle["request"].get("file") != request_path
                or bundle["report"].get("file") != report_path
                or set(bundle["packets"]) != {"source", "target"}):
            raise ValueError("Unexpected PIN build path inventory")
        materials = root / "materials"
        materials.mkdir(mode=0o700)
        mapping = {}
        for name in ("source", "target"):
            row = bundle["packets"][name]
            expected_name = packet_prefix + expected_id[:16] + "." + name + ".bin"
            if row.get("file") != expected_name or row.get("upload_path") != "/tmp/jiritsu/" + expected_name:
                raise ValueError("PIN packet path differs from the exact plan")
            raw = read_private(directory / expected_name, 65535)
            if len(raw) != row["size"] or sha256(raw).hexdigest() != row["sha256"]:
                raise ValueError("Fresh complete PIN packet identity differs")
            mapping[row["upload_path"]] = raw
            _write(materials / expected_name, raw)
        _write(materials / worker["file"], binary)
        bundle = dict(bundle, output_dir=str(materials), build_origin="fresh-local-this-job")
        _write(materials / "build.json", _json(bundle))
        _write(root / "plan.json", _json(plan))
        if runtime_plan is not None:
            _write(root / "runtime-rebase.json", _json(runtime_plan))
        return bundle, binary, mapping


def execute_pin_sound(capture_path, prepared_pack, output, *, compiler=None, requested_cutoff=None, previous_job=None,
                      survey=host_metadata.survey, runner=None, lock=camera_lock,
                      session_factory=None, actions_factory=NativeActions):
    """Execute the preplanned first install or exact inverse-then-forward.

    This is never a failure-recovery policy. Every selected build is prepared
    before USB entry; any failed segment forbids further phases or cleanup.
    """
    import subprocess
    from .job_ownership import create_job_output
    capture, selection = _selection(capture_path, prepared_pack, requested_cutoff, previous_job)
    plan = selection["plan"]
    runner = runner or subprocess.run
    compiler = compiler or shutil.which("zig")
    root = create_job_output(output)
    receipt = root / "job.private.json"
    replacement = previous_job is not None
    old_plan = selection["previous_forward_plan"]
    result = dict(schema="a7m4-toolbox-device-job/1",
        feature="pin-sound-replacement" if replacement else "pin-sound-first-install",
        status="PREPARING_LOCAL", camera_io=False, network_io=False, simulation=False,
        complete=False, verified=False, full_readback_verified=False, stop_safe=False,
        receipt=str(receipt), body_binding=capture["body_binding"],
        backup_archive_sha256=capture["archive_sha256"], selection=selection,
        device_validation="not-performed", dynamic_layout_device_validated=False,
        installed_cutoff="unchanged-approximately-1/8", requested_cutoff=None,
        replacement_supported=True, replacement_requested=replacement,
        running_memory_policy="R066-source-or-selected-previous-target-only",
        replacement_inverse_completed=False, explicit_inverse_before_forward=replacement,
        automatic_retry=False, automatic_inverse=False, camera_applied=False,
        persistent_write_phase_attempted=False, activation_requires_user_power_cycle=True,
        physical_audio_acceptance="NOT_PERFORMED")
    _atomic_json(receipt, result)
    session = channel = actions = protocol = None
    action_history, protocols = [], []
    used_nonces = set()
    def safe_read_only_abort():
        return all(getattr(action, "safe_read_only_abort", False) for action in action_history)
    def nonce():
        value = os.urandom(16)
        if value == bytes(16) or value in used_nonces:
            raise ValueError("PIN nonce must be fresh across the complete replacement job")
        used_nonces.add(value)
        return value
    released = None
    session_opened = False
    try:
        bundle, binary, packets = _freeze_build(plan, compiler, root, selection["runtime_rebase"])
        old_build = None
        if replacement:
            inverse_root = root / "inverse"
            inverse_root.mkdir(mode=0o700)
            old_build = _freeze_build(old_plan, compiler, inverse_root)
        result["build"] = {key: bundle[key] for key in ("plan_id", "status", "worker", "packets", "request", "report")}
        result["build"]["content_plan_id"] = plan["plan_id"]
        _atomic_json(receipt, result)
        with lock():
            # Reopen the full same-body archive and every object immediately
            # before any host/device ownership action, after the offline build.
            if verified_capture(capture_path) != capture:
                raise ValueError("Verified complete backup changed during local preparation")
            if replacement:
                rechecked = _previous_job(previous_job, capture)
                if (rechecked["receipt_sha256"] != selection["previous"]["receipt_sha256"]
                        or rechecked["forward_plan"] != old_plan):
                    raise ValueError("Previous completed PIN job changed during preparation")
            released = release_host_volumes(root, survey=survey, runner=runner)
            result["host_release"] = released
            reads = {"/version.txt": 4096, "/usr/lib/libJiritsu.so": 160 * 1024 * 1024,
                     "/usr/lib/appFw.so": pin.BASELINE["ap"]["size"],
                     "/cp/CPAPP-B.BIN": pin.BASELINE["cp_program"]["size"],
                     "/cp/SysSound.bin": 131072, CUSTOM_CSV: 4096}
            owned = {LIBRARY: 65535, workspace.REQUEST_PATH: 64, workspace.REPORT_PATH: workspace.REPORT.size,
                     bundle["request"]["file"]: 64, bundle["report"]["file"]: 184}
            owned.update({path: len(raw) for path, raw in packets.items()})
            if old_build:
                owned.update({path: len(raw) for path, raw in old_build[2].items()})
                owned[old_build[0]["request"]["file"]] = 64
                owned[old_build[0]["report"]["file"]] = 184
            native = channel_class(reads, owned)
            session = (session_factory(native, released) if session_factory else
                       ServiceSession(channel_factory=native, expected_usb_serial=released["camera"]["usb_serial"]))
            result["simulation"] = getattr(session, "mode", None) == "SIMULATED"
            with session as channel, ExitStack() as preflight_exit:
                session_opened = True
                def finish_read_only_preflight():
                    if safe_read_only_abort() and channel.healthy:
                        channel.allow_clean_stop()
                preflight_exit.callback(finish_read_only_preflight)
                try:
                    result["camera_io"] = getattr(session, "camera_io", True)
                    result["status"] = "VERIFYING_FRESH_SOURCE"
                    _atomic_json(receipt, result)

                    def identity():
                        if sha256(channel.file("/version.txt")).hexdigest() != VERSION_SHA256:
                            raise ValueError("Fresh complete firmware version differs")
                        if sha256(channel.file("/usr/lib/libJiritsu.so")).hexdigest() != LOADER_SHA256:
                            raise ValueError("Fresh complete service loader differs")
                        channel.settings(False)
                        if body_binding(channel.serial()) != capture["body_binding"]:
                            raise ValueError("Current body differs from the complete same-body backup")
                        if channel.read_ap55() != b"\x02":
                            raise ValueError("AP55=02 file-loader prerequisite absent; no setting was changed")
                        if channel.peek(CUSTOM_CSV) is not None:
                            raise ValueError("Existing legacy custom sound CSV is not admitted")

                    def readback(label, direction, selected_plan=plan):
                        folder = root / label
                        folder.mkdir(mode=0o700)
                        paths = {}
                        for role in pin.ROLES:
                            raw = channel.file(pin.TARGET_PATHS[role])
                            path = folder / (role + ".bin")
                            _write(path, raw)
                            paths[role] = path
                        checked = pin.verify_full_readback(selected_plan, paths, direction)
                        _write(folder / "verified.json", _json(checked))
                        return paths, checked

                    identity()
                    readback("pre", "forward" if replacement else "source", old_plan if replacement else plan)
                    result["status"] = "NATIVE_SEQUENCE_STARTED"
                    _atomic_json(receipt, result)
                    previous_identity = None
                    def sequence(selected_plan, built, *, inverse=False, runtime_plan=None):
                        nonlocal actions, protocol, previous_identity
                        selected_bundle, selected_binary, selected_packets = built
                        prefix = "inverse/" if inverse else ""
                        if runtime_plan is not None:
                            from .pin_rebase import RebaseProtocol
                            protocol = RebaseProtocol(runtime_plan)
                        else:
                            protocol = pin.PinWorkerProtocol(selected_plan, inverse=inverse)
                        protocols.append(protocol)
                        actions = actions_factory(channel, root / (prefix + "native-actions"))
                        action_history.append(actions)
                        actions.upload_data(selected_packets, report_sizes=(184,))
                        modes = (3, 2, 0) if inverse else (0, 1, 3)
                        verified = None
                        for index, mode in enumerate(modes):
                            request = protocol.request(mode, nonce())
                            if mode in (1, 2):
                                result["persistent_write_phase_attempted"] = True
                                _atomic_json(receipt, result)
                            actions.phase(selected_binary, selected_bundle["request"]["file"], request,
                                selected_bundle["report"]["file"], protocol.accept_report, report_bytes=184)
                            if index == 0:
                                if previous_identity is not None and protocol.file_identities != previous_identity:
                                    raise ValueError("AP/bank inode or native process changed between replacement segments")
                                result["native_legacy_csv_absence_verified"] = True
                                readback(prefix + "inspect-source", "forward" if inverse else "source", selected_plan)
                            if index == 2:
                                paths, _ = readback(prefix + "post", "inverse" if inverse else "forward", selected_plan)
                                verified = protocol.confirm_readback(paths)
                        actions.clean_packets()
                        previous_identity = protocol.file_identities
                        return verified
                    if replacement:
                        result["inverse_readback"] = sequence(old_plan, old_build, inverse=True)
                        result["replacement_inverse_completed"] = True
                        result["status"] = "R066_RESTORED_BEFORE_EXPLICIT_NEW_FORWARD"
                        _atomic_json(receipt, result)
                    result["readback"] = sequence(plan, (bundle, binary, packets), runtime_plan=selection["runtime_rebase"])
                    identity()
                    channel.allow_clean_stop()
                    result.update(status="VERIFIED_AWAITING_SERVICE_EXIT", full_readback_verified=True,
                                  stop_safe=True, native_sequence_complete=True)
                    _atomic_json(receipt, result)
                except BaseException:
                    if not safe_read_only_abort():
                        channel.healthy = channel.safe_to_stop = False
                        for current in protocols:
                            current.unknown()
                    raise
            if not getattr(session, "stop_succeeded", False) or not getattr(session, "resources_disposed", False):
                raise RuntimeError("PIN service exit did not fully complete")
            result["normal_return"] = verify_normal_return(released, survey=survey, runner=runner)
            simulated = result["simulation"]
            result.update(status="SIMULATED_VERIFIED_APPLIED" if simulated else "VERIFIED_APPLIED",
                          complete=True, verified=True, normal_return_verified=True,
                          service_exit_confirmed=True, camera_applied=not simulated)
            _atomic_json(receipt, result)
            return result
    except BaseException as error:
        if session is not None:
            result["camera_io"] = getattr(session, "camera_io", True)
        clean_preflight = False
        if (session is not None and safe_read_only_abort() and getattr(session, "stop_succeeded", False)
                and getattr(session, "resources_disposed", False) and released is not None):
            try:
                result["normal_return"] = verify_normal_return(released, survey=survey, runner=runner)
                clean_preflight = True
            except (ValueError, RuntimeError, OSError):
                pass
        unknown = result["camera_io"] or session_opened or actions is not None
        applied = None if result["persistent_write_phase_attempted"] and not result["simulation"] else False
        result.update(status="STOP_UNKNOWN" if unknown else "STOPPED_LOCAL",
                      complete=False, verified=False, camera_applied=applied,
                      error=str(error), error_type=type(error).__name__,
                      stop_safe=clean_preflight, normal_return_verified=clean_preflight)
        if clean_preflight:
            result["status"] = "STOPPED_PREFLIGHT_NORMAL_RETURN"
        try:
            _atomic_json(receipt, result)
        except OSError as journal_error:
            # Do not let a second disk error hide the original outcome or turn
            # failed receipt persistence into a completed/clean device result.
            result["receipt_error"] = str(journal_error)
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise
        raise PinJobError(str(error), result) from error
