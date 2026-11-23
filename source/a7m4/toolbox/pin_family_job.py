"""Source-bound PIN sound coordinator over an explicitly opened USB session.

Only a newly verified canonical stock602/current or receipt-bound backup and a validated prepared sound pack are
accepted. Replacement requires an explicitly selected completed previous job,
then plans inverse-to-R066 before the new forward. No user patch manifest,
existing bound worker, failure inverse or cutoff change is accepted. Public CLI/GUI owns
fresh user risk authorization before calling execute_pin_sound.
"""
from contextlib import ExitStack
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import tempfile
import uuid

from ..research import pin_audio
from . import pin_product as pin, pin_product_worker as worker, pin_sources as sources
from .capture_inputs import read_private, verified_device_capture as verified_capture
from .device_job import complete_capture, Journal
from .settings_channel import SettingsChannel
from .settings_scope import settings_scope_freshness_report,sound_operation
from .settings_job import SettingsJob, _maps as settings_maps, check_full as check_settings_full
from .settings_plan import plan_ap55, plan_manifest, inverse_plan as inverse_settings_plan
from . import settings_archive
from .native_actions import NativeActions, _write, _json
from .native_channel import channel_class, LIBRARY
from .ownership import camera_lock, release_host_volumes, verify_normal_return
from . import host_metadata, workspace
from .usb_read import ServiceSession, body_binding, VERSION_SHA256, LOADER_SHA256, _atomic_json

CUSTOM_CSV = "/usr/share/avsystemsound/custom.txt"
SNAPSHOT_PATHS = {"ap": "appFw.so", "cp_program": "CPAPP-B.BIN", "bank": "extras/SysSound.bin"}


class ProductSoundJobError(RuntimeError):
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


def _previous_job(previous_job, capture, *, _current_images=None):
    if not isinstance(previous_job, (str, os.PathLike)):
        raise ValueError("Previous job must be a completed local product sound job")
    path = Path(previous_job).absolute()
    if path.is_dir(): path /= "job.private.json"
    if path.name != "job.private.json": raise ValueError("Previous product receipt filename differs")
    record, digest = _json_record(path)
    flags = ("camera_io", "camera_applied", "complete", "verified", "full_readback_verified", "stop_safe",
             "normal_return_verified", "service_exit_confirmed", "native_sequence_complete")
    if (record.get("schema") != "a7m4-toolbox-device-job/1" or record.get("status") != "VERIFIED_APPLIED"
            or record.get("feature") not in ("product-pin-first-install", "product-pin-replacement")
            or record.get("simulation") is not False or any(record.get(k) is not True for k in flags)
            or record.get("receipt") != str(path) or record.get("body_binding") != capture["body_binding"]):
        raise ValueError("Only a real complete same-body product VERIFIED_APPLIED supports replacement")
    normal = record.get("normal_return", {})
    if normal.get("normal_msc_verified") is not True or normal.get("same_body_and_port") is not True:
        raise ValueError("Previous product normal return missing")
    selection = record.get("selection", {})
    plan, _ = _json_record(path.parent / "plan.json")
    if selection.get("plan") != plan or selection.get("body_binding") != capture["body_binding"]:
        raise ValueError("Previous product selection/stored plan differs")
    original = {role: read_private(path.parent / "source-witness" / (role + ".bin"), sources.MAXIMUM[role]) for role in pin.ROLES}
    pin.validate_product_pin(plan, original)
    prior = selection.get("previous_forward_plan")
    wire = worker.wire_plan(plan, original, previous_plan=prior, previous_source=original if prior else None)
    stored_wire, _ = _json_record(path.parent / "wire-plan.json")
    if stored_wire != wire or record.get("build", {}).get("plan_id") != wire["plan_id"]:
        raise ValueError("Previous full wire/content/runtime plan binding differs")
    if record.get("build", {}).get("content_plan_id") != plan["plan_id"]:
        raise ValueError("Previous content plan identity differs")
    retained = {role: read_private(path.parent / "post" / (role + ".bin"), sources.MAXIMUM[role]) for role in pin.ROLES}
    checked = pin.verify_product_readback(plan, retained, original)
    expected_objects = [{"path": "post/" + role + ".bin", **sources.identity(retained[role])} for role in pin.ROLES]
    if record.get("readback") != checked or record.get("verified_objects") != expected_objects:
        raise ValueError("Previous retained full readback differs")
    current = _source_paths(capture) if _current_images is None else _current_images
    pin.verify_product_readback(plan, current, original)
    baseline = pin.materialize_product_pin(plan, current, original, inverse=True)
    return dict(receipt=str(path), receipt_sha256=digest, plan_id=plan["plan_id"], forward_plan=plan,
                inverse_plan=pin.plan_product_inverse(plan, current, original), baseline=baseline, record=record)


def _restored_sound_job(previous, capture):
    """Bind UI's restored forward receipt to actual validated old history."""
    record = previous["record"]
    selected = record.get("selection", {})
    prior_plan = selected.get("previous_forward_plan")
    if prior_plan is None: return None
    link = selected.get("previous", {})
    if type(link) is not dict or not isinstance(link.get("receipt"), str):
        raise ValueError("Replacement restore lacks its exact previous forward receipt")
    path = Path(link["receipt"]).absolute()
    old = _previous_job(path, capture, _current_images={role:path.parent/"post"/(role+".bin") for role in pin.ROLES})
    original = selected.get("previous_original_forward_plan") or prior_plan
    if (old["receipt_sha256"] != link.get("receipt_sha256") or old["plan_id"] != link.get("plan_id")
            or old["forward_plan"] != original):
        raise ValueError("Restored previous forward receipt SHA/plan binding differs")
    # A completed later fixed program overlay can transpose the original old
    # plan, but it cannot invent a different sound to call the previous one.
    if (pin._clips(prior_plan) != pin._clips(original) or prior_plan["controls"] != original["controls"]):
        raise ValueError("Transposed previous plan changed the selected old sound")
    return old["receipt"]


def _ap55_restore_origin(previous, capture):
    record = previous["record"]
    if record.get("ap55_owned_changed") is not True: return None
    root = Path(previous["receipt"]).parent
    baseline = settings_archive.load_snapshot(root / "settings-before")
    bound = record.get("ap55_settings_binding", {})
    forward = plan_ap55(baseline, identity=capture["body_binding"]["serial_sha256"],
                        boot_id=bound.get("boot_id"), nonce=bound.get("nonce"))
    manifest, _ = _json_record(root / "ap55-settings-plan.json")
    completion = record.get("ap55_settings_result", {})
    final = settings_archive.load_snapshot(root / "ap55-settings-final")
    if (manifest != json.loads(_json(plan_manifest(forward))) or forward.plan_id != bound.get("plan_id")
            or forward.records[0].before_saved != b"\0" or forward.records[0].after_saved != b"\2"
            or completion.get("status") != "DONE" or completion.get("plan_id") != forward.plan_id
            or any(completion.get(k) is not True for k in ("full_readback_verified", "complete_BIN_BAK_verified", "backing_copies_match_active_saved"))
            or completion.get("raw_sha256") != {name: sha256(getattr(final, name).raw).hexdigest()
                    for name in ("ram", "saved", "bin", "bak")}):
        raise ValueError("Previous own AP55 original/full completion differs")
    expected = settings_maps(baseline)
    record55 = forward.records[0]
    pair = record55.chip, record55.key
    expected["ram"][pair] = type(expected["ram"][pair])(expected["ram"][pair].attrs, record55.after_saved)
    for key, value in expected["ram"].items():
        if key[1] >> 16 == 0x51: expected["saved"][key] = value
    expected["bin"], expected["bak"] = dict(expected["saved"]), dict(expected["saved"])
    check_settings_full(forward, final, expected, after_save=True)
    return forward, completion


def _previous_inputs(previous_job, capture_path, capture, program_jobs):
    from .pin_composition import product_source_context
    context = product_source_context(capture_path, previous_job=previous_job, program_jobs=program_jobs)
    path = Path(previous_job).absolute()
    if path.is_dir(): path /= "job.private.json"
    old = _previous_job(path, capture, _current_images={role:path.parent/"post"/(role+".bin") for role in pin.ROLES})
    if context["admission"].get("post_sound_program_lineage"):
        original = old["forward_plan"]
        old["forward_plan"] = pin.transpose_previous_pin(original, capture_path, context)
        old["original_forward_plan"] = original
        old["baseline"] = context["pin_normalized_bytes"]
        old["inverse_plan"] = pin.plan_product_inverse(old["forward_plan"], context["actual_bytes"], old["baseline"])
        old["composed_context"] = context
    else:
        # No later program changes: bind the fresh complete target directly.
        _previous_job(path, capture)
    return old


def _selection(capture_path, prepared_pack, requested_cutoff, previous_job=None, program_jobs=()):
    if requested_cutoff is not None: raise ValueError("Body cutoff remains near1/8; 1/50 is preview only")
    capture, _ = complete_capture(capture_path)
    previous = _previous_inputs(previous_job, capture_path, capture, program_jobs) if previous_job is not None else None
    if previous and previous.get("composed_context") is not None:
        plan = pin.plan_composed_pin(capture_path, prepared_pack, previous_job=previous_job, program_jobs=program_jobs)
    else:
        original = previous["baseline"] if previous else _source_paths(capture)
        old_admission = previous["forward_plan"]["source_admission"] if previous else None
        if old_admission and old_admission.get("schema") == "a7m4-toolbox-pin-composed-source/1":
            # A later repeated volume edit keeps the same already proved
            # transposed source; do not create another capture projection layer.
            prepared = pin_audio.validate_prepared_pack(prepared_pack)
            manifest, clips = pin.reference._pack(prepared)
            plan = pin._construct(sources.images(original), clips, manifest.get("controls", {}), old_admission)
        else:
            jobs = [row["receipt"] for row in old_admission["program_lineage"]] if old_admission else program_jobs
            plan = pin.plan_product_pin(original, prepared_pack, body_binding=capture["body_binding"], program_jobs=jobs)
    return capture, dict(schema="a7m4-toolbox-product-sound-selection/1", plan=plan,
        capture_receipt=str(Path(capture_path).absolute()), body_binding=capture["body_binding"],
        camera_io=False, network_io=False, device_execution_ready=False, dynamic_device_validation="NOT_PERFORMED",
        replacement_supported=True, replacement_requested=previous is not None,
        running_memory_policy="source-or-exact-selected-previous-target-only",
        previous=({key: previous[key] for key in ("receipt", "receipt_sha256", "plan_id")} if previous else None),
        previous_forward_plan=previous["forward_plan"] if previous else None,
        previous_original_forward_plan=previous.get("original_forward_plan") if previous else None,
        explicit_inverse_plan=previous["inverse_plan"] if previous else None,
        planned_sequence=["previous-inverse-3-2-0", "new-forward-0-1-3"] if previous else ["new-forward-0-1-3"],
        cutoff=deepcopy(plan["cutoff"]))


def product_sound_plan(capture_path, prepared_pack, *, requested_cutoff=None, previous_job=None, program_jobs=()):
    """Host-only complete backup/pack/lineage plan; never creates a session."""
    capture, selection = _selection(capture_path, prepared_pack, requested_cutoff, previous_job, program_jobs)
    _, settings = complete_capture(capture_path)
    plan_ap55(settings, identity=capture["body_binding"]["serial_sha256"],
              boot_id="00000000-0000-0000-0000-000000000001", nonce=os.urandom(16).hex())
    return selection


def product_inverse_plan(capture_path, previous_job, *, restore_ap55=True):
    """Validate an explicit restore of this completed operation's backup.

    This only reads retained host evidence. No compiler, output directory,
    transport or execution nonce is created, and a local plan is not a device
    completion. Replacement restores the selected operation's old sound,
    rather than stopping at its intermediate canonical baseline.
    """
    if type(restore_ap55) is not bool:
        raise ValueError("restore_ap55 must be an explicit boolean")
    capture, settings = complete_capture(capture_path)
    plan_ap55(settings, identity=capture["body_binding"]["serial_sha256"],
              boot_id="00000000-0000-0000-0000-000000000001", nonce=os.urandom(16).hex())
    previous = _previous_job(previous_job, capture)
    source = sources.images(previous["baseline"])
    selected = previous["record"]["selection"]
    prior = selected.get("previous_forward_plan")
    restored = _restored_sound_job(previous, capture)
    original_capture = {role: read_private(Path(previous["receipt"]).parent / "pre" / (role + ".bin"),
                                          sources.MAXIMUM[role]) for role in pin.ROLES}
    expected = pin.materialize_product_pin(prior, source) if prior is not None else source
    if expected != original_capture:
        raise ValueError("PIN restoration target differs from this operation's original pre capture")
    owned = _ap55_restore_origin(previous, capture) if restore_ap55 else None
    ap55 = dict(requested=restore_ap55, owned_change=owned is not None,
                fresh_device_binding_required=True, whole_settings_replay=False)
    if owned is not None:
        forward, _ = owned
        row = forward.records[0]
        ap55.update(forward_plan_id=forward.plan_id, before_hex=row.after_saved.hex(),
                    target_hex=row.before_saved.hex())
    return dict(schema="a7m4-toolbox-product-sound-inverse-selection/1", status="PLANNED_OFFLINE",
        capture_receipt=str(Path(capture_path).absolute()), body_binding=capture["body_binding"],
        plan=previous["forward_plan"], previous_forward_plan=prior,
        previous={key: previous[key] for key in ("receipt", "receipt_sha256", "plan_id")},
        explicit_inverse_plan=previous["inverse_plan"], restore_forward_plan=prior,
        restore_ap55=restore_ap55, ap55_restore=ap55,
        restored_sound_job=restored, restored_previous_sound=prior is not None,
        restoration_source={role: sources.identity(read_private(_source_paths(capture)[role], sources.MAXIMUM[role]))
                            for role in pin.ROLES},
        restoration_target={role: sources.identity(expected[role]) for role in pin.ROLES},
        planned_sequence=(["latest-inverse-3-2-0", "previous-forward-0-1-3"] if prior is not None
                          else ["latest-inverse-3-2-0"]),
        automatic_retry=False, automatic_inverse=False, camera_io=False, network_io=False,
        device_execution_ready=False, physical_acceptance="NOT_PERFORMED")


def _freeze_build(plan, source_images, compiler, root, previous_plan=None, *, restore_previous=False):
    with tempfile.TemporaryDirectory(prefix="a7m4-product-pin-build-") as temporary:
        directory = Path(temporary).resolve() / "worker"
        bundle = worker.build_product_worker(plan, source_images, directory, compiler=compiler,
            previous_plan=previous_plan, previous_source=source_images if previous_plan else None, restore_previous=restore_previous)
        wire = worker.wire_plan(plan, source_images, previous_plan=previous_plan,
                                previous_source=source_images if previous_plan else None, restore_previous=restore_previous)
        if (bundle.get("worker_built") is not True or bundle.get("status") != "BUILT_OFFLINE_NOT_DEVICE_VALIDATED"
                or bundle.get("plan_id") != wire["plan_id"] or bundle.get("content_plan_id") != plan["plan_id"]):
            raise ValueError("Product PIN worker not built: " + str(bundle.get("blockers")))
        entry = bundle["worker"]
        if (entry.get("file") != "pin-family.so" or entry.get("source_sha256") != worker.SOURCE_SHA256
                or entry.get("double_build_identical") is not True
                or bundle.get("request") != dict(file=worker.REQUEST_PATH, bytes=64)
                or bundle.get("report") != dict(file=worker.REPORT_PATH, bytes=184)):
            raise ValueError("Fresh product worker ABI/source binding differs")
        binary = read_private(directory / entry["file"], 65535)
        if sources.identity(binary) != {key: entry[key] for key in ("size", "sha256")}:
            raise ValueError("Fresh complete product helper differs")
        expected_packets = worker._packets(wire)
        materials = root / "materials"; materials.mkdir(mode=0o700)
        mapping = {}
        for name, expected in expected_packets.items():
            row = bundle["packets"][name]
            if row != {key: value for key, value in expected.items() if key != "data"}:
                raise ValueError("Product packet identity/inventory differs")
            raw = read_private(directory / row["file"], 65535)
            if raw != expected["data"]: raise ValueError("Fresh complete product packet differs")
            mapping[row["upload_path"]] = raw; _write(materials / row["file"], raw)
        _write(materials / entry["file"], binary)
        _write(root / "plan.json", _json(plan)); _write(root / "wire-plan.json", _json(wire))
        bundle = dict(bundle, output_dir=str(materials), build_origin="fresh-local-this-job")
        _write(materials / "build.json", _json(bundle))
        return bundle, binary, mapping


def execute_product_sound(capture_path, prepared_pack, output, *, compiler=None, requested_cutoff=None, previous_job=None, program_jobs=(),
                      survey=host_metadata.survey, runner=None, lock=camera_lock,
                      session_factory=None, actions_factory=NativeActions, _inverse_only=False, _restore_ap55=True):
    """Execute the preplanned first install or exact inverse-then-forward.

    This is never a failure-recovery policy. Every selected build is prepared
    before USB entry; any failed segment forbids further phases or cleanup.
    """
    import subprocess
    from .job_ownership import create_job_output
    if _inverse_only:
        if requested_cutoff is not None or prepared_pack is not None or program_jobs:
            raise ValueError("Explicit inverse accepts only its selected completed job")
        capture, _ = complete_capture(capture_path)
        previous = _previous_job(previous_job, capture)
        selection = dict(schema="a7m4-toolbox-product-sound-inverse-selection/1", plan=previous["forward_plan"],
            body_binding=capture["body_binding"], previous_forward_plan=previous["forward_plan"],
            previous={key: previous[key] for key in ("receipt", "receipt_sha256", "plan_id")},
            explicit_inverse_plan=previous["inverse_plan"], restore_ap55=_restore_ap55,
            camera_io=False, device_execution_ready=False)
    else:
        capture, selection = _selection(capture_path, prepared_pack, requested_cutoff, previous_job, program_jobs)
    plan = selection["plan"]
    runner = runner or subprocess.run
    compiler = compiler or shutil.which("zig")
    root = create_job_output(output)
    receipt = root / "job.private.json"
    replacement = previous_job is not None
    old_plan = selection["previous_forward_plan"]
    result = dict(schema="a7m4-toolbox-device-job/1",
        feature="product-pin-inverse" if _inverse_only else "product-pin-replacement" if replacement else "product-pin-first-install",
        status="PREPARING_LOCAL", camera_io=False, network_io=False, simulation=False,
        complete=False, verified=False, full_readback_verified=False, stop_safe=False,
        receipt=str(receipt), body_binding=capture["body_binding"],
        backup_archive_sha256=capture["archive_sha256"], selection=selection,
        device_validation="not-performed", dynamic_layout_device_validated=False,
        installed_cutoff="unchanged-approximately-1/8", requested_cutoff=None,
        replacement_supported=True, replacement_requested=replacement,
        running_memory_policy="source-or-exact-selected-previous-target-only",
        replacement_inverse_completed=False, explicit_inverse_before_forward=replacement,
        automatic_retry=False, automatic_inverse=False, camera_applied=False,
        persistent_write_phase_attempted=False, activation_requires_user_power_cycle=True,
        physical_audio_acceptance="NOT_PERFORMED")
    _atomic_json(receipt, result)
    session = channel = actions = protocol = settings_channel = None
    settings_mutated = False
    action_history, protocols = [], []
    used_nonces = set()
    def safe_read_only_abort():
        return (not settings_mutated and not getattr(settings_channel, "mutation_attempted", False)
            and not getattr(settings_channel, "unknown_remote_state", False)
            and all(getattr(action, "safe_read_only_abort", False) for action in action_history))
    def nonce():
        value = os.urandom(16)
        if value == bytes(16) or value in used_nonces:
            raise ValueError("PIN nonce must be fresh across the complete replacement job")
        used_nonces.add(value)
        return value
    released = None
    session_opened = False
    try:
        previous_inputs = (_previous_job(previous_job, capture) if _inverse_only else
                           _previous_inputs(previous_job, capture_path, capture, program_jobs)) if replacement else None
        restore_evidence = product_inverse_plan(capture_path, previous_job, restore_ap55=_restore_ap55) if _inverse_only else None
        restore_origin = _ap55_restore_origin(previous_inputs, capture) if _inverse_only and _restore_ap55 else None
        original = previous_inputs["baseline"] if replacement else _source_paths(capture)
        source_images = sources.images(original)
        witness = root / "source-witness"; witness.mkdir(mode=0o700)
        for role in pin.ROLES: _write(witness / (role + ".bin"), source_images[role])
        prior_restore = previous_inputs["record"]["selection"].get("previous_forward_plan") if _inverse_only else None
        restored_sound_job = restore_evidence["restored_sound_job"] if _inverse_only else None
        if _inverse_only:
            result["restored_sound_job"] = restored_sound_job
        bundle, binary, packets = _freeze_build(plan, source_images, compiler, root, prior_restore if _inverse_only else old_plan)
        restore_build = None
        expected_restore = source_images
        if _inverse_only and prior_restore is not None:
            folder = root / "restore-previous"; folder.mkdir(mode=0o700)
            restore_build = _freeze_build(prior_restore, source_images, compiler, folder, plan, restore_previous=True)
            expected_restore = {role: read_private(Path(previous_inputs["receipt"]).parent / "pre" / (role + ".bin"), sources.MAXIMUM[role]) for role in pin.ROLES}
            pin.verify_product_readback(prior_restore, expected_restore, source_images)
        if _inverse_only and {role: sources.identity(expected_restore[role]) for role in pin.ROLES} != restore_evidence["restoration_target"]:
            raise ValueError("Explicit restore changed during local preparation")
        result["restoration_target"] = {role: sources.identity(expected_restore[role]) for role in pin.ROLES} if _inverse_only else None
        old_build = None
        if replacement and not _inverse_only:
            inverse_root = root / "inverse"
            inverse_root.mkdir(mode=0o700)
            old_build = _freeze_build(old_plan, source_images, compiler, inverse_root)
        result["build"] = {key: bundle[key] for key in ("plan_id", "status", "worker", "packets", "request", "report")}
        result["build"]["content_plan_id"] = plan["plan_id"]
        _atomic_json(receipt, result)
        with lock():
            # Reopen the full same-body archive and every object immediately
            # before any host/device ownership action, after the offline build.
            if verified_capture(capture_path) != capture:
                raise ValueError("Verified complete backup changed during local preparation")
            if replacement:
                rechecked = (_previous_job(previous_job, capture) if _inverse_only else
                             _previous_inputs(previous_job, capture_path, capture, program_jobs))
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
            if restore_build:
                owned.update({path: len(raw) for path, raw in restore_build[2].items()})
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

                    def identity(require_ap55=True):
                        if sha256(channel.file("/version.txt")).hexdigest() != VERSION_SHA256:
                            raise ValueError("Fresh complete firmware version differs")
                        if sha256(channel.file("/usr/lib/libJiritsu.so")).hexdigest() != LOADER_SHA256:
                            raise ValueError("Fresh complete service loader differs")
                        channel.settings(False)
                        if body_binding(channel.serial()) != capture["body_binding"]:
                            raise ValueError("Current body differs from the complete same-body backup")
                        if require_ap55 and channel.read_ap55() != b"\x02":
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
                        checked = pin.verify_product_readback(selected_plan, paths, source_images, direction)
                        _write(folder / "verified.json", _json(checked))
                        return paths, checked

                    identity(require_ap55=False)
                    readback("pre", "forward" if replacement else "source", old_plan if replacement else plan)
                    # Full four-plane + direct-CP equality precedes even the
                    # separately owned stock AP55 bootstrap setting.
                    _, original_settings = complete_capture(capture_path)
                    wire_journal = Journal(root / "settings-wire")
                    settings_channel = SettingsChannel(channel, intent=wire_journal, reply=wire_journal)
                    fresh_settings = settings_channel.capture()
                    settings_archive.save_snapshot(fresh_settings, root / "settings-before-probe")
                    freshness = settings_scope_freshness_report(original_settings, fresh_settings,
                        operation=sound_operation(fresh_settings,restore_ap55=_inverse_only and _restore_ap55))
                    _write(root / "settings-freshness-before-probe.json", _json(freshness))
                    result["settings_freshness"] = freshness
                    if not freshness["stable"]:
                        raise ValueError("Protected settings drift since verified backup: "+ "; ".join(freshness["errors"][:3]))
                    direct55 = channel.read_ap55()
                    if direct55 not in (b"\0", b"\2") or (plan["source_admission"]["family"] != "stock602" and direct55 != b"\2"):
                        raise ValueError("Fresh AP55 prerequisite is not an admitted exact state")
                    # Pure finite-settings validation first, before even the
                    # temporary bootstrap probe is uploaded. The placeholder
                    # UUID is discarded; it is never an execution binding.
                    plan_ap55(fresh_settings, identity=capture["body_binding"]["serial_sha256"],
                              boot_id="00000000-0000-0000-0000-000000000001", nonce=nonce().hex())
                    identity_actions = actions_factory(channel, root / "identity-native")
                    action_history.append(identity_actions)
                    measured = identity_actions.probe()
                    def settings_budget(value):
                        unit, available = value.get("allocation_unit"), value.get("available_bytes")
                        if (value.get("fresh_measurement") is not True or type(unit) is not int or unit <= 0
                                or type(available) is not int or available < workspace.RESERVE + unit):
                            raise ValueError("Fresh settings preflight requires8MiB plus one allocation unit")
                    settings_budget(measured)
                    boot_id = str(uuid.UUID(measured["boot_id"]))
                    if measured["boot_id"] != boot_id:
                        raise ValueError("Native probe returned noncanonical kernel boot UUID")
                    result["native_boot_binding"] = dict(process_id=measured["process_id"], boot_id=boot_id)
                    # Bootstrap can reset only named APP diagnostic RAM. Bind
                    # the formal setting transaction after that read-only step;
                    # preserve the pre-probe capture rather than rebasing writes.
                    fresh_settings = settings_channel.capture()
                    settings_archive.save_snapshot(fresh_settings, root / "settings-before")
                    freshness = settings_scope_freshness_report(original_settings, fresh_settings,
                        operation=sound_operation(fresh_settings,restore_ap55=_inverse_only and _restore_ap55),native_context=result["native_boot_binding"])
                    _write(root / "settings-freshness.json", _json(freshness))
                    result["settings_freshness"] = freshness
                    if not freshness["stable"]:
                        raise ValueError("Protected settings changed after native bootstrap: "+ "; ".join(freshness["errors"][:3]))
                    plan_ap55(fresh_settings,identity=capture["body_binding"]["serial_sha256"],boot_id=boot_id,nonce=nonce().hex())
                    def fresh_boot():
                        current = identity_actions.probe()
                        settings_budget(current)
                        if current["boot_id"] != boot_id or current["process_id"] != measured["process_id"]:
                            raise ValueError("Native PID/kernel boot UUID changed during sound transaction")
                    if _inverse_only:
                        identity()
                    else:
                        if (plan["source_admission"]["family"] != "stock602"
                                and channel.read_ap55() != b"\x02"):
                            raise ValueError("Current-family AP55 must already be02; no unknown prerequisite change")
                        setting_plan = plan_ap55(fresh_settings, identity=capture["body_binding"]["serial_sha256"],
                                                 boot_id=boot_id, nonce=nonce().hex())
                        _write(root / "ap55-settings-plan.json", _json(plan_manifest(setting_plan)))
                        def settings_binding(p):
                            identity(require_ap55=False)
                            fresh_boot()
                            return dict(identity=p.identity, boot_id=p.boot_id, nonce=p.nonce,
                                        model="ILCE-7M4", firmware="6.02", exclusive_owner=True)
                        settings_job = SettingsJob(settings_channel, bind=settings_binding,
                                                   journal=Journal(root / "ap55-settings-journal"))
                        settings_job.release(setting_plan, dict(schema="a7m4-toolbox-settings-release/1",
                            plan_id=setting_plan.plan_id, identity=setting_plan.identity, boot_id=boot_id,
                            nonce=setting_plan.nonce, backup_verified=True, program_dependencies_verified=True,
                            user_risk_confirmation_fresh=True, release_gate="RELEASED"))
                        try:
                            result["ap55_settings_result"] = settings_job.execute(setting_plan)
                        finally:
                            settings_mutated |= bool(settings_job.mutation_attempted)
                            result["persistent_write_phase_attempted"] |= settings_mutated
                        result["ap55_owned_changed"] = setting_plan.records[0].before_saved != setting_plan.records[0].after_saved
                        result["ap55_settings_binding"] = dict(boot_id=boot_id, nonce=setting_plan.nonce,
                                                              plan_id=setting_plan.plan_id)
                        result["settings_metadata_profile_validation"] = "NEW_SOFTWARE_CANDIDATE_PHYSICAL_NOT_PERFORMED"
                        settings_archive.save_snapshot(settings_job._last_snapshot, root / "ap55-settings-final")
                        final_settings = settings_channel.capture()
                        settings_archive.save_snapshot(final_settings, root / "settings-after")
                        identity()
                        _atomic_json(receipt, result)
                    result["status"] = "NATIVE_SEQUENCE_STARTED"
                    _atomic_json(receipt, result)
                    previous_identity = None
                    def sequence(selected_plan, built, *, inverse=False, runtime_previous=None, restore_previous=False):
                        nonlocal actions, protocol, previous_identity
                        selected_bundle, selected_binary, selected_packets = built
                        prefix = "inverse/" if inverse else ""
                        if inverse and not (root / "inverse").exists(): (root / "inverse").mkdir(mode=0o700)
                        protocol = worker.ProductPinProtocol(selected_plan, source_images, inverse=inverse,
                            previous_plan=runtime_previous, previous_source=source_images if runtime_previous else None, restore_previous=restore_previous)
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
                                if protocol.file_identities[-1] != measured["process_id"]:
                                    raise ValueError("Native worker PID differs from fresh boot-bound probe")
                                if previous_identity is not None and protocol.file_identities != previous_identity:
                                    raise ValueError("AP/bank inode or native process changed between replacement segments")
                                result["native_legacy_csv_absence_verified"] = True
                                initial_paths, _ = readback(prefix + "inspect-source", "forward" if inverse else "source", selected_plan)
                                protocol.confirm_readback(initial_paths)
                            if index == 2:
                                paths, _ = readback(prefix + "post", "inverse" if inverse else "forward", selected_plan)
                                verified = protocol.confirm_readback(paths)
                        actions.clean_packets()
                        previous_identity = protocol.file_identities
                        return verified
                    if replacement and not _inverse_only:
                        result["inverse_readback"] = sequence(old_plan, old_build, inverse=True)
                        result["replacement_inverse_completed"] = True
                        result["status"] = "EXACT_CANONICAL_FAMILY_RESTORED_BEFORE_EXPLICIT_NEW_FORWARD"
                        _atomic_json(receipt, result)
                    if _inverse_only:
                        result["inverse_readback"] = sequence(plan, (bundle, binary, packets), inverse=True, runtime_previous=prior_restore)
                        if prior_restore is not None:
                            result["readback"] = sequence(prior_restore, restore_build,
                                runtime_previous=plan, restore_previous=True)
                            result["restored_previous_sound"] = True
                        else:
                            result["readback"] = result["inverse_readback"]
                            standard = root / "post"; standard.mkdir(mode=0o700)
                            for role in pin.ROLES:
                                _write(standard / (role + ".bin"), read_private(root / "inverse/post" / (role + ".bin"), sources.MAXIMUM[role]))
                        for role in pin.ROLES:
                            if read_private(root / "post" / (role + ".bin"), sources.MAXIMUM[role]) != expected_restore[role]:
                                raise ValueError("Final restore differs from this operation's original capture owned bytes")
                        if restore_origin is not None:
                                forward, completion = restore_origin
                                current_settings = settings_channel.capture()
                                restore_plan = inverse_settings_plan(forward, current_settings,
                                    boot_id=boot_id, nonce=nonce().hex(), completion=completion)
                                _write(root / "ap55-inverse-plan.json", _json(plan_manifest(restore_plan)))
                                def restore_binding(p):
                                    identity(require_ap55=False)
                                    fresh_boot()
                                    return dict(identity=p.identity, boot_id=p.boot_id, nonce=p.nonce,
                                                model="ILCE-7M4", firmware="6.02", exclusive_owner=True)
                                restore_job = SettingsJob(settings_channel, bind=restore_binding,
                                    journal=Journal(root / "ap55-inverse-journal"))
                                restore_job.release(restore_plan, dict(schema="a7m4-toolbox-settings-release/1",
                                    plan_id=restore_plan.plan_id, identity=restore_plan.identity, boot_id=boot_id,
                                    nonce=restore_plan.nonce, backup_verified=True, program_dependencies_verified=True,
                                    user_risk_confirmation_fresh=True, release_gate="RELEASED"))
                                try: result["ap55_inverse_result"] = restore_job.execute(restore_plan)
                                finally:
                                    settings_mutated |= restore_job.mutation_attempted
                                    result["persistent_write_phase_attempted"] |= settings_mutated
                                settings_archive.save_snapshot(restore_job._last_snapshot, root / "settings-restored")
                    else:
                        result["readback"] = sequence(plan, (bundle, binary, packets), runtime_previous=old_plan)
                    result["verified_objects"] = [{"path": "post/" + role + ".bin",
                        **result["readback"]["images"][role]} for role in pin.ROLES]
                    identity(require_ap55=not _inverse_only)
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
        raise ProductSoundJobError(str(error), result) from error


def execute_product_inverse(capture_path, previous_job, output, *, compiler=None, restore_ap55=True,
                            survey=host_metadata.survey, runner=None, lock=camera_lock,
                            session_factory=None, actions_factory=NativeActions):
    """Explicit self-completed latest endpoint inverse; never failure recovery.

    Fresh complete same-body target and full settings backup are mandatory.
    Only an AP55 span changed by this selected job is eligible for restoration.
    No unrelated gate/looks drift or arbitrary restore manifest is accepted.
    """
    if type(restore_ap55) is not bool: raise ValueError("Explicit AP55 restore boolean required")
    return execute_product_sound(capture_path, None, output, compiler=compiler, previous_job=previous_job,
        survey=survey, runner=runner, lock=lock, session_factory=session_factory, actions_factory=actions_factory,
        _inverse_only=True, _restore_ap55=restore_ap55)


def admit_product_capture(capture_path, *, previous_job=None, program_jobs=()):
    """Pure completed-source admission for fixed gate/looks composition."""
    from .pin_composition import admit_product_capture as admit
    return admit(capture_path, previous_job=previous_job, program_jobs=program_jobs)
