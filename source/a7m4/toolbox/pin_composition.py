"""Pure completed-PIN / fixed-program source projection, no camera methods.

A projection is a Mac-side proof witness. Its hashes are not hashes observed on
a camera. Callers must patch only their independently fixed, disjoint windows
into the ACTUAL fresh source, retaining every PIN descriptor/data byte.
"""
from copy import deepcopy
from pathlib import Path

from . import pin_sources as sources, pin_product as product, program_worker
from ..research import pin_plan as reference


def _need(value, message):
    if not value: raise ValueError(message)


def _paths(capture):
    root = Path(capture['snapshot_dir'])
    return dict(ap=root/'appFw.so', cp_program=root/'CPAPP-B.BIN', bank=root/'extras/SysSound.bin')


def _unpin_ap(raw, plan):
    output = bytearray(raw)
    for row in plan['components']['ap']['windows']:
        at, size = row['offset'], row['size']
        _need(output[at:at+size] == bytes.fromhex(row['after_hex']), 'Fixed overlay drifted into PIN descriptors')
        output[at:at+size] = bytes.fromhex(row['before_hex'])
    return bytes(output)


def _replay(stages, current):
    result = dict(current)
    for plan in stages:
        sources._endpoint(plan, result, 'source')
        for role, key in (('ap','ap'),('cp_program','cp')):
            raw = bytearray(result[role])
            for row in plan['components'][key]['windows']:
                at = row['offset']; before = bytes.fromhex(row['before_hex']); after = bytes.fromhex(row['after_hex'])
                _need(raw[at:at+len(before)] == before, 'Fixed overlay source window differs')
                raw[at:at+len(after)] = after
            result[role] = bytes(raw)
        sources._endpoint(plan, result, 'target')
    return result


def _disjoint(stages):
    owned = [(at, at+4) for at in reference.AP_OFFSETS]
    for plan in stages:
        for row in plan['components']['ap']['windows']:
            at, size = row['offset'], len(bytes.fromhex(row['before_hex']))
            _need(all(at+size <= lo or at >= hi for lo, hi in owned), 'Program overlay touches a PIN descriptor')


def _project_stages(stages, actual_before, pin_plan):
    """Recompute projected whole hashes; never reuse actual plan IDs as proof."""
    projected = dict(actual_before, ap=_unpin_ap(actual_before['ap'], pin_plan))
    actual = dict(actual_before)
    result = []
    for stage in stages:
        after = _replay([stage], actual)
        projected_after = dict(after, ap=_unpin_ap(after['ap'], pin_plan))
        components = {key: dict(source=sources.identity(projected[role]), target=sources.identity(projected_after[role]),
            windows=deepcopy(stage['components'][key]['windows'])) for role, key in (('ap','ap'),('cp_program','cp'))}
        result.append(program_worker.program_plan(components, feature_id=stage['feature_id']))
        projected, actual = projected_after, after
    return result, projected


def _ancestry(admission):
    return ([row["receipt"] for row in admission["program_lineage"]]
            if admission["schema"] == "a7m4-toolbox-pin-source/1" else list(admission["program_jobs"]))


def _canonical_witness(admission, baseline):
    if admission["schema"] == "a7m4-toolbox-pin-source/1":
        canonical = dict(baseline)
        for proof in reversed(admission["program_lineage"]): canonical = sources._reverse(proof["stages"], canonical)
        return canonical
    _need(admission["schema"] == "a7m4-toolbox-pin-composed-source/1", "Unknown PIN ancestry")
    return product_source_context(admission["source_capture_receipt"],
        previous_job=admission["sound_job"]["receipt"], program_jobs=admission["program_jobs"])["canonical_bytes"]


def project_product_capture(capture_path, *, previous_job=None, program_jobs=()):
    """Return (JSON admission, complete virtual PIN-free images) locally.

    A selected real completed sound job is mandatory for any dynamic PIN
    endpoint. program_jobs is chronological and contains fixed completed
    looks/gate jobs before or after that PIN operation; no generic plan input.
    """
    from .pin_family_job import complete_capture, _previous_job
    capture, _ = complete_capture(capture_path)
    actual = sources.images(_paths(capture))
    if previous_job is None:
        admitted = sources.admit_pin_source(actual, body_binding=capture['body_binding'], program_jobs=program_jobs)
        canonical = dict(actual)
        for proof in reversed(admitted['program_lineage']): canonical = sources._reverse(proof['stages'], canonical)
        return dict(schema='a7m4-toolbox-product-source/1', family=admitted['family'],
            actual_images=deepcopy(admitted['images']), projected_images=deepcopy(admitted['images']),
            canonical_images={r:sources.identity(canonical[r]) for r in reference.ROLES}, source_admission=admitted, sound_job=None, program_jobs=[r['receipt'] for r in admitted['program_lineage']],
            pin_projection=False, camera_io=False, device_execution_ready=False), actual
    path = Path(previous_job).absolute()
    if path.is_dir(): path /= 'job.private.json'
    # Validate the selected own receipt and independently retained endpoint first.
    retained = {role: path.parent/'post'/(role+'.bin') for role in reference.ROLES}
    old = _previous_job(path, capture, _current_images=retained)
    plan = old['forward_plan']
    prior_paths = _ancestry(plan['source_admission'])
    requested = [str((Path(p)/'job.private.json' if Path(p).is_dir() else Path(p)).absolute()) for p in program_jobs]
    if not requested: requested = prior_paths
    _need(requested[:len(prior_paths)] == prior_paths, 'Explicit program lineage lost/reordered the completed PIN source ancestry')
    _need(len(set(requested)) == len(requested) and len(requested) <= 8, 'Program lineage is repeated or exceeds its bound')
    extras = [sources.program_lineage(p, capture['body_binding']) for p in requested[len(prior_paths):]]
    current, rows = dict(actual), []
    for proof in reversed(extras):
        _disjoint(proof['stages'])
        _need(all(sources.identity(current[role]) == proof['program_endpoint'][role] for role in ('ap','cp_program')), 'Completed program endpoint differs')
        _need(proof['bank'] is None or proof['bank'] == sources.identity(current['bank']), 'Completed program changed the PIN bank')
        before = sources._reverse(proof['stages'], current)
        rows.append((proof, before, current)); current = before
    # Fresh complete target must be EXACTLY the endpoint whose own receipt was
    # proved above, after removing only separately completed fixed overlays.
    old = _previous_job(path, capture, _current_images=current)
    canonical = _canonical_witness(plan['source_admission'], old['baseline'])
    for proof, before, after in reversed(rows):
        if not proof['stages']: continue
        if proof['feature'] == 'electronic-sound-gate':
            _need(len(proof['stages']) == 1, 'Gate has extra stages')
            sources._gate_expected(proof['stages'][0], before)
        else:
            from .looks import validate_program_overlay
            projected_stages, projected_before_after = _project_stages(proof['stages'], before, plan)
            checked = validate_program_overlay(projected_stages, _unpin_ap(before['ap'], plan), before['cp_program'],
                canonical_ap_bytes=canonical['ap'], canonical_cp_bytes=canonical['cp_program'])
            _need(checked.get('verified') is True, 'Completed post-PIN looks overlay failed independent validation')
        _need(before['bank'] == after['bank'], 'Fixed program overlay changed audio data')
    # Inverse only the audio's owned AP words/data; preserve all later fixed
    # program overlays. Current CP is deliberately retained unchanged.
    projection = dict(actual, ap=_unpin_ap(actual['ap'], plan), bank=old['baseline']['bank'])
    canonical = _canonical_witness(plan['source_admission'], old['baseline'])
    _need({r:sources.identity(canonical[r]) for r in reference.ROLES} == plan['source_admission']['canonical_images'], 'Canonical inverse witness differs')
    info = dict(schema='a7m4-toolbox-product-source/1', family=plan['source_admission']['family'],
        actual_images={r:sources.identity(actual[r]) for r in reference.ROLES},
        canonical_images={r:sources.identity(canonical[r]) for r in reference.ROLES},
        projected_images={r:sources.identity(projection[r]) for r in reference.ROLES},
        source_admission=deepcopy(plan['source_admission']),
        sound_job={k:old[k] for k in ('receipt','receipt_sha256','plan_id')},
        program_jobs=requested, post_sound_program_lineage=deepcopy(extras),
        pin_projection=True, pin_descriptor_offsets=list(reference.AP_OFFSETS),
        pin_unchanged_by_program_overlays=True, full_source_and_complement_verified=True,
        projection_origin='Mac-virtual-inverse-never-device-readback', camera_io=False,
        device_execution_ready=False, physical_acceptance_claimed=False)
    return info, projection


def admit_product_capture(capture_path, *, previous_job=None, program_jobs=()):
    return project_product_capture(capture_path, previous_job=previous_job, program_jobs=program_jobs)[0]


def rebase_program_overlay(plan, actual_images, projected_images):
    """Bind a separately fixed projected plan to actual, disjoint PIN bytes.

    This does not grant admission. Callers must obtain both witnesses from
    project_product_capture and use their own independent fixed-plan builder.
    """
    program_worker.validate_plan(plan); _disjoint([plan])
    actual, projected = sources.images(actual_images), sources.images(projected_images)
    sources._endpoint(plan, projected, 'source')
    _replay([plan], projected)  # Independently bind every projected target byte/hash.
    cursor = 0
    _need(len(actual['ap']) == len(projected['ap']), 'Projection changed AP size')
    for at in reference.AP_OFFSETS:
        _need(actual['ap'][cursor:at] == projected['ap'][cursor:at], 'Projection changed an AP complement outside PIN words')
        cursor = at + 4
    _need(actual['ap'][cursor:] == projected['ap'][cursor:], 'Projection changed AP trailing complement')
    _need(actual['cp_program'] == projected['cp_program'], 'Projection changed CP outside audio scope')
    target = dict(actual)
    for role,key in (('ap','ap'),('cp_program','cp')):
        raw=bytearray(actual[role])
        for row in plan['components'][key]['windows']:
            at=row['offset'];before=bytes.fromhex(row['before_hex']);after=bytes.fromhex(row['after_hex'])
            _need(raw[at:at+len(before)] == before, 'Actual source differs at independently fixed overlay window')
            raw[at:at+len(after)] = after
        target[role]=bytes(raw)
    result=program_worker.program_plan({key:dict(source=sources.identity(actual[role]),target=sources.identity(target[role]),
        windows=deepcopy(plan['components'][key]['windows'])) for role,key in (('ap','ap'),('cp_program','cp'))},feature_id=plan['feature_id'])
    return result,target


def product_source_context(capture_path, *, previous_job=None, program_jobs=()):
    """Internal full-byte witnesses, always recomputed from real receipt paths.

    This is not JSON and must never be accepted back from a caller as a trust
    token. Public JSON summaries use admit_product_capture instead.
    """
    from .pin_family_job import complete_capture, _previous_job
    info, projection = project_product_capture(capture_path, previous_job=previous_job, program_jobs=program_jobs)
    capture, _ = complete_capture(capture_path)
    actual = sources.images(_paths(capture))
    if previous_job is not None:
        path = Path(previous_job).absolute()
        if path.is_dir(): path /= 'job.private.json'
        retained = {r:path.parent/'post'/(r+'.bin') for r in reference.ROLES}
        old = _previous_job(path, capture, _current_images=retained)
        canonical = _canonical_witness(old['forward_plan']['source_admission'], old['baseline'])
        rows = [{"offset": row['offset'], "actual_hex": row['after_hex'], "canonical_hex": row['before_hex']}
                for row in old['forward_plan']['components']['ap']['windows']]
    else:
        canonical = dict(actual)
        for proof in reversed(info['source_admission']['program_lineage']):
            canonical = sources._reverse(proof['stages'], canonical)
        rows = []
    _need({r:sources.identity(actual[r]) for r in reference.ROLES} == info['actual_images'], 'Actual source changed during projection')
    _need({r:sources.identity(canonical[r]) for r in reference.ROLES} == info['canonical_images'], 'Canonical witness changed')
    return dict(admission=info, actual_bytes=actual, pin_normalized_bytes=projection,
                canonical_bytes=canonical, canonical_profile=info['family'], body_binding=capture['body_binding'],
                pin_projection={'ap':rows,'actual':info['actual_images'],'normalized':info['projected_images'],
                                'canonical':info['canonical_images'],'camera_io':False})
