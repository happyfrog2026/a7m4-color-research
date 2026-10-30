"""Local original-backup diff and adaptive requirements, without device imports.

The selected complete original backup is the single target. This is a plan,
never a native/USB execution grant or proof of post-boot functional acceptance.
"""
from __future__ import annotations

from hashlib import sha256
import json
import struct
from pathlib import Path

from .capture_inputs import verified_capture, read_private
from . import settings_archive
from .settings_plan import SELECTED, SPANS, AP55, validate_snapshot, body_identity

SCHEMA = 'a7m4-original-backup-diff/1'
VERSION_SHA256 = 'b5377b8e08ba1f7a1105bcb6af07187414a5493a3d4622f02b7ad8a2578c87e5'
LOADER_SHA256 = '3b19665f84bcd1b837a3b9377b40a91893010ff9732be71a430f3d0265c72c69'
BASE_KEYS = (0x02CF0D0D, 0x02CF0D0F, 0x02CF0D11,
             0x02CF12EB, 0x02CF12ED, 0x02CF12EF,
             0x02CF130B, 0x02CF130D, 0x02CF130F)
SETTINGS_SPANS = dict(zip(SELECTED, SPANS)) | {AP55: ((0, 1),)} | {
    (0, key): ((0, 1),) for key in BASE_KEYS}
MAX_DIFF_BYTES = 2 * 1024 * 1024
MAX_WINDOWS = 8192


def _need(value, message):
    if not value: raise ValueError(message)


def _identity(raw):
    return dict(size=len(raw), sha256=sha256(raw).hexdigest())


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def byte_windows(source, target):
    """Bounded exact differing runs in the common prefix; EOF is separate.

    Equal 4KiB chunks are skipped without per-byte iteration on complete APs.
    These raw runs are later batched/aligned by a reviewed native builder.
    """
    _need(type(source) is bytes and type(target) is bytes, 'Complete immutable files required')
    size = min(len(source), len(target)); spans = []; total = 0
    for base in range(0, size, 4096):
        end = min(base + 4096, size)
        if source[base:end] == target[base:end]: continue
        at = base
        while at < end:
            if source[at] == target[at]: at += 1; continue
            start = at
            while at < end and source[at] != target[at]: at += 1
            total += at-start
            _need(total <= MAX_DIFF_BYTES and len(spans) < MAX_WINDOWS, 'Diff exceeds bounded review budget')
            spans.append(dict(offset=start, before_hex=source[start:at].hex(), after_hex=target[start:at].hex()))
    return spans


def resource_difference(source,target):
    """Exact diff fingerprint without embedding full language-file payloads."""
    digest=sha256();count=0;rows=[];bounded=True
    for base in range(0,min(len(source),len(target)),4096):
        end=min(base+4096,len(source),len(target))
        if source[base:end]==target[base:end]:continue
        at=base
        while at<end:
            if source[at]==target[at]:at+=1;continue
            start=at
            while at<end and source[at]!=target[at]:at+=1
            before,after=source[start:at],target[start:at];count+=at-start
            digest.update(struct.pack('<QI',start,at-start));digest.update(before);digest.update(after)
            if bounded and count<=16384 and len(rows)<8192:
                rows.append(dict(offset=start,before_hex=before.hex(),after_hex=after.hex()))
            else:bounded=False;rows=[]
    return rows,dict(changed_prefix_bytes=count,exact_changed_runs_sha256=digest.hexdigest(),
                     windows_embedded=bounded,full_original_target_available=True)


def _settings(root, capture):
    value = settings_archive.load_snapshot(root/'settings')
    validate_snapshot(value)
    _need(body_identity(value.serial) == capture['body_binding']['serial_sha256'], 'Settings/body identity differs')
    _need(capture.get('settings_capture_verified') is True, 'Complete settings capture required')
    return value


def _firmware(root):
    rows = {}
    for name, expected in (('version.txt', VERSION_SHA256), ('libJiritsu.so', LOADER_SHA256)):
        raw = read_private(root/'evidence'/name, 32*1024*1024)
        _need(sha256(raw).hexdigest() == expected, 'Missing or different 6.02 firmware/loader evidence: '+name)
        rows[name] = _identity(raw)
    return rows


def settings_diff(current, original, *, post_startup_ap55=False):
    """Restore declared business spans, never raw historical BK4 metadata.

    Changes outside the declared modifiable scope remain visible and preserved.
    This does not promise a whole-settings factory reset or rewrite calibration.
    """
    _need(type(post_startup_ap55) is bool, "Explicit AP55 verification policy required")
    rows, preserved = [], []
    for plane in ('ram','saved','bin','bak'):
        actual = getattr(current, plane).records
        # SAVE creates new backing copies of the selected saved business
        # values, rather than replaying an inactive historical BIN generation.
        target = getattr(original, 'saved' if plane in ('bin','bak') else plane).records
        _need(set(actual) == set(target), 'Original/current settings inventories differ')
        for pair in sorted(actual):
            before, after = actual[pair], target[pair]
            _need(before.attrs == after.attrs and len(before.data) == len(after.data), 'Setting attributes/size differs')
            if post_startup_ap55 and plane=='ram' and pair==AP55:
                endpoints=(original.ram.records[AP55],original.saved.records[AP55])
                _need(all(value.attrs==0 and value.data in (b'\0',b'\2') for value in endpoints),
                      'Post-startup AP55 policy only admits original00/02 endpoints')
                if before in endpoints:continue
            if before == after: continue
            allowed = SETTINGS_SPANS.get(pair, ())
            patches = []
            complement = bytearray(before.data)
            for lo, hi in allowed:
                _need(0 <= lo < hi <= len(before.data), 'Declared settings span exceeds record')
                if before.data[lo:hi] != after.data[lo:hi]:
                    patches.append(dict(offset=lo, before_hex=before.data[lo:hi].hex(), after_hex=after.data[lo:hi].hex()))
                    complement[lo:hi] = after.data[lo:hi]
            if patches:
                rows.append(dict(plane=plane, chip=pair[0], key=pair[1], attrs=before.attrs,
                                 source=_identity(before.data), target=_identity(bytes(complement)), windows=patches))
            if bytes(complement) != after.data:
                preserved.append(dict(plane=plane, chip=pair[0], key=pair[1],
                                      reason='outside declared modification scope; preserve current value'))
    return dict(schema='a7m4-original-settings-diff/1', records=rows,
                post_startup_settings_policy=dict(id='ap55-original-live-or-saved-only/1' if post_startup_ap55 else 'exact-original-live-and-saved/1',
                    original_AP55_ram_hex=original.ram.records[AP55].data.hex(),
                    original_AP55_saved_hex=original.saved.records[AP55].data.hex(),
                    observed_AP55_ram_hex=current.ram.records[AP55].data.hex(),
                    other_RAM_values='strict-original-owned-spans',saved_and_backing='strict-original-saved-owned-spans',
                    verification_only_exception=post_startup_ap55),
                source_evidence={plane:_identity(getattr(current,plane).raw) for plane in ('ram','saved','bin','bak')},
                original_evidence={plane:_identity(getattr(original,plane).raw) for plane in ('ram','saved','bin','bak')},
                source_direct_cp={str(key):_identity(raw) for key,raw in current.direct_cp},
                original_direct_cp={str(key):_identity(raw) for key,raw in original.direct_cp},
                preserved_non_target_differences=preserved,
                target_scope='declared modification spans from original backup',
                raw_BK4_replay=False, historical_counters_replayed=False,
                checksum_policy='native SAVE/recompute; independently validate complete fresh readback',
                calibration_replay=False, full_settings_factory_reset=False,
                complete_saved_and_live_values_verified=False)


def make_plan(current_capture, original_capture, *, post_startup_ap55=False):
    """Read verified 73-object captures and reconstruct one original target.

    No caller-provided patch/identity/active-feature list can replace the bytes.
    The user must select their actual earliest pre-modification backup; a file
    name, timestamp or hash cannot establish that historical fact by itself.
    """
    current_path, original_path = Path(current_capture).absolute(), Path(original_capture).absolute()
    current, original = verified_capture(current_path), verified_capture(original_path)
    from ..resource_profile import OBJECTS
    current = dict(current, objects={k:v for k,v in current['objects'].items() if k in OBJECTS})
    original = dict(original, objects={k:v for k,v in original['objects'].items() if k in OBJECTS})
    _need(current['body_binding'] == original['body_binding'], 'Original backup belongs to another camera')
    _need(set(current['objects']) == set(original['objects']), 'Original/current complete file inventories differ')
    firmware = _firmware(current_path.parent)
    _need(_firmware(original_path.parent) == firmware, 'Original/current firmware evidence differs')
    current_settings, original_settings = _settings(current_path.parent, current), _settings(original_path.parent, original)
    records = settings_diff(current_settings, original_settings,post_startup_ap55=post_startup_ap55)
    objects, changed, tails, blockers = [], [], [], []
    total_diff_bytes = 0
    for name, before in current['objects'].items():
        after = original['objects'][name]
        _need(all(before[k] == after[k] for k in ('kind','target_path')), 'Object kind or fixed destination differs')
        source_path, target_path = Path(current['snapshot_dir'])/name, Path(original['snapshot_dir'])/name
        source, target = read_private(source_path,160*1024*1024), read_private(target_path,160*1024*1024)
        _need(_identity(source) == {k:before[k] for k in ('size','sha256')}
              and _identity(target) == {k:after[k] for k in ('size','sha256')}, 'Complete source/target changed during diff')
        row = dict(path=name, target_path=before['target_path'], kind=before['kind'],
                   source_path=str(source_path), original_path=str(target_path),
                   source=_identity(source), target=_identity(target), action='NO_CHANGE', windows=[])
        if source != target:
            if before['kind']=='resource':
                row['windows'],row['difference']=resource_difference(source,target)
                row['preferred_strategy']=('protected-delta' if row['difference']['windows_embedded'] else 'original-target-atomic')
            else:row['windows'] = byte_windows(source, target)
            total_diff_bytes += sum(len(bytes.fromhex(w['before_hex'])) for w in row['windows'])
            _need(total_diff_bytes <= MAX_DIFF_BYTES, 'Total original-backup diff exceeds bounded review budget')
            if len(source) == len(target): row['action'] = 'RESTORE_EQUAL_LENGTH_DIFF'
            elif before['kind'] == 'resource' and len(source) > len(target):
                tail = source[len(target):]
                row.update(action='RESTORE_PREFIX_THEN_CONDITIONAL_TAIL', prefix_already_original=source.startswith(target),
                    intermediate=_identity(target+tail), tail=dict(offset=len(target), **_identity(tail)),
                    tail_ownership='NOT_ESTABLISHED_BY_PREFIX_EQUALITY',
                    tail_execution_requires='independent owned-tail proof, restored references and fresh native mapping inspection')
                tails.append(name)
                if len(tail) > 43008:
                    row['preferred_strategy']='original-target-atomic'
                    row['tail_helper_unavailable_reason']='tail exceeds reviewed 43008-byte shadow helper limit'
            elif before['kind'] == 'audio':
                row.update(action='RESTORE_SOUND_DIFF_AND_EOF', audio_descriptor_coordination_required=True,
                           reviewed_sound_adapter_required=True)
            else:
                row['action'] = 'UNSUPPORTED_SIZE_CHANGE'
                blockers.append(dict(path=name,reason='program shrink/growth or missing resource bytes require separate reviewed adapter'))
            changed.append(name)
        objects.append(row)
    unchanged = not changed and not records['records']
    plan = dict(schema=SCHEMA,settings_target_after_startup=post_startup_ap55,target_semantics='selected earliest complete pre-modification backup',
        original_backup_historical_fact='USER_SELECTION_NOT_INFERRED_FROM_FILENAME',
        body_binding=current['body_binding'], firmware='6.02', firmware_evidence=firmware,
        source_capture=dict(receipt=str(current_path), receipt_sha256=sha256(read_private(current_path,2*1024*1024)).hexdigest(),
                            archive_sha256=current['archive_sha256']),
        original_capture=dict(receipt=str(original_path), receipt_sha256=sha256(read_private(original_path,2*1024*1024)).hexdigest(),
                              archive_sha256=original['archive_sha256']),
        objects=objects, changed_objects=changed, object_count=len(objects),
        settings=records, resource_tail_objects=tails, blockers=blockers,
        operation='NO_OP' if unchanged else 'RESTORE_ORIGINAL_BACKUP',
        connection_policy=dict(fixed_round_count=False, exact_required_connections=None,
            write_connection_required=not unchanged,
            split_only_for='fresh mapping, capacity, source/adoption/boot evidence or bounded helper constraints',
            equal_length_round_policy='same or separate rounds according to actual safety dependencies',
            final_reboot_acceptance_required=None,
            runtime_acceptance='pending unless actual same-boot original-load and user acceptance evidence is reusable'),
        functional_restore_complete=False, full_file_restore_complete=False,
        post_boot_full_file_verification_complete=False, user_boot_function_acceptance='NOT_PERFORMED',
        automatic_retry=False, camera_io=False, network_io=False,
        device_ready=False, execution_available=False,
        executor='driver original-restore',
        status='DIFF_VERIFIED_REQUIRES_EXPLICIT_EXECUTION' if not blockers else 'REVIEW_BLOCKED')
    plan['plan_id'] = sha256(_json(plan)).hexdigest()
    return plan


def validate_plan(plan):
    _need(type(plan) is dict and plan.get('schema') == SCHEMA, 'Original-backup diff schema required')
    rebuilt = make_plan(plan['source_capture']['receipt'], plan['original_capture']['receipt'],
                        post_startup_ap55=plan.get('settings_target_after_startup',False))
    _need(rebuilt == plan, 'Original-backup diff changed or arbitrary windows supplied')
    return rebuilt


def decide_connection(plan, observations):
    """Conditional scheduling only; observations never authorize execution.

    A coordinator must populate these from fresh native reports after binding
    current complete sources. Caller-supplied booleans are not release grants.
    """
    plan = validate_plan(plan)
    _need(type(observations) is dict and set(observations) == {'plan_id','objects'}, 'Exact fresh observation envelope required')
    _need(observations['plan_id'] == plan['plan_id'] and type(observations['objects']) is dict, 'Observation plan binding differs')
    decisions = []
    for row in plan['objects']:
        if row['action'] == 'NO_CHANGE': continue
        observed = observations['objects'].get(row['path'])
        if observed is None:
            decisions.append(dict(path=row['path'], action='INSPECT_NATIVE_BEFORE_DECIDING')); continue
        _need(type(observed) is dict and set(observed) == {'source','mapping','available_bytes','allocation_unit'}, 'Exact mapping/capacity observation required')
        _need(observed['source'] == row['source'], 'Native observation is stale or for a different full source')
        mapping = observed['mapping']; available, unit = observed['available_bytes'], observed['allocation_unit']
        _need(mapping in ('none','current-private-readonly','other-process','unknown')
              and type(available) is int and available >= 0 and type(unit) is int and 0 < unit <= 1048576,
              'Invalid bounded native mapping/capacity observation')
        if mapping == 'unknown': action='STOP_UNKNOWN_MAPPING'
        elif row['action'] == 'UNSUPPORTED_SIZE_CHANGE': action='STOP_UNSUPPORTED_CHANGE'
        elif row['kind'] != 'resource': action='REVIEWED_SOURCE_BOUND_PROGRAM_OR_SOUND_ADAPTER'
        elif row.get('preferred_strategy')=='original-target-atomic':
            required=((row['target']['size']+unit-1)//unit+32)*unit
            action='ORIGINAL_TARGET_ATOMIC_ELIGIBLE' if available>=required else 'NEEDS_ORIGINAL_TARGET_ATOMIC_CAPACITY_OR_ANOTHER_REVIEWED_STRATEGY'
        elif row['action'] == 'RESTORE_PREFIX_THEN_CONDITIONAL_TAIL' and row['prefix_already_original']:
            action = 'REQUIRES_REFERENCE_RELEASE_OR_NEW_BOOT' if mapping == 'other-process' else 'CONDITIONAL_SHADOW_TAIL_ELIGIBLE'
        else:
            size = row.get('intermediate',row['target'])['size']
            required = ((size+unit-1)//unit + 4)*unit + 8388608
            if available >= required:
                action = ('ATOMIC_PREFIX_RESTORE_THEN_REINSPECT_TAIL' if row['path'] in plan['resource_tail_objects']
                          else 'ATOMIC_REPLACEMENT_ELIGIBLE')
            else: action = 'NEEDS_REVIEWED_IN_PLACE_DIFF_OR_RELEASE_AND_REINSPECT'
        decisions.append(dict(path=row['path'], action=action))
    return dict(schema='a7m4-original-restore-adaptive-decision/1', plan_id=plan['plan_id'],
                decisions=decisions, fixed_round_count=False, exact_required_connections=None,
                device_ready=False, execution_available=False, observations_are_not_execution_authority=True,
                camera_io=False, network_io=False)
