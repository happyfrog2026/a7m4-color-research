"""Complete protected settings comparison for read-capture and prewrite admission.

This grants no write; existing finite write/readback/identity guards stay active.

All raw snapshots are retained. Named native maintenance observations do not
become restore targets, SAVE permission, or a claim of a fully static snapshot.
Unknown records, shapes, metadata, cached CP and direct CP remain strict.
"""
from hashlib import sha256
import struct

from .bk4 import bk4_rows
from . import native_ui
from .settings_plan import validate_snapshot
from .settings_job import _runtime_counter

PROFILE = 'm4-602-read-capture-stability/3'
FRESHNESS_PROFILE = 'm4-602-protected-settings-freshness/4'
# Cross-STOP observations +4/+5/+6; deliberately finite candidate ceiling.
# No wrapping, backward movement, opaque-header masking or counter replay.
MAX_CROSS_STOP_GENERATION_DELTA = 8
PLANES = ('ram', 'saved', 'bin', 'bak')
# M4 6.02 BKID catalogue / R030 zero-WRITE/SAVE saved-catchup observation.
CATCHUP = {0x02CF0B6E: (0x40, 4, 'top-display-layer-screen-id'),
           0x02CF140C: (0, 4, 'contents-info-list-regenerate-time-slot11')}
# 02770015: observed M4 6.02 RAM-only u32 drift; official name/unit
# remain unknown. This is an explicit bounded candidate policy, not semantics.
COUNTERS = {0x01070000: (0x40, 8), 0x02780000: (2, 256), 0x02770015: (2, 4)}


def _settings_report(before, after, *, cross_stop=False):
    validate_snapshot(before); validate_snapshot(after)
    errors, accepted, planes = [], [], {}
    if not native_ui.snapshot_valid(before) or not native_ui.snapshot_valid(after):
        errors.append('Native UI diagnostic shape/complete word groups differ')
    if before.serial != after.serial: errors.append('Settings body identity changed')
    if before.direct_cp != after.direct_cp: errors.append('Direct CP complete records changed')
    for plane in PLANES:
        old, new = getattr(before, plane), getattr(after, plane)
        row = dict(raw_equal=old.raw == new.raw,
                   before_sha256=sha256(old.raw).hexdigest(), after_sha256=sha256(new.raw).hexdigest())
        planes[plane] = row
        if old.raw == new.raw: continue
        bin_active_match = plane == 'bin' and after.bin.raw == after.saved.raw
        if plane == 'bin': row['active_final_saved_match'] = bin_active_match
        if plane == 'bin' and not cross_stop and not bin_active_match:
            errors.append('BACKUP.BIN complete bytes changed'); continue
        if len(old.raw) != len(new.raw) or set(old.records) != set(new.records):
            errors.append(plane+': record inventory/raw length changed'); continue
        left, right = bytearray(old.raw), bytearray(new.raw)
        old_rows, new_rows = bk4_rows(old.raw), bk4_rows(new.raw)
        catchup_count = 0
        bin_generation_delta = (struct.unpack_from('<I',new.raw,new_rows[0]['base']+0x2c)[0]
            - struct.unpack_from('<I',old.raw,old_rows[0]['base']+0x2c)[0]) if plane == 'bin' else 0
        bin_screen_eligible = bin_active_match and 1 <= bin_generation_delta <= (MAX_CROSS_STOP_GENERATION_DELTA if cross_stop else 2)
        for pair, previous in old.records.items():
            current = new.records[pair]
            if previous == current: continue
            chip, key = pair
            shape = previous.attrs, len(previous.data)
            allowed, rule = False, None
            if (current.attrs, len(current.data)) == shape and chip == 0:
                if plane == 'ram' and native_ui.diagnostic(pair,old.records) and native_ui.diagnostic(pair,new.records):
                    allowed, rule = True, 'fresh-native-APP-UI-diagnostic-value'
                if plane == 'ram' and COUNTERS.get(key) == shape and _runtime_counter(pair, previous, current):
                    allowed, rule = True, ('bounded-unnamed-RAM-u32-candidate' if key == 0x02770015 else 'bounded-inherited-RAM-counter')
                if plane in ('saved', 'bak') and key in CATCHUP and CATCHUP[key][:2] == shape:
                    reference, final = before.ram.records[pair], after.ram.records[pair]
                    if reference == final == current:
                        allowed, rule = True, 'named-native-catchup-to-stable-baseline-RAM'
                        catchup_count += 1
                if plane == 'bin' and bin_screen_eligible and key == 0x02CF0B6E and shape == (0x40, 4):
                    reference, final = before.ram.records[pair], after.ram.records[pair]
                    if reference == final == current:
                        allowed, rule = True, 'BIN-SCREEN-catchup-to-complete-final-saved'
                        catchup_count += 1
            if not allowed:
                errors.append('%s/%d/%08x: unexpected settings value or shape'%(plane, chip, key)); continue
            entry, next_entry = old_rows[chip]['records'][key], new_rows[chip]['records'][key]
            if entry != next_entry:
                errors.append('%s/%d/%08x: record layout changed'%(plane, chip, key)); continue
            start, size = entry['offset'], entry['size']
            left[start:start+size] = right[start:start+size] = bytes(size)
            accepted.append(dict(plane=plane, chip=chip, key='%08x'%key, attrs=shape[0], size=size,
                                 rule=rule, before_sha256=sha256(previous.data).hexdigest(),
                                 after_sha256=sha256(current.data).hexdigest()))
        # Full BK4 parsing above already recomputed both additive checksums.
        # Only AP checksum can accompany the admitted AP payload/counter changes.
        base, next_base = old_rows[0]['base'], new_rows[0]['base']
        if base != next_base:
            errors.append(plane+': AP segment moved'); continue
        left[base+0x20:base+0x24] = right[base+0x20:base+0x24] = bytes(4)
        old_count = struct.unpack_from('<I', old.raw, base+0x2c)[0]
        new_count = struct.unpack_from('<I', new.raw, base+0x2c)[0]
        if old_count != new_count:
            # Cross-STOP count-only persistence is distinct from same-capture
            # native catchup. Check every remaining byte before admitting this
            # one field; unknown data/header/CP changes cannot ride this mask.
            payload_left, payload_right = bytearray(left), bytearray(right)
            payload_left[base+0x2c:base+0x30] = payload_right[base+0x2c:base+0x30] = bytes(4)
            cross_stop_count = (cross_stop and plane in ('saved', 'bin', 'bak')
                and 1 <= new_count-old_count <= MAX_CROSS_STOP_GENERATION_DELTA
                and payload_left == payload_right)
            capture_count = (not cross_stop and plane in ('saved', 'bak', 'bin') and catchup_count
                and 1 <= new_count-old_count <= 2)
            if cross_stop_count or capture_count:
                left[base+0x2c:base+0x30] = right[base+0x2c:base+0x30] = bytes(4)
                accepted.append(dict(plane=plane, chip=0, field='ap-generation-u32',
                    before=old_count, after=new_count,
                    rule='bounded-cross-STOP-generation' if cross_stop_count else 'bounded-native-catchup-generation'))
            else: errors.append(plane+': unexpected AP generation change')
        if left != right:
            errors.append(plane+': unapproved raw settings bytes changed')
    return dict(schema='a7m4-capture-settings-stability/1', profile=PROFILE,
                stable=not errors, raw_equal=all(row['raw_equal'] for row in planes.values()),
                planes=planes, accepted_differences=accepted, errors=errors,
                restoration_scope='owned-spans-only', full_snapshot_static=False,
                write_readback_policy_relaxed=False,
                native_ui_policy=native_ui.POLICY,
                native_ui_ram_before=native_ui.state(before.ram.records) if native_ui.mapping_valid(before.ram.records) else None,
                native_ui_ram_after=native_ui.state(after.ram.records) if native_ui.mapping_valid(after.ram.records) else None)


def capture_stability_report(before, after):
    """Same-capture policy with one proved active-BIN SCREEN catchup endpoint."""
    return _settings_report(before, after)


def settings_freshness_report(before, after, *, native_context=None):
    """Same complete protected-byte rule at explicit prewrite admission only.

    All file/source, selected owned-span, direct CP, native identity, full
    write/readback and finite SAVE guards remain independently mandatory.
    """
    result = _settings_report(before, after, cross_stop=True)
    result.update(schema='a7m4-protected-settings-freshness/1',
                  profile=FRESHNESS_PROFILE,
                  comparison_profile=PROFILE,
                  metadata_profile='m4-602-bounded-cross-STOP-generation/1',
                  maximum_generation_increment=MAX_CROSS_STOP_GENERATION_DELTA,
                  native_context=native_context,
                  authorizes_device_write=False)
    return result
