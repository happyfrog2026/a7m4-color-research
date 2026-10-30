"""Output-volume observation only; storage warnings never authorize or block I/O."""
from pathlib import Path
import json
import os
import sys

LOG_RESERVE = 1 << 30
DEFAULT_DATA = 512 << 20
DEVICE_JOB_DATA = 2 << 30


def observe(output, estimated_data=DEFAULT_DATA):
    parent = Path(output).absolute()
    while not parent.exists() and parent != parent.parent:
        parent = parent.parent
    parent = parent.resolve(strict=True)
    fs = os.statvfs(parent)
    free = fs.f_bavail * fs.f_frsize
    required = max(0, int(estimated_data))
    return dict(schema='a7m4-output-volume-space/1', volume_device=parent.stat().st_dev,
        available_bytes=free, estimated_data_bytes=required, extra_log_reserve_bytes=LOG_RESERVE,
        warning=free < required + LOG_RESERVE, blocking=False)


def warn(output, *, capture=None, operation=None):
    """Best-effort diagnostics. Actual preimage/intent writes still fail closed."""
    try:
        estimate = DEVICE_JOB_DATA if operation in ('selected-install','features','backup-target-restore','backup-target-verify','original-verify','sound','sound-gate','sound-scoped') else DEFAULT_DATA
        if capture is not None:
            from .capture_inputs import read_private
            from ..resource_profile import OBJECTS
            value = json.loads(read_private(capture, 2*1024*1024))
            estimate = max(estimate, 3*sum(row['size'] for name,row in value.get('objects',{}).items()
                if name in OBJECTS and type(row.get('size')) is int and row['size'] >= 0))
        value = observe(output, estimate)
    except (OSError, ValueError, TypeError, KeyError, AttributeError, OverflowError):
        value = dict(schema='a7m4-output-volume-space/1', available_bytes=None,
            extra_log_reserve_bytes=LOG_RESERVE, warning=True, blocking=False, status='UNAVAILABLE')
    from .run_log import event
    event('output-volume-space', **value)
    if value['warning']:
        print('磁盘空间提示：请确认输出磁盘可容纳本次数据，并额外预留 1 GiB 日志空间。此提示不阻止继续；实际记录写入仍须成功。',file=sys.stderr)
    return value
