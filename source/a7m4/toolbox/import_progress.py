"""Small, optional import presentation; never validation or device authority."""
from copy import deepcopy
import json
import math
import os
from pathlib import Path
import stat
import time
import uuid

SCHEMA = 'a7m4-portable-import-progress/1'
FILENAME = 'import-progress.json'
MAX_BYTES = 4096
INTERVAL = 0.75
PHASES = ('PREPARING', 'READ_OUTER_ARCHIVE', 'HASH_OUTER_ARCHIVE',
          'VERIFY_CORE_ARCHIVE', 'VERIFY_SETTINGS', 'VERIFY_NESTED_ARCHIVE',
          'EXTRACT_SNAPSHOT', 'VERIFY_IMPORTED_FILES', 'COMPLETE', 'FAILED')


def _diagnose(error, phase):
    try:
        from .run_log import event
        event('local-import-progress-error', phase=phase,
              error_type=type(error).__name__)
    except Exception:
        pass  # Presentation/log storage never changes the data operation.


def notify(callback, phase, **values):
    """Best effort only, including a caller-supplied presentation callback."""
    if callback is not None:
        try:
            callback(phase, **values)
        except Exception as error:
            _diagnose(error, phase)


class ImportProgress:
    """One fixed sidecar in the new import directory, at most 4096 B per write.

    ``callback`` receives the same scalar-only dict as the sidecar. It is
    invoked only on published updates. Counts describe this phase's actual
    work; None means the existing validator has no per-object callback.
    """
    def __init__(self, root, *, callback=None, clock=time.monotonic,
                 interval=INTERVAL):
        self.root = Path(root).absolute()
        self.path = self.root / FILENAME
        self.callback = callback
        self.clock = clock
        self.interval = interval
        self.started = clock()
        self.last = None
        self.phase = None
        self.row = None

    def emit(self, phase, *, objects_done=None, objects_total=None,
             bytes_done=None, bytes_total=None, force=False, error_type=None):
        try:
            if phase not in PHASES:
                raise ValueError('Unknown local import presentation phase')
            values = dict(objects_done=objects_done, objects_total=objects_total,
                          bytes_done=bytes_done, bytes_total=bytes_total)
            for value in values.values():
                if value is not None and (type(value) is not int or not 0 <= value <= 1 << 40):
                    raise ValueError('Invalid local import presentation count')
            for kind in ('objects', 'bytes'):
                done, total = values[kind + '_done'], values[kind + '_total']
                if done is not None and total is not None and done > total:
                    raise ValueError('Local import presentation count exceeds total')
            now = self.clock()
            elapsed = now - self.started
            if not math.isfinite(elapsed):
                raise ValueError('Invalid local import presentation clock')
            changed = phase != self.phase
            previous = self.phase
            self.phase = phase
            self.row = dict(schema=SCHEMA, phase=phase,
                elapsed_seconds=round(max(0, elapsed), 3), **values,
                complete=phase == 'COMPLETE', failed=phase == 'FAILED',
                presentation_only=True, device_admission=False, camera_io=False)
            if phase == 'FAILED':
                self.row['failed_phase'] = previous
                self.row['error_type'] = str(error_type or 'Exception')[:96]
            if not (force or changed or phase in ('COMPLETE', 'FAILED')
                    or self.last is None or now - self.last >= self.interval):
                return False
            raw = (json.dumps(self.row, ensure_ascii=False, sort_keys=True,
                              allow_nan=False) + '\n').encode('utf-8')
            if len(raw) > MAX_BYTES:
                raise ValueError('Local import presentation exceeds 4096 B')
            self.last = now
            # The root was freshly made by import_portable. Never redirect a
            # display write through an existing link or nonregular sidecar.
            if any(p.is_symlink() for p in (self.root, *self.root.parents)):
                raise ValueError('Redirected local import presentation root')
            if self.path.exists() or self.path.is_symlink():
                info = self.path.lstat()
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise ValueError('Local import presentation is not a regular file')
            temporary = self.root / ('.import-progress-' + uuid.uuid4().hex + '.tmp')
            try:
                fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, self.path)
            finally:
                if temporary.exists():
                    temporary.unlink()
            if self.callback is not None:
                try:
                    self.callback(deepcopy(self.row))
                except Exception as error:
                    _diagnose(error, phase)
            return True
        except Exception as error:
            _diagnose(error, phase)
            return False
