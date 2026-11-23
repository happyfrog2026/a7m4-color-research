"""Discard only compiler-created scratch caches in our new private build tree."""
from pathlib import Path
import shutil
from .run_log import event


def discard_caches(folder):
    folder=Path(folder)
    for name in ('zig-global','zig-local'):
        path=folder/name
        if path.is_symlink():raise ValueError('Compiler cache was redirected')
        if path.is_dir():shutil.rmtree(path)
    event('compiler-scratch-cleared',stage='double-build-verified')
