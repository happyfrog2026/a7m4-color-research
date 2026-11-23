"""Source-tree entry point for the shared toolbox driver."""
from pathlib import Path
import os
import sys

kit = Path(__file__).resolve().parent
sys.path.insert(0, str(kit))
vendor = kit.parent / "vendor"
if (vendor / "vendor-manifest.json").is_file():
    sys.path.insert(1, str(vendor))
compiler = kit.parent / "zig"
if (compiler / "compiler-manifest.json").is_file():
    os.environ["PATH"] = str(compiler) + os.pathsep + os.environ.get("PATH", "/usr/bin:/bin")

from a7m4.toolbox.cli import main

from a7m4.toolbox.run_log import logged_main
raise SystemExit(logged_main(main))
