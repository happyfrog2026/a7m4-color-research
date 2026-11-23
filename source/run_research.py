from pathlib import Path
import os
import sys
kit = Path(__file__).resolve().parent
sys.path.insert(0, str(kit))
vendor = kit.parent / "vendor"
if (vendor / "vendor-manifest.json").is_file(): sys.path.insert(1, str(vendor))
compiler = kit.parent / "zig"
if (compiler / "compiler-manifest.json").is_file():
    os.environ["PATH"] = str(compiler) + os.pathsep + os.environ.get("PATH", "/usr/bin:/bin")
if sys.argv[1:] == ['--dependency-probe']:
    from a7m4.toolbox.dependency_probe import main as dependency_probe
    raise SystemExit(dependency_probe())
if sys.argv[1:2] == ['--session-authorize']:
    from a7m4.toolbox.macos_session import main as session_client
    raise SystemExit(session_client(sys.argv[2:]))
if sys.argv[1:2] == ['--session-bootstrap']:
    from a7m4.toolbox.macos_session import bootstrap
    session,gui,uid,gid,python,resources=sys.argv[2:]
    bootstrap(session,int(gui),int(uid),int(gid),python,resources)
    raise SystemExit(0)
if sys.argv[1:2] == ['--session-server']:
    import json
    from a7m4.toolbox.macos_session import serve,state_path,BoundedServerStderr
    sys.stderr=BoundedServerStderr()
    config_path=Path(sys.argv[2]);config=json.loads(config_path.read_bytes())
    if os.geteuid()!=0 or config_path!=state_path(config['uid'],config['session'])/'config.json' or config_path.stat().st_uid!=0:
        raise SystemExit('Invalid root session configuration')
    serve(config)
    raise SystemExit(0)
if sys.argv[1:2] == ['--terminal-stderr']:
    from a7m4.toolbox.macos_authorization import capture_stderr
    capture_stderr(sys.argv[2])
    raise SystemExit(0)
if sys.argv[1:2] == ['--terminal-authorize']:
    from a7m4.toolbox.macos_authorization import main as authorize
    raise SystemExit(authorize(sys.argv[2:]))
if sys.argv[1:2] == ['--terminal-worker']:
    del sys.argv[1]
    if os.geteuid() != 0: raise SystemExit('Terminal worker requires sudo')
    import signal
    for sig in (signal.SIGHUP, signal.SIGINT, signal.SIGQUIT): signal.signal(sig, signal.SIG_IGN)
    from a7m4.toolbox.macos_authorization import START_MARKER
    sys.stdout.write(START_MARKER+str(os.getpid())+"\n"); sys.stdout.flush()
from a7m4.toolbox.cli import main
from a7m4.toolbox.run_log import logged_main
raise SystemExit(logged_main(main))
