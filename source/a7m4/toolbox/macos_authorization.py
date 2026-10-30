"""One explicit camera job through Terminal sudo; no USB imports or retries.

The login-user bridge creates the script and output files. sudo reads its own
password from the controlling terminal. Closing GUI/Terminal never authorizes
replay or killing the privileged worker. The driver retains result_owner.
"""
from pathlib import Path
import json
import os
import pwd
import shlex
import stat
import subprocess
import sys
import time

EXIT_MARKER = '\n__A7M4_TOOLBOX_DRIVER_EXIT__='
START_MARKER = '__A7M4_TERMINAL_WORKER_STARTED__='
MAX_OUTPUT = 16 * 1024 * 1024
MAX_STDERR = 1024 * 1024


def private_job(value):
    path = Path(value).absolute()
    if '..' in path.parts or any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError('Redirected authorization job')
    info = path.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError('Authorization requires the current user private job')
    return path


def launcher(job, python, runner, arguments):
    """Pure generation: arguments are shell-quoted independently, never eval'd."""
    owner = pwd.getpwuid(os.getuid())
    command = ['/usr/bin/sudo', '/usr/bin/env', 'PATH=/usr/bin:/bin',
               'HOME='+owner.pw_dir, 'USER='+owner.pw_name, 'LOGNAME='+owner.pw_name,
               'LANG=en_US.UTF-8', 'PYTHONDONTWRITEBYTECODE=1', 'LIBUSB_DEBUG=4',
               str(python), '-I', '-B', str(runner), '--terminal-worker', *arguments]
    stderr_capture = shlex.join([str(python), '-I', '-B', str(runner), '--terminal-stderr', str(job/'authorization.stderr.log')])
    return '\n'.join([
        '#!/bin/bash', 'umask 077', "trap '' HUP INT QUIT",
        "printf '%s\\n' 'A7 IV 工具箱：本次相机操作需要管理员权限。' "
        "'请在终端输入 Mac 登录密码（输入时不显示），密码只交给系统 sudo。' "
        "'请等待本次操作结束，不要关闭此终端或重复点击相机操作。'",
        # This redirection is opened by the ordinary-user shell, before sudo.
        shlex.join(command)+' > '+shlex.quote(str(job/'authorization.stdout.log'))+
        ' 2> >('+stderr_capture+')',
        'code=$?',
        "printf '%s\\n' \"$code\" > "+shlex.quote(str(job/'authorization.exit.tmp')),
        '/bin/mv '+shlex.quote(str(job/'authorization.exit.tmp'))+' '+shlex.quote(str(job/'authorization.exit')),
        "printf '\\n相机操作已结束（退出码 %s），请返回 A7 IV 工具箱查看结果。\\n' \"$code\"", ''])


def capture_stderr(value, source=None):
    """Ordinary-user bounded stderr spool; no password input or root writes."""
    path = Path(value)
    private_job(path.parent)
    fd = os.open(path, os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid():
            raise ValueError('Invalid diagnostic spool')
        os.ftruncate(fd, 0)
        count = 0
        source = source if source is not None else sys.stdin.buffer
        while True:
            chunk = source.read(65536)
            if not chunk: break
            if count+len(chunk) > MAX_STDERR:
                os.lseek(fd, 0, os.SEEK_SET); os.ftruncate(fd, 0); count = 0
            os.write(fd, chunk); count += len(chunk)
        os.fsync(fd)
    finally: os.close(fd)


def read_output(path, limit=MAX_OUTPUT):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid() or info.st_size > limit:
            raise ValueError('Authorization output identity/size differs')
        with os.fdopen(fd, 'rb', closefd=False) as stream: return stream.read(limit+1)
    finally: os.close(fd)


def worker_pid(raw):
    line = raw.partition(b'\n')[0]
    if not line.startswith(START_MARKER.encode()): return None
    value = line[len(START_MARKER):]
    if not value.isdigit() or not 0 < int(value) < 2**31: return None
    return int(value)


def finish_output(raw, code):
    started = worker_pid(raw) is not None
    if started:
        raw = raw.partition(b'\n')[2]
        # A sudo/Terminal exit alone cannot prove an orphaned worker ended.
        # Only its final CLI JSON may release the GUI's protected lifetime;
        # malformed/partial output takes the existing owned-receipt fallback.
        value = json.loads(raw)
        if not isinstance(value, dict) or not isinstance(value.get('status'), str):
            raise ValueError('Worker has no final driver result')
    if not started:
        # The bootstrap prints its marker before importing any camera code.
        raw = json.dumps(dict(schema='a7m4-toolbox-authorization/1',
            status='AUTH_CANCELLED' if code == 1 else 'AUTH_NOT_STARTED',
            camera_io=False, complete=False, verified=False,
            error='终端管理员授权未完成；未进入相机驱动。请查看终端与本地日志。'), ensure_ascii=False).encode()
    return raw + (EXIT_MARKER+str(code)+'\n').encode()


def execute(job, python, runner, arguments, *, open_terminal=subprocess.run, pause=time.sleep):
    job = private_job(job)
    if os.geteuid() == 0: raise ValueError('Terminal bridge must remain the login user')
    python, runner = Path(python), Path(runner)
    if not python.is_absolute() or not runner.is_absolute() or runner.name != 'run_research.py':
        raise ValueError('Invalid bundled driver paths')
    if arguments[:1] != ['driver'] or '--job-owner-uid' not in arguments or '--job-owner-gid' not in arguments:
        raise ValueError('An explicit owned device command is required')
    for name, content, mode in [('authorization.stdout.log', b'', 0o600),
                                ('authorization.stderr.log', b'', 0o600),
                                ('authorize-in-terminal.command', launcher(job, python, runner, arguments).encode(), 0o700)]:
        fd = os.open(job/name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
        try: os.write(fd, content)
        finally: os.close(fd)
    opened = open_terminal(['/usr/bin/open', '-a', 'Terminal', str(job/'authorize-in-terminal.command')],
                           capture_output=True, check=False)
    if opened.returncode:
        return finish_output(b'', 128)
    # open only starts Terminal. Never infer worker completion from open's exit,
    # impose a timeout, terminate sudo, or replay a camera operation.
    while not (job/'authorization.exit').exists(): pause(.5)
    code = int(read_output(job/'authorization.exit', 16).strip())
    if not 0 <= code <= 255: raise ValueError('Invalid terminal completion code')
    raw = read_output(job/'authorization.stdout.log')
    metadata = dict(schema='a7m4-terminal-authorization/1', terminal_sudo=True,
        worker_pid=worker_pid(raw), driver_exit_code=code, password_stored=False)
    fd = os.open(job/'authorization.private.json', os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
    try: os.write(fd, (json.dumps(metadata)+'\n').encode())
    finally: os.close(fd)
    return finish_output(raw, code)


def main(arguments):
    if len(arguments) < 4: raise ValueError('Missing one-job authorization arguments')
    try:
        raw = execute(arguments[0], arguments[1], arguments[2], arguments[3:])
    except BaseException as error:
        # No marker: GUI must retain its unknown-result guard and follow the
        # returned-owned driver receipt. Bridge failure never proves no USB I/O.
        print('Terminal authorization bridge failed: '+type(error).__name__, file=sys.stderr)
        return 2
    sys.stdout.buffer.write(raw); sys.stdout.buffer.flush()
    return 0
