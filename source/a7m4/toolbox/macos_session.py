"""App-lifetime, finite macOS root broker. Only local AF_UNIX, never device I/O.

First bootstrap uses system sudo once. No credentials are accepted or stored.
Privileged driver execution uses a root-owned, private snapshot of the bundle.
Every request is a direct GUI-child peer and a fresh, finite owned driver job.
"""
from pathlib import Path
from hashlib import sha256
import ctypes
import json
import os
import pwd
import shlex
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import threading
import time
import uuid

from . import session_policy as policy
from .macos_authorization import EXIT_MARKER,MAX_OUTPUT,MAX_STDERR,private_job,read_output,capture_stderr

MAX_FRAME=24*1024*1024
_device_request_attempted=False


class BoundedServerStderr:
    """A single existing log FD; never sets file limits on device workers."""
    def write(self,text):
        raw=str(text).encode('utf-8',errors='replace')[-MAX_STDERR:]
        if os.fstat(2).st_size+len(raw)>MAX_STDERR:os.ftruncate(2,0);os.lseek(2,0,os.SEEK_SET)
        os.write(2,raw);return len(text)
    def flush(self):os.fsync(2)


def need(ok,message):policy.need(ok,message)


def canonical_uuid(value):
    need(type(value) is str and uuid.UUID(value).hex==value,'Canonical random session UUID required');return value


def state_path(uid,session):
    canonical_uuid(session);need(type(uid) is int and 0<uid<2**31,'Login user required')
    return Path('/private/var/run')/f'a7m4-tb-{uid}-{session}'


class BSDInfo(ctypes.Structure):
    _fields_=[(n,ctypes.c_uint32) for n in ('flags','status','xstatus','pid','ppid','uid','gid','ruid','rgid','svuid','svgid','reserved')]+[
        ('comm',ctypes.c_char*16),('name',ctypes.c_char*32)]+[(n,ctypes.c_uint32) for n in ('nfiles','pgid','jobc','tdev','tpgid')]+[
        ('nice',ctypes.c_int32),('start_sec',ctypes.c_uint64),('start_usec',ctypes.c_uint64)]


def process_identity(pid):
    need(sys.platform=='darwin' and type(pid) is int and pid>1,'Darwin App process required')
    lib=ctypes.CDLL('/usr/lib/libproc.dylib',use_errno=True)
    info=BSDInfo();count=lib.proc_pidinfo(pid,3,0,ctypes.byref(info),ctypes.sizeof(info))
    need(count==ctypes.sizeof(info) and info.pid==pid,'App/peer process no longer exists')
    buf=ctypes.create_string_buffer(4096)
    need(lib.proc_pidpath(pid,buf,len(buf))>0,'Process executable unavailable')
    return dict(pid=pid,ppid=info.ppid,uid=info.uid,start=[info.start_sec,info.start_usec],path=os.fsdecode(buf.value))


def peer_credentials(sock):
    lib=ctypes.CDLL('/usr/lib/libSystem.B.dylib',use_errno=True);uid=ctypes.c_uint32();gid=ctypes.c_uint32()
    need(lib.getpeereid(sock.fileno(),ctypes.byref(uid),ctypes.byref(gid))==0,'Missing Unix peer credentials')
    return dict(uid=uid.value,gid=gid.value)


def peer_identity(sock):
    credentials=peer_credentials(sock)
    pid=struct.unpack('i',sock.getsockopt(0,2,4))[0] # SOL_LOCAL / LOCAL_PEERPID, SDK sys/un.h.
    info=process_identity(pid);need(info['uid']==credentials['uid'],'Unix peer credential mismatch');return info


def send(sock,value):
    raw=json.dumps(value,ensure_ascii=False,allow_nan=False,separators=(',',':')).encode()
    need(0<len(raw)<=MAX_FRAME,'Bounded session frame required');sock.sendall(struct.pack('!I',len(raw))+raw)


def receive(sock):
    def exact(n):
        out=bytearray()
        while len(out)<n:
            raw=sock.recv(n-len(out));need(raw,'Session channel ended');out.extend(raw)
        return bytes(out)
    size=struct.unpack('!I',exact(4))[0];need(0<size<=MAX_FRAME,'Session frame limit exceeded')
    value=json.loads(exact(size));need(type(value) is dict,'Session object required');return value


def app_alive(config):
    try:return process_identity(config['gui']['pid'])==config['gui']
    except (OSError,ValueError):return False


def validate_peer(peer,config):
    need(peer['uid']==config['uid'] and peer['ppid']==config['gui']['pid']
         and peer['path']==config['client_python'],'Only this App direct bundled client may use the session')
    need(app_alive(config),'App session process changed or exited')


def run_driver(argv,config):
    """No shell, caller environment, interpreter choice, timeout or job kill."""
    payload=Path(config['root'])/'payload';owner=pwd.getpwuid(config['uid'])
    env=dict(PATH=str(payload/'zig')+':/usr/bin:/bin',HOME=owner.pw_dir,USER=owner.pw_name,LOGNAME=owner.pw_name,
             LANG='en_US.UTF-8',PYTHONDONTWRITEBYTECODE='1',LIBUSB_DEBUG='4')
    child=subprocess.Popen([str(payload/'python/bin/python3'),'-I','-B',str(payload/'kit/run_research.py'),*argv],
        cwd=payload/'kit',env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,close_fds=True)
    buffers=[bytearray(),bytearray()];overflow=[False]
    def drain(stream,index,limit):
        while True:
            raw=stream.read(65536)
            if not raw:break
            buffers[index].extend(raw)
            if len(buffers[index])>limit:
                if index==0:overflow[0]=True
                del buffers[index][:-limit]
    threads=[threading.Thread(target=drain,args=(child.stdout,0,MAX_OUTPUT)),threading.Thread(target=drain,args=(child.stderr,1,MAX_STDERR))]
    for t in threads:t.start()
    code=child.wait()
    for t in threads:t.join()
    return dict(code=code,stdout=buffers[0].decode('utf-8',errors='replace'),stderr=buffers[1].decode('utf-8',errors='replace'),
                output_complete=not overflow[0],worker_pid=child.pid)


def serve(config,*,executor=run_driver):
    need(os.geteuid()==0,'Session server must run from authorized root snapshot')
    root=Path(config['root']);expected=state_path(config['uid'],config['session'])
    need(root==expected and root.stat().st_uid==0 and (root/'payload').stat().st_uid==0,'Fixed root session snapshot required')
    state=policy.SessionState(lambda:app_alive(config));listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
    listener.bind(str(root/'s'));os.chown(root/'s',config['uid'],config['gid']);os.chmod(root/'s',0o600);listener.listen(1);listener.settimeout(.25)
    def watch():
        while not state.closing:
            if not app_alive(config):state.close();return
            time.sleep(.2)
    monitor=threading.Thread(target=watch,daemon=True);monitor.start()
    try:
        while not state.closing:
            try:conn,_=listener.accept()
            except socket.timeout:continue
            # Sequential requests: no concurrent driver and no replay/restart.
            with conn:
                accepted=False
                try:
                    conn.settimeout(10);validate_peer(peer_identity(conn),config);request=receive(conn)
                    need(request.get('session')==config['session'],'Session identity differs')
                    if request.get('operation')=='ping':
                        need(set(request)=={'session','operation'},'Malformed status request')
                        send(conn,dict(ready=True,pid=os.getpid()));continue
                    need(set(request)=={'session','request_id','job','arguments'},'Only finite job requests admitted')
                    argv=policy.arguments(request['arguments'],job=request['job'],support=config['support'],uid=config['uid'],gid=config['gid'],compiler=root/'payload/zig/zig')
                    state.begin(request['request_id']);accepted=True;conn.settimeout(None)
                    result=executor(argv,config) # App exit revokes new jobs; this one finishes safely.
                    send(conn,dict(accepted=True,request_id=request['request_id'],**result))
                except (OSError,ValueError) as error:
                    try:send(conn,dict(accepted=accepted,error=type(error).__name__,message=str(error)))
                    except OSError:pass
                finally:
                    if accepted:state.finish()
    finally:
        state.close();listener.close()
        # Only this root-created UUID directory, after its sole worker is done.
        need(root==state_path(config['uid'],config['session']) and root.stat().st_uid==0,'Session cleanup root changed')
        shutil.rmtree(root)


def clone_tree(source,destination):
    lib=ctypes.CDLL('/usr/lib/libSystem.B.dylib',use_errno=True)
    lib.clonefile.argtypes=(ctypes.c_char_p,ctypes.c_char_p,ctypes.c_int)
    def copy(src,dst):
        need(not Path(src).is_symlink(),'App snapshot must contain regular files')
        if lib.clonefile(os.fsencode(src),os.fsencode(dst),0)!=0:shutil.copy2(src,dst)
        os.chown(dst,0,0)
        return dst
    # Ignore cache files; all approved source/runtime/compiler bytes are retained.
    shutil.copytree(source,destination,copy_function=copy,ignore=shutil.ignore_patterns('__pycache__','*.pyc'))


def root_dependency_probe(payload):
    """Load only verified snapshot dependencies before granting broker readiness."""
    from .dependency_probe import SCHEMA, MESSAGE
    command=[str(payload/'python/bin/python3'),'-I','-B',str(payload/'kit/run_research.py'),'--dependency-probe']
    result=None;timeout_error=None
    try:
        result=subprocess.run(command,cwd=payload/'kit',stdin=subprocess.DEVNULL,capture_output=True,
            timeout=120,env=dict(PATH='/usr/bin:/bin',LANG='en_US.UTF-8',PYTHONDONTWRITEBYTECODE='1'))
        raw=result.stdout.decode('utf-8',errors='replace') if isinstance(result.stdout,bytes) else result.stdout
        report=json.loads(raw)
        valid=(report.get('schema')==SCHEMA and report.get('camera_io') is False
               and report.get('usb_backend_created') is False and report.get('usb_initialized') is False
               and report.get('camera_protocol_requests_sent') is False)
        if not valid:raise ValueError('Invalid immutable dependency probe receipt')
        checks=report.get('checks',[])
        required=[row for row in checks if type(row) is dict and row.get('required') is True] if type(checks) is list else []
        if (result.returncode==0 and report.get('ready') is True and type(checks) is list
                and len(required)==2 and {row.get('name') for row in required}=={'SHA256','libusb-dlopen'}
                and all(row.get('ready') is True for row in required)):return report
    except Exception as error:
        from .dependency_probe import _cause,system_metadata
        if isinstance(error,subprocess.TimeoutExpired):timeout_error=error
        report=dict(schema=SCHEMA,ready=False,camera_io=False,causes=_cause(error),system=system_metadata(),probe_command=command)
    # Keep dyld/policy output even if the process crashed, timed out, or never
    # produced JSON. These are diagnostic tails, not a readiness grant.
    source=result if result is not None else timeout_error
    report['process_returncode']=getattr(result,'returncode',None)
    report['process_timed_out']=timeout_error is not None
    for field in ('stdout','stderr'):
        value=getattr(source,field,None)
        raw=value if isinstance(value,bytes) else str(value).encode('utf-8') if value is not None else b''
        report['process_'+field]=raw[-65536:].decode('utf-8',errors='replace')
        report['process_'+field+'_bytes']=len(raw)
        report['process_'+field+'_truncated']=len(raw)>65536
    # stdout is the already-open private bootstrap log, never a root-selected
    # user pathname. The client can only use this receipt to refuse dispatch.
    print(json.dumps(dict(status='AUTH_DEPENDENCIES_NOT_READY',camera_io=False,
        camera_protocol_requests_sent=False,error=MESSAGE,dependency_probe=report),ensure_ascii=False),flush=True)
    raise ValueError('AUTH_DEPENDENCIES_NOT_READY: '+MESSAGE)


def bootstrap(session,gui_pid,uid,gid,client_python,resources):
    need(os.geteuid()==0 and str(uid)==os.environ.get('SUDO_UID') and str(gid)==os.environ.get('SUDO_GID'),'Fresh system-authorized login owner required')
    root=state_path(uid,session);resources=Path(resources).absolute();app=resources.parent.parent
    need(resources.name=='Resources' and resources.parent.name=='Contents' and app.suffix=='.app','Fixed bundled resources required')
    need(not any(p.is_symlink() for p in (resources,*resources.parents)),'Redirected App bundle')
    gui=process_identity(gui_pid)
    need(gui['uid']==uid and gui['path']==str(app/'Contents/MacOS/A7M4Research') and client_python==str(resources/'python/bin/python3'), 'App process/bundled client identity differs')
    subprocess.run(['/usr/bin/codesign','--verify','--deep','--strict',str(app)],check=True,stdin=subprocess.DEVNULL)
    root.mkdir(mode=0o700);root.chmod(0o711);payload=root/'payload';payload.mkdir(mode=0o700)
    launched=False
    try:
        for name in ('kit','python','vendor','zig'):clone_tree(resources/name,payload/name)
        # Verify root copy against the reviewed manifest, and immutable helper
        # bytes, after cloning rather than trusting the mutable client paths.
        import importlib.util
        spec=importlib.util.spec_from_file_location('session_release_inputs',payload/'kit/tools/release_inputs.py');mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
        mod.load_inputs(payload/'kit',require_complete=True)
        helper_spec=importlib.util.spec_from_file_location('session_helpers',payload/'kit/a7m4/toolbox/helpers.py')
        helper_mod=importlib.util.module_from_spec(helper_spec);helper_spec.loader.exec_module(helper_mod)
        need(helper_mod.helper_inventory(verify=True).get('verified') is True,'Bundled helper snapshot differs')
        pack_spec=importlib.util.spec_from_file_location('session_packager',payload/'kit/tools/package_internal_research.py')
        pack=importlib.util.module_from_spec(pack_spec);pack_spec.loader.exec_module(pack)
        pack.runtime_license_files(payload/'kit/packaging/internal-research/runtime-licenses',payload/'python')
        pack.verify_app_vendor(payload/'vendor')
        compiler_spec=importlib.util.spec_from_file_location('session_compiler',payload/'kit/tools/compiler_bundle.py')
        compiler_mod=importlib.util.module_from_spec(compiler_spec);compiler_spec.loader.exec_module(compiler_mod)
        compiler_mod.verify_bundle(payload/'zig')
        subprocess.run(['/usr/bin/codesign','--verify','--deep','--strict',str(app)],check=True,stdin=subprocess.DEVNULL)
        need(process_identity(gui_pid)==gui,'App exited/changed during authorization')
        root_dependency_probe(payload)
        need(process_identity(gui_pid)==gui,'App exited/changed during dependency load check')
        config=dict(root=str(root),session=session,uid=uid,gid=gid,gui=gui,client_python=client_python,
            support=str(Path(pwd.getpwuid(uid).pw_dir)/'Library/Application Support/A7 IV Toolbox'))
        path=root/'config.json';fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'w') as f:json.dump(config,f);f.flush();os.fsync(f.fileno())
        log_fd=os.open(root/'server.stderr.log',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        os.fchown(log_fd,uid,gid)
        try:
            child=subprocess.Popen([str(payload/'python/bin/python3'),'-I','-B',str(payload/'kit/run_research.py'),'--session-server',str(path)],
                stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=log_fd,start_new_session=True,close_fds=True,
                env=dict(PATH='/usr/bin:/bin',HOME=pwd.getpwuid(uid).pw_dir,LANG='en_US.UTF-8',PYTHONDONTWRITEBYTECODE='1'))
        finally:os.close(log_fd)
        launched=True
        print(json.dumps(dict(session_started=True,pid=child.pid,password_stored=False)),flush=True)
    finally:
        if not launched and root.exists():shutil.rmtree(root)


def connect(session,uid):
    sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
    try:
        sock.connect(str(state_path(uid,session)/'s'))
        # An ordinary GUI user cannot inspect root proc_pidinfo on Darwin.
        # The root-owned session socket plus kernel peer UID is sufficient
        # here. Server-side full GUI/client PID validation stays unchanged.
        need(peer_credentials(sock)['uid']==0,'Session endpoint must be root')
        return sock
    except BaseException:
        sock.close();raise


def authorization_phase(job,phase):
    """Host-only presentation marker, never an execution/completion grant."""
    path=Path(job)/'authorization-phase.json';tmp=path.with_suffix('.tmp')
    raw=json.dumps(dict(schema='a7m4-authorization-phase/1',phase=phase,time=time.time()),allow_nan=False).encode()
    try:
        fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
        os.replace(tmp,path)
        return True
    except OSError:
        # Optional timing metadata must never cancel or release a device job.
        return False


def wait_bootstrap(folder,ping,*,pause=time.sleep,clock=time.monotonic,alive=None):
    """Only before a job request. Human sudo input has no elapsed deadline.

    A missing Terminal launch or a dead shell must not wait forever for its
    exit marker. An authenticated ready ping wins even if Terminal closed
    after the detached server started. No worker is killed or retried here.
    """
    alive=alive or (lambda pid:process_identity(pid))
    start=clock();shell=None;finished_at=None
    while True:
        try:
            if ping():return
        except OSError:pass
        marker=folder/'bootstrap.exit'
        if marker.exists():
            code=int(read_output(marker,16).strip())
            if code:
                failure=bootstrap_dependency_failure(folder)
                if failure is not None:raise ValueError('AUTH_DEPENDENCIES_NOT_READY: '+failure['error'])
                raise ValueError('AUTH_CANCELLED: 首次授权已取消；未发送相机作业。请重新打开应用。')
            if finished_at is None:finished_at=clock()
            if clock()-finished_at>=10:raise ValueError('AUTH_NOT_STARTED: 授权握手未完成；未发送相机作业。')
        pid_path=folder/'bootstrap.pid'
        if pid_path.exists():
            pid=int(read_output(pid_path,32).strip());need(pid>1,'Invalid authorization shell PID')
            try:current=alive(pid)
            except (OSError,ValueError):current=None
            if current is None or shell is not None and current!=shell:
                raise ValueError('AUTH_CANCELLED: 授权窗口已关闭；未发送相机作业。请重新打开应用。')
            shell=current
        elif not marker.exists() and clock()-start>=30:
            raise ValueError('AUTH_NOT_STARTED: Terminal 未启动授权；未发送相机作业。请重新打开应用。')
        pause(.25)


def bootstrap_dependency_failure(folder):
    try:
        value=json.loads(read_output(folder/'bootstrap.stdout.log',MAX_OUTPUT))
        if (type(value) is dict and value.get('status')=='AUTH_DEPENDENCIES_NOT_READY'
                and value.get('camera_io') is False and type(value.get('error')) is str):return value
    except (OSError,ValueError):pass
    return None


def client(job,session,gui_pid,python,runner,argv,*,open_terminal=subprocess.run,pause=time.sleep):
    global _device_request_attempted
    _device_request_attempted=False
    job=private_job(job);need(os.geteuid()!=0,'GUI session client must remain login user')
    session=canonical_uuid(session);need(os.getppid()==gui_pid,'Session bridge must be the App child')
    python=Path(python);runner=Path(runner);resources=runner.parent.parent
    need(python==resources/'python/bin/python3' and runner.name=='run_research.py','Fixed bundled session bridge paths required')
    support=Path(pwd.getpwuid(os.getuid()).pw_dir)/'Library/Application Support/A7 IV Toolbox'
    policy.arguments(argv,job=job,support=support,uid=os.getuid(),gid=job.stat().st_gid,compiler=resources/'zig/zig')
    folder=support/'authorization-sessions'/session
    if not folder.exists():
        folder.parent.mkdir(mode=0o700,exist_ok=True);private_job(folder.parent)
        folder.mkdir(mode=0o700);private_job(folder)
        for name in ('bootstrap.stdout.log','bootstrap.stderr.log'):
            fd=os.open(folder/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);os.close(fd)
        owner=pwd.getpwuid(os.getuid())
        command=['/usr/bin/sudo','-k','--','/usr/bin/env','PATH=/usr/bin:/bin','HOME='+owner.pw_dir,'USER='+owner.pw_name,
            'LOGNAME='+owner.pw_name,'LANG=en_US.UTF-8','PYTHONDONTWRITEBYTECODE=1',str(python),'-I','-B',str(runner),
            '--session-bootstrap',session,str(gui_pid),str(os.getuid()),str(job.stat().st_gid),str(python),str(resources)]
        stderr=shlex.join([str(python),'-I','-B',str(runner),'--terminal-stderr',str(folder/'bootstrap.stderr.log')])
        exit_path=shlex.quote(str(folder/'bootstrap.exit'));exit_tmp=shlex.quote(str(folder/'bootstrap.exit.tmp'))
        script='\n'.join(['#!/bin/bash','umask 077',
            'printf "%s\\n" "$$" > '+shlex.quote(str(folder/'bootstrap.pid.tmp')),
            '/bin/mv '+shlex.quote(str(folder/'bootstrap.pid.tmp'))+' '+shlex.quote(str(folder/'bootstrap.pid')),
            'write_bootstrap_status() { printf "%s\\n" "$1" > '+exit_tmp+'; /bin/mv '+exit_tmp+' '+exit_path+'; }',
            "trap 'write_bootstrap_status \"$?\"' EXIT",
            "trap 'exit 129' HUP", "trap 'exit 130' INT QUIT", "trap 'exit 143' TERM",
            "printf '%s\\n' 'A7 IV 工具箱：请输入系统 sudo 密码。授权握手完成前请勿关闭此窗口。密码不会交给应用或保存。'",
            shlex.join(command)+' > '+shlex.quote(str(folder/'bootstrap.stdout.log'))+' 2> >('+stderr+')','code=$?',
            'write_bootstrap_status "$code"','if [ "$code" -ne 0 ]; then exit "$code"; fi',
            'while [ ! -f '+shlex.quote(str(folder/'authorization.ready'))+' ]; do',
            '  if [ -f '+shlex.quote(str(folder/'authorization.failed'))+' ]; then exit 1; fi','  /bin/sleep 0.25','done',
            "printf '%s\\n' '授权已就绪。请保持电脑与相机连接；仅在应用明确提示冷启动时，按指引断开。后台会话绑定本次 App，退出 App 后自动撤销。'",''])
        fd=os.open(folder/'authorize-session.command',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o700)
        with os.fdopen(fd,'w') as f:f.write(script)
        authorization_phase(job,'WAITING_FOR_AUTHORIZATION')
        opened=open_terminal(['/usr/bin/open','-a','Terminal',str(folder/'authorize-session.command')],capture_output=True,check=False)
        if opened.returncode:return finish(dict(status='AUTH_NOT_STARTED',camera_io=False,error='无法打开首次管理员授权。'),2)
        def ping():
            with connect(session,os.getuid()) as sock:
                if hasattr(sock,'settimeout'):sock.settimeout(1)
                send(sock,dict(session=session,operation='ping'))
                need(receive(sock).get('ready') is True,'Session not ready')
            return True
        try:wait_bootstrap(folder,ping,pause=pause)
        except ValueError as error:
            try:(folder/'authorization.failed').write_text('no job dispatched\n')
            except OSError:pass
            keep_server_stderr(job,session)
            failure=bootstrap_dependency_failure(folder)
            if failure is not None:return finish(failure,2)
            return finish(dict(status='AUTH_CANCELLED' if str(error).startswith('AUTH_CANCELLED:') else 'AUTH_NOT_STARTED',camera_io=False,error=str(error)),2)
        (folder/'authorization.ready').write_text('authenticated ping ready\n')
        authorization_phase(job,'AUTHORIZATION_READY')
    else:private_job(folder)
    request_id=uuid.uuid4().hex
    try:sock=connect(session,os.getuid())
    except (OSError,ValueError):
        return finish(dict(status='SESSION_ENDED',camera_io=False,error='本次 App 管理员会话已结束；请重新打开应用再授权。'),2)
    with sock:
        authorization_phase(job,'RUNNING')
        _device_request_attempted=True # Set before any job frame bytes: uncertain send stays unknown.
        send(sock,dict(session=session,request_id=request_id,job=str(job),arguments=argv));reply=receive(sock)
    fd=os.open(job/'authorization.private.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as f:json.dump(dict(schema='a7m4-app-session-authorization/1',session=session,request_id=request_id,password_stored=False,worker_pid=reply.get('worker_pid'),driver_exit_code=reply.get('code')),f)
    if not reply.get('accepted'):
        return finish(dict(status='SESSION_REQUEST_REFUSED',camera_io=False,error=reply.get('message','受限会话拒绝本次请求。')),2)
    for name,text in [('authorization.stdout.log',reply.get('stdout','')),('authorization.stderr.log',reply.get('stderr','')+server_stderr(session))]:
        fd=os.open(job/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        raw=text.encode('utf-8')
        if name.endswith('stderr.log'):raw=raw[-MAX_STDERR:]
        with os.fdopen(fd,'wb') as f:f.write(raw)
    need(reply.get('output_complete') is True and type(reply.get('code')) is int,'Unknown session driver output; follow owned terminal receipt')
    return reply['stdout'].encode()+(EXIT_MARKER+str(reply['code'])+'\n').encode()


def finish(value,code):return json.dumps(value,ensure_ascii=False).encode()+(EXIT_MARKER+str(code)+'\n').encode()


def server_stderr(session):
    try:return read_output(state_path(os.getuid(),session)/'server.stderr.log',MAX_STDERR).decode('utf-8',errors='replace')
    except OSError:return ''


def keep_server_stderr(job,session):
    raw=server_stderr(session).encode()
    fd=os.open(job/'authorization.stderr.log',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:f.write(raw[-MAX_STDERR:])


def main(argv):
    global _device_request_attempted
    _device_request_attempted=False
    try:
        raw=client(argv[0],argv[1],int(argv[2]),argv[3],argv[4],argv[5:]);sys.stdout.buffer.write(raw);sys.stdout.buffer.flush();return 0
    except BaseException as error:
        if not _device_request_attempted:
            value=dict(status='AUTH_NOT_STARTED',camera_io=False,error='首次授权或本地准备未完成；未发送相机作业。请检查本地提示后重新打开应用。',error_type=type(error).__name__)
            sys.stdout.buffer.write(finish(value,2));sys.stdout.buffer.flush();return 0
        print('Administrator session channel unknown: '+type(error).__name__,file=sys.stderr);return 2
