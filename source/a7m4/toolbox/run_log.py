"""Segmented local diagnostics: retain every session, never native payloads."""
from contextvars import ContextVar
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import threading
import uuid

_ACTIVE=ContextVar('a7m4_diagnostic_run',default=None)
MAX_BYTES=1024*1024
MAX_RUNS=20  # Legacy compatibility only; history is no longer pruned.


def clean(text):
    text=str(text)[:2048]
    text=re.sub(r'(?i)(password|secret|token|key)\s*[=:]\s*\S+',r'\1=[redacted]',text)
    return re.sub(r'(?i)\b[0-9a-f]{32,}\b','[hex omitted]',text)


def output_summary(raw):
    if raw is None:return None
    raw=raw.encode('utf-8',errors='replace') if isinstance(raw,str) else bytes(raw)
    result=dict(bytes=len(raw),sha256=sha256(raw).hexdigest())
    try:
        value=json.loads(raw[:65536])
        if type(value) is dict:
            result['summary']={k:clean(value[k]) for k in ('schema','status','error','version')
                               if k in value and isinstance(value[k],(str,int,bool))}
    except (ValueError,UnicodeError):pass
    return result


class RunLog:
    def __init__(self,run_id=None,directory=None,*,root_job=False):
        self.run_id=run_id or uuid.uuid4().hex
        if not re.fullmatch(r'[a-fA-F0-9-]{16,40}',self.run_id):raise ValueError('Invalid diagnostic run ID')
        self.root_job=root_job;self.fd=None;self.count=0;self.pending=[];self.lock=threading.RLock()
        self.path=None;self.parent_fd=None;self.base_name=None;self.part=0
        if not root_job:
            directory=Path(directory) if directory is not None else Path.home()/'Library/Logs/A7M4 Toolbox'
            if any(p.is_symlink() for p in (directory,*directory.parents)):raise ValueError('Redirected log directory')
            directory.mkdir(mode=0o700,parents=True,exist_ok=True)
            info=directory.stat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid():raise ValueError('Log directory owner differs')
            directory.chmod(0o700)
            self._open(directory/('run-'+self.run_id+'.jsonl'))
    def _open(self,path):
        self.parent_fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        self.base_name=path.name;self.path=path
        try:
            self.fd=self._segment(self.base_name)
            pending,self.pending=self.pending,[]
            for row in pending:self._append(row)
        except BaseException:
            if self.fd is not None:os.close(self.fd);self.fd=None
            os.close(self.parent_fd);self.parent_fd=None
            raise
    def _segment(self,name):
        # The directory descriptor was pinned at first creation. Root logging
        # never resolves a new pathname in a returned, user-owned job tree.
        fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=self.parent_fd)
        try:
            parent=os.fstat(self.parent_fd)
            if self.root_job and os.geteuid()==0 and parent.st_uid!=0:
                os.fchown(fd,parent.st_uid,parent.st_gid)
        except BaseException:os.close(fd);raise
        return fd
    def bind_job(self,path):
        if self.root_job and self.fd is None:
            # Called only after the existing job owner has created its private,
            # initially empty output. No root writes to the user's Logs tree.
            self._open(Path(path)/'diagnostic.jsonl')
    def _append(self,row):
        raw=(json.dumps(row,ensure_ascii=False,allow_nan=False)+'\n').encode()
        if len(raw)>MAX_BYTES//2:
            raw=(json.dumps(dict(time=row['time'],run_id=self.run_id,event='oversize-diagnostic-omitted',
                bytes=len(raw),sha256=sha256(raw).hexdigest()))+'\n').encode()
        if self.count+len(raw)>MAX_BYTES:
            name=self.base_name.removesuffix('.jsonl')+'-part-%06d.jsonl'%(self.part+1)
            try:new_fd=self._segment(name)
            except OSError:
                # A presentation/storage failure cannot affect device control.
                # Keep appending to the existing inode rather than lose history.
                new_fd=None
            if new_fd is not None:
                old=self.fd;self.fd=new_fd;self.part+=1;self.count=0
                try:os.fsync(old)
                finally:os.close(old)
        view=memoryview(raw)
        while view:
            written=os.write(self.fd,view)
            if written<=0:raise OSError('Diagnostic write did not advance')
            view=view[written:]
        self.count+=len(raw)
    def event(self,event,**facts):
        row=dict(time=datetime.now(timezone.utc).isoformat(),run_id=self.run_id,event=clean(event),
                 **{k:(v if k in ('sha256','report_sha256') else clean(v) if isinstance(v,str) else v) for k,v in facts.items()})
        with self.lock:
            if self.fd is None:
                if len(self.pending)<100:self.pending.append(row)
            else:self._append(row)
    def close(self):
        try:
            if self.fd is not None:
                try:os.fsync(self.fd)
                finally:os.close(self.fd);self.fd=None
        finally:
            if self.parent_fd is not None:os.close(self.parent_fd);self.parent_fd=None


def event(name,**facts):
    logger=_ACTIVE.get()
    if logger is not None:
        try:logger.event(name,**facts)
        except (OSError,ValueError):pass


def active_run_id():
    logger=_ACTIVE.get()
    return logger.run_id if logger is not None else None


def bind_job(path):
    logger=_ACTIVE.get()
    if logger is not None:
        try:logger.bind_job(path)
        except (OSError,ValueError):pass


def logged_main(main):
    run_id=None
    if '--diagnostic-run-id' in sys.argv:
        at=sys.argv.index('--diagnostic-run-id')
        if at+1>=len(sys.argv):raise ValueError('Diagnostic run ID is missing')
        run_id=sys.argv[at+1];del sys.argv[at:at+2]
    # Failures in diagnostics must not change device STOP/cleanup semantics.
    try:logger=RunLog(run_id,root_job=os.geteuid()==0)
    except (OSError,ValueError):logger=None
    token=_ACTIVE.set(logger)
    original_run=subprocess.run
    def traced_run(*args,**kwargs):
        command=args[0] if args else kwargs.get('args',())
        name=Path(command[0]).name if isinstance(command,(tuple,list)) and command else 'shell'
        event('subprocess-start',helper=name,argument_count=len(command) if isinstance(command,(tuple,list)) else 0,
              flags=[str(a) for a in command[1:] if isinstance(a,str) and re.fullmatch(r'--?[a-zA-Z][a-zA-Z0-9-]*',a)][:32]
              if isinstance(command,(tuple,list)) else [])
        try:
            result=original_run(*args,**kwargs)
            event('subprocess-exit',helper=name,exit_code=result.returncode,
                  stdout=output_summary(result.stdout),stderr=output_summary(result.stderr))
            return result
        except subprocess.CalledProcessError as error:
            event('subprocess-exit',helper=name,exit_code=error.returncode,
                  stdout=output_summary(error.stdout),stderr=output_summary(error.stderr))
            raise
        except subprocess.TimeoutExpired:
            event('subprocess-timeout',helper=name);raise
        except BaseException as error:
            event('subprocess-error',helper=name,error_type=type(error).__name__);raise
    subprocess.run=traced_run
    try:
        from . import __version__
        event('driver-start',version=__version__,pid=os.getpid(),euid=os.geteuid(),operation=' '.join(sys.argv[1:3]) if sys.argv[1:2]==['driver'] else (sys.argv[1] if len(sys.argv)>1 else 'help'))
        result=main();event('driver-exit',exit_code=result);return result
    except BaseException as error:
        event('driver-exception',error_type=type(error).__name__);raise
    finally:
        subprocess.run=original_run;_ACTIVE.reset(token)
        if logger is not None:
            try:logger.close()
            except OSError:pass
