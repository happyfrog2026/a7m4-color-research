"""Finite administrator-session request policy; no process/socket/device I/O."""
from pathlib import Path
import os
import re
import stat
import threading

FLAGS=frozenset(('execute','battery-confirmed','msc-confirmed','ack-backup','ack-brick','ack-risk','ack-original','startup-confirmed'))
PATHS=frozenset(('capture','original-capture','output','prepared','config','native-project','program-job','sound-job','previous-job','capsule','c-capsule','gate-capsule','selection'))
COMMON={'output','job-owner-uid','job-owner-gid','diagnostic-run-id'}
WRITES={'execute','battery-confirmed','msc-confirmed','ack-backup','ack-brick','ack-risk'}
OPERATIONS={
 'backup':({'output','execute','battery-confirmed','msc-confirmed'},set()),
 'sound-gate':(WRITES|{'capture','state','program-job','sound-job','c-capsule'}, {'capture','state'}),
 'sound':(WRITES|{'capture','prepared','previous-job','program-job'}, {'capture','prepared'}),
 'looks':(WRITES|{'capture','config','native-project','program-job','sound-job'}, {'capture','config'}),
 'restore':(WRITES|{'capture','previous-job'}, {'capture','previous-job'}),
 'gate-c-restore':(WRITES|{'capture','capsule'}, {'capture','capsule'}),
 'sound-scoped':(WRITES|{'capture','prepared','gate-capsule'}, {'capture','prepared','gate-capsule'}),
 'sound-c-restore':(WRITES|{'capture','capsule'}, {'capture','capsule'}),
 'selected-install':(WRITES|{'capture','selection','selection-sha256'}, {'capture','selection','selection-sha256'}),
 'features':(WRITES|{'capture','profile','native-project','prepared'}, {'capture','profile'}),
 'backup-target-restore':(WRITES|{'capture','original-capture','previous-job','ack-original','startup-confirmed'}, {'capture','original-capture','ack-original'}),
 'backup-target-verify':(WRITES|{'capture','original-capture','previous-job','ack-original','startup-confirmed'}, {'capture','original-capture','previous-job','ack-original','startup-confirmed'}),
 'original-verify':({'capture','original-capture','previous-job','execute','battery-confirmed','msc-confirmed','ack-original','startup-confirmed'}, {'capture','original-capture','ack-original','startup-confirmed'}),
}


def need(ok,message):
    if not ok:raise ValueError(message)


def private_path(value,support,*,directory=False,uid=None):
    need(type(value) is str and value.startswith('/') and len(value)<=4096 and '\0' not in value,'Canonical private path required')
    path=Path(value);support=Path(support)
    need('..' not in path.parts and '.' not in path.parts and path.is_relative_to(support) and path!=support,'Path outside App workspace')
    need(not any(p.is_symlink() for p in (path,*path.parents)),'Redirected App material')
    if directory:
        info=path.stat()
        need(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode)==0o700 and info.st_uid==uid,'Owned private job directory required')
    return path


def arguments(argv,*,job,support,uid,gid,compiler):
    need(type(argv) is list and 2<len(argv)<=128 and all(type(x) is str and 0<len(x)<=4096 and '\0' not in x for x in argv),'Bounded argv required')
    need(argv[0]=='driver' and argv[1] in OPERATIONS,'Only finite camera driver operations permitted')
    allowed,required=OPERATIONS[argv[1]];allowed=allowed|COMMON|{'compiler'}
    seen=set();values={};i=2;result=argv[:2]
    while i<len(argv):
        flag=argv[i];need(flag.startswith('--') and flag[2:] in allowed,'Unapproved session argument')
        name=flag[2:];need(name=='program-job' or name not in seen,'Duplicate session argument');seen.add(name)
        if name in FLAGS:result.append(flag);i+=1;continue
        need(i+1<len(argv) and not argv[i+1].startswith('--'),'Missing session value');value=argv[i+1];values[name]=value
        if name in PATHS:private_path(value,support)
        elif name in ('job-owner-uid','job-owner-gid'):
            need(value==str(uid if name.endswith('uid') else gid),'Fixed login owner required')
        elif name=='selection-sha256':need(re.fullmatch('[0-9a-f]{64}',value) is not None,'Exact confirmed selection SHA-256 required')
        elif name=='state':need(value in ('enabled','disabled'),'Finite Gate state required')
        elif name=='profile':need(value in ('fl23','custom1-m9','all-current'),'Only three fixed feature profiles permitted')
        elif name=='diagnostic-run-id':need(re.fullmatch('[a-zA-Z0-9-]{1,64}',value) is not None,'Finite diagnostic ID required')
        elif name=='compiler':value=str(compiler) # No client-selected executable.
        result.extend((flag,value));i+=2
    base={'output','job-owner-uid','job-owner-gid','execute','battery-confirmed','msc-confirmed'}
    required=required|base|(WRITES if argv[1] not in ('backup','original-verify') else set())
    need(required<=seen,'Missing current job/risk acknowledgments')
    need(values['output']==str(Path(job)/'capture'),'Output must be this new job/capture')
    private_path(str(job),support,directory=True,uid=uid)
    need(not (Path(job)/'capture').exists(),'Job output cannot be reused')
    return result


class SessionState:
    """Replays/overlap denied; closing revokes new jobs, never kills active job."""
    def __init__(self,alive):
        self.alive=alive;self.closing=False;self.active=False;self.claimed=set();self.lock=threading.Lock()
    def begin(self,request_id):
        with self.lock:
            need(not self.closing and self.alive(),'App session ended')
            need(not self.active and request_id not in self.claimed and len(self.claimed)<256,'Busy/replayed/exhausted session job')
            need(type(request_id) is str and re.fullmatch('[0-9a-f]{32}',request_id) is not None,'Unique request UUID required')
            self.claimed.add(request_id);self.active=True
    def finish(self):
        with self.lock:self.active=False
    def close(self):
        with self.lock:self.closing=True
