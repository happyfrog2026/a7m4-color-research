"""Export retained application diagnostics, never device contents or credentials.

No device modules, subprocesses, network, privilege escalation or source mutation.
Only three application-owned trees are enumerated. Reports are projected into
safe metadata; this is deliberately not an arbitrary JSON/file copier.
"""
from datetime import datetime, timezone
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import re
import secrets
import stat
import zipfile

SCHEMA='a7m4-diagnostics-archive/1'
MAX_JSON=16*1024*1024
MAX_LINE=1024*1024
MAX_DEPTH=24
MAX_NODES=200000
_DIR_FLAGS=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW
_SECRET=re.compile(r'password|passwd|secret|credential|cookie|(?:^|_)token$|private_key|api_key|authorization_header|^key$',re.I)
_IDENTITY=re.compile(r'^(?:usb_)?serial(?:_number|_sha256)?$|^body_(?:id|binding)$|^nonce$|^boot_id$',re.I)
_PAYLOAD=re.compile(r'^(?:raw|data|payload|packet|before|after|original|value|values|expected|actual|content|contents|text_bytes|pixels|samples)$|(?:_hex|_base64|_b64|_raw|_payload|_packet|_data)$',re.I)
_NUMERIC=re.compile(r'(?:count|bytes|size|length|offset|errno|returncode|exit_code|pid|uid|gid|flags|mode|status|seconds|available|required|reserve|headroom|written|read|maps|pages|segments|index|ordinal|attempts|rc|rv)$',re.I)
# Fixed scalar fields from the reviewed native report codecs. These are syscall
# outcomes, cleanup counters and file identities, never payload/setting values.
_NATIVE_NUMERIC={'readonly','remount','rollback','plugin_unlink','close_errors',
    'source_dev','source_ino','source_nlink','cross_matches','cross_pids',
    'ap_dev','ap_inode','cp_dev','cp_inode','cleanup','writes',
    'gain_db','recock_gap_ms','recock_gap_samples','cutoff_denominator',
    'kasha_pair_delay_samples'}
_TEXT=re.compile(r'(?:schema|status|phase|profile|feature|operation|event|time|created|version|platform|architecture|system|os_build|validation_scope|error|message|reason|error_type|exception|function|file|path|helper|known_answer|operation_id|run_id|session_id|stage|outcome|scope|name|kind|type|label|method|format|restoration|source_origin|endpoint|result_type|stdio|diagnostic|stderr_tail|stdout_tail)$',re.I)
_HASH=re.compile(r'(?:sha256|sha1|md5|digest|cdhash)$',re.I)
_ARGS={'arguments','argv','command','flags','owned_paths','paths','frames','causes','errors','checks','events','reports','objects','windows','originals','targets','files','observations','results'}
_ARG_LITERALS={'driver','doctor','status','backup','features','feature-c-restore','connection-check','capture-inspect','capture-export','capture-adopt','portable-import','portable-verify','diagnostics-export','selected-freeze','selected-plan','selected-install','selected','fl23','custom1-m9','all-current','enabled','disabled','ioreg','diskutil','info','IOService','IOUSBHostDevice'}
_SKIP_DIRS={'snapshot','settings','settings-before','settings-after','packets','photos','originals','__pycache__','.git'}
_LOG_NAMES={'authorization.stdout.log','authorization.stderr.log','bootstrap.stdout.log','bootstrap.stderr.log','server.stderr.log','build.log','stdout.log','stderr.log'}
_TEXT_DIAGNOSTIC=re.compile(r'^磁盘空间提示：|error|exception|traceback|warning|denied|policy|dlopen|library not loaded|permission|not found|no such|invalid|failed|abort|codesign|libusb|iousb|authenticat|^\s*File\s+"|^\s*\^',re.I)


def _json(value):
    return (json.dumps(value,ensure_ascii=False,sort_keys=True,allow_nan=False)+'\n').encode()


def _plain_path(value):
    path=Path(value).absolute()
    if '..' in path.parts or any(p.is_symlink() for p in (path,*path.parents)):
        raise ValueError('Redirected diagnostics path refused')
    return path


def _open_directory(path):
    """Resolve every ancestor through descriptors, never follow a symlink."""
    path=_plain_path(path);fd=os.open('/',_DIR_FLAGS)
    try:
        for part in path.parts[1:]:
            child=os.open(part,_DIR_FLAGS,dir_fd=fd);os.close(fd);fd=child
        return fd
    except BaseException:os.close(fd);raise


class _Projection:
    def __init__(self):
        self.redactions=0;self.nodes=0;self.aliases={}
    def alias(self,value):
        encoded=_json(value)
        if encoded not in self.aliases:self.aliases[encoded]='identity-%04d'%(len(self.aliases)+1)
        return self.aliases[encoded]
    def summary(self,value,reason):
        self.redactions+=1
        raw=_json(value)
        return dict(omitted=reason,encoded_bytes=len(raw),sha256=sha256(raw).hexdigest())
    def text(self,value):
        value=value.replace(str(Path.home()),'$HOME')
        value=re.sub(r'/Users/[^/\s"\']+',r'/Users/[user]',value)
        value=re.sub(r'(?i)(password|passwd|secret|token|credential|cookie|nonce|(?:usb_)?serial(?:_number|_sha256)?|body_id|private_key)\s*[=:]\s*["\']?[^\s,;"\']+',r'\1=[redacted]',value)
        value=re.sub(r'(?i)\b(password|passwd|secret|credential|cookie|private_key)\b(?![=])[^\n]*',r'\1 [credential text omitted]',value)
        value=re.sub(r'(?i)\b(data|payload|packet|before|after|original|value|values|raw)\s*[=:]\s*(?:["\'][^"\']*["\']|\[[^\n]*\]|[^\s,;]+)',r'\1=[data omitted]',value)
        value=re.sub(r"\bb(['\"]).*?\1",'[bytes omitted]',value)
        value=re.sub(r'(?:\\x[0-9a-fA-F]{2}){2,}','[bytes omitted]',value)
        value=re.sub(r'\b[0-9a-fA-F]{8,}\b','[hex omitted]',value)
        return re.sub(r'(?<![\w/])[A-Za-z0-9+/]{40,}={0,2}(?![\w/])','[encoded data omitted]',value)
    def project(self,value,key='',depth=0):
        if depth==0:self.nodes=0
        self.nodes+=1
        if depth>MAX_DEPTH or self.nodes>MAX_NODES:return self.summary(value,'structure_bound')
        if _SECRET.search(key):self.redactions+=1;return dict(redacted='credential')
        if _IDENTITY.search(key):self.redactions+=1;return dict(redacted='identity',alias=self.alias(value))
        if (_PAYLOAD.search(key) or key=='bytes') and not isinstance(value,(int,float,bool)):
            return self.summary(value,'device_bytes_or_unclassified_value')
        if isinstance(value,dict):
            result={}
            for k,v in value.items():
                safe=str(k)
                if len(safe)>100 or re.fullmatch(r'[0-9a-fA-F]{32,}',safe):safe='opaque-key-'+sha256(safe.encode()).hexdigest()[:12]
                result[safe]=self.project(v,safe,depth+1)
            return result
        if isinstance(value,list):
            if not value:return []
            if all(isinstance(v,(int,float)) and not isinstance(v,bool) for v in value):
                return self.summary(value,'numeric_array_may_encode_device_bytes')
            if key in ('argv','arguments','command'):
                out=[];redact_next=False
                for v in value:
                    if not isinstance(v,str):out.append(self.project(v,'',depth+1));continue
                    if redact_next:out.append('[redacted]');self.redactions+=1;redact_next=False;continue
                    redact_next=bool(_SECRET.search(v) and v.startswith('-'))
                    out.append(self.text(v) if v.startswith(('-','/')) or v in _ARG_LITERALS else self.summary(v,'unclassified_argument'))
                return out
            return [self.project(v,key if isinstance(v,str) else '',depth+1) for v in value]
        if value is None or isinstance(value,bool):return value
        if isinstance(value,(int,float)):
            if isinstance(value,float) and not math.isfinite(value):return self.summary(str(value),'nonfinite_number')
            if _NUMERIC.search(key) or key in _NATIVE_NUMERIC or key in {'line','lineno','line_number','total','minimum','maximum','capacity','free','total_size','source_status','mode','ret','result','version','build','current','limit','requested','actual_count'}:return value
            return self.summary(value,'unclassified_numeric_value')
        if isinstance(value,str):
            if _HASH.search(key) and re.fullmatch(r'[0-9a-fA-F]{16,128}',value):return value
            if key.endswith(('stdout','stderr','stdout_tail','stderr_tail','traceback')):
                try:return self.project(json.loads(value),'',depth+1)
                except (ValueError,RecursionError):
                    return [dict(message=self.text(line)) if _TEXT_DIAGNOSTIC.search(line) else self.summary(line,'unstructured_text') for line in value.splitlines()]
            if _TEXT.search(key) or key in _ARGS:return self.text(value)
            return self.summary(value,'unclassified_string')
        return self.summary(str(type(value).__name__),'unsupported_value')


def _classify(scope,relative):
    path=Path(relative);name=path.name
    if name.endswith('.jsonl'):return 'jsonl'
    if name in _LOG_NAMES or name.endswith(('.stdout.log','.stderr.log')):return 'text'
    if name.endswith('.json') and scope!='logs':return 'json'
    return None


def _snapshot(parent,name,expected):
    fd=os.open(name,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW,dir_fd=parent)
    opened=os.fstat(fd)
    if (opened.st_dev,opened.st_ino)!=(expected.st_dev,expected.st_ino) or not stat.S_ISREG(opened.st_mode) or opened.st_uid!=os.geteuid() or opened.st_nlink!=1:
        os.close(fd);raise ValueError('Diagnostic input is not an owned, single-link regular file')
    return fd,opened


def _collect_file(archive,parent,name,info,scope,relative,manifest,projection):
    record=dict(source=scope+'/'+relative,source_bytes=info.st_size,processing='inventory_only')
    manifest['files'].append(record)
    mode=_classify(scope,relative)
    if mode is None:record['omitted']='not_an_allowlisted_report_or_log';return
    before_redactions=projection.redactions
    try:
        fd,opened=_snapshot(parent,name,info)
        record['source_bytes']=opened.st_size
        source_hash=sha256();remaining=opened.st_size
        def chunks(stream):
            nonlocal remaining
            while remaining:
                raw=stream.read(min(1024*1024,remaining))
                if not raw:raise ValueError('Diagnostic file shrank during export')
                remaining-=len(raw);source_hash.update(raw);yield raw
        member='diagnostics/'+scope+'/'+relative+'.safe.'+('json' if mode=='json' else 'jsonl')
        record['archive_path']=member
        with os.fdopen(fd,'rb') as stream:
            if mode=='json':
                if opened.st_size>MAX_JSON:
                    for _ in chunks(stream):pass
                    result=dict(omitted='structured_report_exceeds_16MiB',source_bytes=opened.st_size)
                    record['omitted']='structured_report_exceeds_16MiB'
                else:
                    raw=b''.join(chunks(stream))
                    try:result=projection.project(json.loads(raw))
                    except (ValueError,UnicodeError,RecursionError):result=dict(omitted='invalid_structured_report');record['omitted']='invalid_structured_report'
                archive.writestr(member,_json(result))
            else:
                with archive.open(member,'w',force_zip64=True) as target:
                    pending=bytearray();line=0;oversize_hash=None;oversize_size=0
                    def emit(raw,complete=True):
                        nonlocal line
                        line+=1
                        try:
                            value=json.loads(raw)
                            safe=projection.project(value)
                            if isinstance(value,dict) and value.get('event')=='log-window-rotated':manifest['history']['legacy_rotation_markers_detected']+=1
                        except (ValueError,UnicodeError,RecursionError):
                            text=raw.decode('utf-8',errors='replace')
                            safe=(dict(line=line,message=projection.text(text.rstrip()),complete_line=complete) if mode=='text' and _TEXT_DIAGNOSTIC.search(text)
                                  else dict(line=line,omitted='unstructured_text',bytes=len(raw),sha256=sha256(raw).hexdigest(),complete_line=complete))
                        target.write(_json(safe))
                    for chunk in chunks(stream):
                        for piece in chunk.splitlines(keepends=True):
                            if oversize_hash is not None:
                                oversize_hash.update(piece);oversize_size+=len(piece)
                            elif len(pending)+len(piece)>MAX_LINE:
                                oversize_hash=sha256(pending);oversize_hash.update(piece);oversize_size=len(pending)+len(piece);pending.clear()
                            else:pending.extend(piece)
                            if piece.endswith(b'\n'):
                                if oversize_hash is not None:
                                    line+=1;target.write(_json(dict(line=line,omitted='line_exceeds_1MiB',bytes=oversize_size,sha256=oversize_hash.hexdigest())));oversize_hash=None;oversize_size=0
                                else:emit(bytes(pending));pending.clear()
                    if oversize_hash is not None:
                        line+=1;target.write(_json(dict(line=line,omitted='line_exceeds_1MiB',bytes=oversize_size,sha256=oversize_hash.hexdigest(),complete_line=False)))
                    elif pending:emit(bytes(pending),False)
                    record['exported_lines']=line
            after=os.fstat(stream.fileno())
        record.update(source_sha256=source_hash.hexdigest(),processing='structured_metadata' if mode=='json' else 'sanitized_lines',redactions=projection.redactions-before_redactions)
        if after.st_size!=opened.st_size or after.st_mtime_ns!=opened.st_mtime_ns:
            record['source_changed_during_export']=True
            record['snapshot']='initial_size_prefix; later appends not included'
    except (OSError,ValueError,RecursionError) as error:
        record['omitted']='unreadable_or_changed_input';record['error_type']=type(error).__name__


def _walk(archive,folder,scope,manifest,projection):
    try:
        path=_plain_path(folder)
        fd=_open_directory(path)
    except (OSError,ValueError) as error:
        manifest['roots'].append(dict(root=scope,status='unavailable',error_type=type(error).__name__));return
    manifest['roots'].append(dict(root=scope,status='enumerated'))
    def visit(parent,prefix,depth):
        try:names=sorted(os.listdir(parent))
        except OSError as error:
            manifest['files'].append(dict(source=scope+'/'+prefix,omitted='directory_unreadable',error_type=type(error).__name__));return
        for name in names:
            relative=prefix+'/'+name if prefix else name
            try:
                info=os.stat(name,dir_fd=parent,follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    if name in _SKIP_DIRS or depth>=MAX_DEPTH:
                        manifest['files'].append(dict(source=scope+'/'+relative,omitted='raw_material_directory' if name in _SKIP_DIRS else 'directory_depth_bound'));continue
                    child=os.open(name,_DIR_FLAGS,dir_fd=parent)
                    try:visit(child,relative,depth+1)
                    finally:os.close(child)
                elif stat.S_ISREG(info.st_mode):_collect_file(archive,parent,name,info,scope,relative,manifest,projection)
                else:manifest['files'].append(dict(source=scope+'/'+relative,omitted='symlink_or_special_file'))
            except OSError as error:manifest['files'].append(dict(source=scope+'/'+relative,omitted='entry_unreadable',error_type=type(error).__name__))
    try:visit(fd,'',0)
    finally:os.close(fd)


def export_archive(output,*,logs_root=None,support_root=None,app_metadata=None):
    """Create a new 0600 ZIP. Existing targets are refused, never overwritten.

    Missing/unreadable/unknown entries remain explicit in manifest.json. Files
    added after enumeration and legacy deleted/truncated history are not claimed.
    """
    if os.geteuid()==0:raise ValueError('Diagnostics export must run as the current desktop user, without sudo')
    logs=Path(logs_root) if logs_root is not None else Path.home()/'Library/Logs/A7M4 Toolbox'
    support=Path(support_root) if support_root is not None else Path.home()/'Library/Application Support/A7 IV Toolbox'
    output=_plain_path(output)
    if output.exists() or not output.parent.is_dir():raise ValueError('Choose a new diagnostics ZIP filename in an existing directory')
    for source in (logs,support):
        if output.is_relative_to(Path(source).absolute()):raise ValueError('Diagnostics output must be outside the source trees')
    projection=_Projection()
    manifest=dict(schema=SCHEMA,created=datetime.now(timezone.utc).isoformat(),camera_io=False,network_io=False,administrator_authorization=False,
        source_policy='Only application logs, runs and authorization-sessions; no original file is copied verbatim',
        history=dict(scope='all currently retained sessions and reports',installation_history_complete=False,
            legacy_deleted_or_truncated_content_recoverable=False,legacy_pruning_or_truncation_possible=True,
            legacy_rotation_markers_detected=0,note='Older versions deleted sessions and truncated log windows. Missing old content cannot be recovered or counted by this export.'),
        roots=[],files=[],app_metadata=projection.project(app_metadata or {}),
        exclusions=['firmware','photos','audio','backup archives','settings originals and values','raw packets and native reports','credentials','symlinks and special files'])
    parent=_open_directory(output.parent);temporary=None
    try:
        temporary='.'+output.name+'.'+secrets.token_hex(8)+'.partial'
        fd=os.open(temporary,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
        with os.fdopen(fd,'w+b') as stream:
            with zipfile.ZipFile(stream,'w',compression=zipfile.ZIP_DEFLATED,allowZip64=True) as archive:
                _walk(archive,logs,'logs',manifest,projection)
                _walk(archive,support/'runs','runs',manifest,projection)
                _walk(archive,support/'authorization-sessions','authorization-sessions',manifest,projection)
                manifest['summary']=dict(enumerated_entries=len(manifest['files']),exported_reports=sum('archive_path' in r for r in manifest['files']),
                    redactions=projection.redactions,omitted_entries=sum('omitted' in r for r in manifest['files']),
                    changed_sources=sum(bool(r.get('source_changed_during_export')) for r in manifest['files']))
                archive.writestr('manifest.json',_json(manifest))
            stream.flush();os.fsync(stream.fileno())
            archive_size=stream.tell();stream.seek(0);archive_hash=sha256()
            while raw:=stream.read(1024*1024):archive_hash.update(raw)
        # link is an atomic no-replace publication in the same pinned directory.
        os.link(temporary,output.name,src_dir_fd=parent,dst_dir_fd=parent,follow_symlinks=False)
        os.unlink(temporary,dir_fd=parent);temporary=None;os.fsync(parent)
        return dict(schema=SCHEMA,status='DIAGNOSTICS_EXPORTED',complete=True,verified=True,camera_io=False,network_io=False,
            output=str(output),archive=str(output),files=manifest['summary']['exported_reports'],summary=manifest['summary'],
            archive_size=archive_size,archive_sha256=archive_hash.hexdigest(),
            installation_history_complete=False,raw_device_data_included=False)
    finally:
        if temporary is not None:
            try:os.unlink(temporary,dir_fd=parent)
            except OSError:pass
        os.close(parent)
