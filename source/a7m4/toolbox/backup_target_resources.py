"""Backup-authorized resource C projection and independently admitted EOF cleanup."""
import os
from hashlib import sha256
from pathlib import Path
from .backup_target_execution import authenticated_plan as validate_plan, authenticated_payload
from .capture_inputs import read_private
from . import looks_resource_scope as scope, looks_resource_restore as tail
from . import original_restore as byte_diff
from .native_actions import NativeActions, _write, _json
from .build_scratch import discard_caches


def original(execution, row):
    authority=execution;execution=validate_plan(authority)
    component=next(r for r in execution['scope_plan']['resources']['files'] if r['path']==row['target_path'])
    target=authenticated_payload(authority,row,target=True)
    windows=[]
    for lo,hi in component['owned_ranges']:
        hi=min(hi,len(target))
        if lo<hi:windows.append(dict(offset=lo,hex=target[lo:hi].hex()))
    source=authenticated_payload(authority,row,target=False)
    return dict(eof=len(target),windows=windows,
        appends=[] if len(source)<=len(target) else [dict(offset=len(target),hex=source[len(target):].hex())],
        authority='selected-original-backup-scope',scope_plan_id=execution['scope_plan_id'])


def live_dependencies(authority,row,raw):
    plan=validate_plan(authority)
    component=next(r for r in plan['scope_plan']['resources']['files'] if r['path']==row['target_path'])
    desired=authenticated_payload(authority,row,target=True)
    projected=bytearray(raw[:len(desired)])
    if len(projected)<len(desired):projected.extend(desired[len(projected):])
    for lo,hi in component['owned_ranges']:
        hi=min(hi,len(desired))
        if lo<hi:projected[lo:hi]=desired[lo:hi]
    from .backup_target_scope import check_resource_D
    check_resource_D(component,raw,bytes(projected))
    victim=component.get('layout',{}).get('victim')
    return dict(offset=0,size=0,donor_id=0) if victim is None else dict(offset=victim['start'],size=20,donor_id=victim['id'])


def prefix(execution,row,current):
    value=original(execution,row)
    victim=live_dependencies(execution,row,current)
    target=bytearray(current)
    desired=read_private(row['original_path'],16*1024*1024)
    if len(current)<len(desired):target.extend(desired[len(current):])
    for window in value['windows']:
        raw=bytes.fromhex(window['hex']);at=window['offset'];target[at:at+len(raw)]=raw
    from .backup_target_scope import _windows
    windows=_windows(current,bytes(target),[(w["offset"],w["offset"]+len(bytes.fromhex(w["hex"]))) for w in value["windows"]])
    return scope.scoped_file(row['target_path'],current,bytes(target),windows,direction='restore-prefix',
        target_C=[dict(offset=w['offset'],hex=w['hex']) for w in value['windows']],victim=victim)


def restore_prefix(execution,row,channel,output,*,compiler,pid):
    current=channel.file(row['target_path']);plan=prefix(execution,row,current)
    if plan['native_plan'] is None:return dict(complete=True,C_D_verified=True,no_op=True,E_F_gate_execution=False)
    output=Path(output);output.mkdir(mode=0o700)
    _write(output/'ticket.json',_json(plan))
    built=scope.build(plan,output/'build',compiler=compiler);discard_caches(output/'build')
    protocol=scope.Protocol(plan);action=NativeActions(channel,output/'native')
    def accept(raw):
        result=protocol.accept(raw)
        if result['pid']!=pid:raise ValueError('Resource native process identity changed')
        return result
    binary=read_private(built['worker']['path'],65535)
    for mode in (0,1,3):
        action.phase(binary,scope.REQUEST_PATH,protocol.request(mode,os.urandom(16)),scope.REPORT_PATH,
            accept,report_bytes=scope.REPORT_BYTES)
        if mode in (0,3):
            observed=channel.file(row['target_path']);live_dependencies(execution,row,observed);proof=protocol.confirm_readback(observed)
            if mode==3:_write(output/'after.bin',observed)
    action.clean_packets()
    return dict(complete=True,C_D_verified=True,E_F_gate_execution=False,readback=proof,readback_path=str(output/'after.bin'),readback_sha256=sha256(observed).hexdigest(),readback_size=len(observed))


def restore_tail(execution,row,channel,output,*,compiler,runtime_factory):
    current=channel.file(row['target_path']);owned=original(execution,row)
    if len(current)==owned['eof']:return dict(complete=True,no_op=True,C_D_verified=True,E_F_gate_execution=False)
    plan=tail.plan_tail(row['target_path'],current,owned,runtime=runtime_factory())
    return _tail(plan,channel,Path(output),compiler=compiler,runtime_factory=runtime_factory)


def _tail(plan,channel,output,*,compiler,runtime_factory,alternative=False):
    output.mkdir(mode=0o700)
    built=tail.build(plan,output/'build',compiler=compiler);discard_caches(output/'build')
    _write(output/'ticket.json',_json(plan))
    protocol=tail.TailProtocol(plan);action=NativeActions(channel,output/'native')
    paths=tail.packets(plan)
    kwargs={k:paths[k] for k in ('report_bytes','native_report_capacity','native_overhead_units')}
    binary=read_private(built['worker']['path'],65535)
    report=action.phase(binary,paths['request_path'],protocol.request(0,os.urandom(16)),paths['report_path'],protocol.accept,**kwargs)
    if report.get('cleanup_safe') is True and report.get('mapping_state_unknown') is False:
        tail.acknowledge_clean_inspection(action,protocol)
    if report.get('complete') is not True:
        boundary=tail.boundary_from_refusal(report)
        if boundary is not None and not alternative:
            next_plan=tail.plan_original_eof_after_clean_refusal(protocol,action,channel.file(plan['target_path']),runtime=runtime_factory())
            return _tail(next_plan,channel,output/'alternate-reviewed-endpoint',compiler=compiler,runtime_factory=runtime_factory,alternative=True)
        if boundary is not None:raise boundary
        raise ValueError('Resource EOF inspect did not prove current C/D and reviewed mapping')
    protocol.confirm_source(channel.file(plan['target_path']))
    report=action.phase(binary,paths['request_path'],protocol.request(1,os.urandom(16)),paths['report_path'],protocol.accept,**kwargs)
    if report.get('complete') is not True or report.get('mapping_state_unknown') is not False:
        raise ValueError('Resource EOF outcome unknown; no retry')
    after=channel.file(plan['target_path']);_write(output/'after.bin',after)
    proof=protocol.confirm_readback(after);result=protocol.finish();action.clean_packets()
    return dict(result,complete=True,C_D_verified=True,E_F_gate_execution=False,readback=proof,readback_path=str(output/'after.bin'),readback_sha256=sha256(after).hexdigest(),readback_size=len(after))
