"""Finite workspace-probe contract and cluster-rounded admission, local only."""
from hashlib import sha256
from pathlib import Path
import struct
import uuid

REQUEST_PATH='/tmp/jiritsu/m4.toolbox-space.request'
REPORT_PATH='/tmp/jiritsu/m4.toolbox-space.result'
SOURCE=Path(__file__).with_name('data')/'workspace_probe.c'
REQUEST=struct.Struct('<8sII16s32s')
REPORT=struct.Struct('<8sII16s8q40s')
RESERVE=8*1024*1024


def probe_request(nonce):
    if type(nonce) is not bytes or len(nonce)!=16 or nonce==bytes(16):
        raise ValueError('Fresh nonzero 16-byte probe nonce required')
    return REQUEST.pack(b'M4SPAQ02',2,0,nonce,sha256(SOURCE.read_bytes()).digest())


def parse_probe(raw,nonce):
    if type(raw) is not bytes or len(raw)!=REPORT.size:
        raise ValueError('Missing complete workspace probe; STOP_UNKNOWN')
    magic,version,phase,bound,status,euid,pid,unit,available,fsid,close,cleanup,boot=REPORT.unpack(raw)
    if (magic!=b'M4SPAR02' or version!=2 or phase!=9 or bound!=nonce or status
            or euid!=0 or pid<=0 or close or cleanup or not 0<unit<=1048576
            or available<0 or available*unit>2**63-1):
        raise ValueError('Failed, stale or foreign workspace probe; STOP_UNKNOWN')
    try:
        boot_id=boot[:36].decode('ascii')
        if boot[36:]!=bytes(4) or str(uuid.UUID(boot_id))!=boot_id or uuid.UUID(boot_id).int==0:raise ValueError()
    except (UnicodeError,ValueError):raise ValueError('Native kernel boot identity is invalid; STOP_UNKNOWN') from None
    return dict(schema='a7m4-toolbox-workspace/2',allocation_unit=unit,boot_id=boot_id,
                available_bytes=available*unit,filesystem_id=fsid,process_id=pid,
                fresh_measurement=True,bootstrap_probe_only=True)


def admit_uploads(measurement,sizes,*,report_sizes=(),owned_existing_sizes=(),report_limit=65535,reserve_extra_bytes=0):
    unit=measurement.get('allocation_unit')
    available=measurement.get('available_bytes')
    if (measurement.get('fresh_measurement') is not True or type(unit) is not int
            or not 0<unit<=1048576 or type(available) is not int or available<0):
        raise ValueError('Fresh actual workspace measurement is required')
    sizes=list(sizes);reports=list(report_sizes);existing=list(owned_existing_sizes)
    if not sizes or any(type(n) is not int or not 0<n<65536 for n in sizes):
        raise ValueError('Every upload must be strictly below 65536 bytes')
    if type(report_limit) is not int or report_limit not in (65535,131072):
        raise ValueError('Unreviewed read-only report limit')
    if (any(type(n) is not int or not 0<=n<=report_limit for n in reports)
            or any(type(n) is not int or not 0<=n<65536 for n in existing)):
        raise ValueError('Invalid bounded owned file/report inventory')
    if type(reserve_extra_bytes) is not int or not 0<=reserve_extra_bytes<=4*1024*1024:
        raise ValueError('Invalid native conservative reserve')
    # Existing owned allocations are counted again conservatively; the fresh
    # available value already excludes them. Never treat an unknown leftover
    # as free space or delete it to make the budget fit.
    staged=sum(((n+unit-1)//unit)*unit for n in sizes+reports+existing)+reserve_extra_bytes
    if available-staged<RESERVE:
        raise ValueError('Workspace reserve would fall below 8 MiB')
    return dict(verified=True,allocation_unit=unit,available_bytes=available,
                reserved_staging_bytes=staged,remaining_minimum_bytes=available-staged,
                minimum_required_bytes=RESERVE)
