"""V2 fixed WBI2-or-exact-zero512 vendor invalidation wire. Import/build is offline; execution needs approval."""
import re
import struct

REQUEST='/tmp/jiritsu/a7m4.wbi-drop-v2.request'
RESULT='/tmp/jiritsu/a7m4.wbi-drop-v2.result'
PENDING=RESULT+'.pending'
MAX_REPORT=65536
REQUEST_BYTES=576
HEADER=struct.Struct('<8sII16sIIqq4IQ6I3Q')
TLV=struct.Struct('<IIq')
STAT=struct.Struct('<QQIIIIQq')
FS=struct.Struct('<qqQQQQQqqq')
IO=struct.Struct('<qqqq')
CAPS=(64,128,16,64,48,64,64,16,8192,8192,16,64,32,32,32768,80,48,32,48,576)
PATHS=('/version.txt','/proc/sys/kernel/random/boot_id','/sys/power/image_mode',
       '/sys/power/image_dev','/dev/cnflasha5:before-stat',
       '/sys/dev/block/252:133/dev','/sys/dev/block/252:133/size',
       '/sys/dev/block/252:133/ro','/dev/cnflasha5:before-read',
       '/dev/cnflasha5:after-read','/sys/power/image_mode:after',
       '/sys/power/image_dev:after','/sys/power/image_drop:io',
       '/sys/power/image_mode:io','/dev/kmsg:fresh-records',
       '/tmp/jiritsu:statfs','/dev/cnflasha5:final-stat',
       '/dev/kmsg:io','/dev/kmsg:stat','request-copy')
READ_VIEW='ordinary block-device cache view; not independent physical-flash freshness'

def _require(ok,message):
    if not ok:raise ValueError(message)

def request(nonce,boot_id,preimage):
    _require(type(nonce) is bytes and len(nonce)==16 and any(nonce),'Expected nonzero16-byte nonce')
    _require(type(boot_id) is bytes and re.fullmatch(rb'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\n',boot_id) is not None,'Expected canonical37-byte boot ID')
    _require(type(preimage) is bytes and len(preimage)==512 and (preimage[:4]==b'WBI2' or preimage==bytes(512)),'Expected exact512-byte WBI2 or all-zero preimage')
    return struct.pack('<8s16s37s3x512s',b'M4WDRQ02',nonce,boot_id,preimage)

def _row(section,log=False):
    if not section['data']:
        _require(section['status']==-125,'Missing visited IO result')
        return None
    _require(len(section['data'])==32,'IO result size')
    row=IO.unpack(section['data'])
    _require(all(-4095<=x<=1 for i,x in enumerate(row) if not(log and i==1))
             and (not log or -4095<=row[1]<2**63),'IO result range')
    return row

def parse_report(raw,nonce,boot_id,preimage):
    expected=request(nonce,boot_id,preimage)
    _require(type(raw) is bytes and HEADER.size<=len(raw)<=MAX_REPORT,'Report size')
    h=HEADER.unpack_from(raw)
    _require(h[:3]==(b'M4WDR002',2,len(raw)) and h[3]==nonce,'Report identity')
    _require(h[4]==1 and 1<=h[5]<=9 and h[14]==len(CAPS) and h[19:]==(0,0,0),'Drop header')
    status,unlink=h[6:8];ids=h[8:12];pid=h[12];flags,count,closes,bad,drop_attempted,mode_attempted=h[13:19]
    _require(-4095<=status<=0 and -4095<=unlink<=0 and flags&~1023==0,'Report status/flags')
    _require(0<=closes<=17 and 0<=bad<=closes and drop_attempted in (0,1) and mode_attempted in (0,1),'Close/attempt bounds')
    sections=[];at=HEADER.size
    for index,cap in enumerate(CAPS,1):
        _require(at+TLV.size<=len(raw),'Truncated section')
        slot,size,code=TLV.unpack_from(raw,at);at+=TLV.size
        _require(slot==index and size<=cap and at+size<=len(raw) and -4095<=code<=0,'Section framing')
        data=raw[at:at+size];at+=size
        _require(code!=-125 or not size,'Unvisited section has data')
        sections.append(dict(id=slot,slot=slot,path=PATHS[index-1],status=code,data=data))
    _require(at==len(raw),'Trailing bytes')
    root=ids==(0,0,0,0)
    _require(bool(flags&8)==root and (not root or pid>0),'Root evidence')
    _require(bool(flags&32)==(unlink==0) and bool(flags&2)==(bad==0),'Unlink/close evidence')
    if flags&1:_require(sections[19]['status']==0 and sections[19]['data']==expected,'Request evidence')
    if flags&16:_require(sections[0]['status']==0 and sections[0]['data']==b'30181_18.2026041801','Version evidence')
    if flags&4:
        _require(sections[1]['status']==0 and sections[1]['data']==boot_id,'Boot binding')
        _require(sections[2]['data']==b'2\n' and sections[3]['data']==b'*wbi4\n','Initial mode/device')
        _require(sections[5]['data']==b'252:133\n' and sections[6]['data']==b'614400\n' and sections[7]['data'] in (b'0\n',b'1\n'),'Block sysfs evidence')
        _require(sections[8]['status']==0 and len(sections[8]['data'])==8192 and sections[8]['data'][:512]==preimage,'Cached preimage binding')
        _require(len(sections[4]['data'])==48,'Block stat')
        st=STAT.unpack(sections[4]['data']);rdev=st[6]
        major=((rdev>>8)&0xfff)|((rdev>>32)&0xfffff000);minor=(rdev&255)|((rdev>>12)&0xffffff00)
        _require(st[2]&0o170000==0o060000 and st[1]>0 and st[3]>0 and (major,minor)==(252,133),'Block identity')
    if flags&64:
        _require(sections[15]['status']==0 and len(sections[15]['data'])==80,'Space evidence')
        fs=FS.unpack(sections[15]['data']);unit=fs[8]
        _require(fs[0]==0x4d44 and fs[1]>0 and unit>0,'VFAT evidence')
        reserve=((MAX_REPORT+unit-1)//unit+2)*unit
        _require(fs[4]*unit<=2**64-1 and reserve<=2**64-1 and fs[4]*unit-reserve>=8388608,'VFAT margin')
    drop=_row(sections[12]);mode=_row(sections[13]);log=_row(sections[17],log=True)
    _require(not drop_attempted or drop is not None and drop[0]==drop[3]==0 and drop[1]!=-125,'Drop attempt evidence')
    _require(not mode_attempted or mode is not None and mode[0]==mode[3]==0 and mode[1]!=-125,'Mode attempt evidence')
    _require(not mode_attempted or drop_attempted and drop[1]==1,'Mode0 only follows accepted drop')
    if flags&256:_require(sections[14]['status']==0 and b'dropped wbi' in sections[14]['data'] and log is not None and log[1]>=0 and log[2]==0,'Fresh marker evidence')
    if flags&512:_require(sections[10]['status']==sections[11]['status']==0 and sections[10]['data']==b'0\n' and sections[11]['data']==b'*wbi4\n','Post mode/device evidence')
    complete=bool(flags&128)
    if complete:
        _require(status==0 and flags==1023 and h[5]==9 and closes==17 and bad==0,'Complete drop header')
        _require(drop_attempted==mode_attempted==1 and drop==(0,1,0,0) and mode==(0,1,0,0),'Complete write outcomes')
        _require(log is not None and log[0]==0 and log[1]>=0 and log[2]==log[3]==0,'Complete log outcomes')
        _require(all(s['status']==0 for s in sections),'Complete section statuses')
        _require(len(sections[9]['data'])==8192,'Post cached read size')
        _require(sections[4]['data']==sections[16]['data'],'Final block identity')
    cleanup=bool((flags&123)==123 and root and pid>0 and unlink==0 and bad==0 and closes>=2)
    return dict(complete=complete,cleanup_safe=cleanup,root=root,root_verified=root,
                unlink_status=unlink,safe_input_closes=bad==0,status=status,mode=1,stage=h[5],flags=flags,
                input_close_count=closes,input_close_errors=bad,sections=sections,
                attempted=bool(drop_attempted),drop_attempted=bool(drop_attempted),mode_attempted=bool(mode_attempted),
                mutation_possible=bool(drop_attempted),mutated=bool(drop_attempted),
                drop_write=None if drop is None else drop[1],drop_close=None if drop is None else drop[2],
                mode_write=None if mode is None else mode[1],mode_close=None if mode is None else mode[2],
                fresh_marker=bool(flags&256),before_mode=sections[2]['data'],after_mode=sections[10]['data'],
                before_dev=sections[3]['data'],after_dev=sections[11]['data'],
                pre_header=sections[8]['data'],post_header=sections[9]['data'],read_view=READ_VIEW,
                preimage_kind='ZERO512' if preimage==bytes(512) else 'WBI2',
                physical_persistence_verified=False,provider_close_observable=False,
                old_snapshot_restore_verified=False,write_implementation_present=True)
