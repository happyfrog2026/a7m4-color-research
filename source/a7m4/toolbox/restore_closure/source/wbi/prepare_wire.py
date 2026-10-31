"""Fixed R027 read-only WBI header preparation. No apply request is implemented."""
import struct

REQUEST='/tmp/jiritsu/a7m4.wbi-invalidate.request'
RESULT='/tmp/jiritsu/a7m4.wbi-invalidate.result'
PENDING=RESULT+'.pending'
MAX_REPORT=65536
REQUEST_BYTES=544
HEADER=struct.Struct('<8sII16sIIqq4IQ6I3Q')
TLV=struct.Struct('<IIq')
STAT=struct.Struct('<QQIIIIQq')
FS=struct.Struct('<qqQQQQQqqq')
CAPS=(64,128,16,64,48,64,64,16,8192,8192,16,64,8192,16,16,80,48)
PATHS=('/version.txt','/proc/sys/kernel/random/boot_id','/sys/power/image_mode',
       '/sys/power/image_dev','/dev/cnflasha5:before-stat',
       '/sys/dev/block/252:133/dev','/sys/dev/block/252:133/size',
       '/sys/dev/block/252:133/ro','/dev/cnflasha5:read1',
       '/dev/cnflasha5:read2','/sys/power/image_mode:after',
       '/sys/power/image_dev:after','reserved:post-header',
       'reserved:drop-io','reserved:mode-io','/tmp/jiritsu:statfs',
       '/dev/cnflasha5:final-stat')
READ_VIEW='ordinary block-device cache view; not independent physical-flash freshness'


def _require(ok,message):
    if not ok:raise ValueError(message)


def request(nonce,mode=0,preimage=None):
    _require(type(nonce) is bytes and len(nonce)==16 and any(nonce),'Expected nonzero16-byte nonce')
    _require(type(mode) is int and mode==0 and preimage is None,'Only read-only prepare mode0 is implemented')
    return struct.pack('<8s16sII',b'M4WIRQ01',nonce,0,0)+bytes(512)


def parse_report(raw,nonce,mode=0):
    request(nonce,mode)
    _require(type(raw) is bytes and HEADER.size<=len(raw)<=MAX_REPORT,'Report size')
    h=HEADER.unpack_from(raw)
    _require(h[:3]==(b'M4WIR001',1,len(raw)) and h[3]==nonce,'Report identity')
    _require(h[4]==0 and 1<=h[5]<=6 and h[14]==len(CAPS) and h[19:]==(0,0,0),'Prepare header')
    status,unlink=h[6:8];ids=h[8:12];pid=h[12];flags,count,closes,bad,drop,mode_write=h[13:19]
    _require(-4095<=status<=0 and -4095<=unlink<=0 and flags&~255==0,'Report statuses')
    _require(0<=closes<=14 and 0<=bad<=closes and drop==mode_write==0,'Prepare cannot mutate WBI')
    sections=[];at=HEADER.size
    for index,cap in enumerate(CAPS,1):
        _require(at+TLV.size<=len(raw),'Truncated section')
        slot,size,code=TLV.unpack_from(raw,at);at+=TLV.size
        _require(slot==index and size<=cap and at+size<=len(raw) and -4095<=code<=0,'Section framing')
        data=raw[at:at+size];at+=size
        _require(code!=-125 or not size,'Unvisited section has data')
        sections.append(dict(id=slot,slot=slot,path=PATHS[index-1],status=code,data=data))
    _require(at==len(raw),'Trailing report bytes')
    for i in (12,13,14):
        _require(sections[i]['status']==-125 and not sections[i]['data'],'Reserved mutation section')
    root=ids==(0,0,0,0)
    _require(bool(flags&8)==root and (not root or pid>0),'Root evidence')
    _require(bool(flags&32)==(unlink==0),'Unlink evidence')
    _require(bool(flags&2)==(bad==0),'Input close evidence')
    if flags&16:_require(sections[0]['status']==0 and sections[0]['data']==b'30181_18.2026041801','Version evidence')
    if flags&64:
        _require(sections[15]['status']==0 and len(sections[15]['data'])==80,'Space evidence')
        fs=FS.unpack(sections[15]['data']);unit=fs[8]
        _require(fs[0]==0x4d44 and fs[1]>0 and unit>0,'VFAT evidence')
        reserve=((MAX_REPORT+unit-1)//unit+2)*unit
        _require(fs[4]*unit<=2**64-1 and reserve<=2**64-1 and fs[4]*unit-reserve>=8388608,'VFAT margin')
    complete=bool(flags&128)
    if complete:
        _require(status==0 and flags==255 and h[5]==6 and closes==14 and bad==0,'Complete prepare header')
        for i in (*range(12),15,16):_require(sections[i]['status']==0,'Complete section status')
        _require(len(sections[1]['data']) in (36,37),'Boot ID size')
        _require(sections[2]['data']==sections[10]['data']==b'2\n' and sections[3]['data']==sections[11]['data']==b'*wbi4\n','Mode/device changed')
        _require(sections[5]['data']==b'252:133\n' and sections[6]['data']==b'614400\n' and sections[7]['data'] in (b'0\n',b'1\n'),'Block sysfs evidence')
        _require(len(sections[4]['data'])==48 and sections[4]['data']==sections[16]['data'],'Block identity changed')
        st=STAT.unpack(sections[4]['data']);rdev=st[6]
        major=((rdev>>8)&0xfff)|((rdev>>32)&0xfffff000);minor=(rdev&255)|((rdev>>12)&0xffffff00)
        _require(st[2]&0o170000==0o060000 and st[1]>0 and st[3]>0 and (major,minor)==(252,133),'Block identity')
        _require(len(sections[8]['data'])==8192 and sections[8]['data']==sections[9]['data'],'Header double-read mismatch')
    cleanup=bool((flags&123)==123 and root and pid>0 and unlink==0 and bad==0 and closes>=2)
    return dict(complete=complete,cleanup_safe=cleanup,root=root,root_verified=root,
                unlink_status=unlink,safe_input_closes=bad==0,status=status,mode=0,
                stage=h[5],flags=flags,input_close_count=closes,input_close_errors=bad,
                sections=sections,header_reads=[sections[i]['data'] for i in (8,9)],
                post_header=b'',before_mode=sections[2]['data'],after_mode=sections[10]['data'],
                before_dev=sections[3]['data'],after_dev=sections[11]['data'],
                drop_write=None,drop_close=None,mode_write=None,mode_close=None,
                mutated=False,write_implementation_present=False,read_view=READ_VIEW,
                header_magic=sections[8]['data'][:4])
