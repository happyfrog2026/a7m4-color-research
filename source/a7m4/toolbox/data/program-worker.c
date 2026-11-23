#ifdef M4_FL23_R021_PROBE
#error R066 has no probe/create/delete mode
#endif
/* Fixed AP/CP program-window transaction (offline-built, not device accepted), adapted from QAQLeonard/a7c2-fl23-research
 * src/fl23/native/installer.c (782785641ca9f8b984940c7274b48706219e0da4).
 * Exact edited bytes only; fresh full source and full readback belong to host.
 * Only source-identical AP private-page COW; no semantic memory changes.
 * No raw-device, settings, power or snapshot writes.
 */
#ifdef M4_FL23_TARGET_ABI_CHECK
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <fcntl.h>
#include <sys/syscall.h>
#endif
typedef unsigned long u64;
typedef unsigned int u32;
typedef long i64;
typedef unsigned char u8;

#ifdef M4_FL23_DIRECT_TEST
extern i64 m4_program_test_syscall(i64,i64,i64,i64,i64,i64,i64);
static i64 sc(i64 n,i64 a,i64 b,i64 c,i64 d,i64 e,i64 f) {
    return m4_program_test_syscall(n,a,b,c,d,e,f);
}
#else
static i64 sc(i64 n,i64 a,i64 b,i64 c,i64 d,i64 e,i64 f) {
    register i64 x0 __asm__("x0")=a,x1 __asm__("x1")=b,x2 __asm__("x2")=c;
    register i64 x3 __asm__("x3")=d,x4 __asm__("x4")=e,x5 __asm__("x5")=f,x8 __asm__("x8")=n;
    __asm__ volatile("svc 0":"+r"(x0):"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5),"r"(x8):"memory","cc");
    return x0;
}
#endif

#ifndef PATCH_MANIFEST
#define PATCH_MANIFEST "patch_manifest.h"
#endif
/* Header owns struct Window, windows[], window_count, file_sizes[], plan_id[]. */
#include PATCH_MANIFEST

#define REQUEST "/tmp/jiritsu/m4.program.request"
#define RESULT "/tmp/jiritsu/m4.program.result"
#define DIRECT_O_NOFOLLOW 0x8000UL
#define DIRECT_O_CLOEXEC 0x80000UL
#define DIRECT_O_NONBLOCK 0x800UL
#define READ_FLAGS (DIRECT_O_NOFOLLOW|DIRECT_O_CLOEXEC|DIRECT_O_NONBLOCK)
#define RESULT_FLAGS (READ_FLAGS|1|64|128)
#ifdef M4_FL23_TARGET_ABI_CHECK
_Static_assert(DIRECT_O_NOFOLLOW==O_NOFOLLOW,"target Linux NOFOLLOW ABI");
_Static_assert(DIRECT_O_CLOEXEC==O_CLOEXEC,"target Linux CLOEXEC ABI");
_Static_assert(READ_FLAGS==(O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK),"target read flags ABI");
_Static_assert(RESULT_FLAGS==(O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK),"target result flags ABI");
_Static_assert(AT_SYMLINK_NOFOLLOW==0x100,"target path identity flags ABI");
_Static_assert(SYS_newfstatat==79,"target newfstatat syscall ABI");
_Static_assert(SYS_unlinkat==35,"target unlinkat syscall ABI");
#endif

struct Stat {
    u64 dev,ino;u32 mode,nlink,uid,gid;u64 rdev,pad1;i64 size;
    u32 blksize,pad2;u64 blocks,rest[7];
};
struct Request {u8 magic[8];u32 mode,reserved;u8 nonce[16],plan_id[32];u32 attributes[8];u64 file_ids[4];};
struct Report {
    u8 magic[8];u32 version,mode,phase,writes;
    i64 status,rollback,remount,readonly,cleanup,euid,pid;
    u64 ap_dev,ap_inode,ap_size,cp_dev,cp_inode,cp_size;
    u8 plan_id[32],nonce[16];i64 cp_mount_status;
    u64 jiritsu_type,jiritsu_unit,jiritsu_available,cp_type,cp_unit,cp_available;
    u32 ap_mode,ap_nlink,ap_uid,ap_gid,cp_mode,cp_nlink,cp_uid,cp_gid;
};
_Static_assert(sizeof(struct Stat)==128,"Linux AArch64 stat ABI");
_Static_assert(sizeof(struct Request)==128,"request ABI");
_Static_assert(sizeof(struct Report)==264,"report ABI");
_Static_assert(sizeof(plan_id)==32,"plan ID ABI");
static struct Report r;
static struct Request req;
static struct Stat initial[2];
static i64 fd[2]={-1,-1};
static u8 checkbytes[4096],mounts[8192];
static int restore_usr_ro,dirty[2];
struct StatFS{i64 type,bsize;u64 blocks,bfree,bavail,files,ffree;u32 fsid[2];i64 namelen,frsize,flags,spare[4];};
_Static_assert(sizeof(struct StatFS)==120,"statfs ABI");
static u64 expected_size(u32 chip){return file_sizes[chip];}

static int same(const u8*a,const u8*b,u32 n) {
    for(u32 i=0;i<n;i++)if(a[i]!=b[i])return 0;
    return 1;
}
static u32 length(const char*s) {u32 n=0;while(s[n])n++;return n;}
static int field(const u8*a,u32 n,const char*b) {
    return n==length(b)&&same(a,(const u8*)b,n);
}
static i64 op(const char*p,i64 flags,u32 mode) {return sc(56,-100,(i64)p,flags,mode,0,0);}
static i64 cl(i64 *f) {
    if(*f<0)return 0;
    i64 value=sc(57,*f,0,0,0,0,0);*f=-1;return value;
}
static const char *path(u32 chip) {
#ifdef M4_FL23_R021_PROBE
    (void)chip;return "/cp/a7m4-fl23-transaction-r021.bin";
#else
    return chip?"/cp/CPAPP-B.BIN":"/usr/lib/appFw.so";
#endif
}
static i64 read_exact(i64 f,void*out,u32 n,u64 offset) {
    u32 done=0,retries=0;
    while(done<n) {
        i64 v=sc(67,f,(i64)((u8*)out+done),n-done,offset+done,0,0);
        if(v==-4&&retries++<3)continue;
        if(v<=0||(u64)v>n-done)return v<0?v:-5;
        done+=(u32)v;
    }
    return 0;
}
static i64 write_exact(i64 f,const void*data,u32 n,u64 offset,int sequential) {
    u32 done=0,retries=0;
    while(done<n) {
        i64 v=sc(sequential?64:68,f,(i64)((const u8*)data+done),n-done,offset+done,0,0);
        if(v==-4&&retries++<3)continue;
        if(v<=0||(u64)v>n-done)return v<0?v:-5;
        done+=(u32)v;
    }
    return 0;
}
static i64 mount_state(u32 chip,int ro) {
    /* /proc/mounts is itself a final-component symlink on Linux. */
    i64 f=op("/proc/self/mounts",READ_FLAGS,0);if(f<0)return f;
    u32 size=0,retries=0;i64 result=0;
    while(size<sizeof(mounts)) {
        i64 n=sc(63,f,(i64)(mounts+size),sizeof(mounts)-size,0,0,0);
        if(n==-4&&retries++<3)continue;
        if(n<0) {result=n;break;}
        if(!n)break;
        if((u64)n>sizeof(mounts)-size) {result=-75;break;}
        size+=(u32)n;
    }
    i64 c=cl(&f);if(result)return result;if(c)return c;
    if(size==sizeof(mounts))return -75;
    const char *source=chip?"/dev/nflasha8":"/dev/nflasha15";
    const char *target=chip?"/cp":"/usr";
    const char *type=chip?"vfat":"ext2";
    const char *options=chip?
        "rw,sync,noatime,nodiratime,fmask=0022,dmask=0022,codepage=437,iocharset=ascii,shortname=mixed,posix_attr,avoid_dlink,errors=remount-ro":
        (ro?"ro,sync,noatime,nodiratime,errors=continue":"rw,sync,noatime,nodiratime,errors=continue");
    u32 matches=0;
    for(u32 at=0;at<size;) {
        u32 end=at;while(end<size&&mounts[end]!='\n')end++;
        const u8 *parts[4];u32 sizes[4],pos=at,count=0;
        while(count<4&&pos<end) {
            u32 start=pos;while(pos<end&&mounts[pos]!=' ')pos++;
            parts[count]=mounts+start;sizes[count]=pos-start;count++;
            while(pos<end&&mounts[pos]==' ')pos++;
        }
        if(count==4&&(field(parts[0],sizes[0],source)||field(parts[1],sizes[1],target))) {
            if(!field(parts[0],sizes[0],source)||!field(parts[1],sizes[1],target)||
               !field(parts[2],sizes[2],type)||!field(parts[3],sizes[3],options))return -30;
            matches++;
        }
        at=end+1;
    }
    return matches==1?0:-22;
}
#ifndef M4_FL23_R021_PROBE
static i64 remount(int ro) {
    i64 v=sc(40,0,(i64)"/usr",0,0xc30UL+(ro?1:0),0,0);
    return v?v:mount_state(0,ro);
}
#endif
#define MAX_WINDOWS 128
#define MAX_AP_BYTES 8192
static u32 coverage_base[MAX_WINDOWS],ap_bytes;
static i64 validate_manifest(void) {
    if(!window_count||window_count>MAX_WINDOWS||window_count!=sizeof(windows)/sizeof(windows[0])||
       !file_sizes[0]||!file_sizes[1]||file_sizes[0]>536870912UL||file_sizes[1]>536870912UL)return -22;
    u32 previous_chip=1,total=0;u64 end=0;ap_bytes=0;
    for(u32 i=0;i<window_count;i++) {
        const struct Window*w=&windows[i];
        if(w->chip>1||!w->length||w->length>sizeof(checkbytes)||
           !w->before||!w->after||w->offset>file_sizes[w->chip]||
           w->length>file_sizes[w->chip]-w->offset)return -22;
        if(i&&w->chip>previous_chip)return -22;
        if(i&&w->chip==previous_chip&&w->offset<end)return -22;
        total+=w->length;if(total>16384)return -22;
        coverage_base[i]=ap_bytes;
        if(!w->chip){ap_bytes+=w->length;if(ap_bytes>MAX_AP_BYTES)return -22;}
        end=w->offset+w->length;previous_chip=w->chip;dirty[w->chip]=1;
    }
    return 0;
}
static int same_stat(const struct Stat*a,const struct Stat*b) {
    return a->dev==b->dev&&a->ino==b->ino&&a->mode==b->mode&&a->nlink==b->nlink&&
           a->uid==b->uid&&a->gid==b->gid&&a->size==b->size;
}
static i64 inspect(u32 chip,int writable) {
    fd[chip]=op(path(chip),READ_FLAGS|(writable?2:0),0);
    if(fd[chip]<0)return fd[chip];
    struct Stat st;i64 v=sc(80,fd[chip],(i64)&st,0,0,0,0);if(v)return v;
    /* Factory AP is uid 57285/gid 1000 on observed 6.02. Preserve
       observed ownership; it is identity data, not a root prerequisite. */
    if(chip){r.cp_mode=st.mode;r.cp_nlink=st.nlink;r.cp_uid=st.uid;r.cp_gid=st.gid;}
    else {r.ap_mode=st.mode;r.ap_nlink=st.nlink;r.ap_uid=st.uid;r.ap_gid=st.gid;}
    if((st.mode&0170000)!=0100000||st.nlink!=1||
       st.size<0||(u64)st.size!=expected_size(chip))return -22;
    u32 has_identity=req.attributes[1]||req.attributes[5];
    if(has_identity && (st.mode!=req.attributes[chip*4]||st.nlink!=req.attributes[chip*4+1]||
       st.uid!=req.attributes[chip*4+2]||st.gid!=req.attributes[chip*4+3]||
       st.dev!=req.file_ids[chip*2]||st.ino!=req.file_ids[chip*2+1]))return -116;
    if(writable) {if(!same_stat(&st,&initial[chip]))return -116;}
    else initial[chip]=st;
    return 0;
}
static i64 verify_windows(int target) {
    for(u32 i=0;i<window_count;i++) {
        const struct Window*w=&windows[i];
        i64 v=read_exact(fd[w->chip],checkbytes,w->length,w->offset);if(v)return v;
        if(!same(checkbytes,target?w->after:w->before,w->length))return -84;
    }
#ifdef M4_FL23_R021_PROBE
    /* Ownership covers the whole file, not merely the three edited windows. */
    i64 full=read_exact(fd[1],checkbytes,1024,0);if(full)return full;
    if(!same(checkbytes,target?probe_b:probe_a,1024))return -84;
#endif
    return 0;
}
static i64 verify_fds(void) {
    for(u32 chip=0;chip<2;chip++) {
        struct Stat st,named;i64 v=sc(80,fd[chip],(i64)&st,0,0,0,0);if(v)return v;
        if(!same_stat(&st,&initial[chip]))return -116;
        v=sc(79,-100,(i64)path(chip),(i64)&named,0x100,0,0);if(v)return v;
        if(!same_stat(&named,&initial[chip]))return -116;
    }
    return 0;
}
static i64 verify_chip(u32 chip,int target) {
    for(u32 i=0;i<window_count;i++)if(windows[i].chip==chip) {
        const struct Window*w=&windows[i];
        i64 v=read_exact(fd[chip],checkbytes,w->length,w->offset);if(v)return v;
        if(!same(checkbytes,target?w->after:w->before,w->length))return -84;
    }
    return 0;
}
static i64 patch_chip(u32 chip,int target,int reverse) {
    if(!dirty[chip])return 0;
    i64 v=verify_fds();if(v)return v;
    for(u32 j=0;j<window_count;j++) {
        u32 i=reverse?window_count-1-j:j;const struct Window*w=&windows[i];if(w->chip!=chip)continue;
        v=verify_fds();if(v)return v;
        v=read_exact(fd[chip],checkbytes,w->length,w->offset);if(v)return v;
        if(!same(checkbytes,target?w->before:w->after,w->length))return -84;
        r.writes++;
        v=write_exact(fd[chip],target?w->after:w->before,w->length,w->offset,0);if(v)return v;
    }
    v=sc(82,fd[chip],0,0,0,0,0);if(v)return v;
    v=verify_fds();return v?v:verify_chip(chip,target);
}
static i64 measure_space(int enforce) {
    const char*names[2]={"/tmp/jiritsu","/cp"};
    for(u32 i=0;i<2;i++) {
        struct StatFS s;i64 v=sc(43,(i64)names[i],(i64)&s,0,0,0,0);if(v)return v;
        i64 unit=s.frsize>0?s.frsize:s.bsize;
        if(s.type!=0x4d44||s.bsize<=0||s.bsize>65536||unit<=0||unit>65536||s.bavail>~0UL/(u64)unit)return -22;
        u64 bytes=s.bavail*(u64)unit;
        if(!i){r.jiritsu_type=s.type;r.jiritsu_unit=unit;r.jiritsu_available=bytes;}
        else {r.cp_type=s.type;r.cp_unit=unit;r.cp_available=bytes;}
        if(enforce&&((!i&&s.bavail<(8388608UL+(u64)unit-1)/(u64)unit+(sizeof(r)+(u64)unit-1)/(u64)unit)||
                     (i&&s.bavail<2)))return -28;
    }
    return 0;
}
/* Source-identical AP COW, adapted from existing playback.c freeze/parse.
 * All bounded AP windows are read from private same-inode appFw mappings.
 * No semantic memory change: write exact bytes just read, then readback.
 * Mode1 requires source words; explicit inverse accepts either legal endpoint
 * in current running private pages (same-process or later cold target boot).
 */
static u8 maps[131072],mem[4096],memcheck[4096],covered[(MAX_AP_BYTES+7)/8];static u32 maps_len;
struct Mapping{u64 start,stop,offset,major,minor,ino;u32 readable,private_map;};
static int number(const u8*b,u32 end,u32*at,u64*out,u32 radix){u64 n=0;u32 begin=*at;while(*at<end){u8 c=b[*at];u32 v=c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:99;if(v>=radix)break;if(n>(~0UL-v)/radix)return 0;n=n*radix+v;(*at)++;}*out=n;return *at>begin;}
static int parse(u32 begin,u32 end,struct Mapping*m){const char*p="/usr/lib/appFw.so";u32 len=length(p);if(end-begin<len+1||maps[end-len-1]!=' '||!same(maps+end-len,(const u8*)p,len))return 0;u32 a=begin;int ok=number(maps,end,&a,&m->start,16)&&a<end&&maps[a++]=='-'&&number(maps,end,&a,&m->stop,16)&&a<end&&maps[a++]==' ';if(!ok||a+5>=end)return -1;m->readable=maps[a]=='r';m->private_map=maps[a+3]=='p';a+=5;if(!number(maps,end,&a,&m->offset,16)||a>=end||maps[a++]!=' '||!number(maps,end,&a,&m->major,16)||a>=end||maps[a++]!=':'||!number(maps,end,&a,&m->minor,16)||a>=end||maps[a++]!=' ')return -1;while(a<end&&maps[a]==' ')a++;if(!number(maps,end,&a,&m->ino,10)||m->stop<=m->start)return -1;return 1;}
static int identity(const struct Mapping*m){u64 dev=initial[0].dev,major=((dev>>8)&0xfff)|((dev>>32)&~0xfffUL),minor=(dev&0xff)|((dev>>12)&~0xffUL);return m->ino==initial[0].ino&&m->major==major&&m->minor==minor;}
static i64 freeze_ap(int cow){
 i64 f=op("/proc/self/maps",READ_FLAGS,0);if(f<0)return f;u32 size=0,retry=0;i64 v=0;
 while(size<sizeof(maps)){i64 n=sc(63,f,(i64)(maps+size),sizeof(maps)-size,0,0,0);if(n==-4&&retry++<3)continue;if(n<0){v=n;break;}if(!n)break;if((u64)n>sizeof(maps)-size){v=-75;break;}size+=n;}
 i64 close=cl(&f);if(v)return v;if(close)return close;if(!size||size==sizeof(maps)||maps[size-1]!='\n')return -75;maps_len=size;
 f=op("/proc/self/mem",READ_FLAGS|(cow?2:0),0);if(f<0)return f;
 for(u32 k=0;k<sizeof(covered);k++)covered[k]=0;u32 begin=0;
 for(u32 line=0;line<maps_len&&!v;line++)if(maps[line]=='\n'){
  struct Mapping m;int p=parse(begin,line,&m);begin=line+1;if(p<0){v=-22;break;}if(!p)continue;if(!identity(&m)){v=-116;break;}
  for(u32 w=0;w<window_count&&!v;w++){const struct Window*x=&windows[w];if(x->chip)continue;u64 a=x->offset>m.offset?x->offset:m.offset,b=x->offset+x->length<m.offset+m.stop-m.start?x->offset+x->length:m.offset+m.stop-m.start;if(a>=b)continue;
   if(!m.readable||!m.private_map){v=-13;break;}u32 n=b-a;u64 address=m.start+a-m.offset;
   v=read_exact(f,mem,n,address);if(v)break;int legal=same(mem,x->before+a-x->offset,n)||(req.mode==2&&same(mem,x->after+a-x->offset,n));if(!legal){v=-11;break;}
   if(cow){v=write_exact(f,mem,n,address,0);if(!v)v=read_exact(f,memcheck,n,address);if(!v&&!same(mem,memcheck,n))v=-84;if(v)break;}
   for(u32 k=0;k<n;k++){u32 bit=coverage_base[w]+a-x->offset+k;covered[bit/8]|=1U<<(bit%8);}
  }
 }
 for(u32 bit=0;bit<ap_bytes&&!v;bit++)if(!(covered[bit/8]&(1U<<(bit%8))))v=-18;
 close=cl(&f);return v?v:close;
}

static void work(void) {
    i64 f=op(REQUEST,READ_FLAGS,0);if(f<0){r.status=f;return;}
    struct Stat st;r.status=sc(80,f,(i64)&st,0,0,0,0);
    if(!r.status&&((st.mode&0170000)!=0100000||st.nlink!=1||st.uid||st.gid||st.size!=sizeof(req)))r.status=-22;
    if(!r.status)r.status=read_exact(f,&req,sizeof(req),0);
    u8 extra;if(!r.status){i64 n=sc(67,f,(i64)&extra,1,sizeof(req),0,0);if(n)r.status=n<0?n:-22;}
    i64 c=cl(&f);if(!r.status&&c)r.status=c;if(r.status)return;
    u8 nonzero=0;for(u32 i=0;i<16;i++){r.nonce[i]=req.nonce[i];nonzero|=req.nonce[i];}
    r.mode=req.mode;
    if(!same(req.magic,(const u8*)"M4PG0002",8)||req.mode>3||req.reserved||!nonzero){r.status=-22;return;}
    if(!same(req.plan_id,plan_id,32)){r.status=-84;return;}
    u32 has_identity=0;for(u32 i=0;i<8;i++)has_identity|=req.attributes[i];
    for(u32 i=0;i<4;i++)has_identity|=req.file_ids[i]!=0;
    if((has_identity && (req.attributes[1]!=1||req.attributes[5]!=1||
       !req.file_ids[0]||!req.file_ids[1]||!req.file_ids[2]||!req.file_ids[3]))||
       (!has_identity&&(req.mode==1||req.mode==2))){r.status=-22;return;}
    if(r.euid){r.status=-13;return;}
    r.status=validate_manifest();if(r.status)return;
    r.phase=1;r.status=mount_state(0,1);if(r.status)return;
    r.cp_mount_status=mount_state(1,0);if(r.cp_mount_status){r.status=r.cp_mount_status;return;}
    r.status=measure_space(0);if(r.status)return;
    for(u32 chip=0;chip<2;chip++){r.status=inspect(chip,0);if(r.status)return;}
    r.ap_dev=initial[0].dev;r.ap_inode=initial[0].ino;r.ap_size=initial[0].size;
    r.cp_dev=initial[1].dev;r.cp_inode=initial[1].ino;r.cp_size=initial[1].size;
    int endpoint=req.mode==2||req.mode==3;
    r.phase=2;r.status=verify_windows(endpoint);if(r.status)return;
    r.status=verify_fds();if(r.status)return;
    if(req.mode==0||req.mode==3){r.phase=9;return;}
    for(u32 chip=0;chip<2;chip++){r.status=cl(&fd[chip]);if(r.status)return;}
    r.phase=3;
    if(dirty[0]){
        r.status=freeze_ap(0);if(r.status)return;
        r.status=freeze_ap(1);if(r.status)return;
        restore_usr_ro=1;r.remount=remount(0);if(r.remount){r.status=r.remount;return;}
    }
    for(u32 chip=0;chip<2;chip++){r.status=inspect(chip,dirty[chip]);if(r.status)return;}
    r.status=verify_windows(endpoint);if(r.status)return;
    r.status=verify_fds();if(r.status)return;
    r.status=measure_space(1);if(r.status)return;
    r.phase=4;
    /* CP content is durable and read back before AP points at it. Explicit
       inverse restores AP first, then CP. No failed pass is auto-reversed. */
    if(req.mode==1){r.status=patch_chip(1,1,0);if(!r.status)r.status=patch_chip(0,1,0);}
    else {r.status=patch_chip(0,0,1);if(!r.status)r.status=patch_chip(1,0,1);}
    if(r.status&&r.writes){r.phase=6;r.rollback=-125;return;}
    if(!r.status)r.phase=9;
}

__attribute__((visibility("default"))) void m4_program_run(void) {
    u8*z=(u8*)&r;for(u32 i=0;i<sizeof(r);i++)z[i]=0;
    z=(u8*)&req;for(u32 i=0;i<sizeof(req);i++)z[i]=0;
    fd[0]=fd[1]=-1;restore_usr_ro=dirty[0]=dirty[1]=0;ap_bytes=0;
    for(u32 i=0;i<8;i++)r.magic[i]=((const u8*)"M4PGR001")[i];
    for(u32 i=0;i<32;i++)r.plan_id[i]=plan_id[i];
    r.version=2;r.cp_mount_status=-125;
    r.euid=sc(175,0,0,0,0,0,0);r.pid=sc(172,0,0,0,0,0,0);
    i64 out=op(RESULT,RESULT_FLAGS,0600);if(out<0)return;
    struct Stat st;r.status=sc(80,out,(i64)&st,0,0,0,0);
    if(!r.status&&((st.mode&0170000)!=0100000||st.nlink!=1||st.uid||st.gid||st.size))r.status=-22;
    if(!r.status){
        r.cleanup=sc(35,-100,(i64)"/tmp/jiritsu/libJit.so",0,0,0,0);
        if(r.cleanup)r.status=r.cleanup;else work();
    }
    for(u32 chip=0;chip<2;chip++){i64 c=cl(&fd[chip]);if(c&&!r.status)r.status=c;}
    r.readonly=restore_usr_ro?remount(1):mount_state(0,1);
    r.cp_mount_status=mount_state(1,0);
    if(!r.status&&r.readonly)r.status=r.readonly;
    if(!r.status&&r.cp_mount_status)r.status=r.cp_mount_status;
    if(r.status&&r.phase==9)r.phase=8;
    /* Report delivery cannot attest its own final fsync/close. Missing, partial
       or failed delivery always remains unknown; host full hashes decide. */
    if(!write_exact(out,&r,sizeof(r),0,1))sc(82,out,0,0,0,0,0);
    cl(&out);
}
#ifndef M4_FL23_DIRECT_TEST
__attribute__((visibility("default"))) void _init(void){m4_program_run();}
#endif

