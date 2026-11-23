/* Bounded M4 program-file transaction, adapted from QAQLeonard/a7c2-fl23-research
 * src/fl23/native/installer.c (782785641ca9f8b984940c7274b48706219e0da4).
 * Exact edited bytes only; fresh full source and full readback belong to host.
 * No process-memory, raw-device, settings, power or snapshot writes.
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
extern i64 m4_fl23_direct_test_syscall(i64,i64,i64,i64,i64,i64,i64);
static i64 sc(i64 n,i64 a,i64 b,i64 c,i64 d,i64 e,i64 f) {
    return m4_fl23_direct_test_syscall(n,a,b,c,d,e,f);
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

#define REQUEST "/tmp/jiritsu/m4-fl23-direct.program.request"
#define RESULT "/tmp/jiritsu/m4-fl23-direct.program.result"
#define DIRECT_O_NOFOLLOW 0x8000UL
#define DIRECT_O_CLOEXEC 0x80000UL
#define READ_FLAGS (DIRECT_O_NOFOLLOW|DIRECT_O_CLOEXEC)
#define RESULT_FLAGS (READ_FLAGS|1|64|128)
#ifdef M4_FL23_TARGET_ABI_CHECK
_Static_assert(DIRECT_O_NOFOLLOW==O_NOFOLLOW,"target Linux NOFOLLOW ABI");
_Static_assert(DIRECT_O_CLOEXEC==O_CLOEXEC,"target Linux CLOEXEC ABI");
_Static_assert(READ_FLAGS==(O_RDONLY|O_NOFOLLOW|O_CLOEXEC),"target read flags ABI");
_Static_assert(RESULT_FLAGS==(O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC),"target result flags ABI");
_Static_assert(AT_SYMLINK_NOFOLLOW==0x100,"target path identity flags ABI");
_Static_assert(SYS_newfstatat==79,"target newfstatat syscall ABI");
_Static_assert(SYS_unlinkat==35,"target unlinkat syscall ABI");
#endif

struct Stat {
    u64 dev,ino;u32 mode,nlink,uid,gid;u64 rdev,pad1;i64 size;
    u32 blksize,pad2;u64 blocks,rest[7];
};
struct Request {u8 magic[8];u32 mode,reserved;u8 nonce[16];};
struct Report {
    u8 magic[8];u32 version,mode,phase,writes;
    i64 status,rollback,remount,readonly,cleanup,euid,pid;
    u64 ap_dev,ap_inode,ap_size,cp_dev,cp_inode,cp_size;
    u8 plan_id[32],nonce[16];i64 cp_mount_status;
};
_Static_assert(sizeof(struct Stat)==128,"Linux AArch64 stat ABI");
_Static_assert(sizeof(struct Request)==32,"request ABI");
_Static_assert(sizeof(struct Report)==184,"report ABI");
_Static_assert(sizeof(plan_id)==32,"plan ID ABI");
static struct Report r;
static struct Request req;
static struct Stat initial[2];
static i64 fd[2]={-1,-1};
static u8 checkbytes[4096],mounts[8192];
static int restore_usr_ro,dirty[2];

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
static int active_chip(u32 chip) {
#ifdef M4_FL23_R021_PROBE
    return chip==1;
#else
    (void)chip;return 1;
#endif
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
static i64 validate_manifest(void) {
    if(!window_count||window_count!=sizeof(windows)/sizeof(windows[0])||
       !file_sizes[1])return -22;
#ifdef M4_FL23_R021_PROBE
    if(file_sizes[0]||file_sizes[1]!=1024||sizeof(probe_a)!=1024||sizeof(probe_b)!=1024||window_count!=3)return -22;
    if(!same(probe_a,(const u8*)"M4R021A1",8))return -22;
    u8 owner=0;for(u32 i=8;i<24;i++)owner|=probe_a[i];if(!owner)return -22;
    static const u64 expected_offsets[3]={64,512,1000};
    for(u32 i=0;i<3;i++) {
        const struct Window*w=&windows[i];
        if(w->chip!=1||w->offset!=expected_offsets[i]||w->length!=8||
           !w->before||!w->after||!same(w->before,probe_a+w->offset,8)||
           !same(w->after,probe_b+w->offset,8))return -22;
    }
    for(u32 i=0;i<1024;i++) {
        int changed=(i>=64&&i<72)||(i>=512&&i<520)||(i>=1000&&i<1008);
        if(probe_b[i]!=(u8)(probe_a[i]^(changed?0x5a:0)))return -22;
    }
#else
    if(!file_sizes[0])return -22;
#endif
    u32 previous_chip=1;u64 end=0;
    for(u32 i=0;i<window_count;i++) {
        const struct Window*w=&windows[i];
        if(w->chip>1||!w->length||w->length>sizeof(checkbytes)||
           !w->before||!w->after||w->offset>file_sizes[w->chip]||
           w->length>file_sizes[w->chip]-w->offset)return -22;
        if(i&&w->chip>previous_chip)return -22;
        if(i&&w->chip==previous_chip&&w->offset<end)return -22;
        end=w->offset+w->length;previous_chip=w->chip;dirty[w->chip]=1;
    }
    return 0;
}
static i64 inspect(u32 chip,int writable) {
    fd[chip]=op(path(chip),READ_FLAGS|(writable?2:0),0);
    if(fd[chip]<0)return fd[chip];
    struct Stat st;i64 v=sc(80,fd[chip],(i64)&st,0,0,0,0);if(v)return v;
    if((st.mode&0170000)!=0100000||st.size<0||(u64)st.size!=file_sizes[chip])return -22;
    if(writable) {
        if(st.dev!=initial[chip].dev||st.ino!=initial[chip].ino)return -116;
    } else initial[chip]=st;
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
    for(u32 chip=0;chip<2;chip++)if(active_chip(chip)) {
        struct Stat st;i64 v=sc(80,fd[chip],(i64)&st,0,0,0,0);if(v)return v;
        if((st.mode&0170000)!=0100000||st.size<0||(u64)st.size!=file_sizes[chip]||
           st.dev!=initial[chip].dev||st.ino!=initial[chip].ino)return -116;
    }
    return 0;
}
static i64 patch(int target,int reverse,int count_attempts) {
    /* Recheck identity before every pass, including a failure inverse. Never
       write a formerly valid FD after its regular/dev/inode/size guard failed. */
    i64 guard=verify_fds();if(guard)return guard;
    for(u32 j=0;j<window_count;j++) {
        u32 i=reverse?window_count-1-j:j;const struct Window*w=&windows[i];
        if(count_attempts)r.writes++;
        i64 v=write_exact(fd[w->chip],target?w->after:w->before,w->length,w->offset,0);
        if(v)return v;
    }
    for(u32 chip=0;chip<2;chip++)if(dirty[chip]) {
        i64 v=sc(82,fd[chip],0,0,0,0,0);if(v)return v;
    }
    i64 v=verify_fds();return v?v:verify_windows(target);
}
#ifdef M4_FL23_R021_PROBE
static void probe_create(void) {
    /* Exclusive creation is the sole full-file write and accepts no old file. */
    fd[1]=op(path(1),READ_FLAGS|2|64|128,0600);
    if(fd[1]<0) {r.status=fd[1];return;}
    struct Stat st;r.status=sc(80,fd[1],(i64)&st,0,0,0,0);if(r.status)return;
    if((st.mode&0170000)!=0100000||st.size) {r.status=-22;return;}
    initial[1]=st;r.cp_dev=st.dev;r.cp_inode=st.ino;
    r.phase=4;r.writes=1;
    r.status=write_exact(fd[1],probe_a,1024,0,0);if(r.status)return;
    r.status=sc(82,fd[1],0,0,0,0,0);if(r.status)return;
    r.status=sc(80,fd[1],(i64)&st,0,0,0,0);if(r.status)return;
    if((st.mode&0170000)!=0100000||st.size!=1024||
       st.dev!=initial[1].dev||st.ino!=initial[1].ino) {r.status=-116;return;}
    initial[1]=st;r.cp_size=st.size;
    r.status=verify_windows(0);if(r.status)return;
    r.status=verify_fds();if(!r.status)r.phase=9;
}
static void probe_delete(void) {
    /* Keep the owned FD open; reject replaced paths and confirm exact ENOENT. */
    r.status=verify_fds();if(r.status)return;
    struct Stat st;
    r.status=sc(79,-100,(i64)path(1),(i64)&st,0x100,0,0);if(r.status)return;
    if((st.mode&0170000)!=0100000||st.size!=1024||
       st.dev!=initial[1].dev||st.ino!=initial[1].ino) {r.status=-116;return;}
    r.phase=4;r.status=sc(35,-100,(i64)path(1),0,0,0,0);if(r.status)return;
    i64 v=sc(79,-100,(i64)path(1),(i64)&st,0x100,0,0);
    if(v!=-2) {r.status=v<0?v:-17;return;}
    r.phase=9;
}
#endif
static void work(void) {
    i64 f=op(REQUEST,READ_FLAGS,0);if(f<0) {r.status=f;return;}
    struct Stat st;r.status=sc(80,f,(i64)&st,0,0,0,0);
    if(!r.status&&((st.mode&0170000)!=0100000||st.size!=sizeof(req)))r.status=-22;
    if(!r.status)r.status=read_exact(f,&req,sizeof(req),0);
    u8 extra;
    if(!r.status) {
        i64 n=sc(67,f,(i64)&extra,1,sizeof(req),0,0);if(n)r.status=n<0?n:-22;
    }
    i64 c=cl(&f);if(!r.status&&c)r.status=c;if(r.status)return;
    u8 nonzero=0;for(u32 i=0;i<16;i++) {r.nonce[i]=req.nonce[i];nonzero|=req.nonce[i];}
    r.mode=req.mode;
    u32 max_mode=3;
#ifdef M4_FL23_R021_PROBE
    max_mode=5;
#endif
    if(!same(req.magic,(const u8*)"M4FD0001",8)||req.mode>max_mode||req.reserved||!nonzero) {r.status=-22;return;}
    if(r.euid) {r.status=-13;return;}
    r.status=validate_manifest();if(r.status)return;
    r.phase=1;r.status=mount_state(0,1);if(r.status)return;
    r.cp_mount_status=mount_state(1,0);if(r.cp_mount_status) {r.status=r.cp_mount_status;return;}
#ifdef M4_FL23_R021_PROBE
    if(req.mode==4) {probe_create();return;}
#endif
    for(u32 chip=0;chip<2;chip++)if(active_chip(chip)) {r.status=inspect(chip,0);if(r.status)return;}
#ifndef M4_FL23_R021_PROBE
    r.ap_dev=initial[0].dev;r.ap_inode=initial[0].ino;r.ap_size=initial[0].size;
#endif
    r.cp_dev=initial[1].dev;r.cp_inode=initial[1].ino;r.cp_size=initial[1].size;
    int source_target=req.mode==2||req.mode==3;
    r.phase=2;r.status=verify_windows(source_target);if(r.status)return;
    r.status=verify_fds();if(r.status)return;
#ifdef M4_FL23_R021_PROBE
    if(req.mode==5) {probe_delete();return;}
#endif
    if(req.mode==0||req.mode==3) {r.phase=9;return;}
    for(u32 chip=0;chip<2;chip++) {r.status=cl(&fd[chip]);if(r.status)return;}
    r.phase=3;
#ifndef M4_FL23_R021_PROBE
    if(dirty[0]) {
        restore_usr_ro=1;r.remount=remount(0);
        if(r.remount) {r.status=r.remount;return;}
    }
#endif
    for(u32 chip=0;chip<2;chip++)if(active_chip(chip)) {r.status=inspect(chip,dirty[chip]);if(r.status)return;}
    r.status=verify_windows(source_target);if(r.status)return;
    r.status=verify_fds();if(r.status)return;
    r.phase=4;r.status=patch(req.mode==1,0,1);
    if(r.status&&r.writes) {r.phase=6;r.rollback=patch(source_target,1,0);return;}
    if(!r.status)r.phase=9;
}
__attribute__((visibility("default"))) void m4_fl23_direct_run(void) {
    u8*z=(u8*)&r;for(u32 i=0;i<sizeof(r);i++)z[i]=0;
    z=(u8*)&req;for(u32 i=0;i<sizeof(req);i++)z[i]=0;
    fd[0]=fd[1]=-1;restore_usr_ro=dirty[0]=dirty[1]=0;
    for(u32 i=0;i<8;i++)r.magic[i]=((const u8*)"M4FDR001")[i];
    for(u32 i=0;i<32;i++)r.plan_id[i]=plan_id[i];
    r.version=1;r.cp_mount_status=-125;
    r.euid=sc(175,0,0,0,0,0,0);r.pid=sc(172,0,0,0,0,0,0);
    /* Exclusive output reservation precedes even owned-plugin cleanup. */
    i64 out=op(RESULT,RESULT_FLAGS,0600);if(out<0)return;
    struct Stat st;r.status=sc(80,out,(i64)&st,0,0,0,0);
    if(!r.status&&((st.mode&0170000)!=0100000||st.size!=0))r.status=-22;
    if(!r.status) {
        r.cleanup=sc(35,-100,(i64)"/tmp/jiritsu/libJit.so",0,0,0,0);
        if(r.cleanup)r.status=r.cleanup;
        else work();
    }
    for(u32 chip=0;chip<2;chip++) {i64 c=cl(&fd[chip]);if(c&&!r.status)r.status=c;}
    /* All writable descriptors are closed before a read-only mount attempt. */
#ifdef M4_FL23_R021_PROBE
    r.readonly=mount_state(0,1);
#else
    r.readonly=restore_usr_ro?remount(1):mount_state(0,1);
#endif
    r.cp_mount_status=mount_state(1,0);
    if(!r.status&&r.readonly)r.status=r.readonly;
    if(!r.status&&r.cp_mount_status)r.status=r.cp_mount_status;
    if(r.status&&r.phase==9)r.phase=8;
    /* Best-effort report delivery only. The 184-byte report cannot attest its
       own subsequent fsync/final close. Host-durable raw bytes and full program
       readback are authoritative; a delivery failure never replays or reverses
       completed program writes. Missing/partial reports remain unknown. */
    if(!write_exact(out,&r,sizeof(r),0,1))sc(82,out,0,0,0,0,0);
    cl(&out);
}
#ifndef M4_FL23_DIRECT_TEST
__attribute__((visibility("default"))) void _init(void) {m4_fl23_direct_run();}
#endif
