#ifdef M4_FL23_R021_PROBE
#error R066 has no probe/create/delete mode
#endif
/* Stock602/current receipt-bound PIN product transaction (offline-built, not device accepted), adapted from QAQLeonard/a7c2-fl23-research
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

#define REQUEST "/tmp/jiritsu/m4.sound-scope.request"
#define RESULT "/tmp/jiritsu/m4.sound-scope.result"
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
struct Request {u8 magic[8];u32 mode,reserved;u8 nonce[16],plan_id[32];};
struct Report {
    u8 magic[8];u32 version,mode,phase,writes;
    i64 status,rollback,remount,readonly,cleanup,euid,pid;
    u64 ap_dev,ap_inode,ap_size,cp_dev,cp_inode,cp_size;
    u8 plan_id[32],nonce[16];i64 cp_mount_status;
};
_Static_assert(sizeof(struct Stat)==128,"Linux AArch64 stat ABI");
_Static_assert(sizeof(struct Request)==64,"request ABI");
_Static_assert(sizeof(struct Report)==184,"report ABI");
_Static_assert(sizeof(plan_id)==32,"plan ID ABI");
static struct Report r;
static struct Request req;
static struct Stat initial[2];
static i64 fd[2]={-1,-1};
static u8 checkbytes[4096],mounts[8192];
static int restore_usr_ro,dirty[2];
static u64 bank_guard;
struct StatFS{i64 type,bsize;u64 blocks,bfree,bavail,files,ffree;u32 fsid[2];i64 namelen,frsize,flags,spare[4];};
_Static_assert(sizeof(struct StatFS)==120,"statfs ABI");
static u64 expected_size(u32 chip){return chip?bank_guard:file_sizes[0];}

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
    return chip?"/cp/SysSound.bin":"/usr/lib/appFw.so";
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
    /* Extra runtime words are derived from a separately validated previous
       forward plan and included in this worker's full plan_id. Never replace
       mapped bytes with R066/new target values: COW writes exact bytes read. */
    if(sizeof(runtime_ap_words)!=28||sizeof(previous_plan_id)!=32||allow_target_runtime>1)return -22;
    u8 nonzero_runtime=0;for(u32 k=0;k<32;k++)nonzero_runtime|=previous_plan_id[k];
    if(!nonzero_runtime)return -22;
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
    if(file_sizes[0]!=98212632||file_sizes[1]<77504||file_sizes[1]>110528||window_count!=7||source_packet_bytes!=file_sizes[1]-77504+304||target_packet_bytes!=target_bank_size-77504+304)return -22;
    if(scoped_restore>1||(scoped_restore?target_bank_size!=77504:(file_sizes[1]!=77504||target_bank_size!=110528)))return -22;
    if(req.mode==2)return -22; /* Explicit scoped restore is a separately bound mode0/1/3 transaction. */
    static const u64 fixed[7]={0x317c5f0,0x317c5f4,0x317c5f8,0x317c5fc,0x317c628,0x317c62c,0x317c630};
    for(u32 i=0;i<7;i++)if(windows[i].chip||windows[i].offset!=fixed[i]||windows[i].length!=4)return -22;
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
    dirty[1]=1; /* Fixed append/truncate resource, never CP program windows. */
    return 0;
}
static i64 inspect(u32 chip,int writable) {
    fd[chip]=op(path(chip),READ_FLAGS|(writable?2:0),0);
    if(fd[chip]<0)return fd[chip];
    struct Stat st;i64 v=sc(80,fd[chip],(i64)&st,0,0,0,0);if(v)return v;
    if((st.mode&0170000)!=0100000||st.nlink!=1||st.size<0||(u64)st.size!=expected_size(chip))return -22;
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
        if((st.mode&0170000)!=0100000||st.size<0||(u64)st.size!=expected_size(chip)||
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


/* Two immutable, plan-bound packets carry only Ka and the owned tail. */
static u8 packet_source[33328],packet_target[33328];
static int bank_endpoint;
/* [256,77504) is F: never rewritten or used as an execution fingerprint. */
/* SHA-256 is used for packet integrity; full firmware SHA is a Mac obligation. */
static u32 rr(u32 x,u32 n){return (x>>n)|(x<<(32-n));}
static void packet_sha(const u8 *data,u32 size,u8 out[32]){
 static const u32 k[64]={0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
 u32 h[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
 u32 total=(size+9+63)&~63U;u8 block[64];u32 w[64];
 for(u32 at=0;at<total;at+=64){
  for(u32 j=0;j<64;j++){u32 p=at+j;block[j]=p<size?data[p]:p==size?128:0;if(p>=total-8)block[j]=(u8)(((u64)size*8)>>(8*(total-1-p)));}
  for(u32 j=0;j<16;j++)w[j]=((u32)block[j*4]<<24)|((u32)block[j*4+1]<<16)|((u32)block[j*4+2]<<8)|block[j*4+3];
  for(u32 j=16;j<64;j++)w[j]=w[j-16]+(rr(w[j-15],7)^rr(w[j-15],18)^(w[j-15]>>3))+w[j-7]+(rr(w[j-2],17)^rr(w[j-2],19)^(w[j-2]>>10));
  u32 a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],q=h[7];
  for(u32 j=0;j<64;j++){u32 t=q+(rr(e,6)^rr(e,11)^rr(e,25))+((e&f)^((~e)&g))+k[j]+w[j],v=(rr(a,2)^rr(a,13)^rr(a,22))+((a&b)^(a&c)^(b&c));q=g;g=f;f=e;e=d+t;d=c;c=b;b=a;a=t+v;}
  h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=q;
 }
 for(u32 j=0;j<32;j++)out[j]=(u8)(h[j/4]>>(24-8*(j%4)));
}
static i64 load_packet(const char *name,u8 *out,u32 size,const u8 expected[32],u32 index){
 i64 f=op(name,READ_FLAGS,0);if(f<0)return f;struct Stat st;i64 v=sc(80,f,(i64)&st,0,0,0,0);
 if(!v&&((st.mode&0170000)!=0100000||st.nlink!=1||st.size!=size))v=-22;
 if(!v)v=read_exact(f,out,size,0);i64 c=cl(&f);if(v)return v;if(c)return c;
 u8 hash[32];packet_sha(out,size,hash);if(!same(hash,expected,32)||!same(out,(const u8*)"M4PIND01",8)||!same(out+8,plan_id,32))return -84;
 u32 value=(u32)out[40]|((u32)out[41]<<8)|((u32)out[42]<<16)|((u32)out[43]<<24);
 u32 length=(u32)out[44]|((u32)out[45]<<8)|((u32)out[46]<<16)|((u32)out[47]<<24);
 return value!=index||length!=size-48?-22:0;
}
static i64 load_packets(void){
 i64 v=load_packet(source_packet_path,packet_source,source_packet_bytes,source_packet_sha,0);if(v)return v;
 return load_packet(target_packet_path,packet_target,target_packet_bytes,target_packet_sha,1);
}
static i64 bank_shape(int partial){
 if(partial)return -22; /* Unknown/partial writes are never automatically replayed. */
 struct Stat st;i64 v=sc(80,fd[1],(i64)&st,0,0,0,0);if(v)return v;
 u64 required=bank_endpoint?target_bank_size:file_sizes[1];
 if((st.mode&0170000)!=0100000||st.dev!=initial[1].dev||st.ino!=initial[1].ino||st.size!=(i64)required||bank_guard!=required)return -116;
 /* The two exact C packets are checked below; unmodified bank F is observation-only. */
 const u8 *data=(bank_endpoint?packet_target:packet_source)+48;
 for(u32 part=0;part<2;part++){
  u64 position=part?77504:0,total=part?required-77504:256,at=0;const u8 *expected=data+(part?256:0);
  while(at<total){u32 n=total-at>sizeof(checkbytes)?sizeof(checkbytes):(u32)(total-at);v=read_exact(fd[1],checkbytes,n,position+at);if(v)return v;if(!same(checkbytes,expected+at,n))return -84;at+=n;}
 }
 return verify_fds();
}
static i64 capacity(void){
 struct StatFS s;i64 v=sc(43,(i64)"/cp",(i64)&s,0,0,0,0);if(v)return v;
 if(s.type!=0x4d44||s.bsize<=0||s.bsize>65536)return -22;
 u64 target_blocks=(target_bank_size+s.bsize-1)/s.bsize,source_blocks=(file_sizes[1]+s.bsize-1)/s.bsize;
 u64 growth=target_blocks>source_blocks?target_blocks-source_blocks:0;
 if(s.bavail<growth+2)return -28;
 v=sc(43,(i64)"/tmp/jiritsu",(i64)&s,0,0,0,0);if(v)return v;
 i64 unit=s.frsize>0?s.frsize:s.bsize;
 if(s.bsize<=0||s.bsize>65536||unit<=0||unit>65536)return -22;
 /* RESULT exists but is empty: reserve its final allocation as well. */
 u64 needed=(8388608UL+(u64)unit-1)/(u64)unit+(sizeof(r)+(u64)unit-1)/(u64)unit;
 if(s.bavail<needed)return -28;
 return 0;
}
static int number(const u8*b,u32 end,u32*at,u64*out,u32 radix){u64 n=0;u32 begin=*at;while(*at<end){u8 c=b[*at];u32 v=c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:99;if(v>=radix)break;if(n>(~0UL-v)/radix)return 0;n=n*radix+v;(*at)++;}*out=n;return *at>begin;}
static i64 bank_not_mapped(void){
 static u8 bank_map_line[8192];
 i64 f=op("/proc/self/maps",READ_FLAGS,0);if(f<0)return f;u32 n=0;u8 byte;i64 v=0;
 for(;;){i64 z=sc(63,f,(i64)&byte,1,0,0,0);if(z<0){v=z;break;}if(!z)break;
  if(n>=sizeof(bank_map_line)){v=-75;break;}bank_map_line[n++]=byte;
  if(byte=='\n'){
   u32 at=0,end=n-1;u64 start,stop,offset,major,minor,ino;
   int valid=number(bank_map_line,end,&at,&start,16)&&at<end&&bank_map_line[at++]=='-'&&number(bank_map_line,end,&at,&stop,16)&&at<end&&bank_map_line[at++]==' ';
   if(!valid||at+5>=end){v=-22;break;}at+=5;
   valid=number(bank_map_line,end,&at,&offset,16)&&at<end&&bank_map_line[at++]==' '&&number(bank_map_line,end,&at,&major,16)&&at<end&&bank_map_line[at++]==':'&&number(bank_map_line,end,&at,&minor,16)&&at<end&&bank_map_line[at++]==' ';
   while(at<end&&bank_map_line[at]==' ')at++;
   if(!valid||!number(bank_map_line,end,&at,&ino,10)||stop<=start){v=-22;break;}
   u64 dev=initial[1].dev,expected_major=((dev>>8)&0xfff)|((dev>>32)&~0xfffUL),expected_minor=(dev&0xff)|((dev>>12)&~0xffUL);
   if(ino==initial[1].ino&&major==expected_major&&minor==expected_minor){v=-16;break;}n=0;
  }
 }
 if(!v&&n)v=-75;
 i64 c=cl(&f);return v?v:c;
}
static i64 write_bank(int target,int count){
 i64 v=bank_shape(0);if(v)return v;v=verify_fds();if(v)return v;
 const u8 *data=(target?packet_target:packet_source)+48;u64 size=target?target_bank_size:file_sizes[1];
 if(count)r.writes++;
 v=write_exact(fd[1],data,256,0,0);if(v)return v;
 v=write_exact(fd[1],data+256,(u32)(size-77504),77504,0);if(v){struct Stat st;if(!sc(80,fd[1],(i64)&st,0,0,0,0))bank_guard=st.size;return v;}
 if(size<bank_guard){v=bank_not_mapped();if(v)return v;v=sc(46,fd[1],size,0,0,0,0);if(v)return v;}
 bank_guard=size;bank_endpoint=target;
 v=sc(82,fd[1],0,0,0,0,0);if(v)return v;
 v=verify_fds();return v?v:bank_shape(0);
}
static i64 append_target(int count){return write_bank(1,count);}
static i64 truncate_source(int count){return write_bank(0,count);}
static i64 inverse_failed_forward(void){return -125;}
static i64 inverse_failed_inverse(void){return -125;}
/* Source-identical AP COW, adapted from existing playback.c freeze/parse.
 * The7 aligned4B words are read from private same-inode appFw mappings.
 * No semantic memory change: write exact bytes just read, then readback.
 * Forward permits only R066 source or the trusted previous-plan target words.
 * This derived worker has no inverse mode; the original forward plan owns inverse.
 */
static u8 maps[131072],mem[4],memcheck[4];static u32 maps_len;
struct Mapping{u64 start,stop,offset,major,minor,ino;u32 readable,private_map;};
static int parse(u32 begin,u32 end,struct Mapping*m){const char*p="/usr/lib/appFw.so";u32 len=length(p);if(end-begin<len+1||maps[end-len-1]!=' '||!same(maps+end-len,(const u8*)p,len))return 0;u32 a=begin;int ok=number(maps,end,&a,&m->start,16)&&a<end&&maps[a++]=='-'&&number(maps,end,&a,&m->stop,16)&&a<end&&maps[a++]==' ';if(!ok||a+5>=end)return -1;m->readable=maps[a]=='r';m->private_map=maps[a+3]=='p';a+=5;if(!number(maps,end,&a,&m->offset,16)||a>=end||maps[a++]!=' '||!number(maps,end,&a,&m->major,16)||a>=end||maps[a++]!=':'||!number(maps,end,&a,&m->minor,16)||a>=end||maps[a++]!=' ')return -1;while(a<end&&maps[a]==' ')a++;if(!number(maps,end,&a,&m->ino,10)||m->stop<=m->start)return -1;return 1;}
static int identity(const struct Mapping*m){u64 dev=initial[0].dev,major=((dev>>8)&0xfff)|((dev>>32)&~0xfffUL),minor=(dev&0xff)|((dev>>12)&~0xffUL);return m->ino==initial[0].ino&&m->major==major&&m->minor==minor;}
static i64 freeze_ap(int cow){
 i64 f=op("/proc/self/maps",READ_FLAGS,0);if(f<0)return f;u32 size=0,retry=0;i64 v=0;
 while(size<sizeof(maps)){i64 n=sc(63,f,(i64)(maps+size),sizeof(maps)-size,0,0,0);if(n==-4&&retry++<3)continue;if(n<0){v=n;break;}if(!n)break;if((u64)n>sizeof(maps)-size){v=-75;break;}size+=n;}
 i64 close=cl(&f);if(v)return v;if(close)return close;if(!size||size==sizeof(maps)||maps[size-1]!='\n')return -75;maps_len=size;
 f=op("/proc/self/mem",READ_FLAGS|(cow?2:0),0);if(f<0)return f;
 u8 covered[7]={0};u32 begin=0;int source_ok=1,previous_ok=1,target_ok=req.mode==2||allow_target_runtime;
 for(u32 line=0;line<maps_len&&!v;line++)if(maps[line]=='\n'){
  struct Mapping m;int p=parse(begin,line,&m);begin=line+1;if(p<0){v=-22;break;}if(!p)continue;if(!identity(&m)){v=-116;break;}if((m.start|m.stop|m.offset)&4095UL||m.offset>~0UL-(m.stop-m.start)){v=-22;break;}
  for(u32 w=0;w<7&&!v;w++){const struct Window*x=&windows[w];u64 a=x->offset>m.offset?x->offset:m.offset,b=x->offset+4<m.offset+m.stop-m.start?x->offset+4:m.offset+m.stop-m.start;if(a>=b)continue;
   if(!m.readable||!m.private_map){v=-13;break;}u32 n=b-a;u64 address=m.start+a-m.offset;
   v=read_exact(f,mem,n,address);if(v)break;int source=same(mem,x->before+a-x->offset,n),previous=same(mem,runtime_ap_words[w]+a-x->offset,n);int target=(req.mode==2||allow_target_runtime)&&same(mem,x->after+a-x->offset,n);source_ok&=source;previous_ok&=previous;target_ok&=target;if(!source&&!previous&&!target){v=-11;break;}
   if(cow){v=write_exact(f,mem,n,address,0);if(!v)v=read_exact(f,memcheck,n,address);if(!v&&!same(mem,memcheck,n))v=-84;if(v)break;}
   for(u32 k=0;k<n;k++)covered[w]|=1U<<(a-x->offset+k);
  }
 }
 for(u32 w=0;w<7&&!v;w++)if(covered[w]!=15)v=-18;if(!v&&!source_ok&&!previous_ok&&!target_ok)v=-11;
 close=cl(&f);return v?v:close;
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
    if(!same(req.magic,(const u8*)"M4PF0001",8)||req.mode>max_mode||req.reserved||!nonzero) {r.status=-22;return;}
    if(!same(req.plan_id,plan_id,32)){r.status=-84;return;}
    if(r.euid) {r.status=-13;return;}
    r.status=validate_manifest();if(r.status)return;bank_endpoint=req.mode==3;bank_guard=bank_endpoint?target_bank_size:file_sizes[1];r.status=load_packets();if(r.status)return;
    r.phase=1;r.status=mount_state(0,1);if(r.status)return;
    i64 csv=op("/usr/share/avsystemsound/custom.txt",READ_FLAGS,0);if(csv>=0){cl(&csv);r.status=-17;return;}if(csv!=-2){r.status=csv;return;}
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
    r.status=bank_shape(0);if(r.status)return;
    r.status=verify_fds();if(r.status)return;
#ifdef M4_FL23_R021_PROBE
    if(req.mode==5) {probe_delete();return;}
#endif
    if(req.mode==0||req.mode==3) {r.phase=9;return;}
    for(u32 chip=0;chip<2;chip++) {r.status=cl(&fd[chip]);if(r.status)return;}
    r.phase=3;
    r.status=freeze_ap(0);if(r.status)return;
    r.status=freeze_ap(1);if(r.status)return;
#ifndef M4_FL23_R021_PROBE
    if(dirty[0]) {
        restore_usr_ro=1;r.remount=remount(0);
        if(r.remount) {r.status=r.remount;return;}
    }
#endif
    for(u32 chip=0;chip<2;chip++)if(active_chip(chip)) {r.status=inspect(chip,dirty[chip]);if(r.status)return;}
    r.status=verify_windows(source_target);if(r.status)return;
    r.status=verify_fds();if(r.status)return;
    r.status=bank_shape(0);if(r.status)return;
    r.status=capacity();if(r.status)return;
    if(scoped_restore){r.status=bank_not_mapped();if(r.status)return;}
    r.phase=4;
    if(req.mode==1){if(scoped_restore){r.status=patch(1,0,1);if(!r.status)r.status=append_target(1);}else{r.status=append_target(1);if(!r.status)r.status=patch(1,0,1);}}
    else{r.status=patch(0,1,1);if(!r.status)r.status=truncate_source(1);}
    if(r.status&&r.writes){r.phase=6;r.rollback=req.mode==1?inverse_failed_forward():inverse_failed_inverse();return;}
    if(!r.status)r.phase=9;
}
__attribute__((visibility("default"))) void m4_fl23_direct_run(void) {
    u8*z=(u8*)&r;for(u32 i=0;i<sizeof(r);i++)z[i]=0;
    z=(u8*)&req;for(u32 i=0;i<sizeof(req);i++)z[i]=0;
    fd[0]=fd[1]=-1;restore_usr_ro=dirty[0]=dirty[1]=0;bank_guard=0;
    for(u32 i=0;i<8;i++)r.magic[i]=((const u8*)"M4PFR001")[i];
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
    if(r.cp_inode)r.cp_size=bank_guard;
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
