/* V2 fixed separately-approved WBI2-or-exact-zero512 vendor WBI invalidation; no rawblockwrite.
 * Publication/close discipline adapted from service-ap-loaded-state. */
typedef __UINT32_TYPE__ u32;typedef __UINT64_TYPE__ u64;typedef __INT64_TYPE__ i64;typedef unsigned char u8;
#ifdef WD_TARGET_ABI
#define _GNU_SOURCE 1
#include <fcntl.h>
#include <sys/syscall.h>
#include <linux/fs.h>
_Static_assert(O_NOFOLLOW==32768 && O_CLOEXEC==524288 && O_DIRECTORY==16384,"AArch64 flags");
_Static_assert(SYS_pread64==67 && SYS_ioctl==29 && SYS_newfstatat==79 && SYS_renameat2==276,"AArch64 syscalls");
_Static_assert(BLKGETSIZE64==0x80081272UL,"block capacity ioctl");
#endif
#ifdef WD_TEST
extern long wbi_drop_test_syscall(long,long,long,long,long,long,long);
static long sc(long n,long a,long b,long c,long d,long e,long f){return wbi_drop_test_syscall(n,a,b,c,d,e,f);}
#elif defined(__aarch64__)
static long sc(long n,long a,long b,long c,long d,long e,long f){register long x0 __asm__("x0")=a,x1 __asm__("x1")=b,x2 __asm__("x2")=c,x3 __asm__("x3")=d,x4 __asm__("x4")=e,x5 __asm__("x5")=f,x8 __asm__("x8")=n;__asm__ volatile("svc 0":"+r"(x0):"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5),"r"(x8):"memory","cc");return x0;}
#else
#error AArch64 or WD_TEST required
#endif
enum{READ_FLAGS=2048|32768|524288,MAX_REPORT=65536,COUNT=20,HEADER=128};
struct Stat{u64 dev,ino;u32 mode,nlink,uid,gid;u64 rdev,pad;i64 size;u32 blksize,pad2;i64 rest[8];};
struct FS{i64 type,bsize;u64 blocks,bfree,bavail,files,ffree;u32 fsid[2];i64 namelen,frsize,flags,spare[4];};
_Static_assert(sizeof(struct Stat)==128 && sizeof(struct FS)==120,"AArch64 layouts");
struct Section{u8*data;u32 length,cap;long status;};
static const char reqpath[]="/tmp/jiritsu/a7m4.wbi-drop-v2.request",outpath[]="/tmp/jiritsu/a7m4.wbi-drop-v2.result",pending[]="/tmp/jiritsu/a7m4.wbi-drop-v2.result.pending",node[]="/dev/cnflasha5";
static u8 request_data[576],report[MAX_REPORT],arena[40960];
static u8 before1[8192] __attribute__((aligned(4096))),after1[8192] __attribute__((aligned(4096))),logpiece[8192];
static struct Section sec[COUNT];static struct Stat baseline;static u32 closes,bad,flags,ids[4],stage,drop_attempted,mode_attempted;static long output_fd=-1;static struct Stat output_stat;
static void p32(u8*p,u32 v){for(u32 i=0;i<4;i++)p[i]=(u8)(v>>(8*i));}static void p64(u8*p,u64 v){for(u32 i=0;i<8;i++)p[i]=(u8)(v>>(8*i));}
static int equal(const u8*a,const u8*b,u32 n){for(u32 i=0;i<n;i++)if(a[i]!=b[i])return 0;return 1;}
static long op(const char*p,long flags_){return sc(56,-100,(long)p,flags_,0600,0,0);}static long cl(long f){long r=sc(57,f,0,0,0,0,0);closes++;if(r)bad++;return r;}
static long st(const char*p,struct Stat*s){return sc(79,-100,(long)p,(long)s,256,0,0);}
static int same(const struct Stat*a,const struct Stat*b){return a->dev==b->dev&&a->ino==b->ino&&a->mode==b->mode&&a->nlink==b->nlink&&a->uid==b->uid&&a->gid==b->gid&&a->rdev==b->rdev&&a->size==b->size;}
static int regular(const struct Stat*s){return(s->mode&0170000)==0100000&&s->ino&&s->nlink;}
static u64 major(u64 d){return((d>>8)&0xfff)|((d>>32)&0xfffff000);}static u64 minor(u64 d){return(d&255)|((d>>12)&0xffffff00);}
static void statbytes(u8*p,const struct Stat*s){p64(p,s->dev);p64(p+8,s->ino);p32(p+16,s->mode);p32(p+20,s->nlink);p32(p+24,s->uid);p32(p+28,s->gid);p64(p+32,s->rdev);p64(p+40,(u64)s->size);}
static long text(const char*p,u8*out,u32 cap,long fs_kind){struct Stat a,b;struct FS fs;long r=st(p,&a),fd,c;u32 at=0,calls=0,intr=0;u8 extra;
 if(r)return r;if(!regular(&a))return-13;fd=op(p,READ_FLAGS);if(fd<0)return fd;r=sc(80,fd,(long)&b,0,0,0,0);if(!r&&!same(&a,&b))r=-116;
 if(!r&&fs_kind){r=sc(44,fd,(long)&fs,0,0,0,0);if(!r&&fs.type!=fs_kind)r=-13;}
 while(!r){if(++calls>32){r=-5;break;}u32 n=cap-at;if(n>4096)n=4096;long v=sc(63,fd,(long)(n?out+at:&extra),n?n:1,0,0,0);if(v==-4&&++intr<=16)continue;if(v<0){r=v;break;}if(!v)break;if(!n||(u64)v>n){r=-75;break;}at+=(u32)v;}
 if(!r){r=sc(80,fd,(long)&b,0,0,0,0);if(!r&&!same(&a,&b))r=-116;}c=cl(fd);if(c)return c;return r?r:(long)at;}
static long observe(u32 id,const char*p,long kind){struct Section*s=&sec[id-1];long n=text(p,s->data,s->cap,kind);s->length=n<0?0:(u32)n;s->status=n<0?n:0;return n<0?n:0;}
static long readblock(u32 slot){struct Stat a,b;u64 size=0;long r=st(node,&a),fd,c;struct Section*s=&sec[slot];
 if(r){s->status=r;return r;}if(!same(&baseline,&a)){s->status=-116;return-116;}fd=op(node,READ_FLAGS);if(fd<0){s->status=fd;return fd;}
 r=sc(80,fd,(long)&b,0,0,0,0);if(!r&&!same(&a,&b))r=-116;if(!r)r=sc(29,fd,0x80081272UL,(long)&size,0,0,0);if(!r&&size!=314572800UL)r=-116;
 for(u32 at=0;at<8192&&!r;at+=4096){u32 intr=0;long n;do{n=sc(67,fd,(long)(s->data+at),4096,at,0,0);}while(n==-4&&++intr<=16);if(n!=4096)r=n<0?n:-5;else s->length=at+4096;}
 if(!r){r=sc(80,fd,(long)&b,0,0,0,0);if(!r&&!same(&a,&b))r=-116;}if(!r){r=st(node,&b);if(!r&&!same(&a,&b))r=-116;}c=cl(fd);if(c)r=c;s->status=r;return r;}
static long budget(void){struct Stat a,b;struct FS fs;long r=st("/tmp/jiritsu",&a),fd,c;if(r)return r;if((a.mode&0170000)!=0040000)return-13;fd=op("/tmp/jiritsu",READ_FLAGS|16384);if(fd<0)return fd;
 r=sc(80,fd,(long)&b,0,0,0,0);if(!r&&!same(&a,&b))r=-116;if(!r)r=sc(44,fd,(long)&fs,0,0,0,0);c=cl(fd);if(c)return c;if(r)return r;
 if(fs.type!=0x4d44||fs.bsize<=0||fs.frsize<=0)return-13;u64 unit=(u64)fs.frsize,max=~(u64)0;if(fs.bavail>max/unit)return-75;u64 avail=fs.bavail*unit,clusters=MAX_REPORT/unit+(MAX_REPORT%unit!=0);if(clusters>max-2||clusters+2>max/unit)return-75;u64 reserve=(clusters+2)*unit;if(avail<reserve||avail-reserve<8388608)return-28;
 u8*p=sec[15].data;p64(p,(u64)fs.type);p64(p+8,(u64)fs.bsize);p64(p+16,fs.blocks);p64(p+24,fs.bfree);p64(p+32,fs.bavail);p64(p+40,fs.files);p64(p+48,fs.ffree);p64(p+56,(u64)fs.namelen);p64(p+64,(u64)fs.frsize);p64(p+72,(u64)fs.flags);sec[15].length=80;sec[15].status=0;return 0;}
static long output(long fd,u32 size){u32 at=0,calls=0,intr=0;while(at<size){u32 n=size-at;if(n>4096)n=4096;if(++calls>40)return-5;long v=sc(64,fd,(long)(report+at),n,0,0,0);if(v==-4&&++intr<=16)continue;if(v<=0||(u64)v>n)return v<0?v:-5;at+=(u32)v;}return 0;}

static long claim(void){struct Stat s;long r=st(outpath,&s);if(r!=-2)return r?r:-17;r=st(pending,&s);if(r!=-2)return r?r:-17;
 output_fd=op(pending,READ_FLAGS|1|64|128);if(output_fd<0)return output_fd;
 r=sc(80,output_fd,(long)&output_stat,0,0,0,0);if(!r&&(!regular(&output_stat)||output_stat.nlink!=1||output_stat.size))r=-13;
 if(!r)r=sc(82,output_fd,0,0,0,0,0);return r;}
static void publish(u32 size){struct Stat b;long r,c;if(output_fd<0)return;
 r=output(output_fd,size);if(!r)r=sc(82,output_fd,0,0,0,0,0);c=cl(output_fd);output_fd=-1;if(c)r=c;
 if(!r){r=st(pending,&b);if(!r&&(output_stat.dev!=b.dev||output_stat.ino!=b.ino||output_stat.mode!=b.mode||output_stat.uid!=b.uid||output_stat.gid!=b.gid||b.nlink!=1||b.size!=size))r=-116;}
 if(!r)(void)sc(276,-100,(long)pending,-100,(long)outpath,1,0);}
static void io_start(u32 slot){sec[slot].length=32;sec[slot].status=0;for(u32 i=0;i<4;i++)p64(sec[slot].data+8*i,(u64)-125);}
/* A mutation write is attempted ONCE, including EINTR or a short return. */
static long change(u32 slot,const char*path,u8 byte,u32*attempted){struct Stat a,b;struct FS fs;long r,fd,c,w=-125;io_start(slot);r=st(path,&a);
 if(!r&&!regular(&a))r=-13;if(r){p64(sec[slot].data,(u64)r);sec[slot].status=r;return r;}
 fd=op(path,READ_FLAGS|1);p64(sec[slot].data,(u64)(fd<0?fd:0));if(fd<0){sec[slot].status=fd;return fd;}
 r=sc(80,fd,(long)&b,0,0,0,0);if(!r&&!same(&a,&b))r=-116;if(!r)r=sc(44,fd,(long)&fs,0,0,0,0);if(!r&&fs.type!=0x62656572)r=-13;
 p64(sec[slot].data+24,(u64)r);if(!r){*attempted=1;w=sc(64,fd,(long)&byte,1,0,0,0);p64(sec[slot].data+8,(u64)w);if(w!=1)r=w<0?w:-5;}
 c=cl(fd);p64(sec[slot].data+16,(u64)c);if(c)r=c;sec[slot].status=r;return r;}
static long openlog(long*fd){struct Stat a,b;long r=st("/dev/kmsg",&a);io_start(17);
 if(!r&&((a.mode&0170000)!=0020000||!a.ino||!a.nlink))r=-13;if(r){p64(sec[17].data,(u64)r);return sec[17].status=r;}
 statbytes(sec[18].data,&a);sec[18].length=48;sec[18].status=0;*fd=op("/dev/kmsg",READ_FLAGS);p64(sec[17].data,(u64)(*fd<0?*fd:0));if(*fd<0)return sec[17].status=*fd;
 r=sc(80,*fd,(long)&b,0,0,0,0);if(!r&&!same(&a,&b))r=-116;long seek=-125;if(!r){seek=sc(62,*fd,0,2,0,0,0);if(seek<0)r=seek;}p64(sec[17].data+8,(u64)seek);return sec[17].status=r;}
static long readlog(long fd){u32 calls=0,intr=0;long r=-11;sec[14].status=0;
 while(calls++<32){long n=sc(63,fd,(long)logpiece,8192,0,0,0);if(n==-4&&++intr<=16)continue;if(n<=0){r=n<0?n:-5;break;}if(n>8192||(u64)n>sec[14].cap-sec[14].length){r=-75;break;}
  for(u32 i=0;i<(u32)n;i++)sec[14].data[sec[14].length++]=logpiece[i];
  for(u32 i=0;i+11<=(u32)n;i++)if(equal(logpiece+i,(const u8*)"dropped wbi",11)){flags|=256;r=0;break;}if(!r)break;
 }sec[14].status=r;p64(sec[17].data+16,(u64)r);return r;}
static long close_log(long fd){struct Stat now;long r=st("/dev/kmsg",&now),c;if(!r){u8 raw[48];statbytes(raw,&now);if(sec[18].length!=48||!equal(raw,sec[18].data,48))r=-116;}
 c=cl(fd);p64(sec[17].data+24,(u64)c);if(c)r=c;sec[17].status=r;return r;}
static long i64at(const u8*p){u64 v=0;for(u32 i=0;i<8;i++)v|=(u64)p[i]<<(8*i);return(long)v;}
static int admissible_header(const u8*p){u8 any=0;for(u32 i=0;i<512;i++)any|=p[i];return !any||equal(p,(const u8*)"WBI2",4);}
static int boot_format(const u8*p){for(u32 i=0;i<37;i++){if(i==36){if(p[i]!='\n')return 0;}else if(i==8||i==13||i==18||i==23){if(p[i]!='-')return 0;}else if(!((p[i]>='0'&&p[i]<='9')||(p[i]>='a'&&p[i]<='f')))return 0;}return 1;}
static void run(void){static const u32 caps[20]={64,128,16,64,48,64,64,16,8192,8192,16,64,32,32,32768,80,48,32,48,576};long unlink_status=sc(35,-100,(long)"/tmp/jiritsu/libJit.so",0,0,0,0),status=0,logfd=-1,r;u32 at=0;
 closes=bad=flags=stage=drop_attempted=mode_attempted=0;output_fd=-1;for(u32 i=0;i<576;i++)request_data[i]=0;
 for(u32 i=0;i<COUNT;i++){sec[i].cap=caps[i];sec[i].length=0;sec[i].status=-125;if(i==8)sec[i].data=before1;else if(i==9)sec[i].data=after1;else if(i==19)sec[i].data=request_data;else{sec[i].data=arena+at;at+=caps[i];}}
 if(!unlink_status)flags|=32;else status=unlink_status;for(u32 i=0;i<4;i++){long v=sc(174+i,0,0,0,0,0,0);ids[i]=v>=0&&(u64)v<=0xffffffffUL?(u32)v:0xffffffffU;if(v&&!status)status=v<0?v:-13;}if(!(ids[0]|ids[1]|ids[2]|ids[3]))flags|=8;long pid=sc(172,0,0,0,0,0,0);if(pid<=0&&!status)status=pid<0?pid:-22;
 stage=1;if(!status){long n=text(reqpath,request_data,576,0);if(n!=576)status=n<0?n:-22;else{u8 nz=0,pad=0;for(u32 i=8;i<24;i++)nz|=request_data[i];for(u32 i=61;i<64;i++)pad|=request_data[i];if(!equal(request_data,(const u8*)"M4WDRQ02",8)||!nz||pad||!boot_format(request_data+24)||!admissible_header(request_data+64))status=-22;else{flags|=1;sec[19].length=576;sec[19].status=0;}}}
 if(!status){stage=2;status=observe(1,"/version.txt",0);}if(!status){if(sec[0].length!=19||!equal(sec[0].data,(const u8*)"30181_18.2026041801",19))status=-116;else flags|=16;}
 if(!status)status=observe(2,"/proc/sys/kernel/random/boot_id",0x9fa0);if(!status&&(sec[1].length!=37||!equal(sec[1].data,request_data+24,37)))status=-116;
 if(!status)status=observe(3,"/sys/power/image_mode",0x62656572);if(!status)status=observe(4,"/sys/power/image_dev",0x62656572);if(!status&&(sec[2].length!=2||!equal(sec[2].data,(const u8*)"2\n",2)||sec[3].length!=6||!equal(sec[3].data,(const u8*)"*wbi4\n",6)))status=-116;
 if(!status){stage=3;status=st(node,&baseline);sec[4].status=status;if(!status){statbytes(sec[4].data,&baseline);sec[4].length=48;if((baseline.mode&0170000)!=0060000||!baseline.ino||!baseline.nlink||major(baseline.rdev)!=252||minor(baseline.rdev)!=133)status=sec[4].status=-116;}}
 if(!status)status=observe(6,"/sys/dev/block/252:133/dev",0x62656572);if(!status)status=observe(7,"/sys/dev/block/252:133/size",0x62656572);if(!status)status=observe(8,"/sys/dev/block/252:133/ro",0x62656572);
 if(!status&&(sec[5].length!=8||!equal(sec[5].data,(const u8*)"252:133\n",8)||sec[6].length!=7||!equal(sec[6].data,(const u8*)"614400\n",7)||sec[7].length!=2||(sec[7].data[0]!='0'&&sec[7].data[0]!='1')||sec[7].data[1]!='\n'))status=-116;
 if(!status)status=readblock(8);if(!status&&!equal(before1,request_data+64,512))status=-116;if(!status)flags|=4;
 if(!status){stage=4;status=budget();if(!status)flags|=64;}if(!status){status=claim();if(status&&output_fd>=0){/* Owned empty claim can carry a safe pre-write failure report. */}}
 if(!status){stage=5;status=openlog(&logfd);}
 if(!status){stage=6;status=change(12,"/sys/power/image_drop",'1',&drop_attempted);}
 /* The drop may have succeeded even when its close failed. Never skip mode0 in that case. */
 if(sec[12].length==32&&i64at(sec[12].data+8)==1){stage=7;r=change(13,"/sys/power/image_mode",'0',&mode_attempted);if(!status)status=r;}
 if(drop_attempted){stage=8;r=observe(11,"/sys/power/image_mode",0x62656572);if(!status)status=r;r=observe(12,"/sys/power/image_dev",0x62656572);if(!status)status=r;
  if(!sec[10].status&&!sec[11].status&&sec[10].length==2&&equal(sec[10].data,(const u8*)"0\n",2)&&sec[11].length==6&&equal(sec[11].data,(const u8*)"*wbi4\n",6))flags|=512;else if(!status)status=-116;
  r=readblock(9);if(!status)status=r;if(logfd>=0){r=readlog(logfd);if(!status)status=r;}}
 if(logfd>=0){r=close_log(logfd);if(!status)status=r;logfd=-1;}
 if(!status){struct Stat s;status=st(node,&s);sec[16].status=status;if(!status){statbytes(sec[16].data,&s);sec[16].length=48;if(!same(&baseline,&s))status=sec[16].status=-116;}}
 if(!status&&!bad&&(flags&(256|512))==(256|512)){flags|=128;stage=9;}
 r=budget();if(r){if(output_fd>=0){(void)cl(output_fd);output_fd=-1;}return;}flags|=64;if(!bad)flags|=2;else if(!status)status=-5;
 if(output_fd<0){/* No claim means no mutation occurred. Publish a fresh owned diagnostic if possible. */if(drop_attempted||mode_attempted)return;r=claim();if(r){if(output_fd>=0)(void)cl(output_fd);output_fd=-1;return;}}
 for(u32 i=0;i<HEADER;i++)report[i]=0;for(u32 i=0;i<8;i++)report[i]=((const u8*)"M4WDR002")[i];p32(report+8,2);for(u32 i=0;i<16;i++)report[16+i]=request_data[8+i];p32(report+32,1);p32(report+36,stage);p64(report+40,(u64)status);p64(report+48,(u64)unlink_status);for(u32 i=0;i<4;i++)p32(report+56+4*i,ids[i]);p64(report+72,(u64)pid);p32(report+80,flags);p32(report+84,COUNT);p32(report+88,closes);p32(report+92,bad);p32(report+96,drop_attempted);p32(report+100,mode_attempted);
 at=HEADER;for(u32 i=0;i<COUNT;i++){p32(report+at,i+1);p32(report+at+4,sec[i].length);p64(report+at+8,(u64)sec[i].status);at+=16;for(u32 j=0;j<sec[i].length;j++)report[at++]=sec[i].data[j];}p32(report+12,at);publish(at);
}
#ifdef WD_TEST
void a7m4_wbi_drop_run(void){run();}
#else
__attribute__((visibility("default"))) void _init(void){run();}
#endif
