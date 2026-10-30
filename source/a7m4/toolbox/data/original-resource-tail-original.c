/* SPDX-License-Identifier: MIT
 * Independent original-EOF runtime tail restoration profile. Disk and runtime
 * expectations are separate, both derived from complete verified endpoints.
 * The retained upstream tail helper and read-only helper are not modified.
 */
/* Per-plan owned UXC appended-tail restoration, derived from the separately
 * retained R067 native boundary. Distributable source contains no camera bytes,
 * body inode/device IDs, ownership IDs, or virtual addresses. Its generated
 * private manifest fixes exactly one of seventy explicit allowed resource
 * paths, source/target lengths, plan identity and last-partial/tail bytes.
 * mode0 observes native-derived source identity/ranges and raw preimages.
 * Mode1 binds same-session inspection, privately shadows canonical original
 * EOF RAM, then applies the retained upstream remap/truncate/RO sequence.
 * MREMAP_FIXED failure is UNKNOWN, even before any successful remap count.
 * No prefix overwrite, automatic retry, settings, WBI, NOR, shell or network.
 */
#ifdef TARGET_ABI
#define _GNU_SOURCE 1
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <stddef.h>
#endif
typedef unsigned long u64;typedef unsigned int u32;typedef long i64;typedef unsigned char u8;
#define RD (0x8000UL|0x80000UL)
#define DIR 0x4000UL
#define CAP 65536U
#define SOURCE_SIZE ((u64)TR_SOURCE_SIZE)
#define STOCK_SIZE ((u64)TR_TARGET_SIZE)
#define SHADOW_BEGIN (STOCK_SIZE&~4095UL)
#define SHADOW_END ((SOURCE_SIZE+4095UL)&~4095UL)
#define RUNTIME_END ((STOCK_SIZE+4095UL)&~4095UL)
#define SOURCE_INO (R.source_ino)
#define SOURCE_DEV (R.source_dev)
#ifdef TARGET_ABI
_Static_assert(RD==(O_NOFOLLOW|O_CLOEXEC)&&DIR==O_DIRECTORY,"flags");
_Static_assert((MAP_PRIVATE|MAP_ANONYMOUS)==0x22&&(MREMAP_MAYMOVE|MREMAP_FIXED)==3,"mapflags");
#endif
static i64 sc(i64 n,i64 a,i64 b,i64 c,i64 d,i64 e,i64 f){register i64 x0 __asm__("x0")=a,x1 __asm__("x1")=b,x2 __asm__("x2")=c,x3 __asm__("x3")=d,x4 __asm__("x4")=e,x5 __asm__("x5")=f,x8 __asm__("x8")=n;__asm__ volatile("svc 0":"+r"(x0):"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5),"r"(x8):"memory","cc");return x0;}
struct Stat{u64 dev,ino;u32 mode,nlink,uid,gid;u64 rdev,pad1;i64 size;u32 blksize,pad2;u64 blocks,rest[7];};
struct FS{i64 type,bsize;u64 blocks,bfree,bavail,files,ffree;u32 fsid[2];i64 namelen,frsize,flags,spare[4];};
struct Range{u64 va,len,off,prot;};
struct Identity{u64 dev,ino,size;u32 mode,uid,gid,nlink;};
struct Request{u8 magic[8];u32 mode,count;u8 nonce[16],plan_id[32];u64 pid;struct Identity identity;u64 target_size,reserved;struct Range ranges[4];};
struct Result{u8 magic[8];u32 version,mode;u8 nonce[16],plan_id[32];u32 phase,index,range_count,cross_pids,cross_matches,mremap_attempts,changed_aliases,flags;i64 status,euid,pid,plugin_unlink,close_errors,readonly,remount,auxv_status,source_status;u64 source_dev,source_ino,source_size;u32 source_mode,source_uid,source_gid,source_nlink;u64 target_size,page_size,anon_bytes,bytes_truncated;u32 total,preimage_bytes,offender_pid,reserved;struct Range ranges[4];u64 scratch[4];struct Stat source_stat;};
_Static_assert(sizeof(struct Stat)==128&&sizeof(struct FS)==120,"statABI");
_Static_assert(sizeof(struct Identity)==40&&sizeof(struct Request)==256&&sizeof(struct Result)==544,"wireABI");
#ifdef TARGET_ABI
_Static_assert(sizeof(struct Stat)==sizeof(struct stat),"independent stat size");
_Static_assert(offsetof(struct Stat,dev)==offsetof(struct stat,st_dev),"stat dev");
_Static_assert(offsetof(struct Stat,ino)==offsetof(struct stat,st_ino),"stat ino");
_Static_assert(offsetof(struct Stat,mode)==offsetof(struct stat,st_mode),"stat mode");
_Static_assert(offsetof(struct Stat,nlink)==offsetof(struct stat,st_nlink),"stat nlink");
_Static_assert(offsetof(struct Stat,uid)==offsetof(struct stat,st_uid),"stat uid");
_Static_assert(offsetof(struct Stat,gid)==offsetof(struct stat,st_gid),"stat gid");
_Static_assert(offsetof(struct Stat,size)==offsetof(struct stat,st_size),"stat size");
_Static_assert(offsetof(struct Stat,blksize)==offsetof(struct stat,st_blksize),"stat blksize");
_Static_assert(offsetof(struct Stat,blocks)==offsetof(struct stat,st_blocks),"stat blocks");
#endif

#include PATCH_MANIFEST
static const char path[]=TR_PATH,plugin[]="/tmp/jiritsu/libJit.so",rqpath[]="/tmp/jiritsu/a7m4.original-tail-restore.request",outpath[]="/tmp/jiritsu/a7m4.original-tail-restore.result";
static const u8 magic[8]={'A','7','T','O','0','0','0','1'};
static union{u64 align;u8 bytes[CAP];}out;
#define R (*(struct Result*)out.bytes)
static u8 maps[131072],proc_dents[4096],mounts[8192],io[4096],rqbuf[257];static u32 maps_len;
static i64 source_fd=-1;static struct Identity initial;static struct Request*q=(struct Request*)rqbuf;
static const char allowed_names[8][42]={"image_00_23_IPSX.uxc","image_00_32_IPSX.uxc","string_english_horizontal.uxc","string_english_vertical.uxc","string_simplifiedchinese_horizontal.uxc","string_simplifiedchinese_vertical.uxc","string_traditionalchinese_horizontal.uxc","string_traditionalchinese_vertical.uxc"};
static int same(const u8*a,const u8*b,u64 n){for(u64 i=0;i<n;i++)if(a[i]!=b[i])return 0;return 1;}
static void copy(u8*a,const u8*b,u64 n){for(u64 i=0;i<n;i++)a[i]=b[i];}
static u32 length(const char*s){u32 n=0;while(s[n])n++;return n;}
static i64 plan_guard(void){const char prefix[]="/usr/share/app/";u32 n=length(path),p=sizeof(prefix)-1;int allowed=0;if(n>p&&same((const u8*)path,(const u8*)prefix,p))for(u32 i=0;i<8;i++){u32 z=length(allowed_names[i]);if(n==p+z&&same((const u8*)path+p,(const u8*)allowed_names[i],z))allowed=1;}if(!allowed||!STOCK_SIZE||SOURCE_SIZE<=STOCK_SIZE||SOURCE_SIZE-STOCK_SIZE>43008UL||SOURCE_SIZE>16777216UL||SHADOW_END<SHADOW_BEGIN||SHADOW_END-SHADOW_BEGIN>49152||sizeof(tr_expected_shadow)!=SHADOW_END-SHADOW_BEGIN||sizeof(tr_runtime_shadow)!=(RUNTIME_END-SHADOW_BEGIN?RUNTIME_END-SHADOW_BEGIN:1)||TR_PID<=0||sizeof(tr_boot_id)!=37||sizeof(tr_plan_id)!=32)return -22;u32 any=0;for(u32 i=0;i<32;i++)any|=tr_plan_id[i];if(!any)return -22;for(u64 at=SOURCE_SIZE;at<SHADOW_END;at++)if(tr_expected_shadow[at-SHADOW_BEGIN])return -22;for(u64 at=SHADOW_BEGIN;at<RUNTIME_END;at++)if(tr_runtime_shadow[at-SHADOW_BEGIN]!=(at<STOCK_SIZE?tr_expected_shadow[at-SHADOW_BEGIN]:0))return -22;return 0;}
static i64 op(const char*p,i64 flags){return sc(56,-100,(i64)p,flags,0600,0,0);}
static i64 cl(i64*fd){if(*fd<0)return 0;i64 n=sc(57,*fd,0,0,0,0,0);*fd=-1;if(n)R.close_errors++;return n;}
static i64 all(const char*p,u8*b,u32 cap){i64 fd=op(p,RD);if(fd<0)return fd;u32 at=0;i64 e=0;while(at<cap){i64 n=sc(63,fd,(i64)(b+at),cap-at,0,0,0);if(n<0){e=n;break;}if(!n)break;if((u64)n>cap-at){e=-5;break;}at+=(u32)n;}if(!e&&at==cap)e=-75;i64 c=cl(&fd);return e?e:c?c:at;}
static i64 read_at(i64 fd,u8*b,u32 n,u64 at){u32 done=0;while(done<n){i64 k=sc(67,fd,(i64)(b+done),n-done,at+done,0,0);if(k<=0||(u64)k>n-done)return k<0?k:-5;done+=(u32)k;}return 0;}
static int number(const u8*b,u32 end,u32*a,u64*v,u32 radix){u64 n=0;u32 start=*a;while(*a<end){u8 c=b[*a];u32 d=c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:99;if(d>=radix)break;if(n>(~0UL-d)/radix)return 0;n=n*radix+d;(*a)++;}*v=n;return *a>start;}
struct Mapping{u64 va,end,off,major,minor,ino,prot;u32 priv,path_at,path_end;};
static int parse(u32 begin,u32 end,struct Mapping*m){u32 a=begin;int ok=number(maps,end,&a,&m->va,16)&&a<end&&maps[a++]=='-'&&number(maps,end,&a,&m->end,16)&&a<end&&maps[a++]==' ';if(!ok||a+5>=end)return 0;if((maps[a]!='r'&&maps[a]!='-')||(maps[a+1]!='w'&&maps[a+1]!='-')||(maps[a+2]!='x'&&maps[a+2]!='-')||(maps[a+3]!='p'&&maps[a+3]!='s')||maps[a+4]!=' ')return 0;m->prot=(maps[a]=='r'?1:0)|(maps[a+1]=='w'?2:0)|(maps[a+2]=='x'?4:0);m->priv=maps[a+3]=='p';a+=5;if(!number(maps,end,&a,&m->off,16)||a>=end||maps[a++]!=' '||!number(maps,end,&a,&m->major,16)||a>=end||maps[a++]!=':'||!number(maps,end,&a,&m->minor,16)||a>=end||maps[a++]!=' ')return 0;while(a<end&&maps[a]==' ')a++;if(!number(maps,end,&a,&m->ino,10)||m->end<=m->va||m->off>~0UL-(m->end-m->va))return 0;while(a<end&&maps[a]==' ')a++;m->path_at=a;m->path_end=end;return 1;}
static int named(const struct Mapping*m,const char*p){u32 n=length(p);return m->path_end-m->path_at==n&&same(maps+m->path_at,(const u8*)p,n);}
static int deleted(const struct Mapping*m){const u8 suffix[]=" (deleted)";return m->path_end-m->path_at>=sizeof(suffix)-1&&same(maps+m->path_end-(sizeof(suffix)-1),suffix,sizeof(suffix)-1);}
static int devino(const struct Mapping*m,u64 dev,u64 ino){u64 major=((dev>>8)&0xfff)|((dev>>32)&~0xfffUL),minor=(dev&0xff)|((dev>>12)&~0xffUL);return m->ino==ino&&m->major==major&&m->minor==minor;}
static int overlap(const struct Mapping*m){return m->off<SHADOW_END&&m->off+m->end-m->va>SHADOW_BEGIN;}
static i64 loadmaps(const char*p){i64 n=all(p,maps,sizeof(maps));if(n<0)return n;if(n&&maps[n-1]!='\n')return -22;maps_len=(u32)n;return 0;}
static i64 self_unlink(void){i64 fd=op(plugin,RD);if(fd<0)return fd;struct Stat s;i64 e=sc(80,fd,(i64)&s,0,0,0,0);u32 found=0;if(!e&&((s.mode&0170000)!=0100000||s.uid||s.nlink!=1))e=-22;for(u32 a=0,start=0;!e&&a<maps_len;a++)if(maps[a]=='\n'){struct Mapping m;if(!parse(start,a,&m)){e=-22;break;}start=a+1;if(named(&m,plugin)&&devino(&m,s.dev,s.ino)&&(m.prot&1)&&m.priv)found=1;}if(!e&&!found)e=-18;if(!e)e=sc(35,-100,(i64)plugin,0,0,0,0);if(!e){e=sc(80,fd,(i64)&s,0,0,0,0);if(!e&&s.nlink)e=-116;}i64 c=cl(&fd);return e?e:c;}
static i64 workspace(void){struct FS s;i64 e=sc(43,(i64)"/tmp/jiritsu",(i64)&s,0,0,0,0);if(e)return e;if(s.type!=0x4d44||s.frsize<=0||s.frsize>65536||s.bavail>~0UL/(u64)s.frsize)return -22;return s.bavail*s.frsize>=8388608UL+CAP+2*(u64)s.frsize?0:-28;}
static i64 pagesize(void){i64 n=all("/proc/self/auxv",io,sizeof(io));if(n<0)return n;if(n%16)return -22;u32 found=0,end=0;for(u32 at=0;at<(u32)n;at+=16){u64*t=(u64*)(io+at);if(!t[0]){end=1;break;}if(t[0]==6){if(found++)return -22;R.page_size=t[1];}}return found==1&&end&&R.page_size==4096?0:-22;}
static int stat_same(const struct Stat*s,u64 size){return s->dev==SOURCE_DEV&&s->ino==SOURCE_INO&&s->mode==R.source_mode&&s->uid==R.source_uid&&s->gid==R.source_gid&&s->nlink==R.source_nlink&&s->size==(i64)size;}
static i64 stable(u64 size){struct Stat s;i64 e=sc(80,source_fd,(i64)&s,0,0,0,0);if(!e&&!stat_same(&s,size))e=-116;if(!e)e=sc(79,-100,(i64)path,(i64)&s,0x100,0,0);return e?e:stat_same(&s,size)?0:-116;}
static i64 source_check(void){i64 e=stable(SOURCE_SIZE);if(e)return e;for(u64 at=SHADOW_BEGIN;at<SOURCE_SIZE;){u32 n=SOURCE_SIZE-at>sizeof(io)?sizeof(io):(u32)(SOURCE_SIZE-at);e=read_at(source_fd,io,n,at);if(e)return e;if(!same(io,tr_expected_shadow+at-SHADOW_BEGIN,n))return -84;at+=n;}return 0;}
static i64 collect(int observe){i64 e=loadmaps("/proc/self/maps");if(e)return e;u32 count=0;u64 bytes=0;for(u32 at=0,start=0;at<maps_len;at++)if(maps[at]=='\n'){struct Mapping m;if(!parse(start,at,&m))return -22;start=at+1;
 if(named(&m,path)&&!devino(&m,SOURCE_DEV,SOURCE_INO))return -116;if(!devino(&m,SOURCE_DEV,SOURCE_INO)||!overlap(&m))continue;if(!m.priv||m.prot!=1||(m.va|m.end|m.off)&4095)return -13;u64 a=m.off>SHADOW_BEGIN?m.off:SHADOW_BEGIN,z=m.off+m.end-m.va<SHADOW_END?m.off+m.end-m.va:SHADOW_END;if(a>=z)continue;if(z>RUNTIME_END)return -13;if(count>=4||bytes+z-a>61440||sizeof(R)+bytes+z-a>CAP)return -75;struct Range v={m.va+a-m.off,z-a,a,1};if(observe)R.ranges[count]=v;else if(!same((u8*)&v,(u8*)&R.ranges[count],sizeof(v)))return -116;count++;bytes+=z-a;}
 if(observe){R.range_count=count;R.preimage_bytes=(u32)bytes;R.total=sizeof(R)+(u32)bytes;}else if(count!=R.range_count||bytes!=R.preimage_bytes)return -116;return 0;}
static i64 pidpath(char*out,u64 pid){if(!pid||pid>4194304)return -22;const char p[]="/proc/";u32 n=0;for(;n<sizeof(p)-1;n++)out[n]=p[n];char digits[16];u32 count=0;while(pid){digits[count++]=(char)('0'+pid%10);pid/=10;}while(count)out[n++]=digits[--count];const char suffix[]="/maps";for(u32 i=0;i<sizeof(suffix);i++)out[n++]=suffix[i];return 0;}
static i64 other_processes(void){i64 fd=op("/proc",RD|DIR);if(fd<0)return fd;R.cross_pids=R.cross_matches=0;R.flags&=~64U;i64 e=0;u32 rounds=0;while(!e){if(rounds++>=128){e=-75;break;}i64 n=sc(61,fd,(i64)proc_dents,sizeof(proc_dents),0,0,0);if(n<0){e=n;break;}if(!n)break;if(n>(i64)sizeof(proc_dents)){e=-5;break;}for(u32 at=0;at<(u32)n;){if((u32)n-at<20){e=-22;break;}u32 reclen=proc_dents[at+16]|((u32)proc_dents[at+17]<<8);if(reclen<20||reclen>(u32)n-at){e=-22;break;}u32 start=at+19,end=at+reclen,pos=start;u64 pid=0;while(pos<end&&proc_dents[pos]>='0'&&proc_dents[pos]<='9')pos++;if(pos<end&&pos>start&&proc_dents[pos]==0){u32 a=start;if(!number(proc_dents,pos,&a,&pid,10)){e=-22;break;}if(pid!=(u64)R.pid){if(R.cross_pids++>=4096){e=-75;break;}char p[40];e=pidpath(p,pid);if(e)break;e=loadmaps(p);if(e==-2){e=0;at+=reclen;continue;}if(e)break;for(u32 k=0,line=0;k<maps_len;k++)if(maps[k]=='\n'){struct Mapping m;if(!parse(line,k,&m)){e=-22;break;}line=k+1;if(devino(&m,SOURCE_DEV,SOURCE_INO)&&overlap(&m)){R.cross_matches++;R.offender_pid=(u32)pid;e=-16;break;}}if(e)break;}}at+=reclen;}}
 i64 c=cl(&fd);if(!e)e=c;if(!e)R.flags|=64;return e;}
static i64 snapshot(void){u32 done=0;for(u32 i=0;i<R.range_count;i++){struct Range*v=&R.ranges[i];const u8*memory=(const u8*)v->va;if(!same(memory,tr_runtime_shadow+v->off-SHADOW_BEGIN,v->len))return -84;copy(out.bytes+sizeof(R)+done,memory,v->len);done+=(u32)v->len;}R.flags|=128;return 0;}
static i64 prepared(void){for(u32 i=0;i<R.range_count;i++){R.index=i;struct Range*v=&R.ranges[i];i64 p=sc(222,0,v->len,3,0x22,-1,0);if(p<0&&p>=-4095)return p;if(!p||(u64)p&4095)return -22;R.scratch[i]=(u64)p;R.anon_bytes+=v->len;copy((u8*)p,(u8*)v->va,v->len);if(!same((u8*)p,tr_runtime_shadow+v->off-SHADOW_BEGIN,v->len))return -84;i64 e=sc(226,p,v->len,1,0,0,0);if(e)return e;}return 0;}
static i64 installed(void){i64 e=loadmaps("/proc/self/maps");if(e)return e;u32 cover[4]={0};for(u32 at=0,start=0;at<maps_len;at++)if(maps[at]=='\n'){struct Mapping m;if(!parse(start,at,&m))return -22;start=at+1;if(devino(&m,SOURCE_DEV,SOURCE_INO)&&overlap(&m))return -16;for(u32 i=0;i<R.range_count;i++){struct Range*v=&R.ranges[i];u64 end=v->va+v->len;if(m.va<end&&m.end>v->va){if(m.va>v->va||m.end<end||m.ino||m.major||m.minor||!m.priv||m.prot!=1)return -13;cover[i]++;}}}for(u32 i=0;i<R.range_count;i++){struct Range*v=&R.ranges[i];if(cover[i]!=1||!same((u8*)v->va,tr_runtime_shadow+v->off-SHADOW_BEGIN,v->len))return -84;}R.flags|=8;return 0;}
/* Match the exact mountpoint and filesystem, not a body-specific block name. */
static i64 mount_state(void){i64 n=all("/proc/self/mounts",mounts,sizeof(mounts));if(n<0)return n;u32 count=0;int state=-22;for(u32 begin=0;begin<(u32)n;){u32 end=begin;while(end<(u32)n&&mounts[end]!='\n')end++;u32 a=begin;while(a<end&&mounts[a]!=' ')a++;if(a==end){begin=end+1;continue;}u32 target=++a;while(a<end&&mounts[a]!=' ')a++;if(a-target==4&&same(mounts+target,(const u8*)"/usr",4)){count++;u32 fs=++a;while(a<end&&mounts[a]!=' ')a++;if(a-fs!=4||!same(mounts+fs,(const u8*)"ext2",4))state=-22;else{a++;if(a+2<end&&mounts[a]=='r'&&(mounts[a+2]==','||mounts[a+2]==' '))state=mounts[a+1]=='o'?0:mounts[a+1]=='w'?1:-22;}}begin=end+1;}return count==1?state:-22;}
static i64 remount(int ro){i64 e=sc(40,0,(i64)"/usr",0,0xc30UL+(ro?1:0),0,0);if(e)return e;e=mount_state();return e<0?e:e==(ro?0:1)?0:-30;}
static void publish(void){i64 fd=op(outpath,RD|1|64|128);if(fd<0)return;u32 done=0;while(done<R.total){i64 n=sc(64,fd,(i64)(out.bytes+done),R.total-done,0,0,0);if(n<=0||(u64)n>R.total-done)break;done+=(u32)n;}sc(82,fd,0,0,0,0,0);cl(&fd);}
__attribute__((visibility("default")))void _init(void){copy(R.magic,magic,8);copy(R.plan_id,tr_plan_id,32);R.version=1;R.mode=0xffffffffU;R.total=sizeof(R);R.plugin_unlink=-1;R.readonly=-1;R.euid=sc(175,0,0,0,0,0,0);R.pid=sc(172,0,0,0,0,0,0);R.source_size=SOURCE_SIZE;R.target_size=STOCK_SIZE;if(R.euid||R.pid!=TR_PID)R.status=-13;if(!R.status)R.status=plan_guard();i64 n=0;if(!R.status){n=all(rqpath,rqbuf,sizeof(rqbuf));if(n!=sizeof(*q))R.status=n<0?n:-22;else{u32 any=0;copy(R.nonce,q->nonce,16);for(u32 i=0;i<16;i++)any|=q->nonce[i];R.mode=q->mode;if(!same(q->magic,magic,8)||!same(q->plan_id,tr_plan_id,32)||q->mode>1||!any)R.status=-22;if(!R.status&&!q->mode){const u8*rest=(u8*)&q->pid;for(u32 i=0;i<192;i++)if(rest[i])R.status=-22;if(q->count)R.status=-22;}if(!R.status&&q->mode&&(q->pid!=(u64)R.pid||q->count>4||q->target_size!=STOCK_SIZE||q->reserved))R.status=-116;}}
 R.phase=1;if(!R.status){u8 boot[38];i64 n=all("/proc/sys/kernel/random/boot_id",boot,sizeof(boot));if(n!=37||boot[36]!=10||!same(boot,(const u8*)tr_boot_id,36))R.status=n<0?n:-116;}if(!R.status)R.status=loadmaps("/proc/self/maps");if(!R.status){R.plugin_unlink=self_unlink();R.status=R.plugin_unlink;}if(!R.status)R.status=workspace();if(!R.status){R.auxv_status=pagesize();R.status=R.auxv_status;}if(!R.status){n=mount_state();R.readonly=n==0?0:n==1?-16:n;if(n)R.status=n<0?n:-16;}
 R.phase=2;if(!R.status){source_fd=op(path,RD);if(source_fd<0)R.status=source_fd;else{R.source_status=sc(80,source_fd,(i64)&R.source_stat,0,0,0,0);if(!R.source_status){struct Stat*v=&R.source_stat;if((v->mode&0170000)!=0100000||v->nlink!=1||v->size!=(i64)SOURCE_SIZE||!v->ino)R.source_status=-116;else{R.source_dev=v->dev;R.source_ino=v->ino;R.source_mode=v->mode;R.source_uid=v->uid;R.source_gid=v->gid;R.source_nlink=v->nlink;initial=(struct Identity){v->dev,v->ino,(u64)v->size,v->mode,v->uid,v->gid,v->nlink};if(q->mode&&!same((u8*)&q->identity,(u8*)&initial,sizeof(initial)))R.source_status=-116;}}if(!R.source_status)R.source_status=source_check();R.status=R.source_status;}}
 if(!R.status)R.status=collect(1);if(!R.status&&q->mode&&(q->count!=R.range_count||!same((u8*)q->ranges,(u8*)R.ranges,sizeof(q->ranges))))R.status=-116;if(!R.status)R.status=other_processes();if(!R.status)R.status=collect(0);if(!R.status)R.status=snapshot();
 if(!R.status&&!q->mode){R.phase=3;R.flags|=1;}
 if(!R.status&&q->mode){R.phase=4;R.status=prepared();if(!R.status)R.status=collect(0);if(!R.status)R.status=source_check();if(!R.status)R.status=other_processes();
  for(u32 i=0;i<R.range_count&&!R.status;i++){R.phase=5;R.index=i;R.flags|=2;R.mremap_attempts++;struct Range*v=&R.ranges[i];n=sc(216,R.scratch[i],v->len,v->len,3,v->va,0);if(n!=(i64)v->va){R.flags|=4;R.status=n<0?n:-116;break;}R.changed_aliases++;}
  if(!R.status){R.phase=6;R.status=installed();}if(!R.status)R.status=source_check();if(!R.status)R.status=other_processes();if(!R.status)R.status=installed();
  if(!R.status){R.phase=7;R.remount=remount(0);R.status=R.remount;if(!R.status)R.status=stable(SOURCE_SIZE);if(!R.status){i64 c=cl(&source_fd);if(c)R.status=c;}if(!R.status){source_fd=op(path,RD|2);if(source_fd<0)R.status=source_fd;else R.status=source_check();}if(!R.status){R.phase=8;R.flags|=16;R.status=sc(46,source_fd,STOCK_SIZE,0,0,0,0);if(!R.status){R.flags|=32;R.bytes_truncated=SOURCE_SIZE-STOCK_SIZE;R.status=sc(82,source_fd,0,0,0,0,0);if(!R.status)R.status=stable(STOCK_SIZE);}}{i64 c=cl(&source_fd);if(!R.status&&c)R.status=c;}i64 operation_status=R.status;R.readonly=remount(1);if(!operation_status&&(R.readonly==0||R.readonly==-16)){R.status=R.readonly;R.phase=9;R.flags|=1;}else if(!operation_status)R.status=R.readonly;}
 }
 /* Scratch may be released only before any fixed-remap attempt. After a
  * failed fixed remap, even its source/destination state is not presumed. */
 if(R.status&&!R.mremap_attempts)for(u32 i=0;i<4;i++)if(R.scratch[i]){n=sc(215,R.scratch[i],R.ranges[i].len,0,0,0,0);if(n)R.close_errors++;}
 {i64 c=cl(&source_fd);if(!R.status&&c)R.status=c;}if(R.close_errors)R.flags&=~1U;publish();
}
