/* Version2: fresh bounded allocation scans; capacity proof report672B.
 * Independent Custom1 M9 C/D resource profile; derived from fixed-UXC forward.
 * C windows/append and explicit reference dependencies alone control disk admission.
 * Full protected pages are preserved; the cross-phase runtime digest covers C only.
 * No whole resource SHA comparison. Original reviewed helper is unchanged.
 * Independent fixed-UXC forward window+append worker. MIT adaptation of the
 * reviewed prefix-delta COW/mapping proof mechanism; restore source untouched.
 * No truncate, rename, backup copy, AP/CP/settings/NOR/WBI or automatic inverse.
 * Every resource is inspected before any feature write by the coordinator.
 */
#ifdef TARGET_ABI
#define _GNU_SOURCE 1
#include <fcntl.h>
#endif
typedef unsigned long u64;typedef unsigned int u32;typedef long i64;typedef unsigned char u8;
#define RD (0x8000UL|0x80000UL|0x800UL)
#define DIR 0x4000UL
#define CAP 65536U
#define SOURCE_SIZE ((u64)RD_SOURCE_SIZE)
#define STOCK_SIZE ((u64)RD_TARGET_SIZE)
#define SOURCE_INO (R.source_ino)
#define SOURCE_DEV (R.source_dev)
#ifdef TARGET_ABI
_Static_assert(RD==(O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK)&&DIR==O_DIRECTORY,"flags");
#endif
static i64 sc(i64 n,i64 a,i64 b,i64 c,i64 d,i64 e,i64 f){register i64 x0 __asm__("x0")=a,x1 __asm__("x1")=b,x2 __asm__("x2")=c,x3 __asm__("x3")=d,x4 __asm__("x4")=e,x5 __asm__("x5")=f,x8 __asm__("x8")=n;__asm__ volatile("svc 0":"+r"(x0):"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5),"r"(x8):"memory","cc");return x0;}
struct Stat{u64 dev,ino;u32 mode,nlink,uid,gid;u64 rdev,pad1;i64 size;u32 blksize,pad2;u64 blocks,rest[7];};
struct FS{i64 type,bsize;u64 blocks,bfree,bavail,files,ffree;u32 fsid[2];i64 namelen,frsize,flags,spare[4];};
struct Range{u64 va,len,off,prot;};
struct Identity{u64 dev,ino,size;u32 mode,uid,gid,nlink;};
struct Request{u8 magic[8];u32 mode,count;u8 nonce[16],plan_id[32];u64 pid;struct Identity identity;u64 target_size,reserved;struct Range ranges[4];u8 runtime_sha[32];};
struct Result{u8 magic[8];u32 version,mode;u8 nonce[16],plan_id[32];u32 phase,index,mapping_count,cross_pids,cross_matches,cow_attempts,cow_segments,flags;i64 status,euid,pid,plugin_unlink,close_errors,readonly,remount,auxv_status,source_status;u64 source_dev,source_ino,source_size;u32 source_mode,source_uid,source_gid,source_nlink;u64 target_size,page_size,bytes_written,bytes_cow_preserved;u32 total,window_count,write_attempts,writes_completed;struct Range mappings[4];u64 cow_segments_expected,cow_bytes_expected,offender_pid,reserved;struct Stat source_stat;u64 usr_type,usr_unit,usr_available,usr_required,append_bytes,append_attempts,append_completed,unknown_dirty_blocks;u8 runtime_sha[32];u64 scanned_dirty_blocks,scanned_pending_files,capacity_scan_complete,capacity_reserved;};
_Static_assert(sizeof(struct Stat)==128&&sizeof(struct FS)==120,"statABI");
_Static_assert(sizeof(struct Identity)==40&&sizeof(struct Request)==288&&sizeof(struct Result)==672,"wireABI");
struct DeltaWindow{u64 at;u32 size;const u8*before,*after;};
#include PATCH_MANIFEST
typedef u64 U;typedef u32 W;typedef u8 B;
#include "resource-sha256.h"
static const char path[]=RD_PATH,plugin[]="/tmp/jiritsu/libJit.so",rqpath[]="/tmp/jiritsu/m4.resource-forward.request",outpath[]="/tmp/jiritsu/m4.resource-forward.result";
static const u8 magic[8]={'M','4','R','F','0','0','0','1'};
static union{u64 align;u8 bytes[CAP];}out;
#define R (*(struct Result*)out.bytes)
static u8 maps[131072],proc_dents[4096],mounts[8192],io[4096],memory[512],verify[512],runtime_snapshot[65536],rqbuf[289];static u32 maps_len,runtime_snapshot_bytes;
static i64 source_fd=-1;static struct Identity initial;static struct Request*q=(struct Request*)rqbuf;
static const char*allowed_names[8]={"image_00_23_IPSX.uxc","image_00_32_IPSX.uxc","string_english_horizontal.uxc","string_english_vertical.uxc","string_simplifiedchinese_horizontal.uxc","string_simplifiedchinese_vertical.uxc","string_traditionalchinese_horizontal.uxc","string_traditionalchinese_vertical.uxc"};
static int same(const u8*a,const u8*b,u64 n){for(u64 i=0;i<n;i++)if(a[i]!=b[i])return 0;return 1;}
static void copy(u8*a,const u8*b,u64 n){for(u64 i=0;i<n;i++)a[i]=b[i];}
static u32 length(const char*s){u32 n=0;while(s[n])n++;return n;}
static int allowed(const char*p){const char prefix[]="/usr/share/app/";u32 n=length(p),z=sizeof(prefix)-1;if(n<=z||!same((const u8*)p,(const u8*)prefix,z))return 0;for(u32 i=0;i<8;i++){u32 k=length(allowed_names[i]);if(n==z+k&&same((const u8*)p+z,(const u8*)allowed_names[i],k))return 1;}return 0;}
static i64 plan_guard(void){
 if(!allowed(path)||!SOURCE_SIZE||SOURCE_SIZE>STOCK_SIZE||STOCK_SIZE>16777216UL||rd_window_count>128||sizeof(rd_plan_id)!=32||append_size!=STOCK_SIZE-SOURCE_SIZE||append_size>16384||protect_count>128||!pending_count||pending_count>70)return -22;
 if(!rd_window_count&&!append_size)return -22;u64 end=0,total=0;
 for(u32 i=0;i<rd_window_count;i++){const struct DeltaWindow*w=&rd_windows[i];if(!w->size||w->size>512||w->at<end||w->at>SOURCE_SIZE||w->size>SOURCE_SIZE-w->at||same(w->before,w->after,w->size))return -22;end=w->at+w->size;total+=w->size;}
 if(total>16384)return -75;end=0;
 for(u32 i=0;i<protect_count;i++){const struct Protect*w=&protection[i];if(w->size!=512||w->at%512||w->at<end||w->at>=(SOURCE_SIZE+4095UL)/4096*4096)return -22;end=w->at+512;}
 R.window_count=rd_window_count;return 0;
}
static i64 op(const char*p,i64 flags){return sc(56,-100,(i64)p,flags,0600,0,0);}
static i64 cl(i64*fd){if(*fd<0)return 0;i64 n=sc(57,*fd,0,0,0,0,0);*fd=-1;if(n)R.close_errors++;return n;}
static i64 all(const char*p,u8*b,u32 cap){i64 fd=op(p,RD);if(fd<0)return fd;u32 at=0;i64 e=0;while(at<cap){i64 n=sc(63,fd,(i64)(b+at),cap-at,0,0,0);if(n<0){e=n;break;}if(!n)break;if((u64)n>cap-at){e=-5;break;}at+=(u32)n;}if(!e&&at==cap)e=-75;i64 c=cl(&fd);return e?e:c?c:at;}
static i64 read_at(i64 fd,u8*b,u32 n,u64 at){u32 done=0;while(done<n){i64 k=sc(67,fd,(i64)(b+done),n-done,at+done,0,0);if(k<=0||(u64)k>n-done)return k<0?k:-5;done+=(u32)k;}return 0;}
static int number(const u8*b,u32 end,u32*a,u64*v,u32 radix){u64 n=0;u32 start=*a;while(*a<end){u8 c=b[*a];u32 d=c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:99;if(d>=radix)break;if(n>(~0UL-d)/radix)return 0;n=n*radix+d;(*a)++;}*v=n;return *a>start;}
struct Mapping{u64 va,end,off,major,minor,ino,prot;u32 priv,path_at,path_end;};
static int parse(u32 begin,u32 end,struct Mapping*m){u32 a=begin;int ok=number(maps,end,&a,&m->va,16)&&a<end&&maps[a++]=='-'&&number(maps,end,&a,&m->end,16)&&a<end&&maps[a++]==' ';if(!ok||a+5>=end)return 0;if((maps[a]!='r'&&maps[a]!='-')||(maps[a+1]!='w'&&maps[a+1]!='-')||(maps[a+2]!='x'&&maps[a+2]!='-')||(maps[a+3]!='p'&&maps[a+3]!='s')||maps[a+4]!=' ')return 0;m->prot=(maps[a]=='r'?1:0)|(maps[a+1]=='w'?2:0)|(maps[a+2]=='x'?4:0);m->priv=maps[a+3]=='p';a+=5;if(!number(maps,end,&a,&m->off,16)||a>=end||maps[a++]!=' '||!number(maps,end,&a,&m->major,16)||a>=end||maps[a++]!=':'||!number(maps,end,&a,&m->minor,16)||a>=end||maps[a++]!=' ')return 0;while(a<end&&maps[a]==' ')a++;if(!number(maps,end,&a,&m->ino,10)||m->end<=m->va||m->off>~0UL-(m->end-m->va))return 0;while(a<end&&maps[a]==' ')a++;m->path_at=a;m->path_end=end;return 1;}
static int named(const struct Mapping*m,const char*p){u32 n=length(p);return m->path_end-m->path_at==n&&same(maps+m->path_at,(const u8*)p,n);}
static int devino(const struct Mapping*m,u64 dev,u64 ino){u64 major=((dev>>8)&0xfff)|((dev>>32)&~0xfffUL),minor=(dev&0xff)|((dev>>12)&~0xffUL);return m->ino==ino&&m->major==major&&m->minor==minor;}
/* Page boundaries matter even when the declared byte window is smaller. */
static int overlap(const struct Mapping*m){for(u32 i=0;i<protect_count;i++){const struct Protect*w=&protection[i];if(m->off<w->at+w->size&&m->off+m->end-m->va>w->at)return 1;}return 0;}
static i64 loadmaps(const char*p){i64 n=all(p,maps,sizeof(maps));if(n<0)return n;if(n&&maps[n-1]!='\n')return -22;maps_len=(u32)n;return 0;}
static i64 self_unlink(void){i64 fd=op(plugin,RD);if(fd<0)return fd;struct Stat s;i64 e=sc(80,fd,(i64)&s,0,0,0,0);u32 found=0;if(!e&&((s.mode&0170000)!=0100000||s.uid||s.nlink!=1))e=-22;for(u32 a=0,start=0;!e&&a<maps_len;a++)if(maps[a]=='\n'){struct Mapping m;if(!parse(start,a,&m)){e=-22;break;}start=a+1;if(named(&m,plugin)&&devino(&m,s.dev,s.ino)&&(m.prot&1)&&m.priv)found=1;}if(!e&&!found)e=-18;if(!e)e=sc(35,-100,(i64)plugin,0,0,0,0);if(!e){e=sc(80,fd,(i64)&s,0,0,0,0);if(!e&&s.nlink)e=-116;}i64 c=cl(&fd);return e?e:c;}
static i64 workspace(void){struct FS s;i64 e=sc(43,(i64)"/tmp/jiritsu",(i64)&s,0,0,0,0);if(e)return e;if(s.type!=0x4d44||s.frsize<=0||s.frsize>65536||s.bavail>~0UL/(u64)s.frsize)return -22;return s.bavail*s.frsize>=8388608UL+CAP+2*(u64)s.frsize?0:-28;}
static i64 request_stat(void){i64 fd=op(rqpath,RD);if(fd<0)return fd;struct Stat st;i64 e=sc(80,fd,(i64)&st,0,0,0,0);if(!e&&((st.mode&0170000)!=0100000||st.nlink!=1||st.uid||st.gid||st.size!=sizeof(*q)))e=-22;i64 c=cl(&fd);return e?e:c;}
static i64 pagesize(void){i64 n=all("/proc/self/auxv",io,sizeof(io));if(n<0)return n;if(n%16)return -22;u32 found=0,end=0;for(u32 at=0;at<(u32)n;at+=16){u64*t=(u64*)(io+at);if(!t[0]){end=1;break;}if(t[0]==6){if(found++)return -22;R.page_size=t[1];}}return found==1&&end&&R.page_size==4096?0:-22;}
static int stat_same(const struct Stat*s,u64 size){return s->dev==SOURCE_DEV&&s->ino==SOURCE_INO&&s->mode==R.source_mode&&s->uid==R.source_uid&&s->gid==R.source_gid&&s->nlink==R.source_nlink&&s->size==(i64)size;}
static i64 stable(u64 size){struct Stat s;i64 e=sc(80,source_fd,(i64)&s,0,0,0,0);if(!e&&!stat_same(&s,size))e=-116;if(!e)e=sc(79,-100,(i64)path,(i64)&s,0x100,0,0);return e?e:stat_same(&s,size)?0:-116;}
/* Finite resource reference dependencies, never a whole-file hash. */
static u32 le32(const u8*p){return (u32)p[0]|((u32)p[1]<<8)|((u32)p[2]<<16)|((u32)p[3]<<24);}
static i64 scope_dependencies(int target){for(u32 i=0;i<scope_d_count;i++){const struct ScopeDependency*d=&scope_d[i];if(!d->size||d->size>512)return -22;i64 e=read_at(source_fd,io,d->size,d->at);if(e)return e;if(!same(io,target?d->after:d->before,d->size))return -84;}return 0;}
static i64 scope_references(u64 limit){
 u8 head[16],index[2],record[40];i64 e=read_at(source_fd,head,16,0);if(e)return e;u32 count=le32(head+12)&8191,base;
 if(head[0]!='u'||head[1]!='x'||head[3]!=7||le32(head+4)||head[8]!=8||head[9])return -22;
 if(head[2]=='d'){
  if(head[10]||head[11]||count!=7844||le32(head+12)!=(count|(count<<12)))return -22;base=16+((le32(head+12)>>11)&0x7ffc);
  for(u32 i=0;i<count;i++){e=read_at(source_fd,index,2,16+2*i);if(e)return e;u32 p=index[0]|((u32)index[1]<<8);if(p==65535)continue;u64 at=base+4UL*p;if(at+12>limit)return -84;e=read_at(source_fd,record,12,at);if(e)return e;u32 field=le32(record+4)&0x08000000?32:12;if(at+field+8>limit)return -84;e=read_at(source_fd,record+field,8,at+field);if(e)return e;u64 size=le32(record+field),start=at+4+le32(record+field+4);if(le32(record)!=0x1a000000U+i||!size||start<at+field+8||start>limit||size>limit-start)return -84;
   if(scope_victim_size&&i!=scope_donor_id&&start<scope_victim+scope_victim_size&&start+size>scope_victim)return -84;
  }
 }else if(head[2]=='c'){
  if(head[10]!=5||head[11]||(count!=3032&&count!=3048)||le32(head+12)!=(count|(count<<12)))return -22;base=(16+2*count+3)&~3U;
  for(u32 i=0;i<count;i++){e=read_at(source_fd,index,2,16+2*i);if(e)return e;u32 p=index[0]|((u32)index[1]<<8);if(p==65535)continue;u64 at=base+4UL*p;if(at+5>limit)return -84;e=read_at(source_fd,record,4,at);if(e)return e;if(le32(record)!=0x1e000000U+0xa000+i)return -84;at+=4;int found=0;while(at<limit&&!found){u32 n=limit-at>sizeof(io)?sizeof(io):(u32)(limit-at);e=read_at(source_fd,io,n,at);if(e)return e;for(u32 j=0;j<n;j++)if(!io[j]){found=1;break;}at+=n;}if(!found)return -84;
  }
 }else return -22;return 0;
}
static i64 scope_check(int target){i64 e=scope_dependencies(target);if(e)return e;for(u32 i=0;i<rd_window_count;i++){const struct DeltaWindow*w=&rd_windows[i];e=read_at(source_fd,io,w->size,w->at);if(e)return e;if(!same(io,target?w->after:w->before,w->size))return -84;}if(target)for(u32 at=0;at<append_size;){u32 n=append_size-at>sizeof(io)?sizeof(io):(u32)(append_size-at);e=read_at(source_fd,io,n,SOURCE_SIZE+at);if(e)return e;if(!same(io,append_data+at,n))return -84;at+=n;}return scope_victim_size?scope_references(target?STOCK_SIZE:SOURCE_SIZE):0;}
/* Tie source and capacity to the same real /usr mount, without assuming
 * factory ownership of share/app. Never follow a parent symlink. */
static i64 parents(void){const char*names[3]={"/usr","share","app"};i64 fd=-1,e=0;
 for(u32 i=0;i<3;i++){i64 next=sc(56,i?fd:-100,(i64)names[i],RD|DIR,0,0,0);if(next<0){e=next;break;}struct Stat st;e=sc(80,next,(i64)&st,0,0,0,0);
 if(!e&&((st.mode&0170000)!=0040000||(st.mode&07022)||st.dev!=SOURCE_DEV))e=-116;
 i64 c=cl(&fd);fd=next;if(!e)e=c;if(e)break;}
 i64 c=cl(&fd);return e?e:c;
}
static i64 source_check(void){i64 parent_status=parents();if(parent_status)return parent_status;u64 size=q->mode==3?STOCK_SIZE:SOURCE_SIZE;i64 e=stable(size);return e?e:scope_check(q->mode==3);}
static i64 collect(int observe){i64 e=loadmaps("/proc/self/maps");if(e)return e;u32 count=0;u64 segments=0,bytes=0;for(u32 at=0,start=0;at<maps_len;at++)if(maps[at]=='\n'){struct Mapping m;if(!parse(start,at,&m))return -22;start=at+1;if(named(&m,path)&&!devino(&m,SOURCE_DEV,SOURCE_INO))return -116;if(!devino(&m,SOURCE_DEV,SOURCE_INO)||!overlap(&m))continue;if(!m.priv||m.prot!=1||(m.va|m.end|m.off)&4095)return -13;if(count>=4)return -75;struct Range v={m.va,m.end-m.va,m.off,1};if(observe)R.mappings[count]=v;else if(!same((u8*)&v,(u8*)&R.mappings[count],sizeof(v)))return -116;count++;for(u32 i=0;i<protect_count;i++){const struct Protect*w=&protection[i];u64 a=w->at>m.off?w->at:m.off,z=w->at+w->size<m.off+m.end-m.va?w->at+w->size:m.off+m.end-m.va;if(a<z){segments++;bytes+=z-a;}}}if(segments>512||bytes>65536)return -75;if(observe){R.mapping_count=count;R.cow_segments_expected=segments;R.cow_bytes_expected=bytes;}else if(count!=R.mapping_count||segments!=R.cow_segments_expected||bytes!=R.cow_bytes_expected)return -116;return 0;}
static i64 pidpath(char*out,u64 pid){if(!pid||pid>4194304)return -22;const char p[]="/proc/";u32 n=0;for(;n<sizeof(p)-1;n++)out[n]=p[n];char digits[16];u32 count=0;while(pid){digits[count++]=(char)('0'+pid%10);pid/=10;}while(count)out[n++]=digits[--count];const char suffix[]="/maps";for(u32 i=0;i<sizeof(suffix);i++)out[n++]=suffix[i];return 0;}
static i64 other_processes(void){i64 fd=op("/proc",RD|DIR);if(fd<0)return fd;R.cross_pids=R.cross_matches=0;R.flags&=~64U;i64 e=0;u32 rounds=0;while(!e){if(rounds++>=128){e=-75;break;}i64 n=sc(61,fd,(i64)proc_dents,sizeof(proc_dents),0,0,0);if(n<0){e=n;break;}if(!n)break;if(n>(i64)sizeof(proc_dents)){e=-5;break;}for(u32 at=0;at<(u32)n;){if((u32)n-at<20){e=-22;break;}u32 reclen=proc_dents[at+16]|((u32)proc_dents[at+17]<<8);if(reclen<20||reclen>(u32)n-at){e=-22;break;}u32 start=at+19,end=at+reclen,pos=start;u64 pid=0;while(pos<end&&proc_dents[pos]>='0'&&proc_dents[pos]<='9')pos++;if(pos<end&&pos>start&&proc_dents[pos]==0){u32 a=start;if(!number(proc_dents,pos,&a,&pid,10)){e=-22;break;}if(pid!=(u64)R.pid){if(R.cross_pids++>=4096){e=-75;break;}char p[40];e=pidpath(p,pid);if(e)break;e=loadmaps(p);if(e==-2){e=0;at+=reclen;continue;}if(e)break;for(u32 k=0,line=0;k<maps_len;k++)if(maps[k]=='\n'){struct Mapping m;if(!parse(line,k,&m)){e=-22;break;}line=k+1;if(devino(&m,SOURCE_DEV,SOURCE_INO)&&overlap(&m)){R.cross_matches++;R.offender_pid=(u32)pid;e=-16;break;}}if(e)break;}}at+=reclen;}}
 i64 c=cl(&fd);if(!e)e=c;if(!e)R.flags|=64;return e;}
/* The PF2 boundary: same logical bytes via /proc/self/mem trigger private
 * page COW, preserving the runtime view when the backing inode changes. */
static i64 preserve(int cow){
 i64 fd=op("/proc/self/mem",RD|(cow?2:0));if(fd<0)return fd;i64 e=0;u64 segments=0,bytes=0;struct SHA digest;sha_start(&digest);
 for(u32 map=0;map<R.mapping_count&&!e;map++){const struct Range*m=&R.mappings[map];for(u32 i=0;i<protect_count&&!e;i++){const struct Protect*w=&protection[i];u64 a=w->at>m->off?w->at:m->off,z=w->at+w->size<m->off+m->len?w->at+w->size:m->off+m->len;if(a>=z)continue;u32 n=(u32)(z-a);u64 address=m->va+a-m->off;e=read_at(fd,memory,n,address);if(e)break;
 /* Existing source bytes must be source-identical. The old EOF's zero/private
  * tail is observed, fingerprinted and preserved, never replaced by new tail. */
 for(u32 j=0;j<rd_window_count&&!e;j++){const struct DeltaWindow*v=&rd_windows[j];u64 x=a>v->at?a:v->at,z=a+n<v->at+v->size?a+n:v->at+v->size;if(x<z){if(!same(memory+x-a,v->before+x-v->at,z-x))e=-84;else sha_add(&digest,memory+x-a,z-x);}}if(e)break;
 if(bytes+n>sizeof(runtime_snapshot)){e=-75;break;}copy(runtime_snapshot+bytes,memory,n);segments++;bytes+=n;
 if(cow){R.flags|=2|4;R.cow_attempts++;u32 done=0;while(done<n){i64 v=sc(68,fd,(i64)(memory+done),n-done,address+done,0,0);if(v<=0||(u64)v>n-done){e=v<0?v:-5;break;}done+=(u32)v;}if(!e)e=read_at(fd,verify,n,address);if(!e&&!same(memory,verify,n))e=-84;if(!e){R.flags&=~4U;R.cow_segments++;R.bytes_cow_preserved+=n;}}
 }}
 if(!e&&(segments!=R.cow_segments_expected||bytes!=R.cow_bytes_expected))e=-116;
 if(!e){runtime_snapshot_bytes=(u32)bytes;sha_end(&digest,R.runtime_sha);if(q->mode&&!same(q->runtime_sha,R.runtime_sha,32))e=-116;}
 if(!e)R.flags|=cow?8:128;i64 c=cl(&fd);return e?e:c;
}
/* A same-value write/readback alone would not establish that COW survived
 * later backing-file writes. Re-read the entire saved runtime view afterward. */
static i64 verify_runtime(void){i64 fd=op("/proc/self/mem",RD);if(fd<0)return fd;i64 e=0;u64 segments=0,bytes=0;for(u32 map=0;map<R.mapping_count&&!e;map++){const struct Range*m=&R.mappings[map];for(u32 i=0;i<protect_count&&!e;i++){const struct Protect*w=&protection[i];u64 a=w->at>m->off?w->at:m->off,z=w->at+w->size<m->off+m->len?w->at+w->size:m->off+m->len;if(a>=z)continue;u32 n=(u32)(z-a);if(bytes+n>runtime_snapshot_bytes){e=-75;break;}e=read_at(fd,verify,n,m->va+a-m->off);if(!e&&!same(verify,runtime_snapshot+bytes,n))e=-84;if(!e){segments++;bytes+=n;}}}if(!e&&(segments!=R.cow_segments_expected||bytes!=R.cow_bytes_expected||bytes!=runtime_snapshot_bytes))e=-116;i64 c=cl(&fd);return e?e:c;}
static i64 apply_windows(void){
 if(append_size){R.index=0xffffffffU;R.flags|=16|256;R.write_attempts++;R.append_attempts=1;u32 done=0;while(done<append_size){i64 v=sc(68,source_fd,(i64)(append_data+done),append_size-done,SOURCE_SIZE+done,0,0);if(v<=0||(u64)v>append_size-done)return v<0?v:-5;done+=(u32)v;R.bytes_written+=(u64)v;R.append_bytes+=(u64)v;}i64 e=sc(82,source_fd,0,0,0,0,0);if(e)return e;e=stable(STOCK_SIZE);if(e)return e;
 for(u32 at=0;at<append_size;){u32 n=append_size-at>sizeof(io)?sizeof(io):(u32)(append_size-at);e=read_at(source_fd,io,n,SOURCE_SIZE+at);if(e)return e;if(!same(io,append_data+at,n))return -84;at+=n;}
 R.writes_completed++;R.append_completed=1;}
 for(u32 i=0;i<R.window_count;i++){const struct DeltaWindow*w=&rd_windows[i];R.index=i;i64 e=read_at(source_fd,io,w->size,w->at);if(e)return e;if(!same(io,w->before,w->size))return -84;R.flags|=16|256;R.write_attempts++;u32 done=0;while(done<w->size){i64 v=sc(68,source_fd,(i64)(w->after+done),w->size-done,w->at+done,0,0);if(v<=0||(u64)v>w->size-done)return v<0?v:-5;done+=(u32)v;R.bytes_written+=(u64)v;}e=sc(82,source_fd,0,0,0,0,0);if(e)return e;R.writes_completed++;}
 i64 e=stable(STOCK_SIZE);if(!e)e=scope_check(1);if(!e){R.flags&=~256U;R.flags|=32;}return e;
}
/* Fresh physical allocation evidence, never equality with historical F.
 * Read every listed existing dirty block (at most1024B). Any nonzero byte
 * proves allocation. All-zero blocks remain conservatively charged. No host
 * witness value or host claim that a block is allocated enters this check. */
static i64 capacity(void){
 R.usr_type=R.usr_unit=R.usr_available=R.usr_required=0;
 R.unknown_dirty_blocks=R.scanned_dirty_blocks=R.scanned_pending_files=R.capacity_scan_complete=R.capacity_reserved=0;
 struct FS fs;i64 e=sc(43,(i64)"/usr",(i64)&fs,0,0,0,0);if(e)return e;
 if(fs.type!=0xef53||fs.bsize!=1024||fs.frsize!=1024||fs.bavail>~0UL/1024)return -22;
 R.usr_type=(u64)fs.type;R.usr_unit=1024;R.usr_available=fs.bavail*1024;
 u64 growth=0,unknown=0,scanned=0;
 if(dirty_block_count>17920)return -75;
 for(u32 i=0;i<pending_count;i++){
  const struct BudgetFile*f=&pending_files[i];
  if(!allowed(f->path)||!f->source_size||f->source_size>f->target_size||f->target_size>16777216UL||f->dirty_count>256||f->dirty_begin>dirty_block_count||f->dirty_count>dirty_block_count-f->dirty_begin)return -22;
  i64 fd=op(f->path,RD);if(fd<0)return fd;struct Stat st;
  e=sc(80,fd,(i64)&st,0,0,0,0);if(!e&&((st.mode&0170000)!=0100000||st.nlink!=1||st.size!=(i64)f->source_size||st.dev!=SOURCE_DEV))e=-116;
  u32 previous=0;
  for(u32 j=0;j<f->dirty_count&&!e;j++){
   u32 block=dirty_blocks[f->dirty_begin+j];u64 at=1024UL*block;
   if(at>=f->source_size||(j&&block<=previous)){e=-22;break;}previous=block;
   u32 n=f->source_size-at>1024?1024:(u32)(f->source_size-at);
   e=read_at(fd,io,n,at);if(e)break;u32 nonzero=0;for(u32 k=0;k<n;k++)nonzero|=io[k];
   if(!nonzero)unknown++;scanned++;
  }
  i64 c=cl(&fd);if(e)return e;if(c)return c;
  growth+=(f->target_size+1023)/1024-(f->source_size+1023)/1024;
 }
 /* Publish a complete proof only after every pending file/block succeeded. */
 R.unknown_dirty_blocks=unknown;R.scanned_dirty_blocks=scanned;R.scanned_pending_files=pending_count;R.capacity_scan_complete=1;
 R.usr_required=8388608UL+(4*(growth+unknown)+2)*1024;
 return R.usr_available>=R.usr_required?0:-28;
}
/* Match the exact mountpoint and filesystem, not a body-specific block name. */
static i64 mount_state(void){i64 n=all("/proc/self/mounts",mounts,sizeof(mounts));if(n<0)return n;u32 count=0;int state=-22;for(u32 begin=0;begin<(u32)n;){u32 end=begin;while(end<(u32)n&&mounts[end]!='\n')end++;u32 a=begin;while(a<end&&mounts[a]!=' ')a++;if(a==end){begin=end+1;continue;}u32 target=++a;while(a<end&&mounts[a]!=' ')a++;if(a-target==4&&same(mounts+target,(const u8*)"/usr",4)){count++;u32 fs=++a;while(a<end&&mounts[a]!=' ')a++;if(a-fs!=4||!same(mounts+fs,(const u8*)"ext2",4))state=-22;else{a++;if(a+2<end&&mounts[a]=='r'&&(mounts[a+2]==','||mounts[a+2]==' '))state=mounts[a+1]=='o'?0:mounts[a+1]=='w'?1:-22;}}begin=end+1;}return count==1?state:-22;}
static i64 remount(int ro){i64 e=sc(40,0,(i64)"/usr",0,0xc30UL+(ro?1:0),0,0);if(e)return e;e=mount_state();return e<0?e:e==(ro?0:1)?0:-30;}
static void publish(void){i64 fd=op(outpath,RD|1|64|128);if(fd<0)return;u32 done=0;while(done<R.total){i64 n=sc(64,fd,(i64)(out.bytes+done),R.total-done,0,0,0);if(n<=0||(u64)n>R.total-done)break;done+=(u32)n;}sc(82,fd,0,0,0,0,0);cl(&fd);}
__attribute__((visibility("default")))void _init(void){
 copy(R.magic,magic,8);copy(R.plan_id,rd_plan_id,32);R.version=2;R.mode=0xffffffffU;R.total=sizeof(R);R.plugin_unlink=-1;R.readonly=-1;R.euid=sc(175,0,0,0,0,0,0);R.pid=sc(172,0,0,0,0,0,0);R.source_size=SOURCE_SIZE;R.target_size=STOCK_SIZE;
 if(R.euid||R.pid<=0)R.status=-13;if(!R.status)R.status=plan_guard();i64 n=0;
 if(!R.status)R.status=request_stat();
 if(!R.status){n=all(rqpath,rqbuf,sizeof(rqbuf));if(n!=sizeof(*q))R.status=n<0?n:-22;else{u32 any=0;copy(R.nonce,q->nonce,16);for(u32 i=0;i<16;i++)any|=q->nonce[i];R.mode=q->mode;if(!same(q->magic,magic,8)||!same(q->plan_id,rd_plan_id,32)||(q->mode!=0&&q->mode!=1&&q->mode!=3)||!any)R.status=-22;
 if(!R.status&&!q->mode){const u8*rest=(u8*)&q->pid;for(u32 i=0;i<224;i++)if(rest[i])R.status=-22;if(q->count)R.status=-22;}
 if(!R.status&&q->mode&&(q->pid!=(u64)R.pid||q->count>4||q->target_size!=STOCK_SIZE||q->reserved))R.status=-116;}}
 R.phase=1;if(!R.status)R.status=loadmaps("/proc/self/maps");if(!R.status){R.plugin_unlink=self_unlink();R.status=R.plugin_unlink;}if(!R.status)R.status=workspace();if(!R.status){R.auxv_status=pagesize();R.status=R.auxv_status;}if(!R.status){n=mount_state();R.readonly=n==0?0:n==1?-16:n;if(n)R.status=n<0?n:-16;}
 R.phase=2;if(!R.status){source_fd=op(path,RD);if(source_fd<0)R.status=source_fd;else{R.source_status=sc(80,source_fd,(i64)&R.source_stat,0,0,0,0);if(!R.source_status){struct Stat*v=&R.source_stat;u64 expected=q->mode==3?STOCK_SIZE:SOURCE_SIZE;
 if((v->mode&0170000)!=0100000||v->nlink!=1||v->size!=(i64)expected||!v->ino)R.source_status=-116;else{R.source_dev=v->dev;R.source_ino=v->ino;R.source_mode=v->mode;R.source_uid=v->uid;R.source_gid=v->gid;R.source_nlink=v->nlink;R.source_size=(u64)v->size;initial=(struct Identity){v->dev,v->ino,(u64)v->size,v->mode,v->uid,v->gid,v->nlink};if(q->mode&&!same((u8*)&q->identity,(u8*)&initial,sizeof(initial)))R.source_status=-116;}}
 if(!R.source_status)R.source_status=source_check();R.status=R.source_status;}}
 if(!R.status&&q->mode!=3)R.status=capacity();
 if(!R.status)R.status=collect(1);if(!R.status&&q->mode&&(q->count!=R.mapping_count||!same((u8*)q->ranges,(u8*)R.mappings,sizeof(q->ranges))))R.status=-116;
 if(!R.status)R.status=other_processes();if(!R.status)R.status=collect(0);if(!R.status)R.status=preserve(0);
 if(!R.status&&q->mode!=1){R.phase=3;R.flags|=1;}
 if(!R.status&&q->mode==1){R.phase=4;R.status=preserve(1);if(!R.status)R.status=collect(0);if(!R.status)R.status=source_check();if(!R.status)R.status=other_processes();if(!R.status)R.status=collect(0);if(!R.status)R.status=capacity();
 if(!R.status){R.phase=7;R.remount=remount(0);R.status=R.remount;if(!R.status)R.status=stable(SOURCE_SIZE);if(!R.status){i64 c=cl(&source_fd);if(c)R.status=c;}if(!R.status){source_fd=op(path,RD|2);if(source_fd<0)R.status=source_fd;else R.status=source_check();}
 if(!R.status){R.phase=8;R.status=apply_windows();}if(!R.status){R.flags|=4;R.status=collect(0);if(!R.status)R.status=other_processes();if(!R.status)R.status=collect(0);if(!R.status)R.status=verify_runtime();if(!R.status){R.flags&=~4U;R.flags|=512;}}
 {i64 c=cl(&source_fd);if(!R.status&&c)R.status=c;}i64 operation_status=R.status;R.readonly=remount(1);if(!operation_status&&!R.readonly){R.status=0;R.phase=9;R.flags|=1;}else if(!operation_status)R.status=R.readonly;}}
 {i64 c=cl(&source_fd);if(!R.status&&c)R.status=c;}if(R.close_errors)R.flags&=~1U;publish();
}
