/* SPDX-License-Identifier: MIT
 * Original-backup, bounded streaming atomic inode replacement.
 * Derived in part from a7m4-toolbox native/resource-worker/resource-worker.c
 * (MIT; retained LICENSE.MIT) and the separately retained portable helpers.
 * The generated private manifest fixes one allowlisted path, its original
 * target/current hashes and sizes, and one same-directory plan-owned stage.
 * No current inode content is written or truncated. There is no automatic
 * rollback, retry, WBI/settings/program/NOR operation, shell or network API.
 * Host must verify complete source, complete stage before commit and complete
 * final target on the Mac. A supplied proof digest is not independently
 * interpreted as evidence of its provenance by this mechanism.
 */
#ifdef TARGET_ABI
#define _GNU_SOURCE 1
#include <fcntl.h>
#include <sys/syscall.h>
#endif
typedef unsigned long U;typedef long I;typedef unsigned int W;typedef unsigned char B;typedef unsigned char u8;
#define RF (0x8000UL|0x80000UL)
#define DIR 0x4000UL
#define MAX_FILE 16777216UL
#define MAX_CHUNK 32768U
#define REQUEST_BYTES 256U
#define RESULT_BYTES 384U
#define F_COMPLETE 1U
#define F_CREATE_ATTEMPT 2U
#define F_CREATED 4U
#define F_WRITE_ATTEMPT 8U
#define F_WRITE_VERIFIED 16U
#define F_RENAME_ATTEMPT 32U
#define F_RENAMED 64U
#define F_UNLINK_ATTEMPT 128U
#define F_UNLINKED 256U
#define F_SOURCE_HASH 512U
#define F_STAGE_HASH 1024U
#define F_IDENTITY 2048U
#define F_WORKSPACE 4096U
#define F_MOUNT 8192U
#define F_DIRSYNC 16384U
#define F_UNKNOWN 32768U
#ifdef TARGET_ABI
_Static_assert(RF==(O_NOFOLLOW|O_CLOEXEC)&&DIR==O_DIRECTORY,"Linux open flags");
_Static_assert(SYS_renameat==38&&SYS_fstat==80&&SYS_fstatfs==44,"Linux syscall ABI");
#endif
static I sc(I n,I a,I b,I c,I d,I e,I f){register I x0 __asm__("x0")=a,x1 __asm__("x1")=b,x2 __asm__("x2")=c,x3 __asm__("x3")=d,x4 __asm__("x4")=e,x5 __asm__("x5")=f,x8 __asm__("x8")=n;__asm__ volatile("svc 0":"+r"(x0):"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5),"r"(x8):"memory","cc");return x0;}
struct Stat{U dev,ino;W mode,nlink,uid,gid;U rdev,pad;I size;W blksize,pad2;U blocks,rest[7];};
struct FS{I type,bsize;U blocks,bfree,bavail,files,ffree;W fsid[2];I namelen,frsize,flags,spare[4];};
struct Identity{U dev,ino,size;W mode,uid,gid,nlink;};
struct Request{B magic[8];W mode,chunk_bytes;B nonce[16],plan_id[32];U pid;struct Identity source,stage;U offset;B stage_sha256[32],chunk_sha256[32];W guard_flags;B reserved[28];};
struct Report{B magic[8];W version,mode;B nonce[16],plan_id[32];W phase,flags;I status,euid,pid,plugin_unlink,close_errors,remount,readonly,source_status,stage_status,fs_status;struct Identity source,stage;U fs_type,fs_unit,fs_available,fs_needed,offset,bytes_written,bytes_verified;B source_sha256[32],stage_sha256[32];W write_attempts,rename_attempts,renamed,stage_created,stage_removed,profile;U reserved;};
_Static_assert(sizeof(struct Stat)==128&&sizeof(struct FS)==120,"Linux AArch64 stat ABI");
_Static_assert(sizeof(struct Identity)==40&&sizeof(struct Request)==256&&sizeof(struct Report)==384,"wire ABI");
#include PATCH_MANIFEST
#include "original-sha256.h"
static const char actual_path[]=OA_PATH,stage_path[]=OA_STAGE_PATH;
static const char library[]="/tmp/jiritsu/libJit.so",request_path[]="/tmp/jiritsu/a7m4.original-atomic.request",result_path[]="/tmp/jiritsu/a7m4.original-atomic.result";
static const B magic[8]={'A','7','O','A','0','0','0','1'};
static const char *source_name,*stage_name;
static struct Report r;static B request_data[REQUEST_BYTES+MAX_CHUNK+1],io[4096],mounts[8192],maps[131072];
static struct Request*q=(struct Request*)request_data;
static I parent_fd=-1,source_fd=-1,stage_fd=-1;static int rw_attempted;
static U source_size=(U)OA_SOURCE_SIZE,target_size=(U)OA_TARGET_SIZE;
static int equal(const B*a,const B*b,U n){for(U j=0;j<n;j++)if(a[j]!=b[j])return 0;return 1;}
static void copy(B*a,const B*b,U n){for(U j=0;j<n;j++)a[j]=b[j];}
static W length(const char*s){W n=0;while(s[n])n++;return n;}
static int nonzero(const B*a,U n){B v=0;for(U i=0;i<n;i++)v|=a[i];return v!=0;}
static I op(const char*p,U f,W mode){return sc(56,-100,(I)p,f,mode,0,0);}
static I closefd(I*f){if(*f<0)return 0;I v=sc(57,*f,0,0,0,0,0);*f=-1;if(v)r.close_errors++;return v;}
static I readat(I f,B*b,U n,U at){U done=0,retries=0;while(done<n){I v=sc(67,f,(I)(b+done),n-done,at+done,0,0);if(v==-4&&retries++<3)continue;if(v<=0||(U)v>n-done)return v<0?v:-5;done+=(U)v;}return 0;}
static I all(const char*p,B*b,U cap){I f=op(p,RF,0);if(f<0)return f;U used=0,retries=0;I v=0;while(used<cap){I n=sc(63,f,(I)(b+used),cap-used,0,0,0);if(n==-4&&retries++<3)continue;if(n<0){v=n;break;}if(!n)break;if((U)n>cap-used){v=-5;break;}used+=(U)n;}I c=closefd(&f);return v?v:c?c:used==cap?-75:(I)used;}
static struct Identity identity(const struct Stat*s){return(struct Identity){s->dev,s->ino,(U)s->size,s->mode,s->uid,s->gid,s->nlink};}
static int same_identity(const struct Identity*a,const struct Identity*b){return equal((const B*)a,(const B*)b,sizeof(*a));}
static I regular(I fd,struct Identity*out){struct Stat s;I v=sc(80,fd,(I)&s,0,0,0,0);if(v)return v;if((s.mode&0170000)!=0100000||s.mode&07000||s.nlink!=1||!s.ino||s.size<0||(U)s.size>MAX_FILE)return -22;*out=identity(&s);return 0;}
static I linked(const char*name,const struct Identity*expected){struct Stat s;I v=sc(79,parent_fd,(I)name,(I)&s,0x100,0,0);if(v)return v;struct Identity a=identity(&s);return same_identity(&a,expected)?0:-116;}
static I absent(const char*name){struct Stat s;I v=sc(79,parent_fd,(I)name,(I)&s,0x100,0,0);return v==-2?0:v?v:-17;}
static I digest(I fd,const struct Identity*expected,const B*hash,B*out){struct Identity before,after;I v=regular(fd,&before);if(!v&&!same_identity(&before,expected))v=-116;struct SHA h;sha_start(&h);for(U at=0;!v&&at<expected->size;){U n=expected->size-at>sizeof(io)?sizeof(io):expected->size-at;v=readat(fd,io,n,at);if(!v)sha_add(&h,io,n);at+=n;}if(!v)v=regular(fd,&after);if(!v&&!same_identity(&before,&after))v=-116;if(!v){sha_end(&h,out);if(hash&&!equal(out,hash,32))v=-84;}return v;}
static I source_check(int full){struct Identity same;I v=regular(source_fd,&same);if(!v&&!same_identity(&same,&r.source))v=-116;if(!v)v=linked(source_name,&r.source);if(!v&&full){v=digest(source_fd,&r.source,oa_source_sha256,r.source_sha256);if(!v)r.flags|=F_SOURCE_HASH;}return v;}
static I stage_check(int full,const B*hash){struct Identity same;I v=regular(stage_fd,&same);if(!v&&!same_identity(&same,&r.stage))v=-116;if(!v)v=linked(stage_name,&r.stage);if(!v&&full){v=digest(stage_fd,&r.stage,hash,r.stage_sha256);if(!v)r.flags|=F_STAGE_HASH;}return v;}
static I parent_open(void){const char*names[3]={r.profile?"/cp":"/usr","share","app"};U count=r.profile?1:3;for(U j=0;j<count;j++){I next=sc(56,j?parent_fd:-100,(I)names[j],RF|DIR,0,0,0);if(next<0)return next;struct Stat s;I v=sc(80,next,(I)&s,0,0,0,0);if(!v&&(s.mode&0170000)!=0040000)v=-22;I c=closefd(&parent_fd);parent_fd=next;if(v)return v;if(c)return c;}return 0;}
static int part(const B*p,U n,const char*s){return n==length(s)&&equal(p,(const B*)s,n);}
/* Exact /usr ext2 or /cp vfat mount and no nested mount beneath its tree.
 * UXC /usr is read-only at every call boundary. CP stays vfat read-write;
 * native never calls chown/chmod/remount on this VFAT profile. */
static I mount_state(int usr_ro){I size=all("/proc/self/mounts",mounts,sizeof(mounts));if(size<0)return size;U count=0;const char*point=r.profile?"/cp":"/usr";U plen=length(point);for(U at=0;at<(U)size;){U end=at;while(end<(U)size&&mounts[end]!='\n')end++;const B*p[4];U n[4],pos=at,k=0;while(k<4&&pos<end){U start=pos;while(pos<end&&mounts[pos]!=' ')pos++;p[k]=mounts+start;n[k++]=pos-start;while(pos<end&&mounts[pos]==' ')pos++;}if(k!=4)return -22;if(n[1]>plen&&equal(p[1],(const B*)point,plen)&&p[1][plen]=='/')return -22;if(part(p[1],n[1],point)){if(!part(p[0],n[0],r.profile?"/dev/nflasha8":"/dev/nflasha15")||!part(p[2],n[2],r.profile?"vfat":"ext2"))return -22;const char*options=r.profile?"rw,sync,noatime,nodiratime,fmask=0022,dmask=0022,codepage=437,iocharset=ascii,shortname=mixed,posix_attr,avoid_dlink,errors=remount-ro":usr_ro?"ro,sync,noatime,nodiratime,errors=continue":"rw,sync,noatime,nodiratime,errors=continue";if(!part(p[3],n[3],options))return -30;count++;}at=end+1;}return count==1?0:-22;}
static I remount_usr(int ro){if(r.profile)return mount_state(0);I v=sc(40,0,(I)"/usr",0,0xc30UL+(ro?1:0),0,0);return v?v:mount_state(ro);}
static I workspace(void){struct FS s;I v=sc(43,(I)"/tmp/jiritsu",(I)&s,0,0,0,0);if(v)return v;I fallback=s.frsize?s.frsize:s.bsize;if(s.type!=0x4d44||fallback<=0||fallback>65536||s.bavail>~0UL/(U)fallback)return -22;U unit=(U)fallback;return s.bavail*unit>=8388608UL+((RESULT_BYTES+unit-1)/unit)*unit+2*unit?0:-28;}
static I budget(U already){struct FS fs;I v=sc(44,parent_fd,(I)&fs,0,0,0,0);if(v)return v;I unit=fs.frsize?fs.frsize:fs.bsize;if(fs.type!=(r.profile?0x4d44:0xef53)||unit<=0||unit>1048576||fs.bavail>~0UL/(U)unit||already>target_size)return -22;r.fs_type=(U)fs.type;r.fs_unit=(U)unit;r.fs_available=fs.bavail*r.fs_unit;r.fs_needed=q->mode==4?0:(((target_size+r.fs_unit-1)/r.fs_unit)-((already+r.fs_unit-1)/r.fs_unit)+32)*r.fs_unit;return r.fs_available>=r.fs_needed?0:-28;}
static I dirsync(void){I v=sc(82,parent_fd,0,0,0,0,0);if(!v)r.flags|=F_DIRSYNC;return v;}
/* Self-unlink only the regular root-owned single-link library whose exact
 * inode is presently mapped privately/readably at its fixed loader path. */
static int number(const B*b,U end,U*at,U*out,U base){U a=*at,n=0;while(*at<end){B c=b[*at];U d=c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:base;if(d>=base)break;if(n>(~0UL-d)/base)return 0;n=n*base+d;(*at)++;}*out=n;return *at>a;}
static I self_unlink(void){I fd=op(library,RF,0);if(fd<0)return fd;struct Stat s;I v=sc(80,fd,(I)&s,0,0,0,0);if(!v&&((s.mode&0170000)!=0100000||s.uid||s.nlink!=1||s.size<=0||s.size>=65536))v=-22;I size=0;if(!v){size=all("/proc/self/maps",maps,sizeof(maps));if(size<0)v=size;}W found=0;for(U at=0;!v&&at<(U)size;){U end=at;while(end<(U)size&&maps[end]!='\n')end++;U pos=at,a,z,off,major,minor,ino;if(!number(maps,end,&pos,&a,16)||pos>=end||maps[pos++]!='-'||!number(maps,end,&pos,&z,16)||pos+6>end||maps[pos++]!=' '){v=-22;break;}int readable=maps[pos]=='r',priv=maps[pos+3]=='p';pos+=5;if(!number(maps,end,&pos,&off,16)||pos>=end||maps[pos++]!=' '||!number(maps,end,&pos,&major,16)||pos>=end||maps[pos++]!=':'||!number(maps,end,&pos,&minor,16)||pos>=end||maps[pos++]!=' '){v=-22;break;}while(pos<end&&maps[pos]==' ')pos++;if(!number(maps,end,&pos,&ino,10)){v=-22;break;}while(pos<end&&maps[pos]==' ')pos++;U devmajor=((s.dev>>8)&0xfff)|((s.dev>>32)&~0xfffUL),devminor=(s.dev&0xff)|((s.dev>>12)&~0xffUL);if(z>a&&readable&&priv&&major==devmajor&&minor==devminor&&ino==s.ino&&part(maps+pos,end-pos,library))found++;at=end+1;}if(!v&&!found)v=-18;if(!v)v=sc(35,-100,(I)library,0,0,0,0);if(!v){v=sc(80,fd,(I)&s,0,0,0,0);if(!v&&s.nlink)v=-116;}I c=closefd(&fd);return v?v:c;}
/* Recomputed filename and allowlist prevent a generated header from turning
 * this mechanism into an arbitrary path or arbitrary stage-file operation. */
static I plan_guard(void);
static I validate_request(void){I fd=op(request_path,RF,0);if(fd<0)return fd;struct Stat st;I e=sc(80,fd,(I)&st,0,0,0,0);if(!e&&((st.mode&0170000)!=0100000||st.uid||st.nlink!=1||st.size<(I)REQUEST_BYTES||st.size>(I)(REQUEST_BYTES+MAX_CHUNK)))e=-22;I c=closefd(&fd);if(e)return e;if(c)return c;I n=all(request_path,request_data,sizeof(request_data));if(n<0)return n;if(n!=st.size)return -116;r.mode=q->mode;copy(r.nonce,q->nonce,16);if(!equal(q->magic,magic,8)||!equal(q->plan_id,oa_plan_id,32)||!nonzero(q->nonce,16)||q->mode>4||q->chunk_bytes>MAX_CHUNK||n!=(I)(REQUEST_BYTES+q->chunk_bytes)||q->guard_flags>1||nonzero(q->reserved,28)||(q->guard_flags&&(r.profile||q->mode<2)))return -22;if(q->mode==0){if(q->chunk_bytes||nonzero((B*)&q->pid,192))return -22;}else{if(q->pid!=(U)r.pid||q->source.size!=source_size||!q->source.ino||q->source.nlink!=1)return -116;if(q->mode==1){if(q->chunk_bytes||nonzero((B*)&q->stage,sizeof(q->stage))||q->offset||nonzero(q->stage_sha256,64))return -22;}else if(!q->stage.ino||q->stage.nlink!=1||q->offset!=q->stage.size||q->stage.size>target_size)return -116;}if(q->mode==2){if(!q->chunk_bytes||q->chunk_bytes>target_size-q->offset||(q->guard_flags?!nonzero(q->stage_sha256,32):nonzero(q->stage_sha256,32)))return -22;B h[32];struct SHA digest;sha_start(&digest);sha_add(&digest,request_data+REQUEST_BYTES,q->chunk_bytes);sha_end(&digest,h);if(!equal(h,q->chunk_sha256,32))return -84;}else if(q->chunk_bytes||nonzero(q->chunk_sha256,32))return -22;if(q->mode==3&&(q->stage.size!=target_size||!equal(q->stage_sha256,oa_target_sha256,32)))return -22;if(q->mode==4&&!nonzero(q->stage_sha256,32))return -22;return 0;}
static I open_sources(void){source_fd=sc(56,parent_fd,(I)source_name,RF,0,0,0);if(source_fd<0)return source_fd;I v=regular(source_fd,&r.source);struct Stat parent;if(!v)v=sc(80,parent_fd,(I)&parent,0,0,0,0);if(!v&&(r.source.size!=source_size||r.source.dev!=parent.dev))v=-116;if(!v&&q->mode&&!same_identity(&q->source,&r.source))v=-116;if(!v)v=source_check(q->mode==0||q->mode==1||q->mode==3||q->mode==4||q->guard_flags);if(v)return v;if(q->mode<2){v=absent(stage_name);if(!v)r.flags|=F_IDENTITY;return v;}stage_fd=sc(56,parent_fd,(I)stage_name,RF,0,0,0);if(stage_fd<0)return stage_fd;v=regular(stage_fd,&r.stage);if(!v&&(!same_identity(&q->stage,&r.stage)||r.stage.dev!=r.source.dev||r.stage.ino==r.source.ino||r.stage.mode!=r.source.mode||r.stage.uid!=r.source.uid||r.stage.gid!=r.source.gid))v=-116;if(!v)v=stage_check(q->mode==3||q->mode==4||q->guard_flags,q->mode==3?oa_target_sha256:q->stage_sha256);r.stage_status=v;if(!v)r.flags|=F_IDENTITY;return v;}
static I begin_stage(void){r.flags|=F_CREATE_ATTEMPT;stage_fd=sc(56,parent_fd,(I)stage_name,RF|2|64|128,r.source.mode&0777,0,0);if(stage_fd<0){if(stage_fd!=-17)r.flags|=F_UNKNOWN;return stage_fd;}r.stage_created=1;r.flags|=F_CREATED;I v=0;if(!r.profile){v=sc(55,stage_fd,r.source.uid,r.source.gid,0,0,0);if(!v)v=sc(52,stage_fd,r.source.mode&0777,0,0,0,0);}if(!v)v=regular(stage_fd,&r.stage);if(!v&&(r.stage.size||r.stage.dev!=r.source.dev||r.stage.ino==r.source.ino||r.stage.mode!=r.source.mode||r.stage.uid!=r.source.uid||r.stage.gid!=r.source.gid))v=-116;if(!v)v=sc(82,stage_fd,0,0,0,0,0);if(!v)v=stage_check(0,0);if(!v)v=source_check(0);if(!v)v=dirsync();return v;}
static I reopen_stage(void){I v=closefd(&stage_fd);if(v)return v;stage_fd=sc(56,parent_fd,(I)stage_name,RF|2,0,0,0);return stage_fd<0?stage_fd:stage_check(0,0);}
static I append_stage(void){I v=reopen_stage();if(v)return v;if((v=source_check(0)))return v;r.offset=q->offset;r.flags&=~F_STAGE_HASH;for(W i=0;i<32;i++)r.stage_sha256[i]=0;U done=0,retries=0;while(done<q->chunk_bytes){r.flags|=F_WRITE_ATTEMPT;r.write_attempts++;I n=sc(68,stage_fd,(I)(request_data+REQUEST_BYTES+done),q->chunk_bytes-done,q->offset+done,0,0);if(n==-4&&retries++<3)continue;if(n<=0||(U)n>q->chunk_bytes-done){r.flags|=F_UNKNOWN;return n<0?n:-5;}done+=(U)n;r.bytes_written+=(U)n;}v=sc(82,stage_fd,0,0,0,0,0);if(v){r.flags|=F_UNKNOWN;return v;}struct Identity fresh;v=regular(stage_fd,&fresh);struct Identity wanted=r.stage;wanted.size+=q->chunk_bytes;if(!v&&!same_identity(&fresh,&wanted))v=-116;if(!v){r.stage=fresh;for(U at=0;at<q->chunk_bytes;){U n=q->chunk_bytes-at>sizeof(io)?sizeof(io):q->chunk_bytes-at;v=readat(stage_fd,io,n,q->offset+at);if(v)break;if(!equal(io,request_data+REQUEST_BYTES+at,n)){v=-84;break;}r.bytes_verified+=n;at+=n;}}if(!v)v=stage_check(0,0);if(!v)v=source_check(0);if(v)r.flags|=F_UNKNOWN;else r.flags|=F_WRITE_VERIFIED;return v;}
static I commit_stage(void){I v=source_check(1);if(!v)v=stage_check(1,oa_target_sha256);if(!v)v=sc(82,stage_fd,0,0,0,0,0);if(v)return v;r.flags|=F_RENAME_ATTEMPT;r.rename_attempts++;v=sc(38,parent_fd,(I)stage_name,parent_fd,(I)source_name,0,0);if(v){r.flags|=F_UNKNOWN;return v;}r.flags|=F_RENAMED;r.renamed=1;v=dirsync();if(!v)v=absent(stage_name);if(!v)v=linked(source_name,&r.stage);if(!v)v=digest(stage_fd,&r.stage,oa_target_sha256,r.stage_sha256);struct Stat old;if(!v)v=sc(80,source_fd,(I)&old,0,0,0,0);if(!v){struct Identity a=identity(&old),b=r.source;b.nlink=0;if(!same_identity(&a,&b))v=-116;}if(v)r.flags|=F_UNKNOWN;return v;}
static I abort_stage(void){I v=source_check(1);if(!v)v=stage_check(1,q->stage_sha256);if(v)return v;r.flags|=F_UNLINK_ATTEMPT;v=sc(35,parent_fd,(I)stage_name,0,0,0,0);if(v){r.flags|=F_UNKNOWN;return v;}r.flags|=F_UNLINKED;r.stage_removed=1;v=dirsync();if(!v)v=absent(stage_name);if(!v)v=source_check(0);if(v)r.flags|=F_UNKNOWN;return v;}
/* A completed operation may encounter the known vendor RO EBUSY condition.
 * Only a successfully closed, otherwise complete operation can continue its
 * same-plan identity chain. For an extant stage, publish a fresh full digest;
 * the next guarded append must bind it. Never derive this from an unknown
 * operation or claim that /usr is read-only. No remount retry is performed. */
static I deferred_stage_hashes(void){I v=parent_open();if(!v){source_fd=sc(56,parent_fd,(I)source_name,RF,0,0,0);if(source_fd<0)v=source_fd;}if(!v)v=source_check(1);if(!v){stage_fd=sc(56,parent_fd,(I)stage_name,RF,0,0,0);if(stage_fd<0)v=stage_fd;}if(!v)v=stage_check(1,0);I c=closefd(&stage_fd);if(!v)v=c;c=closefd(&source_fd);if(!v)v=c;c=closefd(&parent_fd);if(!v)v=c;if(!v)v=mount_state(0);return v;}
static void publish(void){I fd=op(result_path,RF|1|64|128,0600);if(fd<0)return;struct Stat s;I v=sc(80,fd,(I)&s,0,0,0,0);if(!v&&((s.mode&0170000)!=0100000||s.uid||s.nlink!=1||s.size))v=-22;U done=0,retries=0;while(!v&&done<sizeof(r)){I n=sc(64,fd,(I)((B*)&r+done),sizeof(r)-done,0,0,0);if(n==-4&&retries++<3)continue;if(n<=0||(U)n>sizeof(r)-done){v=n<0?n:-5;break;}done+=(U)n;}if(!v)sc(82,fd,0,0,0,0,0);closefd(&fd);}
__attribute__((visibility("default")))void _init(void){copy(r.magic,magic,8);copy(r.plan_id,oa_plan_id,32);r.version=1;r.mode=0xffffffffU;r.plugin_unlink=-1;r.readonly=-1;r.euid=sc(175,0,0,0,0,0,0);r.pid=sc(172,0,0,0,0,0,0);if(r.euid||r.pid<=0)r.status=-13;if(!r.status)r.status=plan_guard();if(!r.status)r.status=validate_request();r.phase=1;if(!r.status){r.plugin_unlink=self_unlink();r.status=r.plugin_unlink;}if(!r.status){r.status=workspace();if(!r.status)r.flags|=F_WORKSPACE;}if(!r.status){r.status=mount_state(1);if(r.status&&q->guard_flags)r.status=mount_state(0);if(!r.status)r.flags|=F_MOUNT;}if(!r.status)r.status=parent_open();r.phase=2;if(!r.status){r.source_status=open_sources();r.status=r.source_status;}if(!r.status){U already=q->mode>=2?r.stage.size:0;r.fs_status=budget(already);r.status=r.fs_status;}
 if(!r.status&&!q->mode){r.phase=9;r.flags|=F_COMPLETE;}
 if(!r.status&&q->mode){r.phase=3;rw_attempted=1;r.remount=remount_usr(0);r.status=r.remount;if(!r.status)r.status=source_check(0);if(!r.status&&q->mode<2)r.status=absent(stage_name);if(!r.status&&q->mode>=2)r.status=stage_check(0,0);if(!r.status){r.phase=q->mode+3;if(q->mode==1)r.status=begin_stage();else if(q->mode==2)r.status=append_stage();else if(q->mode==3)r.status=commit_stage();else r.status=abort_stage();}}
 {I c=closefd(&stage_fd);if(!r.status&&c)r.status=c;c=closefd(&source_fd);if(!r.status&&c)r.status=c;c=closefd(&parent_fd);if(!r.status&&c)r.status=c;}int deferred_ok=0;I operation=r.status;if(rw_attempted)r.readonly=remount_usr(1);else r.readonly=mount_state(1);if(!operation&&r.readonly)r.status=r.readonly;if(!operation&&rw_attempted&&r.readonly==-16&&!r.profile&&!r.close_errors&&!(r.flags&F_UNKNOWN)){I checked=0;if(q->mode==1||q->mode==2)checked=deferred_stage_hashes();if(checked){r.status=checked;r.flags|=F_UNKNOWN;}else if((r.flags&(F_SOURCE_HASH|F_STAGE_HASH))==(F_SOURCE_HASH|F_STAGE_HASH)){r.status=-16;r.phase=9;r.flags|=F_COMPLETE;deferred_ok=1;}}if(!r.status&&!r.close_errors){r.phase=9;r.flags|=F_COMPLETE;}else if(!deferred_ok)r.flags&=~F_COMPLETE;publish();}

/* Explicit filenames, no wildcard acceptance at runtime. */
static const char*allowed_names[8]={"image_00_23_IPSX.uxc","image_00_32_IPSX.uxc","string_english_horizontal.uxc","string_english_vertical.uxc","string_simplifiedchinese_horizontal.uxc","string_simplifiedchinese_vertical.uxc","string_traditionalchinese_horizontal.uxc","string_traditionalchinese_vertical.uxc"};
static I plan_guard(void){if(sizeof(oa_plan_id)!=32||sizeof(oa_source_sha256)!=32||sizeof(oa_target_sha256)!=32||!nonzero(oa_plan_id,32)||!nonzero(oa_source_sha256,32)||!nonzero(oa_target_sha256,32)||source_size>MAX_FILE||!target_size||target_size>MAX_FILE)return -22;const char prefix[]="/usr/share/app/";U parent_length=0;W matches=0;if(length(actual_path)>sizeof(prefix)-1&&equal((const B*)actual_path,(const B*)prefix,sizeof(prefix)-1)){r.profile=0;parent_length=sizeof(prefix)-1;source_name=actual_path+parent_length;for(W j=0;j<8;j++)if(part((const B*)source_name,length(source_name),allowed_names[j]))matches++;}else if(part((const B*)actual_path,length(actual_path),"/cp/SysSound.bin")){r.profile=1;parent_length=4;source_name=actual_path+4;matches=1;}if(matches!=1)return -22;const char stem[]=".a7m4-original-",suffix[]=".stage",hex[]="0123456789abcdef";if(length(stage_path)!=parent_length+sizeof(stem)-1+64+sizeof(suffix)-1||!equal((const B*)stage_path,(const B*)actual_path,parent_length))return -22;stage_name=stage_path+parent_length;if(!equal((const B*)stage_name,(const B*)stem,sizeof(stem)-1))return -22;U a=sizeof(stem)-1;for(W j=0;j<32;j++)if(stage_name[a+j*2]!=hex[oa_plan_id[j]>>4]||stage_name[a+j*2+1]!=hex[oa_plan_id[j]&15])return -22;if(!part((const B*)stage_name+a+64,sizeof(suffix)-1,suffix))return -22;return 0;}
