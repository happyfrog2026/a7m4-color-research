/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 A7M4 Fastboot Toolkit contributors
 * Derived from local/release-transfer-20261027/tail-restore/native/tail_restore.c
 * (syscall, dynamic loader identity, bounded reads and VFAT reserve guards).
 * Only persistent operations: fixed loader unlink, one /usr RO remount,
 * and fixed report staging/publication. No shell, other PID, device or memory IO.
 */
#ifdef TARGET_ABI
#define _GNU_SOURCE 1
#include <fcntl.h>
#include <sys/mount.h>
#endif
typedef unsigned long U;typedef long I;typedef unsigned int W;typedef unsigned char B;
#define RF (0x8000UL|0x80000UL)
#define DIRECTORY 0x4000UL
#define RESERVE 8388608UL
#ifdef TARGET_ABI
_Static_assert(RF==(O_NOFOLLOW|O_CLOEXEC)&&DIRECTORY==O_DIRECTORY,"open flags");
_Static_assert((MS_RDONLY|MS_SYNCHRONOUS|MS_REMOUNT|MS_NOATIME|MS_NODIRATIME)==0xc31,"RO only mount flags");
#endif
static I sc(I n,I a,I b,I c,I d,I e,I f){register I x0 __asm__("x0")=a,x1 __asm__("x1")=b,x2 __asm__("x2")=c,x3 __asm__("x3")=d,x4 __asm__("x4")=e,x5 __asm__("x5")=f,x8 __asm__("x8")=n;__asm__ volatile("svc 0":"+r"(x0):"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5),"r"(x8):"memory","cc");return x0;}
struct Stat{U dev,ino;W mode,nlink,uid,gid;U rdev,pad1;I size;W blksize,pad2;U blocks,rest[7];};
struct FS{I type,bsize;U blocks,bfree,bavail,files,ffree;W fsid[2];I namelen,frsize,flags,spare[4];};
struct Request{B magic[8];W version,total;B nonce[16],plan_id[32],reserved[16];};
struct Report{B magic[8];W version,total;struct Request request;W phase,flags,outcome,mount_attempts;I status,euid,pid,plugin_unlink,proc_status,budget_status,request_status,initial_mount,remount_status,final_mount,close_errors;U workspace_free,workspace_required,loader_dev,loader_ino,loader_size;W request_bytes,reserved[3];};
_Static_assert(sizeof(struct Stat)==128&&sizeof(struct FS)==120,"stat ABI");
_Static_assert(sizeof(struct Request)==80&&sizeof(struct Report)==256,"wire ABI");
#include PLAN_MANIFEST
static const char library[]="/tmp/jiritsu/libJit.so",rqpath[]="/tmp/jiritsu/a7m4.usr-ro.request",pending[]="/tmp/jiritsu/a7m4.usr-ro.result.pending",result[]="/tmp/jiritsu/a7m4.usr-ro.result";
static const B rqmagic[8]="A7URQ001",rmagic[8]="A7URR001";
#define MAX_MAPS_BYTES (1024UL*1024UL)
/* Read the entire proc view through EOF. The extra byte detects overflow;
 * a table of exactly MAX_MAPS_BYTES is admissible only after EOF is read. */
static struct Report r;static B rqbuf[81],maps[MAX_MAPS_BYTES+1],mounts[32768];
void _init(void);
static int same(const B*a,const B*b,U n){for(U i=0;i<n;i++)if(a[i]!=b[i])return 0;return 1;}
static void copy(B*a,const B*b,U n){for(U i=0;i<n;i++)a[i]=b[i];}
static U len(const char*s){U n=0;while(s[n])n++;return n;}
static int part(const B*b,U n,const char*s){return n==len(s)&&same(b,(const B*)s,n);}
static I op(const char*p,I flags){return sc(56,-100,(I)p,flags,0600,0,0);}
static I cl(I*fd){if(*fd<0)return 0;I e=sc(57,*fd,0,0,0,0,0);*fd=-1;if(e)r.close_errors++;return e;}
static I all(const char*p,B*b,W cap,int proc){I fd=op(p,RF);if(fd<0)return fd;I e=0;struct FS fs;if(proc){e=sc(44,fd,(I)&fs,0,0,0,0);if(!e&&fs.type!=0x9fa0)e=-22;}W at=0;while(!e&&at<cap){I n=sc(63,fd,(I)(b+at),cap-at,0,0,0);if(n<0){e=n;break;}if(!n)break;if((U)n>cap-at){e=-5;break;}at+=(W)n;}if(!e&&at==cap)e=-75;I c=cl(&fd);return e?e:c?c:at;}
static int number(const B*b,U end,U*a,U*v,W radix){U n=0,start=*a;while(*a<end){B c=b[*a];W d=c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:99;if(d>=radix)break;if(n>(~0UL-d)/radix)return 0;n=n*radix+d;(*a)++;}*v=n;return *a>start;}
static I validate_request(void){I n=all(rqpath,rqbuf,sizeof(rqbuf),0);if(n<0)return n;r.request_bytes=(W)n;copy((B*)&r.request,rqbuf,n<80?(U)n:80);if(n!=80)return -22;struct Request*q=&r.request;W any=0,planany=0;for(W i=0;i<16;i++){any|=q->nonce[i];if(q->reserved[i])return -22;}for(W i=0;i<32;i++)planany|=ur_plan_id[i];if(!any||!planany||!same(q->magic,rqmagic,8)||q->version!=1||q->total!=80||!same(q->plan_id,ur_plan_id,32))return -22;r.flags|=1;return 0;}
static I workspace(void){I fd=op("/tmp/jiritsu",RF|DIRECTORY);if(fd<0)return fd;struct Stat s;struct FS fs;I e=sc(80,fd,(I)&s,0,0,0,0);if(!e&&((s.mode&0170000)!=0040000||s.uid||(s.mode&0022)))e=-13;if(!e)e=sc(44,fd,(I)&fs,0,0,0,0);if(!e&&(fs.type!=0x4d44||fs.frsize<=0||fs.frsize>65536||fs.bavail>~0UL/(U)fs.frsize))e=-22;if(!e){r.workspace_free=fs.bavail*(U)fs.frsize;r.workspace_required=RESERVE+2*(U)fs.frsize;if(r.workspace_free<r.workspace_required)e=-28;}I c=cl(&fd);return e?e:c;}
/* The running constructor must itself lie in a private executable mapping of
 * this dynamically observed root-owned regular loader inode. No fixed VA/ino. */
static I self_unlink(void){I fd=op(library,RF);if(fd<0)return fd;struct Stat s;I e=sc(80,fd,(I)&s,0,0,0,0);if(!e&&((s.mode&0170000)!=0100000||s.uid||s.nlink!=1||s.size<=0||s.size>=65536))e=-22;I n=0;if(!e){n=all("/proc/self/maps",maps,sizeof(maps),1);if(n<0)e=n;else if(!n||maps[n-1]!='\n')e=-22;}W found=0;U pc=(U)&_init;for(U at=0;!e&&at<(U)n;){U end=at;while(end<(U)n&&maps[end]!='\n')end++;U p=at,a,z,off,major,minor,ino;if(!number(maps,end,&p,&a,16)||p>=end||maps[p++]!='-'||!number(maps,end,&p,&z,16)||p+6>end||maps[p++]!=' '){e=-22;break;}if((maps[p]!='r'&&maps[p]!='-')||(maps[p+1]!='w'&&maps[p+1]!='-')||(maps[p+2]!='x'&&maps[p+2]!='-')||(maps[p+3]!='p'&&maps[p+3]!='s')||maps[p+4]!=' '){e=-22;break;}int rx=maps[p]=='r'&&maps[p+2]=='x'&&maps[p+3]=='p';p+=5;if(!number(maps,end,&p,&off,16)||p>=end||maps[p++]!=' '||!number(maps,end,&p,&major,16)||p>=end||maps[p++]!=':'||!number(maps,end,&p,&minor,16)||p>=end||maps[p++]!=' '){e=-22;break;}while(p<end&&maps[p]==' ')p++;if(!number(maps,end,&p,&ino,10)||z<=a){e=-22;break;}while(p<end&&maps[p]==' ')p++;U devmajor=((s.dev>>8)&0xfff)|((s.dev>>32)&~0xfffUL),devminor=(s.dev&0xff)|((s.dev>>12)&~0xffUL);if(a<=pc&&pc<z&&rx&&major==devmajor&&minor==devminor&&ino==s.ino&&part(maps+p,end-p,library))found++;at=end+1;}if(!e&&found!=1)e=-18;if(!e){r.loader_dev=s.dev;r.loader_ino=s.ino;r.loader_size=(U)s.size;e=sc(35,-100,(I)library,0,0,0,0);}if(!e){e=sc(80,fd,(I)&s,0,0,0,0);if(!e&&s.nlink)e=-116;}I c=cl(&fd);return e?e:c;}
/* Strict six-field proc record, one exact public M4 source+mountpoint+ext2.
 * Any nested /usr mount, duplicate or ambiguous option state is refused. */
static I mount_state(void){I n=all("/proc/self/mounts",mounts,sizeof(mounts),1);if(n<0){r.proc_status=n;return n;}if(!n||mounts[n-1]!='\n'){r.proc_status=-22;return -22;}r.proc_status=0;r.flags|=2;W count=0;I state=-22;for(U at=0;at<(U)n;){U end=at;while(end<(U)n&&mounts[end]!='\n')end++;U starts[6],ends[6],p=at;for(W f=0;f<6;f++){starts[f]=p;while(p<end&&mounts[p]!=' ')p++;ends[f]=p;if(starts[f]==ends[f]||(f<5&&(p==end||mounts[++p]==' ')))return -22;}if(p!=end)return -22;const B*t=mounts+starts[1];U tn=ends[1]-starts[1];if(tn>4&&same(t,(const B*)"/usr",4)&&(t[4]=='/'||t[4]=='\\'))return -22;if(part(t,tn,"/usr")){count++;if(!part(mounts+starts[0],ends[0]-starts[0],"/dev/nflasha15")||!part(mounts+starts[2],ends[2]-starts[2],"ext2"))return -22;W modes=0;for(U k=starts[3];k<ends[3];){U z=k;while(z<ends[3]&&mounts[z]!=',')z++;if(z==k)return -22;if(part(mounts+k,z-k,"ro")){modes++;state=0;}if(part(mounts+k,z-k,"rw")){modes++;state=1;}k=z+1;}if(modes!=1)return -22;}at=end+1;}return count==1?state:-22;}
/* A final filename is created only after all report bytes, fsync and close
 * succeeded. The transport owner holds the exclusive session. Check final
 * absence twice and use the already-established renameat syscall, avoiding
 * a new kernel/filesystem requirement. Publication failure is host rejection.
 */
static int report_absent(void){struct Stat s;return sc(79,-100,(I)result,(I)&s,0x100,0,0)==-2;}
static void publish(void){if(!report_absent())return;I fd=op(pending,RF|1|64|128);if(fd<0)return;U done=0;I e=0;while(done<sizeof(r)){I n=sc(64,fd,(I)((B*)&r+done),sizeof(r)-done,0,0,0);if(n<=0||(U)n>sizeof(r)-done){e=n<0?n:-5;break;}done+=(U)n;}if(!e)e=sc(82,fd,0,0,0,0,0);I c=cl(&fd);if(!e)e=c;if(!e&&report_absent())sc(38,-100,(I)pending,-100,(I)result,0,0);}
__attribute__((visibility("default")))void _init(void){copy(r.magic,rmagic,8);r.version=1;r.total=sizeof(r);r.outcome=4;r.phase=1;r.plugin_unlink=r.proc_status=r.budget_status=r.request_status=r.initial_mount=r.remount_status=r.final_mount=-1;r.euid=sc(175,0,0,0,0,0,0);r.pid=sc(172,0,0,0,0,0,0);if(r.euid||r.pid<=0)r.status=-13;if(!r.status){r.request_status=validate_request();r.status=r.request_status;}r.phase=2;if(!r.status){r.budget_status=workspace();r.status=r.budget_status;if(!r.status)r.flags|=4;}if(!r.status){r.plugin_unlink=self_unlink();r.status=r.plugin_unlink;if(!r.status)r.flags|=8;}r.phase=3;if(!r.status){r.initial_mount=mount_state();if(r.initial_mount<0)r.status=r.initial_mount;else r.flags|=16;}if(!r.status&&r.close_errors)r.status=-5;if(!r.status){if(r.initial_mount==1){r.phase=4;r.mount_attempts=1;r.remount_status=sc(40,0,(I)"/usr",0,0xc31,0,0);}r.phase=5;r.final_mount=mount_state();if(r.final_mount>=0)r.flags|=32;if(r.close_errors)r.status=-5;else if(r.final_mount<0)r.status=r.final_mount;else if(r.initial_mount==0&&r.final_mount==0){r.outcome=1;r.flags|=64;}else if(r.mount_attempts==1&&r.remount_status==0&&r.final_mount==0){r.outcome=2;r.flags|=64;}else if(r.mount_attempts==1&&r.remount_status==-16){r.outcome=3;r.status=-16;}else r.status=r.mount_attempts&&r.remount_status?r.remount_status:-30;}if(r.flags&64)r.phase=6;publish();}
