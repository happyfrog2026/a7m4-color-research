/* Original toolbox code, MIT. AArch64 Linux, fixed temporary workspace only.
 * No remount, program/settings/bank write, reset, shell, or dynamic path.
 * The first bootstrap upload cannot claim a pre-upload free-space measurement;
 * this probe obtains that measurement before any persistent-feature upload.
 */
typedef unsigned long U;
typedef long I;
typedef unsigned int W;
typedef unsigned char B;
#ifdef M4_PROBE_TEST
extern I m4_probe_syscall(I,I,I,I,I,I,I);
static I sc(I n,I a,I b,I c,I d,I e,I f){return m4_probe_syscall(n,a,b,c,d,e,f);}
#else
static I sc(I n,I a,I b,I c,I d,I e,I f){
 register I x0 __asm__("x0")=a,x1 __asm__("x1")=b,x2 __asm__("x2")=c;
 register I x3 __asm__("x3")=d,x4 __asm__("x4")=e,x5 __asm__("x5")=f,x8 __asm__("x8")=n;
 __asm__ volatile("svc 0":"+r"(x0):"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5),"r"(x8):"memory","cc");return x0;
}
#endif
#include "probe_identity.h"
#define REQUEST "/tmp/jiritsu/m4.toolbox-space.request"
#define RESULT "/tmp/jiritsu/m4.toolbox-space.result"
#define LIBRARY "/tmp/jiritsu/libJit.so"
#define READ_FLAGS 0x88800UL
struct Stat{U dev,ino;W mode,nlink,uid,gid;U rdev,pad;I size;W blksize,pad2;U blocks,rest[7];};
struct FS{I type,bsize;U blocks,bfree,bavail,files,ffree;W fsid[2];I namelen,frsize,flags,spare[4];};
struct Request{B magic[8];W version,reserved;B nonce[16],identity[32];};
struct Report{B magic[8];W version,phase;B nonce[16];I status,euid,pid,frsize,bavail,fsid,close_status,cleanup;B boot_id[40];};
_Static_assert(sizeof(struct Stat)==128,"stat ABI");
_Static_assert(sizeof(struct FS)==120,"statfs ABI");
_Static_assert(sizeof(struct Request)==64,"request ABI");
_Static_assert(sizeof(struct Report)==136,"report ABI");
static I op(const char*p,U flags){return sc(56,-100,(I)p,flags,0600,0,0);}
static int equal(const B*a,const B*b,U n){for(U j=0;j<n;j++)if(a[j]!=b[j])return 0;return 1;}
static I transfer(I fd,B*data,U size,int write){
 U done=0,retries=0;while(done<size){I n=sc(write?64:63,fd,(I)(data+done),size-done,0,0,0);
 if(n==-4&&retries++<3)continue;if(n<=0||(U)n>size-done)return n<0?n:-5;done+=(U)n;}return 0;
}
__attribute__((visibility("default"))) void m4_workspace_probe(void){
 struct Request q={0};struct Report r={0};struct Stat st;struct FS fs;
 for(U j=0;j<8;j++)r.magic[j]=((const B*)"M4SPAR02")[j];
 r.version=2;r.euid=sc(175,0,0,0,0,0,0);r.pid=sc(172,0,0,0,0,0,0);
 if(r.euid||r.pid<=0)return;
 I in=op(REQUEST,READ_FLAGS);if(in<0)return;
 I status=sc(80,in,(I)&st,0,0,0,0);
 if(!status&&((st.mode&0170000)!=0100000||st.nlink!=1||st.uid||st.size!=64))status=-22;
 if(!status)status=transfer(in,(B*)&q,sizeof(q),0);
 r.close_status=sc(57,in,0,0,0,0,0);
 if(status||r.close_status)return;
 B nonce=0;for(U j=0;j<16;j++)nonce|=q.nonce[j];
 if(!equal(q.magic,(const B*)"M4SPAQ02",8)||q.version!=2||q.reserved||!nonce||!equal(q.identity,probe_identity,32))return;
 for(U j=0;j<16;j++)r.nonce[j]=q.nonce[j];
 I out=op(RESULT,READ_FLAGS|1|64|128);if(out<0)return;
 r.status=sc(80,out,(I)&st,0,0,0,0);
 if(!r.status&&((st.mode&0170000)!=0100000||st.nlink!=1||st.uid||st.size))r.status=-22;
 I directory=-1;
 if(!r.status){directory=op("/tmp/jiritsu",READ_FLAGS);if(directory<0)r.status=directory;}
 if(!r.status){r.status=sc(80,directory,(I)&st,0,0,0,0);if(!r.status&&(st.mode&0170000)!=0040000)r.status=-20;}
 if(!r.status){r.status=sc(44,directory,(I)&fs,0,0,0,0);if(!r.status){
  if(fs.frsize<=0||fs.frsize>1048576||fs.bavail>0x7fffffffffffffffUL/(U)fs.frsize)r.status=-75;
  else{r.frsize=fs.frsize;r.bavail=(I)fs.bavail;r.fsid=(I)(((U)fs.fsid[1]<<32)|fs.fsid[0]);}
 }}
 if(directory>=0){I close=sc(57,directory,0,0,0,0,0);if(close)r.close_status=close;}
 /* GET_FILE can depend on a stat/fseek size. Read this fixed proc file
    directly instead, so a zero st_size is never mistaken for an empty ID. */
 if(!r.status){
  I boot=op("/proc/sys/kernel/random/boot_id",READ_FLAGS);if(boot<0)r.status=boot;
  else{B raw[38];U done=0,retries=0;while(done<38){I n=sc(63,boot,(I)(raw+done),38-done,0,0,0);
   if(n==-4&&retries++<3)continue;if(n<0){r.status=n;break;}if(!n)break;if((U)n>38-done){r.status=-75;break;}done+=(U)n;}
   I close=sc(57,boot,0,0,0,0,0);if(close)r.close_status=close;
   if(!r.status&&(done!=37||raw[36]!='\n'))r.status=-22;
   B nonzero=0;for(U j=0;!r.status&&j<36;j++){
    int dash=j==8||j==13||j==18||j==23;
    if(dash?raw[j]!='-':!((raw[j]>='0'&&raw[j]<='9')||(raw[j]>='a'&&raw[j]<='f')))r.status=-22;
    if(!dash&&raw[j]!='0')nonzero=1;r.boot_id[j]=raw[j];}
   if(!r.status&&!nonzero)r.status=-22;
  }
 }
 /* Delete only the two fixed owned inputs, after the nonce was validated. */
 I cleanup=sc(35,-100,(I)REQUEST,0,0,0,0);if(cleanup)r.cleanup=cleanup;
 cleanup=sc(35,-100,(I)LIBRARY,0,0,0,0);if(cleanup)r.cleanup=cleanup;
 r.phase=(!r.status&&!r.close_status&&!r.cleanup)?9:8;
 if(!transfer(out,(B*)&r,sizeof(r),1))sc(82,out,0,0,0,0,0);
 sc(57,out,0,0,0,0,0);
}
#ifndef M4_PROBE_TEST
__attribute__((visibility("default"))) void _init(void){m4_workspace_probe();}
#endif
