/* Original toolbox code, MIT. Fixed single UXC file, atomic inode replacement.
 * No AP/CP/settings/device/reset operations. Never truncate a mapped resource.
 * A failed operation retains owned stage/backup evidence; no automatic inverse.
 */
typedef unsigned long U;typedef long I;typedef unsigned int W;typedef unsigned char B;
#ifdef M4_RESOURCE_TEST
extern I m4_resource_syscall(I,I,I,I,I,I,I);
static I sc(I n,I a,I b,I c,I d,I e,I f){return m4_resource_syscall(n,a,b,c,d,e,f);}
#else
static I sc(I n,I a,I b,I c,I d,I e,I f){
 register I x0 __asm__("x0")=a,x1 __asm__("x1")=b,x2 __asm__("x2")=c;
 register I x3 __asm__("x3")=d,x4 __asm__("x4")=e,x5 __asm__("x5")=f,x8 __asm__("x8")=n;
 __asm__ volatile("svc 0":"+r"(x0):"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5),"r"(x8):"memory","cc");return x0;}
#endif
#include "resource-plan.h"
#include "resource-sha256.h"
#define REQUEST "/tmp/jiritsu/m4.resource.request"
#define RESULT "/tmp/jiritsu/m4.resource.result"
#define LIBRARY "/tmp/jiritsu/libJit.so"
#define RF 0x88800UL
struct Stat{U dev,ino;W mode,nlink,uid,gid;U rdev,pad;I size;W blksize,pad2;U blocks,rest[7];};
struct FS{I type,bsize;U blocks,bfree,bavail,files,ffree;W fsid[2];I namelen,frsize,flags,spare[4];};
struct Request{B magic[8];W mode,reserved;B nonce[16],plan[32];U source_dev,source_ino,current_dev,current_ino,uid,gid,modebits;};
struct Report{B magic[8];W version,mode,phase,commits;I status,remount,readonly,cleanup,euid,pid;
 U dev,ino,size,uid,gid,modebits,fs_type,fs_unit,fs_avail,backup_dev,backup_ino;B observed[32],nonce[16],plan[32];};
_Static_assert(sizeof(struct Stat)==128,"Linux AArch64 stat ABI");
_Static_assert(sizeof(struct FS)==120,"Linux AArch64 statfs ABI");
_Static_assert(sizeof(struct Request)==120,"resource request ABI");
_Static_assert(sizeof(struct Report)==240,"resource report ABI");
static struct Request q;static struct Report r;static B buffer[4096],mounts[8192];
static I op(const char*p,U f,W mode){return sc(56,-100,(I)p,f,mode,0,0);}
static I closefd(I*f){if(*f<0)return 0;I v=sc(57,*f,0,0,0,0,0);*f=-1;return v;}
static int equal(const B*a,const B*b,U n){for(U j=0;j<n;j++)if(a[j]!=b[j])return 0;return 1;}
static I readat(I f,B*b,U n,U at){U done=0,retries=0;while(done<n){I v=sc(67,f,(I)(b+done),n-done,at+done,0,0);
 if(v==-4&&retries++<3)continue;if(v<=0||(U)v>n-done)return v<0?v:-5;done+=(U)v;}return 0;}
static I writeall(I f,const B*b,U n){U done=0,retries=0;while(done<n){I v=sc(64,f,(I)(b+done),n-done,0,0,0);
 if(v==-4&&retries++<3)continue;if(v<=0||(U)v>n-done)return v<0?v:-5;done+=(U)v;}return 0;}
static I statfd(I f,struct Stat*s){I v=sc(80,f,(I)s,0,0,0,0);if(v)return v;
 return (s->mode&0170000)==0100000&&!(s->mode&07022)&&s->nlink>0&&s->nlink<=2?0:-22;}
static I verify(const char*p,U n,const B*hash,struct Stat*s,B*out){I f=op(p,RF,0);if(f<0)return f;
 struct Stat a,b;I v=statfd(f,&a);if(!v&&(a.size!=(I)n||n>16777216UL))v=-22;
 struct SHA h;sha_start(&h);for(U at=0;!v&&at<n;){U size=n-at>4096?4096:n-at;v=readat(f,buffer,size,at);if(!v)sha_add(&h,buffer,size);at+=size;}
 if(!v){v=statfd(f,&b);if(!v&&(a.dev!=b.dev||a.ino!=b.ino||a.size!=b.size||a.mode!=b.mode||a.uid!=b.uid||a.gid!=b.gid||a.nlink!=b.nlink))v=-116;}
 B digest[32];if(!v){sha_end(&h,digest);if(hash&&!equal(digest,hash,32))v=-84;}
 I c=closefd(&f);if(!v)v=c;if(!v){if(s)*s=a;if(out)for(U j=0;j<32;j++)out[j]=digest[j];}return v;}
static I absent(const char*p){I f=op(p,RF,0);if(f==-2)return 0;if(f<0)return f;I c=closefd(&f);return c?c:-17;}
static I mountstate(int ro){I f=op("/proc/self/mounts",RF,0);if(f<0)return f;
 U used=0;I v=0;while(used<sizeof(mounts)){I n=sc(63,f,(I)(mounts+used),sizeof(mounts)-used,0,0,0);
  if(n<0){v=n;break;}if(!n)break;if((U)n>sizeof(mounts)-used){v=-75;break;}used+=(U)n;}
 I c=closefd(&f);if(v)return v;if(c)return c;if(!used||used==sizeof(mounts))return -75;
 U count=0;for(U at=0;at<used;){U end=at;while(end<used&&mounts[end]!='\n')end++;
  U a=at;while(a<end&&mounts[a]!=' ')a++;U b=a+1;while(b<end&&mounts[b]!=' ')b++;
  U d=b+1;while(d<end&&mounts[d]!=' ')d++;
  if(a>=end||b>=end||d>=end)return -22;
  U point=b-a-1;
  if(point>=4&&equal(mounts+a+1,(const B*)"/usr",4)){
   if(point>4&&mounts[a+5]=='/')return -22;
   if(point==4){if(a-at!=14||!equal(mounts+at,(const B*)"/dev/nflasha15",14)
      ||d-b-1!=4||!equal(mounts+b+1,(const B*)"ext2",4))return -22;
    if(d+4>end||mounts[d+1]!='r'||mounts[d+2]!=(ro?'o':'w')||mounts[d+3]!=',')return -30;count++;}}
  at=end+1;}
 return count==1?0:-22;}
static I remount(int ro){I v=sc(40,0,(I)"/usr",0,0xc30UL+(ro?1:0),0,0);return v?v:mountstate(ro);}
static const char *allowed_resource_paths[8]={"/usr/share/app/image_00_23_IPSX.uxc","/usr/share/app/image_00_32_IPSX.uxc","/usr/share/app/string_english_horizontal.uxc","/usr/share/app/string_english_vertical.uxc","/usr/share/app/string_simplifiedchinese_horizontal.uxc","/usr/share/app/string_simplifiedchinese_vertical.uxc","/usr/share/app/string_traditionalchinese_horizontal.uxc","/usr/share/app/string_traditionalchinese_vertical.uxc"};
static int allowed_resource(void){for(U i=0;i<8;i++){U j=0;while(actual_path[j]&&allowed_resource_paths[i][j]&&actual_path[j]==allowed_resource_paths[i][j])j++;if(!actual_path[j]&&!allowed_resource_paths[i][j])return 1;}return 0;}
static I dirsync(void){I f=op("/usr/share/app",RF|0x4000,0);if(f<0)return f;I v=sc(82,f,0,0,0,0,0),c=closefd(&f);return v?v:c;}
static I budget(void){struct FS fs;I v=sc(43,(I)"/usr",(I)&fs,0,0,0,0);if(v)return v;
 if(fs.type!=0xef53||fs.frsize<=0||fs.frsize>1048576||fs.bavail>0x7fffffffffffffffUL/(U)fs.frsize)return -22;
 r.fs_type=(U)fs.type;r.fs_unit=(U)fs.frsize;r.fs_avail=fs.bavail*(U)fs.frsize;
 U cost=0;if(q.mode<=1){if(!allocation_count||allocation_count>8||allocation_sizes[0]!=target_size)return -22;
  for(W j=0;j<allocation_count;j++){U n=allocation_sizes[j];if(!n||n>16777216UL)return -22;
   cost+=((n+r.fs_unit-1)/r.fs_unit)*r.fs_unit+4*r.fs_unit;}}
 return r.fs_avail>=8388608UL+cost?0:-28;}
static int inode(const struct Stat*s,U d,U i){return d&&i&&s->dev==d&&s->ino==i;}
static I remove_owned(const char*p,U n,const B*hash,const struct Stat*expected){struct Stat st;
 I v=verify(p,n,hash,&st,0);if(!v&&(!inode(&st,expected->dev,expected->ino)||st.nlink!=1
    ||st.mode!=expected->mode||st.uid!=expected->uid||st.gid!=expected->gid))v=-116;
 return v?v:sc(35,-100,(I)p,0,0,0,0);}
static U parent_dev;
static I parents(void){I fd=-1,next=-1,v=0;parent_dev=0;const char*names[]={"/usr","share","app"};
 for(U j=0;j<3;j++){next=sc(56,j?fd:-100,(I)names[j],RF|0x4000,0,0,0);if(next<0){v=next;break;}
  struct Stat st;v=sc(80,next,(I)&st,0,0,0,0);
  /* Factory share/app directories need not be owned by root. */
  if(!v&&((st.mode&0170000)!=0040000||(st.mode&07022)))v=-22;
  if(!v&&(!st.dev||(parent_dev&&st.dev!=parent_dev)||(q.mode&&st.dev!=q.current_dev)))v=-116;
  if(!v)parent_dev=st.dev;
  I c=closefd(&fd);if(!v)v=c;fd=next;next=-1;if(v)break;}
 I c=closefd(&fd);return v?v:c;}
static I attributes(const struct Stat*a,const struct Stat*b){return a->mode==b->mode&&a->uid==b->uid&&a->gid==b->gid;}
static I build_stage(struct Stat*source,struct Stat*created){I in=op(actual_path,RF,0),out=-1;if(in<0)return in;
 struct Stat st;I v=statfd(in,&st);if(!v&&(!inode(&st,q.source_dev,q.source_ino)||st.nlink!=2))v=-116;
 if(!v){out=op(stage_path,RF|1|64|128,source->mode&0777);if(out<0)v=out;}
 if(!v)v=sc(55,out,source->uid,source->gid,0,0,0);if(!v)v=sc(52,out,source->mode&0777,0,0,0,0);
 if(!v)v=statfd(out,created);if(!v&&(created->size||created->nlink!=1||created->dev!=source->dev
   ||created->ino==source->ino||!attributes(created,source)))v=-116;
 for(U at=0;!v&&at<source_size;){U n=source_size-at>4096?4096:source_size-at;v=readat(in,buffer,n,at);
  for(W j=0;!v&&j<window_count;j++){const struct Window*w=&windows[j];U lo=w->offset>at?w->offset:at;
   U hi=w->offset+w->size<at+n?w->offset+w->size:at+n;
   for(U k=lo;k<hi;k++){U x=k-w->offset;if(buffer[k-at]!=w->before[x]){v=-84;break;}buffer[k-at]=w->after[x];}}
  if(!v)v=writeall(out,buffer,n);at+=n;}
 if(!v)v=writeall(out,append_data,append_size);if(!v)v=sc(82,out,0,0,0,0,0);
 I c=closefd(&in);if(!v)v=c;c=closefd(&out);if(!v)v=c;
 if(!v){struct Stat same;v=verify(stage_path,target_size,target_hash,&same,0);
  if(!v&&(!inode(&same,created->dev,created->ino)||same.nlink!=1||!attributes(&same,source)))v=-116;}return v;}
__attribute__((visibility("default"))) void m4_resource_worker(void){
 for(U j=0;j<sizeof(q);j++)((B*)&q)[j]=0;for(U j=0;j<sizeof(r);j++)((B*)&r)[j]=0;
 for(U j=0;j<8;j++)r.magic[j]=((const B*)"M4RSR001")[j];r.version=1;r.euid=sc(175,0,0,0,0,0,0);r.pid=sc(172,0,0,0,0,0,0);
 if(r.euid||r.pid<=0||!allowed_resource())return;I in=op(REQUEST,RF,0);if(in<0)return;struct Stat rs={0};
 I v=statfd(in,&rs);if(!v&&(rs.uid||rs.gid||rs.nlink!=1||rs.size!=sizeof(q)))v=-22;if(!v)v=readat(in,(B*)&q,sizeof(q),0);
 struct Stat request_stat=rs;B request_hash[32],library_hash[32];struct SHA request_sha;
 I c=closefd(&in);if(v||c)return;B nonce=0;for(U j=0;j<16;j++)nonce|=q.nonce[j];
 if(!equal(q.magic,(const B*)"M4RSQ002",8)||q.reserved||q.mode>4||q.mode==2||!nonce||!equal(q.plan,plan_id,32))return;
 if(!q.mode&&(q.source_dev||q.source_ino||q.current_dev||q.current_ino||q.uid||q.gid||q.modebits))return;
 if(q.mode&&((q.modebits&0170000)!=0100000||q.uid>0xffffffffUL||q.gid>0xffffffffUL))return;
 sha_start(&request_sha);sha_add(&request_sha,(const B*)&q,sizeof(q));sha_end(&request_sha,request_hash);
 r.mode=q.mode;for(U j=0;j<16;j++)r.nonce[j]=q.nonce[j];for(U j=0;j<32;j++)r.plan[j]=plan_id[j];
 I report=op(RESULT,RF|1|64|128,0600);if(report<0)return;
 v=statfd(report,&rs);if(!v&&(rs.uid||rs.gid||rs.nlink!=1||rs.size))v=-22;
 struct Stat current={0},old={0},library_stat={0};int writable=0,library_bound=0;
 I lib=-1;if(!v){lib=op(LIBRARY,RF,0);if(lib<0)v=lib;}
 if(!v)v=statfd(lib,&library_stat);if(!v&&(library_stat.uid||library_stat.gid||library_stat.nlink!=1||library_stat.size<=0||library_stat.size>=65536))v=-22;
 c=closefd(&lib);if(!v)v=c;
 if(!v){struct Stat same;v=verify(LIBRARY,(U)library_stat.size,0,&same,library_hash);
  if(!v&&!inode(&same,library_stat.dev,library_stat.ino))v=-116;if(!v)library_bound=1;}
 if(!v)v=mountstate(1);if(!v)v=parents();if(!v)v=budget();
 if(!v)v=verify(actual_path,q.mode>=3?target_size:source_size,q.mode>=3?target_hash:source_hash,&current,r.observed);
 if(!v&&current.dev!=parent_dev)v=-116;
 if(!v&&q.mode&&(!inode(&current,q.current_dev,q.current_ino)||current.nlink!=1||
    current.uid!=q.uid||current.gid!=q.gid||current.mode!=q.modebits))v=-116;
 if(!v&&q.mode<=1&&current.nlink!=1)v=-22;
 if(!v)v=absent(stage_path);
 if(!v&&q.mode<=1)v=absent(backup_path);
 if(!v&&q.mode>=3){v=verify(backup_path,source_size,source_hash,&old,0);if(!v&&(!inode(&old,q.source_dev,q.source_ino)||old.nlink!=1||old.mode!=current.mode||old.uid!=current.uid||old.gid!=current.gid))v=-116;}
 if(!v&&q.mode==1&&(!inode(&current,q.source_dev,q.source_ino)))v=-116;
 /* A failed post-mount verification does not prove mount(2) left /usr RO.
  * After any RW attempt, always attempt the RO closeout, even on failure. */
 if(!v&&(q.mode==1||q.mode==4)){writable=1;r.remount=remount(0);v=r.remount;}
 if(!v&&q.mode==1){r.phase=1;struct Stat source=current,created={0};v=sc(37,-100,(I)actual_path,-100,(I)backup_path,0,0);
  if(!v)v=build_stage(&source,&created);
  struct Stat same;if(!v)v=verify(actual_path,source_size,source_hash,&same,0);
  if(!v&&(!inode(&same,q.source_dev,q.source_ino)||same.nlink!=2||!attributes(&same,&source)))v=-116;
  if(!v)v=verify(stage_path,target_size,target_hash,&same,0);
  if(!v&&(!inode(&same,created.dev,created.ino)||same.nlink!=1||!attributes(&same,&source)))v=-116;
  if(!v)v=sc(38,-100,(I)stage_path,-100,(I)actual_path,0,0);
  if(!v){r.commits=1;v=dirsync();}
  if(!v)v=verify(actual_path,target_size,target_hash,&current,r.observed);
  if(!v&&(!inode(&current,created.dev,created.ino)||current.nlink!=1||!attributes(&current,&source)))v=-116;
  if(!v)v=verify(backup_path,source_size,source_hash,&old,0);
  if(!v&&(!inode(&old,source.dev,source.ino)||old.nlink!=1||!attributes(&old,&source)))v=-116;}
 if(!v&&q.mode==4){r.phase=4;v=remove_owned(backup_path,source_size,source_hash,&old);if(!v)v=dirsync();}
 if(writable){r.readonly=remount(1);if(!v)v=r.readonly;}
 if(!v){r.dev=current.dev;r.ino=current.ino;r.size=(U)current.size;r.uid=current.uid;r.gid=current.gid;r.modebits=current.mode;
  r.backup_dev=old.dev;r.backup_ino=old.ino;r.phase=9;}
 r.status=v;
 c=remove_owned(REQUEST,sizeof(q),request_hash,&request_stat);if(c)r.cleanup=c;
 if(library_bound){c=remove_owned(LIBRARY,(U)library_stat.size,library_hash,&library_stat);if(c&&!r.cleanup)r.cleanup=c;}
 if(!writeall(report,(B*)&r,sizeof(r)))sc(82,report,0,0,0,0,0);closefd(&report);
}
#ifndef M4_RESOURCE_TEST
__attribute__((visibility("default"))) void _init(void){m4_resource_worker();}
#endif
