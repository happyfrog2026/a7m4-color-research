/* Original-on-current-source read-only AP load proof, MIT. No COW/memory/program writes,
 * no mount/settings/WBI/NOR/USB/shell. Expected bytes are private build inputs.
 * Native maps derive all VAs. Only fixed AP file windows may be inspected. */
#ifdef AP_ORIGINAL_ON_SOURCE_TARGET_ABI_CHECK
#define _GNU_SOURCE 1
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#endif
typedef unsigned long U;typedef long I;typedef unsigned int W;typedef unsigned char B;
#ifdef AP_ORIGINAL_ON_SOURCE_TEST
extern I ap_original_on_source_syscall(I,I,I,I,I,I,I);
static I sc(I n,I a,I b,I c,I d,I e,I f){return ap_original_on_source_syscall(n,a,b,c,d,e,f);}
#else
static I sc(I n,I a,I b,I c,I d,I e,I f){register I x0 __asm__("x0")=a,x1 __asm__("x1")=b,x2 __asm__("x2")=c,x3 __asm__("x3")=d,x4 __asm__("x4")=e,x5 __asm__("x5")=f,x8 __asm__("x8")=n;__asm__ volatile("svc 0":"+r"(x0):"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5),"r"(x8):"memory","cc");return x0;}
#endif
struct Window{U offset;W size;const B*disk,*runtime;};
#ifndef AP_ORIGINAL_ON_SOURCE_PLAN
#define AP_ORIGINAL_ON_SOURCE_PLAN "ap-original-on-source-plan.h"
#endif
#include AP_ORIGINAL_ON_SOURCE_PLAN
#define RF 0x88800UL
#define REQUEST "/tmp/jiritsu/a7m4.original-ap-original-on-source.request"
#define RESULT "/tmp/jiritsu/a7m4.original-ap-original-on-source.result"
#define LIBRARY "/tmp/jiritsu/libJit.so"
struct Stat{U dev,ino;W mode,nlink,uid,gid;U rdev,pad;I size;W blksize,pad2;U blocks,rest[7];};
struct Request{B magic[8],nonce[16],plan[32],reserved[8];};
struct Report{B magic[8];W version,phase;B nonce[16],plan[32];I status,euid,pid,close,unlink;U dev,ino,size;W windows,covered,aliases,comparisons;B boot[40],reserved[8];};
_Static_assert(sizeof(struct Request)==64,"request64");_Static_assert(sizeof(struct Report)==192,"report192");_Static_assert(sizeof(struct Stat)==128,"stat128");
#ifdef AP_ORIGINAL_ON_SOURCE_TARGET_ABI_CHECK
_Static_assert(sizeof(struct stat)==sizeof(struct Stat),"target stat size");
_Static_assert(__builtin_offsetof(struct stat,st_dev)==__builtin_offsetof(struct Stat,dev),"target dev");
_Static_assert(__builtin_offsetof(struct stat,st_ino)==__builtin_offsetof(struct Stat,ino),"target inode");
_Static_assert(__builtin_offsetof(struct stat,st_mode)==__builtin_offsetof(struct Stat,mode),"target mode");
_Static_assert(__builtin_offsetof(struct stat,st_nlink)==__builtin_offsetof(struct Stat,nlink),"target nlink");
_Static_assert(__builtin_offsetof(struct stat,st_uid)==__builtin_offsetof(struct Stat,uid),"target uid");
_Static_assert(__builtin_offsetof(struct stat,st_gid)==__builtin_offsetof(struct Stat,gid),"target gid");
_Static_assert(__builtin_offsetof(struct stat,st_size)==__builtin_offsetof(struct Stat,size),"target size offset");
_Static_assert(RF==(O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_NOFOLLOW),"target read flags");
_Static_assert(SYS_openat==56&&SYS_close==57&&SYS_read==63&&SYS_pread64==67&&SYS_newfstatat==79&&SYS_fstat==80&&SYS_getpid==172&&SYS_geteuid==175,"target syscall ABI");
#endif

static B maps[262144],again[262144],bytes[512],covered[256][512];static struct Report r;
static int same(const B*a,const B*b,U n){for(U j=0;j<n;j++)if(a[j]!=b[j])return 0;return 1;}
static I op(const char*p,U flags){return sc(56,-100,(I)p,flags,0600,0,0);}
static I cl(I*f){if(*f<0)return 0;I s=sc(57,*f,0,0,0,0,0);*f=-1;if(s&&!r.close)r.close=s;return s;}
static I exact(I f,B*b,U n,U off){U done=0,retry=0;while(done<n){I v=sc(67,f,(I)(b+done),n-done,off+done,0,0);if(v==-4&&retry++<3)continue;if(v<=0||(U)v>n-done)return v<0?v:-5;done+=(U)v;}return 0;}
static I all(const char*p,B*b,U cap){I f=op(p,RF);if(f<0)return f;U n=0,retry=0;I e=0;while(n<cap){I v=sc(63,f,(I)(b+n),cap-n,0,0,0);if(v==-4&&retry++<3)continue;if(v<0){e=v;break;}if(!v)break;if((U)v>cap-n){e=-75;break;}n+=(U)v;}I c=cl(&f);return e?e:c?c:n==cap?-75:(I)n;}
static int number(const B*b,U end,U*a,U*v,W base){U value=0,at=*a;while(*a<end){B c=b[*a];W d=c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:c>='A'&&c<='F'?c-'A'+10:99;if(d>=base)break;if(value>(~0UL-d)/base)return 0;value=value*base+d;(*a)++;}*v=value;return *a>at;}
static I inspect(I mem,U length){U lines=0;for(U start=0;start<length;){U end=start;while(end<length&&maps[end]!='\n')end++;if(end==length||++lines>4096)return -75;U a=start,va=0,stop=0,off=0,major=0,minor=0,ino=0;
 if(!number(maps,end,&a,&va,16)||a>=end||maps[a++]!='-'||!number(maps,end,&a,&stop,16)||a>=end||maps[a++]!=' '||a+5>end)return -22;
 int readable=maps[a]=='r',writable=maps[a+1]=='w',private_map=maps[a+3]=='p';a+=5;
 if(!number(maps,end,&a,&off,16)||a>=end||maps[a++]!=' '||!number(maps,end,&a,&major,16)||a>=end||maps[a++]!=':'||!number(maps,end,&a,&minor,16)||a>=end||maps[a++]!=' ')return -22;
 while(a<end&&maps[a]==' ')a++;if(!number(maps,end,&a,&ino,10)||stop<=va)return -22;while(a<end&&maps[a]==' ')a++;
 const B*p=(const B*)"/usr/lib/appFw.so";U n=17;int match=end-a==n&&same(maps+a,p,n);match|=end-a==n+10&&same(maps+a,p,n)&&same(maps+a+n,(const B*)" (deleted)",10);
 if(match){U expected_major=((expected_dev>>8)&0xfff)|((expected_dev>>32)&~0xfffUL),expected_minor=(expected_dev&0xff)|((expected_dev>>12)&~0xffUL);
 if(!ino||ino!=expected_ino||major!=expected_major||minor!=expected_minor||r.aliases++>=256)return -13;for(W k=0;k<window_count;k++){const struct Window*w=&windows[k];U lo=w->offset>off?w->offset:off,hi=w->offset+w->size<off+stop-va?w->offset+w->size:off+stop-va;
 if(hi<=lo)continue;if(!readable||!private_map||writable)return -13;if(lo<off||va>~0UL-(lo-off)||hi-lo>512)return -22;I e=exact(mem,bytes,hi-lo,va+lo-off);if(e)return e;if(!same(bytes,w->runtime+lo-w->offset,hi-lo))return -84;
 for(U j=lo;j<hi;j++)covered[k][j-w->offset]=1;r.comparisons++;}}
 start=end+1;}
 for(W k=0;k<window_count;k++){for(W j=0;j<windows[k].size;j++)if(!covered[k][j])return -18;r.covered++;}return 0;}
__attribute__((visibility("default")))void original_ap_original_on_source_probe(void){struct Request q={0};struct Stat before={0},after={0};for(W j=0;j<8;j++)r.magic[j]=((const B*)"A7AO0001")[j];r.version=1;r.euid=sc(175,0,0,0,0,0,0);r.pid=sc(172,0,0,0,0,0,0);r.unlink=-1;r.windows=window_count;
 if(r.euid||r.pid!=(I)expected_pid)r.status=-13;if(!window_count||window_count>256)r.status=-22;I in=-1,ap=-1,mem=-1;I n=0;if(!r.status){in=op(REQUEST,RF);if(in<0)r.status=in;}
 if(!r.status){r.status=sc(80,in,(I)&before,0,0,0,0);if(!r.status&&((before.mode&0170000)!=0100000||before.size!=64||before.nlink!=1||before.uid))r.status=-22;}
 if(!r.status)r.status=exact(in,(B*)&q,sizeof(q),0);cl(&in);B any=0;for(W j=0;j<16;j++){any|=q.nonce[j];r.nonce[j]=q.nonce[j];}for(W j=0;j<32;j++)r.plan[j]=q.plan[j];
 if(!r.status&&(!any||!same(q.magic,(const B*)"A7AOQ001",8)||!same(q.plan,plan_id,32)))r.status=-22;for(W j=0;j<8;j++)if(q.reserved[j])r.status=-22;
 if(!r.status){r.unlink=sc(35,-100,(I)LIBRARY,0,0,0,0);if(r.unlink)r.status=r.unlink;}
 if(!r.status){n=all("/proc/sys/kernel/random/boot_id",r.boot,40);if(n!=37||r.boot[36]!='\n')r.status=n<0?n:-22;else{r.boot[36]=0;if(!same(r.boot,expected_boot,36))r.status=-116;}}
 if(!r.status){ap=op("/usr/lib/appFw.so",RF);if(ap<0)r.status=ap;}
 if(!r.status){r.status=sc(80,ap,(I)&before,0,0,0,0);if(!r.status&&((before.mode&0170000)!=0100000||before.size!=(I)ap_size||before.nlink!=1||before.dev!=expected_dev||before.ino!=expected_ino))r.status=-22;r.dev=before.dev;r.ino=before.ino;r.size=before.size;}
 for(W k=0;k<window_count&&!r.status;k++){const struct Window*w=&windows[k];if(!w->size||w->size>512||w->offset+w->size>ap_size){r.status=-22;break;}r.status=exact(ap,bytes,w->size,w->offset);if(!r.status&&!same(bytes,w->disk,w->size))r.status=-84;}
 r.phase=1;if(!r.status){n=all("/proc/self/maps",maps,sizeof(maps));if(n<=0)r.status=n?n:-22;}
 if(!r.status){mem=op("/proc/self/mem",RF);if(mem<0)r.status=mem;}
 if(!r.status)r.status=inspect(mem,(U)n);cl(&mem);
 if(!r.status){I m=all("/proc/self/maps",again,sizeof(again));if(m!=n||!same(maps,again,(U)n))r.status=-116;}
 if(!r.status){r.status=sc(80,ap,(I)&after,0,0,0,0);if(!r.status&&(before.dev!=after.dev||before.ino!=after.ino||before.size!=after.size||before.mode!=after.mode||before.nlink!=after.nlink||before.uid!=after.uid||before.gid!=after.gid))r.status=-116;}if(!r.status){struct Stat named={0};r.status=sc(79,-100,(I)"/usr/lib/appFw.so",(I)&named,0x100,0,0);if(!r.status&&(named.dev!=before.dev||named.ino!=before.ino||named.size!=before.size||named.mode!=before.mode||named.nlink!=1||named.uid!=before.uid||named.gid!=before.gid))r.status=-116;}cl(&ap);
 if(r.close&&!r.status)r.status=r.close;if(!r.status&&r.covered==r.windows&&r.aliases&&r.comparisons)r.phase=9;
 I out=op(RESULT,RF|1|64|128);if(out>=0){U at=0;while(at<sizeof(r)){I v=sc(64,out,(I)((B*)&r+at),sizeof(r)-at,0,0,0);if(v<=0)break;at+=(U)v;}sc(82,out,0,0,0,0,0);sc(57,out,0,0,0,0,0);}}
#ifndef AP_ORIGINAL_ON_SOURCE_TEST
__attribute__((visibility("default")))void _init(void){original_ap_original_on_source_probe();}
#endif
