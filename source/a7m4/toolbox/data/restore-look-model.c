/* SPDX-License-Identifier: MIT
 * Fixed M4 6.02 read-only AP model proof. No AP calls, settings, program,
 * memory, mount, WBI, NOR or boot writes. Only owned temporary report/library.
 * A different boot and factory ST save are host coordinator prerequisites.
 */
typedef unsigned long U;typedef long I;typedef unsigned int W;typedef unsigned char B;
static I sc(I n,I a,I b,I c,I d,I e,I f){register I x0 __asm__("x0")=a,x1 __asm__("x1")=b,x2 __asm__("x2")=c,x3 __asm__("x3")=d,x4 __asm__("x4")=e,x5 __asm__("x5")=f,x8 __asm__("x8")=n;__asm__ volatile("svc 0":"+r"(x0):"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5),"r"(x8):"memory","cc");return x0;}
struct Guard{U offset;const B*bytes;};
#ifndef LOOK_MODEL_PLAN
#define LOOK_MODEL_PLAN "look-model-plan.h"
#endif
#include LOOK_MODEL_PLAN
#define RF 0x88800UL
#define REQUEST "/tmp/jiritsu/a7m4.restore-look-model.request"
#define RESULT "/tmp/jiritsu/a7m4.restore-look-model.result"
#define LIBRARY "/tmp/jiritsu/libJit.so"
struct Stat{U dev,ino;W mode,nlink,uid,gid;U rdev,pad;I size;W blksize,pad2;U blocks,rest[7];};
struct Request{B magic[8],nonce[16],plan[32],reserved[8];};
struct Report{B magic[8];W version,phase;B nonce[16],plan[32];I status,euid,pid,close,unlink;U bias;W guards,seen,current,current2,before[54],after[54];B boot[40],reserved[8];};
_Static_assert(sizeof(struct Request)==64,"request64");_Static_assert(sizeof(struct Report)==608,"report608");_Static_assert(sizeof(struct Stat)==128,"stat128");
static B maps[262144],again[262144],code[20];static struct Report r;
static int same(const B*a,const B*b,U n){for(U j=0;j<n;j++)if(a[j]!=b[j])return 0;return 1;}
static I op(const char*p,U flags){return sc(56,-100,(I)p,flags,0600,0,0);}
static I cl(I*f){if(*f<0)return 0;I s=sc(57,*f,0,0,0,0,0);*f=-1;if(s&&!r.close)r.close=s;return s;}
static I exact(I f,B*b,U n,U off){U done=0,retry=0;while(done<n){I v=sc(67,f,(I)(b+done),n-done,off+done,0,0);if(v==-4&&retry++<3)continue;if(v<=0||(U)v>n-done)return v<0?v:-5;done+=(U)v;}return 0;}
static I all(const char*p,B*b,U cap){I f=op(p,RF);if(f<0)return f;U n=0,retry=0;I e=0;while(n<cap){I v=sc(63,f,(I)(b+n),cap-n,0,0,0);if(v==-4&&retry++<3)continue;if(v<0){e=v;break;}if(!v)break;if((U)v>cap-n){e=-75;break;}n+=(U)v;}I c=cl(&f);return e?e:c?c:n==cap?-75:(I)n;}
static int number(const B*b,U end,U*a,U*v,W base){U value=0,at=*a;while(*a<end){B c=b[*a];W d=c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:c>='A'&&c<='F'?c-'A'+10:99;if(d>=base)break;if(value>(~0UL-d)/base)return 0;value=value*base+d;(*a)++;}*v=value;return *a>at;}
static I find_bias(const B*data,U length,U*bias){U lines=0,matches=0;for(U start=0;start<length;){U end=start;while(end<length&&data[end]!='\n')end++;if(end==length||++lines>4096)return -75;U a=start,va=0,stop=0,off=0,major=0,minor=0,ino=0;
 if(!number(data,end,&a,&va,16)||a>=end||data[a++]!='-'||!number(data,end,&a,&stop,16)||a>=end||data[a++]!=' '||a+5>end)return -22;
 int readable=data[a]=='r',writable=data[a+1]=='w',executable=data[a+2]=='x',private_map=data[a+3]=='p';a+=5;
 if(!number(data,end,&a,&off,16)||a>=end||data[a++]!=' '||!number(data,end,&a,&major,16)||a>=end||data[a++]!=':'||!number(data,end,&a,&minor,16)||a>=end||data[a++]!=' ')return -22;
 while(a<end&&data[a]==' ')a++;if(!number(data,end,&a,&ino,10)||stop<=va)return -22;while(a<end&&data[a]==' ')a++;
 const B*p=(const B*)"/usr/lib/appFw.so";U n=17;int match=end-a==n&&same(data+a,p,n);match|=end-a==n+10&&same(data+a,p,n)&&same(data+a+n,(const B*)" (deleted)",10);
 if(match&&off==0){if(!readable||writable||!executable||!private_map||!ino||!va||va%4096||stop-va<0x290e710UL||++matches!=1)return -13;*bias=va;}
 start=end+1;}return matches==1?0:-18;}
static I read_models(I mem,W*out,W*current){static const U offsets[]={0x802ce08UL,0x802d120UL,0x802d438UL};I e=exact(mem,(B*)current,4,r.bias+0x7feea70UL);for(W j=0;j<3&&!e;j++)e=exact(mem,(B*)(out+j*18),72,r.bias+offsets[j]);return e;}
__attribute__((visibility("default")))void _init(void){struct Request q={0};struct Stat st={0};for(W j=0;j<8;j++)r.magic[j]=((const B*)"A7LM0001")[j];r.version=1;r.guards=4;r.euid=sc(175,0,0,0,0,0,0);r.pid=sc(172,0,0,0,0,0,0);r.unlink=-1;
 if(r.euid||r.pid<=0)r.status=-13;I in=-1,mem=-1,n=0;if(!r.status){in=op(REQUEST,RF);if(in<0)r.status=in;}
 if(!r.status){r.status=sc(80,in,(I)&st,0,0,0,0);if(!r.status&&((st.mode&0170000)!=0100000||st.size!=64||st.nlink!=1||st.uid))r.status=-22;}
 if(!r.status)r.status=exact(in,(B*)&q,sizeof(q),0);cl(&in);B any=0;for(W j=0;j<16;j++){any|=q.nonce[j];r.nonce[j]=q.nonce[j];}for(W j=0;j<32;j++)r.plan[j]=q.plan[j];
 if(!r.status&&(!any||!same(q.magic,(const B*)"A7LMQ001",8)||!same(q.plan,plan_id,32)))r.status=-22;for(W j=0;j<8;j++)if(q.reserved[j])r.status=-22;
 if(!r.status){r.unlink=sc(35,-100,(I)LIBRARY,0,0,0,0);if(r.unlink)r.status=r.unlink;}
 if(!r.status){n=all("/proc/sys/kernel/random/boot_id",r.boot,40);if(n!=37||r.boot[36]!='\n')r.status=n<0?n:-22;else r.boot[36]=0;}
 r.phase=1;if(!r.status){n=all("/proc/self/maps",maps,sizeof(maps));if(n<=0)r.status=n?n:-22;}
 if(!r.status)r.status=find_bias(maps,(U)n,&r.bias);if(!r.status){mem=op("/proc/self/mem",RF);if(mem<0)r.status=mem;}
 for(W j=0;j<4&&!r.status;j++){if(r.bias>~0UL-guards[j].offset)r.status=-75;else r.status=exact(mem,code,20,r.bias+guards[j].offset);if(!r.status&&!same(code,guards[j].bytes,20))r.status=-84;if(!r.status)r.seen++;}
 if(!r.status&&r.bias>~0UL-0x802d480UL)r.status=-75;
 if(!r.status)r.status=read_models(mem,r.before,&r.current);if(!r.status)r.status=read_models(mem,r.after,&r.current2);cl(&mem);
 if(!r.status){I m=all("/proc/self/maps",again,sizeof(again));U bias=0;if(m<=0)r.status=m?m:-22;else r.status=find_bias(again,(U)m,&bias);if(!r.status&&bias!=r.bias)r.status=-116;}
 if(r.close&&!r.status)r.status=r.close;if(!r.status&&r.seen==4)r.phase=9;
 I out=op(RESULT,RF|1|64|128);if(out>=0){U at=0;while(at<sizeof(r)){I v=sc(64,out,(I)((B*)&r+at),sizeof(r)-at,0,0,0);if(v<=0)break;at+=(U)v;}sc(82,out,0,0,0,0,0);sc(57,out,0,0,0,0,0);}}
