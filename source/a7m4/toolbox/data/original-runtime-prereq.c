/* SPDX-License-Identifier: MIT
 * R009a v2: fixed read-only SSH prerequisite inventory. No daemon or socket.
 * Final result is published only after the staging descriptor closes cleanly.
 */
typedef __UINT32_TYPE__ sq_u32;
typedef __UINT64_TYPE__ sq_u64;
typedef __INT64_TYPE__ sq_i64;
typedef unsigned char sq_byte;
typedef char sq_require_64bit_long[(sizeof(long)==8)?1:-1];
#if defined(M4_SSH_PREREQ_V2_TEST)
extern long ssh_prereq_v2_test_syscall(long,long,long,long,long,long,long);
static long sq_syscall(long n,long a,long b,long c,long d,long e,long f)
{ return ssh_prereq_v2_test_syscall(n,a,b,c,d,e,f); }
#elif defined(__aarch64__)
static long sq_syscall(long n,long a,long b,long c,long d,long e,long f)
{
    register long x0 __asm__("x0")=a;register long x1 __asm__("x1")=b;
    register long x2 __asm__("x2")=c;register long x3 __asm__("x3")=d;
    register long x4 __asm__("x4")=e;register long x5 __asm__("x5")=f;
    register long x8 __asm__("x8")=n;
    __asm__ volatile("svc #0":"+r"(x0):"r"(x1),"r"(x2),"r"(x3),
                     "r"(x4),"r"(x5),"r"(x8):"memory","cc");
    return x0;
}
#else
#error "Build for Linux/AArch64 or the in-memory syscall harness."
#endif
enum {
    SQ_SYS_UNLINKAT=35,SQ_SYS_FSTATFS=44,SQ_SYS_OPENAT=56,SQ_SYS_CLOSE=57,
    SQ_SYS_READ=63,SQ_SYS_WRITE=64,SQ_SYS_READLINKAT=78,SQ_SYS_NEWFSTATAT=79,
    SQ_SYS_FSTAT=80,SQ_SYS_FSYNC=82,SQ_SYS_GETGROUPS=158,SQ_SYS_GETPID=172,
    SQ_SYS_GETUID=174,SQ_SYS_GETEUID=175,SQ_SYS_GETGID=176,SQ_SYS_GETEGID=177,
    SQ_SYS_RENAMEAT2=276,SQ_AT_FDCWD=-100,SQ_AT_SYMLINK_NOFOLLOW=256,
    SQ_O_RDONLY=0,SQ_O_WRONLY=1,SQ_O_CREAT=64,SQ_O_EXCL=128,
    SQ_O_NONBLOCK=2048,SQ_O_DIRECTORY=16384,SQ_O_NOFOLLOW=32768,SQ_O_CLOEXEC=524288,
    SQ_READ_FLAGS=SQ_O_RDONLY|SQ_O_NONBLOCK|SQ_O_NOFOLLOW|SQ_O_CLOEXEC,
    SQ_S_IFMT=0170000,SQ_S_IFREG=0100000,SQ_S_IFDIR=0040000,SQ_S_IFLNK=0120000,
    SQ_ENOENT=2,SQ_EINTR=4,SQ_EIO=5,SQ_EACCES=13,SQ_EINVAL=22,SQ_ELOOP=40,
    SQ_EOVERFLOW=75,SQ_ECANCELED=125,SQ_PROC_SUPER_MAGIC=0x9fa0,
    SQ_MSDOS_SUPER_MAGIC=0x4d44,SQ_RENAME_NOREPLACE=1,
    SQ_HEADER=80,SQ_SECTION_HEADER=16,SQ_OBSERVATIONS=38,SQ_SECTIONS=39,SQ_STAT=48,SQ_DIR=128,
    SQ_DIAGNOSTIC_ROW=64,SQ_DIAGNOSTIC_BYTES=SQ_OBSERVATIONS*SQ_DIAGNOSTIC_ROW,
    SQ_MAX_REPORT=131072,SQ_IO_LIMIT=64,SQ_EINTR_LIMIT=16,
    SQ_FREE_MARGIN=8388608,SQ_REPORT_RESERVE=131072
};
struct sq_stat {
    sq_u64 dev,ino;sq_u32 mode,nlink,uid,gid;sq_u64 rdev,pad1;
    sq_i64 size;sq_u32 blksize,pad2;sq_i64 blocks,atime;
    sq_u64 atimensec;sq_i64 mtime;sq_u64 mtimensec;
    sq_i64 ctime;sq_u64 ctimensec;sq_u32 unused[2];
};
struct sq_statfs {
    sq_i64 type,bsize;sq_u64 blocks,bfree,bavail,files,ffree;
    sq_u32 fsid[2];sq_i64 namelen,frsize,flags,spare[4];
};
struct sq_section { const char *path;sq_u32 kind,cap,length;long status;sq_byte *data; };
struct sq_diagnostic {sq_u32 stage,valid;long terminal;sq_byte before[SQ_STAT];};
enum {SQ_FILE=1,SQ_PROC=2,SQ_LINK=3,SQ_DIRECTORY=4,SQ_METADATA=5,SQ_GROUPS=6,SQ_DIAGNOSTICS=7};
enum {SQ_STAGE_NONE=0,SQ_STAGE_LSTAT=1,SQ_STAGE_TYPE=2,SQ_STAGE_OWNER=3,
      SQ_STAGE_OPEN=4,SQ_STAGE_FSTAT=5,SQ_STAGE_IDENTITY=6,SQ_STAGE_FSTATFS=7,
      SQ_STAGE_READ=8,SQ_STAGE_CLOSE=9,SQ_STAGE_READLINK=10,SQ_STAGE_GROUPS=11,
      SQ_STAGE_COMPLETE=12,SQ_STAGE_BOUNDS=13,SQ_STAGE_FS_KIND=14};
static const char sq_loader[]="/tmp/jiritsu/libJit.so";
static const char sq_request[]="/tmp/jiritsu/a7m4.ssh-prereq-v2.request";
static const char sq_result[]="/tmp/jiritsu/a7m4.ssh-prereq-v2.result";
static const char sq_pending[]="/tmp/jiritsu/a7m4.ssh-prereq-v2.result.pending";
static const char sq_version[]="30181_18.2026041801";
static const sq_byte sq_request_magic[8]={'M','4','S','R','E','Q','0','2'};
static const sq_byte sq_result_magic[8]={'M','4','S','S','H','0','0','2'};
static sq_byte sq_arena[SQ_MAX_REPORT],sq_report[SQ_MAX_REPORT];
static struct sq_section sq_sections[SQ_SECTIONS];
static struct sq_diagnostic sq_diagnostics[SQ_OBSERVATIONS];
static int sq_close_bad;
static void sq_put32(sq_byte *p,sq_u32 v)
{sq_u32 i;for(i=0;i<4;++i)p[i]=(sq_byte)(v>>(8*i));}
static void sq_put64(sq_byte *p,sq_u64 v)
{sq_u32 i;for(i=0;i<8;++i)p[i]=(sq_byte)(v>>(8*i));}
static int sq_equal(const sq_byte *a,const sq_byte *b,sq_u32 n)
{sq_u32 i;for(i=0;i<n;++i)if(a[i]!=b[i])return 0;return 1;}
static long sq_open(const char *p,long flags,long mode)
{return sq_syscall(SQ_SYS_OPENAT,SQ_AT_FDCWD,(long)p,flags,mode,0,0);}
static long sq_close(long fd)
{long r=sq_syscall(SQ_SYS_CLOSE,fd,0,0,0,0,0);if(r<0)sq_close_bad=1;return r;}
static long sq_statat(const char *p,struct sq_stat *s)
{return sq_syscall(SQ_SYS_NEWFSTATAT,SQ_AT_FDCWD,(long)p,(long)s,SQ_AT_SYMLINK_NOFOLLOW,0,0);}
static long sq_fstat(long fd,struct sq_stat *s)
{return sq_syscall(SQ_SYS_FSTAT,fd,(long)s,0,0,0,0);}
static int sq_same(const struct sq_stat *a,const struct sq_stat *b)
{return a->dev==b->dev && a->ino==b->ino && a->rdev==b->rdev && a->uid==b->uid &&
        a->gid==b->gid && a->mode==b->mode && a->nlink==b->nlink;}
static void sq_encode_stat(sq_byte *p,const struct sq_stat *s)
{
    sq_put64(p,s->dev);sq_put64(p+8,s->ino);sq_put32(p+16,s->mode);sq_put32(p+20,s->nlink);
    sq_put32(p+24,s->uid);sq_put32(p+28,s->gid);sq_put64(p+32,s->rdev);sq_put64(p+40,(sq_u64)s->size);
}
static void sq_encode_fs(sq_byte *p,const struct sq_statfs *s)
{
    sq_put64(p,(sq_u64)s->type);sq_put64(p+8,(sq_u64)s->bsize);sq_put64(p+16,s->blocks);
    sq_put64(p+24,s->bfree);sq_put64(p+32,s->bavail);sq_put64(p+40,s->files);
    sq_put64(p+48,s->ffree);sq_put64(p+56,(sq_u64)s->namelen);
    sq_put64(p+64,(sq_u64)s->frsize);sq_put64(p+72,(sq_u64)s->flags);
}
static long sq_diagnose(struct sq_diagnostic *d,sq_u32 stage,long status)
{if(d){d->stage=stage;d->terminal=status;}return status;}
static void sq_before(struct sq_diagnostic *d,const struct sq_stat *s)
{if(d){d->valid=1;sq_encode_stat(d->before,s);}}
static int sq_owner(const struct sq_stat *s,int root_only)
{return (s->uid==0 && s->gid==0) || (!root_only && s->uid==57285 && s->gid==1000);}
static int sq_proc_path(const char *p)
{return p && p[0]=='/' && p[1]=='p' && p[2]=='r' && p[3]=='o' && p[4]=='c' && p[5]=='/';}
/* Complete bounded input; final component may never be followed as a link. */
static long sq_read_file(const char *path,sq_byte *out,sq_u32 cap,int proc,int root_only,struct sq_diagnostic *d)
{
    struct sq_stat before,after;struct sq_statfs fs;sq_byte extra;
    sq_u32 used=0,calls=0,interrupts=0,stage=SQ_STAGE_READ;long r=sq_statat(path,&before),fd,c;
    if(r<0)return sq_diagnose(d,SQ_STAGE_LSTAT,r);sq_before(d,&before);
    if((before.mode&SQ_S_IFMT)==SQ_S_IFLNK)return sq_diagnose(d,SQ_STAGE_TYPE,-SQ_ELOOP);
    if((before.mode&SQ_S_IFMT)!=SQ_S_IFREG)return sq_diagnose(d,SQ_STAGE_TYPE,-SQ_EACCES);
    if(!sq_owner(&before,root_only))return sq_diagnose(d,SQ_STAGE_OWNER,-SQ_EACCES);
    fd=sq_open(path,SQ_READ_FLAGS,0);if(fd<0)return sq_diagnose(d,SQ_STAGE_OPEN,fd);
    r=sq_fstat(fd,&after);
    if(r<0)stage=SQ_STAGE_FSTAT;
    if(r==0 && ((after.mode&SQ_S_IFMT)!=SQ_S_IFREG || !sq_same(&before,&after))){r=-SQ_EACCES;stage=SQ_STAGE_IDENTITY;}
    if(r==0 && proc){
        r=sq_syscall(SQ_SYS_FSTATFS,fd,(long)&fs,0,0,0,0);
        if(r<0)stage=SQ_STAGE_FSTATFS;
        if(r==0 && fs.type!=SQ_PROC_SUPER_MAGIC){r=-SQ_EACCES;stage=SQ_STAGE_FS_KIND;}
    }
    if(r==0)for(;;){
        sq_u32 n=cap-used;if(n>4096)n=4096;
        if(++calls>SQ_IO_LIMIT){r=-SQ_EIO;stage=SQ_STAGE_BOUNDS;break;}
        r=sq_syscall(SQ_SYS_READ,fd,(long)(n?out+used:&extra),n?n:1,0,0,0);
        if(r==-SQ_EINTR && ++interrupts<=SQ_EINTR_LIMIT)continue;
        if(r<0)break;if(r==0){r=used;break;}
        if(!n){r=-SQ_EOVERFLOW;stage=SQ_STAGE_BOUNDS;break;}
        if((sq_u64)r>n){r=-SQ_EIO;stage=SQ_STAGE_BOUNDS;break;}
        used+=(sq_u32)r;
    }
    c=sq_close(fd);if(c<0)return sq_diagnose(d,SQ_STAGE_CLOSE,c);
    if(r<0)return sq_diagnose(d,stage,r);sq_diagnose(d,SQ_STAGE_COMPLETE,0);return r;
}
static long sq_read_link(const char *path,sq_byte *out,sq_u32 cap,int root_only,struct sq_diagnostic *d)
{
    struct sq_stat before,after;sq_byte extra[513];sq_u32 i;long r=sq_statat(path,&before);
    if(r<0)return sq_diagnose(d,SQ_STAGE_LSTAT,r);sq_before(d,&before);
    if((before.mode&SQ_S_IFMT)!=SQ_S_IFLNK)return sq_diagnose(d,SQ_STAGE_TYPE,-SQ_EINVAL);
    if(!sq_owner(&before,root_only))return sq_diagnose(d,SQ_STAGE_OWNER,-SQ_EACCES);
    r=sq_syscall(SQ_SYS_READLINKAT,SQ_AT_FDCWD,(long)path,(long)extra,cap+1,0,0);
    if(r<0)return sq_diagnose(d,SQ_STAGE_READLINK,r);
    if((sq_u64)r>cap)return sq_diagnose(d,SQ_STAGE_BOUNDS,-SQ_EOVERFLOW);
    {long s=sq_statat(path,&after);if(s<0)return sq_diagnose(d,SQ_STAGE_LSTAT,s);
     if(!sq_same(&before,&after))return sq_diagnose(d,SQ_STAGE_IDENTITY,-SQ_EACCES);}
    for(i=0;i<(sq_u32)r;++i)out[i]=extra[i];sq_diagnose(d,SQ_STAGE_COMPLETE,0);return r;
}
static long sq_directory(const char *path,sq_byte *out,struct sq_statfs *observed,int root_only,struct sq_diagnostic *d)
{
    struct sq_stat before,after;struct sq_statfs fs;sq_u32 stage=SQ_STAGE_FSTAT;
    long fd,c,r=sq_statat(path,&before);
    if(r<0)return sq_diagnose(d,SQ_STAGE_LSTAT,r);sq_before(d,&before);
    if((before.mode&SQ_S_IFMT)!=SQ_S_IFDIR)return sq_diagnose(d,SQ_STAGE_TYPE,-SQ_EACCES);
    if(!sq_owner(&before,root_only))return sq_diagnose(d,SQ_STAGE_OWNER,-SQ_EACCES);
    fd=sq_open(path,SQ_READ_FLAGS|SQ_O_DIRECTORY,0);if(fd<0)return sq_diagnose(d,SQ_STAGE_OPEN,fd);
    r=sq_fstat(fd,&after);if(r==0 && !sq_same(&before,&after)){r=-SQ_EACCES;stage=SQ_STAGE_IDENTITY;}
    if(r==0){r=sq_syscall(SQ_SYS_FSTATFS,fd,(long)&fs,0,0,0,0);stage=SQ_STAGE_FSTATFS;}
    c=sq_close(fd);if(c<0)return sq_diagnose(d,SQ_STAGE_CLOSE,c);
    if(r<0)return sq_diagnose(d,stage,r);
    sq_encode_stat(out,&after);sq_encode_fs(out+SQ_STAT,&fs);
    /* Copy only fields used by the caller's space guard; a whole kernel
     * struct assignment can introduce an implicit freestanding memcpy. */
    if(observed){observed->type=fs.type;observed->bsize=fs.bsize;
                 observed->bavail=fs.bavail;observed->frsize=fs.frsize;}
    sq_diagnose(d,SQ_STAGE_COMPLETE,0);return SQ_DIR;
}
static long sq_metadata(const char *path,sq_byte *out,struct sq_diagnostic *d)
{
    struct sq_stat s;long r=sq_statat(path,&s);if(r<0)return sq_diagnose(d,SQ_STAGE_LSTAT,r);
    sq_before(d,&s);if(!sq_owner(&s,0))return sq_diagnose(d,SQ_STAGE_OWNER,-SQ_EACCES);
    sq_encode_stat(out,&s);sq_diagnose(d,SQ_STAGE_COMPLETE,0);return SQ_STAT;
}
static void sq_observe(sq_u32 slot)
{
    struct sq_section *s=&sq_sections[slot-1];struct sq_diagnostic *d=&sq_diagnostics[slot-1];long r;
    int proc=sq_proc_path(s->path);
    if(s->kind==SQ_FILE || s->kind==SQ_PROC)r=sq_read_file(s->path,s->data,s->cap,s->kind==SQ_PROC,proc,d);
    else if(s->kind==SQ_LINK)r=sq_read_link(s->path,s->data,s->cap,proc,d);
    else if(s->kind==SQ_DIRECTORY)r=sq_directory(s->path,s->data,0,slot==15,d);
    else if(s->kind==SQ_METADATA)r=sq_metadata(s->path,s->data,d);
    else {
        sq_u32 groups[64],i;r=sq_syscall(SQ_SYS_GETGROUPS,64,(long)groups,0,0,0,0);
        if(r>=0 && r<=64){for(i=0;i<(sq_u32)r;++i)sq_put32(s->data+4*i,groups[i]);r*=4;}
        else if(r>64){r=-SQ_EOVERFLOW;sq_diagnose(d,SQ_STAGE_BOUNDS,r);}
        if(r<0 && d->stage!=SQ_STAGE_BOUNDS)sq_diagnose(d,SQ_STAGE_GROUPS,r);
        if(r>=0)sq_diagnose(d,SQ_STAGE_COMPLETE,0);
    }
    if(r<0){s->status=r;s->length=0;}else{s->status=0;s->length=(sq_u32)r;}
}
static int sq_optional(sq_u32 id,long status)
{
    if(status==0)return 1;
    /* Only the mount namespace is used by the supervised SSH mechanism.
     * These absent proc entries are observations, never fabricated proof. */
    if(status==-SQ_ENOENT && (id==12 || id==14))
        return sq_diagnostics[id-1].stage==SQ_STAGE_LSTAT && !sq_diagnostics[id-1].valid;
    if(status==-SQ_ENOENT && ((id>=6 && id<=9) || id==13 || id==17 || id==31 || id==32 || id==33 || id==34))return 1;
    if(status==-SQ_EINVAL && ((id>=21 && id<=23) || (id>=27 && id<=29) || id==32))return 1;
    if(status==-SQ_ELOOP && (id==18 || id==19 || id==20 || id==31))return 1;
    return 0;
}
static int sq_space_budget(const struct sq_statfs *fs)
{
    sq_u64 unit,available,clusters,reserve,max=~(sq_u64)0;
    if(fs->type!=SQ_MSDOS_SUPER_MAGIC || fs->frsize<=0 || fs->bsize<=0)return 0;
    unit=(sq_u64)fs->frsize;if(fs->bavail>max/unit)return 0;available=fs->bavail*unit;
    clusters=SQ_REPORT_RESERVE/unit+(SQ_REPORT_RESERVE%unit!=0);
    if(clusters>max-2)return 0;clusters+=2;
    if(clusters>max/unit)return 0;reserve=clusters*unit;
    return available>=reserve && available-reserve>=SQ_FREE_MARGIN;
}
static long sq_write_all(long fd,sq_u32 n)
{
    sq_u32 used=0,calls=0,interrupts=0;
    while(used<n){
        sq_u32 amount=n-used;long r;if(amount>4096)amount=4096;
        if(++calls>SQ_IO_LIMIT)return -SQ_EIO;
        r=sq_syscall(SQ_SYS_WRITE,fd,(long)(sq_report+used),amount,0,0,0);
        if(r==-SQ_EINTR && ++interrupts<=SQ_EINTR_LIMIT)continue;
        if(r<=0 || (sq_u64)r>amount)return r<0?r:-SQ_EIO;used+=(sq_u32)r;
    }
    return 0;
}
/* Never expose a valid final report while the report FD has an uncertain close. */
static void sq_publish(sq_u32 n)
{
    struct sq_stat saved,current;long fd,r,c;int known=0;
    fd=sq_open(sq_pending,SQ_READ_FLAGS|SQ_O_WRONLY|SQ_O_CREAT|SQ_O_EXCL,0600);if(fd<0)return;
    r=sq_fstat(fd,&saved);
    if(r==0 && (saved.mode&SQ_S_IFMT)==SQ_S_IFREG && saved.nlink==1 && saved.size==0 && saved.uid==0 && saved.gid==0)known=1;
    else if(r==0)r=-SQ_EACCES;
    if(r==0)r=sq_write_all(fd,n);
    if(r==0)r=sq_syscall(SQ_SYS_FSYNC,fd,0,0,0,0,0);
    c=sq_close(fd);if(c<0)r=c;
    if(r==0){
        r=sq_statat(sq_pending,&current);
        if(r==0 && (!sq_same(&saved,&current) || current.size!=(sq_i64)n))r=-SQ_EACCES;
        if(r==0)r=sq_syscall(SQ_SYS_RENAMEAT2,SQ_AT_FDCWD,(long)sq_pending,SQ_AT_FDCWD,(long)sq_result,SQ_RENAME_NOREPLACE,0);
    }
    if(r<0 && known && sq_statat(sq_pending,&current)==0 && sq_same(&saved,&current) &&
       (current.mode&SQ_S_IFMT)==SQ_S_IFREG && current.nlink==1)
        (void)sq_syscall(SQ_SYS_UNLINKAT,SQ_AT_FDCWD,(long)sq_pending,0,0,0,0);
}
static void sq_run(void)
{
    /* This must remain the first syscall, including rejected requests. */
    long unlinked=sq_syscall(SQ_SYS_UNLINKAT,SQ_AT_FDCWD,(long)sq_loader,0,0,0,0);
    sq_byte request[24];sq_u32 i,j,flags=0,offset=SQ_HEADER,arena=0;
    sq_u32 uid,euid,gid,egid,pid;long req,r;int nonzero=0,allowed,all=1,continue_observing=1;
    struct sq_statfs fresh;
    static const struct sq_section initial[SQ_SECTIONS]={
        {"/version.txt",SQ_FILE,64,0,-SQ_ECANCELED,0},
        {0,SQ_GROUPS,256,0,-SQ_ECANCELED,0},
        {"/proc/self/status",SQ_PROC,8192,0,-SQ_ECANCELED,0},
        {"/proc/self/mountinfo",SQ_PROC,16384,0,-SQ_ECANCELED,0},
        {"/proc/self/mounts",SQ_PROC,16384,0,-SQ_ECANCELED,0},
        {"/proc/self/net/dev",SQ_PROC,4096,0,-SQ_ECANCELED,0},
        {"/proc/self/net/route",SQ_PROC,4096,0,-SQ_ECANCELED,0},
        {"/proc/self/net/if_inet6",SQ_PROC,2048,0,-SQ_ECANCELED,0},
        {"/proc/self/net/wireless",SQ_PROC,2048,0,-SQ_ECANCELED,0},
        {"/proc/self/root",SQ_LINK,512,0,-SQ_ECANCELED,0},
        {"/proc/self/ns/mnt",SQ_LINK,128,0,-SQ_ECANCELED,0},
        {"/proc/self/ns/net",SQ_LINK,128,0,-SQ_ECANCELED,0},
        {"/proc/self/ns/user",SQ_LINK,128,0,-SQ_ECANCELED,0},
        {"/proc/self/ns/pid",SQ_LINK,128,0,-SQ_ECANCELED,0},
        {"/tmp/jiritsu",SQ_DIRECTORY,SQ_DIR,0,-SQ_ECANCELED,0},
        {"/tmp_wbshd",SQ_DIRECTORY,SQ_DIR,0,-SQ_ECANCELED,0},
        {"/tmp_network",SQ_DIRECTORY,SQ_DIR,0,-SQ_ECANCELED,0},
        {"/etc/passwd",SQ_FILE,8192,0,-SQ_ECANCELED,0},
        {"/etc/nsswitch.conf",SQ_FILE,2048,0,-SQ_ECANCELED,0},
        {"/etc/ssh/sshd_config",SQ_FILE,8192,0,-SQ_ECANCELED,0},
        {"/etc/passwd",SQ_LINK,512,0,-SQ_ECANCELED,0},
        {"/etc/nsswitch.conf",SQ_LINK,512,0,-SQ_ECANCELED,0},
        {"/etc/ssh/sshd_config",SQ_LINK,512,0,-SQ_ECANCELED,0},
        {"/usr/sbin/sshd",SQ_METADATA,SQ_STAT,0,-SQ_ECANCELED,0},
        {"/usr/bin/ssh-keygen",SQ_METADATA,SQ_STAT,0,-SQ_ECANCELED,0},
        {"/lib/ld-linux-aarch64.so.1",SQ_METADATA,SQ_STAT,0,-SQ_ECANCELED,0},
        {"/usr/sbin/sshd",SQ_LINK,512,0,-SQ_ECANCELED,0},
        {"/usr/bin/ssh-keygen",SQ_LINK,512,0,-SQ_ECANCELED,0},
        {"/lib/ld-linux-aarch64.so.1",SQ_LINK,512,0,-SQ_ECANCELED,0},
        {"/proc/self/limits",SQ_PROC,4096,0,-SQ_ECANCELED,0},
        {"/etc/ld.so.preload",SQ_FILE,1024,0,-SQ_ECANCELED,0},
        {"/etc/ld.so.preload",SQ_LINK,512,0,-SQ_ECANCELED,0},
        {"/etc/shadow",SQ_METADATA,SQ_STAT,0,-SQ_ECANCELED,0},
        {"/proc/self/net/fib_trie",SQ_PROC,8192,0,-SQ_ECANCELED,0},
        {"/var",SQ_DIRECTORY,SQ_DIR,0,-SQ_ECANCELED,0},
        {"/etc",SQ_DIRECTORY,SQ_DIR,0,-SQ_ECANCELED,0},
        {"/dev/pts",SQ_DIRECTORY,SQ_DIR,0,-SQ_ECANCELED,0},
        {"/tmp",SQ_DIRECTORY,SQ_DIR,0,-SQ_ECANCELED,0},
        {0,SQ_DIAGNOSTICS,SQ_DIAGNOSTIC_BYTES,0,-SQ_ECANCELED,0}
    };
    if(unlinked!=0 && unlinked!=-SQ_ENOENT)return;
    sq_close_bad=0;
    for(i=0;i<SQ_SECTIONS;++i){sq_sections[i]=initial[i];sq_sections[i].data=sq_arena+arena;arena+=initial[i].cap;}
    for(i=0;i<SQ_OBSERVATIONS;++i){
        sq_diagnostics[i].stage=SQ_STAGE_NONE;sq_diagnostics[i].valid=0;sq_diagnostics[i].terminal=-SQ_ECANCELED;
        for(j=0;j<SQ_STAT;++j)sq_diagnostics[i].before[j]=0;
    }
    if(arena+SQ_HEADER+SQ_SECTION_HEADER*SQ_SECTIONS>SQ_MAX_REPORT)return;
    for(i=0;i<SQ_HEADER;++i)sq_report[i]=0;
    req=sq_read_file(sq_request,request,24,0,1,0);
    if(req>=0){
        if(req!=24 || !sq_equal(request,sq_request_magic,8))req=-SQ_EINVAL;
        else {for(i=8;i<24;++i)if(request[i])nonzero=1;req=nonzero?0:-SQ_EINVAL;}
    }
    if(req==0){flags|=1;for(i=0;i<16;++i)sq_report[24+i]=request[8+i];}
    if(unlinked==0 || unlinked==-SQ_ENOENT)flags|=4;
    uid=(sq_u32)sq_syscall(SQ_SYS_GETUID,0,0,0,0,0,0);
    euid=(sq_u32)sq_syscall(SQ_SYS_GETEUID,0,0,0,0,0,0);
    gid=(sq_u32)sq_syscall(SQ_SYS_GETGID,0,0,0,0,0,0);
    egid=(sq_u32)sq_syscall(SQ_SYS_GETEGID,0,0,0,0,0,0);
    pid=(sq_u32)sq_syscall(SQ_SYS_GETPID,0,0,0,0,0,0);
    allowed=(flags&5)==5 && !sq_close_bad && uid==0 && euid==0 && gid==0 && egid==0;
    if(allowed){
        sq_observe(1);
        allowed=!sq_close_bad && sq_sections[0].status==0 && sq_sections[0].length==19 &&
                sq_equal(sq_sections[0].data,(const sq_byte *)sq_version,19);
    }
    if(allowed){
        flags|=8;
        for(i=2;i<=SQ_OBSERVATIONS && continue_observing;++i){
            if(i==15)continue; /* Fresh report-space observation is last. */
            sq_observe(i);
            if(sq_close_bad || !sq_optional(i,sq_sections[i-1].status))continue_observing=0;
        }
    }
    /* A fresh, successfully closed directory descriptor is mandatory even for
     * an error report. No guessed free space and no alternate staging path. */
    r=sq_directory("/tmp/jiritsu",sq_sections[14].data,&fresh,1,&sq_diagnostics[14]);
    if(r<0 || !sq_space_budget(&fresh))return;
    sq_sections[14].status=0;sq_sections[14].length=SQ_DIR;flags|=32;
    /* ELOOP is admitted only when its fixed counterpart observed a link. */
    for(i=18;i<=20;++i)if(sq_sections[i-1].status==-SQ_ELOOP && sq_sections[i+2].status!=0)all=0;
    if(sq_sections[30].status==-SQ_ELOOP && sq_sections[31].status!=0)all=0;
    for(i=0;i<SQ_OBSERVATIONS;++i){
        sq_byte *row=sq_sections[38].data+i*SQ_DIAGNOSTIC_ROW;
        struct sq_diagnostic *d=&sq_diagnostics[i];
        sq_put32(row,d->stage);sq_put32(row+4,d->valid);sq_put64(row+8,(sq_u64)d->terminal);
        for(j=0;j<SQ_STAT;++j)row[16+j]=d->before[j];
        if(d->terminal!=sq_sections[i].status)all=0;
    }
    sq_sections[38].status=0;sq_sections[38].length=SQ_DIAGNOSTIC_BYTES;
    for(i=0;i<SQ_SECTIONS;++i){
        struct sq_section *s=&sq_sections[i];
        sq_put32(sq_report+offset,i+1);sq_put32(sq_report+offset+4,s->length);
        sq_put64(sq_report+offset+8,(sq_u64)s->status);offset+=SQ_SECTION_HEADER;
        for(j=0;j<s->length;++j)sq_report[offset+j]=s->data[j];offset+=s->length;
        if(!sq_optional(i+1,s->status))all=0;
    }
    if(all)flags|=2;if(!sq_close_bad)flags|=16;
    for(i=0;i<8;++i)sq_report[i]=sq_result_magic[i];
    sq_put32(sq_report+8,2);sq_put32(sq_report+12,SQ_HEADER);sq_put32(sq_report+16,offset);
    sq_put32(sq_report+20,SQ_SECTIONS);sq_put32(sq_report+40,uid);sq_put32(sq_report+44,euid);
    sq_put32(sq_report+48,gid);sq_put32(sq_report+52,egid);sq_put32(sq_report+56,pid);
    sq_put32(sq_report+60,flags);sq_put64(sq_report+64,(sq_u64)unlinked);sq_put64(sq_report+72,(sq_u64)req);
    sq_publish(offset);
}
#if defined(M4_SSH_PREREQ_V2_TEST)
void a7m4_ssh_prereq_v2_run(void){sq_run();}
#else
__attribute__((visibility("default"))) void _init(void){sq_run();}
#endif
