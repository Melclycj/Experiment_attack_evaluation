#define _GNU_SOURCE
#include "support.h"
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <linux/openat2.h>
#include <sha256.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#ifdef W2_TESTING
static char fault_point[128];
static char fault_scope[48];
#endif
void w2_fault_configure(const char *point) {
#ifdef W2_TESTING
    if (point && strlen(point) < sizeof fault_point) strcpy(fault_point, point);
#else
    (void)point;
#endif
}
void w2_fault_scope(const char *prefix) {
#ifdef W2_TESTING
    if(prefix&&strlen(prefix)<sizeof fault_scope)strcpy(fault_scope,prefix);
#else
    (void)prefix;
#endif
}
int w2_fault(const char *point) {
#ifdef W2_TESTING
    char scoped[192];snprintf(scoped,sizeof scoped,"%s%s",fault_scope,point);
    if (!strcmp(scoped, fault_point)) { errno = EIO; return -1; }
#else
    (void)point;
#endif
    return 0;
}
uint64_t w2_now(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) return 0;
    return (uint64_t)t.tv_sec * UINT64_C(1000000000) + (uint64_t)t.tv_nsec;
}
int w2_nonblock(int fd) {
    int f = fcntl(fd, F_GETFL);
    return f < 0 ? -1 : fcntl(fd, F_SETFL, f | O_NONBLOCK);
}
int w2_digest(const void *data, size_t size, char out[W2_DIGEST_CAP]) {
    SHA256_CTX ctx; unsigned char hash[32];
    SHA256Init(&ctx); SHA256Update(&ctx, data, size); SHA256Final(hash, &ctx);
    memcpy(out, "sha256:", 7);
    for (size_t i=0; i<32; ++i) snprintf(out+7+i*2, 3, "%02x", hash[i]);
    return 0;
}
int w2_digest_fd(int fd, char out[W2_DIGEST_CAP]) {
    SHA256_CTX ctx; unsigned char buf[65536], hash[32]; ssize_t n;
    if (w2_checkpoint() || lseek(fd, 0, SEEK_SET) < 0 || w2_checkpoint()) return -1;
    SHA256Init(&ctx);
    for (;;) {
        n=read(fd, buf, sizeof buf);int saved=errno;
        if(w2_checkpoint())return -1;
        if (n<0) { errno=saved;if(errno==EINTR) continue; return -1; }
        if (!n) break;
        SHA256Update(&ctx, buf, (size_t)n);
    }
    SHA256Final(hash, &ctx); memcpy(out,"sha256:",7);
    for(size_t i=0;i<32;++i) snprintf(out+7+i*2,3,"%02x",hash[i]);
    return 0;
}
bool w2_is_digest(const char *s) {
    if(!s || strlen(s)!=71 || strncmp(s,"sha256:",7)) return false;
    for(size_t i=7;i<71;++i) if(!strchr("0123456789abcdef",s[i])) return false;
    return true;
}
bool w2_is_id(const char *s) {
    if(!s || !*s || strlen(s)>W2_ID_MAX) return false;
    for(;*s;++s) if(!((*s>='a'&&*s<='z')||(*s>='A'&&*s<='Z')||
        (*s>='0'&&*s<='9')||strchr("._:-",*s))) return false;
    return true;
}
bool w2_decimal(const char *s, uint64_t *out, bool positive) {
    uint64_t n=0;
    if(!s || !*s || (s[0]=='0' && s[1])) return false;
    for(;*s;++s) {
        if(*s<'0'||*s>'9'||n>(UINT64_MAX-(unsigned)(*s-'0'))/10) return false;
        n=n*10+(unsigned)(*s-'0');
    }
    if(positive && !n) return false;
    *out=n; return true;
}
static int (*job_checkpoint)(void *);
static void *job_context;
void w2_checkpoint_configure(int (*check)(void *),void *context){job_checkpoint=check;job_context=context;}
int w2_checkpoint(void){
    if(!job_checkpoint)return 0;
    int saved=errno,rc=job_checkpoint(job_context);
    if(!rc)errno=saved; /* Polling IPC must not replace a filesystem errno. */
    return rc;
}
static bool json_values(json_t *j, unsigned depth) {
    if(depth>32 || json_is_real(j)) return false;
    if(json_is_string(j)) return strlen(json_string_value(j))==json_string_length(j);
    if(json_is_object(j)) {
        const char *key; json_t *v;
        json_object_foreach(j,key,v) {
            if(strlen(key)>W2_STRING_MAX || !json_values(v,depth+1)) return false;
        }
    } else if(json_is_array(j)) {
        size_t i; json_t *v;
        json_array_foreach(j,i,v) if(!json_values(v,depth+1)) return false;
    }
    return true;
}
json_t *w2_json(const char *data, size_t size) {
    json_error_t error;
    if(!data||!size||size>W2_MANIFEST_MAX||memchr(data,0,size)) return NULL;
    json_t *j=json_loadb(data,size,JSON_REJECT_DUPLICATES,&error);
    if(!j||!json_is_object(j)||!json_values(j,0)) { json_decref(j); return NULL; }
    return j;
}
static bool frame_values(json_t *j,unsigned depth,size_t *elements) {
    if(json_is_integer(j)) {
        json_int_t n=json_integer_value(j);
        return n>=-INT64_C(9007199254740991)&&n<=INT64_C(9007199254740991);
    }
    if(json_is_object(j)||json_is_array(j)) {
        if(depth>=16)return false;
        size_t n=json_is_object(j)?json_object_size(j):json_array_size(j);
        if(n>4096-*elements)return false;
        *elements+=n;
        if(json_is_object(j)) {
            const char *key;json_t *v;
            json_object_foreach(j,key,v) { (void)key;if(!frame_values(v,depth+1,elements))return false; }
        } else {
            size_t i;json_t *v;
            json_array_foreach(j,i,v)if(!frame_values(v,depth+1,elements))return false;
        }
    }
    return true;
}
json_t *w2_frame_json(const char *data,size_t size) {
    if(size>W2_BODY_MAX)return NULL;
    json_t *j=w2_json(data,size);size_t elements=0;
    if(j&&!frame_values(j,0,&elements)){json_decref(j);return NULL;}
    return j;
}
bool w2_keys(json_t *j,const char *const *keys,size_t count) {
    if(!json_is_object(j)||json_object_size(j)!=count) return false;
    for(size_t i=0;i<count;++i) if(!json_object_get(j,keys[i])) return false;
    return true;
}
const char *w2_str(json_t *j,const char *key) { return json_string_value(json_object_get(j,key)); }
bool w2_relative(const char *s) {
    if(!s||!*s||*s=='/'||strlen(s)>=W2_PATH_CAP) return false;
    const char *p=s;unsigned depth=0;
    while(*p) {
        const char *q=strchr(p,'/'); size_t n=q?(size_t)(q-p):strlen(p);
        if(!n||n>255||++depth>64||(n==1&&*p=='.')||(n==2&&!strncmp(p,"..",2))) return false;
        for(size_t i=0;i<n;++i) if((unsigned char)p[i]<32 || p[i]=='\\') return false;
        if(!q) break;
        p=q+1; if(!*p) return false;
    }
    return true;
}
int w2_open_at(int root,const char *path,int flags) {
    if(!w2_relative(path)) { errno=EINVAL; return -1; }
    /* Anchoring prevents escape; ownership of every ancestor prevents an agent
     * from replacing a root-owned leaf through a writable containing folder. */
    char parent[W2_PATH_CAP];strcpy(parent,path);
    for(char *slash=strchr(parent,'/');slash;slash=strchr(slash+1,'/')) {
        *slash=0;
        struct open_how check={.flags=O_PATH|O_DIRECTORY|O_CLOEXEC,
            .resolve=RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS};
        int dir=(int)syscall(SYS_openat2,root,parent,&check,sizeof check);struct stat st;
        bool safe=dir>=0&&!fstat(dir,&st)&&st.st_uid==0&&!(st.st_mode&0022);
        if(dir>=0)close(dir);
        *slash='/';
        if(!safe){errno=EPERM;return -1;}
    }
    struct open_how h={.flags=(uint64_t)(unsigned)(flags|O_CLOEXEC),
        .resolve=RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS};
    return (int)syscall(SYS_openat2,root,path,&h,sizeof h);
}
int w2_read_at(int root,const char *path,size_t limit,char **out,size_t *size) {
    int fd=w2_open_at(root,path,O_RDONLY); struct stat st; char *b=NULL; size_t n=0;
    if(fd<0) return -1;
    if(fstat(fd,&st)||!S_ISREG(st.st_mode)||st.st_uid!=0||(st.st_mode&0022)||
       st.st_size<=0||(uint64_t)st.st_size>limit) goto bad;
    b=malloc((size_t)st.st_size+1); if(!b) goto bad;
    while(n<(size_t)st.st_size) {
        ssize_t r=read(fd,b+n,(size_t)st.st_size-n);
        if(r<0&&errno==EINTR) continue;
        if(r<=0) goto bad;
        n+=(size_t)r;
    }
    char extra; if(read(fd,&extra,1)!=0) goto bad;
    b[n]=0; close(fd); *out=b; *size=n; return 0;
bad: free(b); close(fd); errno=EINVAL; return -1;
}
json_t *w2_json_at(int root,const char *path,char digest[W2_DIGEST_CAP]) {
    char *bytes; size_t n;
    if(w2_read_at(root,path,W2_CATALOG_MAX,&bytes,&n)) return NULL;
    w2_digest(bytes,n,digest); json_t *j=w2_json(bytes,n); free(bytes); return j;
}
static int read_small(const char *path,char *out,size_t cap) {
    int fd=open(path,O_RDONLY|O_CLOEXEC); if(fd<0) return -1;
    ssize_t n=read(fd,out,cap-1); close(fd);
    if(n<=0||(size_t)n==cap-1) return -1;
    out[n]=0; return 0;
}
int w2_environment_values(const char *map,const char *uid,const char *gid,
                         const char *yama,const char *ksm,uid_t *out,gid_t *out_gid) {
    unsigned long long a,b,c,u,g,y,k; char tail;
    if(sscanf(map,"%llu %llu %llu %c",&a,&b,&c,&tail)!=3||a||b||c!=4294967295ULL||
       sscanf(uid,"%llu %c",&u,&tail)!=1||!u||u>=UINT32_MAX||
       sscanf(gid,"%llu %c",&g,&tail)!=1||!g||g>=UINT32_MAX||
       sscanf(yama,"%llu %c",&y,&tail)!=1||y<1||y>3||
       sscanf(ksm,"%llu %c",&k,&tail)!=1||k) { errno=EPERM; return -1; }
    *out=(uid_t)u; *out_gid=(gid_t)g; return 0;
}
int w2_environment(uid_t *out,gid_t *out_gid) {
    char map[128],u[64],g[64],y[64],k[64];
    if(read_small("/proc/self/uid_map",map,sizeof map)||
       read_small("/proc/sys/kernel/overflowuid",u,sizeof u)||
       read_small("/proc/sys/kernel/overflowgid",g,sizeof g)||
       read_small("/proc/sys/kernel/yama/ptrace_scope",y,sizeof y)||
       read_small("/sys/kernel/mm/ksm/run",k,sizeof k)) return -1;
    return w2_environment_values(map,u,g,y,k,out,out_gid);
}
int w2_drop(uid_t uid,gid_t gid,enum w2_stage *stage) {
    *stage=W2_STAGE_NO_NEW_PRIVS;
    if(w2_fault("no_new_privs")||prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)) return -1;
    *stage=W2_STAGE_BOUNDING;
    for(unsigned i=0;;++i) {
        int present=prctl(PR_CAPBSET_READ,i,0,0,0);
        if(present<0) { if(errno==EINVAL) break; return -1; }
        char point[64]; snprintf(point,sizeof point,"bounding.%u",i);
        if(w2_fault(point)||w2_fault("bounding")||prctl(PR_CAPBSET_DROP,i,0,0,0)) return -1;
    }
    *stage=W2_STAGE_GROUPS_GID;
    if(w2_fault("groups")||setgroups(0,NULL)||w2_fault("gid")||setresgid(gid,gid,gid)) return -1;
    *stage=W2_STAGE_UID;
    if(w2_fault("uid")||setresuid(uid,uid,uid)) return -1;
    /* Re-read before any filter is installed: real, effective and saved uid
     * must all equal the recorded uid, or the drop fails (conn E-01). */
    uid_t real,effective,saved;
    if(w2_fault("uid.reread")||getresuid(&real,&effective,&saved)) return -1;
    if(real!=uid||effective!=uid||saved!=uid) { errno=EPERM; return -1; }
    *stage=W2_STAGE_CAPS;
    if(w2_fault("ambient")||prctl(PR_CAP_AMBIENT,PR_CAP_AMBIENT_CLEAR_ALL,0,0,0)) return -1;
    cap_t empty=cap_init(); if(!empty) return -1;
    int r=w2_fault("caps") ? -1 : cap_set_proc(empty);
    cap_free(empty); return r;
}
int w2_require_spawner_caps(void) {
    static const cap_value_t need[]={CAP_SYS_ADMIN,CAP_SETUID,CAP_SETGID,CAP_SETPCAP,CAP_NET_ADMIN,CAP_KILL};
    cap_t caps=cap_get_proc(); if(!caps) return -1;
    for(size_t i=0;i<sizeof need/sizeof need[0];++i) {
        cap_flag_value_t v;
        if(cap_get_flag(caps,need[i],CAP_EFFECTIVE,&v)||v!=CAP_SET) { cap_free(caps);errno=EPERM;return -1; }
    }
    cap_free(caps); return 0;
}
int w2_limit_spawner_caps(void) {
    cap_value_t need[]={CAP_SYS_ADMIN,CAP_SETUID,CAP_SETGID,CAP_SETPCAP,CAP_NET_ADMIN,CAP_KILL};
    if(w2_require_spawner_caps())return -1;
    for(unsigned i=0;;++i) {
        int present=prctl(PR_CAPBSET_READ,i,0,0,0);
        if(present<0){if(errno==EINVAL)break;return -1;}
        bool keep=false;for(size_t j=0;j<6;++j)if((unsigned)need[j]==i)keep=true;
        if(!keep&&prctl(PR_CAPBSET_DROP,i,0,0,0))return -1;
    }
    cap_t caps=cap_init();if(!caps)return -1;
    int r=cap_set_flag(caps,CAP_PERMITTED,6,need,CAP_SET)||cap_set_flag(caps,CAP_EFFECTIVE,6,need,CAP_SET)||cap_set_proc(caps);
    cap_free(caps);
    if(r||prctl(PR_CAP_AMBIENT,PR_CAP_AMBIENT_CLEAR_ALL,0,0,0))return -1;
    return 0;
}
