#define _GNU_SOURCE
#include "catalog.h"
#include "storage.h"
#include <dirent.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/btrfs.h>
#include <linux/fs.h>
#include <linux/magic.h>
#include <linux/openat2.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/xattr.h>
#include <unistd.h>

#define KEYS(j,...) w2_keys((j),(const char *const[]){__VA_ARGS__},sizeof((const char *const[]){__VA_ARGS__})/sizeof(char *))
static bool eq(json_t *j,const char *key,const char *s) {
    const char *v=w2_str(j,key); return v&&s&&!strcmp(v,s);
}
static bool integer(json_t *j,const char *key,uint64_t max,uint64_t *v) {
    json_t *n=json_object_get(j,key);
    if(!json_is_integer(n)||json_integer_value(n)<0||(uint64_t)json_integer_value(n)>max) return false;
    *v=(uint64_t)json_integer_value(n);return true;
}
static bool array(json_t *j,const char *name) {
    json_t *a=json_object_get(j,name);
    return json_is_array(a)&&json_array_size(a)>0&&json_array_size(a)<=W2_ITEMS_MAX;
}
static int check_dir(int fd,bool writable) {
    struct stat st; struct statfs fs;
    if(fstat(fd,&st)||fstatfs(fd,&fs)||!S_ISDIR(st.st_mode)||st.st_uid!=0||
       (st.st_mode&0022)||fs.f_type!=BTRFS_SUPER_MAGIC) return -1;
    if(!writable && !(st.st_mode&0500)) return -1;
    return 0;
}
static int open_deployment(const char *path) {
    /* Root ownership along the complete non-symlink path; ephemeral test roots
     * are provisioned under /var/lib, never under an agent/user-writable /tmp. */
    if(!path||strncmp(path,"/var/lib/",9)||!w2_relative(path+1)) return -1;
    int fd=open("/",O_RDONLY|O_DIRECTORY|O_CLOEXEC); if(fd<0) return -1;
    char *copy=strdup(path+1); if(!copy) {close(fd);return -1;}
    char *save=NULL,*part=strtok_r(copy,"/",&save);
    while(part) {
        int next=openat(fd,part,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);close(fd);fd=next;
        struct stat st;
        if(fd<0||fstat(fd,&st)||st.st_uid!=0||(st.st_mode&0022)) {
            if(fd>=0)close(fd);
            free(copy);return -1;
        }
        part=strtok_r(NULL,"/",&save);
    }
    free(copy); return fd;
}
static json_t *reference(int root,json_t *ref,char digest[W2_DIGEST_CAP]) {
    if(!KEYS(ref,"artifact_ref","artifact_digest")||!w2_is_digest(w2_str(ref,"artifact_digest"))) return NULL;
    json_t *j=w2_json_at(root,w2_str(ref,"artifact_ref"),digest);
    if(!j||strcmp(digest,w2_str(ref,"artifact_digest"))) {json_decref(j);return NULL;}
    return j;
}
static bool environment_key(const char *key) {
    if(!key||!((*key>='A'&&*key<='Z')||(*key>='a'&&*key<='z')||*key=='_'))return false;
    for(++key;*key;++key) if(!((*key>='A'&&*key<='Z')||(*key>='a'&&*key<='z')||
        (*key>='0'&&*key<='9')||*key=='_'))return false;
    return true;
}
static int runtime_args(struct w2_runtime *r) {
    json_t *d=r->descriptor;
    if(!KEYS(d,"runtime_id","artifact_digest","dependency_digest","layout_id","executable","argv","cwd","env","protocol",
        "component_manifest_ref","component_manifest_digest","storage_profile_id"))return -1;
    const char *ids[]={"runtime_id","layout_id","storage_profile_id"};
    for(size_t i=0;i<3;++i)if(!w2_is_id(w2_str(d,ids[i])))return -1;
    const char *digests[]={"artifact_digest","dependency_digest","component_manifest_digest"};
    for(size_t i=0;i<3;++i)if(!w2_is_digest(w2_str(d,digests[i])))return -1;
    if(!eq(d,"protocol",W2_DATA_PROTOCOL)||!eq(d,"cwd","/work")||!eq(d,"layout_id","runtime-root-v1"))return -1;
    const char *exe=w2_str(d,"executable");
    if(!exe||strncmp(exe,"/runtime/",9)||!w2_relative(exe+9)||strlen(exe)>W2_STRING_MAX)return -1;
    json_t *args=json_object_get(d,"argv"),*env=json_object_get(d,"env");
    if(!json_is_array(args)||!json_array_size(args)||json_array_size(args)>W2_ARGV_MAX||
       !json_is_object(env)||json_object_size(env)>W2_ENV_MAX)return -1;
    size_t total=strlen(exe)+1+strlen("/work")+1,i; json_t *v;
    json_array_foreach(args,i,v) {
        const char *s=json_string_value(v);
        if(!s||strlen(s)>W2_STRING_MAX||(i==0&&strcmp(s,exe)))return -1;
        total+=strlen(s)+1;r->argv[i]=strdup(s);if(!r->argv[i])return -1;
    }
    const char *key; i=0;
    json_object_foreach(env,key,v) {
        const char *s=json_string_value(v);
        if(!environment_key(key)||strlen(key)>W2_STRING_MAX||!s||strlen(s)>W2_STRING_MAX)return -1;
        total+=strlen(key)+strlen(s)+2;
        if(asprintf(&r->env[i++],"%s=%s",key,s)<0)return -1;
    }
    return total<=W2_EXEC_BYTES_MAX?0:-1;
}
/* Phase 2 (validation.md U-03): one table from a manifest path to its position in "files", built once per seed. The
 * duplicate, ancestor and enumeration checks look paths up there instead of scanning the list (they were quadratic);
 * the conditions are unchanged: no path twice, a parent earlier in the list and a
 * directory, nothing on disk outside the list. The old loops took 30.4 s for 22,347 entries, measured on a copy of
 * them (validation.md U-03). */
static int index_manifest(struct w2_runtime *r) {
    json_t *a=json_object_get(r->manifest,"files"),*e;size_t i;
    if(!json_is_array(a))return -1;
    json_decref(r->paths);r->paths=json_object();if(!r->paths)return -1;
    json_array_foreach(a,i,e) {
        const char *path=w2_str(e,"path");
        if(!path||json_object_get(r->paths,path)||json_object_set_new(r->paths,path,json_integer((json_int_t)i)))return -1;
    }
    return 0;
}
static json_t *manifest_entry(struct w2_runtime *r,const char *path) {
    json_t *at=r->paths?json_object_get(r->paths,path):NULL;
    return at?json_array_get(json_object_get(r->manifest,"files"),(size_t)json_integer_value(at)):NULL;
}
static int resolve_runtime(int root,const char *path,int flags) {
    if(!w2_relative(path)||w2_checkpoint())return -1;
    struct open_how h={.flags=(uint64_t)(unsigned)(flags|O_CLOEXEC),.resolve=RESOLVE_BENEATH|RESOLVE_NO_MAGICLINKS|RESOLVE_NO_XDEV};
    int fd=(int)syscall(SYS_openat2,root,path,&h,sizeof h);
    if(w2_checkpoint()){int saved=errno;if(fd>=0)close(fd);errno=saved;return -1;}return fd;
}
static int tree_open(int root,const char *path,int flags) {
    if(!w2_relative(path)){errno=EINVAL;return -1;}
    if(w2_checkpoint())return -1;
    struct open_how h={.flags=(uint64_t)(unsigned)(flags|O_CLOEXEC|O_NOFOLLOW),
        .mode=(flags&O_CREAT)?0600:0,
        .resolve=RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS|RESOLVE_NO_XDEV};
    int fd=(int)syscall(SYS_openat2,root,path,&h,sizeof h);
    if(w2_checkpoint()){int saved=errno;if(fd>=0)close(fd);errno=saved;return -1;}return fd;
}
static int plain_attributes(int fd) {
    int flags=0;if(w2_checkpoint()||ioctl(fd,FS_IOC_GETFLAGS,&flags)||w2_checkpoint()||flags&(FS_IMMUTABLE_FL|FS_APPEND_FL))return -1;
    const char *attrs[]={"system.posix_acl_access","system.posix_acl_default","security.capability"};
    for(size_t k=0;k<3;++k){errno=0;ssize_t n=fgetxattr(fd,attrs[k],NULL,0);if(n>=0||errno!=ENODATA||w2_checkpoint())return -1;}
    return 0;
}
static int tree_check(struct w2_runtime *r,int root,bool distinct) {
    json_t *a=json_object_get(r->manifest,"files"),*e;size_t i;uint64_t bytes=0;
    struct stat root_stat;
    if(w2_checkpoint()||fstat(root,&root_stat)||w2_checkpoint()||root_stat.st_uid!=0||root_stat.st_gid!=0||
       (root_stat.st_mode&07777)!=0755||plain_attributes(root))return -1;
    if(!KEYS(r->manifest,"v","files")||json_integer_value(json_object_get(r->manifest,"v"))!=1||
       !json_is_array(a)||!json_array_size(a)||json_array_size(a)>=65536)return -1;
    json_array_foreach(a,i,e) {
        const char *path=w2_str(e,"path"),*type=w2_str(e,"type");uint64_t mode,size;
        if(!path||!w2_relative(path)||!type||!integer(e,"mode",0777,&mode)||
           !integer(e,"size",INT64_MAX,&size)||w2_checkpoint())return -1;
        json_t *self=r->paths?json_object_get(r->paths,path):NULL;      /* the table holds each path once */
        if(!self||json_integer_value(self)!=(json_int_t)i)return -1;
        /* Validate already checked ancestors before any path traversal. */
        char parent[W2_PATH_CAP];strcpy(parent,path);char *slash;
        while((slash=strrchr(parent,'/'))) {
            *slash=0;json_t *at=json_object_get(r->paths,parent);
            if(!at||json_integer_value(at)>=(json_int_t)i||!eq(manifest_entry(r,parent),"type","directory"))return -1;
        }
        struct stat st,seed;
        if(fstatat(root,path,&st,AT_SYMLINK_NOFOLLOW)||w2_checkpoint()||st.st_uid!=0||st.st_gid!=0||st.st_dev!=root_stat.st_dev||(st.st_mode&07777)!=(mode_t)mode)return -1;
        if(distinct&&(fstatat(r->seed_fd,path,&seed,AT_SYMLINK_NOFOLLOW)||w2_checkpoint()||
            (seed.st_dev==st.st_dev&&seed.st_ino==st.st_ino)))return -1;
        if(!strcmp(type,"directory")) {
            if(!KEYS(e,"path","type","size","mode")||size||!S_ISDIR(st.st_mode)||mode!=0755)return -1;
        } else if(!strcmp(type,"file")) {
            if(!KEYS(e,"path","type","size","mode","digest")||!S_ISREG(st.st_mode)||
               st.st_nlink!=1||(mode!=0444&&mode!=0555)||(uint64_t)st.st_size!=size||!w2_is_digest(w2_str(e,"digest")))return -1;
            if(size>UINT64_MAX-4095||bytes>UINT64_MAX-((size+4095)&~UINT64_C(4095)))return -1;
            bytes+=(size+4095)&~UINT64_C(4095);
            /* The digest is computed for the seed only, once at start (distinct false). A row's copy is checked for
             * its structure only: owner, mode, type, link count, no inode shared with the seed, nothing extra; it is
             * root's, made just now by reflink from the checked seed, and no program of the row has run yet
             * (validation.md S-21). */
            if(!distinct) {
                int fd=tree_open(root,path,O_RDONLY);char hash[W2_DIGEST_CAP];
                if(fd<0)return -1;
                int rc=w2_digest_fd(fd,hash);close(fd);
                if(rc||strcmp(hash,w2_str(e,"digest")))return -1;
            }
        } else if(!strcmp(type,"symlink")) {
            char target[W2_PATH_CAP];
            if(!KEYS(e,"path","type","size","mode","target")||!S_ISLNK(st.st_mode)||!w2_str(e,"target"))return -1;
            ssize_t n=readlinkat(root,path,target,sizeof target-1);
            if(n<0||w2_checkpoint()||(size_t)n>=sizeof target-1||(uint64_t)n!=size)return -1;
            target[n]=0;if(strcmp(target,w2_str(e,"target")))return -1;
            int fd=resolve_runtime(root,path,O_PATH);if(fd<0)return -1;close(fd);
        } else return -1;
        if(strcmp(type,"symlink")) {
            int fd=tree_open(root,path,O_RDONLY);if(fd<0)return -1;
            int rc=plain_attributes(fd);close(fd);if(rc)return -1;
        }
    }
    uint64_t nodes=json_array_size(a)+1;
    if(bytes>UINT64_MAX-4096*nodes)return -1;
    if(!distinct){r->charge_nodes=nodes;r->charge_bytes=bytes+4096*nodes;}
    return w2_checkpoint();
}
static int enumerate_tree(int fd,const char *prefix,struct w2_runtime *r,size_t *seen) {
    if(w2_checkpoint())return -1;
    int copy=dup(fd);if(copy<0)return -1;
    if(w2_checkpoint()){int saved=errno;close(copy);errno=saved;return -1;}
    DIR *dir=fdopendir(copy);if(!dir){close(copy);return -1;}
    struct dirent *e;int result=0;
    for(;;) {
        if(w2_checkpoint()){result=-1;break;}
        errno=0;e=readdir(dir);int saved=errno;
        if(w2_checkpoint()){result=-1;break;}
        if(!e){errno=saved;if(saved)result=-1;break;}
        if(!strcmp(e->d_name,".")||!strcmp(e->d_name,".."))continue;
        char path[W2_PATH_CAP];int n=snprintf(path,sizeof path,"%s%s%s",prefix,*prefix?"/":"",e->d_name);
        if(n<0||(size_t)n>=sizeof path||++*seen>65536||!manifest_entry(r,path)){result=-1;break;}
        struct stat st;if(fstatat(fd,e->d_name,&st,AT_SYMLINK_NOFOLLOW)||w2_checkpoint()){result=-1;break;}
        if(S_ISDIR(st.st_mode)) {
            int sub=tree_open(fd,e->d_name,O_RDONLY|O_DIRECTORY);
            if(sub<0){result=-1;break;}
            result=enumerate_tree(sub,path,r,seen);close(sub);if(result)break;
        }
        errno=0;
    }
    int saved=errno;closedir(dir);errno=saved;return result;
}
static int validate_elf(struct w2_runtime *r) {
    const char *exe=w2_str(r->descriptor,"executable");
    int fd=resolve_runtime(r->seed_fd,exe+9,O_RDONLY);if(fd<0)return -1;
    Elf64_Ehdr h;struct stat st;int result=-1;
    if(fstat(fd,&st)||!(st.st_mode&0111)||pread(fd,&h,sizeof h,0)!=(ssize_t)sizeof h||
       memcmp(h.e_ident,ELFMAG,SELFMAG)||h.e_ident[EI_CLASS]!=ELFCLASS64||h.e_ident[EI_DATA]!=ELFDATA2LSB||
       h.e_machine!=EM_X86_64||h.e_phnum>128||h.e_phentsize!=sizeof(Elf64_Phdr))goto done;
    for(size_t i=0;i<h.e_phnum;++i) {
        Elf64_Phdr p;
        if(h.e_phoff>(uint64_t)st.st_size||pread(fd,&p,sizeof p,(off_t)(h.e_phoff+i*sizeof p))!=(ssize_t)sizeof p)goto done;
        if(p.p_type==PT_INTERP) {
            char name[W2_PATH_CAP];
            if(p.p_filesz<2||p.p_filesz>sizeof name||p.p_offset>(uint64_t)st.st_size||
               pread(fd,name,(size_t)p.p_filesz,(off_t)p.p_offset)!=(ssize_t)p.p_filesz||
               name[p.p_filesz-1]||name[0]!='/'||strlen(name)+1!=p.p_filesz)goto done;
            const char *relative=!strncmp(name,"/runtime/",9)?name+9:name+1;
            if(strncmp(name,"/runtime/",9)&&strncmp(name,"/lib/",5)&&strncmp(name,"/lib64/",7)&&strncmp(name,"/usr/",5))goto done;
            int loader=resolve_runtime(r->seed_fd,relative,O_RDONLY);if(loader<0)goto done;
            Elf64_Ehdr lh;ssize_t n=pread(loader,&lh,sizeof lh,0);close(loader);
            if(n!=(ssize_t)sizeof lh||memcmp(lh.e_ident,ELFMAG,SELFMAG)||lh.e_machine!=EM_X86_64||lh.e_ident[EI_CLASS]!=ELFCLASS64)goto done;
        }
    }
    /* All ELF components, including dlopened libraries, have a native header. */
    json_t *a=json_object_get(r->manifest,"files"),*e;size_t i;
    json_array_foreach(a,i,e)if(eq(e,"type","file")) {
        int f=tree_open(r->seed_fd,w2_str(e,"path"),O_RDONLY);if(f<0)goto done;
        Elf64_Ehdr lh;ssize_t n=pread(f,&lh,sizeof lh,0);close(f);
        if(n>=4&&!memcmp(lh.e_ident,ELFMAG,SELFMAG)&&(n!=(ssize_t)sizeof lh||
           lh.e_ident[EI_CLASS]!=ELFCLASS64||lh.e_ident[EI_DATA]!=ELFDATA2LSB||lh.e_machine!=EM_X86_64))goto done;
    }
    result=0;
done:close(fd);return result;
}
/* Phase 2 (agent-rm-model 648d60f2 6.5 性质 12; validation.md S-20): the cell files directory is bind-mounted read-only
 * into every cell; a read-only mount stops neither connecting to a Unix socket nor writing a FIFO, so a socket or FIFO
 * there would be an explicit channel between cells and to the host. Only directories, regular files and symlinks
 * that resolve beneath it; root's, and writable by no group or other, so nothing can be added after this check (D-16).
 * child.c mounts it again by path; the reference is one component of the deployment root, which the catalog load
 * checked is root's and writable by no group or other, so no one else can swap it in between.
 * Checked before every row: ENOTSUP for another file type, EPERM for an owner or a mode, EXDEV for a link that does not
 * resolve beneath it. */
static int cell_files_walk(int top,int dir,const char *prefix,unsigned depth,size_t *seen) {
    if(depth>16){errno=ELOOP;return -1;}
    int copy=dup(dir);if(copy<0)return -1;
    DIR *d=fdopendir(copy);if(!d){close(copy);return -1;}
    struct dirent *e;int result=0;
    for(;;) {
        errno=0;e=readdir(d);
        if(!e){if(errno)result=-1;break;}
        if(!strcmp(e->d_name,".")||!strcmp(e->d_name,".."))continue;
        char path[W2_PATH_CAP];int n=snprintf(path,sizeof path,"%s%s%s",prefix,*prefix?"/":"",e->d_name);
        if(n<0||(size_t)n>=sizeof path||++*seen>4096){errno=E2BIG;result=-1;break;}
        struct stat st;if(fstatat(dir,e->d_name,&st,AT_SYMLINK_NOFOLLOW)){result=-1;break;}
        if(st.st_uid!=0||(!S_ISLNK(st.st_mode)&&(st.st_mode&022))){errno=EPERM;result=-1;break;}   /* a link's mode is 0777 */
        if(S_ISDIR(st.st_mode)) {
            int sub=tree_open(dir,e->d_name,O_RDONLY|O_DIRECTORY);if(sub<0){result=-1;break;}
            result=cell_files_walk(top,sub,path,depth+1,seen);close(sub);if(result)break;
        } else if(S_ISLNK(st.st_mode)) {
            int fd=resolve_runtime(top,path,O_PATH);if(fd<0){errno=EXDEV;result=-1;break;}close(fd);
        } else if(!S_ISREG(st.st_mode)){errno=ENOTSUP;result=-1;break;}
    }
    int saved=errno;closedir(d);errno=saved;return result;
}
int w2_cell_files_check(struct w2_catalog *c) {
    int top=tree_open(c->root_fd,c->cell_files_ref,O_RDONLY|O_DIRECTORY);if(top<0)return -1;
    struct stat st;size_t seen=0;int result=-1;
    if(fstat(top,&st))goto done;
    if(st.st_uid!=0||(st.st_mode&022)){errno=EPERM;goto done;}
    result=cell_files_walk(top,top,"",0,&seen);
done:{int saved=errno;close(top);errno=saved;return result;}
}
int w2_runtime_verify_source(struct w2_runtime *r) {
    size_t seen=0;
    if(tree_check(r,r->seed_fd,false)||lseek(r->seed_fd,0,SEEK_SET)<0||w2_checkpoint()||
       enumerate_tree(r->seed_fd,"",r,&seen))return -1;
    return seen+1==r->charge_nodes?0:-1;
}
/* v2: an absolute executable with its argv (argv[0] equal to it), for the connector and the two cell helpers. */
static int parse_program(json_t *o,char **exe,char **argv) {
    const char *pexe=w2_str(o,"executable");json_t *pargv=json_object_get(o,"argv");size_t i;json_t *e;
    if(!pexe||pexe[0]!='/'||strlen(pexe)>W2_STRING_MAX||!json_is_array(pargv)||!json_array_size(pargv)||json_array_size(pargv)>W2_ARGV_MAX)return -1;
    *exe=strdup(pexe);if(!*exe)return -1;
    json_array_foreach(pargv,i,e){const char *s=json_string_value(e);if(!s||strlen(s)>W2_STRING_MAX||(i==0&&strcmp(s,pexe)))return -1;argv[i]=strdup(s);if(!argv[i])return -1;}
    return 0;
}
static int catalog_load(struct w2_catalog *c,const char *root,const char *file,bool recovery) {
    memset(c,0,sizeof *c);c->root_fd=c->instances_fd=-1;
    c->recovery_mode=recovery;
    c->storage.root_fd=c->storage.lock_fd=-1;
    for(size_t i=0;i<W2_ITEMS_MAX;++i)c->runtime[i].seed_fd=-1;
    if(w2_environment(&c->overflow,&c->overflow_gid)||strlen(root)>=sizeof c->root)return -1;
    c->root_fd=open_deployment(root);if(c->root_fd<0||check_dir(c->root_fd,true))goto bad;
    strcpy(c->root,root);
    c->document=w2_json_at(c->root_fd,file,c->digest);json_t *d=c->document;
    static const char *const catalog_keys[]={"v","runtimes","policies","workspaces","profiles","plans","storage_profile",
        "uid_range","connector","relay","frontend","proxy_port","cell_files_ref","ca_pool_ref","pdp","file_worker",
        "mcp_server","mcp_port","runtime_mode"};
    json_t *mode=d?json_object_get(d,"runtime_mode"):NULL;   /* optional, last in the list */
    c->shared_runtime=true;   /* the default since the workspace rework: every cell binds the verified seed (validation.md S-23) */
    if(mode){const char *m=json_string_value(mode);if(!m||(strcmp(m,"copy")&&strcmp(m,"shared")))goto bad;c->shared_runtime=!strcmp(m,"shared");}
    if(!d||!w2_keys(d,catalog_keys,mode?19:18)||
       !json_is_integer(json_object_get(d,"v"))||json_integer_value(json_object_get(d,"v"))!=1||
       !array(d,"runtimes")||!array(d,"policies")||!array(d,"workspaces")||!array(d,"profiles")||!array(d,"plans"))goto bad;
    size_t i;json_t *e;
    /* v2: the reserved uid range and the connector identity (agent-rm-model 3.1, 3.7). The engine's own uid is
     * checked against both by cell.c; the workspace owners below must lie outside the range. */
    json_t *range=json_object_get(d,"uid_range"),*conn=json_object_get(d,"connector");uint64_t first,last,cu,cg;
    if(!json_is_object(range)||!KEYS(range,"first","last")||!integer(range,"first",UINT32_MAX-2,&first)||
       !integer(range,"last",UINT32_MAX-2,&last)||!first||first>last||last-first>=65536||
       (c->overflow>=first&&c->overflow<=last)||(c->overflow_gid>=first&&c->overflow_gid<=last))goto bad;
    c->range_first=(uid_t)first;c->range_last=(uid_t)last;
    if(!json_is_object(conn)||!KEYS(conn,"uid","gid","executable","argv")||!integer(conn,"uid",UINT32_MAX-2,&cu)||
       !integer(conn,"gid",UINT32_MAX-2,&cg)||!cu||!cg||cu==c->overflow||cg==c->overflow_gid||
       (cu>=first&&cu<=last)||(cg>=first&&cg<=last))goto bad;
    c->connector.uid=(uid_t)cu;c->connector.gid=(gid_t)cg;
    /* v2 phase 2: the PDP's dedicated uid and group (agent-rm-model 648d60f2 4.2). The spawner never uses them; it only
     * holds the catalog to the same rules as the connector identity: outside the range, not a sentinel, not the
     * connector's. The engine checks them against its own uid at start (validation.md K-48). */
    json_t *pdp=json_object_get(d,"pdp");uint64_t pu,pg;
    if(!json_is_object(pdp)||!KEYS(pdp,"uid","gid")||!integer(pdp,"uid",UINT32_MAX-2,&pu)||!integer(pdp,"gid",UINT32_MAX-2,&pg)||
       !pu||!pg||pu==c->overflow||pg==c->overflow_gid||pu==cu||(pu>=first&&pu<=last)||(pg>=first&&pg<=last))goto bad;
    if(parse_program(conn,&c->connector.exe,c->connector.argv))goto bad;
    /* the row's file worker (validation.md H-14): its own dedicated identity under the same rules, apart from the
     * connector's (which holds the credentials) and the PDP's; the workspace loop below keeps it from every owner */
    json_t *fw=json_object_get(d,"file_worker");uint64_t wu,wg;
    if(!json_is_object(fw)||!KEYS(fw,"uid","gid","executable","argv")||!integer(fw,"uid",UINT32_MAX-2,&wu)||
       !integer(fw,"gid",UINT32_MAX-2,&wg)||!wu||!wg||wu==c->overflow||wg==c->overflow_gid||wu==cu||wg==cg||
       wu==pu||wg==pg||(wu>=first&&wu<=last)||(wg>=first&&wg<=last)||
       parse_program(fw,&c->file_worker.exe,c->file_worker.argv))goto bad;
    c->file_worker.uid=(uid_t)wu;c->file_worker.gid=(gid_t)wg;
    json_t *relay=json_object_get(d,"relay"),*frontend=json_object_get(d,"frontend");uint64_t port;
    if(!json_is_object(relay)||!KEYS(relay,"executable","argv")||parse_program(relay,&c->relay.exe,c->relay.argv)||
       !json_is_object(frontend)||!KEYS(frontend,"executable","argv")||parse_program(frontend,&c->frontend.exe,c->frontend.argv)||
       !integer(d,"proxy_port",65535,&port)||!port||!w2_relative(w2_str(d,"cell_files_ref"))||!w2_relative(w2_str(d,"ca_pool_ref"))||
       strchr(w2_str(d,"cell_files_ref"),'/'))goto bad;   /* one component: child.c mounts it by path (S-20) */
    c->proxy_port=(unsigned)port;c->cell_files_ref=strdup(w2_str(d,"cell_files_ref"));if(!c->cell_files_ref)goto bad;
    /* the in-cell MCP server (validation.md H-23): a program like the frontend's, its port like proxy_port and apart from it */
    json_t *mcp=json_object_get(d,"mcp_server");uint64_t mcp_port;
    if(!json_is_object(mcp)||!KEYS(mcp,"executable","argv")||parse_program(mcp,&c->mcp.exe,c->mcp.argv)||
       !integer(d,"mcp_port",65535,&mcp_port)||!mcp_port||mcp_port==port)goto bad;
    c->mcp_port=(unsigned)mcp_port;
    c->ca_pool_ref=strdup(w2_str(d,"ca_pool_ref"));if(!c->ca_pool_ref)goto bad;
    json_array_foreach(json_object_get(d,"runtimes"),i,e) {
        struct w2_runtime *r=&c->runtime[c->runtime_count++];char hash[W2_DIGEST_CAP];
        if(!KEYS(e,"descriptor_ref","descriptor_digest","seed_ref","dependency_lock_ref")||!w2_is_digest(w2_str(e,"descriptor_digest")))goto bad;
        r->descriptor=w2_json_at(c->root_fd,w2_str(e,"descriptor_ref"),r->digest);
        if(!r->descriptor||strcmp(r->digest,w2_str(e,"descriptor_digest"))||runtime_args(r))goto bad;
        for(size_t j=0;j<i;++j)if(eq(c->runtime[j].descriptor,"runtime_id",w2_str(r->descriptor,"runtime_id")))goto bad;
        r->seed_fd=w2_open_at(c->root_fd,w2_str(e,"seed_ref"),O_RDONLY|O_DIRECTORY);
        if(r->seed_fd<0||check_dir(r->seed_fd,false))goto bad;
        r->seed_ref=strdup(w2_str(e,"seed_ref"));if(!r->seed_ref)goto bad;
        char *manifest_bytes=NULL;
        if(w2_read_at(c->root_fd,w2_str(r->descriptor,"component_manifest_ref"),W2_MANIFEST_MAX,&manifest_bytes,&r->manifest_bytes))goto bad;
        w2_digest(manifest_bytes,r->manifest_bytes,hash);
        r->manifest=w2_json(manifest_bytes,r->manifest_bytes);free(manifest_bytes);
        if(!r->manifest||!eq(r->descriptor,"component_manifest_digest",hash)||!eq(r->descriptor,"artifact_digest",hash)||
           index_manifest(r)||tree_check(r,r->seed_fd,false))goto bad;
        size_t seen=0;if(enumerate_tree(r->seed_fd,"",r,&seen)||seen!=json_array_size(json_object_get(r->manifest,"files"))||validate_elf(r))goto bad;
        json_t *lock=manifest_entry(r,w2_str(e,"dependency_lock_ref"));
        if(!lock||!eq(lock,"type","file")||!eq(r->descriptor,"dependency_digest",w2_str(lock,"digest")))goto bad;
    }
    json_array_foreach(json_object_get(d,"policies"),i,e) {
        struct w2_policy *p=&c->policy[c->policy_count++];if(w2_policy_compile(c->root_fd,e,p))goto bad;
        for(size_t j=0;j<i;++j)if(eq(c->policy[j].entry,"policy_id",w2_str(e,"policy_id")))goto bad;
    }
    json_array_foreach(json_object_get(d,"workspaces"),i,e) {
        struct w2_workspace *w=&c->workspace[c->workspace_count++];uint64_t u,g;
        if(!KEYS(e,"workspace_id","workspace_layout_id","source_ref","workspace_uid","workspace_gid")||
           !w2_is_id(w2_str(e,"workspace_id"))||!eq(e,"workspace_layout_id","private-work-v1")||
           !integer(e,"workspace_uid",UINT32_MAX-1,&u)||!u||u==c->overflow||(u>=first&&u<=last)||
           !integer(e,"workspace_gid",UINT32_MAX-1,&g)||!g||g==c->overflow_gid||(g>=first&&g<=last)||
           u==cu||g==cg||u==pu||g==pg||u==wu||g==wg)goto bad;
        /* workspace_uid/gid are the on-disk owner: since the workspace rework a dedicated uid that no host process runs
         * as, so not the connector's or the PDP's (validation.md S-22; the engine's own ids are checked by cell.c).
         * Executions see the fixed subdirectory through an idmapped mount as their own uid (agent-rm-model 3.1, S-25).
         * Several workspaces may share one owner. */
        w->uid=(uid_t)u;w->gid=(gid_t)g;w->entry=json_incref(e);
        /* O_PATH anchors the granted directory without needing CAP_DAC_OVERRIDE
         * to read a 0700 workspace owned by the agent. Btrfs subvolume roots
         * have inode 256 and a device identity distinct from their parent. */
        int workspace_fd=w2_open_at(c->root_fd,w2_str(e,"source_ref"),O_PATH|O_DIRECTORY);
        struct stat st,parent_st;struct statfs fs;
        bool valid=workspace_fd>=0&&!fstat(workspace_fd,&st)&&!fstatfs(workspace_fd,&fs)&&fs.f_type==BTRFS_SUPER_MAGIC&&
           S_ISDIR(st.st_mode)&&st.st_uid==w->uid&&st.st_gid==w->gid&&(st.st_mode&07777)==0700&&st.st_ino==256&&
           !fstat(c->root_fd,&parent_st)&&st.st_dev!=parent_st.st_dev;
        if(workspace_fd>=0&&close(workspace_fd))valid=false;
        if(!valid)goto bad;
        /* Keep only deployment identity, never a workspace source reference
         * across pre-fork or executions. The preparing child opens its own. */
        w->identity=st;
        for(size_t j=0;j<i;++j)if(eq(c->workspace[j].entry,"workspace_id",w2_str(e,"workspace_id"))||
           eq(c->workspace[j].entry,"source_ref",w2_str(e,"source_ref")))goto bad;
    }
    json_array_foreach(json_object_get(d,"profiles"),i,e) {
        json_t *p=reference(c->root_fd,e,c->profile_digest[i]);c->profile[c->profile_count++]=p;
        if(!p||!KEYS(p,"isolation_profile_id","target_arch","layout","construction")||
           !w2_is_id(w2_str(p,"isolation_profile_id"))||!eq(p,"target_arch","x86_64")||
           !eq(p,"layout","runtime-root-v1")||!eq(p,"construction","SB-01-SB-09"))goto bad;
        for(size_t j=0;j<i;++j)if(eq(c->profile[j],"isolation_profile_id",w2_str(p,"isolation_profile_id")))goto bad;
    }
    json_array_foreach(json_object_get(d,"plans"),i,e) {
        struct w2_plan *p=&c->plan[c->plan_count++];p->entry=reference(c->root_fd,e,p->digest);json_t *j=p->entry;
        if(!j||!KEYS(j,"launch_plan_id","runtime_id","runtime_descriptor_digest","workspace_id","workspace_layout_id",
           "policy_id","policy_digest","isolation_profile_id","isolation_profile_digest"))goto bad;
        const char *ids[]={"launch_plan_id","runtime_id","workspace_id","workspace_layout_id","policy_id","isolation_profile_id"};
        for(size_t k=0;k<6;++k)if(!w2_is_id(w2_str(j,ids[k])))goto bad;
        for(size_t k=0;k<i;++k)if(eq(c->plan[k].entry,"launch_plan_id",w2_str(j,"launch_plan_id")))goto bad;
        for(size_t k=0;k<c->runtime_count;++k)if(eq(c->runtime[k].descriptor,"runtime_id",w2_str(j,"runtime_id"))&&eq(j,"runtime_descriptor_digest",c->runtime[k].digest))p->runtime=&c->runtime[k];
        for(size_t k=0;k<c->policy_count;++k)if(eq(c->policy[k].entry,"policy_id",w2_str(j,"policy_id"))&&eq(j,"policy_digest",c->policy[k].digest))p->policy=&c->policy[k];
        for(size_t k=0;k<c->workspace_count;++k)if(eq(c->workspace[k].entry,"workspace_id",w2_str(j,"workspace_id"))&&eq(j,"workspace_layout_id",w2_str(c->workspace[k].entry,"workspace_layout_id")))p->workspace=&c->workspace[k];
        bool profile=false;
        for(size_t k=0;k<c->profile_count;++k)if(eq(c->profile[k],"isolation_profile_id",w2_str(j,"isolation_profile_id"))&&eq(j,"isolation_profile_digest",c->profile_digest[k]))profile=true;
        if(!p->runtime||!p->policy||!p->workspace||!profile)goto bad;
    }
    if(w2_storage_load(c))goto bad;
    for(size_t k=0;k<c->runtime_count;++k)if(!eq(c->runtime[k].descriptor,"storage_profile_id",w2_str(c->storage.entry,"storage_profile_id")))goto bad;
    int mount_root=w2_open_at(c->root_fd,"sandbox-root",O_RDONLY|O_DIRECTORY);struct stat mount_st;
    if(mount_root<0)goto bad;
    int root_valid=!fstat(mount_root,&mount_st)&&mount_st.st_uid==0&&!(mount_st.st_mode&0022);close(mount_root);if(!root_valid)goto bad;
    return 0;
bad:w2_catalog_free(c);errno=EINVAL;return -1;
}
int w2_catalog_load(struct w2_catalog *c,const char *root,const char *file){return catalog_load(c,root,file,false);}
int w2_catalog_load_recovery(struct w2_catalog *c,const char *root,const char *file){return catalog_load(c,root,file,true);}
int w2_workspace_open(int deployment_fd,const struct w2_workspace *w) {
    int fd=w2_open_at(deployment_fd,w2_str(w->entry,"source_ref"),O_PATH|O_DIRECTORY);
    if(fd<0)return -1;
    struct stat st;struct statfs fs;
    if(fstat(fd,&st)||fstatfs(fd,&fs)||fs.f_type!=BTRFS_SUPER_MAGIC||!S_ISDIR(st.st_mode)||
       st.st_dev!=w->identity.st_dev||st.st_ino!=w->identity.st_ino||
       st.st_uid!=w->uid||st.st_gid!=w->gid||(st.st_mode&07777)!=0700){
        close(fd);errno=ESTALE;return -1;
    }
    return fd;
}
void w2_catalog_free(struct w2_catalog *c) {
    for(size_t i=0;i<c->runtime_count;++i) {
        struct w2_runtime *r=&c->runtime[i];json_decref(r->descriptor);json_decref(r->manifest);json_decref(r->paths);r->paths=NULL;
        if(r->seed_fd>=0)close(r->seed_fd);
        free(r->seed_ref);r->seed_ref=NULL;
        for(size_t j=0;j<W2_ARGV_MAX;++j)free(r->argv[j]);
        for(size_t j=0;j<W2_ENV_MAX;++j)free(r->env[j]);
    }
    for(size_t i=0;i<c->policy_count;++i){json_decref(c->policy[i].entry);free(c->policy[i].program.filter);}
    for(size_t i=0;i<c->workspace_count;++i)json_decref(c->workspace[i].entry);
    free(c->connector.exe);c->connector.exe=NULL;
    for(size_t j=0;j<W2_ARGV_MAX;++j){free(c->connector.argv[j]);c->connector.argv[j]=NULL;}
    free(c->file_worker.exe);c->file_worker.exe=NULL;
    for(size_t j=0;j<W2_ARGV_MAX;++j){free(c->file_worker.argv[j]);c->file_worker.argv[j]=NULL;}
    free(c->relay.exe);c->relay.exe=NULL;free(c->frontend.exe);c->frontend.exe=NULL;free(c->cell_files_ref);c->cell_files_ref=NULL;
    free(c->ca_pool_ref);c->ca_pool_ref=NULL;
    for(size_t j=0;j<W2_ARGV_MAX;++j){free(c->relay.argv[j]);c->relay.argv[j]=NULL;free(c->frontend.argv[j]);c->frontend.argv[j]=NULL;}
    free(c->mcp.exe);c->mcp.exe=NULL;
    for(size_t j=0;j<W2_ARGV_MAX;++j){free(c->mcp.argv[j]);c->mcp.argv[j]=NULL;}
    for(size_t i=0;i<c->profile_count;++i)json_decref(c->profile[i]);
    for(size_t i=0;i<c->plan_count;++i)json_decref(c->plan[i].entry);
    if(c->instances_fd>=0)close(c->instances_fd);
    if(c->storage.root_fd>=0)close(c->storage.root_fd);
    if(c->storage.lock_fd>=0)close(c->storage.lock_fd);
    json_decref(c->storage.entry);
    if(c->root_fd>=0)close(c->root_fd);
    json_decref(c->document);c->root_fd=c->instances_fd=-1;
}
struct w2_plan *w2_plan_find(struct w2_catalog *c,const char *id,const char *digest) {
    for(size_t i=0;i<c->plan_count;++i)if(eq(c->plan[i].entry,"launch_plan_id",id)&&digest&&!strcmp(c->plan[i].digest,digest))return &c->plan[i];
    return NULL;
}
int w2_runtime_create(struct w2_catalog *c,struct w2_runtime *r,const char *copy,
                      uint64_t *dev,uint64_t *ino,bool *created) {
    *created=false;*dev=*ino=0;int root=-1,result=-1;
    if(w2_checkpoint()||w2_fault("create.mkdir")||mkdirat(c->instances_fd,copy,0755))return -1;
    *created=true;struct stat identity;
    if(w2_checkpoint())return -1;
    if(fstatat(c->instances_fd,copy,&identity,AT_SYMLINK_NOFOLLOW))return -1;
    *dev=identity.st_dev;*ino=identity.st_ino;
    root=tree_open(c->instances_fd,copy,O_RDONLY|O_DIRECTORY);if(root<0)return -1;
    json_t *files=json_object_get(r->manifest,"files"),*e;size_t i;
    json_array_foreach(files,i,e) {
        if(w2_checkpoint())goto done;
        const char *path=w2_str(e,"path");mode_t mode=(mode_t)json_integer_value(json_object_get(e,"mode"));
        if(eq(e,"type","directory")){if(w2_fault("create.directory")||mkdirat(root,path,0755))goto done;}
        else if(eq(e,"type","symlink")){if(w2_fault("create.symlink")||symlinkat(w2_str(e,"target"),root,path))goto done;}
        else {
            int src=tree_open(r->seed_fd,path,O_RDONLY);
            if(src<0)goto done;
            int dst=w2_fault("create.open")?-1:tree_open(root,path,O_RDWR|O_CREAT|O_EXCL);
            if(src<0||dst<0){if(src>=0)close(src);if(dst>=0)close(dst);goto done;}
            int rc=w2_checkpoint()||w2_fault("reflink")||ioctl(dst,FICLONE,src);   /* no digest per row (S-21) */
            if(!rc)rc=w2_checkpoint()||w2_fault("create.chmod")||fchmod(dst,mode);
            int saved=errno;close(src);close(dst);errno=saved;if(rc)goto done;
        }
        if(w2_checkpoint())goto done;
    }
#ifdef W2_TESTING
    /* check_storage (validation.md S-21): a FIFO or a socket put in a manifest file's place after the copy is made must
     * be refused by the structure check below, by its type */
    {bool fifo=w2_fault("create.special.fifo"),sock=!fifo&&w2_fault("create.special.socket");
     if(fifo||sock)json_array_foreach(files,i,e)if(eq(e,"type","file")) {
         const char *path=w2_str(e,"path");mode_t mode=(mode_t)json_integer_value(json_object_get(e,"mode"));
         if(unlinkat(root,path,0)||mknodat(root,path,(fifo?S_IFIFO:S_IFSOCK)|mode,0)||fchmodat(root,path,mode,0))goto done;
         break;
     }}
#endif
    if(w2_fault("create.tree_verify")||tree_check(r,root,true))goto done;
    {size_t seen=0;      /* nothing on the copy outside the manifest (S-21) */
     if(lseek(root,0,SEEK_SET)<0||enumerate_tree(root,"",r,&seen)||seen!=json_array_size(files))goto done;}
    result=0;
done:{int saved=errno;close(root);errno=saved;return result;}
}
/* Consumes fd, so recursive traversal holds one directory fd per level. */
static int remove_known(int fd,struct w2_runtime *runtime,const char *prefix,unsigned depth,size_t *nodes,bool deleting) {
    if(depth>64||w2_checkpoint()){close(fd);return -1;}
    DIR *dir=fdopendir(fd);if(!dir){close(fd);return -1;}
    struct dirent *entry;int result=0;
    for(;;) {
        if(w2_checkpoint()){result=-1;break;}
        errno=0;entry=readdir(dir);int saved=errno;
        if(w2_checkpoint()){result=-1;break;}
        if(!entry){errno=saved;if(saved)result=-1;break;}
        if(!strcmp(entry->d_name,".")||!strcmp(entry->d_name,".."))continue;
        char path[W2_PATH_CAP];int length=snprintf(path,sizeof path,"%s%s%s",prefix,*prefix?"/":"",entry->d_name);
        if(length<0||(size_t)length>=sizeof path||++*nodes>runtime->charge_nodes||w2_checkpoint()){result=-1;break;}
        json_t *expected=manifest_entry(runtime,path);struct stat st;
        if(!expected||fstatat(fd,entry->d_name,&st,AT_SYMLINK_NOFOLLOW)||st.st_uid!=0||st.st_gid!=0){errno=ESTALE;result=-1;break;}
        if(w2_checkpoint()){result=-1;break;}
        if(eq(expected,"type","directory")) {
            if(!S_ISDIR(st.st_mode)||((st.st_mode&07777)!=0755&&(st.st_mode&07777)!=0700)){errno=ESTALE;result=-1;break;}
            int sub=tree_open(fd,entry->d_name,O_RDONLY|O_DIRECTORY);if(sub<0){result=-1;break;}
            result=remove_known(sub,runtime,path,depth+1,nodes,deleting);if(result)break;
            if(deleting&&(w2_checkpoint()||w2_fault("delete.rmdir")||unlinkat(fd,entry->d_name,AT_REMOVEDIR))){result=-1;break;}
        }else {
            bool regular=eq(expected,"type","file");
            /* Partial create may still own a 0600 file; it is still the same
             * manifest node. No unknown type, hardlink, or foreign owner. */
            if((regular&&(!S_ISREG(st.st_mode)||st.st_nlink!=1||st.st_size<0||
                  (uint64_t)st.st_size>(uint64_t)json_integer_value(json_object_get(expected,"size"))||
                  ((st.st_mode&07777)!=0600&&(st.st_mode&07777)!=(mode_t)json_integer_value(json_object_get(expected,"mode")))))||
               (!regular&&(!eq(expected,"type","symlink")||!S_ISLNK(st.st_mode)))){errno=ESTALE;result=-1;break;}
            if(!regular){char target[W2_PATH_CAP];ssize_t n=readlinkat(fd,entry->d_name,target,sizeof target-1);
                if(n<0||w2_checkpoint()||(size_t)n>=sizeof target-1){result=-1;break;}target[n]=0;
                if(strcmp(target,w2_str(expected,"target"))){errno=ESTALE;result=-1;break;}}
            if(deleting&&(w2_checkpoint()||w2_fault("delete.unlink")||unlinkat(fd,entry->d_name,0))){result=-1;break;}
            if(deleting&&w2_fault("delete.partial")){result=-1;break;}
        }
        if(w2_checkpoint()){result=-1;break;}errno=0;
    }
    int saved=errno;closedir(dir);errno=saved;return result;
}
int w2_runtime_delete(struct w2_catalog *c,struct w2_runtime *r,const char *copy,
                      uint64_t dev,uint64_t ino,bool previously_removed,bool *removed) {
    *removed=false;if(w2_checkpoint())return -1;
    struct stat identity;
    if(fstatat(c->instances_fd,copy,&identity,AT_SYMLINK_NOFOLLOW)) {
        if(errno!=ENOENT||!previously_removed)return -1;
        *removed=true;
    }else {
        if(previously_removed||!S_ISDIR(identity.st_mode)||identity.st_uid!=0||identity.st_gid!=0||
           ((identity.st_mode&07777)!=0755&&(identity.st_mode&07777)!=0700)||(uint64_t)identity.st_dev!=dev||(uint64_t)identity.st_ino!=ino){errno=ESTALE;return -1;}
        int fd=tree_open(c->instances_fd,copy,O_RDONLY|O_DIRECTORY);if(fd<0)return -1;
        size_t nodes=1;int rc=remove_known(fd,r,"",0,&nodes,true);if(rc)return -1;
        if(w2_checkpoint()||w2_fault("delete.root")||unlinkat(c->instances_fd,copy,AT_REMOVEDIR))return -1;
        *removed=true;
    }
#ifdef W2_TESTING
    static bool fsync_faulted;
    if(w2_fault("delete.fsync.once")&&!fsync_faulted){fsync_faulted=true;return -1;}
#endif
    if(w2_checkpoint()||w2_fault("delete.fsync")||fsync(c->instances_fd))return -1;
#ifdef W2_TESTING
    if(w2_fault("delete.fsync.late"))(void)poll(NULL,0,1200);
#endif
    return 0; /* Actual fsync completion remains a release fact even if late. */
}
int w2_runtime_matches(struct w2_catalog *c,struct w2_runtime *r,const char *copy) {
    int fd=tree_open(c->instances_fd,copy,O_RDONLY|O_DIRECTORY);if(fd<0)return -1;
    size_t nodes=1;return remove_known(fd,r,"",0,&nodes,false);
}
