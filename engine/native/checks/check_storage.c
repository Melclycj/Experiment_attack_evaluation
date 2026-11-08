#define _GNU_SOURCE
#include "storage.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <unistd.h>

/* Filesystem checks use the same capless 0:0 posture as the file worker.
 * Faults below simulate syscall failure; the surrounding filesystem is real. */
static void protocol(void) {
    const char *good="{\"v\":1,\"type\":\"job\",\"seq\":\"1\",\"job_id\":\"1\",\"op\":\"create\",\"copy_id\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:1:r\",\"runtime_id\":\"observe\",\"deadline_ns\":\"1\",\"root_dev\":null,\"root_ino\":null}";
    const char *keys[]={"v","seq","job_id","op","copy_id","deadline_ns","root_dev","extra"};
    json_t *base=w2_json(good,strlen(good));assert(base);json_object_set_new(base,"root_removed",json_false());
    char *current=json_dumps(base,JSON_COMPACT);assert(current);json_decref(base);
    json_t *j=w2_job_parse(current,strlen(current));assert(j);json_decref(j);
    for(size_t i=0;i<sizeof keys/sizeof *keys;++i){
        j=w2_json(current,strlen(current));assert(j);json_object_set_new(j,keys[i],json_string("bad"));
        char *s=json_dumps(j,JSON_COMPACT);assert(s);assert(!w2_job_parse(s,strlen(s)));free(s);json_decref(j);
    }
    char large[1025];memset(large,' ',sizeof large);assert(!w2_job_parse(large,sizeof large));
    free(current);
    puts("{\"check\":\"private-job-schema\",\"result\":\"passed\"}");
}
static void made(struct w2_catalog *c,const char *copy,uint64_t *dev,uint64_t *ino) {
    bool created=false;assert(!w2_runtime_create(c,&c->runtime[0],copy,dev,ino,&created)&&created);
}
static void deleted(struct w2_catalog *c,const char *copy,uint64_t dev,uint64_t ino) {
    bool removed=false;assert(!w2_runtime_delete(c,&c->runtime[0],copy,dev,ino,false,&removed)&&removed);
}
int main(int argc,char **argv) {
    assert(argc==3||argc==4);if(argc==3)protocol();
    struct w2_catalog *c=calloc(1,sizeof *c);assert(c&&!w2_catalog_load(c,argv[1],argv[2]));
    enum w2_stage stage;umask(0);assert(!w2_drop(0,0,&stage));
    cap_t caps=cap_get_proc();char *text=cap_to_text(caps,NULL);assert(text&&!strcmp(text,"="));cap_free(text);cap_free(caps);
    for(int i=0;i<=40;++i)assert(prctl(PR_CAPBSET_READ,i,0,0,0)==0);
    assert(prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)==1);
    const char *copy="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:1:r";
    if(argc==4){
        assert(!strcmp(argv[3],"--probe-failure"));
        /* This primitive-only observer relinquishes the writable lock handle
         * so the supervisor can remount readonly. Production retains it. */
        close(c->storage.lock_fd);c->storage.lock_fd=-1;
        puts("READY");fflush(stdout);assert(getchar()=='G');
        uint64_t dev=0,ino=0;bool created=false;errno=0;
        int rc=w2_runtime_create(c,&c->runtime[0],copy,&dev,&ino,&created),saved=errno;
        printf("{\"runtime_create_result\":%d,\"os_errno\":%d,\"partial_created\":%s,\"capabilities\":\"all-zero\"}\n",rc,saved,created?"true":"false");
        w2_catalog_free(c);free(c);return rc?0:1;
    }
    /* phase 2 (validation.md S-21): a row's copy is not hashed any more, so there is no create.verify point */
    const char *faults[]={"create.mkdir","create.directory","create.open","reflink","create.chmod","create.symlink","create.tree_verify"};
    for(size_t i=0;i<sizeof faults/sizeof *faults;++i){
        uint64_t dev=0,ino=0;bool created=false;w2_fault_configure(faults[i]);
        assert(w2_runtime_create(c,&c->runtime[0],copy,&dev,&ino,&created));w2_fault_configure("");
        if(created){assert(ino);deleted(c,copy,dev,ino);}
        struct stat st;assert(fstatat(c->instances_fd,copy,&st,AT_SYMLINK_NOFOLLOW)&&errno==ENOENT);
        printf("{\"check\":\"%s\",\"partial_created\":%s,\"result\":\"passed\"}\n",faults[i],created?"true":"false");
    }
    /* phase 2 (validation.md S-21): at row start the copy gets a structure check only. A FIFO or a socket in a file's
     * place is refused by its type; a seed whose content changed after start (size kept) is copied as it is. */
    const char *first=NULL;
    {json_t *e;size_t i;json_array_foreach(json_object_get(c->runtime[0].manifest,"files"),i,e)
         if(!first&&!strcmp(w2_str(e,"type"),"file"))first=w2_str(e,"path");}
    assert(first);
    const char *special[]={"create.special.fifo","create.special.socket"};
    for(size_t i=0;i<2;++i){
        uint64_t dev=0,ino=0;bool created=false;w2_fault_configure(special[i]);
        assert(w2_runtime_create(c,&c->runtime[0],copy,&dev,&ino,&created)&&created);w2_fault_configure("");
        int fd=openat(c->instances_fd,copy,O_RDONLY|O_DIRECTORY|O_NOFOLLOW);struct stat st;
        assert(fd>=0&&!fstatat(fd,first,&st,AT_SYMLINK_NOFOLLOW)&&(i?S_ISSOCK(st.st_mode):S_ISFIFO(st.st_mode)));
        assert(!unlinkat(fd,first,0));close(fd);deleted(c,copy,dev,ino);
        printf("{\"check\":\"%s-refused\",\"result\":\"passed\"}\n",special[i]);
    }
    {   const char *lock="dependency-lock.json";int seed=c->runtime[0].seed_fd;struct stat st;
        assert(!fstatat(seed,lock,&st,AT_SYMLINK_NOFOLLOW)&&!fchmodat(seed,lock,0600,0));
        int fd=openat(seed,lock,O_RDWR|O_NOFOLLOW|O_CLOEXEC);unsigned char was,now,got;
        assert(fd>=0&&pread(fd,&was,1,0)==1);now=was^0xff;assert(pwrite(fd,&now,1,0)==1);
        uint64_t dev=0,ino=0;made(c,copy,&dev,&ino);
        int cfd=openat(c->instances_fd,copy,O_RDONLY|O_DIRECTORY|O_NOFOLLOW);assert(cfd>=0);
        int f=openat(cfd,lock,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);assert(f>=0&&pread(f,&got,1,0)==1&&got==now);
        close(f);close(cfd);deleted(c,copy,dev,ino);
        assert(pwrite(fd,&was,1,0)==1&&!fsync(fd));close(fd);assert(!fchmodat(seed,lock,st.st_mode&07777,0));
        puts("{\"check\":\"row-start-does-not-compare-content\",\"result\":\"passed\"}");
    }
    uint64_t dev=0,ino=0;bool removed=false;made(c,copy,&dev,&ino);
    assert(w2_runtime_delete(c,&c->runtime[0],copy,dev,ino+1,false,&removed)&&!removed);
    int fd=openat(c->instances_fd,copy,O_RDONLY|O_DIRECTORY|O_NOFOLLOW);assert(fd>=0);
    int extra=openat(fd,"unknown",O_WRONLY|O_CREAT|O_EXCL,0600);assert(extra>=0);close(extra);
    assert(w2_runtime_matches(c,&c->runtime[0],copy));
    assert(w2_runtime_delete(c,&c->runtime[0],copy,dev,ino,false,&removed)&&!removed);
    assert(!unlinkat(fd,"unknown",0));close(fd);deleted(c,copy,dev,ino);
    puts("{\"check\":\"wrong-inode-and-unknown-node-retained\",\"result\":\"passed\"}");
    made(c,copy,&dev,&ino);
    fd=openat(c->instances_fd,copy,O_RDONLY|O_DIRECTORY|O_NOFOLLOW);assert(fd>=0);
    assert(!fchmod(fd,0700)&&!fchmodat(fd,"bin",0700,0));close(fd);
    assert(!w2_runtime_matches(c,&c->runtime[0],copy));deleted(c,copy,dev,ino);
    puts("{\"check\":\"0700-partial-root-and-directory-without-chmod-repair\",\"result\":\"passed\"}");
    made(c,copy,&dev,&ino);fd=openat(c->instances_fd,copy,O_RDONLY|O_DIRECTORY|O_NOFOLLOW);assert(fd>=0);
    assert(!unlinkat(fd,"dependency-lock.json",0));
    extra=openat(fd,"dependency-lock.json",O_RDWR|O_CREAT|O_EXCL,0600);assert(extra>=0);
    assert(!ftruncate(extra,1024*1024));close(extra);
    assert(w2_runtime_matches(c,&c->runtime[0],copy));
    assert(w2_runtime_delete(c,&c->runtime[0],copy,dev,ino,false,&removed)&&!removed);
    assert(!unlinkat(fd,"dependency-lock.json",0));close(fd);deleted(c,copy,dev,ino);
    puts("{\"check\":\"oversized-partial-node-retained\",\"result\":\"passed\"}");
    made(c,copy,&dev,&ino);w2_fault_configure("delete.fsync");
    assert(w2_runtime_delete(c,&c->runtime[0],copy,dev,ino,false,&removed)&&removed);
    w2_fault_configure("");
    assert(w2_runtime_delete(c,&c->runtime[0],copy,dev,ino,false,&removed)&&!removed);
    assert(!w2_runtime_delete(c,&c->runtime[0],copy,dev,ino,true,&removed)&&removed);
    puts("{\"check\":\"removed-root-fsync-failure-requires-known-ENOENT-retry\",\"result\":\"passed\"}");
    const char *deletes[]={"delete.unlink","delete.rmdir","delete.partial","delete.root"};
    for(size_t i=0;i<sizeof deletes/sizeof *deletes;++i){
        made(c,copy,&dev,&ino);w2_fault_configure(deletes[i]);
        assert(w2_runtime_delete(c,&c->runtime[0],copy,dev,ino,false,&removed)&&!removed);
        w2_fault_configure("");deleted(c,copy,dev,ino);
        printf("{\"check\":\"%s-retry\",\"result\":\"passed\"}\n",deletes[i]);
    }
    w2_catalog_free(c);free(c);puts("{\"capless_storage_checks\":\"passed\"}");return 0;
}
