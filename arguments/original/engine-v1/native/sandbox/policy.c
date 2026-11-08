#define _GNU_SOURCE
#include "catalog.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/sched.h>
#include <seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

int w2_policy_compile(int root,json_t *entry,struct w2_policy *p) {
    static const char *const fields[]={"policy_id","artifact_ref","artifact_digest","target_arch","format","compiler_identity"};
    static const char *const body_fields[]={"v","target_arch","default_action","default_errno","allow"};
    static const char *const forbidden[]={"bind","connect","io_uring_setup","io_uring_enter","io_uring_register", "clone3", "sysinfo", "sync", "syncfs"};
    if(!w2_keys(entry,fields,6)||!w2_is_id(w2_str(entry,"policy_id"))||
       !w2_is_digest(w2_str(entry,"artifact_digest"))||
       !w2_str(entry,"target_arch")||strcmp(w2_str(entry,"target_arch"),"x86_64")||
       !w2_str(entry,"format")||strcmp(w2_str(entry,"format"),"w2-seccomp-json/1")) return -1;
    char compiler[80]; const struct scmp_version *v=seccomp_version();
    snprintf(compiler,sizeof compiler,"libseccomp-%u.%u.%u",v->major,v->minor,v->micro);
    if(!w2_str(entry,"compiler_identity")||strcmp(w2_str(entry,"compiler_identity"),compiler)) return -1;
    json_t *body=w2_json_at(root,w2_str(entry,"artifact_ref"),p->digest);
    scmp_filter_ctx ctx=NULL; int fd=-1,ret=-1;
    if(!body||strcmp(p->digest,w2_str(entry,"artifact_digest"))||!w2_keys(body,body_fields,5)||
       !json_is_integer(json_object_get(body,"v"))||json_integer_value(json_object_get(body,"v"))!=1||
       !w2_str(body,"target_arch")||strcmp(w2_str(body,"target_arch"),"x86_64")||
       !w2_str(body,"default_action")||strcmp(w2_str(body,"default_action"),"errno")||
       !json_is_integer(json_object_get(body,"default_errno"))||json_integer_value(json_object_get(body,"default_errno"))!=EPERM) goto done;
    json_t *allow=json_object_get(body,"allow");
    if(!json_is_array(allow)||!json_array_size(allow)||json_array_size(allow)>256) goto done;
    if(seccomp_arch_native()!=SCMP_ARCH_X86_64) goto done;
    ctx=seccomp_init(SCMP_ACT_ERRNO(EPERM)); if(!ctx) goto done;
    if(seccomp_attr_set(ctx,SCMP_FLTATR_ACT_BADARCH,SCMP_ACT_KILL_PROCESS)) goto done;
    if(seccomp_rule_add(ctx,SCMP_ACT_ERRNO(ENOSYS),SCMP_SYS(clone3),0)) goto done;
    size_t i; json_t *s;
    json_array_foreach(allow,i,s) {
        const char *name=json_string_value(s);
        if(!name||!w2_is_id(name)) goto done;
        for(size_t j=0;j<i;++j) if(!strcmp(name,json_string_value(json_array_get(allow,j)))) goto done;
        for(size_t j=0;j<sizeof forbidden/sizeof forbidden[0];++j) if(!strcmp(name,forbidden[j])) goto done;
        int nr=seccomp_syscall_resolve_name_arch(SCMP_ARCH_X86_64,name);
        if(nr<0) goto done;
        int r;
        if(!strcmp(name,"clone")||!strcmp(name,"unshare")) {
            r=seccomp_rule_add(ctx,SCMP_ACT_ALLOW,nr,1,
                 SCMP_A0(SCMP_CMP_MASKED_EQ,CLONE_NEWUSER,0));
        } else r=seccomp_rule_add(ctx,SCMP_ACT_ALLOW,nr,0);
        if(r) goto done;
    }
    fd=memfd_create("w2-policy",MFD_CLOEXEC|MFD_ALLOW_SEALING); if(fd<0) goto done;
    if(seccomp_export_bpf(ctx,fd)) goto done;
    off_t n=lseek(fd,0,SEEK_END);
    if(n<=0||n>(off_t)(4096*sizeof(struct sock_filter))||n%sizeof(struct sock_filter)) goto done;
    if(fcntl(fd,F_ADD_SEALS,F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_SEAL)) goto done;
    p->program.filter=malloc((size_t)n); if(!p->program.filter) goto done;
    if(pread(fd,p->program.filter,(size_t)n,0)!=n) goto done;
    p->program.len=(unsigned short)((size_t)n/sizeof(struct sock_filter));
    w2_digest(p->program.filter,(size_t)n,p->bpf_digest);
    p->entry=json_incref(entry); ret=0;
done:
    if(ret) { free(p->program.filter);p->program.filter=NULL;p->program.len=0; }
    if(fd>=0) close(fd);
    if(ctx) seccomp_release(ctx);
    json_decref(body); return ret;
}
