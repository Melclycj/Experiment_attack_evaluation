#define _GNU_SOURCE
#include "catalog.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int main(int argc,char **argv) {
    if(argc!=3&&argc!=4)return 2;
    struct w2_catalog *c=calloc(1,sizeof *c);if(!c)return 2;
    if(w2_catalog_load(c,argv[1],argv[2])){perror("catalog validation");free(c);return 1;}
    json_t *root=json_pack("{s:s,s:[]}","catalog_digest",c->digest,"policies");
    for(size_t i=0;i<c->policy_count;++i) {
        struct w2_policy *p=&c->policy[i];
        if(argc==4) {
            char path[W2_PATH_CAP];int n=snprintf(path,sizeof path,"%s/%s.bpf",argv[3],w2_str(p->entry,"policy_id"));
            if(n<0||(size_t)n>=sizeof path)return 2;
            int fd=open(path,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);if(fd<0)return 2;
            size_t bytes=(size_t)p->program.len*sizeof(struct sock_filter),offset=0;
            while(offset<bytes){ssize_t got=write(fd,(char *)p->program.filter+offset,bytes-offset);if(got<0&&errno==EINTR)continue;if(got<=0)return 2;offset+=(size_t)got;}
            if(close(fd))return 2;
        }
        json_array_append_new(json_object_get(root,"policies"),json_pack("{s:s,s:s,s:s,s:i}",
            "policy_id",w2_str(p->entry,"policy_id"),"source_digest",p->digest,"bpf_digest",p->bpf_digest,"instructions",(int)p->program.len));
    }
    char *wire=json_dumps(root,JSON_COMPACT);if(!wire)return 2;puts(wire);free(wire);json_decref(root);
    w2_catalog_free(c);free(c);return 0;
}
