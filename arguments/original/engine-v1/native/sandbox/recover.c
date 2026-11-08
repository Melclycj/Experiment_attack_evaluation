#define _GNU_SOURCE
#include "storage.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int main(int argc,char **argv){
    if(argc!=4||strcmp(argv[3],"--supervisor-confirmed-old-domain-empty")){
        fputs("usage: w2-recover ROOT CATALOG --supervisor-confirmed-old-domain-empty\n",stderr);return 2;}
    if(close_range(3,~0u,0))return 2;
    struct w2_catalog *catalog=calloc(1,sizeof *catalog);if(!catalog)return 2;
    if(w2_catalog_load_recovery(catalog,argv[1],argv[2])){free(catalog);return 2;}
    int rc=w2_recover_store(catalog);w2_catalog_free(catalog);free(catalog);
    if(rc){perror("store recovery retained");return 1;}
    puts("{\"filesystem_recovery\":\"released\",\"old_domain_empty\":\"supplied by trusted supervisor; not inferred here\"}");return 0;
}
