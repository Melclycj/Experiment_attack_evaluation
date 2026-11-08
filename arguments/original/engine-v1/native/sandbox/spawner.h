#ifndef W2_SPAWNER_H
#define W2_SPAWNER_H
#include "catalog.h"
/* Owns control fd until exit; caller must pre-fork before opening secrets. */
int w2_spawner_run(struct w2_catalog *catalog,int control);
int w2_child_launch(struct w2_plan *plan,int channel,int objects_fd,int deployment_fd,const char *copy,
                    uint64_t root_dev,uint64_t root_ino,const char *root,
                    const char *runtime_source,const char *deployment,uint64_t deadline);
#endif
