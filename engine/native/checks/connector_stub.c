#define _GNU_SOURCE
/* Test stand-in for the v2 connector (block 1 regression only; the real connector is block 4, Python).
 * It verifies the inheritance contract the spawner promises (validation.md S-11, S-12): fd 3 is the row's proxy
 * listening socket with SO_PASSCRED set, fd 4 is one end of the judgment socketpair, nothing else is open, and
 * then waits to be ended by the spawner. Exit codes: 3 wrong fd 3, 4 wrong fd 4, 5 extra fds, 6 bad argv. */
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static int sockopt(int fd,int option) {int value=-1;socklen_t size=sizeof value;return getsockopt(fd,SOL_SOCKET,option,&value,&size)?-1:value;}
int main(int argc,char **argv) {
    if(argc<3||!argv[argc-2][0]||!argv[argc-1][0])return 6;   /* ... <uid_i> <execution_id> */
    if(sockopt(3,SO_DOMAIN)!=AF_UNIX||sockopt(3,SO_TYPE)!=SOCK_STREAM||sockopt(3,SO_ACCEPTCONN)!=1||sockopt(3,SO_PASSCRED)!=1)return 3;
    struct sockaddr_un peer;socklen_t n=sizeof peer;
    if(sockopt(4,SO_DOMAIN)!=AF_UNIX||sockopt(4,SO_TYPE)!=SOCK_STREAM||getpeername(4,(struct sockaddr *)&peer,&n))return 4;
    for(int fd=5;fd<64;++fd)if(fcntl(fd,F_GETFD)>=0)return 5;
    for(;;)pause();
}
