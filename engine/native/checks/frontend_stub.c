#define _GNU_SOURCE
/* Test stand-in for the in-cell HTTP frontend (block 1 regression only; the real frontend is block 5). It runs
 * inside the cell as uid_i under the agent's seccomp policy, before the agent, and verifies what the child
 * promises it (validation.md S-01, F-01): the row's proxy socket is reachable at the bind-mounted path, and the
 * loopback port the agent's HTTPS_PROXY names can be listened on. It writes the ready file only after both, so an
 * agent that starts sees a listening proxy. argv: <proxy socket path> <port> <ready file path>.
 * Host file reads (validation.md H-23): it stands in for the in-cell MCP server too, whose argv has the same tail
 * (<file socket path> <port> <ready file path>); the same checks then say the file port is reachable and the MCP port
 * listens before the agent starts. It waits in nanosleep, not pause: the deployment's workload policy has no pause.
 * Exit codes: 3 proxy socket not connectable, 4 cannot listen on the port, 5 extra fds, 6 bad argv, 7 ready file. */
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

int main(int argc,char **argv) {
    if(argc!=4)return 6;
    for(int fd=3;fd<64;++fd)if(fcntl(fd,F_GETFD)>=0)return 5;
    struct sockaddr_un a={.sun_family=AF_UNIX};
    if(strlen(argv[1])>=sizeof a.sun_path)return 6;
    strcpy(a.sun_path,argv[1]);
    int proxy=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0);
    if(proxy<0||connect(proxy,(struct sockaddr *)&a,sizeof a))return 3;
    struct sockaddr_in in={.sin_family=AF_INET,.sin_port=htons((unsigned short)atoi(argv[2]))};
    in.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    int listener=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0);
    if(listener<0||bind(listener,(struct sockaddr *)&in,sizeof in)||listen(listener,16))return 4;
    int ready=open(argv[3],O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0644);
    if(ready<0)return 7;
    close(ready);
    for(;;){struct timespec hour={3600,0};nanosleep(&hour,NULL);}
}
