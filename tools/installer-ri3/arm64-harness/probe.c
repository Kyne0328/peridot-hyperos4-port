// Harmless isolation checks. The outside sentinel is an ordinary workspace file.
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
static int failures=0,checks=0;
static void check(const char* name,int ok){checks++;printf("%s: %s\n",ok?"PASS":"FAIL",name);if(!ok)failures++;}
static int regular_tree(const char* path){
  DIR* d=opendir(path);if(!d)return 0;int ok=1;struct dirent* e;
  while((e=readdir(d))){
    if(!strcmp(e->d_name,".")||!strcmp(e->d_name,".."))continue;
    char p[4096];if(snprintf(p,sizeof(p),"%s/%s",path,e->d_name)>=(int)sizeof(p)){ok=0;break;}
    struct stat st;if(lstat(p,&st)){ok=0;break;}
    if(S_ISDIR(st.st_mode)){if(!regular_tree(p))ok=0;}
    else if(!S_ISREG(st.st_mode) || st.st_mode&06000)ok=0;
  }
  closedir(d);return ok;
}
int main(int argc,char** argv){
  if(argc!=2)return 2;
  check("no_new_privs",prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)==1);
  check("seccomp filter",prctl(PR_GET_SECCOMP,0,0,0,0)==2);
  struct __user_cap_header_struct h={.version=_LINUX_CAPABILITY_VERSION_3,.pid=0};
  struct __user_cap_data_struct d[2]={{0},{0}};
  check("all capabilities dropped",syscall(SYS_capget,&h,d)==0&&!d[0].effective&&!d[0].permitted&&!d[0].inheritable&&!d[1].effective&&!d[1].permitted&&!d[1].inheritable);
  check("namespace PID 1",getpid()==1);
  int fds=1;for(int i=3;i<256;i++){errno=0;if(fcntl(i,F_GETFD)!=-1||errno!=EBADF)fds=0;}
  check("only stdio descriptors inherited",fds);
  int pipes=1;for(int i=0;i<3;i++){struct stat st;if(fstat(i,&st)||!S_ISFIFO(st.st_mode))pipes=0;}
  check("stdio are pipes",pipes);
  check("regular files and directories only",regular_tree("/"));
  DIR* root=opendir("/");int count=0,known=1;struct dirent* e;
  if(!root)known=0;else {while((e=readdir(root))){if(!strcmp(e->d_name,".")||!strcmp(e->d_name,".."))continue;count++;if(strcmp(e->d_name,"probe")&&strcmp(e->d_name,"qemu-aarch64-static")&&strcmp(e->d_name,"prep-update-binary")&&strcmp(e->d_name,"fixtures"))known=0;}closedir(root);}
  check("root contains only expected harness content",known&&count==4);
  int f=open("/fixtures/sentinel.txt",O_RDONLY|O_CLOEXEC);char text[16]={0};ssize_t n=f>=0?read(f,text,sizeof(text)):0;if(f>=0)close(f);
  check("fixture readable",n==12&&!memcmp(text,"RI3 fixture\n",12));
  errno=0;f=open(argv[1],O_RDONLY|O_CLOEXEC);int outside_errno=errno;if(f>=0)close(f);
  check("outside workspace sentinel inaccessible",f<0&&outside_errno==ENOENT);
  errno=0;f=open("/fixtures/sentinel.txt",O_WRONLY|O_CLOEXEC);int write_errno=errno;if(f>=0)close(f);
  check("existing regular-file writes denied",f<0&&write_errno==EACCES);
  errno=0;f=open("/fixtures/new.txt",O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);int create_errno=errno;if(f>=0)close(f);
  check("new file creation denied",f<0&&create_errno==EACCES);
  f=open("/fixtures/sentinel.txt",O_RDONLY|O_CLOEXEC);errno=0;int rc=fchmod(f,0600),mode_errno=errno;if(f>=0)close(f);
  check("metadata writes denied",rc<0&&mode_errno==EPERM);
  errno=0;f=socket(AF_INET,SOCK_STREAM,0);int socket_errno=errno;if(f>=0)close(f);
  check("network socket creation denied",f<0&&socket_errno==EPERM);
  errno=0;rc=unshare(CLONE_NEWUSER);int unshare_errno=errno;
  check("further namespaces denied",rc<0&&unshare_errno==EPERM);
  errno=0;rc=chroot("/");int chroot_errno=errno;
  check("further chroot denied",rc<0&&chroot_errno==EPERM);
  errno=0;rc=syscall(SYS_shmget,0,4096,01000|0600);int ipc_errno=errno;
  check("System V IPC denied",rc<0&&ipc_errno==EPERM);
  errno=0;rc=syscall(SYS_mq_open,"ri3-probe",O_CREAT|O_RDWR,0600,NULL);int mq_errno=errno;
  check("POSIX message queues denied",rc<0&&mq_errno==EPERM);
  errno=0;rc=syscall(SYS_syslog,10,NULL,0);int log_errno=errno;
  check("kernel syslog interface denied",rc<0&&log_errno==EPERM);
  printf("checks=%d failures=%d\n",checks,failures);
  return failures?1:0;
}
