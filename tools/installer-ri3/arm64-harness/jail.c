// RI3 regular-file test jail launcher. No mounts, device access, or host setting changes.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/landlock.h>
#include <linux/seccomp.h>
#include <sched.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#ifndef LANDLOCK_ACCESS_FS_IOCTL_DEV
#define LANDLOCK_ACCESS_FS_IOCTL_DEV (1ULL << 15)
#endif
#define DENY(n) BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,(n),0,1), BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM)
static void fail(const char* what){perror(what);_exit(125);}
static void restrict_syscalls(void) {
  const unsigned ns_flags=CLONE_NEWNS|CLONE_NEWCGROUP|CLONE_NEWUTS|CLONE_NEWIPC|CLONE_NEWUSER|CLONE_NEWPID|CLONE_NEWNET;
  struct sock_filter f[]={
    BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,arch)),
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,AUDIT_ARCH_X86_64,1,0),
    BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL_PROCESS),
    BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
    BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K,0x40000000U,0,1),
    BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL_PROCESS),
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_clone,0,6),
    BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[0])),
    BPF_JUMP(BPF_JMP|BPF_JSET|BPF_K,ns_flags,0,1),
    BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),
    BPF_JUMP(BPF_JMP|BPF_JSET|BPF_K,CLONE_THREAD,1,0),
    BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),
    BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
#ifdef SYS_clone3
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_clone3,0,1),
    BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|ENOSYS),
#endif
    DENY(SYS_fork),DENY(SYS_vfork),DENY(SYS_unshare),DENY(SYS_setns),
    DENY(SYS_chroot),DENY(SYS_pivot_root),DENY(SYS_mount),DENY(SYS_umount2),
    DENY(SYS_socket),DENY(SYS_socketpair),DENY(SYS_connect),DENY(SYS_bind),
    DENY(SYS_shmget),DENY(SYS_shmat),DENY(SYS_shmdt),DENY(SYS_shmctl),
    DENY(SYS_semget),DENY(SYS_semop),DENY(SYS_semtimedop),DENY(SYS_semctl),
    DENY(SYS_msgget),DENY(SYS_msgsnd),DENY(SYS_msgrcv),DENY(SYS_msgctl),
    DENY(SYS_mq_open),DENY(SYS_mq_unlink),DENY(SYS_mq_notify),
    DENY(SYS_mq_timedsend),DENY(SYS_mq_timedreceive),DENY(SYS_mq_getsetattr),
    DENY(SYS_syslog),
    DENY(SYS_listen),DENY(SYS_accept),DENY(SYS_accept4),DENY(SYS_sendto),
    DENY(SYS_sendmsg),DENY(SYS_sendmmsg),DENY(SYS_ioctl),
    DENY(SYS_ptrace),DENY(SYS_process_vm_readv),DENY(SYS_process_vm_writev),
    DENY(SYS_bpf),DENY(SYS_perf_event_open),DENY(SYS_open_by_handle_at),
    DENY(SYS_name_to_handle_at),DENY(SYS_keyctl),DENY(SYS_add_key),DENY(SYS_request_key),
    DENY(SYS_chmod),DENY(SYS_fchmod),DENY(SYS_fchmodat),
    DENY(SYS_chown),DENY(SYS_fchown),DENY(SYS_lchown),DENY(SYS_fchownat),
    DENY(SYS_utime),DENY(SYS_utimes),DENY(SYS_futimesat),DENY(SYS_utimensat),
    DENY(SYS_setxattr),DENY(SYS_lsetxattr),DENY(SYS_fsetxattr),
    DENY(SYS_removexattr),DENY(SYS_lremovexattr),DENY(SYS_fremovexattr),
    DENY(SYS_mknod),DENY(SYS_mknodat),DENY(SYS_setuid),DENY(SYS_setgid),
    DENY(SYS_setreuid),DENY(SYS_setregid),DENY(SYS_setresuid),DENY(SYS_setresgid),
    DENY(SYS_setfsuid),DENY(SYS_setfsgid),DENY(SYS_setgroups),
#ifdef SYS_pidfd_getfd
    DENY(SYS_pidfd_getfd),
#endif
#ifdef SYS_io_uring_setup
    DENY(SYS_io_uring_setup),
#endif
#ifdef SYS_fsopen
    DENY(SYS_fsopen),DENY(SYS_fsconfig),DENY(SYS_fsmount),DENY(SYS_fspick),
    DENY(SYS_open_tree),DENY(SYS_move_mount),
#endif
#ifdef SYS_mount_setattr
    DENY(SYS_mount_setattr),
#endif
#ifdef SYS_fchmodat2
    DENY(SYS_fchmodat2),
#endif
    BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)
  };
  struct sock_fprog p={.len=(unsigned short)(sizeof(f)/sizeof(f[0])),.filter=f};
  if(prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&p))fail("seccomp");
}
int main(int argc,char** argv){
  if(argc<3 || (strcmp(argv[2],"/probe") && strcmp(argv[2],"/qemu-aarch64-static"))){
    fputs("usage: jail <workspace-root> </probe|/qemu-aarch64-static> [args]\n",stderr);return 125;
  }
  if(geteuid()!=0){fputs("requires mapped namespace root, never sudo\n",stderr);return 125;}
  int abi=syscall(SYS_landlock_create_ruleset,NULL,0,LANDLOCK_CREATE_RULESET_VERSION);
  if(abi<5){fputs("Landlock ABI >=5 required\n",stderr);return 125;}
  int root=open(argv[1],O_PATH|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(root<0)fail("root");
  struct landlock_ruleset_attr a={.handled_access_fs=(1ULL<<16)-1};
  int rules=syscall(SYS_landlock_create_ruleset,&a,sizeof(a),0);if(rules<0)fail("Landlock create");
  struct landlock_path_beneath_attr rule={.allowed_access=LANDLOCK_ACCESS_FS_EXECUTE|LANDLOCK_ACCESS_FS_READ_FILE|LANDLOCK_ACCESS_FS_READ_DIR,.parent_fd=root};
  if(syscall(SYS_landlock_add_rule,rules,LANDLOCK_RULE_PATH_BENEATH,&rule,0))fail("Landlock add");
  if(fchdir(root)||chroot(".")||chdir("/"))fail("chroot");
  close(root);
  if(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0))fail("no_new_privs");
  if(syscall(SYS_landlock_restrict_self,rules,0))fail("Landlock enforce");
  close(rules);
  for(int cap=0;cap<64;cap++)if(prctl(PR_CAPBSET_DROP,cap,0,0,0)&&errno!=EINVAL)fail("cap bounding drop");
  if(prctl(PR_CAP_AMBIENT,PR_CAP_AMBIENT_CLEAR_ALL,0,0,0))fail("ambient drop");
  struct __user_cap_header_struct h={.version=_LINUX_CAPABILITY_VERSION_3,.pid=0};
  struct __user_cap_data_struct d[2]={{0},{0}};
  if(syscall(SYS_capset,&h,d))fail("capset");
  struct rlimit core={0,0},cpu={20,20};
  if(setrlimit(RLIMIT_CORE,&core)||setrlimit(RLIMIT_CPU,&cpu))fail("rlimit");
#ifdef SYS_close_range
  if(syscall(SYS_close_range,3U,~0U,0))fail("close inherited descriptors");
#else
#error close_range required
#endif
  if(clearenv() || setenv("LANG","C",1) || setenv("HOME","/",1) || setenv("TMPDIR","/tmp",1))fail("environment");
  restrict_syscalls();
  execv(argv[2],argv+2);fail("exec");
}
