// SPDX-License-Identifier: Apache-2.0
#include "snapshot_collect.h"
#include <mbedtls/sha256.h>
#include <array>
#include <algorithm>
#include <cerrno>
#include <chrono>
#include <climits>
#include <cstring>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdexcept>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>
namespace ri3::snapshot {
namespace {
void Need(bool b,const char* text){if(!b)throw std::runtime_error(text);}
struct Fd{
 int n=-1;explicit Fd(int v=-1):n(v){}~Fd(){if(n>=0)close(n);}
 Fd(const Fd&)=delete;Fd& operator=(const Fd&)=delete;
 Fd(Fd&& o) noexcept:n(o.n){o.n=-1;}
 Fd& operator=(Fd&& o) noexcept {if(this!=&o){if(n>=0)close(n);n=o.n;o.n=-1;}return *this;}
};
struct stat Stat(int fd){struct stat s{};Need(fstat(fd,&s)==0,"HAL artifact stat failed");return s;}
bool Same(const struct stat& a,const struct stat& b){
 return a.st_dev==b.st_dev&&a.st_ino==b.st_ino&&a.st_size==b.st_size&&a.st_mode==b.st_mode&&
 a.st_mtim.tv_sec==b.st_mtim.tv_sec&&a.st_mtim.tv_nsec==b.st_mtim.tv_nsec&&
 a.st_ctim.tv_sec==b.st_ctim.tv_sec&&a.st_ctim.tv_nsec==b.st_ctim.tv_nsec;
}
Fd OpenArtifact(const char* path){
 Fd dir(open("/",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC));
 Need(dir.n>=0,"recovery root unreadable");std::string p(path);size_t start=0;
 while(true){
  auto slash=p.find('/',start);std::string part=p.substr(start,slash==std::string::npos?std::string::npos:slash-start);
  Need(!part.empty()&&part!="."&&part!="..","invalid fixed artifact path");
  int flags=O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK;if(slash!=std::string::npos)flags|=O_DIRECTORY;
  Fd next(openat(dir.n,part.c_str(),flags));Need(next.n>=0,"pinned recovery artifact open failed");
  if(slash==std::string::npos)return next;dir=std::move(next);start=slash+1;
 }
}
std::string Hash(int fd,uint64_t bytes){
 mbedtls_sha256_context c;mbedtls_sha256_init(&c);std::array<unsigned char,32> out{};
 int code=mbedtls_sha256_starts(&c,0);std::array<unsigned char,8192> b{};uint64_t off=0;
 while(!code&&off<bytes){
  size_t count=static_cast<size_t>(std::min<uint64_t>(b.size(),bytes-off));
  ssize_t n=pread(fd,b.data(),count,static_cast<off_t>(off));if(n<0&&errno==EINTR)continue;
  if(n<=0){code=-1;break;}code=mbedtls_sha256_update(&c,b.data(),static_cast<size_t>(n));off+=static_cast<uint64_t>(n);
 }
 if(!code)code=mbedtls_sha256_finish(&c,out.data());mbedtls_sha256_free(&c);Need(code==0&&off==bytes,"pinned recovery artifact read/hash failed");
 std::string s;const char hex[]="0123456789abcdef";for(auto x:out){s+=hex[x>>4];s+=hex[x&15];}return s;
}
struct Pin{const char* path;uint64_t bytes;const char* hash;};
constexpr Pin pins[]={
 {"system/bin/bootctl",51784,"be618f8c9434c66c3a73fd309395bd1456d114afb048d1dd8e1a8c86b7b6a863"},
 {"system/lib64/libboot_control_client.so",68840,"82cbc64bccf910918aa77653b26833ce36823d32dd960c1f12950545d1d05be6"},
 {"vendor/bin/hw/android.hardware.boot-service.qti.recovery",33856,"07193642ec3c0c6fad309ffea5a38c98c2120ea2c3dccfabacf77d492dc5d6af"},
 {"vendor/lib64/libboot_control_qti.so",171992,"ed25f4c6d3690f2cf5dd2275a8366d51d083fbb9b064bd3b95948a92e159c9de"}
};
void CheckPin(int fd,const Pin& pin,const struct stat& original){
 auto s=Stat(fd);Need(Same(s,original)&&S_ISREG(s.st_mode)&&s.st_size>=0&&static_cast<uint64_t>(s.st_size)==pin.bytes,"pinned recovery artifact identity mismatch");
 Need(Hash(fd,pin.bytes)==pin.hash&&Same(s,Stat(fd)),"pinned recovery artifact hash mismatch");
 auto named=OpenArtifact(pin.path);Need(Same(s,Stat(named.n)),"pinned recovery artifact pathname changed");
}
using Clock=std::chrono::steady_clock;
HalResult Run(int executable,const std::string& argument,uint32_t timeout,int response=0,const char* extra=nullptr){
 HalResult r;Need(timeout>=10&&timeout<=5000,"HAL timeout outside bounds");
 Need(executable>=3&&S_ISREG(Stat(executable).st_mode),"query executable is not a held regular file");
 int p[2],q[2],input[2];Need(pipe2(p,O_CLOEXEC)==0,"stdout pipe failed");Fd pr(p[0]),pw(p[1]);
 Need(pipe2(q,O_CLOEXEC)==0,"stderr pipe failed");Fd qr(q[0]),qw(q[1]);
 Need(pipe2(input,O_CLOEXEC)==0,"stdin pipe failed");Fd ir(input[0]),iw(input[1]);
 Need(fcntl(pr.n,F_SETFL,O_NONBLOCK)==0&&fcntl(qr.n,F_SETFL,O_NONBLOCK)==0,"pipe nonblocking failed");
 struct rlimit lim{};Need(getrlimit(RLIMIT_NOFILE,&lim)==0&&lim.rlim_cur<=1048576,"descriptor bound unavailable");
 std::array<char*,4> argv={const_cast<char*>("bootctl"),const_cast<char*>(argument.c_str()),const_cast<char*>(extra),nullptr};
 char path[]="PATH=/system/bin:/vendor/bin";char lang[]="LANG=C";char home[]="HOME=/";
 std::array<char*,4> env={path,lang,home,nullptr};
 auto deadline=Clock::now()+std::chrono::milliseconds(timeout);pid_t pid=fork();Need(pid>=0,"query fork failed");
 if(pid==0){
  if(setpgid(0,0)<0||dup2(ir.n,0)<0||dup2(pw.n,1)<0||dup2(qw.n,2)<0)_exit(125);
  // Only the held ELF descriptor and stdio survive until exec. close_range
  // is optional; the finite inherited rlimit bounds the fallback.
  bool closed=false;
#ifdef __NR_close_range
  long a=executable==3?0:syscall(__NR_close_range,3U,static_cast<unsigned>(executable-1),0U);
  long b=syscall(__NR_close_range,static_cast<unsigned>(executable+1),UINT_MAX,0U);closed=(a==0&&b==0);
#endif
  if(!closed)for(rlim_t f=3;f<lim.rlim_cur;++f)if(static_cast<int>(f)!=executable)close(static_cast<int>(f));
  fexecve(executable,argv.data(),env.data());_exit(126);
 }
 // This group contains only our child. setpgid races are harmless because the
 // child performs the same setup before exec; fallback kill(pid) is always used.
 setpgid(pid,pid);pw=Fd();qw=Fd();ir=Fd();iw=Fd();
 bool oe=false,ee=false,failed=false;int status=0;
 auto drain=[&](int fd,std::string& out,size_t cap,bool& eof){
  char b[256];
  while(!eof){
   ssize_t n=read(fd,b,sizeof(b));if(n>0){if(out.size()+static_cast<size_t>(n)>cap){failed=true;r.error="query output limit";return;}out.append(b,static_cast<size_t>(n));}
   else if(n==0){eof=true;return;}
   else if(errno==EINTR)continue;
   else if(errno==EAGAIN||errno==EWOULDBLOCK)return;
   else{failed=true;r.error="query pipe read failed";return;}
  }
 };
 while(true){
  drain(pr.n,r.stdout_text,64,oe);drain(qr.n,r.stderr_text,1024,ee);
  if(!r.reaped){pid_t got=waitpid(pid,&status,WNOHANG);if(got==pid)r.reaped=true;else if(got<0&&errno!=EINTR){failed=true;r.error="query wait failed";}}
  if(r.reaped&&oe&&ee)break;
  if(failed||Clock::now()>=deadline){if(!failed){r.timed_out=true;r.error="HAL query timed out";}break;}
  pollfd fds[2]={{pr.n,POLLIN|POLLHUP,0},{qr.n,POLLIN|POLLHUP,0}};
  int n=poll(fds,2,10);if(n<0&&errno!=EINTR){failed=true;r.error="query poll failed";}
 }
 if(failed||r.timed_out||!r.reaped){
  kill(-pid,SIGKILL);kill(pid,SIGKILL);
  auto reap_deadline=Clock::now()+std::chrono::milliseconds(250);
  while(!r.reaped&&Clock::now()<reap_deadline){
   pid_t got=waitpid(pid,&status,WNOHANG);if(got==pid){r.reaped=true;break;}
   if(got<0&&errno!=EINTR)break;poll(nullptr,0,5);
  }
  r.state=State::Error;return r;
 }
 if(WIFEXITED(status))r.exit_code=WEXITSTATUS(status);
 if(r.exit_code!=0||!r.stderr_text.empty()){r.state=State::Error;r.error="HAL query failed or emitted stderr";return r;}
 if(response!=0){
  r.complete=response==1?r.stdout_text=="0\n":response==2&&r.stdout_text.empty();
  if(!r.complete)r.error="unexpected active-slot command response";
  return r;
 }
 if(r.stdout_text=="none\n"){r.state=State::None;r.complete=true;return r;}
 if(r.stdout_text=="snapshotted\n"||r.stdout_text=="merging\n"||r.stdout_text=="cancelled\n"){r.state=State::Active;r.complete=true;return r;}
 r.state=State::Error;r.error="unrecognized HAL query response";return r;
}
} // namespace
HalResult RunPinnedBootctl(BootctlCommand command,uint32_t timeout){
 try{
  const char* argument=nullptr;const char* extra=nullptr;int response=0;
  switch(command){
   case BootctlCommand::SnapshotMergeStatus:argument="get-snapshot-merge-status";break;
   case BootctlCommand::GetActiveBootSlot:argument="get-active-boot-slot";response=1;break;
   case BootctlCommand::SetActiveBootSlotA:argument="set-active-boot-slot";extra="0";response=2;break;
   default:throw std::runtime_error("invalid pinned command");
  }
  std::vector<Fd> fds;std::vector<struct stat> identity;
  for(const auto& pin:pins){fds.push_back(OpenArtifact(pin.path));identity.push_back(Stat(fds.back().n));CheckPin(fds.back().n,pin,identity.back());}
  auto r=Run(fds[0].n,argument,timeout,response,extra);
  for(size_t i=0;i<fds.size();++i)CheckPin(fds[i].n,pins[i],identity[i]);
  r.pinned_contract=true;return r;
 }catch(const std::exception& e){HalResult r;r.state=State::Error;r.error=e.what();return r;}
}
HalResult QueryPinnedRecoveryHal(uint32_t timeout){return RunPinnedBootctl(BootctlCommand::SnapshotMergeStatus,timeout);}
#ifdef RI3_SNAPSHOT_TESTING
HalResult RunFixtureQuery(int fd,const std::string& mode,uint32_t timeout){
 try{return Run(fd,mode,timeout);}
 catch(const std::exception& e){HalResult r;r.state=State::Error;r.error=e.what();return r;}
}
HalResult RunFixtureCommand(int fd,const std::string& mode,BootctlCommand command,uint32_t timeout){
 try{
  int response=command==BootctlCommand::GetActiveBootSlot?1:command==BootctlCommand::SetActiveBootSlotA?2:0;
  return Run(fd,mode,timeout,response);
 }catch(const std::exception& e){HalResult r;r.state=State::Error;r.error=e.what();return r;}
}
#endif
} // namespace ri3::snapshot
