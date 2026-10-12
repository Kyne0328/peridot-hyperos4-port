#include "snapshot_collect.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <fcntl.h>
#include <unistd.h>
#include <sys/file.h>
#include <signal.h>
#include <poll.h>
using namespace ri3::snapshot;namespace fs=std::filesystem;
int checks=0;void C(bool b,const std::string& n){if(!b)throw std::runtime_error(n);std::cout<<"PASS\t"<<n<<"\n";++checks;}
void Put(const fs::path& p,const std::string& b){std::ofstream f(p,std::ios::binary);f.write(b.data(),b.size());if(!f)throw std::runtime_error("write fixture");}
MetadataResult Read(const fs::path& p,int fault=0){int fd=open(p.c_str(),O_RDONLY|O_DIRECTORY|O_CLOEXEC);if(fd<0)throw std::runtime_error("open fixture");auto r=InspectFixtureDirectory(fd,fault);close(fd);return r;}
int main(int argc,char** argv){
 if(argc==2&&std::string(argv[1]).rfind("child-",0)==0){
  std::string s=argv[1];if(s=="child-empty")return 0;if(s=="child-slot-a"){write(1,"0\n",2);return 0;}if(s=="child-slot-b"){write(1,"1\n",2);return 0;}if(s=="child-timeout"){poll(nullptr,0,2000);return 0;}
  if(s=="child-large"){std::string b(200,'x');write(1,b.data(),b.size());return 0;}
  if(s=="child-stderr")write(2,"error\n",6);
  std::string b=s=="child-active"?"merging\n":s=="child-unknown"?"unknown\n":s=="child-truncated"?"none":s=="child-extra"?"none\n\n":"none\n";
  write(1,b.data(),b.size());if(s=="child-signal")raise(SIGTERM);return s=="child-fail"?1:0;
 }
 try{
  if(argc!=3)throw std::runtime_error("root and own executable required");fs::path root=argv[1];fs::create_directories(root);int seq=0;
  auto New=[&](){auto p=root/std::to_string(seq++);fs::create_directory(p);return p;};
  auto Good=[&](const fs::path& p,const std::string& n){auto r=Read(p);C(r.state==State::None&&r.readable&&r.inspectable&&r.clean_complete&&!r.exact_mount,n);};
  auto Bad=[&](const fs::path& p,const std::string& n){auto r=Read(p);C(r.state!=State::None&&!r.clean_complete&&!r.exact_mount,n);};
  auto p=New();Good(p,"absent ota fixture is never live authority");
  p=New();fs::create_directory(p/"ota");Good(p,"empty ota");
  p=New();fs::create_directories(p/"ota/snapshots");Good(p,"empty snapshots");
  for(const auto& s:std::vector<std::string>{"","none",std::string("\x08\x00",2)}){
   p=New();fs::create_directories(p/"ota/snapshots");Put(p/"ota/state",s);Good(p,"clean encoding bytes "+std::to_string(s.size()));
  }
  int i=0;for(const auto& s:std::vector<std::string>{"none\n","NONE","garbage","initiated","unverified","merging","merge-completed","merge-needs-reboot","merge-failed","cancelled",std::string("\x08\x01",2),std::string("\x08",1),std::string("\x08\x80\x00",3),std::string("\x08\x00\x08\x00",4),std::string("\x10\x00",2),std::string("\x08\x00\x52\x00",4),std::string(4097,'x')}){
   p=New();fs::create_directory(p/"ota");Put(p/"ota/state",s);Bad(p,"bad state "+std::to_string(i++));
  }
  for(auto name:{"snapshot-boot","rollback-indicator","allow-forward-merge","old-partition-metadata","merge_state","unknown","state.tmp"}){
   p=New();fs::create_directory(p/"ota");Put(p/"ota"/name,"");Bad(p,std::string("artifact ")+name);
  }
  p=New();fs::create_directories(p/"ota/snapshots");Put(p/"ota/snapshots/system_a","");Bad(p,"nonempty snapshots");
  p=New();fs::create_directories(p/"ota/state");Bad(p,"state directory");
  p=New();fs::create_directory(p/"ota");Put(p/"ota/snapshots","");Bad(p,"snapshots file");
  p=New();fs::create_directory(p/"target");fs::create_directory_symlink("target",p/"ota");Bad(p,"ota symlink");
  p=New();fs::create_directory(p/"ota");Put(p/"target","none");fs::create_symlink("../target",p/"ota/state");Bad(p,"state symlink");
  p=New();fs::create_directory(p/"ota");fs::create_directory(p/"target");fs::create_directory_symlink("../target",p/"ota/snapshots");Bad(p,"snapshots symlink");
  p=New();fs::create_directory(p/"ota");Put(p/"ota/state","none");C(!Read(p,1).clean_complete,"injected readdir error");C(!Read(p,2).clean_complete,"injected read error");
  int fd=open((p/"ota").c_str(),O_RDONLY|O_DIRECTORY|O_CLOEXEC);if(fd<0||flock(fd,LOCK_EX|LOCK_NB))throw std::runtime_error("fixture lock");C(!Read(p).clean_complete,"cooperating lock contention");close(fd);
  std::string good="18 1 8:7 / /metadata rw,nosuid,nodev - f2fs /dev/block/sda7 rw\n";C(ParseExactMetadataMount(good).mount_id==18,"exact f2fs mount parser");
  i=0;for(const auto& s:std::vector<std::string>{good+good,"18 1 8:7 / /metadata rw - ext4 /dev/block/sda7 rw\n","18 1 8:7 /ota /metadata rw - f2fs /dev/block/sda7 rw\n","18 1 8:7 / /data rw - f2fs /dev/block/sda7 rw\n",good+"19 18 8:8 / /metadata/ota rw - f2fs /dev/block/sda8 rw\n",good.substr(0,good.size()-1),"18 1 8:7 / /metadata rw - f2fs\n","18 1 8:7 / /meta\\777data rw - f2fs /dev/block/sda7 rw\n"}){
   bool bad=false;try{ParseExactMetadataMount(s);}catch(...){bad=true;}C(bad,"mount rejection "+std::to_string(i++));
  }
  fd=open(argv[2],O_RDONLY|O_NOFOLLOW|O_CLOEXEC);if(fd<0)throw std::runtime_error("own executable open");
  auto h=RunFixtureQuery(fd,"child-none",500);C(h.state==State::None&&h.complete&&h.reaped&&!h.pinned_contract,"own helper exact none");
  h=RunFixtureQuery(fd,"child-active",500);C(h.state==State::Active&&h.complete&&!h.pinned_contract,"active HAL");
  for(auto mode:{"child-stderr","child-truncated","child-extra","child-unknown","child-fail","child-signal","child-large"}){
   h=RunFixtureQuery(fd,mode,500);C(h.state!=State::None&&!h.complete&&h.reaped&&!h.pinned_contract,std::string("query rejection ")+mode);
  }
  h=RunFixtureQuery(fd,"child-timeout",30);C(h.timed_out&&h.reaped&&!h.complete,"timeout kills/reaps own helper");h=RunFixtureQuery(fd,"child-none",0);C(!h.complete&&h.state==State::Error,"invalid timeout");h=RunFixtureCommand(fd,"child-slot-a",BootctlCommand::GetActiveBootSlot,500);C(h.complete&&!h.pinned_contract&&h.state==State::Unknown,"own helper confirms exact slot A");
  h=RunFixtureCommand(fd,"child-slot-b",BootctlCommand::GetActiveBootSlot,500);C(!h.complete&&!h.pinned_contract,"slot B rejected");
  h=RunFixtureCommand(fd,"child-empty",BootctlCommand::SetActiveBootSlotA,500);C(h.complete&&!h.pinned_contract&&h.state==State::Unknown,"own helper empty success protocol");
  h=RunFixtureCommand(fd,"child-none",BootctlCommand::SetActiveBootSlotA,500);C(!h.complete&&!h.pinned_contract,"slot command output rejected");close(fd);
  std::cout<<"TOTAL\t"<<checks<<"\n";return 0;
 }catch(const std::exception& e){std::cerr<<"FAIL "<<e.what()<<"\n";return 1;}
}
