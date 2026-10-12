#include <stdexcept>
// Apache-2.0. Calls the real DeviceRuntime entry; no parallel model coordinator.
#include "fixture_backend.h"
#include "../install_runtime.h"
#include <fcntl.h>
#include <iostream>
#include <unistd.h>
static std::string Q(const std::string&s){std::string o="\"";for(unsigned char c:s){if(c=='\"'||c=='\\'){o+='\\';o+=c;}else if(c=='\n')o+="\\n";else if(c=='\r')o+="\\r";else if(c<32)o+='?';else o+=c;}return o+"\"";}
int main(int argc,char**argv){
 try{
  if(argc!=4)throw std::runtime_error("usage: fixture-coordinator CASE_ROOT SIGNED_ZIP FAULT");
  ri3::fixture::Configure(argv[1],argv[3]);int fd=open(argv[2],O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
  if(fd<0)throw std::runtime_error("fixture source open");
  auto result=ri3::runtime::InstallHeldPackage(fd,{},{});close(fd);const auto&a=ri3::fixture::GetAudit();
  std::cout<<"{\"success\":"<<(result.success?"true":"false")<<",\"mutations_started\":"<<(result.mutations_started?"true":"false")<<",\"error\":"<<Q(result.error)
   <<",\"observations\":"<<a.observations<<",\"unmount_attempts\":"<<a.unmount_attempts<<",\"unmounts\":"<<a.unmounts<<",\"remove_attempts\":"<<a.remove_attempts<<",\"removals\":"<<a.removals
   <<",\"write_calls\":"<<a.write_calls<<",\"bytes_written\":"<<a.bytes_written<<",\"sync_calls\":"<<a.sync_calls<<",\"read_calls\":"<<a.read_calls
   <<",\"slot_set_attempts\":"<<a.slot_set_attempts<<",\"slot_get_attempts\":"<<a.slot_get_attempts<<",\"active_slot\":"<<a.active_slot<<",\"events\":[";
  for(size_t i=0;i<a.events.size();++i){if(i)std::cout<<",";std::cout<<Q(a.events[i]);}std::cout<<"]}\n";return 0;
 }catch(const std::exception&e){std::cerr<<e.what()<<"\n";return 2;}
}
