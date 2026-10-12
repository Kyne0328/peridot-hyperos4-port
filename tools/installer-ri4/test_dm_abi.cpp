// Exercises the actual production Init/Status against a simulated kernel ABI.
// No device access: ioctl is replaced at compile time; unused live code is dropped.
#include "../installer-ri3/native-updater/backend/storage_backend.h"
#include <libdm/dm.h>
#include <linux/dm-ioctl.h>
#include <sys/ioctl.h>
#include <sys/sysmacros.h>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <functional>
#undef DM_VERSION_MINOR
#define DM_VERSION_MINOR 48 // Simulate the Android NDK even on an older host.
static unsigned kernel_minor=47,calls=0;
static int injected_errno=0;
static std::function<void(dm_ioctl&)> edit;
static int MockIoctl(int fd,unsigned long command,void*data){
  if(fd!=123||command!=DM_DEV_STATUS)throw std::runtime_error("unexpected ioctl");
  ++calls;auto&io=*static_cast<dm_ioctl*>(data);
  bool incompatible=io.version[0]!=4||io.version[1]>kernel_minor;
  io.version[0]=4;io.version[1]=kernel_minor;io.version[2]=0;
  if(incompatible||injected_errno){errno=incompatible?EINVAL:injected_errno;return -1;}
  io.data_size=offsetof(dm_ioctl,data);io.open_count=0;io.target_count=1;
  io.flags=DM_ACTIVE_PRESENT_FLAG;io.dev=makedev(253,0);
  if(edit)edit(io);return 0;
}
#define ioctl MockIoctl
#include "../installer-ri3/native-updater/backend/libdm_adapter.cpp"
#undef ioctl
int main()try{
  using namespace ri3::backend;unsigned cases=0;
  auto need=[](bool v){if(!v)throw std::runtime_error("test failed");};
  auto reject=[&](const std::function<void(dm_ioctl&)>&f,const char*error){
    edit=f;bool failed=false;try{Status(123,"userdata");}catch(const std::runtime_error&e){failed=true;need(std::string(e.what()).find(error)!=std::string::npos);}need(failed);++cases;edit={};
  };
  for(auto minor:{47U,48U,0U}){kernel_minor=minor;auto io=Status(123,"userdata");need(io.version[1]==minor&&io.data_size==offsetof(dm_ioctl,data));++cases;}
  for(unsigned size=offsetof(dm_ioctl,data);size<=sizeof(dm_ioctl);++size){edit=[=](dm_ioctl&io){io.data_size=size;};Status(123,"userdata");++cases;}edit={};
  reject([](auto&io){io.data_size=offsetof(dm_ioctl,data)-1;},"dm_status_incomplete");
  reject([](auto&io){io.data_size=sizeof(dm_ioctl)+1;},"dm_status_incomplete");
  reject([](auto&io){io.open_count=-1;},"dm_status_incomplete");
  reject([](auto&io){io.target_count=0;},"dm_status_incomplete");
  reject([](auto&io){io.target_count=16385;},"dm_status_incomplete");
  for(unsigned flag:{0U,unsigned(DM_ACTIVE_PRESENT_FLAG|DM_BUFFER_FULL_FLAG),unsigned(DM_ACTIVE_PRESENT_FLAG|DM_INACTIVE_PRESENT_FLAG),unsigned(DM_ACTIVE_PRESENT_FLAG|DM_SUSPEND_FLAG)})reject([=](auto&io){io.flags=flag;},"dm_status_incomplete");
  reject([](auto&io){std::memset(io.name,'x',sizeof(io.name));},"dm_identity");
  reject([](auto&io){std::memset(io.uuid,'x',sizeof(io.uuid));},"dm_identity");
  reject([](auto&io){std::strcpy(io.name,"changed");},"dm_name_changed");
  for(int e:{EINVAL,ENXIO,EACCES}){injected_errno=e;reject({},("errno="+std::to_string(e)).c_str());}injected_errno=0;
  need(calls==cases);std::cout<<cases<<" actual DM ABI cases passed; no devices accessed\n";
}catch(const std::exception&e){std::cerr<<e.what()<<"\n";return 1;}
