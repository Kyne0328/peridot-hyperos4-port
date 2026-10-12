// SPDX-License-Identifier: Apache-2.0
// Compiled integration only. Never instantiated by default updater or tests.
#include "storage_backend.h"
#include "verity_table.h"
#include <libdm/dm.h>
#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <fcntl.h>
#include <linux/dm-ioctl.h>
#include <sstream>
#include <stdexcept>
#include <sys/ioctl.h>
#include <sys/sysmacros.h>
#include <unistd.h>
namespace ri3::backend {
namespace {
using android::dm::DeviceMapper;
[[noreturn]]void Fail(const char*s){throw std::runtime_error(s);}
[[noreturn]]void IoFail(const char*operation,const std::string&name,const dm_ioctl*io=nullptr){
  const int error=errno;
  std::string detail=std::string(operation)+" ["+name+"]: errno="+std::to_string(error)+" ("+std::strerror(error)+")";
  if(io)detail+="; kernel DM ABI="+std::to_string(io->version[0])+"."+std::to_string(io->version[1])+"."+std::to_string(io->version[2]);
  throw std::runtime_error(detail);
}
uint64_t Number(const std::string&s){if(s.empty()||s.size()>20||s.find_first_not_of("0123456789")!=s.npos)Fail("dm_integer");return std::stoull(s);}
uint64_t Bytes(uint64_t n){if(n>UINT64_MAX/512)Fail("dm_sector_overflow");return n*512;}
std::string Dev(const std::string&s){auto p=s.find(':');if(p==s.npos||s.find(':',p+1)!=s.npos)Fail("dm_dev_id");return DeviceId(Number(s.substr(0,p)),Number(s.substr(p+1)));}
void Init(dm_ioctl&io,const std::string&name,uint32_t size){
  if(name.empty()||name.size()>=DM_NAME_LEN||name.find('\0')!=name.npos)Fail("dm_name");
  // Match pinned AOSP libdm's backwards-compatible request, not the NDK's
  // newest header ABI (4.48), which Linux 6.1 (4.47) rejects with EINVAL.
  std::memset(&io,0,sizeof(io));io.version[0]=DM_VERSION0;io.version[1]=DM_VERSION1;io.version[2]=DM_VERSION2;
  io.data_size=size;io.data_start=sizeof(io);std::memcpy(io.name,name.c_str(),name.size()+1);
}
class Control {
 public:
  Control(){fd=open("/dev/device-mapper",O_RDWR|O_CLOEXEC|O_NOFOLLOW);if(fd<0)IoFail("dm_control_open","control");}
  ~Control(){if(fd>=0)close(fd);}
  int fd=-1;
};
dm_ioctl Status(int fd,const std::string&name){
  dm_ioctl io;Init(io,name,sizeof(io));if(ioctl(fd,DM_DEV_STATUS,&io))IoFail("dm_status",name,&io);
  // Header-only ioctls return offsetof(data), excluding the flexible payload
  // and trailing struct padding. Accept that bounded kernel header span.
  if(io.data_size<offsetof(dm_ioctl,data)||io.data_size>sizeof(io)||io.open_count<0||io.target_count==0||io.target_count>16384||
    !(io.flags&DM_ACTIVE_PRESENT_FLAG)||(io.flags&(DM_BUFFER_FULL_FLAG|DM_INACTIVE_PRESENT_FLAG|DM_SUSPEND_FLAG)))Fail("dm_status_incomplete");
  if(strnlen(io.name,DM_NAME_LEN)==DM_NAME_LEN||strnlen(io.uuid,DM_UUID_LEN)==DM_UUID_LEN)Fail("dm_identity");
  if(name!=io.name)Fail("dm_name_changed");return io;
}
bool Same(const dm_ioctl&a,const dm_ioctl&b){
  return a.dev==b.dev&&a.event_nr==b.event_nr&&a.open_count==b.open_count&&a.target_count==b.target_count&&a.flags==b.flags&&
    std::strcmp(a.name,b.name)==0&&std::strcmp(a.uuid,b.uuid)==0;
}
std::vector<std::string> Dependencies(int fd,const std::string&name){
  std::vector<char>b(1U<<20);auto*io=reinterpret_cast<dm_ioctl*>(b.data());Init(*io,name,b.size());
  if(ioctl(fd,DM_TABLE_DEPS,io))IoFail("dm_deps",name,io);
  if(io->flags&DM_BUFFER_FULL_FLAG||io->data_size>b.size()||io->data_start<sizeof(*io)||
    io->data_start>io->data_size||io->data_size-io->data_start<sizeof(dm_target_deps))Fail("dm_deps_frame");
  auto*d=reinterpret_cast<dm_target_deps*>(b.data()+io->data_start);
  if(!d->count||d->count>(io->data_size-io->data_start-sizeof(*d))/sizeof(uint64_t))Fail("dm_deps_count");
  std::vector<std::string>v;for(uint32_t n=0;n<d->count;++n)v.push_back(DeviceId(major(d->dev[n]),minor(d->dev[n])));
  std::sort(v.begin(),v.end());if(std::adjacent_find(v.begin(),v.end())!=v.end())Fail("dm_duplicate_dep");return v;
}
std::vector<std::pair<std::string,std::pair<uint64_t,uint64_t>>> Types(int fd,const std::string&name,const dm_ioctl&expected){
  // Status, NOT TABLE mode: never request crypt/default-key key parameters.
  std::vector<char>b(1U<<20);auto*io=reinterpret_cast<dm_ioctl*>(b.data());Init(*io,name,b.size());
  if(ioctl(fd,DM_TABLE_STATUS,io))IoFail("dm_table_status",name,io);
  if(io->flags&DM_BUFFER_FULL_FLAG||io->data_size>b.size()||io->data_start<sizeof(*io)||
    io->target_count!=expected.target_count||io->data_start>io->data_size)Fail("dm_table_status_frame");
  std::vector<std::pair<std::string,std::pair<uint64_t,uint64_t>>>out;
  uint64_t cursor=io->data_start,end=0;
  for(uint32_t i=0;i<io->target_count;++i){
    if(cursor>io->data_size||io->data_size-cursor<sizeof(dm_target_spec))Fail("dm_target_frame");
    auto*s=reinterpret_cast<dm_target_spec*>(b.data()+cursor);
    auto len=strnlen(s->target_type,sizeof(s->target_type));if(!len||len==sizeof(s->target_type))Fail("dm_target_type");
    uint64_t begin=Bytes(s->sector_start),size=Bytes(s->length);
    if(begin!=end||!size||end>UINT64_MAX-size)Fail("dm_target_ranges");end+=size;
    out.push_back({std::string(s->target_type,len),{begin,size}});
    // Kernel status-mode next is relative to data_start, unlike load buffers.
    if(i+1<io->target_count){
      uint64_t next=uint64_t(io->data_start)+s->next;
      if(next<=cursor||next>io->data_size||(next&7))Fail("dm_target_next");cursor=next;
    }
  }
  return out;
}
std::vector<std::string> SysDeps(const std::string&id){
  std::vector<std::string>out;std::filesystem::path p="/sys/dev/block";p/=id;p/="slaves";
  for(const auto&e:std::filesystem::directory_iterator(p)){
    std::ifstream in(e.path()/"dev");std::string s,extra;if(!(in>>s)||(in>>extra))Fail("dm_sysfs_dep");out.push_back(Dev(s));
  }
  std::sort(out.begin(),out.end());return out;
}
uint64_t Capacity(const std::string&id){
  std::ifstream in("/sys/dev/block/"+id+"/size");std::string s,extra;
  if(!(in>>s)||(in>>extra))Fail("dm_sysfs_capacity");return Bytes(Number(s));
}
class LibDmAdapter final:public DmAdapter {
 public:
  std::vector<Mapping> List() override {
    Control c;auto&dm=DeviceMapper::Instance();std::vector<DeviceMapper::DmBlockDevice>list;
    if(!dm.GetAvailableDevices(&list))Fail("libdm_list");
    std::vector<Mapping>out;
    for(const auto&item:list){
      auto first=Status(c.fd,item.name());Mapping m;m.id=DeviceId(item.Major(),item.Minor());m.name=item.name();m.uuid=first.uuid;
      if(m.id!=DeviceId(major(first.dev),minor(first.dev)))Fail("dm_list_status_identity");
      m.event=first.event_nr;m.open_count=first.open_count;m.active=true;m.capacity=Capacity(m.id);m.read_only=(first.flags&DM_READONLY_FLAG)!=0;
      m.dependencies=Dependencies(c.fd,m.name);if(m.dependencies!=SysDeps(m.id))Fail("dm_dependency_mismatch");
      auto types=Types(c.fd,m.name,first);bool linear=true,verity=true,crypto=true,snapshot=false;
      for(const auto&t:types){
        linear&=t.first=="linear";verity&=t.first=="verity";crypto&=t.first=="crypt"||t.first=="default-key";
        snapshot|=t.first=="snapshot"||t.first=="snapshot-merge"||t.first=="snapshot-origin";
        if(t.first!="linear"&&t.first!="crypt"&&t.first!="default-key"&&t.first!="verity"&&
          t.first!="snapshot"&&t.first!="snapshot-merge"&&t.first!="snapshot-origin")Fail("unclassified_dm_target");
      }
      uint64_t total=0;for(const auto&t:types){if(total>UINT64_MAX-t.second.second)Fail("dm_capacity_overflow");total+=t.second.second;}
      if(total!=m.capacity)Fail("dm_table_capacity");
      m.kind=linear?guard::Kind::Linear:(verity?guard::Kind::Verity:(crypto?guard::Kind::Crypto:(snapshot?guard::Kind::Snapshot:guard::Kind::Other)));
      if(linear||verity){
        // Supported pinned AOSP API; request only after all-linear/all-verity status.
        // Held topology authority is still mandatory before any mutation.
        std::vector<android::dm::IDeviceMapper::TargetInfo>table;
        struct WipeTable { std::vector<android::dm::IDeviceMapper::TargetInfo>& v;
          ~WipeTable(){for(auto&t:v){volatile char*p=t.data.empty()?nullptr:&t.data[0];for(size_t j=0;j<t.data.size();++j)p[j]=0;}}
        } wipe{table};
        if(!dm.GetTableInfo(m.name,&table)||table.size()!=types.size())Fail("libdm_linear_table");
        if(verity){
          if(!m.read_only||table.size()!=1||DeviceMapper::GetTargetType(table[0].spec)!="verity"||
             table[0].spec.sector_start!=0||Bytes(table[0].spec.length)!=m.capacity)Fail("verity_target_changed_or_not_readonly");
          auto proof=ParseVerity(table[0].data,m.capacity);
          if(proof.dependencies!=m.dependencies)Fail("verity_kernel_dependency_mismatch");
          std::map<std::string,uint64_t>caps;for(const auto&d:m.dependencies)caps[d]=Capacity(d);
          CheckVerityBounds(proof,caps);m.verity_parameters=proof.canonical;
        }
        for(size_t i=0;linear&&i<table.size();++i){
          const auto&t=table[i];
          if(DeviceMapper::GetTargetType(t.spec)!="linear"||Bytes(t.spec.sector_start)!=types[i].second.first||Bytes(t.spec.length)!=types[i].second.second)Fail("linear_table_changed");
          std::istringstream in(t.data);std::string dev,offset,extra;
          if(!(in>>dev>>offset)||(in>>extra))Fail("linear_parameters");
          m.segments.push_back({types[i].second.first,types[i].second.second,Bytes(Number(offset)),Dev(dev)});
        }
      }
      // Nonlinear extents are conservative union of all backing dependencies.
      // No crypt keys or raw table strings enter Mapping, logs or receipts.
      auto last=Status(c.fd,m.name);
      if(!Same(first,last)||m.dependencies!=Dependencies(c.fd,m.name)||m.dependencies!=SysDeps(m.id)||m.capacity!=Capacity(m.id))Fail("dm_observation_race");
      out.push_back(std::move(m));
    }
    std::sort(out.begin(),out.end(),[](auto&a,auto&b){return a.id<b.id;});return out;
  }
  bool Remove(const std::string&name) override {
    if(name.empty()||name.size()>=DM_NAME_LEN||name.find('\0')!=name.npos)return false;
    // Exact API: immediate DM_DEV_REMOVE. No deferred deletion or state edits.
    return DeviceMapper::Instance().DeleteDevice(name);
  }
};
}
std::unique_ptr<DmAdapter> NewLibDmAdapter(){return std::make_unique<LibDmAdapter>();}
} // namespace ri3::backend
