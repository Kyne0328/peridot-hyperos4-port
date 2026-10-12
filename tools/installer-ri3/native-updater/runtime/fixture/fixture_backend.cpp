// Apache-2.0. Every I/O path below is a checked host regular file.
#include "fixture_backend.h"
#include <algorithm>
#include <cerrno>
#include <filesystem>
#include <fcntl.h>
#include <map>
#include <stdexcept>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>
namespace ri3::fixture {
namespace {
struct Context {
 std::string root,fault,source_id; Audit audit;
 bool mounted=true,parent_mapping=true,child_mapping=true,partial_done=false;
 std::map<std::string,ri3::backend::FileIdentity> identities;
 std::vector<ri3::backend::Physical> physical;
} ctx;
void Need(bool ok,const std::string&s){if(!ok)throw std::runtime_error("fixture:"+s);}
std::string TargetName(int fd){
 auto id=ri3::backend::InspectFd(fd);
 for(const auto& p:ctx.identities)if(p.second.SameObject(id))return p.first;
 throw std::runtime_error("fixture:unknown target descriptor");
}
std::string Id(const std::string&name){
 for(const auto&p:ctx.physical)if(p.partition==name)return p.id;
 throw std::runtime_error("fixture:missing physical "+name);
}
class Mapper final:public ri3::backend::DmAdapter {
 public:std::vector<ri3::backend::Mapping> List()override{
  std::vector<ri3::backend::Mapping> out;
  if(ctx.parent_mapping){ri3::backend::Mapping m;m.id="253:1";m.name="system_a";m.uuid="fixture-parent";m.kind=guard::Kind::Linear;m.capacity=4096;m.open_count=ctx.child_mapping?1:0;m.event=1;m.active=true;m.dependencies={Id("super")};m.segments={{0,4096,0,Id("super")}};out.push_back(m);}
  if(ctx.child_mapping){ri3::backend::Mapping m;m.id="253:2";m.name="fixture-system-child";m.uuid="fixture-child";m.kind=guard::Kind::Linear;m.capacity=4096;m.open_count=ctx.mounted?1:0;m.event=1;m.active=true;m.dependencies={"253:1"};m.segments={{0,4096,0,"253:1"}};out.push_back(m);}
  return out;
 }
 bool Remove(const std::string& name)override {
  ++ctx.audit.remove_attempts;ctx.audit.events.push_back("remove-attempt:"+name);
  if(ctx.fault=="removal")return false;
  if(name=="fixture-system-child"&&ctx.child_mapping&&!ctx.mounted)ctx.child_mapping=false;
  else if(name=="system_a"&&ctx.parent_mapping&&!ctx.child_mapping)ctx.parent_mapping=false;
  else return false;
  ++ctx.audit.removals;ctx.audit.events.push_back("removed:"+name);return true;
 }
};
class Unmount final:public ri3::backend::UnmountOps {
 public:bool NormalUnmount(const ri3::backend::MountRecord&r)override{
  ++ctx.audit.unmount_attempts;ctx.audit.events.push_back("unmount-attempt:"+r.path);
  if(ctx.fault=="unmount"||r.id!=42||r.device!="253:2"||!ctx.mounted)return false;
  ctx.mounted=false;++ctx.audit.unmounts;ctx.audit.events.push_back("unmounted:"+r.path);return true;
 }
};
}
void Configure(const std::string&root,const std::string&fault){
 ctx=Context{};ctx.root=std::filesystem::canonical(root).string();ctx.fault=fault;
 Need(ctx.root.find("installer-ri3-native/runtime-fixture/")!=std::string::npos,"root outside fixture work");
 struct stat st{};Need(stat(ctx.root.c_str(),&st)==0&&S_ISDIR(st.st_mode),"fixture root");
 ctx.source_id=ri3::backend::DeviceId(major(st.st_dev),minor(st.st_dev));
 std::vector<std::filesystem::path> files;
 for(const auto&e:std::filesystem::directory_iterator(ctx.root+"/targets"))files.push_back(e.path());
 std::sort(files.begin(),files.end());uint64_t index=0;
 for(const auto& p:files){
  int fd=open(p.c_str(),O_RDONLY|O_CLOEXEC|O_NOFOLLOW);Need(fd>=0,"target open");
  auto id=ri3::backend::InspectFd(fd);close(fd);Need(id.type==S_IFREG,"nonregular fixture");
  std::string name=p.filename().string();ctx.identities[name]=id;
  ri3::backend::Physical ph;ph.id="240:"+std::to_string(100+index);ph.partition=name;ph.disk="fixture-disk";ph.begin=index*65536;ph.bytes=id.capacity;ph.device_path=p.string();ctx.physical.push_back(ph);++index;
 }
 ri3::backend::Physical source;source.id=ctx.source_id;source.partition="fixture_source";source.disk="fixture-source";source.bytes=1ULL<<40;ctx.physical.push_back(source);
}
const Audit&GetAudit(){return ctx.audit;}
std::string Path(const std::string&p){
 Need(!ctx.root.empty(),"not configured");
 if(p=="/proc/sys/kernel/random/boot_id")return ctx.root+"/boot-id";
 if(p.rfind("/system/",0)==0||p=="/sbin/afterromflash.sh"){
  Need(p.find("..")==std::string::npos,"unsafe fixture path");
  return ctx.root+"/runtime"+p;
 }
 throw std::runtime_error("fixture:unrecognized platform path "+p);
}
std::string DeviceProduct(){return ctx.fault=="product"?"wrong-device":"peridot";}
void CheckParent(pid_t expected){Need(getppid()==expected&&expected>1&&ctx.fault!="parent","parent observation changed");}
namespace backend {
FileIdentity CheckTargetFd(int fd,const guard::Node&n){
 auto id=InspectFd(fd);auto it=ctx.identities.find(n.partition);
 Need(id.type==S_IFREG&&n.kind==guard::Kind::Partition&&n.identity_verified==guard::Truth::Yes&&it!=ctx.identities.end()&&it->second.SameObject(id)&&n.id==Id(n.partition)&&id.capacity==n.capacity,"file target identity or capacity");return id;
}
HeldReadTarget::HeldReadTarget(int fd,const guard::Node&n):original_(n),identity_(CheckTargetFd(fd,n)){
 Need((fcntl(fd,F_GETFL)&O_ACCMODE)==O_RDONLY,"target must be held read-only");fd_=fcntl(fd,F_DUPFD_CLOEXEC,3);Need(fd_>=0,"duplicate target");
}
HeldReadTarget::~HeldReadTarget(){if(fd_>=0)close(fd_);}
void HeldReadTarget::Bind(guard::Node&n)const{
 Need(identity_.SameObject(CheckTargetFd(fd_,n))&&n.id==original_.id&&n.partition==original_.partition&&n.extents.size()==original_.extents.size(),"held file target changed");
 for(size_t i=0;i<n.extents.size();++i){auto&a=n.extents[i];auto&b=original_.extents[i];Need(a.disk==b.disk&&a.begin==b.begin&&a.bytes==b.bytes,"held file extents changed");}
 n.read_handle_id="fixture-held-fd:"+std::to_string(fd_)+":"+n.id+":"+std::to_string(identity_.inode);n.held_identity_checked=guard::Truth::Yes;
}
ssize_t IoOps::Write(int fd,const void*p,size_t n,uint64_t off){
 TargetName(fd);++ctx.audit.write_calls;
 if(ctx.fault=="partial_write"){
  if(ctx.partial_done){errno=EIO;return -1;}ctx.partial_done=true;n=std::min<size_t>(n,37);
 }
 auto r=ri3::backend::IoOps::Write(fd,p,n,off);
 if(r>0){ctx.audit.bytes_written+=r;ctx.audit.events.push_back("write:"+TargetName(fd)+":"+std::to_string(off)+":"+std::to_string(r));}
 return r;
}
ssize_t IoOps::Read(int fd,void*p,size_t n,uint64_t off)const{
 TargetName(fd);++ctx.audit.read_calls;auto r=ri3::backend::IoOps::Read(fd,p,n,off);
 if(ctx.fault=="readback"&&r>0)static_cast<unsigned char*>(p)[0]^=1;
 return r;
}
int IoOps::Sync(int fd){
 auto name=TargetName(fd);++ctx.audit.sync_calls;ctx.audit.events.push_back("fsync:"+name);
 if(ctx.fault=="fsync"){errno=EIO;return -1;}
 return ri3::backend::IoOps::Sync(fd);
}
Observation CollectLinux(const std::string&,const std::string&,DmAdapter&dm,const std::string&){
 ++ctx.audit.observations;Observation o;o.physical=ctx.physical;o.mappings=dm.List();
 for(auto&p:o.physical)if(p.partition=="super"&&ctx.parent_mapping)p.holders={"253:1"};
 o.mounts.complete=ctx.fault!="inventory";o.mounts.namespace_scope={"fixture-current"};
 o.mounts.current.push_back({41,1,ctx.source_id,"/",ctx.root,"fixture"});
 o.mounts.devices.insert(ctx.source_id);
 if(ctx.mounted){o.mounts.devices.insert("253:2");o.mounts.current.push_back({42,1,"253:2","/","/system","ext4"});}
 return o;
}
std::unique_ptr<DmAdapter> NewLibDmAdapter(){return std::make_unique<Mapper>();}
std::unique_ptr<UnmountOps> NewNormalUnmountOps(){return std::make_unique<Unmount>();}
}
namespace snapshot {
MetadataResult MetadataLease::Read(const guard::Inventory&){
 MetadataResult r;r.state=State::None;r.readable=r.inspectable=r.exact_mount=r.clean_complete=true;r.encoding="fixture";r.mount_identity="fixture-metadata-held";
 if(ctx.fault=="metadata"){r.state=State::Unknown;r.readable=false;r.error="injected unreadable metadata";}
 return r;
}
HalResult QueryPinnedRecoveryHal(uint32_t){
 HalResult r;r.state=State::None;r.complete=r.pinned_contract=r.reaped=true;r.exit_code=0;r.stdout_text="none\n";
 if(ctx.fault=="hal"||(ctx.fault=="late_hal"&&ctx.audit.bytes_written)){r.state=State::Unknown;r.complete=false;r.error="injected incomplete HAL";}
 return r;
}
HalResult RunPinnedBootctl(BootctlCommand cmd,uint32_t){
 HalResult r;r.complete=r.pinned_contract=r.reaped=true;r.exit_code=0;
 if(cmd==BootctlCommand::SetActiveBootSlotA){++ctx.audit.slot_set_attempts;ctx.audit.events.push_back("slot-set-attempt:a");if(ctx.fault=="slot_set"){r.complete=false;r.exit_code=1;r.error="injected slot-set failure";}else ctx.audit.active_slot=0;}
 else if(cmd==BootctlCommand::GetActiveBootSlot){++ctx.audit.slot_get_attempts;ctx.audit.events.push_back("slot-get");r.stdout_text=ctx.fault=="slot_get"?"1\n":std::to_string(ctx.audit.active_slot)+"\n";}
 else return QueryPinnedRecoveryHal();
 return r;
}
}
}
