// SPDX-License-Identifier: Apache-2.0
#include "storage_backend.h"
#include <algorithm>
#include <fcntl.h>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>
namespace ri3::backend {
namespace {
[[noreturn]]void Fail(const char*s){throw std::runtime_error(s);}
bool Overlap(const guard::Extent&a,const guard::Extent&b){
 return a.disk==b.disk&&a.begin<b.begin+b.bytes&&b.begin<a.begin+a.bytes;
}
bool Inside(const guard::Extent&a,const std::vector<guard::Extent>&v){
 for(const auto&b:v)if(a.disk==b.disk&&a.begin>=b.begin&&a.begin+a.bytes<=b.begin+b.bytes)return true;return false;
}
bool SameTopology(const Observation&a,const Observation&b,const std::set<std::string>&may_close={}){
 if(a.physical.size()!=b.physical.size()||a.mappings.size()!=b.mappings.size()||a.excluded.size()!=b.excluded.size()||
    a.mounts.complete!=b.mounts.complete||a.mounts.namespace_scope!=b.mounts.namespace_scope||a.mounts.foreign_devices!=b.mounts.foreign_devices)return false;
 for(size_t i=0;i<a.physical.size();++i){
  const auto&x=a.physical[i];const auto&y=b.physical[i];
  if(x.id!=y.id||x.partition!=y.partition||x.disk!=y.disk||x.begin!=y.begin||x.bytes!=y.bytes||x.holders!=y.holders||x.device_path!=y.device_path)return false;
 }
 for(size_t i=0;i<a.mappings.size();++i){auto x=a.mappings[i],y=b.mappings[i];if(may_close.count(x.id)&&y.open_count<=x.open_count)x.open_count=y.open_count;if(!(x==y))return false;}
 for(size_t i=0;i<a.excluded.size();++i){auto x=a.excluded[i],y=b.excluded[i];if(x.id!=y.id||x.reason!=y.reason||x.fingerprint!=y.fingerprint)return false;}
 return true;
}
class NormalUnmountOps final:public UnmountOps {
 public:
  bool NormalUnmount(const MountRecord&m)override{
   // Close our inspection FD before normal unmount; retaining it can cause
   // EBUSY. Path-to-syscall atomicity relies on the documented workflow lease.
   int fd=open(m.path.c_str(),O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
   if(fd<0)return false;
   try{CheckMountFd(fd,m);}catch(...){close(fd);return false;}
   close(fd);
   return umount2(m.path.c_str(),0)==0; // NEVER MNT_FORCE or MNT_DETACH.
  }
};
}
uint64_t FdMountId(int fd,const std::string&proc){
 std::ifstream in(proc+"/self/fdinfo/"+std::to_string(fd));if(!in)Fail("fdinfo_unreadable");
 std::string line;uint64_t out=0;bool found=false;size_t total=0;
 while(std::getline(in,line)){
  total+=line.size();if(total>65536)Fail("fdinfo_limit");
  if(line.rfind("mnt_id:",0)!=0)continue;
  if(found)Fail("duplicate_fd_mount_id");found=true;
  std::istringstream fields(line.substr(7));std::string value,extra;
  if(!(fields>>value)||(fields>>extra)||value.empty()||value.find_first_not_of("0123456789")!=value.npos)Fail("fd_mount_id");
  out=std::stoull(value);
 }
 if(!in.eof()||!found||!out)Fail("fd_mount_id_missing");return out;
}
void CheckMountFd(int fd,const MountRecord&m){
 struct stat s{};
 if(fstat(fd,&s)||!S_ISDIR(s.st_mode)||DeviceId(major(s.st_dev),minor(s.st_dev))!=m.device||FdMountId(fd)!=m.id)Fail("mount_fd_identity");
}
std::unique_ptr<UnmountOps>NewNormalUnmountOps(){return std::make_unique<NormalUnmountOps>();}
std::vector<MountRecord> PlanTargetUnmounts(const Observation&o,const guard::Source&s){
 using guard::Kind;using guard::Truth;
 if(!o.mounts.complete||s.open_handle_id.empty()||s.readable!=Truth::Yes||s.content_verified!=Truth::Yes||
    s.dependencies_complete!=Truth::Yes||s.extents_complete!=Truth::Yes||s.dependencies.empty()||s.extents.empty())Fail("unmount_source_or_mount_evidence");
 auto inv=BuildInventory(o);std::map<std::string,const guard::Node*>nodes;std::map<std::string,const Mapping*>maps;
 const guard::Node*super=nullptr;std::vector<guard::Extent>targets;
 const std::set<std::string>writes={"super","boot_a","dtbo_a","init_boot_a","vendor_boot_a","vbmeta_system_a","vbmeta_a"};
 for(const auto&n:inv.nodes){nodes[n.id]=&n;if(n.partition=="super")super=&n;if(writes.count(n.partition))targets.insert(targets.end(),n.extents.begin(),n.extents.end());}
 if(!super)Fail("unmount_super_missing");for(const auto&m:o.mappings)maps[m.id]=&m;
 for(const auto&dep:s.dependencies)if(!nodes.count(dep))Fail("unmount_source_unknown");
 for(const auto&e:s.extents){
  if(e.disk.empty()||!e.bytes||e.begin>UINT64_MAX-e.bytes)Fail("unmount_source_extent");
  bool backed=false;for(const auto&dep:s.dependencies)backed=backed||Inside(e,nodes.at(dep)->extents);
  if(!backed)Fail("unmount_source_unbacked");
  for(const auto&t:targets)if(Overlap(e,t))Fail("unmount_source_target_overlap");
 }
 const std::map<std::string,std::string>allow={{"/system_root","system"},{"/system","system"},{"/system_ext","system_ext"},{"/product","product"},{"/vendor","vendor"},{"/vendor_dlkm","vendor_dlkm"},{"/system_dlkm","system_dlkm"},{"/odm","odm"},{"/mi_ext","mi_ext"}};
 std::map<uint64_t,MountRecord>byid;std::set<uint64_t>selected;std::set<std::string>paths;std::vector<MountRecord>plan;
 for(const auto&m:o.mounts.current)if(!byid.emplace(m.id,m).second)Fail("unmount_duplicate_mount_id");
 for(const auto&m:o.mounts.current){
  auto it=nodes.find(m.device);if(it==nodes.end())continue;
  bool target=false;for(const auto&e:it->second->extents)for(const auto&t:targets)target=target||Overlap(e,t);
  if(!target)continue;
  auto role=allow.find(m.path);
  if(role==allow.end()||(m.filesystem!="ext4"&&m.filesystem!="erofs")||m.root!="/"||!paths.insert(m.path).second)Fail("unmount_nonallowlisted_target_mount");
  bool logical=false;std::set<std::string>seen;
  std::function<void(const std::string&)>check=[&](const std::string&id){
   if(!seen.insert(id).second)return;
   const auto&n=*nodes.at(id);
   for(const auto&e:n.extents)if(!Inside(e,super->extents))Fail("unmount_backing_outside_super");
   if(n.kind==Kind::Partition){if(n.partition!="super")Fail("unmount_non_super_leaf");return;}
   if(n.kind!=Kind::Linear&&(n.kind!=Kind::Verity||n.read_only!=Truth::Yes))Fail("unmount_unrecognized_mapping");
   if(n.kind==Kind::Verity)for(const auto&other:inv.nodes)if(std::find(other.dependencies.begin(),other.dependencies.end(),id)!=other.dependencies.end())Fail("unmount_verity_not_leaf");
   auto mi=maps.find(id);if(mi==maps.end())Fail("unmount_mapping_identity");
   if(n.kind==Kind::Linear&&(mi->second->name==role->second+"_a"||mi->second->name==role->second+"_b"))logical=true;
   for(const auto&d:n.dependencies)check(d);
  };
  check(m.device);if(!logical)Fail("unmount_wrong_logical_partition");
  for(const auto&d:s.dependencies)if(seen.count(d))Fail("unmount_source_dependency");
  selected.insert(m.id);plan.push_back(m);
 }
 for(const auto&dev:o.mounts.devices){
  auto n=nodes.find(dev);if(n==nodes.end())continue;
  bool target=false;for(const auto&e:n->second->extents)for(const auto&t:targets)target=target||Overlap(e,t);
  if(target&&(o.mounts.foreign_devices.count(dev)||std::none_of(plan.begin(),plan.end(),[&](auto&m){return m.device==dev;})))Fail("target_mount_outside_current_namespace");
 }
 auto depth=[&](uint64_t id){
  std::set<uint64_t>seen;size_t d=0;
  while(byid.count(id)){if(!seen.insert(id).second)Fail("mount_parent_cycle");const auto&parent=byid.at(id);++d;
   if(parent.parent==id&&parent.path=="/"&&parent.root=="/")break;
   id=parent.parent;}return d;
 };
 for(const auto&m:o.mounts.current){
  uint64_t id=m.parent;std::set<uint64_t>seen;
  while(byid.count(id)){
   if(!seen.insert(id).second)Fail("mount_parent_cycle");
   if(selected.count(id)&&!selected.count(m.id))Fail("unmount_non_target_descendant");
   const auto&parent=byid.at(id);if(parent.parent==id&&parent.path=="/"&&parent.root=="/")break;
   id=byid.at(id).parent;
  }
 }
 std::sort(plan.begin(),plan.end(),[&](auto&a,auto&b){auto x=depth(a.id),y=depth(b.id);return x>y||(x==y&&a.id<b.id);});
 return plan;
}
UnmountReceipt PrepareUnmountsChecked(const guard::Binding&binding,const Observation&expected,
 const guard::Source&source,UnmountOps&ops,TopologyLease&lease,const std::function<Observation()>&refresh){
 UnmountReceipt receipt;receipt.binding=binding;receipt.source_handle=source.open_handle_id;
 try{
  if(binding.session.empty()||binding.boot.empty()||binding.package.empty()||!binding.generation)Fail("unmount_binding");
  Observation current=refresh();
  if(!SameTopology(expected,current)||expected.mounts.current!=current.mounts.current||expected.mounts.devices!=current.mounts.devices)Fail("unmount_stale_observation");
  auto plan=PlanTargetUnmounts(current,source);
  for(const auto&m:plan){
   auto before=refresh();
   if(!SameTopology(current,before)||current.mounts.current!=before.mounts.current||current.mounts.devices!=before.mounts.devices||
      !lease.Recheck(before,"before_unmount"))Fail("unmount_recheck");
   if(!ops.NormalUnmount(m))Fail("normal_unmount_busy_or_error");
   receipt.removed_mount_ids.push_back(m.id);
   auto after=refresh();auto remaining=before.mounts.current;
   remaining.erase(std::remove(remaining.begin(),remaining.end(),m),remaining.end());
   std::set<std::string>may_close;
   std::function<void(const std::string&)>ancestors=[&](const std::string&id){
    if(!may_close.insert(id).second)return;
    for(const auto&n:before.mappings)if(n.id==id)for(const auto&d:n.dependencies)ancestors(d);
   };ancestors(m.device);
   if(!SameTopology(before,after,may_close)||remaining!=after.mounts.current||!lease.Recheck(after,"after_unmount"))Fail("unmount_postcheck");
   (void)PlanTargetUnmounts(after,source);current=std::move(after);
  }
  if(!PlanTargetUnmounts(current,source).empty())Fail("target_mounts_remain");
  receipt.status=guard::Status::Known;
 }catch(const std::exception&e){receipt.status=guard::Status::Error;receipt.error=e.what();}
 return receipt;
}
} // namespace ri3::backend
