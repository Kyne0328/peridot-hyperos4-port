// SPDX-License-Identifier: Apache-2.0
#include "storage_backend.h"
#include "verity_table.h"
#include "observation_window.h"
#include <algorithm>
#include <cerrno>
#include <filesystem>
#include <fstream>
#include <fcntl.h>
#include <functional>
#include <limits>
#include <linux/major.h>
#include <map>
#include <sstream>
#include <stdexcept>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>
namespace ri3::backend {
namespace {
using guard::Extent;using guard::Kind;using guard::Truth;
[[noreturn]] void Fail(const std::string&s){throw std::runtime_error(s);}
uint64_t Add(uint64_t a,uint64_t b){if(a>UINT64_MAX-b)Fail("extent_overflow");return a+b;}
uint64_t Number(const std::string&s){
  if(s.empty()||s.size()>20||s.find_first_not_of("0123456789")!=std::string::npos)Fail("invalid_unsigned_integer");
  size_t used=0;uint64_t n=std::stoull(s,&used);if(used!=s.size())Fail("invalid_unsigned_integer");return n;
}
uint64_t Sectors(const std::string&s){uint64_t n=Number(s);if(n>UINT64_MAX/512)Fail("sector_overflow");return n*512;}
std::string Trim(std::string s){auto e=s.find_last_not_of(" \t\r\n");if(e==s.npos)return {};s.resize(e+1);auto b=s.find_first_not_of(" \t\r\n");return s.substr(b);}
std::string Text(const std::filesystem::path&p,size_t max=1U<<20){
  std::ifstream in(p,std::ios::binary);if(!in)Fail("read_metadata_failed");
  std::string s;char b[4096];
  while(in){in.read(b,sizeof(b));auto n=in.gcount();if(n<0||s.size()+size_t(n)>max)Fail("metadata_limit");s.append(b,size_t(n));}
  if(!in.eof())Fail("metadata_read_error");return Trim(s);
}
std::vector<std::string> Words(const std::string&s){std::istringstream i(s);std::vector<std::string>v;std::string w;while(i>>w)v.push_back(w);return v;}
bool BlockDriver(const std::string&proc,unsigned number,const std::string&driver){
  std::istringstream in(Text(std::filesystem::path(proc)/"devices",65536));std::string line;bool block=false,matched=false;
  while(std::getline(in,line)){
    if(line=="Block devices:"){block=true;continue;}if(!block)continue;
    auto fields=Words(line);if(fields.empty())continue;if(fields.size()!=2)Fail("block_driver_registry");
    if(Number(fields[0])==number){if(matched||fields[1]!=driver)return false;matched=true;}
  }return matched;
}
bool ExitedWithoutMountNamespace(const std::filesystem::path&task,const std::string&pid){
  // A zombie has released its filesystem/files state. Prove that state with
  // matching PID/start-time observations, empty mountinfo/fds and no namespace.
  // Inaccessible living tasks and process churn still leave scope incomplete.
  try{
    auto identity=[&](){auto stat=Text(task/"stat",4096);auto end=stat.rfind(')');
      if(stat.rfind(pid+" (",0)!=0||end==stat.npos)Fail("task_stat");auto fields=Words(stat.substr(end+1));
      if(fields.size()<20||fields[0]!="Z")Fail("task_not_exited");return Number(fields[19]);};
    const auto before=identity();
    try{(void)std::filesystem::read_symlink(task/"ns/mnt");return false;}
    catch(const std::filesystem::filesystem_error&e){if(e.code().value()!=ENOENT&&e.code().value()!=ESRCH)return false;}
    int fd=open((task/"mountinfo").c_str(),O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    if(fd<0){if(errno!=EINVAL&&errno!=ENOENT&&errno!=ESRCH)return false;}
    else{char byte;ssize_t n;do{n=read(fd,&byte,1);}while(n<0&&errno==EINTR);const int error=errno;close(fd);
      // proc_mounts_open returns EINVAL when an exited task has no fs state.
      if(n>0||(n<0&&error!=EINVAL&&error!=ENOENT&&error!=ESRCH))return false;}
    if(!std::filesystem::is_empty(task/"fd"))return false;
    return before==identity();
  }catch(...){return false;}
}
std::string ValidDev(const std::string&s){auto p=s.find(':');if(p==s.npos||s.find(':',p+1)!=s.npos)Fail("invalid_device_id");auto a=Number(s.substr(0,p)),b=Number(s.substr(p+1));if(a>UINT32_MAX||b>UINT32_MAX)Fail("device_id_overflow");return DeviceId(a,b);}
std::vector<Extent> Slice(const std::vector<Extent>&v,uint64_t begin,uint64_t bytes){
  std::vector<Extent>out;uint64_t pos=0,end=Add(begin,bytes);
  for(const auto&e:v){uint64_t next=Add(pos,e.bytes);if(begin<next&&end>pos){
    uint64_t a=std::max(pos,begin),b=std::min(next,end);out.push_back({e.disk,Add(e.begin,a-pos),b-a});}pos=next;}
  if(!bytes||end>pos)Fail("mapping_backing_range");return out;
}
bool Overlap(const Extent&a,const Extent&b){return a.disk==b.disk&&a.begin<Add(b.begin,b.bytes)&&b.begin<Add(a.begin,a.bytes);}
bool Subset(const Extent&a,const std::vector<Extent>&es){for(const auto&e:es)if(a.disk==e.disk&&a.begin>=e.begin&&Add(a.begin,a.bytes)<=Add(e.begin,e.bytes))return true;return false;}
bool SamePhysical(const Physical&a,const Physical&b){return a.id==b.id&&a.partition==b.partition&&a.disk==b.disk&&a.begin==b.begin&&a.bytes==b.bytes&&a.holders==b.holders&&a.device_path==b.device_path;}
bool SameObservation(const Observation&a,const Observation&b,const std::string&omit={}){
  // Excluded entries are re-proven by every fresh collection to be non-backing,
  // unmounted and absent from mapping dependencies. Recovery may create/remove
  // such inert loop/zram/ramdisk nodes between reads without changing storage topology.
  if(a.physical.size()!=b.physical.size()||a.mounts.complete!=b.mounts.complete||a.mounts.devices!=b.mounts.devices||a.mounts.foreign_devices!=b.mounts.foreign_devices||a.mounts.namespace_scope!=b.mounts.namespace_scope||a.mounts.current!=b.mounts.current)return false;
  for(size_t i=0;i<a.physical.size();++i){auto p=a.physical[i];if(!omit.empty())p.holders.erase(std::remove(p.holders.begin(),p.holders.end(),omit),p.holders.end());if(!SamePhysical(p,b.physical[i]))return false;}
  std::vector<Mapping>x,y;for(const auto&m:a.mappings)if(m.id!=omit)x.push_back(m);for(const auto&m:b.mappings)y.push_back(m);
  std::set<std::string>ancestors;
  std::function<void(const std::string&)>walk=[&](const std::string&id){
    for(const auto&m:a.mappings)if(m.id==id)for(const auto&d:m.dependencies)if(ancestors.insert(d).second)walk(d);
  };
  if(!omit.empty())walk(omit);
  if(x.size()!=y.size())return false;
  for(size_t i=0;i<x.size();++i){
    if(ancestors.count(x[i].id)&&y[i].open_count<=x[i].open_count)x[i].open_count=y[i].open_count;
    if(!(x[i]==y[i]))return false;
  }return true;
}
}
bool MountRecord::operator==(const MountRecord&b)const{
 return id==b.id&&parent==b.parent&&device==b.device&&root==b.root&&path==b.path&&filesystem==b.filesystem;
}
std::vector<MountRecord> ParseMountRecords(const std::string&s){
 if(s.empty()||s.size()>16U*1024*1024)Fail("mountinfo_empty_or_limit");
 auto decode=[](const std::string&v){
  std::string out;
  for(size_t j=0;j<v.size();++j){
   if(v[j]!='\\'){out+=v[j];continue;}
   if(j+3>=v.size())Fail("mountinfo_escape");auto oct=v.substr(j+1,3);
   if(oct=="040")out+=' ';else if(oct=="011")out+='\t';else if(oct=="012")out+='\n';else if(oct=="134")out+='\\';else Fail("mountinfo_escape");j+=3;
  }return out;
 };
 std::istringstream in(s);std::string line;std::vector<MountRecord>out;std::set<uint64_t>ids;
 while(std::getline(in,line)){
  auto w=Words(line);if(w.size()<10)Fail("mountinfo_fields");
  auto sep=std::find(w.begin()+6,w.end(),"-");
  if(sep==w.end()||w.end()-sep!=4)Fail("mountinfo_separator");
  MountRecord m;m.id=Number(w[0]);m.parent=Number(w[1]);m.device=ValidDev(w[2]);
  m.root=decode(w[3]);m.path=decode(w[4]);m.filesystem=*(sep+1);
  if(!m.id||!ids.insert(m.id).second)Fail("mountinfo_duplicate_id");
  if(m.root.empty()||m.root[0]!='/'||m.path.empty()||m.path[0]!='/')Fail("mountinfo_paths");
  out.push_back(std::move(m));
 }
 std::sort(out.begin(),out.end(),[](auto&a,auto&b){return a.id<b.id;});return out;
}
std::set<std::string> ParseMountInfo(const std::string&s){
 std::set<std::string>out;for(const auto&m:ParseMountRecords(s))out.insert(m.device);return out;
}
guard::Inventory BuildInventory(const Observation&o){
  guard::Inventory inv;std::map<std::string,guard::Node>nodes;std::map<std::string,Mapping>maps;std::map<std::string,bool>exact;std::set<std::string>names;
  std::set<std::string>excluded;
  for(const auto&e:o.excluded){ValidDev(e.id);if(!excluded.insert(e.id).second||e.fingerprint.empty()||
    (e.reason!="unconfigured_zero_loop"&&e.reason!="memory_only_zram"&&e.reason!="memory_only_ramdisk"))Fail("unrecognized_exclusion");}
  for(const auto&p:o.physical){
    ValidDev(p.id);if(excluded.count(p.id)||p.partition.empty()||p.disk.empty()||!p.bytes||!names.insert(p.partition).second)Fail("physical_identity");
    Add(p.begin,p.bytes);guard::Node n;n.id=p.id;n.partition=p.partition;n.kind=Kind::Partition;n.capacity=p.bytes;
    n.extents={{p.disk,p.begin,p.bytes}};n.identity_verified=n.table_complete=n.dependencies_complete=n.extents_complete=Truth::Yes;
    n.mounted=o.mounts.complete?(o.mounts.devices.count(p.id)?Truth::Yes:Truth::No):Truth::Unknown;
    // No portable physical-device open counter exists. Never substitute zero.
    if(!nodes.emplace(p.id,n).second)Fail("duplicate_device");exact[p.id]=true;
  }
  for(const auto&m:o.mappings){
    ValidDev(m.id);if(excluded.count(m.id)||m.name.empty()||m.capacity==0||!m.active||m.inactive||m.suspended||
      (m.kind!=Kind::Linear&&m.kind!=Kind::Verity&&m.kind!=Kind::Crypto&&m.kind!=Kind::Snapshot&&m.kind!=Kind::Other))Fail("mapping_unknown_state_or_kind");
    if(nodes.count(m.id)||!maps.emplace(m.id,m).second)Fail("duplicate_mapping");
  }
  std::map<std::string,int>color;
  std::function<void(const std::string&)>visit=[&](const std::string&id){
    if(nodes.count(id))return;if(color[id]==1)Fail("mapping_cycle");
    auto it=maps.find(id);if(it==maps.end())Fail("unknown_mapping_dependency");
    color[id]=1;const auto&m=it->second;std::set<std::string>deps(m.dependencies.begin(),m.dependencies.end()),actual;
    if(deps.empty()||deps.size()!=m.dependencies.size())Fail("invalid_mapping_dependencies");
    guard::Node n;n.id=m.id;n.kind=m.kind;n.capacity=m.capacity;n.open_count=m.open_count;n.dependencies=m.dependencies;n.read_only=m.read_only?Truth::Yes:Truth::No;
    uint64_t end=0;bool exact_mapping=m.kind==Kind::Linear;
    if(m.kind!=Kind::Linear){
      if(!m.segments.empty())Fail("nonlinear_segments_forbidden");
      for(const auto&d:deps){visit(d);const auto&es=nodes.at(d).extents;n.extents.insert(n.extents.end(),es.begin(),es.end());}
      uint64_t total=0;for(const auto&e:n.extents)total=Add(total,e.bytes);
      if(total<m.capacity)Fail("nonlinear_backing_too_small");
      if(m.kind==Kind::Verity){
        if(!m.read_only)Fail("verity_not_readonly");
        auto proof=ParseVerity(m.verity_parameters,m.capacity);
        if(proof.dependencies!=m.dependencies)Fail("verity_dependency_mismatch");
        std::map<std::string,uint64_t>caps;for(const auto&d:deps)caps[d]=nodes.at(d).capacity;
        CheckVerityBounds(proof,caps);
      }
      actual=deps;end=m.capacity;
    }
    for(const auto&s:m.segments){
      if(s.logical!=end||!s.bytes)Fail("mapping_gap_overlap_or_empty");
      end=Add(end,s.bytes);actual.insert(s.dependency);visit(s.dependency);
      const auto&parent=nodes.at(s.dependency);
      if(s.backing_offset>parent.capacity||s.bytes>parent.capacity-s.backing_offset)Fail("mapping_parent_capacity");
      auto ext=exact.at(s.dependency)?Slice(parent.extents,s.backing_offset,s.bytes):parent.extents;
      exact_mapping=exact_mapping&&exact.at(s.dependency);
      n.extents.insert(n.extents.end(),ext.begin(),ext.end());
    }
    if(end!=m.capacity||actual!=deps)Fail("mapping_incomplete_or_sysfs_mismatch");
    if(!exact_mapping){
      // A nonlinear backing superset has no logical ordering. Preserve its full
      // union through linear children; slicing it could discard a dependency.
      std::sort(n.extents.begin(),n.extents.end(),[](const auto&a,const auto&b){return a.disk<b.disk||(a.disk==b.disk&&a.begin<b.begin);});
      std::vector<Extent>merged;
      for(const auto&e:n.extents){if(!merged.empty()&&merged.back().disk==e.disk&&e.begin<=Add(merged.back().begin,merged.back().bytes)){
        auto&last=merged.back();last.bytes=std::max(Add(last.begin,last.bytes),Add(e.begin,e.bytes))-last.begin;
      }else merged.push_back(e);}
      n.extents=std::move(merged);
    }
    for(size_t i=0;i<n.extents.size();++i)for(size_t j=0;j<i;++j)if(Overlap(n.extents[i],n.extents[j]))Fail("mapping_alias_extents");
    n.identity_verified=n.table_complete=n.dependencies_complete=n.extents_complete=Truth::Yes;
    n.mounted=o.mounts.complete?(o.mounts.devices.count(id)?Truth::Yes:Truth::No):Truth::Unknown;
    nodes.emplace(id,n);exact[id]=exact_mapping;color[id]=2;
  };
  for(const auto&m:maps)visit(m.first);
  for(const auto&p:o.physical){
    std::vector<std::string>expected;
    for(const auto&m:o.mappings)if(std::find(m.dependencies.begin(),m.dependencies.end(),p.id)!=m.dependencies.end())expected.push_back(m.id);
    std::sort(expected.begin(),expected.end());auto actual=p.holders;std::sort(actual.begin(),actual.end());
    if(expected!=actual)Fail("physical_holder_graph_mismatch");
  }
  for(auto&n:nodes)inv.nodes.push_back(std::move(n.second));
  inv.partitions_complete=inv.mappings_complete=Truth::Yes;
  inv.mounts_complete=o.mounts.complete?Truth::Yes:Truth::Unknown;return inv;
}
Observation CollectLinux(const std::string&sys,const std::string&proc,DmAdapter&dm,const std::string&dev_root){
  namespace fs=std::filesystem;
  auto once=[&](){
    Observation o;o.mappings=dm.List();std::set<std::string>dmids;
    for(const auto&m:o.mappings)if(!dmids.insert(m.id).second)Fail("duplicate_dm_id");
    const fs::path root=fs::canonical(sys),classes=root/"class/block";
    std::string boot=Text(fs::path(proc)/"sys/kernel/random/boot_id",256);
    if(boot.size()!=36||boot.find_first_not_of("0123456789abcdef-")!=boot.npos)Fail("boot_id");
    std::map<std::string,std::string>device_paths;size_t dev_count=0;
    const auto dev_base=fs::canonical(dev_root);
    for(const auto&e:fs::directory_iterator(dev_base)){
      if(++dev_count>16384)Fail("device_node_catalog_limit");
      struct stat st{};if(lstat(e.path().c_str(),&st))Fail("device_node_stat");
      if(!S_ISBLK(st.st_mode))continue;
      auto id=DeviceId(major(st.st_rdev),minor(st.st_rdev));auto path=e.path().string();
      auto it=device_paths.find(id);if(it==device_paths.end()||path<it->second)device_paths[id]=path;
    }
    size_t count=0;
    for(const auto&e:fs::directory_iterator(classes)){
      if(++count>4096)Fail("sysfs_device_limit");
      auto p=fs::canonical(e.path());auto rel=p.lexically_relative(root);
      if(rel.empty()||*rel.begin()=="..")Fail("sysfs_escape");
      std::string id=ValidDev(Text(p/"dev",64));
      bool isdm=fs::is_directory(p/"dm");
      if(isdm){if(!dmids.erase(id))Fail("unlisted_dm");continue;}
      if(rel.generic_string().find("devices/virtual/")!=std::string::npos){
        std::string name=p.filename().string();uint64_t bytes=Sectors(Text(p/"size",64));
        bool empty_holders=fs::is_empty(p/"holders"),empty_slaves=fs::is_empty(p/"slaves");
        auto numbered=[&](const std::string&prefix){return name.rfind(prefix,0)==0&&name.size()>prefix.size()&&name.substr(prefix.size()).find_first_not_of("0123456789")==std::string::npos;};
        if(numbered("loop")&&bytes==0&&!fs::exists(p/"loop")&&empty_holders&&empty_slaves){
          o.excluded.push_back({id,"unconfigured_zero_loop",boot+":"+rel.generic_string()+":0:no-backing"});continue;
        }
        if(numbered("zram")&&Text(p/"backing_dev",256)=="none"&&empty_holders&&empty_slaves&&Number(Text(p/"disksize",64))==bytes){
          o.excluded.push_back({id,"memory_only_zram",boot+":"+rel.generic_string()+":"+std::to_string(bytes)+":backing=none"});continue;
        }
        if(numbered("ram")&&id.rfind(std::to_string(RAMDISK_MAJOR)+":",0)==0&&
           rel.generic_string()=="devices/virtual/block/"+name&&empty_holders&&empty_slaves&&
           !fs::exists(p/"loop")&&!fs::exists(p/"partition")&&BlockDriver(proc,RAMDISK_MAJOR,"ramdisk")){
          o.excluded.push_back({id,"memory_only_ramdisk",boot+":"+rel.generic_string()+":"+std::to_string(bytes)+":major=1:driver=ramdisk:no-backing"});continue;
        }
        Fail("unmodeled_or_backed_virtual_block_device: "+name+" dev="+id+" bytes="+std::to_string(bytes)+" path="+rel.generic_string());
      }
      bool part=fs::exists(p/"partition");auto disk=part?p.parent_path():p;
      std::string diskdev=ValidDev(Text(disk/"dev",64));
      auto diskrel=disk.lexically_relative(root);
      uint64_t bytes=Sectors(Text(p/"size",64)),begin=part?Sectors(Text(p/"start",64)):0;
      if(!bytes)Fail("empty_physical_device");
      if(Add(begin,bytes)>Sectors(Text(disk/"size",64)))Fail("partition_outside_disk");
      std::string name;
      if(part){
        const auto number=Number(Text(p/"partition",64));
        std::istringstream in(Text(p/"uevent"));std::string line;bool named=false;
        std::map<std::string,std::string> fields;
        while(std::getline(in,line)){
          auto equal=line.find('=');if(equal==line.npos)continue;
          auto key=line.substr(0,equal),value=line.substr(equal+1);
          if(!fields.emplace(key,value).second)Fail("duplicate_partition_uevent_field");
          if(key=="PARTNAME"){named=true;name=value;}
        }
        if(named){
          if(name.empty()||name.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")!=name.npos)
            Fail("invalid_partname: dev="+id+" path="+rel.generic_string());
        }else{
          // MSDOS/MBR media can legitimately omit GPT's PARTNAME. Retain the
          // physical node and exact backing extents; never exclude USB storage.
          // This reserved name cannot alias any required ROM target label.
          if(fields["DEVTYPE"]!="partition"||Number(fields["PARTN"])!=number||
             ValidDev(fields["MAJOR"]+":"+fields["MINOR"])!=id)
            Fail("unnamed_partition_identity: dev="+id+" path="+rel.generic_string());
          name="@partition:"+id;
        }
      }else name="@disk:"+diskdev;
      // Session-scoped physical coordinates: boot ID + exact sysfs disk path/dev.
      // Continuous anti-rebind authority remains mandatory for any mutation.
      Physical item{id,name,boot+":"+diskdev+":"+diskrel.generic_string(),begin,bytes,{}};
      for(const auto&h:fs::directory_iterator(p/"holders"))item.holders.push_back(ValidDev(Text(h.path()/"dev",64)));
      std::sort(item.holders.begin(),item.holders.end());
      if(device_paths.count(id))item.device_path=device_paths.at(id);
      o.physical.push_back(std::move(item));
    }
    if(!dmids.empty())Fail("dm_missing_sysfs");
    std::sort(o.physical.begin(),o.physical.end(),[](auto&a,auto&b){return a.id<b.id;});
    std::sort(o.mappings.begin(),o.mappings.end(),[](auto&a,auto&b){return a.id<b.id;});
    // All visible process mount namespaces, not only /proc/self/mountinfo.
    // Process churn, inaccessible namespaces and hidden process views leave scope
    // incomplete. A separate deployment authority must certify visibility.
    bool readable=true;size_t processes=0;
    const auto own_namespace=fs::read_symlink(fs::path(proc)/"self/ns/mnt").string();
    for(const auto&e:fs::directory_iterator(proc)){
      std::string pid=e.path().filename().string();
      if(pid.empty()||pid.find_first_not_of("0123456789")!=pid.npos)continue;
      if(++processes>65536)Fail("process_limit");
      try {auto ns=fs::read_symlink(e.path()/"ns/mnt").string();
        if(ns.rfind("mnt:[",0)!=0||ns.back()!=']')Fail("namespace_identity");
        // Namespace identity, rather than its current set of processes, is the
        // storage authority. Still inspect every visible process's mount view.
        Number(ns.substr(5,ns.size()-6));o.mounts.namespace_scope.push_back(ns);
        auto s=ParseMountInfo(Text(e.path()/"mountinfo",16U<<20));o.mounts.devices.insert(s.begin(),s.end());
        if(ns!=own_namespace)o.mounts.foreign_devices.insert(s.begin(),s.end());}
      catch(const std::exception&error){if(fs::exists(e.path())&&!ExitedWithoutMountNamespace(e.path(),pid)){
        readable=false;o.mounts.inspection_errors.push_back("process "+pid+": "+error.what());}}
    }
    o.mounts.current=ParseMountRecords(Text(fs::path(proc)/"self/mountinfo",16U<<20));
    for(const auto&m:o.mounts.current)o.mounts.devices.insert(m.device);
    // Scope is all visible proc namespaces only. Hidden namespaces, new mounts,
    // and arbitrary privileged writers are outside the supported single-recovery
    // workflow assumption and are not claimed impossible by this observation.
    std::sort(o.mounts.namespace_scope.begin(),o.mounts.namespace_scope.end());
    o.mounts.namespace_scope.erase(std::unique(o.mounts.namespace_scope.begin(),o.mounts.namespace_scope.end()),o.mounts.namespace_scope.end());
    o.mounts.complete=readable&&!o.mounts.namespace_scope.empty();
    for(const auto&e:o.excluded){
      if(e.reason=="unconfigured_zero_loop"&&o.mounts.devices.count(e.id))Fail("empty_loop_mounted");
      for(const auto&m:o.mappings)if(std::find(m.dependencies.begin(),m.dependencies.end(),e.id)!=m.dependencies.end())Fail("excluded_device_is_mapping_dependency");
    }
    std::sort(o.excluded.begin(),o.excluded.end(),[](auto&a,auto&b){return a.id<b.id;});
    return o;
  };
  auto describe=[](const Observation&a,const Observation&b)->std::string{try{
    if(a.mounts.complete!=b.mounts.complete){std::string errors;for(auto&e:a.mounts.inspection_errors)errors+="; first "+e;for(auto&e:b.mounts.inspection_errors)errors+="; second "+e;Fail("topology_changed_during_collection: inspection completeness"+errors);}
    if(a.mounts.namespace_scope!=b.mounts.namespace_scope)Fail("topology_changed_during_collection: mount namespace set");
    if(a.mounts.devices!=b.mounts.devices||a.mounts.current!=b.mounts.current)Fail("topology_changed_during_collection: mounted devices");
    if(a.mappings!=b.mappings)Fail("topology_changed_during_collection: device-mapper state");
    if(a.mounts.foreign_devices!=b.mounts.foreign_devices)Fail("topology_changed_during_collection: foreign namespace mount view");
    if(a.physical.size()!=b.physical.size())Fail("topology_changed_during_collection: physical device count "+std::to_string(a.physical.size())+" -> "+std::to_string(b.physical.size()));
    for(size_t i=0;i<a.physical.size();++i)if(!SamePhysical(a.physical[i],b.physical[i]))Fail("topology_changed_during_collection: physical "+a.physical[i].id+" "+a.physical[i].partition+" path="+a.physical[i].device_path+" -> "+b.physical[i].device_path);
    if(a.excluded.size()!=b.excluded.size())Fail("topology_changed_during_collection: inert virtual device count");
    for(size_t i=0;i<a.excluded.size();++i)if(a.excluded[i].fingerprint!=b.excluded[i].fingerprint)Fail("topology_changed_during_collection: virtual backing "+a.excluded[i].id);
    Fail("incomplete mount namespace inspection");
  }catch(const std::exception&error){return error.what();}};
  return StableObservation(once,[](const Observation&a,const Observation&b){return SameObservation(a,b);},
    [](const Observation&o){return o.mounts.complete;},[](const Observation&o){(void)BuildInventory(o);},describe);
}
void RemoveMappingChecked(const std::string&id,const std::vector<std::string>&order,
 const Observation&expected,DmAdapter&dm,TopologyLease&lease,const std::function<Observation()>&refresh){
  if(order.empty()||order.front()!=id||std::set<std::string>(order.begin(),order.end()).size()!=order.size())Fail("unapproved_teardown_order");
  Observation before=refresh();
  if(!SameObservation(expected,before)||!before.mounts.complete)Fail("teardown_stale_or_incomplete");
  auto inv=BuildInventory(before);const guard::Node*target=nullptr,*super=nullptr;const Mapping*map=nullptr;
  for(const auto&n:inv.nodes){if(n.id==id)target=&n;if(n.partition=="super")super=&n;}
  for(const auto&m:before.mappings)if(m.id==id)map=&m;
  if(!target||!super||!map||(target->kind!=Kind::Linear&&target->kind!=Kind::Verity)||
    (target->kind==Kind::Verity&&target->read_only!=Truth::Yes)||target->mounted!=Truth::No||
    !target->open_count||*target->open_count!=0)Fail("unsafe_teardown_target");
  for(const auto&e:target->extents)if(!Subset(e,super->extents))Fail("teardown_not_only_super");
  for(const auto&n:inv.nodes)if(std::find(n.dependencies.begin(),n.dependencies.end(),id)!=n.dependencies.end())Fail("teardown_child_still_present");
  if(!lease.Recheck(before,"before_remove"))Fail("teardown_exclusion_missing");
  if(!dm.Remove(map->name))Fail("dm_remove_failed");
  Observation after=refresh();
  for(const auto&m:after.mappings)if(m.id==id||m.name==map->name||(!map->uuid.empty()&&m.uuid==map->uuid))Fail("mapping_still_present_or_recreated");
  if(!SameObservation(before,after,id)||!lease.Recheck(after,"after_remove"))Fail("post_remove_race");
}
} // namespace ri3::backend
