// SPDX-License-Identifier: Apache-2.0
#include "storage_backend.h"
#include "verity_table.h"
#include "observation_window.h"
#include <algorithm>
#include <cerrno>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <cstring>
#include <cstdarg>
#include <iostream>
#include <stdexcept>
#include <functional>
#include <filesystem>
#include <fstream>
using namespace ri3::backend;
using ri3::guard::Kind;
static int injected_mount_read_errno=0,injected_mount_open_errno=0;static dev_t injected_mount_dev=0;static ino_t injected_mount_inode=0;
extern "C" int __real_open(const char*,int,...);
extern "C" int __real_open64(const char*,int,...);
extern "C" int __wrap_open(const char*path,int flags,...){struct stat s{};mode_t mode=0;
 if(flags&O_CREAT){va_list args;va_start(args,flags);mode=va_arg(args,int);va_end(args);}
 if(injected_mount_open_errno&&stat(path,&s)==0&&s.st_dev==injected_mount_dev&&s.st_ino==injected_mount_inode){errno=injected_mount_open_errno;return -1;}
 return __real_open(path,flags,mode);
}
extern "C" int __wrap_open64(const char*path,int flags,...){struct stat s{};mode_t mode=0;
 if(flags&O_CREAT){va_list args;va_start(args,flags);mode=va_arg(args,int);va_end(args);}
 if(injected_mount_open_errno&&stat(path,&s)==0&&s.st_dev==injected_mount_dev&&s.st_ino==injected_mount_inode){errno=injected_mount_open_errno;return -1;}
 return __real_open64(path,flags,mode);
}
extern "C" ssize_t __real_read(int,void*,size_t);
extern "C" ssize_t __wrap_read(int fd,void*data,size_t bytes){struct stat s{};
 if(injected_mount_read_errno&&fstat(fd,&s)==0&&s.st_dev==injected_mount_dev&&s.st_ino==injected_mount_inode){errno=injected_mount_read_errno;return -1;}
 return __real_read(fd,data,bytes);
}
int passed=0;
void Test(const char*n,const std::function<void()>&f){f();++passed;std::cout<<"PASS "<<n<<"\n";}
void Need(bool x){if(!x)throw std::runtime_error("assertion_failed");}
void Throws(const std::function<void()>&f){bool hit=false;try{f();}catch(const std::exception&){hit=true;}Need(hit);}
struct Lease:ExclusionLease{
 bool valid=true;int calls=0;std::string deny;
 LeaseScope Scope()const override{return LeaseScope::RegularFileFixture;}
 bool Recheck(const FileIdentity&,const std::string&p)override{++calls;return valid&&p!=deny;}
};
struct Faults:IoOps{
 mutable bool interrupt_read=false;bool interrupt_write=false,zero_write=false,fail_sync=false,corrupt=false;
 mutable bool zero_read=false;size_t max=3;
 ssize_t Read(int fd,void*p,size_t n,uint64_t o)const override{
  if(interrupt_read){interrupt_read=false;errno=EINTR;return -1;}
  if(zero_read)return 0;auto r=IoOps::Read(fd,p,std::min(n,max),o);
  if(corrupt&&r>0)static_cast<char*>(p)[0]^=1;return r;
 }
 ssize_t Write(int fd,const void*p,size_t n,uint64_t o)override{
  if(interrupt_write){interrupt_write=false;errno=EINTR;return -1;}
  if(zero_write)return 0;return IoOps::Write(fd,p,std::min(n,max),o);
 }
 int Sync(int fd)override{if(fail_sync){errno=EIO;return -1;}return IoOps::Sync(fd);}
};
Observation Base(){
 Observation o;o.mounts.complete=true;
 o.physical={{"8:1","super","disk",4096,8192,{"253:0"}},{"8:2","userdata","disk",16384,8192,{}}};
 Mapping m;m.id="253:0";m.name="system_a";m.uuid="lp-system-a";m.kind=Kind::Linear;m.capacity=4096;m.active=true;
 m.dependencies={"8:1"};m.segments={{0,4096,0,"8:1"}};o.mappings={m};return o;
}
struct FakeDm:DmAdapter{
 Observation*state;bool remove_ok=true,retain=false,recreate=false;std::function<void()> after_remove,on_list;
 explicit FakeDm(Observation*s):state(s){}
 std::vector<Mapping>List()override{if(on_list)on_list();return state->mappings;}
 bool Remove(const std::string&name)override{
  if(!remove_ok)return false;
  std::string removed_id;for(const auto&m:state->mappings)if(m.name==name)removed_id=m.id;
  if(!retain)for(auto&p:state->physical)p.holders.erase(std::remove(p.holders.begin(),p.holders.end(),removed_id),p.holders.end());
  if(!retain)state->mappings.erase(std::remove_if(state->mappings.begin(),state->mappings.end(),[&](auto&m){return m.name==name;}),state->mappings.end());
  if(recreate){auto m=Base().mappings[0];m.uuid="replacement";state->mappings.push_back(m);}if(after_remove)after_remove();return true;
 }
};
struct TLease:TopologyLease{bool okay=true;bool Recheck(const Observation&,const std::string&)override{return okay;}};
Observation MountBase(){
 auto o=Base();o.mappings[0].open_count=1;
 o.mounts.devices={"253:0","8:2"};o.mounts.namespace_scope={"1:mnt:[42]"};
 o.mounts.current={{1,0,"0:1","/","/","rootfs"},{10,1,"253:0","/","/system","erofs"},{20,1,"8:2","/","/data","f2fs"}};return o;
}
ri3::guard::Source SourceProof(){
 ri3::guard::Source s;s.open_handle_id="held-source";s.readable=s.content_verified=s.extents_complete=s.dependencies_complete=ri3::guard::Truth::Yes;
 s.dependencies={"8:2"};s.extents={{"disk",16384,8192}};return s;
}
struct FakeUnmount:UnmountOps{
 Observation*state;bool busy=false,recreate=false;std::vector<uint64_t>calls;
 explicit FakeUnmount(Observation*p):state(p){}
 bool NormalUnmount(const MountRecord&m)override{
  calls.push_back(m.id);if(busy)return false;
  auto&v=state->mounts.current;v.erase(std::remove(v.begin(),v.end(),m),v.end());
  if(std::none_of(v.begin(),v.end(),[&](const auto&n){return n.device==m.device;}))state->mounts.devices.erase(m.device);
  for(auto&n:state->mappings)if(n.id==m.device)n.open_count=0;
  if(recreate){auto n=m;n.id+=100;v.push_back(n);state->mounts.devices.insert(m.device);}return true;
 }
};
int main(int argc,char**argv){
 try{
  if(argc!=2||std::string(argv[1]).rfind("/dev",0)==0)throw std::runtime_error("fixture_path_required");
  int fd=open(argv[1],O_RDWR|O_CREAT|O_EXCL|O_CLOEXEC,0600);if(fd<0)throw std::runtime_error("fixture_create");
  if(ftruncate(fd,64))throw std::runtime_error("fixture_resize");
  const std::string text="exact regular-file readback";
  Test("short_io_and_eintr",[&]{Lease l;Faults io;io.interrupt_read=io.interrupt_write=true;PinnedOutputSink s(fd,InspectFd(fd),l,io);
    s.Write(5,text.data(),text.size());s.Sync();std::string b(text.size(),'\0');s.Read(5,b.data(),b.size());Need(b==text&&l.calls>10&&s.Capacity()==64);});
  Test("capacity_mismatch",[&]{auto e=InspectFd(fd);e.capacity=65;Lease l;Faults io;Throws([&]{PinnedOutputSink s(fd,e,l,io);});});
  Test("inode_mismatch",[&]{auto e=InspectFd(fd);++e.inode;Lease l;Faults io;Throws([&]{PinnedOutputSink s(fd,e,l,io);});});
  Test("deny_before_adopt",[&]{Lease l;l.valid=false;Faults io;Throws([&]{PinnedOutputSink s(fd,InspectFd(fd),l,io);});});
  Test("deny_before_write_no_mutation",[&]{Lease l;Faults io;PinnedOutputSink s(fd,InspectFd(fd),l,io);l.deny="before_write";Throws([&]{s.Write(0,"x",1);});});
  Test("lease_loss_poisoned",[&]{Lease l;Faults io;PinnedOutputSink s(fd,InspectFd(fd),l,io);l.valid=false;Throws([&]{s.Write(0,"x",1);});l.valid=true;Throws([&]{s.Capacity();});});
  Test("zero_write_fails",[&]{Lease l;Faults io;io.zero_write=true;PinnedOutputSink s(fd,InspectFd(fd),l,io);Throws([&]{s.Write(0,"x",1);});});
  Test("zero_read_fails",[&]{Lease l;Faults io;io.zero_read=true;PinnedOutputSink s(fd,InspectFd(fd),l,io);char b;Throws([&]{s.Read(0,&b,1);});});
  Test("fsync_failure",[&]{Lease l;Faults io;io.fail_sync=true;PinnedOutputSink s(fd,InspectFd(fd),l,io);Throws([&]{s.Sync();});});
  Test("write_past_capacity",[&]{Lease l;Faults io;PinnedOutputSink s(fd,InspectFd(fd),l,io);Throws([&]{s.Write(64,"x",1);});});
  Test("read_offset_overflow",[&]{Lease l;Faults io;PinnedOutputSink s(fd,InspectFd(fd),l,io);char b;Throws([&]{s.Read(UINT64_MAX,&b,1);});});
  Test("shrink_detected",[&]{Lease l;Faults io;PinnedOutputSink s(fd,InspectFd(fd),l,io);Need(!ftruncate(fd,63));Throws([&]{s.Sync();});Need(!ftruncate(fd,64));});
  Test("source_retains_handle",[&]{PinnedSource s(fd);s.Recheck();Need(!s.HandleId().empty());});
  Test("source_mutation_detected",[&]{PinnedSource s(fd);Need(!ftruncate(fd,62));Throws([&]{s.Recheck();});Need(!ftruncate(fd,64));});
  Test("source_dependency_proof_content_unknown",[&]{PinnedSource s(fd);auto i=InspectFd(fd);Observation o;o.mounts.complete=true;
    o.physical={{DeviceId(major(i.device),minor(i.device)),"userdata","disk",999999,65536,{}}};
    auto v=s.Describe(BuildInventory(o));Need(v.extents[0].begin==999999&&v.content_verified==ri3::guard::Truth::Unknown);});
  Test("source_unknown_filesystem",[&]{PinnedSource s(fd);Throws([&]{s.Describe(BuildInventory(Base()));});});
  Test("mountinfo_valid",[&]{auto v=ParseMountInfo("12 1 253:0 / /system ro shared:1 - ext4 /dev/block/dm-0 ro\n13 1 8:2 / /data rw - f2fs /dev/block/sda2 rw\n");Need(v.size()==2&&v.count("253:0"));});
  Test("mountinfo_malformed",[&]{Throws([&]{ParseMountInfo("12 1 8:2 / /data\n");});});
  Test("mountinfo_duplicate",[&]{Throws([&]{ParseMountInfo("12 1 8:2 / /data rw - f2fs x rw\n12 1 8:1 / /x rw - ext4 y rw\n");});});
  Test("physical_open_count_unknown",[&]{auto v=BuildInventory(Base());for(auto&n:v.nodes)if(n.kind==Kind::Partition)Need(!n.open_count);});
  Test("optional_empty_mapping_uuid",[&]{auto o=Base();o.mappings[0].uuid.clear();Need(BuildInventory(o).nodes.size()==3);});
  Test("linear_exact_extent",[&]{auto v=BuildInventory(Base());for(auto&n:v.nodes)if(n.id=="253:0")Need(n.extents[0].begin==4096&&n.extents[0].bytes==4096);});
  Test("userdata_crypto_disjoint_same_disk",[&]{auto o=Base();auto&m=o.mappings[0];m.kind=Kind::Crypto;m.dependencies={"8:2"};m.segments.clear();o.physical[0].holders.clear();o.physical[1].holders={"253:0"};
    auto v=BuildInventory(o);for(auto&n:v.nodes)if(n.id==m.id)Need(n.extents[0].begin==16384&&n.extents[0].bytes==8192);});
  Test("linear_over_nonlinear_preserves_backing_union",[&]{
    auto o=Base();auto&m=o.mappings[0];m.kind=Kind::Crypto;m.dependencies={"8:1","8:2"};m.segments.clear();o.physical[1].holders={"253:0"};
    Mapping child;child.id="253:1";child.name="child";child.uuid="child";child.active=true;child.kind=Kind::Linear;child.capacity=512;child.dependencies={"253:0"};child.segments={{0,512,0,"253:0"}};o.mappings.push_back(child);
    auto inv=BuildInventory(o);for(const auto&n:inv.nodes)if(n.id=="253:1")Need(n.extents.size()==2&&n.extents[0].bytes==8192&&n.extents[1].bytes==8192);
  });
  Test("mapping_cycle",[&]{auto o=Base();o.mappings[0].dependencies={"253:0"};o.mappings[0].segments[0].dependency="253:0";Throws([&]{BuildInventory(o);});});
  Test("unknown_dependency",[&]{auto o=Base();o.mappings[0].dependencies={"9:9"};o.mappings[0].segments[0].dependency="9:9";Throws([&]{BuildInventory(o);});});
  Test("mapping_gap",[&]{auto o=Base();o.mappings[0].segments[0].logical=512;Throws([&]{BuildInventory(o);});});
  Test("mapping_outside_backing",[&]{auto o=Base();o.mappings[0].segments[0].backing_offset=8192;Throws([&]{BuildInventory(o);});});
  Test("mapping_sysfs_mismatch",[&]{auto o=Base();o.mappings[0].dependencies={"8:2"};Throws([&]{BuildInventory(o);});});
  Test("suspended_mapping",[&]{auto o=Base();o.mappings[0].suspended=true;Throws([&]{BuildInventory(o);});});
  Test("inactive_table",[&]{auto o=Base();o.mappings[0].inactive=true;Throws([&]{BuildInventory(o);});});
  Test("unknown_kind",[&]{auto o=Base();o.mappings[0].kind=Kind::Unknown;Throws([&]{BuildInventory(o);});});
  auto removal=[&](Observation o,FakeDm&dm,TLease&l){auto expected=o;RemoveMappingChecked("253:0",{"253:0"},expected,dm,l,[&]{return *dm.state;});};
  Test("linear_remove_rechecked",[&]{auto o=Base();FakeDm d(&o);TLease l;removal(o,d,l);Need(o.mappings.empty());});
  Test("remove_failure",[&]{auto o=Base();FakeDm d(&o);d.remove_ok=false;TLease l;Throws([&]{removal(o,d,l);});});
  Test("remove_still_present",[&]{auto o=Base();FakeDm d(&o);d.retain=true;TLease l;Throws([&]{removal(o,d,l);});});
  Test("remove_recreation",[&]{auto o=Base();FakeDm d(&o);d.recreate=true;TLease l;Throws([&]{removal(o,d,l);});});
  Test("remove_mounted",[&]{auto o=Base();o.mounts.devices.insert("253:0");FakeDm d(&o);TLease l;Throws([&]{removal(o,d,l);});});
  Test("remove_open",[&]{auto o=Base();o.mappings[0].open_count=1;FakeDm d(&o);TLease l;Throws([&]{removal(o,d,l);});});
  Test("remove_crypto_target",[&]{auto o=Base();o.mappings[0].kind=Kind::Crypto;o.mappings[0].segments.clear();FakeDm d(&o);TLease l;Throws([&]{removal(o,d,l);});});
  Test("remove_unknown_mount_scope",[&]{auto o=Base();o.mounts.complete=false;FakeDm d(&o);TLease l;Throws([&]{removal(o,d,l);});});
  Test("remove_exclusion_absent",[&]{auto o=Base();FakeDm d(&o);TLease l;l.okay=false;Throws([&]{removal(o,d,l);});});
  Test("remove_child_first",[&]{auto o=Base();auto child=o.mappings[0];child.id="253:1";child.name="child";child.uuid="child-id";child.dependencies={"253:0"};child.segments[0].dependency="253:0";o.mappings.push_back(child);FakeDm d(&o);TLease l;Throws([&]{removal(o,d,l);});});
  Test("remove_not_super",[&]{auto o=Base();o.mappings[0].dependencies={"8:2"};o.mappings[0].segments[0].dependency="8:2";FakeDm d(&o);TLease l;Throws([&]{removal(o,d,l);});});
  std::string vt="1 8:1 8:1 4096 4096 1 1 sha256 "+std::string(64,'a')+" -";
  Test("verity_table_plain",[&]{auto t=ParseVerity(vt,4096);Need(t.dependencies==std::vector<std::string>{"8:1"});CheckVerityBounds(t,{{"8:1",8192}});});
  Test("verity_unknown_option",[&]{Throws([&]{ParseVerity(vt+" 1 arbitrary_option",4096);});});
  Test("verity_wrong_optional_count",[&]{Throws([&]{ParseVerity(vt+" 2 ignore_zero_blocks",4096);});});
  Test("verity_incomplete_fec",[&]{Throws([&]{ParseVerity(vt+" 2 fec_roots 2",4096);});});
  Test("verity_fec_bounds",[&]{auto t=ParseVerity(vt+" 8 use_fec_from_device 8:2 fec_roots 2 fec_blocks 1 fec_start 0",4096);
    CheckVerityBounds(t,{{"8:1",8192},{"8:2",8192}});Throws([&]{CheckVerityBounds(t,{{"8:1",8192},{"8:2",4096}});});});
  Test("verity_data_geometry",[&]{Throws([&]{ParseVerity(vt,8192);});});
  Test("verity_conflicting_options",[&]{Throws([&]{ParseVerity(vt+" 2 ignore_corruption restart_on_corruption",4096);});});
  Test("verity_hash_outside_backing",[&]{auto t=ParseVerity(vt,4096);Throws([&]{CheckVerityBounds(t,{{"8:1",2048}});});});
  Test("verity_leaf_remove",[&]{auto o=Base();auto&m=o.mappings[0];m.kind=Kind::Verity;m.read_only=true;m.verity_parameters=vt;m.segments.clear();FakeDm d(&o);TLease l;removal(o,d,l);Need(o.mappings.empty());});
  Test("verity_writable_rejected",[&]{auto o=Base();auto&m=o.mappings[0];m.kind=Kind::Verity;m.verity_parameters=vt;m.segments.clear();Throws([&]{BuildInventory(o);});});
  Test("verity_hidden_fec_dependency",[&]{auto o=Base();auto&m=o.mappings[0];m.kind=Kind::Verity;m.read_only=true;m.verity_parameters=vt+" 8 use_fec_from_device 8:2 fec_roots 2 fec_blocks 1 fec_start 0";m.segments.clear();Throws([&]{BuildInventory(o);});});
  Test("verity_fec_outside_super",[&]{auto o=Base();auto&m=o.mappings[0];m.kind=Kind::Verity;m.read_only=true;m.verity_parameters=vt+" 8 use_fec_from_device 8:2 fec_roots 2 fec_blocks 1 fec_start 0";m.segments.clear();m.dependencies={"8:1","8:2"};o.physical[1].holders={"253:0"};FakeDm d(&o);TLease l;Throws([&]{removal(o,d,l);});});
  Test("verity_cannot_remove_with_child",[&]{auto o=Base();auto&m=o.mappings[0];m.kind=Kind::Verity;m.read_only=true;m.verity_parameters=vt;m.segments.clear();
    Mapping child;child.id="253:1";child.name="child";child.uuid="child-id";child.kind=Kind::Linear;child.active=true;child.capacity=4096;child.dependencies={"253:0"};child.segments={{0,4096,0,"253:0"}};o.mappings.push_back(child);FakeDm d(&o);TLease l;Throws([&]{removal(o,d,l);});});
  Test("stacked_parent_open_released_by_child",[&]{
    auto o=Base();o.mappings[0].open_count=1;auto child=o.mappings[0];child.id="253:1";child.name="child";child.uuid="child";child.open_count=0;child.dependencies={"253:0"};child.segments={{0,4096,0,"253:0"}};o.mappings.push_back(child);
    auto expected=o;FakeDm d(&o);TLease l;d.after_remove=[&]{o.mappings[0].open_count=0;};
    RemoveMappingChecked("253:1",{"253:1","253:0"},expected,d,l,[&]{return o;});Need(o.mappings.size()==1&&o.mappings[0].open_count==0);
    d.after_remove={};expected=o;RemoveMappingChecked("253:0",{"253:0"},expected,d,l,[&]{return o;});Need(o.mappings.empty());
  });
  Test("stacked_parent_residual_open_aborts",[&]{
    auto o=Base();o.mappings[0].open_count=2;auto child=o.mappings[0];child.id="253:1";child.name="child";child.uuid="child";child.open_count=0;child.dependencies={"253:0"};child.segments={{0,4096,0,"253:0"}};o.mappings.push_back(child);
    auto expected=o;FakeDm d(&o);TLease l;d.after_remove=[&]{o.mappings[0].open_count=1;};
    RemoveMappingChecked("253:1",{"253:1","253:0"},expected,d,l,[&]{return o;});expected=o;d.after_remove={};
    Throws([&]{RemoveMappingChecked("253:0",{"253:0"},expected,d,l,[&]{return o;});});Need(o.mappings.size()==1);
  });
  Test("normal_target_unmount_receipt",[&]{
    auto o=MountBase(),expected=o;FakeUnmount u(&o);TLease l;auto source=SourceProof();
    auto r=PrepareUnmountsChecked({"s","boot","pkg",1,1},expected,source,u,l,[&]{return o;});
    Need(r.status==ri3::guard::Status::Known&&r.removed_mount_ids==std::vector<uint64_t>{10}&&u.calls.size()==1&&o.mounts.devices.count("8:2"));
  });
  Test("normal_unmount_busy_aborts",[&]{
    auto o=MountBase();FakeUnmount u(&o);u.busy=true;TLease l;
    auto r=PrepareUnmountsChecked({"s","boot","pkg",1,1},o,SourceProof(),u,l,[&]{return o;});
    Need(r.status==ri3::guard::Status::Error&&r.removed_mount_ids.empty()&&o.mounts.devices.count("253:0"));
  });
  Test("unmount_excludes_metadata_path",[&]{auto o=MountBase();o.mounts.current[1].path="/metadata";Throws([&]{PlanTargetUnmounts(o,SourceProof());});});
  Test("unmount_excludes_zip_source",[&]{auto o=MountBase();auto s=SourceProof();s.dependencies={"253:0"};s.extents={{"disk",4096,4096}};Throws([&]{PlanTargetUnmounts(o,s);});});
  Test("unmount_excludes_unknown_descendant",[&]{auto o=MountBase();o.mounts.current.push_back({11,10,"0:2","/","/system/apex","tmpfs"});Throws([&]{PlanTargetUnmounts(o,SourceProof());});});
  Test("unmount_foreign_namespace_aborts",[&]{auto o=MountBase();o.mounts.foreign_devices.insert("253:0");Throws([&]{PlanTargetUnmounts(o,SourceProof());});});
  Test("unmount_wrong_logical_identity",[&]{auto o=MountBase();o.mappings[0].name="vendor_a";Throws([&]{PlanTargetUnmounts(o,SourceProof());});});
  Test("unmount_remount_race_aborts",[&]{auto o=MountBase();FakeUnmount u(&o);u.recreate=true;TLease l;auto r=PrepareUnmountsChecked({"s","boot","pkg",1,1},o,SourceProof(),u,l,[&]{return o;});Need(r.status==ri3::guard::Status::Error&&r.removed_mount_ids.size()==1);});
  Test("unmount_children_first",[&]{
    auto o=MountBase();auto child=o.mappings[0];child.id="253:1";child.name="system_ext_a";child.uuid="system-ext";child.segments[0].backing_offset=4096;
    o.mappings.push_back(child);o.physical[0].holders.push_back("253:1");o.mounts.devices.insert("253:1");
    o.mounts.current.insert(o.mounts.current.begin()+2,{11,10,"253:1","/","/system_ext","ext4"});
    FakeUnmount u(&o);TLease l;auto r=PrepareUnmountsChecked({"s","boot","pkg",1,1},o,SourceProof(),u,l,[&]{return o;});
    Need(r.status==ri3::guard::Status::Known&&u.calls==std::vector<uint64_t>({11,10}));
  });
  Test("unmount_no_lease_no_effect",[&]{auto o=MountBase();FakeUnmount u(&o);TLease l;l.okay=false;auto r=PrepareUnmountsChecked({"s","boot","pkg",1,1},o,SourceProof(),u,l,[&]{return o;});Need(r.status==ri3::guard::Status::Error&&u.calls.empty());});
  Test("unmount_self_parented_root_supported",[&]{auto o=MountBase();o.mounts.current[0].parent=1;auto plan=PlanTargetUnmounts(o,SourceProof());Need(plan.size()==1&&plan[0].id==10);});
  Test("unmount_self_parented_nonroot_rejected",[&]{auto o=MountBase();o.mounts.current[1].parent=10;Throws([&]{PlanTargetUnmounts(o,SourceProof());});});
  Test("unmount_multinode_parent_cycle_rejected",[&]{auto o=MountBase();o.mounts.current[0].parent=10;Throws([&]{PlanTargetUnmounts(o,SourceProof());});});
  Test("snapshot_authority_pending",[&]{PendingSnapshotAuthority p;Need(p.Read({}).status==ri3::guard::Status::Unknown);});
  Test("physical_unknown_holder",[&]{auto o=Base();o.physical[0].holders.push_back("253:99");Throws([&]{BuildInventory(o);});});
  Test("physical_missing_holder",[&]{auto o=Base();o.physical[0].holders.clear();Throws([&]{BuildInventory(o);});});
  Test("regular_fd_rejected_as_block_target",[&]{auto inv=BuildInventory(Base());Throws([&]{CheckTargetFd(fd,inv.nodes[0]);});});
  Test("observation_resamples_transient_pair",[&]{unsigned calls=0,validated=0;auto result=StableObservation([&]{++calls;return calls<3?calls:9U;},[](auto a,auto b){return a==b;},[](auto){return true;},[&](auto){++validated;},[](auto,auto){return "change";});Need(result==9&&calls==4&&validated==1);});
  Test("observation_persistent_change_refused",[&]{unsigned calls=0,validated=0;Throws([&]{StableObservation([&]{return ++calls;},[](auto a,auto b){return a==b;},[](auto){return true;},[&](auto){++validated;},[](auto,auto){return "change";});});Need(calls==8&&validated==0);});
  Test("observation_equal_incomplete_refused",[&]{unsigned calls=0,validated=0;Throws([&]{StableObservation([&]{++calls;return 1;},[](auto a,auto b){return a==b;},[](auto){return false;},[&](auto){++validated;},[](auto,auto){return "incomplete";});});Need(calls==8&&validated==0);});
  Test("observation_collection_error_not_retried",[&]{unsigned calls=0;Throws([&]{StableObservation([&]()->int{++calls;throw std::runtime_error("untrusted device");},[](auto a,auto b){return a==b;},[](auto){return true;},[](auto){},[](auto,auto){return "error";});});Need(calls==1);});
  Test("observation_validation_error_not_retried",[&]{unsigned calls=0;Throws([&]{StableObservation([&]{++calls;return 1;},[](auto a,auto b){return a==b;},[](auto){return true;},[](auto){throw std::runtime_error("bad graph");},[](auto,auto){return "error";});});Need(calls==2);});
  Test("sysfs_proc_fixture_collection",[&]{
    namespace fs=std::filesystem;
    fs::path root=std::string(argv[1])+".tree",sys=root/"sys",proc=root/"proc",dev=root/"dev";
    fs::create_directories(dev);
    auto put=[&](const fs::path&p,const std::string&s){fs::create_directories(p.parent_path());std::ofstream out(p);out<<s;if(!out)throw std::runtime_error("fixture_write");};
    auto disk=sys/"devices/pci/block/sda",part=disk/"sda1",dm=sys/"devices/virtual/block/dm-0";
    fs::create_directories(sys/"class/block");fs::create_directories(disk/"holders");fs::create_directories(part/"holders");fs::create_directories(dm/"dm");
    put(disk/"dev","8:0\n");put(disk/"size","128\n");put(part/"dev","8:1\n");put(part/"size","16\n");put(part/"start","8\n");put(part/"partition","1\n");put(part/"uevent","PARTNAME=super\n");
    put(dm/"dev","253:0\n");
    fs::create_directory_symlink(fs::absolute(disk),sys/"class/block/sda");
    fs::create_directory_symlink(fs::absolute(part),sys/"class/block/sda1");
    fs::create_directory_symlink(fs::absolute(dm),sys/"class/block/dm-0");
    fs::create_directory_symlink(fs::absolute(dm),part/"holders/dm-0");
    put(proc/"sys/kernel/random/boot_id","12345678-1234-1234-1234-123456789abc\n");
    put(proc/"1/mountinfo","1 0 0:1 / / rw - rootfs rootfs rw\n");
    fs::create_directories(proc/"1/ns");fs::create_symlink("mnt:[42]",proc/"1/ns/mnt");
    fs::create_directory_symlink(fs::absolute(proc/"1"),proc/"self");
    auto state=Base();FakeDm fake(&state);auto got=CollectLinux(sys.string(),proc.string(),fake,dev.string());
    Need(got.physical.size()==2&&got.mounts.complete&&got.mounts.namespace_scope.size()==1);
    auto inv=BuildInventory(got);Need(inv.nodes.size()==3);
    Test("collector_unnamed_mbr_partition_retains_backing",[&]{
      put(part/"uevent","MAJOR=8\nMINOR=1\nDEVTYPE=partition\nPARTN=1\n");
      auto unnamed=CollectLinux(sys.string(),proc.string(),fake,dev.string());
      auto inventory=BuildInventory(unnamed);const auto&node=*std::find_if(inventory.nodes.begin(),inventory.nodes.end(),[](auto&n){return n.id=="8:1";});
      Need(node.partition=="@partition:8:1"&&node.extents.size()==1&&node.extents[0].begin==4096&&node.extents[0].bytes==8192);
      Need(std::none_of(inventory.nodes.begin(),inventory.nodes.end(),[](auto&n){return n.partition=="super";}));
      put(part/"uevent","PARTNAME=super\n");
    });
    Test("collector_empty_present_partname_rejected",[&]{put(part/"uevent","PARTNAME=\n");Throws([&]{CollectLinux(sys.string(),proc.string(),fake,dev.string());});put(part/"uevent","PARTNAME=super\n");});
    Test("collector_invalid_present_partname_rejected",[&]{put(part/"uevent","PARTNAME=../super\n");Throws([&]{CollectLinux(sys.string(),proc.string(),fake,dev.string());});put(part/"uevent","PARTNAME=super\n");});
    Test("collector_unnamed_wrong_identity_rejected",[&]{put(part/"uevent","MAJOR=8\nMINOR=2\nDEVTYPE=partition\nPARTN=1\n");Throws([&]{CollectLinux(sys.string(),proc.string(),fake,dev.string());});put(part/"uevent","PARTNAME=super\n");});
    Test("collector_duplicate_partname_rejected",[&]{put(part/"uevent","PARTNAME=\nPARTNAME=super\n");Throws([&]{CollectLinux(sys.string(),proc.string(),fake,dev.string());});put(part/"uevent","PARTNAME=super\n");});
    auto loop=sys/"devices/virtual/block/loop0";
    fs::create_directories(loop/"holders");fs::create_directories(loop/"slaves");put(loop/"dev","7:0\n");put(loop/"size","0\n");
    fs::create_directory_symlink(fs::absolute(loop),sys/"class/block/loop0");
    Need(CollectLinux(sys.string(),proc.string(),fake,dev.string()).excluded.size()==1);
    put(loop/"loop/backing_file","/data/unproven.img\n");Throws([&]{CollectLinux(sys.string(),proc.string(),fake,dev.string());});
    fs::remove_all(loop/"loop");
    auto zram=sys/"devices/virtual/block/zram0";
    fs::create_directories(zram/"holders");fs::create_directories(zram/"slaves");put(zram/"dev","252:0\n");put(zram/"size","16\n");
    put(zram/"disksize","8192\n");put(zram/"backing_dev","none\n");
    fs::create_directory_symlink(fs::absolute(zram),sys/"class/block/zram0");
    Need(CollectLinux(sys.string(),proc.string(),fake,dev.string()).excluded.size()==2);
    put(zram/"backing_dev","8:1\n");Throws([&]{CollectLinux(sys.string(),proc.string(),fake,dev.string());});put(zram/"backing_dev","none\n");
    auto ram=sys/"devices/virtual/block/ram0";
    fs::create_directories(ram/"holders");fs::create_directories(ram/"slaves");put(ram/"dev","1:0\n");put(ram/"size","16384\n");
    put(proc/"devices","Character devices:\n  1 mem\n\nBlock devices:\n  1 ramdisk\n  7 loop\n  8 sd\n");
    fs::create_directory_symlink(fs::absolute(ram),sys/"class/block/ram0");
    auto collect=[&]{return CollectLinux(sys.string(),proc.string(),fake,dev.string());};
    Test("collector_recognizes_ramdisk_driver",[&]{auto o=collect();Need(o.excluded.size()==3&&std::any_of(o.excluded.begin(),o.excluded.end(),[](auto&e){return e.reason=="memory_only_ramdisk";}));});
    Test("collector_ramdisk_wrong_major_rejected",[&]{put(ram/"dev","43:0\n");Throws([&]{collect();});put(ram/"dev","1:0\n");});
    Test("collector_ramdisk_wrong_driver_rejected",[&]{put(proc/"devices","Block devices:\n  1 something_else\n");Throws([&]{collect();});put(proc/"devices","Block devices:\n  1 ramdisk\n");});
    Test("collector_ramdisk_missing_driver_rejected",[&]{put(proc/"devices","Block devices:\n  8 sd\n");Throws([&]{collect();});put(proc/"devices","Block devices:\n  1 ramdisk\n");});
    Test("collector_ramdisk_slaves_rejected",[&]{fs::create_directory_symlink(fs::absolute(part),ram/"slaves/sda1");Throws([&]{collect();});fs::remove(ram/"slaves/sda1");});
    Test("collector_ramdisk_holders_rejected",[&]{fs::create_directory_symlink(fs::absolute(dm),ram/"holders/dm-0");Throws([&]{collect();});fs::remove(ram/"holders/dm-0");});
    Test("collector_ramdisk_loop_backing_rejected",[&]{put(ram/"loop/backing_file","/data/image.bin\n");Throws([&]{collect();});fs::remove_all(ram/"loop");});
    Test("collector_ramdisk_mapping_dependency_rejected",[&]{auto prior=state.mappings[0].dependencies;state.mappings[0].dependencies={"1:0"};Throws([&]{collect();});state.mappings[0].dependencies=prior;});
    Test("collector_unknown_virtual_diagnostic",[&]{auto nbd=sys/"devices/virtual/block/nbd0";fs::create_directories(nbd/"holders");fs::create_directories(nbd/"slaves");put(nbd/"dev","43:0\n");put(nbd/"size","16\n");fs::create_directory_symlink(fs::absolute(nbd),sys/"class/block/nbd0");bool rejected=false;try{collect();}catch(const std::exception&e){rejected=std::string(e.what()).find("nbd0 dev=43:0")!=std::string::npos;}Need(rejected);fs::remove(sys/"class/block/nbd0");fs::remove_all(nbd);});
    Test("collector_inert_virtual_churn_allowed",[&]{auto loop1=sys/"devices/virtual/block/loop1";unsigned calls=0;fake.on_list=[&]{if(++calls==2){fs::create_directories(loop1/"holders");fs::create_directories(loop1/"slaves");put(loop1/"dev","7:8\n");put(loop1/"size","0\n");fs::create_directory_symlink(fs::absolute(loop1),sys/"class/block/loop1");}};auto o=collect();Need(std::any_of(o.excluded.begin(),o.excluded.end(),[](auto&e){return e.id=="7:8"&&e.reason=="unconfigured_zero_loop";}));fake.on_list={};fs::remove(sys/"class/block/loop1");fs::remove_all(loop1);});
    Test("collector_backed_virtual_churn_rejected",[&]{auto loop1=sys/"devices/virtual/block/loop1";unsigned calls=0;fake.on_list=[&]{if(++calls==2){fs::create_directories(loop1/"holders");fs::create_directories(loop1/"slaves");put(loop1/"dev","7:8\n");put(loop1/"size","0\n");put(loop1/"loop/backing_file","/data/unproven.img\n");fs::create_directory_symlink(fs::absolute(loop1),sys/"class/block/loop1");}};Throws([&]{collect();});fake.on_list={};fs::remove(sys/"class/block/loop1");fs::remove_all(loop1);});
    fs::create_directories(proc/"3/ns");fs::create_directories(proc/"3/fd");put(proc/"3/mountinfo","");
    auto task_stat=[&](const std::string&state){std::string text="3 (dead ) worker) "+state;for(int i=1;i<20;++i)text+=" "+std::string(i==19?"1000":"0");return text+"\n";};
    put(proc/"3/stat",task_stat("Z"));
    Test("collector_proves_exited_empty_task",[&]{auto o=collect();Need(o.mounts.complete&&o.mounts.namespace_scope.size()==1);});
    Test("collector_live_inaccessible_task_incomplete",[&]{put(proc/"3/stat",task_stat("S"));Throws([&]{collect();});put(proc/"3/stat",task_stat("Z"));});
    Test("collector_exited_with_fd_incomplete",[&]{put(proc/"3/fd/0","held");Throws([&]{collect();});fs::remove(proc/"3/fd/0");});
    Test("collector_exited_with_mount_incomplete",[&]{put(proc/"3/mountinfo","1 0 8:1 / /system ro - erofs /dev/block/sda1 ro\n");Throws([&]{collect();});put(proc/"3/mountinfo","");});
    Test("collector_exited_with_namespace_incomplete",[&]{fs::create_symlink("mnt:[99]",proc/"3/ns/mnt");Throws([&]{collect();});fs::remove(proc/"3/ns/mnt");});
    Test("collector_wrong_pid_stat_incomplete",[&]{put(proc/"3/stat","999 (dead) Z 0 0\n");Throws([&]{collect();});put(proc/"3/stat",task_stat("Z"));});
    auto inject_mount_read=[&](int error){struct stat s{};Need(stat((proc/"3/mountinfo").c_str(),&s)==0);injected_mount_dev=s.st_dev;injected_mount_inode=s.st_ino;injected_mount_read_errno=error;};
    Test("collector_exited_mountinfo_einval_supported",[&]{inject_mount_read(EINVAL);Need(collect().mounts.complete);injected_mount_read_errno=0;});
    Test("collector_exited_mountinfo_permission_still_incomplete",[&]{inject_mount_read(EACCES);Throws([&]{collect();});injected_mount_read_errno=0;});
    Test("collector_exited_mountinfo_io_error_still_incomplete",[&]{inject_mount_read(EIO);Throws([&]{collect();});injected_mount_read_errno=0;});
    Test("collector_exited_mountinfo_open_einval_supported",[&]{inject_mount_read(0);injected_mount_open_errno=EINVAL;Need(collect().mounts.complete);injected_mount_open_errno=0;});
    Test("collector_exited_mountinfo_open_permission_incomplete",[&]{inject_mount_read(0);injected_mount_open_errno=EACCES;Throws([&]{collect();});injected_mount_open_errno=0;});
    Test("collector_same_namespace_process_churn_allowed",[&]{unsigned calls=0;fake.on_list=[&]{if(++calls==2){put(proc/"4/mountinfo","1 0 0:1 / / rw - rootfs rootfs rw\n");fs::create_directories(proc/"4/ns");fs::create_symlink("mnt:[42]",proc/"4/ns/mnt");}};auto o=collect();Need(o.mounts.complete&&o.mounts.namespace_scope==std::vector<std::string>{"mnt:[42]"});fake.on_list={};fs::remove_all(proc/"4");});
    Test("collector_persistent_namespace_churn_rejected",[&]{unsigned calls=0;fake.on_list=[&]{if(++calls%2==0){put(proc/"5/mountinfo","1 0 0:1 / / rw - rootfs rootfs rw\n");fs::create_directories(proc/"5/ns");fs::create_symlink("mnt:[99]",proc/"5/ns/mnt");}else if(fs::exists(proc/"5")){fs::remove_all(proc/"5");}};Throws([&]{collect();});fake.on_list={};fs::remove_all(proc/"5");});
    put(proc/"2/mountinfo","bad\n");fs::create_directories(proc/"2/ns");fs::create_symlink("mnt:[99]",proc/"2/ns/mnt");
    Throws([&]{CollectLinux(sys.string(),proc.string(),fake,dev.string());});
  });
  close(fd);
  std::cout<<"RESULT "<<passed<<" fixture/mock tests passed; no device operations executed\n";return 0;
 }catch(const std::exception&e){std::cerr<<"FAIL "<<e.what()<<"\n";return 1;}
}
