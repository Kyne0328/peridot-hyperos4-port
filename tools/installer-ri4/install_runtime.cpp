// SPDX-License-Identifier: Apache-2.0
// RI4: install a complete A image set from a working recovery on either slot.
#include "install_runtime.h"
#include "held_package.h"
#include "storage_backend.h"
#include "snapshot_collect.h"
#include "image_pins.h"
#include "sequence.h"
#include <algorithm>
#include <chrono>
#include <fcntl.h>
#include <map>
#include <set>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>
#ifdef __ANDROID__
#include <sys/system_properties.h>
#endif
namespace ri3::runtime {
namespace {
namespace b=ri3::backend;namespace g=ri3::guard;namespace sn=ri3::snapshot;
void Need(bool v,const std::string& e){if(!v)throw std::runtime_error(e);}
struct Fd{int n;explicit Fd(int x):n(x){}~Fd(){if(n>=0)close(n);}Fd(const Fd&)=delete;};
bool Overlap(const g::Extent&a,const g::Extent&c){return a.disk==c.disk&&a.begin<c.begin+c.bytes&&c.begin<a.begin+a.bytes;}
bool Intersect(const std::vector<g::Extent>&a,const std::vector<g::Extent>&c){for(auto&x:a)for(auto&y:c)if(Overlap(x,y))return true;return false;}
struct Payload{const ri4::Pin*pin;std::unique_ptr<CheckedRaw>raw;std::unique_ptr<CheckedSparse>sparse;};
std::vector<Payload> ValidatePayloads(int fd,package::Package&zip,const Message&message={}){
 std::vector<Payload>out;
 Need(zip.Count()==ri4::kImageCount+5,"Unexpected ZIP members");
 for(const auto&pin:ri4::kPins){
  if(message)message("Verifying image "+std::string(pin.name)+" ("+std::to_string(pin.bytes/(1024*1024))+" MiB)...");
  auto range=zip.CheckedStoredRange(std::string("partitions/")+pin.name+".bin");
  Payload p;p.pin=&pin;ExpectedImage expected{pin.bytes,pin.sha};
  if(std::string(pin.name)=="super")p.sparse=std::make_unique<CheckedSparse>(fd,range.offset,range.bytes,expected);
  else{Need(range.bytes==pin.bytes,"Image length mismatch");p.raw=std::make_unique<CheckedRaw>(fd,range.offset,expected);}
  out.push_back(std::move(p));
 }return out;
}
const g::Node&Named(const g::Inventory& inv,const std::string&n){for(auto&x:inv.nodes)if(x.kind==g::Kind::Partition&&x.partition==n)return x;throw std::runtime_error("Missing partition "+n);}
class Device;
class Lease:public b::ExclusionLease{Device&d_;uint64_t last_=0;public:explicit Lease(Device&d):d_(d){}b::LeaseScope Scope()const override{return b::LeaseScope::ReviewedDevice;}bool Recheck(const b::FileIdentity&,const std::string&)override;};
class Topology:public b::TopologyLease{Device&d_;public:explicit Topology(Device&d):d_(d){}bool Recheck(const b::Observation&,const std::string&)override;};
class Device{
 int fd_;b::PinnedSource source_;ri3crypto::ZipVerificationReceipt sig_;Message message_;Progress progress_;
 std::unique_ptr<b::DmAdapter>mapper_=b::NewLibDmAdapter();std::unique_ptr<sn::MetadataLease>metadata_;
 std::vector<Payload>payloads_;std::set<std::string>targets_;std::vector<g::Extent>source_extents_;
 std::map<std::string,std::string>protected_hashes_;pid_t parent_=getppid();
 std::map<std::string,std::unique_ptr<b::HeldReadTarget>>held_;uint64_t sequence_=0;
 public:b::Observation observation_;g::Inventory inventory_;
 Device(int fd,const Message&m,const Progress&p,const ri3crypto::ZipVerificationReceipt&sig):fd_(fd),source_(fd),sig_(sig),message_(m),progress_(p){}
 std::string Path(const std::string&n){for(auto&p:observation_.physical)if(p.partition==n)return p.device_path;throw std::runtime_error("No physical path "+n);}
 void Parent(){
  Need(getppid()==parent_,"Recovery parent changed");
  Fd actual(open(("/proc/"+std::to_string(parent_)+"/exe").c_str(),O_RDONLY|O_CLOEXEC));
  Fd named(open("/system/bin/recovery",O_RDONLY|O_CLOEXEC));Need(actual.n>=0&&named.n>=0,"Not a normal recovery session");
  Need(b::InspectFd(actual.n).SameContentVersion(b::InspectFd(named.n)),"Updater not launched by running recovery");
#ifdef __ANDROID__
  char v[PROP_VALUE_MAX]{};__system_property_get("ro.product.device",v);Need(std::string(v)=="peridot","Wrong device");
  Fd config(open("/proc/bootconfig",O_RDONLY|O_CLOEXEC));Need(config.n>=0,"Bootloader state unavailable");char buf[32768]{};auto length=read(config.n,buf,sizeof(buf)-1);Need(length>0&&length<sizeof(buf)-1,"Invalid boot parameters");std::string boot(buf,length);Need(boot.find("androidboot.verifiedbootstate = \"orange\"")!=std::string::npos,"Unlocked bootloader required");
#endif
 }
 void Source(){source_.Recheck();std::string e;Need(ri3crypto::ReceiptMatchesFd(fd_,sig_,&e),"Source package changed: "+e);Parent();}
 void Collect(){observation_=b::CollectLinux("/sys","/proc",*mapper_);inventory_=b::BuildInventory(observation_);}
 void Snapshots(){auto m=metadata_->Read(inventory_);auto h=sn::QueryPinnedRecoveryHal();Need(m.state==sn::State::None&&m.readable&&m.inspectable&&m.exact_mount&&m.clean_complete,"OTA/snapshot metadata not clean: "+m.error);Need(h.state==sn::State::None&&h.complete&&h.pinned_contract,"Snapshot HAL check failed: "+h.error);}
 void State(bool allow_maps){
  Source();Collect();Snapshots();
  Need(inventory_.partitions_complete==g::Truth::Yes&&inventory_.mappings_complete==g::Truth::Yes&&inventory_.mounts_complete==g::Truth::Yes,"Incomplete topology");
  auto source=source_.Describe(inventory_);Need(source.extents.size()==source_extents_.size(),"Source backing changed");
  for(size_t i=0;i<source.extents.size();++i)Need(source.extents[i].disk==source_extents_[i].disk&&source.extents[i].begin==source_extents_[i].begin&&source.extents[i].bytes==source_extents_[i].bytes,"Source extent changed");
  std::vector<g::Extent>all;
  for(auto&p:payloads_){std::string name=p.pin->name;std::string target=name=="super"?name:name+"_a";auto&n=Named(inventory_,target);Need(n.identity_verified==g::Truth::Yes&&n.capacity>=p.pin->bytes,"Target identity/capacity: "+target);held_.at(target)->Bind(const_cast<g::Node&>(n));all.insert(all.end(),n.extents.begin(),n.extents.end());}
  Need(!Intersect(source.extents,all),"ZIP storage overlaps installation targets");
  for(auto&n:inventory_.nodes)if(Intersect(n.extents,all)){
   if(n.kind==g::Kind::Partition){Need(n.mounted==g::Truth::No,"Physical target is mounted");continue;}
   Need(allow_maps&&(n.kind==g::Kind::Linear||(n.kind==g::Kind::Verity&&n.read_only==g::Truth::Yes)),"Active mapping overlaps write target");
  }
 }
 void Prepare(){
  // Probe live storage/device-mapper state before the expensive full payload scan,
  // then collect again afterwards so no topology observation is carried across it.
  if(message_)message_("Checking live storage topology before image verification...");
  Source();Collect();package::Package zip(fd_);if(message_)message_("Checking every image before any write...");payloads_=ValidatePayloads(fd_,zip,message_);Source();Collect();
  for(auto&p:payloads_){std::string n=p.pin->name;n=n=="super"?n:n+"_a";targets_.insert(n);}
  for(auto&n:inventory_.nodes)if(n.kind==g::Kind::Partition&&(targets_.count(n.partition)||n.partition.size()>2&&n.partition.substr(n.partition.size()-2)=="_b")){
   Fd f(open(Path(n.partition).c_str(),O_RDONLY|O_CLOEXEC|O_NONBLOCK));Need(f.n>=0,"Cannot inspect "+n.partition);held_[n.partition]=std::make_unique<b::HeldReadTarget>(f.n,n);
   if(!targets_.count(n.partition))protected_hashes_[n.partition]=HashFdRange(f.n,0,n.capacity);
  }
  source_extents_=source_.Describe(inventory_).extents;metadata_=std::make_unique<sn::MetadataLease>(inventory_);State(true);
 }
 void Unmount(){
  auto s=source_.Describe(inventory_);s.content_verified=g::Truth::Yes;Topology lease(*this);auto ops=b::NewNormalUnmountOps();
  g::Binding binding{"RI4",std::to_string(parent_),sig_.certificate_der_sha256,++sequence_,1};
  auto r=b::PrepareUnmountsChecked(binding,observation_,s,*ops,lease,[&]{return b::CollectLinux("/sys","/proc",*mapper_);});Need(r.status==g::Status::Known,"Cannot safely unmount targets: "+r.error);
  for(;;){State(true);const auto&super=Named(inventory_,"super");std::vector<std::string>order;
   for(auto&n:inventory_.nodes){
    if(n.kind==g::Kind::Partition||!Intersect(n.extents,super.extents))continue;
    Need(n.mounted==g::Truth::No&&n.open_count&&*n.open_count==0,"Target mapping still in use");
    bool child=false;for(auto&c:inventory_.nodes)if(std::find(c.dependencies.begin(),c.dependencies.end(),n.id)!=c.dependencies.end())child=true;
    if(!child)order.push_back(n.id);
   }
   if(order.empty()){State(false);break;}
   b::RemoveMappingChecked(order.front(),{order.front()},observation_,*mapper_,lease,[&]{return b::CollectLinux("/sys","/proc",*mapper_);});
  }
 }
 void Protect(){Collect();for(auto&p:protected_hashes_){auto&n=Named(inventory_,p.first);held_.at(p.first)->Bind(const_cast<g::Node&>(n));Need(HashFdRange(held_.at(p.first)->Fd(),0,n.capacity)==p.second,"Preserved B partition changed: "+p.first);}}
 void WriteAll(){
  // Compiled plan is super, firmware, complete boot stack, recovery, vbmeta_system, vbmeta.
  ri4::VerifiedSequence(payloads_.size(),[&](size_t){State(false);},[&](size_t i){auto&p=payloads_.at(i);std::string target=p.pin->name;target=target=="super"?target:target+"_a";
   if(message_)message_("Writing and reading back "+target);
   Fd fd(open(Path(target).c_str(),O_RDWR|O_CLOEXEC|O_EXCL));Need(fd.n>=0,"Cannot exclusively open "+target);auto id=b::CheckTargetFd(fd.n,Named(inventory_,target));Lease lease(*this);b::IoOps io;b::PinnedOutputSink sink(fd.n,id,lease,io);
   if(p.sparse)p.sparse->Apply(sink,progress_);else p.raw->Apply(sink,progress_);
  },[&]{Protect();State(false);auto s=sn::RunPinnedBootctl(sn::BootctlCommand::SetActiveBootSlotA);Need(s.complete&&s.pinned_contract,"Could not select A: "+s.error);auto a=sn::RunPinnedBootctl(sn::BootctlCommand::GetActiveBootSlot);Need(a.complete&&a.pinned_contract&&a.stdout_text=="0\n","Active slot A not confirmed");});
 }
};
bool Lease::Recheck(const b::FileIdentity&,const std::string&){try{d_.Source();auto now=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();if(!last_||now-last_>=1000){d_.State(false);last_=now;}return true;}catch(...){return false;}}
bool Topology::Recheck(const b::Observation&,const std::string&){try{d_.State(true);return true;}catch(...){return false;}}
}
Result VerifyHeldPayloads(int fd){Result r;try{struct stat s{};Need(fstat(fd,&s)==0&&S_ISREG(s.st_mode)&&s.st_size>0,"Package must be regular");ri3crypto::ZipVerificationReceipt sig;std::string e;Need(ri3crypto::VerifyZipFd(fd,s.st_size,&sig,&e),"Signature invalid: "+e);package::Package zip(fd);auto p=ValidatePayloads(fd,zip);Need(ri3crypto::ReceiptMatchesFd(fd,sig,&e),"Source changed");r.success=true;}catch(const std::exception&e){r.error=e.what();}return r;}
Result InstallHeldPackage(int fd,const Message&m,const Progress&p,const ri3crypto::ZipVerificationReceipt*sig){
 Result r;
#ifndef __ANDROID__
 (void)fd;(void)m;(void)p;(void)sig;r.error="Device installation unavailable in host build";
#else
 try{Need(sig&&sig->verified,"Unverified package");Device d(fd,m,p,*sig);d.Prepare();r.mutations_started=true;d.Unmount();d.WriteAll();r.success=true;}catch(const std::exception&e){r.error=e.what();}
#endif
 return r;
}
}
