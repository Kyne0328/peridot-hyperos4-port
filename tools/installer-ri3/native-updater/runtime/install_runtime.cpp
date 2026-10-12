// Apache-2.0. Fixed production contract; device operations are never invoked by host tests.
#include "install_runtime.h"
#include "held_package.h"
#include "../guard/guard_policy.h"
#include "../backend/storage_backend.h"
#include "../crypto/native_zip_crypto.h"
#include "../snapshot/snapshot_collect.h"
#ifdef RI3_FILE_FIXTURE_RUNTIME
#include "fixture/fixture_backend.h"
#endif
#include <algorithm>
#include <chrono>
#include <cerrno>
#include <fcntl.h>
#include <map>
#include <memory>
#include <set>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>
#ifdef __ANDROID__
#include <sys/system_properties.h>
#endif

namespace ri3::runtime {
namespace {
namespace g=ri3::guard;
#ifdef RI3_FILE_FIXTURE_RUNTIME
namespace b=ri3::fixture::backend;
namespace sn=ri3::fixture::snapshot;
#else
namespace b=ri3::backend;
namespace sn=ri3::snapshot;
#endif
std::string PlatformPath(const std::string& path){
#ifdef RI3_FILE_FIXTURE_RUNTIME
 return ri3::fixture::Path(path);
#else
 return path;
#endif
}
void Need(bool v,const std::string& why){if(!v)throw std::runtime_error(why);}
uint64_t Now(){return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();}
std::string Hex(const ri3crypto::Digest& d){static const char h[]="0123456789abcdef";std::string s;for(auto c:d){s+=h[c>>4];s+=h[c&15];}return s;}
struct Fd {
 int value=-1;explicit Fd(int n=-1):value(n){}~Fd(){if(value>=0)close(value);}
 Fd(Fd&& o)noexcept:value(o.value){o.value=-1;}Fd&operator=(Fd&&o)noexcept{if(this!=&o){if(value>=0)close(value);value=o.value;o.value=-1;}return *this;}
 Fd(const Fd&)=delete;Fd&operator=(const Fd&)=delete;
};
std::string ReadSmall(const std::string& path,size_t limit){
 Fd fd(open(PlatformPath(path).c_str(),O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK));Need(fd.value>=0,"cannot read "+path);
 std::string out;char buf[1024];
 for(;;){ssize_t n=read(fd.value,buf,sizeof(buf));if(n<0&&errno==EINTR)continue;Need(n>=0,"read error "+path);if(!n)break;Need(static_cast<size_t>(n)<=limit-out.size(),"oversized "+path);out.append(buf,n);}
 return out;
}
std::string DeviceProduct(){
#ifdef RI3_FILE_FIXTURE_RUNTIME
 return ri3::fixture::DeviceProduct();
#elif defined(__ANDROID__)
 char value[PROP_VALUE_MAX]={};int n=__system_property_get("ro.product.device",value);Need(n>0,"device property unavailable");return std::string(value,n);
#else
 throw std::runtime_error("live device runtime is unavailable in host builds");
#endif
}
g::PairContract Pair(){
#ifdef RI3_FILE_FIXTURE_RUNTIME
 return ri3::fixture::Pair();
#else
 return {g::Status::Known,"RI3_PAIRED_RECOVERY_DECLARED_GUI_V1",
 "76b6b839b320fd4796808fe9fa7ab4c03cc4e81bbd275a7617f26a80930515c0",
 {104857600,"8ba7e1e077f31e1a345397fca9842ed1bdf39e69d1003b7bbbcde0830b65e52a"},
 {12288,"2c3ad5c1ebdf271a6c2363d5367791e52bf119683091100254143f476587777c"},
 {3123,"321427f66c7661c7eb09aef4e9ecfae4b698c2e01f84f8175d427fc55b9203a9"}};
#endif
}
const g::Node& NodeNamed(const g::Inventory& inv,const std::string& name){
 for(const auto& n:inv.nodes)if(n.kind==g::Kind::Partition&&n.partition==name)return n;
 throw std::runtime_error("physical partition missing: "+name);
}
g::Node& NodeNamed(g::Inventory& inv,const std::string& name){
 for(auto& n:inv.nodes)if(n.kind==g::Kind::Partition&&n.partition==name)return n;
 throw std::runtime_error("physical partition missing: "+name);
}
bool Protected(const std::string& n){return n=="recovery_a"||(n.size()>2&&n.substr(n.size()-2)=="_b");}
template<class T> g::Fact<T> Fact(const g::Binding& binding,const T& value){g::Fact<T> f;f.status=g::Status::Known;f.binding=binding;f.value=value;return f;}
std::string IdentityToken(const b::FileIdentity& x){
 return std::to_string(x.device)+":"+std::to_string(x.inode)+":"+std::to_string(x.special)+":"+std::to_string(x.capacity)+":"+std::to_string(x.type);
}
template<class T> g::Fact<T> Retained(g::Binding binding,const T& value,uint64_t start,uint64_t end,const std::string& handle,const std::string& token){
 binding.observed_ms=end;auto f=Fact(binding,value);f.lease=g::ContentLease{start,end,handle,token,binding,g::Truth::Yes,g::Truth::Yes};return f;
}
template<class T> void CheckedNow(g::Fact<T>& fact,const g::Binding& binding){
 Need(fact.lease.has_value(),"missing content lease");fact.lease->checked_at=binding;
}
struct RuntimeFile {
 std::string path;Fd fd;b::FileIdentity original;g::Fact<g::Digest> digest;
 RuntimeFile(const std::string& p,const g::Digest& wanted,const g::Binding& binding):path(p),fd(open(PlatformPath(p).c_str(),O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK)){
  Need(fd.value>=0,"runtime file open: "+p);original=b::InspectFd(fd.value);
  struct stat st{};Need(fstat(fd.value,&st)==0&&S_ISREG(st.st_mode)&&st.st_size>0,"runtime file is not regular: "+p);
  Need(!wanted.bytes||wanted.bytes==static_cast<uint64_t>(st.st_size),"runtime file size: "+p);
  uint64_t start=Now();g::Digest actual{static_cast<uint64_t>(st.st_size),HashFdRange(fd.value,0,st.st_size)};uint64_t end=Now();
  Need(actual.sha256==wanted.sha256,"runtime file hash: "+p);
  digest=Retained(binding,actual,start,end,"runtime:"+p,IdentityToken(original));Recheck();
 }
 void Recheck()const{
  Need(original.SameContentVersion(b::InspectFd(fd.value)),"runtime held file changed: "+path);
  Fd current(open(PlatformPath(path).c_str(),O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK));Need(current.value>=0,"runtime path disappeared: "+path);
  Need(original.SameContentVersion(b::InspectFd(current.value)),"runtime path replaced: "+path);
 }
};
struct Payload {
 g::Image image;std::unique_ptr<CheckedSparse> sparse;std::unique_ptr<CheckedRaw> raw;
 g::Fact<g::Digest> digest;
 void Apply(OutputSink& out,const Progress& progress){if(sparse)sparse->Apply(out,progress);else{Need(bool(raw),"missing raw source");raw->Apply(out,progress);}}
};
class DeviceRuntime;
class WriteLease final:public b::ExclusionLease{
 public:WriteLease(DeviceRuntime& runtime,const b::FileIdentity& identity):runtime_(runtime),identity_(identity){}
 b::LeaseScope Scope()const override{
#ifdef RI3_FILE_FIXTURE_RUNTIME
 return b::LeaseScope::RegularFileFixture;
#else
 return b::LeaseScope::ReviewedDevice;
#endif
}
 bool Recheck(const b::FileIdentity&,const std::string&)override;
 private:DeviceRuntime&runtime_;b::FileIdentity identity_;uint64_t last_state_check_=0;
};
class TopologyLease final:public b::TopologyLease{
 public:TopologyLease(DeviceRuntime& runtime,const g::Action* action):runtime_(runtime),action_(action){}
 bool Recheck(const b::Observation&,const std::string&)override;
 private:DeviceRuntime& runtime_;const g::Action* action_;
};
class DeviceRuntime {
 public:
 explicit DeviceRuntime(int source_fd,const Message& message,const Progress& progress,const ri3crypto::ZipVerificationReceipt* verified)
   :source_(source_fd),message_(message),progress_(progress),mapper_(b::NewLibDmAdapter()),supplied_(verified){}
 Result Run(){
  Result result;
  try{
   Prevalidate();
   // All cryptographic, firmware, runtime, snapshot and storage prerequisites
   // precede even the normal target-only preparation unmount operations.
   auto e=Refresh();auto before=g::preflight(manifest_,requests_,e,Now(),g::PreflightPhase::BeforeTargetUnmount);
   Need(before.ok,before.error);
   auto unmount=b::NewNormalUnmountOps();TopologyLease preparation(*this,nullptr);
   result.mutations_started=true; // Conservative: an error may follow a partial unmount.
   auto prepared=b::PrepareUnmountsChecked(e.binding,observation_,e.source.value,*unmount,preparation,[&]{return Observe();});
   Need(prepared.status==g::Status::Known,"target unmount preparation failed: "+prepared.error);
   g::Session session(manifest_,requests_);
   while(session.stage()!=g::Stage::Succeeded){
    const bool final=session.verified_writes()==manifest_.images.size();
    if(final)RehashProtected();
    e=Refresh();
    auto action=session.next(e,Now());Need(action.has_value(),"guard rejected action: "+session.error());
    g::Receipt receipt;receipt.sequence=action->sequence;receipt.generation=action->generation;receipt.binding=action->binding;
    receipt.kind=action->kind;receipt.subject=action->subject;
    // Refresh immediately before entering the actual kernel operation.
    CheckAction(*action);
    receipt.started_ms=Now();Need(receipt.started_ms<=action->expires_ms,"action authorization expired");
    if(action->kind==g::ActionKind::RemoveMapping){
     TopologyLease lease(*this,&*action);
     auto approved=g::preflight(manifest_,requests_,latest_,Now());Need(approved.ok,"teardown recheck failed");
     b::RemoveMappingChecked(action->subject,approved.teardown_order,observation_,*mapper_,lease,[&]{return Observe();});
    }else if(action->kind==g::ActionKind::WriteImage){
     const auto& node=NodeNamed(latest_.inventory.value,action->subject);
     const auto path=DevicePath(action->subject);
     Fd fd(open(path.c_str(),O_RDWR|O_CLOEXEC|O_EXCL));Need(fd.value>=0,"exclusive target open failed: "+action->subject);
     auto id=b::CheckTargetFd(fd.value,node);WriteLease lease(*this,id);b::IoOps io;
     b::PinnedOutputSink output(fd.value,id,lease,io);
     Payload& payload=payloads_.at(action->subject);
     if(message_)message_("Writing and verifying "+action->subject);
     payload.Apply(output,progress_);
     // Apply returns only after actual source-stream digest, fsync and complete
     // independent target readback match these exact immutable expected bytes.
     receipt.transferred=payload.image.bytes;receipt.fsync_ok=g::Truth::Yes;
     receipt.source_digest={payload.image.bytes,payload.image.sha256};receipt.readback_digest=receipt.source_digest;
    }else if(action->kind==g::ActionKind::SelectA){
     auto set=sn::RunPinnedBootctl(sn::BootctlCommand::SetActiveBootSlotA);
     Need(set.complete&&set.pinned_contract,"set-active-boot-slot failed or ambiguous: "+set.error);
     auto active=sn::RunPinnedBootctl(sn::BootctlCommand::GetActiveBootSlot);
     Need(active.complete&&active.pinned_contract&&active.stdout_text=="0\n","active slot A not confirmed");
     receipt.slot_a_confirmed=g::Truth::Yes;
    }else throw std::runtime_error("unsupported action");
    receipt.completed_ms=Now();receipt.status=g::Status::Known;receipt.complete=g::Truth::Yes;
    receipt.guard_revalidated=receipt.target_state_held=receipt.source_readable_throughout=g::Truth::Yes;
    Need(session.complete(receipt),"action receipt rejected: "+session.error());
   }
   result.success=true;
  }catch(const std::exception& error){result.error=error.what();}
  return result;
 }
 void RecheckWriteState(){
  auto e=Refresh();auto check=g::preflight(manifest_,requests_,e,Now());
  Need(check.ok&&check.teardown_order.empty(),"observed target state changed during image I/O");
 }
 void RecheckSource()const{
  source_.Recheck();std::string error;Need(ri3crypto::ReceiptMatchesFd(source_.Fd(),signature_,&error),"held signed package changed: "+error);
 }
 bool SafeSameTopology(const b::Observation& observation,const g::Action* action){
  // Any backend-observed change is checked through the same complete collector.
  observation_=observation;
  auto e=Refresh();
  auto check=g::preflight(manifest_,requests_,e,Now(),action?g::PreflightPhase::Writes:g::PreflightPhase::BeforeTargetUnmount);
  if(!check.ok)return false;
  if(action&&action->kind==g::ActionKind::RemoveMapping){
   bool exists=std::any_of(e.inventory.value.nodes.begin(),e.inventory.value.nodes.end(),[&](const g::Node& n){return n.id==action->subject;});
   // Backend separately proves whether this callback is before/after removal.
   return !exists||(!check.teardown_order.empty()&&check.teardown_order.front()==action->subject);
  }
  return true;
 }
 private:
 b::PinnedSource source_;Message message_;Progress progress_;std::unique_ptr<b::DmAdapter> mapper_;
 const ri3crypto::ZipVerificationReceipt* supplied_=nullptr;
 ri3crypto::ZipVerificationReceipt signature_{};std::unique_ptr<package::Package> package_;
 g::Manifest manifest_;std::vector<g::Request> requests_;g::Binding context_;uint64_t generation_=0;pid_t parent_=0;
 std::map<std::string,std::unique_ptr<b::HeldReadTarget>> held_;
 std::map<std::string,std::unique_ptr<RuntimeFile>> runtime_;
 std::map<std::string,Payload> payloads_;
 std::unique_ptr<sn::MetadataLease> metadata_;
 b::Observation observation_;g::Evidence slow_,latest_;
 std::string DevicePath(const std::string& partition)const{
  for(const auto& p:observation_.physical)if(p.partition==partition){Need(!p.device_path.empty(),"no observed block node: "+partition);return p.device_path;}
  throw std::runtime_error("observed target missing: "+partition);
 }
 b::Observation Observe(){return b::CollectLinux("/sys","/proc",*mapper_);}
 g::Fact<g::Digest> HashTarget(const std::string& name,uint64_t bytes,const g::Inventory& inv){
  auto& hold=*held_.at(name);const auto& node=NodeNamed(inv,name);
  Need(bytes<=node.capacity,"hash prefix exceeds target");uint64_t start=Now();
  g::Digest digest{bytes,HashFdRange(hold.Fd(),0,bytes)};uint64_t end=Now();
  auto copy=node;hold.Bind(copy);
  return Retained(context_,digest,start,end,copy.read_handle_id,IdentityToken(b::InspectFd(hold.Fd())));
 }
 void Prevalidate(){
  struct stat stat{};Need(fstat(source_.Fd(),&stat)==0&&S_ISREG(stat.st_mode)&&stat.st_size>0,"package is not a regular file");
  std::string error;
  if(supplied_){
   Need(supplied_->verified,"unverified package receipt");
   Need(ri3crypto::ReceiptMatchesFd(source_.Fd(),*supplied_,&error),"signed package receipt changed: "+error);
   signature_=*supplied_;
  }else Need(ri3crypto::VerifyZipFd(source_.Fd(),stat.st_size,&signature_,&error),"whole-ZIP signature failed: "+error);
  Need(signature_.verified,"missing native signature receipt");
  context_.package=Hex(signature_.full_file_sha256);context_.boot=ReadSmall("/proc/sys/kernel/random/boot_id",80);
  Need(!context_.boot.empty(),"boot session unavailable");context_.session=context_.boot+":"+std::to_string(getpid())+":"+std::to_string(Now());context_.generation=1;
  manifest_=g::production_manifest(context_.package,Pair());
  for(const auto& im:manifest_.images)requests_.push_back({g::RequestKind::Write,im.partition});
  parent_=getppid();Need(parent_>1,"normal recovery parent missing");
  Need(DeviceProduct()=="peridot","unsupported device");
  package_=std::make_unique<package::Package>(source_.Fd());
  auto package_identity=b::InspectFd(source_.Fd());
  g::ZipVerification zip{{static_cast<uint64_t>(stat.st_size),context_.package},signature_.signed_bytes,signature_.certificate_der_sha256,source_.HandleId(),g::Truth::Yes};
  slow_.zip_signature=Retained(context_,zip,signature_.read_started_monotonic_ns/1000000,signature_.read_completed_monotonic_ns/1000000,source_.HandleId(),IdentityToken(package_identity));
  for(const auto& im:manifest_.images){
   std::string base=im.partition=="super"?"super":im.partition.substr(0,im.partition.size()-2);
   auto range=package_->CheckedStoredRange("images/"+base+".img");Payload payload;payload.image=im;
   uint64_t start=Now();ExpectedImage expected{im.bytes,im.sha256};
#ifdef RI3_FILE_FIXTURE_RUNTIME
   std::fprintf(stderr,"fixture payload %s bytes=%llu sha=%s range=%llu/%llu\n",im.partition.c_str(),static_cast<unsigned long long>(expected.bytes),expected.sha256.c_str(),static_cast<unsigned long long>(range.offset),static_cast<unsigned long long>(range.bytes));
#endif
   if(im.partition=="super")payload.sparse=std::make_unique<CheckedSparse>(source_.Fd(),range.offset,range.bytes,expected);
   else{Need(range.bytes==im.bytes,"raw member size: "+im.partition);payload.raw=std::make_unique<CheckedRaw>(source_.Fd(),range.offset,expected);}
   uint64_t end=Now();payload.digest=Retained(context_,g::Digest{im.bytes,im.sha256},start,end,source_.HandleId(),IdentityToken(package_identity));
   slow_.payloads[im.partition]=payload.digest;payloads_.emplace(im.partition,std::move(payload));
  }
  // The full expanded hash binds the already-audited A-populated/B-empty image.
  auto super=payloads_.at("super").digest;
  slow_.layout=Retained(context_,g::Layout{{g::kSuperBytes,g::super_sha256()},g::Truth::Yes,g::Truth::Yes},super.lease->started_ms,super.lease->completed_ms,source_.HandleId(),IdentityToken(package_identity));
  for(const auto& p:g::recovery_pins(manifest_.pair))if(p.first!="recovery_a")
   runtime_.emplace(p.first,std::make_unique<RuntimeFile>(p.first,p.second,context_));
  CheckParent();
  observation_=Observe();auto inv=b::BuildInventory(observation_);
  std::set<std::string> names;
  for(const auto& im:manifest_.images)names.insert(im.partition);
  for(const auto& fw:g::firmware_pins())names.insert(fw.first);
  for(const auto& n:inv.nodes)if(n.kind==g::Kind::Partition&&Protected(n.partition))names.insert(n.partition);
  for(const auto& name:names){
   const auto path=DevicePath(name);Fd fd(open(path.c_str(),O_RDONLY|O_CLOEXEC|O_NONBLOCK));
   Need(fd.value>=0,"read-only partition open failed: "+name);
   held_.emplace(name,std::make_unique<b::HeldReadTarget>(fd.value,NodeNamed(inv,name)));
   held_.at(name)->Bind(NodeNamed(inv,name));
  }
  for(const auto& fw:g::firmware_pins()){
   auto digest=HashTarget(fw.first,fw.second.bytes,inv);
   Need(digest.value.sha256==fw.second.sha256,"Global firmware prefix mismatch: "+fw.first);
   slow_.firmware.emplace(fw.first,std::move(digest));
  }
  for(const auto& n:inv.nodes)if(n.kind==g::Kind::Partition&&Protected(n.partition))
   slow_.protected_partitions[n.partition]=HashTarget(n.partition,n.capacity,inv);
  slow_.recovery["recovery_a"]=slow_.protected_partitions.at("recovery_a");
  for(const auto& p:runtime_)slow_.recovery[p.first]=p.second->digest;
  metadata_=std::make_unique<sn::MetadataLease>(inv);
  RecheckSource();
 }
 void CheckParent()const{
#ifdef RI3_FILE_FIXTURE_RUNTIME
  ri3::fixture::CheckParent(parent_);return;
#else
  Need(getppid()==parent_,"recovery parent changed");
  auto it=runtime_.find("/system/bin/recovery");Need(it!=runtime_.end(),"recovery runtime pin missing");
  std::string path="/proc/"+std::to_string(parent_)+"/exe";
  Fd fd(open(path.c_str(),O_RDONLY|O_CLOEXEC));Need(fd.value>=0,"parent executable unavailable");
  Need(it->second->original.SameContentVersion(b::InspectFd(fd.value)),"parent is not pinned running recovery executable");
#endif
 }
 void AbsentHook(const std::string& path)const{
  struct stat st{};errno=0;int r=lstat(PlatformPath(path).c_str(),&st);
  Need(r==-1&&errno==ENOENT,"unexpected or unreadable recovery hook: "+path);
 }
 g::Evidence Refresh(){
  const uint64_t started=Now();observation_=Observe();auto inv=b::BuildInventory(observation_);
  for(const auto& h:held_)h.second->Bind(NodeNamed(inv,h.first));
  // This is a documented supported-workflow assumption, not kernel-wide attestation.
  inv.single_recovery_workflow=g::Truth::Yes;
  RecheckSource();for(const auto& file:runtime_)file.second->Recheck();CheckParent();
  AbsentHook("/sbin/afterromflash.sh");AbsentHook("/system/bin/afterromflash.sh");
  Need(DeviceProduct()=="peridot","device property changed");
  auto metadata=metadata_->Read(inv);auto hal=sn::QueryPinnedRecoveryHal();
  Need(metadata.state==sn::State::None&&metadata.readable&&metadata.inspectable&&metadata.exact_mount&&metadata.clean_complete,"snapshot metadata unsafe: "+metadata.error);
  Need(hal.state==sn::State::None&&hal.complete&&hal.pinned_contract,"snapshot HAL unsafe: "+hal.error);
  g::Binding binding=context_;binding.generation=++generation_;binding.observed_ms=started;
  g::Evidence e=slow_;e.binding=binding;
  e.identity=Fact(binding,g::Identity{"peridot",runtime_.at("/system/bin/recovery")->digest.value.sha256,manifest_.pair.version,manifest_.pair.record_sha256,g::Truth::Yes,g::Truth::Yes});
  e.afterromflash=Fact(binding,g::Absence::NoEntry);
  e.snapshot=Fact(binding,g::SnapshotEvidence{g::SnapshotValue::None,g::SnapshotValue::None,g::Truth::Yes,g::Truth::Yes,g::Truth::Yes,g::Truth::Yes,g::Truth::Yes});
  e.inventory=Fact(binding,inv);auto source=source_.Describe(inv);source.content_verified=g::Truth::Yes;e.source=Fact(binding,source);
  CheckedNow(e.zip_signature,binding);CheckedNow(e.layout,binding);
  for(auto* map:{&e.recovery,&e.firmware,&e.payloads,&e.protected_partitions})for(auto& f:*map)CheckedNow(f.second,binding);
  Need(Now()-started<=g::kMaxEvidenceAgeMs,"volatile collection exceeded freshness budget");
  latest_=e;return e;
 }
 void RehashProtected(){
  observation_=Observe();auto inv=b::BuildInventory(observation_);
  for(const auto& h:held_)h.second->Bind(NodeNamed(inv,h.first));
  for(auto& p:slow_.protected_partitions){
   auto current=HashTarget(p.first,NodeNamed(inv,p.first).capacity,inv);
   Need(current.value.sha256==p.second.value.sha256,"protected partition changed: "+p.first);
   p.second=std::move(current);
  }
  slow_.recovery["recovery_a"]=slow_.protected_partitions.at("recovery_a");
 }
 void CheckAction(const g::Action& action){
  auto e=Refresh();auto check=g::preflight(manifest_,requests_,e,Now());Need(check.ok,check.error);
  Need(Now()<=action.expires_ms,"action expired during revalidation");
  if(action.kind==g::ActionKind::RemoveMapping)Need(!check.teardown_order.empty()&&check.teardown_order.front()==action.subject,"mapping action changed");
  else Need(check.teardown_order.empty(),"new target mapping appeared");
 }
 friend class WriteLease;friend class TopologyLease;
};
bool WriteLease::Recheck(const b::FileIdentity& identity,const std::string&){
 try{
  Need(identity_.SameObject(identity),"write target identity changed");runtime_.RecheckSource();
  uint64_t now=Now();if(!last_state_check_||now-last_state_check_>=1000){runtime_.RecheckWriteState();last_state_check_=Now();}
  return true;
 }catch(...){return false;}
}
bool TopologyLease::Recheck(const b::Observation& observation,const std::string&){
 try{return runtime_.SafeSameTopology(observation,action_);}catch(...){return false;}
}
} // namespace
Result InstallHeldPackage(int fd,const Message& message,const Progress& progress,const ri3crypto::ZipVerificationReceipt* verified){
#if !defined(__ANDROID__) && !defined(RI3_FILE_FIXTURE_RUNTIME)
 (void)fd;(void)message;(void)progress;(void)verified;
 return {false,false,"live device installation is disabled in host builds"};
#else
 DeviceRuntime runtime(fd,message,progress,verified);return runtime.Run();
#endif
}
Result VerifyHeldPayloads(int fd){
 Result result;
 try{
  struct stat st{};Need(fstat(fd,&st)==0&&S_ISREG(st.st_mode)&&st.st_size>0,"verification requires a regular package");
  ri3crypto::ZipVerificationReceipt signature;std::string error;
  Need(ri3crypto::VerifyZipFd(fd,st.st_size,&signature,&error),"whole-ZIP signature failed: "+error);
  package::Package zip(fd);auto manifest=g::production_manifest(Hex(signature.full_file_sha256),Pair());
  for(const auto& image:manifest.images){
   std::string name=image.partition=="super"?"super":image.partition.substr(0,image.partition.size()-2);
   auto range=zip.CheckedStoredRange("images/"+name+".img");ExpectedImage expected{image.bytes,image.sha256};
   if(image.partition=="super"){CheckedSparse checked(fd,range.offset,range.bytes,expected);}
   else{Need(range.bytes==image.bytes,"raw member size: "+name);CheckedRaw checked(fd,range.offset,expected);}
  }
  Need(ri3crypto::ReceiptMatchesFd(fd,signature,&error),"package changed during validation: "+error);
  result.success=true;
 }catch(const std::exception& e){result.error=e.what();}
 return result;
}
} // namespace ri3::runtime
