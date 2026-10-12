// Apache-2.0. Host-only physical-observation adapters for the actual coordinator.
#pragma once
#ifndef RI3_FILE_FIXTURE_RUNTIME
#error "Fixture backend must not enter release compilation"
#endif
#ifdef __ANDROID__
#error "File fixture backend is host-only"
#endif
#include "../../backend/storage_backend.h"
#include "../../snapshot/snapshot_collect.h"
#include "fixture_profile.h"
namespace ri3::fixture {
struct Audit {
  unsigned observations=0,unmount_attempts=0,unmounts=0,remove_attempts=0,removals=0;
  unsigned write_calls=0,sync_calls=0,read_calls=0,slot_set_attempts=0,slot_get_attempts=0;
  uint64_t bytes_written=0;
  int active_slot=1;
  std::vector<std::string> events;
};
void Configure(const std::string& root,const std::string& fault);
const Audit& GetAudit();
std::string Path(const std::string&);
std::string DeviceProduct();
void CheckParent(pid_t expected);
namespace backend {
using ri3::backend::FileIdentity; using ri3::backend::InspectFd;
using ri3::backend::LeaseScope; using ri3::backend::ExclusionLease;
using ri3::backend::PinnedOutputSink; using ri3::backend::PinnedSource;
using ri3::backend::Observation; using ri3::backend::Physical;
using ri3::backend::Mapping; using ri3::backend::MountRecord;
using ri3::backend::DmAdapter; using ri3::backend::TopologyLease; using ri3::backend::UnmountOps;
using ri3::backend::BuildInventory; using ri3::backend::RemoveMappingChecked;
using ri3::backend::PrepareUnmountsChecked;
FileIdentity CheckTargetFd(int,const guard::Node&);
class HeldReadTarget {
 public: HeldReadTarget(int,const guard::Node&);~HeldReadTarget();
 int Fd()const{return fd_;}void Bind(guard::Node&)const;
 private:int fd_=-1;guard::Node original_;FileIdentity identity_;
};
class IoOps final:public ri3::backend::IoOps {
 public:ssize_t Read(int,void*,size_t,uint64_t)const override;
 ssize_t Write(int,const void*,size_t,uint64_t)override;int Sync(int)override;
};
Observation CollectLinux(const std::string&,const std::string&,DmAdapter&,const std::string& = "/dev/block");
std::unique_ptr<DmAdapter> NewLibDmAdapter();
std::unique_ptr<UnmountOps> NewNormalUnmountOps();
}
namespace snapshot {
using ri3::snapshot::State;using ri3::snapshot::MetadataResult;
using ri3::snapshot::HalResult;using ri3::snapshot::BootctlCommand;
class MetadataLease {public:explicit MetadataLease(const guard::Inventory&){} MetadataResult Read(const guard::Inventory&);};
HalResult QueryPinnedRecoveryHal(uint32_t=1500);
HalResult RunPinnedBootctl(BootctlCommand,uint32_t=1500);
}
}
