// SPDX-License-Identifier: Apache-2.0
#pragma once
#include "../guard/guard_policy.h"
#include <cstdint>
#include <memory>
#include <string>
namespace ri3::snapshot {
enum class State { Unknown, None, Active, Error };
struct MetadataResult {
  State state=State::Unknown;
  bool readable=false, inspectable=false, exact_mount=false, clean_complete=false;
  std::string encoding, error, mount_identity;
};
struct HalResult {
  State state=State::Unknown;
  bool complete=false, pinned_contract=false, timed_out=false, reaped=false;
  int exit_code=-1;
  std::string stdout_text, stderr_text, error;
};
// Conservative parser for pinned AOSP SnapshotUpdateStatus. This is not a
// general protobuf decoder: only empty/default, field 1=0, or legacy "none".
State ParseCleanState(const std::string& bytes, std::string* encoding=nullptr);
struct MountRow { uint64_t mount_id=0, major=0, minor=0; std::string identity; };
MountRow ParseExactMetadataMount(const std::string& mountinfo);
// Opens only existing /metadata and /metadata/ota. Requires current exact
// physical metadata/f2fs mount and backend inventory. Never mounts or creates.
// Holds the upstream read-existing shared flock on ota when ota exists.
// This does not exclude unrelated privileged writers; the coordinator must
// enforce the supported single-recovery workflow and repeat Read before actions.
class MetadataLease {
 public:
  explicit MetadataLease(const guard::Inventory&);
  ~MetadataLease();
  MetadataLease(const MetadataLease&)=delete;
  MetadataLease& operator=(const MetadataLease&)=delete;
  MetadataResult Read(const guard::Inventory&);
 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};
// Fixed pinned bootctl read-only HAL query. Never called by initialization.
// Runtime invocation requires separately reviewed coordinator activation.
// bootctl is a HAL frontend, NOT an independent second authority.
enum class BootctlCommand { SnapshotMergeStatus, GetActiveBootSlot, SetActiveBootSlotA };
// SetActiveBootSlotA is a consequential production operation, called only by
// an authorized final SelectA coordinator action after verified image writes.
// GetActiveBootSlot accepts only exact slot A (0 newline). Non-snapshot command
// success leaves state Unknown; callers must use complete and pinned_contract.
HalResult RunPinnedBootctl(BootctlCommand,uint32_t timeout_ms=1500);
HalResult QueryPinnedRecoveryHal(uint32_t timeout_ms=1500);
#ifdef RI3_SNAPSHOT_TESTING
// Fixture surfaces do not set exact_mount or pinned_contract. They cannot
// become live evidence, and are absent from production object builds.
MetadataResult InspectFixtureDirectory(int metadata_fd, int inject_fault=0);
HalResult RunFixtureQuery(int executable_fd,const std::string& mode,uint32_t timeout_ms);
HalResult RunFixtureCommand(int executable_fd,const std::string& mode,BootctlCommand,uint32_t timeout_ms);
#endif
} // namespace ri3::snapshot
