// SPDX-License-Identifier: Apache-2.0
#pragma once
#include "../extract/image_extract.h"
#include "../guard/guard_policy.h"
#include <memory>
#include <set>
#include <sys/types.h>
#include <vector>

namespace ri3::backend {
struct FileIdentity {
  uint64_t device=0, inode=0, special=0, capacity=0;
  int64_t mtime_sec=0, mtime_nsec=0, ctime_sec=0, ctime_nsec=0;
  uint32_t type=0;
  bool SameObject(const FileIdentity&) const;
  bool SameContentVersion(const FileIdentity&) const;
};
FileIdentity InspectFd(int fd); // fstat and BLKGETSIZE64 only
FileIdentity CheckTargetFd(int fd, const guard::Node& expected);
class IoOps {
 public:
  virtual ~IoOps()=default;
  virtual ssize_t Read(int, void*, size_t, uint64_t) const;
  virtual ssize_t Write(int, const void*, size_t, uint64_t);
  virtual int Sync(int);
};
enum class LeaseScope { RegularFileFixture, ReviewedDevice };
// A recovery coordinator must hold its supported single-writer workflow and
// revalidate observable guards. No simultaneous external privileged writer is an
// explicit deployment assumption, not a kernel guarantee. flock/O_EXCL alone do
// NOT prove arbitrary-writer exclusion. No production coordinator is supplied.
class ExclusionLease {
 public:
  virtual ~ExclusionLease()=default;
  virtual LeaseScope Scope() const=0;
  virtual bool Recheck(const FileIdentity&, const std::string& phase)=0;
};
class PinnedOutputSink final : public OutputSink {
 public:
  // Owns a duplicate of fd. Requires exact identity/capacity and a continuously
  // held authority. Never opens a pathname or acquires device authority itself.
  PinnedOutputSink(int fd, const FileIdentity& expected, ExclusionLease&, IoOps&);
  ~PinnedOutputSink();
  PinnedOutputSink(const PinnedOutputSink&)=delete;
  PinnedOutputSink& operator=(const PinnedOutputSink&)=delete;
  uint64_t Capacity() const override;
  void Write(uint64_t, const void*, size_t) override;
  void Read(uint64_t, void*, size_t) const override;
  void Sync() override;
 private:
  void Check(const char*) const;
  void Range(uint64_t,size_t) const;
  int fd_=-1;
  FileIdentity expected_;
  ExclusionLease& lease_;
  IoOps& io_;
  mutable bool failed_=false;
};
class PinnedSource {
 public:
  explicit PinnedSource(int fd);
  ~PinnedSource();
  PinnedSource(const PinnedSource&)=delete;
  PinnedSource& operator=(const PinnedSource&)=delete;
  void Recheck() const;
  int Fd() const { return fd_; }
  std::string HandleId() const;
  // Content remains Unknown. Coordinator must bind separately verified content
  // and observation windows to this held descriptor; no hash freshness invented.
  guard::Source Describe(const guard::Inventory&) const;
 private:
  int fd_=-1;
  FileIdentity identity_;
};
// Holds a physical read-only descriptor across hashing and volatile inventory
// refreshes. No method opens a pathname; coordinator supplies the checked FD.
class HeldReadTarget {
 public:
  HeldReadTarget(int fd,const guard::Node&);
  ~HeldReadTarget();
  HeldReadTarget(const HeldReadTarget&)=delete;
  HeldReadTarget& operator=(const HeldReadTarget&)=delete;
  int Fd() const { return fd_; }
  void Bind(guard::Node&) const;
 private:
  int fd_=-1;
  guard::Node original_;
  FileIdentity identity_;
};
struct Segment {
  uint64_t logical=0, bytes=0, backing_offset=0;
  std::string dependency; // exact major:minor identity
};
struct Physical {
  std::string id, partition, disk;
  uint64_t begin=0, bytes=0;
  std::vector<std::string> holders;
  std::string device_path{}; // Observed block node, matched by lstat st_rdev.
};
struct Mapping {
  std::string id, name, uuid;
  guard::Kind kind=guard::Kind::Unknown;
  uint64_t capacity=0, open_count=0, event=0;
  bool active=false, inactive=false, suspended=false, read_only=false;
  std::string verity_parameters; // Only recognized public verity grammar.
  std::vector<Segment> segments;
  std::vector<std::string> dependencies;
  bool operator==(const Mapping&) const;
};
struct MountRecord {
  uint64_t id=0,parent=0;
  std::string device,root,path,filesystem;
  bool operator==(const MountRecord&) const;
};
std::vector<MountRecord> ParseMountRecords(const std::string&);
uint64_t FdMountId(int fd,const std::string& proc_root="/proc");
void CheckMountFd(int fd,const MountRecord&);
struct Mounts {
  std::set<std::string> devices, foreign_devices;
  bool complete=false; // Complete within visible proc namespace scope only.
  std::vector<std::string> namespace_scope;
  std::vector<MountRecord> current;
  std::vector<std::string> inspection_errors;
};
struct ExcludedDevice { std::string id, reason, fingerprint; };
struct Observation {
  std::vector<Physical> physical;
  std::vector<Mapping> mappings;
  Mounts mounts;
  std::vector<ExcludedDevice> excluded; // Explicitly proven irrelevant virtual devices.
};
class DmAdapter {
 public:
  virtual ~DmAdapter()=default;
  virtual std::vector<Mapping> List()=0;
  // Immediate deletion only; no deferred remove, create, suspend or table edits.
  virtual bool Remove(const std::string& name)=0;
};
guard::Inventory BuildInventory(const Observation&);
std::set<std::string> ParseMountInfo(const std::string&);
std::string DeviceId(uint64_t major,uint64_t minor);
// Read-only Linux collection. Calls neither the live collector nor libdm during
// initialization. Physical opens remain Unknown; deployment authority is pending.
Observation CollectLinux(const std::string& sys_root, const std::string& proc_root, DmAdapter&,
                         const std::string& dev_root="/dev/block");
// Factory alone does not open /dev/device-mapper. List/Remove do. Not linked or
// invoked by the default updater. Tests use only a fake DmAdapter.
std::unique_ptr<DmAdapter> NewLibDmAdapter();
class TopologyLease {
 public:
  virtual ~TopologyLease()=default;
  virtual bool Recheck(const Observation&, const std::string& phase)=0;
};
// Requires the coordinator's classified child-first order and a full fresh
// observation callback. Independently validates linear or recognized read-only
// verity leaf, super-only backing, and zero-open state,
// exact identities, child absence, post-removal disappearance and unchanged rest.
void RemoveMappingChecked(const std::string& id, const std::vector<std::string>& approved_order,
                         const Observation& expected, DmAdapter&, TopologyLease&,
                         const std::function<Observation()>& refresh);
class UnmountOps {
 public:
  virtual ~UnmountOps()=default;
  virtual bool NormalUnmount(const MountRecord&)=0;
};
std::unique_ptr<UnmountOps> NewNormalUnmountOps();
struct UnmountReceipt {
  guard::Binding binding;
  guard::Status status=guard::Status::Unknown;
  std::string source_handle,error;
  std::vector<uint64_t> removed_mount_ids;
};
std::vector<MountRecord> PlanTargetUnmounts(const Observation&,const guard::Source&);
UnmountReceipt PrepareUnmountsChecked(const guard::Binding&,const Observation&,
  const guard::Source&,UnmountOps&,TopologyLease&,const std::function<Observation()>& refresh);
class SnapshotAuthority {
 public:
  virtual ~SnapshotAuthority()=default;
  virtual guard::Fact<guard::SnapshotEvidence> Read(const guard::Binding&)=0;
};
class PendingSnapshotAuthority final : public SnapshotAuthority {
 public:
  guard::Fact<guard::SnapshotEvidence> Read(const guard::Binding& b) override {
    guard::Fact<guard::SnapshotEvidence> f; f.binding=b; return f;
  }
};
} // namespace ri3::backend
