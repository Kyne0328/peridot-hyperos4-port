// SPDX-License-Identifier: Apache-2.0
#include "storage_backend.h"
#include <algorithm>
#include <cerrno>
#include <fcntl.h>
#include <limits>
#include <linux/fs.h>
#include <sstream>
#include <stdexcept>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

namespace ri3::backend {
namespace {
[[noreturn]] void Fail(const char* why) { throw std::runtime_error(why); }
uint64_t Add(uint64_t a,uint64_t b) {
  if (a>UINT64_MAX-b) Fail("range_overflow"); return a+b;
}
int Dup(int fd) {
  int copy=fcntl(fd,F_DUPFD_CLOEXEC,3);
  if(copy<0) Fail("descriptor_duplicate_failed"); return copy;
}
}
bool FileIdentity::SameObject(const FileIdentity& b) const {
  return device==b.device&&inode==b.inode&&special==b.special&&capacity==b.capacity&&type==b.type;
}
bool FileIdentity::SameContentVersion(const FileIdentity& b) const {
  return SameObject(b)&&mtime_sec==b.mtime_sec&&mtime_nsec==b.mtime_nsec&&
    ctime_sec==b.ctime_sec&&ctime_nsec==b.ctime_nsec;
}
FileIdentity InspectFd(int fd) {
  struct stat s{};
  if(fstat(fd,&s)) Fail("fstat_failed");
  FileIdentity i;
  i.device=s.st_dev; i.inode=s.st_ino; i.special=s.st_rdev; i.type=s.st_mode&S_IFMT;
  i.mtime_sec=s.st_mtim.tv_sec; i.mtime_nsec=s.st_mtim.tv_nsec;
  i.ctime_sec=s.st_ctim.tv_sec; i.ctime_nsec=s.st_ctim.tv_nsec;
  if(S_ISREG(s.st_mode)) {
    if(s.st_size<0) Fail("negative_file_size"); i.capacity=static_cast<uint64_t>(s.st_size);
  } else if(S_ISBLK(s.st_mode)) {
    if(ioctl(fd,BLKGETSIZE64,&i.capacity)) Fail("block_capacity_failed");
  } else Fail("unsupported_descriptor_type");
  if(!i.capacity||i.capacity>static_cast<uint64_t>(INT64_MAX)) Fail("invalid_capacity");
  return i;
}
FileIdentity CheckTargetFd(int fd,const guard::Node& n) {
  auto i=InspectFd(fd);
  if(i.type!=S_IFBLK||n.kind!=guard::Kind::Partition||n.identity_verified!=guard::Truth::Yes||
     DeviceId(major(i.special),minor(i.special))!=n.id||i.capacity!=n.capacity)
    Fail("target_fd_sysfs_identity_or_capacity");
  return i;
}
ssize_t IoOps::Read(int fd,void*b,size_t n,uint64_t o) const { return pread(fd,b,n,static_cast<off_t>(o)); }
ssize_t IoOps::Write(int fd,const void*b,size_t n,uint64_t o) { return pwrite(fd,b,n,static_cast<off_t>(o)); }
int IoOps::Sync(int fd) { return fsync(fd); }
PinnedOutputSink::PinnedOutputSink(int fd,const FileIdentity&e,ExclusionLease&l,IoOps&i)
  :expected_(e),lease_(l),io_(i) {
  if(!e.SameObject(InspectFd(fd))) Fail("target_identity_mismatch");
  if((e.type==S_IFREG&&l.Scope()!=LeaseScope::RegularFileFixture)||
     (e.type==S_IFBLK&&l.Scope()!=LeaseScope::ReviewedDevice)) Fail("wrong_exclusion_scope");
  int flags=fcntl(fd,F_GETFL);
  if(flags<0||(flags&O_ACCMODE)!=O_RDWR||(flags&O_APPEND)) Fail("target_requires_readwrite_nonappend_fd");
  fd_=Dup(fd);
  try { Check("adopt"); } catch(...) { close(fd_); fd_=-1; throw; }
}
PinnedOutputSink::~PinnedOutputSink() { if(fd_>=0) close(fd_); }
void PinnedOutputSink::Check(const char* phase) const {
  if(failed_) Fail("sink_failed");
  try {
    if(!expected_.SameObject(InspectFd(fd_))) Fail("target_changed");
    if(!lease_.Recheck(expected_,phase)) Fail("exclusion_or_guard_recheck_failed");
  } catch(...) { failed_=true; throw; }
}
void PinnedOutputSink::Range(uint64_t o,size_t n) const {
  if(o>expected_.capacity||n>expected_.capacity-o) {failed_=true;Fail("target_range");}
}
uint64_t PinnedOutputSink::Capacity() const { Check("capacity"); return expected_.capacity; }
void PinnedOutputSink::Write(uint64_t o,const void*b,size_t n) {
  Range(o,n); Check("before_write");
  try {
    const auto*p=static_cast<const unsigned char*>(b); size_t done=0;
    if(n&&!b) Fail("null_write_buffer");
    while(done<n) {
      Check("write_chunk");
      size_t count=std::min<size_t>(n-done,1U<<20);
      ssize_t r=io_.Write(fd_,p+done,count,Add(o,done));
      if(r<0&&errno==EINTR) continue;
      if(r<=0||static_cast<size_t>(r)>count) Fail("short_or_failed_write");
      done+=static_cast<size_t>(r);
    }
    Check("after_write");
  } catch(...) { failed_=true; throw; }
}
void PinnedOutputSink::Read(uint64_t o,void*b,size_t n) const {
  Range(o,n); Check("before_readback");
  try {
    auto*p=static_cast<unsigned char*>(b); size_t done=0;
    if(n&&!b) Fail("null_read_buffer");
    while(done<n) {
      Check("readback_chunk");
      size_t count=std::min<size_t>(n-done,1U<<20);
      ssize_t r=io_.Read(fd_,p+done,count,Add(o,done));
      if(r<0&&errno==EINTR) continue;
      if(r<=0||static_cast<size_t>(r)>count) Fail("short_or_failed_readback");
      done+=static_cast<size_t>(r);
    }
    Check("after_readback");
  } catch(...) { failed_=true; throw; }
}
void PinnedOutputSink::Sync() {
  Check("before_fsync");
  try {
    int r; do { r=io_.Sync(fd_); } while(r<0&&errno==EINTR);
    if(r) Fail("fsync_failed");
    Check("after_fsync");
  } catch(...) { failed_=true; throw; }
}
PinnedSource::PinnedSource(int fd):identity_(InspectFd(fd)) {
  if(identity_.type!=S_IFREG) Fail("source_requires_regular_file");
  int flags=fcntl(fd,F_GETFL);
  if(flags<0||(flags&O_ACCMODE)==O_WRONLY) Fail("source_unreadable");
  fd_=Dup(fd);
  try { Recheck(); } catch(...) { close(fd_); fd_=-1; throw; }
}
PinnedSource::~PinnedSource(){if(fd_>=0)close(fd_);}
void PinnedSource::Recheck() const {
  if(!identity_.SameContentVersion(InspectFd(fd_))) Fail("source_identity_or_version_changed");
}
std::string DeviceId(uint64_t a,uint64_t b){return std::to_string(a)+":"+std::to_string(b);}
std::string PinnedSource::HandleId() const {
  std::ostringstream o;
  o<<"held-fd:"<<fd_<<":"<<identity_.device<<":"<<identity_.inode<<":"<<identity_.capacity<<":"
   <<identity_.mtime_sec<<":"<<identity_.mtime_nsec<<":"<<identity_.ctime_sec<<":"<<identity_.ctime_nsec;
  return o.str();
}
guard::Source PinnedSource::Describe(const guard::Inventory& inv) const {
  Recheck(); guard::Source s; s.open_handle_id=HandleId();
  s.readable=guard::Truth::Yes;
  std::string id=DeviceId(major(identity_.device),minor(identity_.device));
  for(const auto&n:inv.nodes) if(n.id==id) {
    if(n.identity_verified!=guard::Truth::Yes||n.extents_complete!=guard::Truth::Yes||
       n.dependencies_complete!=guard::Truth::Yes) Fail("source_backing_unknown");
    // Conservative superset: whole backing filesystem, not file allocation hints.
    s.dependencies={id}; s.extents=n.extents;
    s.extents_complete=s.dependencies_complete=guard::Truth::Yes; return s;
  }
  Fail("source_filesystem_not_in_block_inventory");
}
HeldReadTarget::HeldReadTarget(int fd,const guard::Node&n):original_(n),identity_(CheckTargetFd(fd,n)){
  int flags=fcntl(fd,F_GETFL);
  if(flags<0||(flags&O_ACCMODE)!=O_RDONLY)Fail("read_target_requires_readonly_fd");
  fd_=Dup(fd);
}
HeldReadTarget::~HeldReadTarget(){if(fd_>=0)close(fd_);}
void HeldReadTarget::Bind(guard::Node&n)const{
  if(!identity_.SameObject(CheckTargetFd(fd_,n))||n.id!=original_.id||
     n.partition!=original_.partition||n.extents.size()!=original_.extents.size())Fail("held_target_changed");
  for(size_t j=0;j<n.extents.size();++j){const auto&a=n.extents[j];const auto&b=original_.extents[j];
    if(a.disk!=b.disk||a.begin!=b.begin||a.bytes!=b.bytes)Fail("held_target_extents_changed");}
  n.read_handle_id="physical-held-fd:"+std::to_string(fd_)+":"+n.id+":"+std::to_string(identity_.inode)+":"+std::to_string(identity_.capacity);
  n.held_identity_checked=guard::Truth::Yes;
}
bool Mapping::operator==(const Mapping&b) const {
  if(id!=b.id||name!=b.name||uuid!=b.uuid||kind!=b.kind||capacity!=b.capacity||
     open_count!=b.open_count||event!=b.event||active!=b.active||inactive!=b.inactive||
     suspended!=b.suspended||read_only!=b.read_only||verity_parameters!=b.verity_parameters||dependencies!=b.dependencies||segments.size()!=b.segments.size())return false;
  for(size_t i=0;i<segments.size();++i) {
    const auto&a=segments[i];const auto&c=b.segments[i];
    if(a.logical!=c.logical||a.bytes!=c.bytes||a.backing_offset!=c.backing_offset||a.dependency!=c.dependency)return false;
  } return true;
}
} // namespace ri3::backend
