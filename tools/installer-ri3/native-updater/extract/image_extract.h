// Apache-2.0. Native image primitives; no device discovery or activation is present.
#pragma once
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>

namespace ri3 {
struct ExpectedImage {
  uint64_t bytes = 0;
  std::string sha256;
};
struct SparseInfo {
  uint64_t source_offset = 0;
  uint64_t source_bytes = 0;
  uint64_t expanded_bytes = 0;
  uint32_t chunks = 0;
  uint32_t crc32 = 0;
  std::string sha256;
};
// The integration layer must supply a policy-authorized sink. This module never
// opens target paths. Write/Read must complete the requested range or throw.
class OutputSink {
 public:
  virtual ~OutputSink() = default;
  virtual uint64_t Capacity() const = 0;
  virtual void Write(uint64_t offset, const void* bytes, size_t length) = 0;
  virtual void Read(uint64_t offset, void* bytes, size_t length) const = 0;
  virtual void Sync() = 0;
};
using Progress = std::function<void(uint64_t, uint64_t)>;

std::string Sha256Bytes(const void* data, size_t length);
std::string HashFdRange(int fd, uint64_t offset, uint64_t length);

// Accepts a bounded regular-file range (e.g. a ZIP_STORED member identified by
// minizip). Validates canonical sparse v1.0/4096-byte blocks, RAW + zero-FILL,
// one terminal CRC chunk, every range/size, full expanded SHA and source identity.
// DONT_CARE, nonzero FILL, extensions, gaps and trailing data are rejected.
class CheckedSparse {
 public:
  CheckedSparse(int source_fd, uint64_t offset, uint64_t length,
                const ExpectedImage& expected);
  ~CheckedSparse();
  CheckedSparse(CheckedSparse&&) noexcept;
  CheckedSparse& operator=(CheckedSparse&&) noexcept;
  CheckedSparse(const CheckedSparse&) = delete;
  CheckedSparse& operator=(const CheckedSparse&) = delete;
  const SparseInfo& Info() const;
  // Uses actual AOSP libsparse expansion. Full source/write hashes, Sync and
  // independent target readback must all pass. Any failure throws.
  void Apply(OutputSink& target, const Progress& progress = {});
 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

// Prevalidation is separate from Apply so multi-minute reads precede the
// short volatile-state authorization window. The held source descriptor survives.
class CheckedRaw {
 public:
  CheckedRaw(int source_fd, uint64_t offset, const ExpectedImage& expected);
  ~CheckedRaw();
  CheckedRaw(CheckedRaw&&) noexcept;
  CheckedRaw& operator=(CheckedRaw&&) noexcept;
  CheckedRaw(const CheckedRaw&) = delete;
  CheckedRaw& operator=(const CheckedRaw&) = delete;
  void Apply(OutputSink& target, const Progress& progress = {});
 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};
// Convenience only. Coordinators should construct CheckedRaw before authorizing.
void CopyRawVerified(int source_fd, uint64_t offset, const ExpectedImage& expected,
                     OutputSink& target, const Progress& progress = {});
}  // namespace ri3
