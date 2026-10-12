// Apache-2.0. No device paths, mount calls, ioctls or process execution.
#include "image_extract.h"
#include <mbedtls/sha256.h>
#include <sparse/sparse.h>
#include <zlib.h>
#include <algorithm>
#include <array>
#include <cerrno>
#include <climits>
#include <cstring>
#include <exception>
#include <fcntl.h>
#include <stdexcept>
#include <vector>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

namespace ri3 {
namespace {
constexpr size_t kBuffer = 1024 * 1024;
constexpr uint32_t kBlock = 4096;
constexpr uint32_t kMaxChunks = 100000;
void Require(bool value, const char* message) {
  if (!value) throw std::runtime_error(message);
}
void CheckExpected(const ExpectedImage& expected) {
  Require(expected.bytes > 0 && expected.bytes <= INT64_MAX, "invalid expected image size");
  Require(expected.sha256.size() == 64, "expected SHA-256 must contain 64 lowercase hex digits");
  for (char c : expected.sha256)
    Require((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'), "invalid expected SHA-256");
}
class Sha256 {
 public:
  Sha256() {
    mbedtls_sha256_init(&context_);
    Require(mbedtls_sha256_starts(&context_, 0) == 0, "SHA-256 initialization failed");
  }
  ~Sha256() { mbedtls_sha256_free(&context_); }
  Sha256(const Sha256&) = delete;
  void Add(const void* data, size_t length) {
    Require(!finished_, "SHA-256 context already finalized");
    Require(mbedtls_sha256_update(&context_, static_cast<const unsigned char*>(data), length) == 0,
            "SHA-256 update failed");
  }
  std::string Finish() {
    Require(!finished_, "SHA-256 context already finalized");
    std::array<unsigned char, 32> bytes {};
    Require(mbedtls_sha256_finish(&context_, bytes.data()) == 0, "SHA-256 finalization failed");
    finished_ = true;
    static constexpr char hex[] = "0123456789abcdef";
    std::string result;
    for (unsigned char b : bytes) { result.push_back(hex[b >> 4]); result.push_back(hex[b & 15]); }
    return result;
  }
 private:
  mbedtls_sha256_context context_ {};
  bool finished_ = false;
};
struct StatIdentity {
  struct stat value {};
  explicit StatIdentity(int fd) { Require(fstat(fd, &value) == 0, "source fstat failed"); }
  void Same(int fd) const {
    struct stat now {};
    Require(fstat(fd, &now) == 0, "source recheck failed");
    Require(now.st_dev == value.st_dev && now.st_ino == value.st_ino &&
            now.st_size == value.st_size &&
            now.st_mtim.tv_sec == value.st_mtim.tv_sec &&
            now.st_mtim.tv_nsec == value.st_mtim.tv_nsec &&
            now.st_ctim.tv_sec == value.st_ctim.tv_sec &&
            now.st_ctim.tv_nsec == value.st_ctim.tv_nsec, "source identity changed");
  }
};
void CheckRange(uint64_t offset, uint64_t length) {
  Require(offset <= INT64_MAX && length <= static_cast<uint64_t>(INT64_MAX) - offset,
          "file range overflow");
}
void RegularRange(const StatIdentity& identity, uint64_t offset, uint64_t length) {
  CheckRange(offset, length);
  Require(S_ISREG(identity.value.st_mode), "image source must be a regular file");
  Require(identity.value.st_size >= 0 && offset <= static_cast<uint64_t>(identity.value.st_size) &&
          length <= static_cast<uint64_t>(identity.value.st_size) - offset,
          "source range exceeds file");
}
void PreadExact(int fd, uint64_t offset, void* buffer, size_t length) {
  CheckRange(offset, length);
  size_t done = 0;
  while (done < length) {
    ssize_t got = pread(fd, static_cast<char*>(buffer) + done, length - done,
                        static_cast<off_t>(offset + done));
    if (got < 0 && errno == EINTR) continue;
    Require(got > 0 && static_cast<size_t>(got) <= length - done, "source short read or I/O failure");
    done += static_cast<size_t>(got);
  }
}
std::string HashTarget(const OutputSink& sink, uint64_t length) {
  std::vector<char> buffer(kBuffer);
  Sha256 sha;
  for (uint64_t pos = 0; pos < length;) {
    size_t chunk = static_cast<size_t>(std::min<uint64_t>(buffer.size(), length - pos));
    sink.Read(pos, buffer.data(), chunk); sha.Add(buffer.data(), chunk); pos += chunk;
  }
  return sha.Finish();
}
uint16_t U16(const unsigned char* p) { return static_cast<uint16_t>(p[0] | (uint16_t(p[1]) << 8)); }
uint32_t U32(const unsigned char* p) {
  return uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
}
}  // namespace

std::string Sha256Bytes(const void* data, size_t length) {
  Sha256 sha; sha.Add(data, length); return sha.Finish();
}
std::string HashFdRange(int fd, uint64_t offset, uint64_t length) {
  CheckRange(offset, length);
  StatIdentity identity(fd);
  Require(S_ISREG(identity.value.st_mode) || S_ISBLK(identity.value.st_mode),
          "hash input must be regular or a separately authorized block descriptor");
  if (S_ISREG(identity.value.st_mode)) RegularRange(identity, offset, length);
  Sha256 sha; std::vector<char> buffer(kBuffer);
  for (uint64_t done = 0; done < length;) {
    size_t chunk = static_cast<size_t>(std::min<uint64_t>(buffer.size(), length - done));
    PreadExact(fd, offset + done, buffer.data(), chunk); sha.Add(buffer.data(), chunk); done += chunk;
  }
  identity.Same(fd);
  return sha.Finish();
}

struct CheckedSparse::Impl {
  int fd = -1;
  void* mapping = MAP_FAILED;
  size_t mapping_length = 0;
  const unsigned char* data = nullptr;
  sparse_file* image = nullptr;
  SparseInfo info;
  ExpectedImage expected;
  std::unique_ptr<StatIdentity> identity;
  ~Impl() {
    if (image) sparse_file_destroy(image);
    if (mapping != MAP_FAILED) munmap(mapping, mapping_length);
    if (fd >= 0) close(fd);
  }
  void Validate() {
    Require(info.source_bytes >= 28, "truncated sparse header");
    Require(U32(data) == 0xed26ff3a && U16(data + 4) == 1 && U16(data + 6) == 0,
            "unsupported sparse magic/version");
    Require(U16(data + 8) == 28 && U16(data + 10) == 12 && U32(data + 12) == kBlock,
            "noncanonical sparse header sizes/block size");
    const uint64_t blocks = U32(data + 16);
    const uint32_t chunks = U32(data + 20), header_crc = U32(data + 24);
    Require(blocks > 0 && blocks * kBlock == expected.bytes, "expanded sparse size mismatch");
    Require(chunks >= 2 && chunks <= kMaxChunks, "invalid sparse chunk count");
    Sha256 sha;
    uLong crc = crc32(0L, Z_NULL, 0);
    uint64_t pos = 28, output = 0;
    std::vector<unsigned char> zeros(kBuffer, 0);
    auto consume = [&](const unsigned char* bytes, uint64_t length, bool zero) {
      Require(output <= expected.bytes && length <= expected.bytes - output,
              "sparse output capacity overflow");
      while (length) {
        size_t part = static_cast<size_t>(std::min<uint64_t>(length, kBuffer));
        const unsigned char* source = zero ? zeros.data() : bytes;
        sha.Add(source, part); crc = crc32(crc, source, static_cast<uInt>(part));
        if (!zero) bytes += part;
        output += part; length -= part;
      }
    };
    for (uint32_t index = 0; index < chunks; ++index) {
      Require(pos <= info.source_bytes && info.source_bytes - pos >= 12, "truncated sparse chunk header");
      const unsigned char* chunk = data + pos;
      const uint16_t kind = U16(chunk), reserved = U16(chunk + 2);
      const uint64_t chunk_blocks = U32(chunk + 4), total = U32(chunk + 8);
      Require(reserved == 0 && total >= 12 && total <= info.source_bytes - pos,
              "invalid sparse chunk bounds/reserved field");
      const uint64_t raw_bytes = chunk_blocks * kBlock;
      if (kind == 0xcac1) {
        Require(index + 1 < chunks && chunk_blocks > 0 && total == raw_bytes + 12,
                "invalid RAW chunk");
        consume(chunk + 12, raw_bytes, false);
      } else if (kind == 0xcac2) {
        Require(index + 1 < chunks && chunk_blocks > 0 && total == 16 && U32(chunk + 12) == 0,
                "only explicit zero-FILL is allowed");
        consume(nullptr, raw_bytes, true);
      } else if (kind == 0xcac4) {
        Require(index + 1 == chunks && chunk_blocks == 0 && total == 16,
                "CRC chunk must be unique and terminal");
        Require(U32(chunk + 12) == static_cast<uint32_t>(crc), "sparse terminal CRC mismatch");
      } else {
        throw std::runtime_error("DONT_CARE and unknown sparse chunk types are forbidden");
      }
      pos += total;
    }
    Require(pos == info.source_bytes && output == expected.bytes, "sparse trailing data/incomplete coverage");
    Require(header_crc == 0 || header_crc == static_cast<uint32_t>(crc), "sparse header CRC mismatch");
    info.expanded_bytes = output; info.chunks = chunks; info.crc32 = static_cast<uint32_t>(crc);
    info.sha256 = sha.Finish();
    Require(info.sha256 == expected.sha256, "expanded sparse SHA-256 mismatch");
    identity->Same(fd);
    image = sparse_file_import_buf(reinterpret_cast<char*>(const_cast<unsigned char*>(data)), static_cast<size_t>(info.source_bytes), false, false);
    Require(image != nullptr, "AOSP libsparse rejected the checked source");
    Require(sparse_file_len(image, false, false) == static_cast<int64_t>(expected.bytes),
            "AOSP libsparse expanded length mismatch");
  }
};

CheckedSparse::CheckedSparse(int source_fd, uint64_t offset, uint64_t length,
                             const ExpectedImage& expected) : impl_(new Impl) {
  CheckExpected(expected);
  impl_->fd = fcntl(source_fd, F_DUPFD_CLOEXEC, 0);
  Require(impl_->fd >= 0, "source descriptor duplication failed");
  impl_->identity.reset(new StatIdentity(impl_->fd));
  RegularRange(*impl_->identity, offset, length);
  Require(length >= 28 && length <= SIZE_MAX, "invalid sparse member length");
  const long page_value = sysconf(_SC_PAGESIZE);
  Require(page_value > 0, "page size unavailable");
  uint64_t page = static_cast<uint64_t>(page_value), base = offset - offset % page, delta = offset - base;
  Require(length <= SIZE_MAX - delta, "mapping range overflow");
  impl_->mapping_length = static_cast<size_t>(length + delta);
  impl_->mapping = mmap(nullptr, impl_->mapping_length, PROT_READ, MAP_PRIVATE, impl_->fd,
                        static_cast<off_t>(base));
  Require(impl_->mapping != MAP_FAILED, "read-only sparse mapping failed");
  impl_->data = static_cast<const unsigned char*>(impl_->mapping) + delta;
  impl_->expected = expected;
  impl_->info.source_offset = offset; impl_->info.source_bytes = length;
  impl_->Validate();
}
CheckedSparse::~CheckedSparse() = default;
CheckedSparse::CheckedSparse(CheckedSparse&&) noexcept = default;
CheckedSparse& CheckedSparse::operator=(CheckedSparse&&) noexcept = default;
const SparseInfo& CheckedSparse::Info() const { Require(bool(impl_), "moved sparse image"); return impl_->info; }

void CheckedSparse::Apply(OutputSink& target, const Progress& progress) {
  Require(bool(impl_), "moved sparse image");
  impl_->identity->Same(impl_->fd);
  Require(target.Capacity() >= impl_->expected.bytes, "target capacity too small");
  struct Context {
    OutputSink* target;
    const ExpectedImage* expected;
    const Progress* progress;
    Sha256 sha;
    uint64_t position = 0;
    std::exception_ptr error;
  } context{&target, &impl_->expected, &progress};
  auto callback = [](void* cookie, const void* data, size_t length) -> int {
    auto* ctx = static_cast<Context*>(cookie);
    try {
      Require(data != nullptr || length == 0, "unexpected sparse hole in canonical input");
      Require(ctx->position <= ctx->expected->bytes && length <= ctx->expected->bytes - ctx->position,
              "AOSP sparse output overrun");
      if (length) {
        ctx->target->Write(ctx->position, data, length);
        ctx->sha.Add(data, length); ctx->position += length;
        if (*ctx->progress) (*ctx->progress)(ctx->position, ctx->expected->bytes);
      }
      return 0;
    } catch (...) { ctx->error = std::current_exception(); return -1; }
  };
  int result = sparse_file_callback(impl_->image, false, false, callback, &context);
  if (context.error) std::rethrow_exception(context.error);
  Require(result == 0 && context.position == impl_->expected.bytes, "AOSP sparse expansion incomplete");
  Require(context.sha.Finish() == impl_->expected.sha256, "written sparse stream hash mismatch");
  impl_->identity->Same(impl_->fd);
  target.Sync();
  Require(HashTarget(target, impl_->expected.bytes) == impl_->expected.sha256, "sparse target readback hash mismatch");
}

struct CheckedRaw::Impl {
  int fd = -1;
  uint64_t offset = 0;
  ExpectedImage expected;
  std::unique_ptr<StatIdentity> identity;
  ~Impl() { if(fd >= 0) close(fd); }
};
CheckedRaw::CheckedRaw(int source_fd,uint64_t offset,const ExpectedImage& expected)
    : impl_(new Impl) {
  CheckExpected(expected);
  impl_->fd=fcntl(source_fd,F_DUPFD_CLOEXEC,0);
  Require(impl_->fd >= 0,"raw source descriptor duplication failed");
  impl_->offset=offset;impl_->expected=expected;
  impl_->identity.reset(new StatIdentity(impl_->fd));
  RegularRange(*impl_->identity,offset,expected.bytes);
  Require(HashFdRange(impl_->fd,offset,expected.bytes)==expected.sha256,"raw source SHA-256 mismatch");
  impl_->identity->Same(impl_->fd);
}
CheckedRaw::~CheckedRaw()=default;
CheckedRaw::CheckedRaw(CheckedRaw&&) noexcept=default;
CheckedRaw& CheckedRaw::operator=(CheckedRaw&&) noexcept=default;
void CheckedRaw::Apply(OutputSink& target,const Progress& progress) {
  Require(bool(impl_),"moved raw image");
  const auto& expected=impl_->expected;
  impl_->identity->Same(impl_->fd);
  Require(target.Capacity() >= expected.bytes, "raw target capacity too small");
  Sha256 sha; std::vector<char> buffer(kBuffer);
  for (uint64_t pos = 0; pos < expected.bytes;) {
    size_t part = static_cast<size_t>(std::min<uint64_t>(buffer.size(), expected.bytes - pos));
    PreadExact(impl_->fd, impl_->offset + pos, buffer.data(), part);
    target.Write(pos, buffer.data(), part); sha.Add(buffer.data(), part); pos += part;
    if (progress) progress(pos, expected.bytes);
  }
  Require(sha.Finish() == expected.sha256, "raw source changed while writing");
  impl_->identity->Same(impl_->fd);
  target.Sync();
  Require(HashTarget(target, expected.bytes) == expected.sha256, "raw target readback hash mismatch");
}
void CopyRawVerified(int source_fd,uint64_t offset,const ExpectedImage& expected,
                     OutputSink& target,const Progress& progress) {
  CheckedRaw raw(source_fd,offset,expected);raw.Apply(target,progress);
}
}  // namespace ri3
