#pragma once
#include <array>
#include <cstdint>
#include <string>
#ifndef RI3_CERTIFICATE_DER_SHA256
#define RI3_CERTIFICATE_DER_SHA256 "24adea378cba169a0852bce0ffd5ee1874940f16b73c873efc75d57129f080cf"
#endif
namespace ri3crypto {
using Digest = std::array<unsigned char, 32>;
struct FileIdentity {
  uint64_t device=0, inode=0, size=0;
  int64_t mtime_seconds=0, mtime_nanoseconds=0;
  int64_t ctime_seconds=0, ctime_nanoseconds=0;
};
struct ZipVerificationReceipt {
  bool verified=false;
  FileIdentity identity{};
  uint64_t signed_bytes=0;
  Digest signed_sha256{};
  Digest full_file_sha256{};
  uint64_t read_started_monotonic_ns=0, read_completed_monotonic_ns=0;
  std::string certificate_der_sha256;
  std::string algorithm;
};
// No path reopen, key from archive, mutation, or private-key operation occurs.
// Caller retains fd until all authorized consumption of this exact file ends.
bool VerifyZipFd(int fd, uint64_t expected_size,
                 ZipVerificationReceipt* receipt, std::string* error);
// Check receipt against the held FD before later consumption; does not rehash.
bool ReceiptMatchesFd(int fd, const ZipVerificationReceipt&, std::string* error);
// Exact positional streaming SHA256; fails short/error reads and never seeks fd.
bool Sha256HeldPrefix(int fd, uint64_t length, Digest*, std::string* error);
bool VerifyFixedRsaSha256(const Digest&, const unsigned char* signature,
                         size_t length, std::string* error);
constexpr const char* CertificateDerSha256() {
  return RI3_CERTIFICATE_DER_SHA256;
}
}
