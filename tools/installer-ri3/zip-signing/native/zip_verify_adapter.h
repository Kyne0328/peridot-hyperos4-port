#pragma once
#include <array>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>
namespace ri3zip {
using Digest = std::array<uint8_t,32>;
// Hash callback MUST hash exactly [0, signed_bytes) from fd and fail on short read.
using HashPrefix = std::function<bool(int fd, uint64_t signed_bytes, Digest* digest,
                                     std::string* error)>;
// RSA callback MUST use the separately pinned public key, SHA256, and PKCS#1 v1.5.
using VerifyRsa = std::function<bool(const Digest&, const std::vector<uint8_t>&,
                                    std::string* error)>;
bool VerifyHeldZip(int fd, uint64_t expected_size, const HashPrefix& hash,
                   const VerifyRsa& rsa, std::string* error);
}
