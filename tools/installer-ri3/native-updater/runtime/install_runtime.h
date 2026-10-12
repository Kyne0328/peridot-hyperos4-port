// Apache-2.0. Fixed-contract RI3 native installer entry point.
#pragma once
#include <functional>
#include <string>
#include "../extract/image_extract.h"
#include "../crypto/native_zip_crypto.h"
namespace ri3::runtime {
struct Result { bool success=false; bool mutations_started=false; std::string error; };
using Message = std::function<void(const std::string&)>;
// fd must be a held read-only regular ZIP. This API is never used by host tests
// against devices. Native signature verification precedes all preparation.
Result InstallHeldPackage(int fd, const Message& message, const Progress& progress,
                          const ri3crypto::ZipVerificationReceipt* verified = nullptr);
Result VerifyHeldPayloads(int fd);
}
