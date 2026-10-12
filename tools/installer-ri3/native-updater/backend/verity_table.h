// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <cstdint>
#include <map>
#include <string>
#include <vector>
namespace ri3::backend {
struct VerityRange { std::string device; uint64_t offset=0,bytes=0; };
struct VerityTable {
  std::vector<std::string> dependencies;
  std::vector<VerityRange> minimum_ranges; // data, hash tree, optional FEC
  std::string canonical; // Public verity parameters only, never crypt table data.
};
// Recognizes a single standard SHA-256/SHA-512 verity target. Throws on unknown
// grammar/options, overflow, missing FEC parameters or inconsistent geometry.
VerityTable ParseVerity(const std::string& parameters,uint64_t logical_bytes);
void CheckVerityBounds(const VerityTable&,const std::map<std::string,uint64_t>& capacities);
} // namespace ri3::backend
