#include "guard_policy.h"
#ifdef RI3_FILE_FIXTURE_RUNTIME
#include "../runtime/fixture/fixture_profile.h"
#endif
#include <algorithm>
#include <functional>
#include <limits>
#include <set>
#include <utility>

namespace ri3::guard {
bool Binding::operator==(const Binding& b) const {
  return session == b.session && boot == b.boot && package == b.package &&
         generation == b.generation && observed_ms == b.observed_ms;
}
const char* super_sha256() {
#ifdef RI3_FILE_FIXTURE_RUNTIME
 return ri3::fixture::SuperSha256();
#else
 return "04842fd6988f96e6e9784adab37d71ec1602ffe35a966f7043658fb84feefd9b";
#endif
}
const std::vector<std::string>& write_allowlist() {
  static const std::vector<std::string> v = {
    "super", "boot_a", "dtbo_a", "init_boot_a", "vendor_boot_a", "vbmeta_system_a", "vbmeta_a"};
  return v;
}
Manifest production_manifest(const std::string& package_id, const PairContract& pair) {
#ifdef RI3_FILE_FIXTURE_RUNTIME
  return ri3::fixture::ManifestFor(package_id,pair);
#else
  return {package_id, {
    {"super", kSuperBytes, super_sha256()},
    {"boot_a", 100663296, "e7be9c65e3e6f0af17572a3fa37d43c4e4031d28f391ed17fc625e383c33bf03"},
    {"dtbo_a", 20971520, "5d3aa0fa69c4a79bb48ade2a1d325893dc70850c5f0e630f773207f66d397dd5"},
    {"init_boot_a", 8388608, "faa65e685c4f82c592eaa898238c485985b3f46b2f03d59bed1f24ec1fd79273"},
    {"vendor_boot_a", 100663296, "183736513c1003e3c0d5f6b6d7128d2e820e0dd1d6aef6c6600cc9d39482b877"},
    {"vbmeta_system_a", 4096, "59091cfb796bd6fb6fd56f2a53a6a2afedc04bf63a414dffebd19eab25be02d3"},
    {"vbmeta_a", pair.vbmeta_a.bytes, pair.vbmeta_a.sha256}
  }, pair};
#endif
}
const std::map<std::string, Digest>& firmware_pins() {
#ifdef RI3_FILE_FIXTURE_RUNTIME
  return ri3::fixture::FirmwarePins();
#else
  // Exact FW heredoc from immutable RI2 updater SHA256
  // 2f7e76ae406fadd962267d78b18b0533f3dec72592c91a2963a2005810c0ef65.
  // Its documented loop checks slot A only, hashing exactly this prefix length.
  static const std::map<std::string, Digest> pins = {
    {"abl_a", {307200, "bf0fe15137067a2b779e122768d11f520872ab2f059032c720c9aa807f30a4e8"}},
    {"aop_a", {319488, "ff05a2f2f6955c92f70f27b70cdf9b2d494a8a03fbfebb3913c6bfc438aa28db"}},
    {"aop_config_a", {24576, "b4f4de29fe840cee5cf5bb05a76acfb2f01c91d5c18ae9ebf344aac07fc46776"}},
    {"bluetooth_a", {1716224, "769bb81bff3c8798c40dc4c9a9c531e2485696f8521293e7012cf90b3a68c1e3"}},
    {"countrycode_a", {1048576, "ff161b42d23834cb78dcf60e385149999340ba7fdb3483b9d23a55ccab7e7333"}},
    {"cpucp_a", {212992, "eee1330912528c278ff48f6c044c760057a8b522048f006e40a8f28583feb9cc"}},
    {"cpucp_dtb_a", {16384, "5a6fcf1c5bada400988d9f660c8f4c04ae629a98d462b2cc3b1f673aafc718dd"}},
    {"devcfg_a", {57344, "d069713918c0348df0c1ed1207f359163797f98d19fcfdad4c4f5c4626e1a648"}},
    {"dsp_a", {67108864, "511b80a83832e1923326cff78b82fc2ada2372528802137c8a828d11d54520e4"}},
    {"featenabler_a", {106496, "e00e91474933d78bd34c041a3fb6a382f05465e5290ec4ae8d854e519beecd5d"}},
    {"hyp_a", {1507328, "ddbe59cf6676377f883dfa786e310111b8fd3b50007bb15650fc0d65d247e17e"}},
    {"imagefv_a", {6299648, "b168795d0c3f642848d4127e58e4d761c7d42890da5bfe4cb1050faa3ca30f75"}},
    {"keymaster_a", {442368, "4d9a2206ed504474547a2f050e959920fcacb6b50c75aa3cac0d72c4bdcd6500"}},
    {"modem_a", {162803712, "3848d2d16e87b95c801864b93ee684e9b884eba73e7df3e4a29b961471a742da"}},
    {"modemfirmware_a", {195612672, "e8426f0b6f0195b42ac8e6167553205addd0cef8e508af4539f23328029e4754"}},
    {"multiimgqti_a", {12288, "de3ba2667aaecdfc0f9785565981969c14f8ca4ebf583d6fa8c407d8ade65f5a"}},
    {"qupfw_a", {57344, "0bc957ef51f1cd9ad754a6b504a535d159592cd8c3aa4e451efeab6e118ce99c"}},
    {"shrm_a", {143360, "6ed2d1a37b74108eb98cd7bb43b4f9756f172c3a7e202548bcac6f5ab8b41e25"}},
    {"tz_a", {4014080, "b20fc1b8efc421ebfe0dc96fb4bb61fe82921d180bf3bc92cf3370a1b988bfe4"}},
    {"uefi_a", {2818048, "16a6f9ab87ac11245a144ce38ce818e821677460266a889f8c177d8daa1994de"}},
    {"uefisecapp_a", {200704, "204b2dea899d744feac2e4091a1a15386bb095f76b2ef33147dd8285abe5a889"}},
    {"xbl_a", {1126400, "4a8519c6817c6589a9d9d245a9b6380adbc8588b46bb5d6b121a9f92b6359d5a"}},
    {"xbl_config_a", {212992, "228ca4e3911e58445d985bc495f510fc432945597c281689bffe10860b99a9ed"}},
    {"xbl_ramdump_a", {942080, "001548a0d98043d54b320a5e50d795999d60713f759201d0c197a4b522ec93f5"}},
  };
  return pins;
#endif
}
std::map<std::string, Digest> recovery_pins(const PairContract& pair) {
#ifdef RI3_FILE_FIXTURE_RUNTIME
  return ri3::fixture::RecoveryPins(pair);
#else
  const std::map<std::string, Digest> p = {
    {"recovery_a", pair.recovery_a},
    {"/system/etc/security/otacerts.zip", pair.otacerts},
    {"/system/bin/recovery", {0, "b9416f70f6403ffe6cadc51626515f49f66a9961bbb7ef14898fdd9173c44a49"}},
    {"/system/bin/pre_rom_flash.sh", {1283, "1a00b22d9cef53fbdc2001d5f2ca0de899dddb8a346fdff9a6a1ab651c58e4ad"}},
    {"/system/bin/post_rom_flash_completion.sh", {1079, "9bb094aa05e4a4d5d79e8214d43cb1d35ddeed10265a1d6e17f3f936e309f920"}},
    {"/system/etc/twrp.flags", {0, "817aa5693a415a111bb80e34efcfcc672fcc62cb83e17bd61880809f36d44421"}},
    {"/system/bin/twrp", {0, "37314b1145bf587615a88db348005268cf28cbd89d5f215dae446e4019464126"}}
  };
  return p;
#endif
}
namespace {
bool yes(Truth t) { return t == Truth::Yes; }
bool sha(const std::string& s) {
  return s.size() == 64 && std::all_of(s.begin(), s.end(), [](char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
  });
}
bool equal_digest(const Digest& a, const Digest& b) {
  return a.bytes == b.bytes && a.sha256 == b.sha256;
}
template<class T> bool known(const Fact<T>& f, const Binding& b) {
  return f.status == Status::Known && f.binding == b;
}
bool same_context(const Binding& a, const Binding& b) {
  return a.session == b.session && a.boot == b.boot && a.package == b.package;
}
template<class T> bool retained(const Fact<T>& f, const Binding& b) {
  if (f.status != Status::Known || !f.lease || !same_context(f.binding,b)) return false;
  const auto& l = *f.lease;
  return l.started_ms <= l.completed_ms && l.completed_ms <= b.observed_ms &&
    f.binding.observed_ms == l.completed_ms && f.binding.generation <= b.generation &&
    !l.handle_id.empty() && !l.identity_token.empty() && l.checked_at == b &&
    yes(l.held_read_only) && yes(l.same_identity);
}
bool valid_extent(const Extent& e) {
  return !e.disk.empty() && e.bytes && e.begin <= std::numeric_limits<uint64_t>::max() - e.bytes;
}
bool overlap(const Extent& a, const Extent& b) {
  return a.disk == b.disk && a.begin < b.begin + b.bytes && b.begin < a.begin + a.bytes;
}
bool any_overlap(const std::vector<Extent>& a, const std::vector<Extent>& b) {
  for (const auto& x : a) for (const auto& y : b) if (overlap(x, y)) return true;
  return false;
}
bool extent_subset(const Extent& a, const std::vector<Extent>& b) {
  // Conservative: every resolved extent must fit wholly in one target extent.
  for (const auto& x : b)
    if (a.disk == x.disk && a.begin >= x.begin && a.begin + a.bytes <= x.begin + x.bytes) return true;
  return false;
}
bool extents_valid(const std::vector<Extent>& es) {
  if (es.empty()) return false;
  for (size_t i = 0; i < es.size(); ++i) {
    if (!valid_extent(es[i])) return false;
    for (size_t j = 0; j < i; ++j) if (overlap(es[i], es[j])) return false;
  }
  return true;
}
bool equal_extents(const std::vector<Extent>& a, const std::vector<Extent>& b) {
  if (a.size() != b.size()) return false;
  for (size_t i = 0; i < a.size(); ++i)
    if (a[i].disk != b[i].disk || a[i].begin != b[i].begin || a[i].bytes != b[i].bytes) return false;
  return true;
}
bool protected_name(const std::string& n) {
  return n == "recovery_a" || (n.size() > 2 && n.substr(n.size()-2) == "_b");
}
Check bad(const std::string& s) { return {false, s, {}}; }
const Node* partition(const Inventory& inv, const std::string& n) {
  for (const auto& x : inv.nodes) if (x.kind == Kind::Partition && x.partition == n) return &x;
  return nullptr;
}
}

Check preflight(const Manifest& m, const std::vector<Request>& requests,
                const Evidence& e, uint64_t now_ms, PreflightPhase phase) {
  const auto& b = e.binding;
  if (b.session.empty() || b.boot.empty() || b.package.empty() || !b.generation ||
      b.observed_ms > now_ms || now_ms - b.observed_ms > kMaxEvidenceAgeMs ||
      b.observed_ms > std::numeric_limits<uint64_t>::max() - kMaxEvidenceAgeMs)
    return bad("binding_missing_future_or_stale");
  if (m.id.empty() || b.package != m.id) return bad("manifest_binding");
  if (m.images.size() != write_allowlist().size() || requests.size() != m.images.size())
    return bad("incomplete_write_plan");
  if (m.pair.finalization != Status::Known || m.pair.version.empty() ||
      !sha(m.pair.record_sha256) || m.pair.recovery_a.bytes != kRecoveryBytes ||
      !sha(m.pair.recovery_a.sha256) || m.pair.vbmeta_a.bytes != 12288 ||
      !sha(m.pair.vbmeta_a.sha256) || !m.pair.otacerts.bytes || !sha(m.pair.otacerts.sha256))
    return bad("unfinalized_or_incomplete_pair_contract");
  // Old no-op-only pair lacks the approved ZIP-trust addition and is never final here.
  if (m.pair.recovery_a.sha256 == "90f0279abe946fc9bd3152a18429828378b9d5e54eb553a3d20e66894068422c")
    return bad("superseded_intermediate_pair");
  const auto pins = production_manifest(m.id, m.pair);
  for (size_t i = 0; i < m.images.size(); ++i) {
    const auto& x = m.images[i];
    if (x.partition != write_allowlist()[i] || x.bytes != pins.images[i].bytes ||
        x.sha256 != pins.images[i].sha256 || !sha(x.sha256) ||
        requests[i].kind != RequestKind::Write || requests[i].partition != x.partition)
      return bad("forbidden_or_unpinned_request");
  }
  if (m.images[0].bytes != kSuperBytes || m.images[0].sha256 != super_sha256())
    return bad("full_super_pin");
  if (!known(e.identity, b) || e.identity.value.product != "peridot" ||
      !yes(e.identity.value.normal_recovery) || !yes(e.identity.value.parent_is_recovery) ||
      e.identity.value.parent_executable_sha256 != recovery_pins(m.pair).at("/system/bin/recovery").sha256 ||
      e.identity.value.pair_version != m.pair.version ||
      e.identity.value.pair_record_sha256 != m.pair.record_sha256)
    return bad("observable_runtime_or_identity");
  for (const auto& p : recovery_pins(m.pair)) {
    auto it = e.recovery.find(p.first);
    if (it == e.recovery.end() || !retained(it->second, b) || it->second.value.bytes == 0 ||
        it->second.value.sha256 != p.second.sha256 ||
        (p.second.bytes && it->second.value.bytes != p.second.bytes))
      return bad("recovery_pin:" + p.first);
  }
  if (!known(e.afterromflash, b) || e.afterromflash.value != Absence::NoEntry)
    return bad("afterromflash_requires_enoent");
  if (!retained(e.zip_signature,b) ||
      !yes(e.zip_signature.value.cryptographic_signature_valid) ||
      !sha(e.zip_signature.value.package.sha256) || e.zip_signature.value.package.sha256 != b.package ||
      !e.zip_signature.value.package.bytes ||
      !e.zip_signature.value.signed_bytes ||
      e.zip_signature.value.signed_bytes >= e.zip_signature.value.package.bytes ||
      e.zip_signature.value.certificate_sha256 !=
        "24adea378cba169a0852bce0ffd5ee1874940f16b73c873efc75d57129f080cf" ||
      e.zip_signature.value.open_handle_id != e.source.value.open_handle_id ||
      e.zip_signature.lease->handle_id != e.source.value.open_handle_id)
    return bad("native_whole_zip_signature");
  if (e.firmware.size() != firmware_pins().size()) return bad("firmware_set");
  for (const auto& p : firmware_pins()) {
    auto f = e.firmware.find(p.first);
    if (f == e.firmware.end() || !retained(f->second,b) || !equal_digest(f->second.value,p.second))
      return bad("firmware_prefix:" + p.first);
  }
  if (e.payloads.size() != m.images.size()) return bad("payload_set");
  for (const auto& image : m.images) {
    auto p = e.payloads.find(image.partition);
    if (p == e.payloads.end() || !retained(p->second,b) ||
        !equal_digest(p->second.value,{image.bytes,image.sha256}) ||
        p->second.lease->handle_id != e.source.value.open_handle_id)
      return bad("payload_prevalidation:" + image.partition);
  }
  if (!known(e.snapshot, b) || e.snapshot.value.hal != SnapshotValue::None || e.snapshot.value.metadata != SnapshotValue::None ||
      !yes(e.snapshot.value.hal_complete) || !yes(e.snapshot.value.metadata_readable) ||
      !yes(e.snapshot.value.metadata_inspectable) || !yes(e.snapshot.value.exact_metadata_mount) ||
      !yes(e.snapshot.value.metadata_clean_complete))
    return bad("snapshot_none_not_proven");
  if (!retained(e.layout, b) || e.layout.value.reconstructed_super.bytes != kSuperBytes ||
      e.layout.value.reconstructed_super.sha256 != super_sha256() ||
      !yes(e.layout.value.a_populated) || !yes(e.layout.value.b_empty) ||
      e.layout.lease->handle_id != e.source.value.open_handle_id)
    return bad("super_layout");
  if (!known(e.inventory, b) || !yes(e.inventory.value.partitions_complete) ||
      !yes(e.inventory.value.mappings_complete) || !yes(e.inventory.value.mounts_complete) ||
      !yes(e.inventory.value.single_recovery_workflow))
    return bad("incomplete_inventory");
  if (!known(e.source, b) || e.source.value.open_handle_id.empty() ||
      !yes(e.source.value.readable) || !yes(e.source.value.content_verified) ||
      !yes(e.source.value.extents_complete) || !yes(e.source.value.dependencies_complete) ||
      !extents_valid(e.source.value.extents) || e.source.value.dependencies.empty())
    return bad("source_proof");
  const auto& inv = e.inventory.value;
  std::map<std::string, const Node*> nodes;
  std::set<std::string> partitions;
  std::vector<Extent> targets;
  std::set<std::string> target_ids;
  for (const auto& n : inv.nodes) {
    if (n.id.empty() || !nodes.emplace(n.id, &n).second || n.kind == Kind::Unknown ||
        !yes(n.identity_verified) || !yes(n.table_complete) || !yes(n.dependencies_complete) ||
        !yes(n.extents_complete) || n.mounted == Truth::Unknown || (n.kind != Kind::Partition && !n.open_count) ||
        !extents_valid(n.extents) || !n.capacity)
      return bad("unknown_or_duplicate_node");
    if (n.kind == Kind::Partition && (n.partition.empty() ||
        !partitions.insert(n.partition).second || !n.dependencies.empty()))
      return bad("partition_identity_or_ancestry");
    if (n.kind != Kind::Partition && (!n.partition.empty() || n.dependencies.empty()))
      return bad("mapping_dependencies");
    uint64_t total = 0;
    for (const auto& ex : n.extents) {
      if (total > std::numeric_limits<uint64_t>::max() - ex.bytes) return bad("extent_overflow");
      total += ex.bytes;
    }
    if (total < n.capacity) return bad("incomplete_capacity_extent");
  }
  for (const auto& x : m.images) {
    const Node* n = partition(inv, x.partition);
    if (!n || n->capacity < x.bytes || (x.partition == "super" && n->capacity != kSuperBytes) ||
        n->mounted != Truth::No || !yes(n->held_identity_checked))
      return bad("target_identity_capacity_mount_or_handle:" + x.partition);
    if (any_overlap(targets, n->extents)) return bad("aliased_write_targets");
    targets.insert(targets.end(), n->extents.begin(), n->extents.end());
    target_ids.insert(n->id);
  }
  for (const auto& fw : firmware_pins()) {
    const Node* n = partition(inv,fw.first);
    if (!n || n->capacity < fw.second.bytes || !yes(n->held_identity_checked) ||
        n->mounted != Truth::No || any_overlap(targets,n->extents) ||
        e.firmware.at(fw.first).lease->handle_id != n->read_handle_id)
      return bad("firmware_identity_capacity_or_alias:" + fw.first);
  }
  if (!partition(inv, "recovery_a") || !partition(inv, "recovery_b"))
    return bad("missing_protected_recovery");
  size_t protected_count = 0;
  for (const auto& n : inv.nodes) if (n.kind == Kind::Partition && protected_name(n.partition)) {
    ++protected_count;
    if (any_overlap(targets, n.extents)) return bad("target_aliases_protected_partition");
    auto h = e.protected_partitions.find(n.partition);
    if (h == e.protected_partitions.end() || !retained(h->second, b) ||
        h->second.value.bytes != n.capacity || !sha(h->second.value.sha256) ||
        h->second.lease->handle_id != n.read_handle_id)
      return bad("protected_partition_hash:" + n.partition);
    if (n.partition == "recovery_a" &&
        !equal_digest(h->second.value, recovery_pins(m.pair).at("recovery_a")))
      return bad("recovery_a_preservation");
  }
  if (protected_count != e.protected_partitions.size()) return bad("unexpected_protected_partition");
  // Validate the WHOLE dependency graph; unknown edges and cycles cannot prove independence.
  std::map<std::string, int> color;
  std::vector<std::string> dependency_first;
  std::function<bool(const std::string&)> visit = [&](const std::string& id) {
    auto it = nodes.find(id);
    if (it == nodes.end() || color[id] == 1) return false;
    if (color[id] == 2) return true;
    color[id] = 1;
    std::set<std::string> unique;
    std::vector<Extent> parents;
    for (const auto& dep : it->second->dependencies) {
      if (!unique.insert(dep).second || !visit(dep)) return false;
      const auto& es = nodes.at(dep)->extents;
      parents.insert(parents.end(), es.begin(), es.end());
    }
    if (it->second->kind != Kind::Partition)
      for (const auto& ex : it->second->extents) if (!extent_subset(ex, parents)) return false;
    color[id] = 2;
    dependency_first.push_back(id);
    return true;
  };
  for (const auto& n : nodes) if (!visit(n.first)) return bad("dependency_cycle_unknown_or_extent");
  std::map<std::string, bool> depends;
  for (const auto& id : dependency_first) {
    const auto& n = *nodes.at(id);
    bool target = target_ids.count(id) || any_overlap(n.extents, targets);
    for (const auto& dep : n.dependencies) target = target || depends[dep];
    depends[id] = target;
  }
  if (any_overlap(e.source.value.extents, targets)) return bad("source_target_overlap");
  std::vector<Extent> source_backing;
  for (const auto& dep : e.source.value.dependencies) {
    if (!nodes.count(dep) || depends[dep]) return bad("source_dependency_unknown_or_target");
    const auto& es = nodes.at(dep)->extents;
    source_backing.insert(source_backing.end(), es.begin(), es.end());
  }
  for (const auto& ex : e.source.value.extents)
    if (!extent_subset(ex, source_backing)) return bad("source_extent_not_backed");
  const auto& super = partition(inv, "super")->extents;
  std::vector<std::string> teardown;
  for (auto it = dependency_first.rbegin(); it != dependency_first.rend(); ++it) {
    const auto& n = *nodes.at(*it);
    if (n.kind == Kind::Partition || !depends[*it]) continue;
    const bool linear = n.kind == Kind::Linear;
    const bool verity = n.kind == Kind::Verity && yes(n.read_only);
    const bool has_child = std::any_of(inv.nodes.begin(),inv.nodes.end(),[&](const Node& child) {
      return std::find(child.dependencies.begin(),child.dependencies.end(),n.id) != child.dependencies.end();
    });
    const bool pending_normal_unmount = phase == PreflightPhase::BeforeTargetUnmount && n.mounted == Truth::Yes;
    if ((!linear && !verity) || (n.mounted != Truth::No && !pending_normal_unmount) ||
        (!has_child && !pending_normal_unmount && *n.open_count != 0))
      return bad("unsafe_target_mapping:" + n.id);
    // Do not subtract guessed child references. Non-leaf open counts are allowed
    // only until their known children are removed. Each actual leaf must be zero.
    if (verity) {
      for (const auto& other : inv.nodes)
        if (std::find(other.dependencies.begin(),other.dependencies.end(),n.id) != other.dependencies.end())
          return bad("verity_must_be_leaf:" + n.id);
    }
    for (const auto& ex : n.extents)
      if (!extent_subset(ex, super)) return bad("mapping_not_only_super");
    teardown.push_back(n.id);
  }
  return {true, "", teardown};
}
Session::Session(Manifest manifest, std::vector<Request> requests)
    : manifest_(std::move(manifest)), requests_(std::move(requests)) {}
void Session::fail(const std::string& e) {
  if (stage_ == Stage::Succeeded) return;
  stage_ = Stage::Failed;
  error_ = e;
  pending_.reset();
}
std::optional<Action> Session::next(const Evidence& e, uint64_t now_ms) {
  if (stage_ == Stage::Failed || stage_ == Stage::Succeeded) return std::nullopt;
  if (stage_ == Stage::AwaitingReceipt) { fail("receipt_missing"); return std::nullopt; }
  Check check = preflight(manifest_, requests_, e, now_ms);
  if (!check.ok) { fail(check.error); return std::nullopt; }
  if (stage_ == Stage::New) {
    original_ = e.binding;
    original_source_ = e.source.value;
    for (const auto& p : e.protected_partitions) original_protected_[p.first] = p.second.value;
    for (const auto& im : manifest_.images)
      original_targets_[im.partition] = *partition(e.inventory.value, im.partition);
    expected_remaining_ = check.teardown_order;
    stage_ = Stage::Ready;
  } else {
    if (e.binding.session != original_.session || e.binding.boot != original_.boot ||
        e.binding.package != original_.package || e.binding.generation <= last_generation_ ||
        e.binding.observed_ms < last_observed_ms_ || e.binding.observed_ms < last_completed_ms_) {
      fail("replayed_or_rebound_evidence"); return std::nullopt;
    }
    if (e.protected_partitions.size() != original_protected_.size()) {
      fail("protected_set_changed"); return std::nullopt;
    }
    for (const auto& p : original_protected_) {
      auto h = e.protected_partitions.find(p.first);
      if (h == e.protected_partitions.end() || !equal_digest(h->second.value, p.second)) {
        fail("protected_partition_changed:" + p.first); return std::nullopt;
      }
    }
    for (const auto& old : original_targets_) {
      const Node* n = partition(e.inventory.value, old.first);
      if (!n || n->id != old.second.id || n->capacity != old.second.capacity ||
          !equal_extents(n->extents, old.second.extents)) {
        fail("target_identity_changed"); return std::nullopt;
      }
    }
    const auto& s = e.source.value;
    if (s.open_handle_id != original_source_.open_handle_id ||
        s.dependencies != original_source_.dependencies || !equal_extents(s.extents, original_source_.extents)) {
      fail("source_binding_changed"); return std::nullopt;
    }
    for (const auto& removed : removed_)
      for (const auto& n : e.inventory.value.nodes) if (n.id == removed) {
        fail("removal_recheck_failed"); return std::nullopt;
      }
    if (check.teardown_order != expected_remaining_) {
      fail("mapping_topology_changed"); return std::nullopt;
    }
  }
  last_generation_ = e.binding.generation;
  last_observed_ms_ = e.binding.observed_ms;
  Action action;
  action.sequence = ++sequence_;
  action.generation = last_generation_;
  action.binding = e.binding;
  action.authorized_ms = now_ms;
  action.expires_ms = e.binding.observed_ms + kMaxEvidenceAgeMs;
  if (!expected_remaining_.empty()) {
    action.kind = ActionKind::RemoveMapping;
    action.subject = expected_remaining_.front();
  } else if (write_index_ < manifest_.images.size()) {
    action.kind = ActionKind::WriteImage;
    action.image = manifest_.images[write_index_];
    action.subject = action.image.partition;
  } else {
    // Full protected readback must start after the last write, not merely renew
    // an earlier descriptor-identity observation.
    for (const auto& p : e.protected_partitions) {
      if (!p.second.lease || p.second.lease->started_ms < last_completed_ms_) {
        fail("final_protected_readback_not_fresh:" + p.first); return std::nullopt;
      }
    }
    action.kind = ActionKind::SelectA;
    action.subject = "a";
  }
  pending_ = action;
  stage_ = Stage::AwaitingReceipt;
  return action;
}
bool Session::complete(const Receipt& r) {
  if (stage_ == Stage::Failed || stage_ == Stage::Succeeded) return false;
  if (stage_ != Stage::AwaitingReceipt || !pending_) { fail("unexpected_receipt"); return false; }
  const auto a = *pending_;
  if (r.sequence != a.sequence || r.generation != a.generation || r.kind != a.kind ||
      r.subject != a.subject || r.status != Status::Known || !yes(r.complete) ||
      !(r.binding == a.binding) || r.started_ms < a.authorized_ms || r.started_ms > a.expires_ms ||
      r.completed_ms < r.started_ms || !yes(r.guard_revalidated) ||
      !yes(r.target_state_held) || !yes(r.source_readable_throughout)) {
    fail("failed_or_mismatched_receipt"); return false;
  }
  last_completed_ms_ = r.completed_ms;
  if (a.kind == ActionKind::RemoveMapping) {
    removed_.push_back(a.subject);
    expected_remaining_.erase(expected_remaining_.begin());
  } else if (a.kind == ActionKind::WriteImage) {
    Digest expected{a.image.bytes, a.image.sha256};
    if (r.transferred != a.image.bytes || !yes(r.fsync_ok) ||
        !equal_digest(r.source_digest, expected) || !equal_digest(r.readback_digest, expected)) {
      fail("incomplete_write_fsync_or_hash"); return false;
    }
    ++write_index_;
  } else if (a.kind == ActionKind::SelectA) {
    if (write_index_ != manifest_.images.size() || !expected_remaining_.empty() ||
        !yes(r.slot_a_confirmed)) {
      fail("slot_selection_not_confirmed"); return false;
    }
    stage_ = Stage::Succeeded;
    pending_.reset();
    return true;
  } else { fail("forbidden_action"); return false; }
  pending_.reset();
  stage_ = Stage::Ready;
  return true;
}
} // namespace ri3::guard
