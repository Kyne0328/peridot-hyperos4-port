#include "guard_policy.h"
#include <algorithm>
#include <functional>
#include <iostream>
#include <limits>
#include <stdexcept>
using namespace ri3::guard;
namespace {
unsigned passed = 0;
void require(bool b, const std::string& why) { if (!b) throw std::runtime_error(why); }
void test(const std::string& name, const std::function<void()>& fn) {
  fn(); ++passed; std::cout << "PASS\t" << name << "\n";
}
PairContract mock_pair() {
  return {Status::Known, "MOCK_FINALIZED_CONTRACT_NOT_DEVICE_PROOF", std::string(64, 'c'),
          {kRecoveryBytes, std::string(64, 'd')}, {12288, std::string(64, 'e')},
          {4096, std::string(64, 'f')}};
}
Manifest manifest() { return production_manifest(std::string(64,'9'), mock_pair()); }
std::vector<Request> requests() {
  std::vector<Request> out;
  for (const auto& n : write_allowlist()) out.push_back({RequestKind::Write, n});
  return out;
}
template<class T> void stamp(Fact<T>& f, const Binding& b) { f.status = Status::Known; f.binding = b; }
template<class T> void content(Fact<T>& f,const Binding& b,const std::string& handle) {
  if(!f.lease) {
    stamp(f,b);
    f.lease=ContentLease{b.observed_ms,b.observed_ms,handle,"identity:"+handle,b,Truth::Yes,Truth::Yes};
  }
  f.lease->checked_at=b;
}
void refresh(Evidence& e) {
  ++e.binding.generation; ++e.binding.observed_ms;
  stamp(e.identity,e.binding); stamp(e.afterromflash,e.binding); stamp(e.snapshot,e.binding);
  stamp(e.inventory,e.binding); stamp(e.source,e.binding);
  content(e.zip_signature,e.binding,e.source.value.open_handle_id);
  content(e.layout,e.binding,e.source.value.open_handle_id);
  for(auto& f:e.recovery) content(f.second,e.binding,"read:"+f.first);
  for(auto& f:e.protected_partitions) content(f.second,e.binding,"read:"+f.first);
  for(auto& f:e.firmware) content(f.second,e.binding,"read:"+f.first);
  for(auto& f:e.payloads) content(f.second,e.binding,e.source.value.open_handle_id);
}
void final_readback(Evidence& e) {
  for(auto& f:e.protected_partitions) { f.second.lease.reset(); content(f.second,e.binding,"read:"+f.first); }
}
Node node(const std::string& name, uint64_t begin, uint64_t bytes) {
  Node n;
  n.id = "id:"+name; n.partition = name; n.read_handle_id="read:"+name; n.kind = Kind::Partition;
  n.identity_verified = n.table_complete = n.dependencies_complete = n.extents_complete = Truth::Yes;
  n.held_identity_checked=Truth::Yes; n.mounted = Truth::No; n.open_count = 0; n.capacity=bytes;
  n.extents={{"same-physical-disk",begin,bytes}};
  return n;
}
Node& find(Evidence& e, const std::string& name) {
  for(auto& n:e.inventory.value.nodes) if(n.id=="id:"+name) return n;
  throw std::runtime_error("fixture node missing");
}
Evidence valid() {
  Evidence e;
  e.binding={"mock-session","mock-boot",std::string(64,'9'),0,1000};
  auto p=mock_pair();
  e.identity.value={"peridot","b9416f70f6403ffe6cadc51626515f49f66a9961bbb7ef14898fdd9173c44a49",p.version,p.record_sha256,Truth::Yes,Truth::Yes};
  for(const auto& pin:recovery_pins(p)) {
    e.recovery[pin.first].value=pin.second;
    if(!e.recovery[pin.first].value.bytes) e.recovery[pin.first].value.bytes=4096;
  }
  e.afterromflash.value=Absence::NoEntry;
  e.zip_signature.value={{4096,std::string(64,'9')},3000,"24adea378cba169a0852bce0ffd5ee1874940f16b73c873efc75d57129f080cf","open-readonly-fd:fixture",Truth::Yes};
  e.snapshot.value={SnapshotValue::None,SnapshotValue::None,
                    Truth::Yes,Truth::Yes,Truth::Yes,Truth::Yes,Truth::Yes};
  e.layout.value={{kSuperBytes,super_sha256()},Truth::Yes,Truth::Yes};
  e.inventory.value.partitions_complete=e.inventory.value.mappings_complete=
      e.inventory.value.mounts_complete=Truth::Yes;
  e.inventory.value.single_recovery_workflow=Truth::Yes;
  uint64_t offset=1048576;
  for(const auto& im:manifest().images) {
    e.inventory.value.nodes.push_back(node(im.partition,offset,im.bytes));
    offset+=im.bytes+1048576;
  }
  for(const auto& fw:firmware_pins()) {
    e.inventory.value.nodes.push_back(node(fw.first,offset,fw.second.bytes+4096));
    e.firmware[fw.first].value=fw.second; offset+=fw.second.bytes+1048576;
  }
  for(const auto& im:manifest().images) e.payloads[im.partition].value={im.bytes,im.sha256};
  for(const auto& name:{"recovery_a","recovery_b","boot_b","dtbo_b","init_boot_b",
                        "vendor_boot_b","vbmeta_system_b","vbmeta_b"}) {
    e.inventory.value.nodes.push_back(node(name,offset,kRecoveryBytes));
    e.protected_partitions[name].value={kRecoveryBytes,std::string(64,'a')};
    offset+=kRecoveryBytes+1048576;
  }
  e.protected_partitions["recovery_a"].value=p.recovery_a;
  auto data=node("userdata",offset,1024ULL*1024*1024);
  data.mounted=Truth::Yes; data.open_count=3;
  e.inventory.value.nodes.push_back(data);
  Node crypto=data; crypto.id="id:crypto-data"; crypto.partition="";
  crypto.kind=Kind::Crypto; crypto.dependencies={"id:userdata"};
  e.inventory.value.nodes.push_back(crypto);
  e.source.value={"open-readonly-fd:fixture",Truth::Yes,Truth::Yes,Truth::Yes,Truth::Yes,
                   {{data.extents[0].disk,offset+4096,4096}},{"id:crypto-data"}};
  refresh(e);
  return e;
}
void add_linear(Evidence& e) {
  Node n=find(e,"super"); n.id="id:logical-base"; n.partition=""; n.kind=Kind::Linear;
  n.dependencies={"id:super"}; n.capacity=4096; n.extents[0].bytes=4096;
  e.inventory.value.nodes.push_back(n);
  n.id="id:logical-child"; n.dependencies={"id:logical-base"};
  e.inventory.value.nodes.push_back(n);
}
Check check(const Evidence& e) { return preflight(manifest(),requests(),e,e.binding.observed_ms); }
void reject(const std::string& name,const std::function<void(Evidence&)>& mutate) {
  test(name,[&] { auto e=valid(); mutate(e); require(!check(e).ok,"unexpected preflight success"); });
}
Receipt good(const Action& a) {
  Receipt r; r.sequence=a.sequence; r.generation=a.generation; r.kind=a.kind; r.subject=a.subject;
  r.binding=a.binding; r.started_ms=a.authorized_ms; r.completed_ms=a.authorized_ms+1;
  r.guard_revalidated=r.target_state_held=r.source_readable_throughout=Truth::Yes;
  r.status=Status::Known; r.complete=Truth::Yes; r.transferred=a.image.bytes; r.fsync_ok=Truth::Yes;
  r.source_digest={a.image.bytes,a.image.sha256}; r.readback_digest=r.source_digest;
  r.slot_a_confirmed=Truth::Yes; return r;
}
Action next(Session& s,Evidence& e) {
  auto a=s.next(e,e.binding.observed_ms);
  require(a.has_value(),"action unavailable:"+s.error()); return *a;
}
void finish_writes(Session& s,Evidence& e) {
  for(size_t i=0;i<write_allowlist().size();++i) {
    auto a=next(s,e); require(a.kind==ActionKind::WriteImage && a.subject==write_allowlist()[i],"write order");
    require(s.complete(good(a)),"write receipt"); refresh(e);
  }
  final_readback(e);
}
void failed_stays_failed(Session& s,Evidence& e) {
  require(s.stage()==Stage::Failed,"failure not latched"); refresh(e);
  require(!s.next(e,e.binding.observed_ms),"failure issued action");
  Receipt r; r.kind=ActionKind::SelectA; r.status=Status::Known; r.complete=Truth::Yes;
  r.slot_a_confirmed=Truth::Yes;
  require(!s.complete(r) && s.stage()==Stage::Failed,"failure resurrected");
}
}
int main() {
 try {
  test("valid_normal_recovery_same_disk_decrypted_userdata",[&]{
    auto e=valid(); auto c=check(e); require(c.ok,c.error); require(c.teardown_order.empty(),"unrelated crypto teardown");
    Session s(manifest(),requests()); finish_writes(s,e);
    require(s.verified_writes()==7 && s.stage()!=Stage::Succeeded,"premature success");
    auto a=next(s,e); require(a.kind==ActionKind::SelectA && a.sequence==8,"final slot ordering");
    require(s.complete(good(a)) && s.stage()==Stage::Succeeded,"mock success unreachable");
    require(!s.next(e,e.binding.observed_ms),"post-success action");
  });
  test("safe_linear_teardown_dependency_order_and_recheck",[&]{
    auto e=valid(); add_linear(e); auto c=check(e);
    require(c.ok && c.teardown_order==std::vector<std::string>{"id:logical-child","id:logical-base"},"teardown plan");
    Session s(manifest(),requests());
    for(const auto& id:c.teardown_order) {
      auto a=next(s,e); require(a.kind==ActionKind::RemoveMapping && a.subject==id,"teardown order");
      require(s.complete(good(a)),"teardown receipt");
      auto& nodes=e.inventory.value.nodes;
      nodes.erase(std::remove_if(nodes.begin(),nodes.end(),[&](const Node& n){return n.id==id;}),nodes.end());
      refresh(e);
    }
    finish_writes(s,e); require(next(s,e).kind==ActionKind::SelectA,"teardown blocked valid path");
  });
  test("recognized_readonly_verity_leaf_teardown",[]{
    auto e=valid();add_linear(e);auto& v=find(e,"logical-child");v.kind=Kind::Verity;v.read_only=Truth::Yes;
    auto c=check(e);require(c.ok&&c.teardown_order.front()=="id:logical-child","verity leaf not reachable");
  });
  reject("verity_writable",[](Evidence&e){add_linear(e);auto& v=find(e,"logical-child");v.kind=Kind::Verity;v.read_only=Truth::No;});
  reject("verity_readonly_unknown",[](Evidence&e){add_linear(e);find(e,"logical-child").kind=Kind::Verity;});
  reject("verity_nonleaf",[](Evidence&e){add_linear(e);auto& v=find(e,"logical-base");v.kind=Kind::Verity;v.read_only=Truth::Yes;});
  test("stacked_parent_opens_clear_after_child_removal",[]{
    auto e=valid();add_linear(e);find(e,"logical-base").open_count=1;
    Session s(manifest(),requests());auto a=next(s,e);require(a.subject=="id:logical-child","wrong first leaf");
    require(s.complete(good(a)),"child receipt");
    auto& ns=e.inventory.value.nodes;ns.erase(std::remove_if(ns.begin(),ns.end(),[](const Node& n){return n.id=="id:logical-child";}),ns.end());
    find(e,"logical-base").open_count=0;refresh(e);
    require(next(s,e).subject=="id:logical-base","parent not removable after recheck");
  });
  test("stacked_parent_residual_open_aborts",[]{
    auto e=valid();add_linear(e);find(e,"logical-base").open_count=1;
    Session s(manifest(),requests());require(s.complete(good(next(s,e))),"child receipt");
    auto& ns=e.inventory.value.nodes;ns.erase(std::remove_if(ns.begin(),ns.end(),[](const Node& n){return n.id=="id:logical-child";}),ns.end());refresh(e);
    require(!s.next(e,e.binding.observed_ms),"busy parent accepted");
    require(s.verified_writes()==0,"write before parent recheck");
  });
  test("preparation_phase_does_not_authorize_writes",[]{
    auto e=valid();add_linear(e);find(e,"logical-child").mounted=Truth::Yes;find(e,"logical-child").open_count=1;
    auto p=preflight(manifest(),requests(),e,e.binding.observed_ms,PreflightPhase::BeforeTargetUnmount);
    require(p.ok,"safe pre-unmount preparation unreachable");
    Session s(manifest(),requests());require(!s.next(e,e.binding.observed_ms),"mounted state issued mutation action");
  });
  test("unknown_defaults_fail_closed",[&]{ require(!check(Evidence{}).ok,"default passed"); });
  for(const auto st:{Status::Unknown,Status::Error,Status::Timeout}) {
    const std::string label=std::to_string(static_cast<int>(st));
    for(const auto& pin:recovery_pins(mock_pair()))
      reject("recovery_fact_"+pin.first+"_"+label,[&](Evidence& e){e.recovery[pin.first].status=st;});
    reject("identity_"+label,[&](Evidence&e){e.identity.status=st;});
    reject("afterromflash_"+label,[&](Evidence&e){e.afterromflash.status=st;});
    reject("zip_signature_"+label,[&](Evidence&e){e.zip_signature.status=st;});
    reject("firmware_"+label,[&](Evidence&e){e.firmware.begin()->second.status=st;});
    reject("snapshot_"+label,[&](Evidence&e){e.snapshot.status=st;});
    reject("layout_"+label,[&](Evidence&e){e.layout.status=st;});
    reject("inventory_"+label,[&](Evidence&e){e.inventory.status=st;});
    reject("source_"+label,[&](Evidence&e){e.source.status=st;});
    reject("protected_hash_"+label,[&](Evidence&e){e.protected_partitions["boot_b"].status=st;});
  }
  for(const auto& pin:recovery_pins(mock_pair())) {
    reject("wrong_hash_"+pin.first,[&](Evidence&e){e.recovery[pin.first].value.sha256=std::string(64,'0');});
    reject("mixed_generation_"+pin.first,[&](Evidence&e){e.recovery[pin.first].lease->checked_at.generation++;});
    reject("missing_hash_"+pin.first,[&](Evidence&e){e.recovery.erase(pin.first);});
  }
  reject("wrong_physical_recovery_size",[](Evidence&e){--e.recovery["recovery_a"].value.bytes;});
  reject("parent_identity_unknown",[](Evidence&e){e.identity.value.parent_is_recovery=Truth::No;});
  reject("wrong_parent_executable",[](Evidence&e){e.identity.value.parent_executable_sha256=std::string(64,'0');});
  reject("wrong_device",[](Evidence&e){e.identity.value.product="other";});
  reject("not_normal_recovery",[](Evidence&e){e.identity.value.normal_recovery=Truth::No;});
  reject("wrong_pair_version",[](Evidence&e){e.identity.value.pair_version="intermediate";});
  reject("wrong_pair_record",[](Evidence&e){e.identity.value.pair_record_sha256=std::string(64,'0');});
  for(const auto a:{Absence::Unknown,Absence::Present,Absence::PermissionDenied,Absence::OtherError})
    reject("absence_not_enoent_"+std::to_string(static_cast<int>(a)),[&](Evidence&e){e.afterromflash.value=a;});
  reject("zip_wrong_certificate",[](Evidence&e){e.zip_signature.value.certificate_sha256=std::string(64,'0');});
  reject("zip_wrong_handle",[](Evidence&e){e.zip_signature.value.open_handle_id="different";});
  reject("zip_wrong_full_digest_binding",[](Evidence&e){e.zip_signature.value.package.sha256=std::string(64,'0');});
  reject("zip_crypto_not_valid",[](Evidence&e){e.zip_signature.value.cryptographic_signature_valid=Truth::No;});
  reject("firmware_missing",[](Evidence&e){e.firmware.erase(e.firmware.begin());});
  reject("firmware_wrong_hash",[](Evidence&e){e.firmware.begin()->second.value.sha256=std::string(64,'0');});
  reject("firmware_wrong_prefix_length",[](Evidence&e){e.firmware.begin()->second.value.bytes--;});
  reject("payload_missing",[](Evidence&e){e.payloads.erase("super");});
  reject("payload_wrong_expanded_hash",[](Evidence&e){e.payloads["super"].value.sha256=std::string(64,'0');});
  reject("payload_wrong_fd",[](Evidence&e){e.payloads["super"].lease->handle_id="different";});
  reject("content_identity_change",[](Evidence&e){e.recovery.begin()->second.lease->same_identity=Truth::No;});
  reject("content_future_end",[](Evidence&e){e.recovery.begin()->second.lease->completed_ms+=100;});
  reject("content_false_retimestamp",[](Evidence&e){e.recovery.begin()->second.binding.observed_ms++;});
  reject("workflow_scope_unknown",[](Evidence&e){e.inventory.value.single_recovery_workflow=Truth::Unknown;});
  test("long_content_validation_and_fresh_volatile_state",[]{
    auto e=valid(); e.binding.observed_ms+=600000; refresh(e);
    require(check(e).ok,"valid retained content rejected by two-second volatile window");
  });
  test("physical_open_count_not_required",[]{
    auto e=valid();for(auto& n:e.inventory.value.nodes) if(n.kind==Kind::Partition)n.open_count.reset();
    require(check(e).ok,"invented physical open count required");
  });
  test("final_vbmeta_may_equal_intermediate",[]{
    auto e=valid(); auto m=manifest();
    m.pair.vbmeta_a.sha256="2c3ad5c1ebdf271a6c2363d5367791e52bf119683091100254143f476587777c";
    m.images.back().sha256=m.pair.vbmeta_a.sha256;e.payloads["vbmeta_a"].value.sha256=m.pair.vbmeta_a.sha256;
    require(preflight(m,requests(),e,e.binding.observed_ms).ok,"unchanged approved vbmeta incorrectly blacklisted");
  });
  for(const auto sv:{SnapshotValue::Unknown,SnapshotValue::Initiated,SnapshotValue::Unverified,
                    SnapshotValue::Merging,SnapshotValue::Cancelled,SnapshotValue::Error}) {
    for(auto field:{&SnapshotEvidence::hal,&SnapshotEvidence::metadata})
      reject("snapshot_non_none_"+std::to_string(passed),[&](Evidence&e){e.snapshot.value.*field=sv;});
  }
  for(auto field:{&SnapshotEvidence::hal_complete,&SnapshotEvidence::metadata_readable,
                  &SnapshotEvidence::metadata_inspectable,&SnapshotEvidence::exact_metadata_mount,
                  &SnapshotEvidence::metadata_clean_complete})
    reject("snapshot_missing_inspection_"+std::to_string(passed),[&](Evidence&e){e.snapshot.value.*field=Truth::Unknown;});
  reject("super_not_a_populated",[](Evidence&e){e.layout.value.a_populated=Truth::Unknown;});
  reject("super_not_b_empty",[](Evidence&e){e.layout.value.b_empty=Truth::No;});
  reject("super_hash_changed",[](Evidence&e){e.layout.value.reconstructed_super.sha256=std::string(64,'0');});
  reject("unknown_mount_inventory",[](Evidence&e){e.inventory.value.mounts_complete=Truth::Unknown;});
  reject("unknown_partition_inventory",[](Evidence&e){e.inventory.value.partitions_complete=Truth::Unknown;});
  reject("unknown_dm_inventory",[](Evidence&e){e.inventory.value.mappings_complete=Truth::Unknown;});
  reject("target_mounted",[](Evidence&e){find(e,"boot_a").mounted=Truth::Yes;});
  reject("target_handle_identity_unknown",[](Evidence&e){find(e,"super").held_identity_checked=Truth::Unknown;});
  reject("dm_open_unknown",[](Evidence&e){add_linear(e);find(e,"logical-child").open_count.reset();});
  reject("super_capacity_not_exact",[](Evidence&e){++find(e,"super").capacity;++find(e,"super").extents[0].bytes;});
  reject("target_capacity_short",[](Evidence&e){--find(e,"super").capacity;});
  reject("target_identity_unknown",[](Evidence&e){find(e,"super").identity_verified=Truth::Unknown;});
  reject("extent_overflow",[](Evidence&e){find(e,"super").extents[0].begin=std::numeric_limits<uint64_t>::max();});
  reject("aliased_targets",[](Evidence&e){find(e,"boot_a").extents[0].begin=find(e,"super").extents[0].begin;});
  reject("alias_protected_b",[](Evidence&e){find(e,"boot_b").extents[0].begin=find(e,"super").extents[0].begin;});
  reject("incomplete_source_extents",[](Evidence&e){e.source.value.extents_complete=Truth::Unknown;});
  reject("incomplete_source_dependencies",[](Evidence&e){e.source.value.dependencies_complete=Truth::Unknown;});
  reject("source_not_readable",[](Evidence&e){e.source.value.readable=Truth::No;});
  reject("source_overlap",[](Evidence&e){e.source.value.extents=find(e,"super").extents;});
  reject("source_unknown_dependency",[](Evidence&e){e.source.value.dependencies={"missing"};});
  reject("source_on_target_logical",[](Evidence&e){add_linear(e);e.source.value.dependencies={"id:logical-child"};});
  reject("source_outside_claimed_backing",[](Evidence&e){e.source.value.extents[0].begin=0;});
  reject("dependency_cycle",[](Evidence&e){add_linear(e);find(e,"logical-base").dependencies={"id:logical-child"};});
  reject("dependency_unknown",[](Evidence&e){add_linear(e);find(e,"logical-base").dependencies={"missing"};});
  reject("linear_mounted",[](Evidence&e){add_linear(e);find(e,"logical-child").mounted=Truth::Yes;});
  reject("linear_open",[](Evidence&e){add_linear(e);find(e,"logical-child").open_count=1;});
  reject("linear_unknown_table",[](Evidence&e){add_linear(e);find(e,"logical-child").table_complete=Truth::Unknown;});
  for(const auto kind:{Kind::Crypto,Kind::Snapshot,Kind::Unknown,Kind::Other})
    reject("unsafe_target_mapping_kind_"+std::to_string(static_cast<int>(kind)),[&](Evidence&e){add_linear(e);find(e,"logical-child").kind=kind;});
  for(const auto kind:{RequestKind::Format,RequestKind::DeleteMetadata,RequestKind::CancelSnapshot,
                       RequestKind::DisableVerification,RequestKind::SelectB})
    test("forbidden_request_"+std::to_string(static_cast<int>(kind)),[&]{
      auto r=requests(); r[0].kind=kind; auto e=valid(); require(!preflight(manifest(),r,e,e.binding.observed_ms).ok,"forbidden request passed");
    });
  for(const auto name:{"boot_b","recovery_a","recovery_b","userdata","metadata"})
    test(std::string("forbidden_target_")+name,[&]{
      auto r=requests(); r[0].partition=name; auto e=valid(); require(!preflight(manifest(),r,e,e.binding.observed_ms).ok,"forbidden target passed");
    });
  test("unfinalized_contract",[]{auto m=manifest();m.pair.finalization=Status::Unknown;auto e=valid();require(!preflight(m,requests(),e,1001).ok,"unfinalized pair");});
  test("superseded_intermediate_pair",[]{auto m=manifest();m.pair.recovery_a.sha256="90f0279abe946fc9bd3152a18429828378b9d5e54eb553a3d20e66894068422c";auto e=valid();require(!preflight(m,requests(),e,1001).ok,"intermediate pair");});
  test("image_pin_override",[]{auto m=manifest();m.images[1].sha256=std::string(64,'0');auto e=valid();require(!preflight(m,requests(),e,1001).ok,"pin override");});
  test("stale_evidence",[]{auto e=valid();require(!preflight(manifest(),requests(),e,100000).ok,"stale passed");});
  test("future_evidence",[]{auto e=valid();require(!preflight(manifest(),requests(),e,1).ok,"future passed");});
  test("failed_preflight_is_terminal",[&]{auto e=valid();e.source.status=Status::Error;Session s(manifest(),requests());require(!s.next(e,1001),"bad preflight action");failed_stays_failed(s,e);});
  test("replayed_generation",[&]{auto e=valid();Session s(manifest(),requests());require(s.complete(good(next(s,e))),"write");require(!s.next(e,1001),"replay");failed_stays_failed(s,e);});
  test("changed_boot_binding",[&]{auto e=valid();Session s(manifest(),requests());require(s.complete(good(next(s,e))),"write");e.binding.boot="new-boot";refresh(e);require(!s.next(e,e.binding.observed_ms),"changed boot");failed_stays_failed(s,e);});
  test("individual_fact_stale_binding",[&]{auto e=valid();e.zip_signature.binding.boot="old";require(!check(e).ok,"mixed boot passed");});
  test("missing_receipt_is_terminal",[&]{auto e=valid();Session s(manifest(),requests());next(s,e);refresh(e);require(!s.next(e,e.binding.observed_ms),"missing receipt");failed_stays_failed(s,e);});
  test("out_of_order_receipt",[&]{auto e=valid();Session s(manifest(),requests());auto r=good(next(s,e));++r.sequence;require(!s.complete(r),"bad receipt");failed_stays_failed(s,e);});
  test("stale_receipt_generation",[&]{auto e=valid();Session s(manifest(),requests());auto r=good(next(s,e));++r.generation;require(!s.complete(r),"bad generation");failed_stays_failed(s,e);});
  std::vector<std::pair<std::string,std::function<void(Receipt&)>>> failures={
    {"receipt_wrong_boot",[](Receipt&r){r.binding.boot="other";}},
    {"expired_action",[](Receipt&r){r.started_ms+=kMaxEvidenceAgeMs+1;r.completed_ms=r.started_ms;}},
    {"receipt_bad_time",[](Receipt&r){r.completed_ms=r.started_ms-1;}},
    {"guard_revalidation_missing",[](Receipt&r){r.guard_revalidated=Truth::Unknown;}},
    {"target_exclusion_lost",[](Receipt&r){r.target_state_held=Truth::No;}},
    {"source_lost_during_action",[](Receipt&r){r.source_readable_throughout=Truth::No;}},
    {"short_write",[](Receipt&r){--r.transferred;}},
    {"excess_write",[](Receipt&r){++r.transferred;}},
    {"write_error",[](Receipt&r){r.status=Status::Error;}},
    {"write_timeout",[](Receipt&r){r.status=Status::Timeout;}},
    {"write_incomplete",[](Receipt&r){r.complete=Truth::No;}},
    {"fsync_error",[](Receipt&r){r.fsync_ok=Truth::No;}},
    {"fsync_unknown",[](Receipt&r){r.fsync_ok=Truth::Unknown;}},
    {"source_hash_mismatch",[](Receipt&r){r.source_digest.sha256=std::string(64,'0');}},
    {"readback_hash_mismatch",[](Receipt&r){r.readback_digest.sha256=std::string(64,'0');}},
    {"readback_short",[](Receipt&r){--r.readback_digest.bytes;}}
  };
  for(const auto& f:failures) test(f.first,[&]{
    auto e=valid();Session s(manifest(),requests());auto r=good(next(s,e));f.second(r);
    require(!s.complete(r),"write failure accepted");require(s.verified_writes()==0,"failed write counted");failed_stays_failed(s,e);
  });
  for(int race=0;race<6;++race) test("between_action_race_"+std::to_string(race),[&]{
    auto e=valid();Session s(manifest(),requests());require(s.complete(good(next(s,e))),"first write");refresh(e);
    if(race==0)find(e,"boot_a").mounted=Truth::Yes;
    if(race==1)find(e,"boot_a").held_identity_checked=Truth::No;
    if(race==2)e.source.value.readable=Truth::No;
    if(race==3)e.protected_partitions["boot_b"].value.sha256=std::string(64,'b');
    if(race==4)e.recovery["recovery_a"].value.sha256=std::string(64,'b');
    if(race==5)e.source.value.open_handle_id="different-fd";
    require(!s.next(e,e.binding.observed_ms),"race accepted");failed_stays_failed(s,e);
  });
  for(int mode=0;mode<4;++mode)test("teardown_failure_"+std::to_string(mode),[&]{
    auto e=valid();add_linear(e);Session s(manifest(),requests());auto r=good(next(s,e));
    if(mode==0){r.status=Status::Error;require(!s.complete(r),"remove error accepted");}
    else {
      require(s.complete(r),"remove receipt");refresh(e);
      if(mode==1)find(e,"logical-child").mounted=Truth::Yes;
      if(mode==2)find(e,"logical-child").open_count=1;
      require(!s.next(e,e.binding.observed_ms),"removed map still present accepted");
    }
    require(s.verified_writes()==0,"write preceded recheck");failed_stays_failed(s,e);
  });
  test("premature_slot_receipt",[]{auto e=valid();Session s(manifest(),requests());auto r=good(next(s,e));r.kind=ActionKind::SelectA;r.subject="a";require(!s.complete(r),"premature slot");failed_stays_failed(s,e);});
  test("last_write_failure_never_selects_a",[]{auto e=valid();Session s(manifest(),requests());for(int i=0;i<6;++i){require(s.complete(good(next(s,e))),"write");refresh(e);}auto r=good(next(s,e));r.fsync_ok=Truth::No;require(!s.complete(r),"last fsync");failed_stays_failed(s,e);});
  test("final_recovery_preservation_recheck",[]{auto e=valid();Session s(manifest(),requests());finish_writes(s,e);e.protected_partitions["recovery_a"].value.sha256=std::string(64,'0');require(!s.next(e,e.binding.observed_ms),"final recovery changed");failed_stays_failed(s,e);});
  test("final_old_preservation_read_rejected",[]{
    auto e=valid();Session s(manifest(),requests());
    for(size_t i=0;i<write_allowlist().size();++i){require(s.complete(good(next(s,e))),"write");refresh(e);}
    require(!s.next(e,e.binding.observed_ms),"old protected digests accepted at final slot");
  });
  test("slot_failure_not_success",[]{auto e=valid();Session s(manifest(),requests());finish_writes(s,e);auto r=good(next(s,e));r.slot_a_confirmed=Truth::No;require(!s.complete(r),"slot failure");failed_stays_failed(s,e);});
  std::cout<<"TOTAL\t"<<passed<<"\n"; return 0;
 } catch(const std::exception& e){std::cerr<<"FAIL after "<<passed<<" checks: "<<e.what()<<"\n";return 1;}
}
