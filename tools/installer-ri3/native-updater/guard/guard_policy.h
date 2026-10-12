#pragma once
// RI3 deterministic guard policy. No collector, device I/O, ioctl, or Edify integration.
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace ri3::guard {
enum class Status { Unknown, Known, Error, Timeout };
enum class Truth { Unknown, No, Yes };
struct Binding {
  std::string session, boot, package;
  uint64_t generation = 0, observed_ms = 0;
  bool operator==(const Binding& b) const;
};
// Long content reads retain their true acquisition interval. A fresh descriptor
// identity check does not claim byte immutability; the supported workflow excludes
// concurrent external privileged writers. Final preservation hashes are re-read.
struct ContentLease {
  uint64_t started_ms = 0, completed_ms = 0;
  std::string handle_id, identity_token;
  Binding checked_at;
  Truth held_read_only = Truth::Unknown, same_identity = Truth::Unknown;
};
template<class T> struct Fact {
  Status status = Status::Unknown;
  Binding binding;
  T value{};
  std::optional<ContentLease> lease;
};
struct Digest { uint64_t bytes = 0; std::string sha256; };
struct Image { std::string partition; uint64_t bytes = 0; std::string sha256; };
// Trusted immutable build input, NEVER supplied by an untrusted ZIP or live collector.
// Finalization means approved bytes are pinned; it does NOT claim device readiness.
struct PairContract {
  Status finalization = Status::Unknown;
  std::string version, record_sha256;
  Digest recovery_a, vbmeta_a, otacerts;
};
struct Manifest {
  std::string id;
  std::vector<Image> images;
  PairContract pair;
};
const std::vector<std::string>& write_allowlist();
// Immutable production image-byte pins; package_id is the verified package identity.
Manifest production_manifest(const std::string& package_id, const PairContract& pair);
std::map<std::string, Digest> recovery_pins(const PairContract& pair);
const char* super_sha256();
const std::map<std::string, Digest>& firmware_pins();
#ifdef RI3_FILE_FIXTURE_RUNTIME
constexpr uint64_t kSuperBytes = 12288;
constexpr uint64_t kRecoveryBytes = 4096;
#else
constexpr uint64_t kSuperBytes = 9126805504ULL;
constexpr uint64_t kRecoveryBytes = 104857600ULL;
#endif
constexpr uint64_t kMaxEvidenceAgeMs = 2000;
enum class Absence { Unknown, Present, NoEntry, PermissionDenied, OtherError };
enum class SnapshotValue { Unknown, None, Initiated, Unverified, Merging, Cancelled, Error };
struct SnapshotEvidence {
  // bootctl is the HAL transport, not a second independent authority.
  SnapshotValue hal = SnapshotValue::Unknown, metadata = SnapshotValue::Unknown;
  Truth hal_complete = Truth::Unknown, metadata_readable = Truth::Unknown,
        metadata_inspectable = Truth::Unknown, exact_metadata_mount = Truth::Unknown,
        metadata_clean_complete = Truth::Unknown;
};
struct Identity {
  std::string product, parent_executable_sha256, pair_version, pair_record_sha256;
  Truth normal_recovery = Truth::Unknown, parent_is_recovery = Truth::Unknown;
};
struct ZipVerification {
  Digest package;
  uint64_t signed_bytes = 0;
  std::string certificate_sha256, open_handle_id;
  Truth cryptographic_signature_valid = Truth::Unknown;
};
struct Layout {
  Digest reconstructed_super;
  Truth a_populated = Truth::Unknown, b_empty = Truth::Unknown;
};
// Physical extent coordinates use a stable physical-disk identity and BYTE offsets.
// Partition/DM ancestry is not overlap. Intersecting byte intervals are overlap.
struct Extent { std::string disk; uint64_t begin = 0, bytes = 0; };
enum class Kind { Unknown, Partition, Linear, Crypto, Snapshot, Other, Verity };
struct Node {
  std::string id, partition, read_handle_id;
  Kind kind = Kind::Unknown;
  Truth identity_verified = Truth::Unknown, table_complete = Truth::Unknown,
        dependencies_complete = Truth::Unknown, extents_complete = Truth::Unknown,
        mounted = Truth::Unknown, held_identity_checked = Truth::Unknown,
        read_only = Truth::Unknown;
  // Required only for device-mapper nodes; physical devices have no such portable proof.
  std::optional<uint64_t> open_count;
  uint64_t capacity = 0;
  std::vector<std::string> dependencies;
  std::vector<Extent> extents;
};
struct Inventory {
  Truth partitions_complete = Truth::Unknown, mappings_complete = Truth::Unknown,
        mounts_complete = Truth::Unknown;
  Truth single_recovery_workflow = Truth::Unknown;
  std::vector<Node> nodes;
};
struct Source {
  std::string open_handle_id;
  Truth readable = Truth::Unknown, content_verified = Truth::Unknown,
        extents_complete = Truth::Unknown, dependencies_complete = Truth::Unknown;
  std::vector<Extent> extents;
  std::vector<std::string> dependencies;
};
struct Evidence {
  Binding binding;
  Fact<Identity> identity;
  std::map<std::string, Fact<Digest>> recovery;
  Fact<Absence> afterromflash;
  // The GUI toggles are declared setup prerequisites, never falsely attested here.
  Fact<ZipVerification> zip_signature;
  std::map<std::string, Fact<Digest>> firmware;
  std::map<std::string, Fact<Digest>> payloads;
  Fact<SnapshotEvidence> snapshot;
  Fact<Layout> layout;
  Fact<Inventory> inventory;
  Fact<Source> source;
  // Complete whole-partition hashes for recovery_a and every physical *_b partition.
  std::map<std::string, Fact<Digest>> protected_partitions;
};
enum class RequestKind { Write, Format, DeleteMetadata, CancelSnapshot, DisableVerification, SelectB };
struct Request { RequestKind kind = RequestKind::Write; std::string partition; };
struct Check {
  bool ok = false;
  std::string error;
  std::vector<std::string> teardown_order;
};
enum class PreflightPhase { Writes, BeforeTargetUnmount };
// Preparation checks all immutable/security/source conditions. The backend must
// separately prove the complete exact target-only unmount plan before mutation.
// Session never uses this phase to authorize writes or mapping removal.
Check preflight(const Manifest&, const std::vector<Request>&, const Evidence&, uint64_t now_ms,
                PreflightPhase phase = PreflightPhase::Writes);
enum class Stage { New, Ready, AwaitingReceipt, Failed, Succeeded };
enum class ActionKind { None, RemoveMapping, WriteImage, SelectA };
struct Action {
  ActionKind kind = ActionKind::None;
  uint64_t sequence = 0, generation = 0;
  Binding binding;
  uint64_t authorized_ms = 0, expires_ms = 0;
  std::string subject;
  Image image;
};
struct Receipt {
  uint64_t sequence = 0, generation = 0;
  Binding binding;
  uint64_t started_ms = 0, completed_ms = 0;
  Truth guard_revalidated = Truth::Unknown, target_state_held = Truth::Unknown,
        source_readable_throughout = Truth::Unknown;
  ActionKind kind = ActionKind::None;
  std::string subject;
  Status status = Status::Unknown;
  uint64_t transferred = 0;
  Truth complete = Truth::Unknown, fsync_ok = Truth::Unknown;
  Digest source_digest, readback_digest;
  // Slot receipt is accepted only for the already-authorized final SelectA action.
  Truth slot_a_confirmed = Truth::Unknown;
};
// State machine issues inert action descriptions. The caller must execute them through
// a future reviewed backend and obtain typed receipts. This class executes NOTHING.
class Session {
 public:
  Session(Manifest manifest, std::vector<Request> requests);
  std::optional<Action> next(const Evidence&, uint64_t now_ms);
  bool complete(const Receipt&);
  void fail(const std::string&);
  Stage stage() const { return stage_; }
  const std::string& error() const { return error_; }
  size_t verified_writes() const { return write_index_; }
 private:
  Manifest manifest_;
  std::vector<Request> requests_;
  Stage stage_ = Stage::New;
  std::string error_;
  Binding original_;
  uint64_t last_generation_ = 0, last_observed_ms_ = 0, last_completed_ms_ = 0, sequence_ = 0;
  size_t write_index_ = 0;
  std::optional<Action> pending_;
  std::map<std::string, Digest> original_protected_;
  std::map<std::string, Node> original_targets_;
  Source original_source_;
  std::vector<std::string> expected_remaining_;
  std::vector<std::string> removed_;
};
} // namespace ri3::guard
