"""Author RI8 read-only recovery updater candidate by a guarded adaptation of RI5.

Generator fails if pinned source, anchors or security constraints drift.
The Android binary must refuse ALL write operations until a separate,
independently reviewed device-validation release enables them.
"""
from pathlib import Path
import hashlib
import json

ROOT=Path(__file__).resolve().parents[2]
SRC=ROOT/"tools/installer-ri5/install_runtime.cpp"
MAIN=ROOT/"builder/work/installer-ri5-stream-20261004/native/main.cpp"
DEST=ROOT/"builder/work/kyneos-ri8-20261014/native"
SHA_SOURCE="333d2181bcf6024f3a3f409598b1b333bdcfb82757db8332b45874c72d8e67af"
SHA_MAIN="7f81eef6912e191989a878249c47c2a3b21b46c8d06de58e9e2a055e56c10496"

def hashit(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
def replace_once(text,old,new):
    count=text.count(old)
    if count!=1:
        raise ValueError(f"expected unique source anchor (found {count}) {old[:110]!r}")
    return text.replace(old,new,1)

def main():
    if hashit(SRC)!=SHA_SOURCE or hashit(MAIN)!=SHA_MAIN:
        raise ValueError("RI5 trusted updater sources changed: re-review required")
    DEST.mkdir(parents=True,exist_ok=True)
    files=[DEST/"install_runtime.cpp",DEST/"main.cpp",DEST/"image_pins.h"]
    if any(p.exists() for p in files):
        raise FileExistsError("Refusing to overwrite an existing RI8 native build")
    c=SRC.read_text(encoding="utf-8")
    c=replace_once(c,"// RI5: compressed raw-image streaming from a working recovery on either slot.",
                   "// RI8 read-only preview: two-image vendor-span plan; Android device writes COMPILE-TIME DISABLED.")
    c=replace_once(c,"void Need(bool v,const std::string& e){if(!v)throw std::runtime_error(e);}",
                   """void Need(bool v,const std::string& e){if(!v)throw std::runtime_error(e);}
constexpr uint64_t kVendorOffset=8496611328ULL;
constexpr uint64_t kVendorBytes=430030848ULL;
constexpr uint64_t kSuperBytes=9126805504ULL;
constexpr uint64_t kMegabyte=1048576ULL;
constexpr char kOldVendorSha[]="42b6e24e3ee5a665535621920d77a88ffd6d99ec2359522bc8a8e82cc6a5a9a7";
constexpr char kOldVbmetaSha[]="225a9dca237c0c46e1e74d44447eb56f9d3d8882ac2b6000bc8e6795aec4cd2d";
constexpr char kSuperStartSha[]="32e08612b68c2a48e27bce245e7251f93b9a3ffa3c7afbfe2373131f2d2e6049";
constexpr char kSuperEndSha[]="30e14955ebf1352266dc2ff8067e68104607e750abb9d3b36582b8af909fcb58";
static_assert(kVendorOffset+kVendorBytes<=kSuperBytes,"vendor subrange outside pinned super");""")
    c=replace_once(c,"struct Payload{const ri4::Pin*pin;};",
                   """// Even a future privileged writer may access vendor only within the exact
// independently pinned super extent. This class cannot address boot/recovery.
class VendorSpanSink final : public ri3::OutputSink {
    ri3::OutputSink& backing_;
public:
    explicit VendorSpanSink(ri3::OutputSink& backing):backing_(backing) {
        Need(backing.Capacity()==kSuperBytes,"shared super capacity differs");
    }
    uint64_t Capacity() const override {return kVendorBytes;}
    void Write(uint64_t off,const void*bytes,size_t len) override {
        Need(off<=kVendorBytes&&len<=kVendorBytes-off,"vendor span write overflow");
        backing_.Write(kVendorOffset+off,bytes,len);
    }
    void Read(uint64_t off,void*bytes,size_t len) const override {
        Need(off<=kVendorBytes&&len<=kVendorBytes-off,"vendor span read overflow");
        backing_.Read(kVendorOffset+off,bytes,len);
    }
    void Sync() override {backing_.Sync();}
};
struct Payload{const ri4::Pin*pin;};""")
    c=replace_once(c,"std::string(\"partitions/\")+pin.name+\".bin\"",
                   "std::string(\"partitions/\")+pin.name+\".bin\"") if False else c
    c=replace_once(c,"std::string target=name==\"super\"?name:name+\"_a\";",
                   "std::string target=name==\"vendor\"?\"super\":name+\"_a\";")
    c=replace_once(c,"n=n==\"super\"?n:n+\"_a\";targets_.insert(n);",
                   "n=n==\"vendor\"?\"super\":n+\"_a\";targets_.insert(n);")
    c=replace_once(c,"n.kind==g::Kind::Partition&&(targets_.count(n.partition)||n.partition.size()>2&&n.partition.substr(n.partition.size()-2)==\"_b\")",
                   "n.kind==g::Kind::Partition&&(targets_.count(n.partition)||(n.partition.size()>2&&(n.partition.substr(n.partition.size()-2)==\"_a\"||n.partition.substr(n.partition.size()-2)==\"_b\")))")
    c=replace_once(c,"  source_extents_=source_.Describe(inventory_).extents;metadata_=std::make_unique<sn::MetadataLease>(inventory_);State(true);",
                   """  // Preflight source ABI + known-unmodified root AVB. A custom ReSukiSU
  // root vbmeta MUST fail, rather than having its boot digests overwritten.
  const auto& super=Named(inventory_,"super");
  Need(super.capacity==kSuperBytes,"unexpected super partition capacity");
  const int superfd=held_.at("super")->Fd();
  Need(HashFdRange(superfd,0,kMegabyte)==kSuperStartSha,"super LP metadata prefix drift");
  Need(HashFdRange(superfd,kSuperBytes-kMegabyte,kMegabyte)==kSuperEndSha,"super metadata suffix drift");
  Need(HashFdRange(superfd,kVendorOffset,kVendorBytes)==kOldVendorSha,"installed vendor bytes/source pin mismatch");
  Need(HashFdRange(held_.at("vbmeta_a")->Fd(),0,12288)==kOldVbmetaSha,
       "custom root vbmeta: cannot overwrite ReSukiSU boot-chain verification metadata");
  source_extents_=source_.Describe(inventory_).extents;metadata_=std::make_unique<sn::MetadataLease>(inventory_);State(true);""")
    c=replace_once(c,"\"Preserved B partition changed: \"", "\"Protected A/B partition changed: \"")
    c=replace_once(c,"\"Read-only preflight: source backing, all 32 target identities/capacities and clean snapshot state verified.\"",
                   "\"Read-only preflight: vendor extent/root AVB source pin, two target identities and clean snapshot state verified.\"")
    c=replace_once(c,"// Compiled plan is super, firmware, complete boot stack, recovery, vbmeta_system, vbmeta.",
                   "// Compiled plan is vendor subrange within super and vbmeta_a ONLY; boot stack is protected.")
    c=replace_once(c,"std::string target=p.pin->name;target=target==\"super\"?target:target+\"_a\";",
                   "std::string target=p.pin->name;target=target==\"vendor\"?\"super\":target+\"_a\";")
    c=replace_once(c,"""   ri5::StreamImage(*zip_,std::string("partitions/")+p.pin->name+".bin",{p.pin->bytes,p.pin->sha},&sink,
    [&](uint64_t done,uint64_t){if(progress_)progress_(done_bytes+done,total_work);},
    [&](const std::string&phase){if(message_)message_(phase+" "+target);});""",
                   """   if(std::string(p.pin->name)=="vendor"){
     VendorSpanSink bounded(sink);
     ri5::StreamImage(*zip_,"partitions/vendor.bin",{p.pin->bytes,p.pin->sha},&bounded,
      [&](uint64_t done,uint64_t){if(progress_)progress_(done_bytes+done,total_work);},
      [&](const std::string&phase){if(message_)message_(phase+" vendor_a");});
   }else{
     Need(std::string(p.pin->name)=="vbmeta","unexpected writable target");
     ri5::StreamImage(*zip_,"partitions/vbmeta.bin",{p.pin->bytes,p.pin->sha},&sink,
      [&](uint64_t done,uint64_t){if(progress_)progress_(done_bytes+done,total_work);},
      [&](const std::string&phase){if(message_)message_(phase+" vbmeta_a");});
   }""")
    c=replace_once(c,"try{Need(sig&&sig->verified,\"Unverified package\");Device d(fd,m,p,*sig);d.Prepare();r.mutations_started=true;d.Unmount();d.WriteAll();r.success=true;}catch(const std::exception&e){r.error=e.what();}",
                   """// Production write is unconditionally disabled until separate recovery
 // preflight, failure-injection, and AVB/custom-kernel compatibility tests.
 // Never enable by macro or by merely renaming an image archive.
 (void)fd;(void)m;(void)p;(void)sig;
 r.error="RI8 recovery install disabled: only verified read-only preview is authorized";""")
    c=replace_once(c,"\"RI5\"", "\"RI8\"")
    # static deployment gates
    if c.count("r.mutations_started=true") or "RI8 recovery install disabled" not in c:
        raise ValueError("RI8 native write blocker not compiled in")
    if "boot_a\", \"dtbo_a" in c or "kVendorOffset+off" not in c:
        raise ValueError("Forbidden boot target or missing bounded write in generated source")
    m=MAIN.read_text(encoding="utf-8")
    if not "ri5_install" in m:
        raise ValueError("Expected RI5 main function missing")
    m=m.replace("ri5_install","ri8_install").replace("ri5_preview","ri8_preview")
    m=m.replace("RI5_READONLY","RI8_READONLY")
    # build unchanged source deps, but preview path must verify two package members.
    srcpins=ROOT/"builder/work/kyneos-ri8-20261014/native/image_pins.h"
    header="""#pragma once
#include <cstdint>
namespace ri4 {
struct Pin{const char*name;uint64_t bytes;const char*sha;};
constexpr unsigned kImageCount=2;
inline const Pin kPins[]={
 {"vendor",430030848ULL,"e7a82d8718b08dfda2cc07bde19433fdf74ee06b236a5f4925da3fd3fe44333f"},
 {"vbmeta",12288ULL,"172a1b8ba1bb19a7a1e7155859d845fa5d3afba8b8431dec48ab41864290fbe0"},
};}
"""
    for p,data in ((files[0],c),(files[1],m),(files[2],header)):
        p.write_text(data,encoding="utf-8",newline="\n")
    print(json.dumps({"status":"RI8 recovery updater source generated with device-install compile-time disabled",
                      "files":[{"path":str(p),"bytes":p.stat().st_size,"sha256":hashit(p)} for p in files],
                      "source_sha256":SHA_SOURCE,"device_install_enabled":False,
                      "protected_flash_targets":["super vendor subrange","vbmeta_a"],
                      "kernel_boot_root_addons_write_allowed":False},indent=2))

if __name__=="__main__":
    main()
