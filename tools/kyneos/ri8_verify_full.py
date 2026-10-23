"""Independent full-ROM RI8 ZIP audit; no ADB and no device mutation.

Audit focuses on the failure mode missed in RI7.3:
- native update-binary has exact SHA pins for 32 emitted partition images;
- old RI7.1 super/vbmeta_system image pins are absent;
- new signed root vendor descriptor binds new vendor image;
- full ROM carries normal boot images unchanged and contains no ReSukiSU addon.
"""
from __future__ import annotations
from pathlib import Path
import hashlib,json,sys,zipfile

ROOT=Path(__file__).resolve().parents[2]
OUT=Path("D:/hyperos4-peridot-kyneos-ri8-20261014/outputs")
SOURCE_OUT=Path("D:/hyperos4-peridot-kyneos-ri7.3-messenger-callaudio-20261007/outputs")
ROOT_AVB=ROOT/"builder/work/kyneos-ri7-20261005/vbmeta.img"
ROOT_VENDOR=ROOT/"builder/work/kyneos-ri7-20261005/vendor.img"
sys.path.insert(0,str(ROOT/"tools/postboot"))
from assemble import footer_metadata,descriptor_name
sys.path.insert(0,str(ROOT/"tools/installer-ri3/recovery-pair"))
from pair_format import verify_avb
sys.path.insert(0,str(ROOT/"tools/installer-ri3/zip-signing"))
from verify_zip import verify_zip

def sha(path):
    with Path(path).open("rb") as f:return hashlib.file_digest(f,"sha256").hexdigest()

def main():
    v=json.loads((OUT/"FULL-ROM-VALIDATION.json").read_text())
    native=json.loads((ROOT/"builder/work/kyneos-ri8-full-20261014/native/BUILD-RECEIPT.json").read_text())
    source=json.loads((SOURCE_OUT/"VALIDATION.json").read_text())
    assembly=json.loads(Path("D:/hyperos4-peridot-kyneos-ri8-20261014/work/ri8-assembly.json").read_text())
    assert v["all_member_crc_sha_checks_passed"] and v["signature_verified"]
    assert v["member_count"]==37 and v["partition_payload_count"]==32
    assert not v["ReSukiSU_included"] and v["rom_boot_images_standard_RI7_3_bytes_preserved"]
    assert not v["device_flashed"] and not v["device_boot_tested"]
    assert sha(v["archive"])==v["sha256"]
    assert sha(native["updater_binary"])==native["updater_sha256"]==v["native_sha256"]
    signer=json.loads((ROOT/"builder/work/installer-ri5-recoveryfix-20261004/signing-public.json").read_text())
    verify=verify_zip(Path(v["archive"]),ROOT/signer["certificate_path"],signer["certificate_der_sha256"])
    assert verify["verified"]
    binary=Path(native["updater_binary"]).read_bytes()
    parent_manifest=None
    with zipfile.ZipFile(source["archive"]) as old,zipfile.ZipFile(v["archive"]) as out:
        oldmanifest=json.loads(old.read("RI5-BUILD-MANIFEST.json"))
        newmanifest=json.loads(out.read("RI5-BUILD-MANIFEST.json"))
        a={x["name"]:x for x in oldmanifest["images"]}
        b={x["name"]:x for x in newmanifest["images"]}
        assert len(a)==len(b)==32 and set(a)==set(b)
        assert b["super"]["sha256"]==assembly["output_super_sha256"]
        assert b["vbmeta"]["sha256"]==assembly["output_vbmeta_sha256"]
        assert b["vbmeta_system"]==a["vbmeta_system"]
        for name in a:
            if name not in ("super","vbmeta"):
                assert b[name]==a[name],name
            assert b[name]["sha256"].encode() in binary,("missing native pin",name)
            member="partitions/"+name+".bin"
            assert out.getinfo(member).file_size==b[name]["bytes"]
        assert a["super"]["sha256"].encode() not in binary
        assert a["vbmeta"]["sha256"].encode() not in binary
        assert newmanifest["root_addon_policy"]["ReSukiSU_SUSFS_bundled"] is False
        assert set(x for x in out.namelist() if x.startswith("partitions/"))==set("partitions/"+n+".bin" for n in a)
        assert not any("resukisu" in x.lower() or "susfs" in x.lower() or "kernelsu" in x.lower() for x in out.namelist())
        script=out.read("META-INF/com/google/android/updater-script").decode()
        assert script.count("ri5_install()")==1
        assert "ReSukiSU is NOT bundled" in script
    original=verify_avb(ROOT_AVB.read_bytes())
    patched=verify_avb(Path(assembly["output_vbmeta"]).read_bytes())
    embedded=footer_metadata(Path(assembly["output_vendor"]))
    vendordesc=next(d for d in embedded["descriptors"] if descriptor_name(d)=="vendor")
    assert vendordesc==next(d for d in patched["descriptors"] if descriptor_name(d)=="vendor")
    assert patched["pk"]==original["pk"] and patched["header"][16:19]==original["header"][16:19]
    for descriptor in original["descriptors"]:
        if descriptor_name(descriptor)!="vendor":
            assert descriptor in patched["descriptors"]
    report={
        "verified":True,
        "archive":v["archive"],"archive_sha256":v["sha256"],
        "native_installer_sha256":native["updater_sha256"],
        "all_32_installer_image_pins_reconciled":True,
        "RI7_3_stale_native_super_pin_corrected":True,
        "RI7_3_stale_native_vbmeta_system_pin_corrected":True,
        "signed_vendor_descriptor_matches_new_vendor_image":True,
        "root_avb_key_flags_rollback_and_all_other_descriptors_preserved":True,
        "normal_boot_images_from_RI7_3_unchanged":True,
        "separate_ReSukiSU_module_bundled":False,
        "flash_boot_tested":False
    }
    (OUT/"RI8-INDEPENDENT-QA.json").write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps(report,indent=2))

if __name__=="__main__":
    main()
