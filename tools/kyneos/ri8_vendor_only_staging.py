"""Create a smaller, signed *non-installable* RI8 vendor-only hotfix image set.

This supersedes the 9 GiB staging *for review*, not for flashing. Its only
partition payloads are the verified vendor_a bytes and vbmeta_a bytes.
Before any future bootloader/recovery use, the old vbmeta on the phone MUST
match the pinned original: an independently modified ReSukiSU bootchain may
have changed its verity expectations. Never overwrite modified AVB blindly.
"""
from __future__ import annotations

from pathlib import Path
import hashlib
import json
import shutil
import sys
import zipfile

ROOT=Path(__file__).resolve().parents[2]
STAGE=Path("D:/hyperos4-peridot-kyneos-ri8-20261014/work")
OUT=Path("D:/hyperos4-peridot-kyneos-ri8-20261014/outputs")
NAME="KyneOS-RI8-VENDOR-ONLY-STAGING-NOT-FLASHABLE-20261014.zip"
sys.path.insert(0,str(ROOT/"tools/installer-ri3/zip-signing"))
from sign_zip import sign_generated_zip

def sha(p:Path)->str:
    with p.open("rb") as stream:
        return hashlib.file_digest(stream,"sha256").hexdigest()

def plan():
    original=json.loads((ROOT/"builder/work/kyneos-ri7-20261005/ASSEMBLY.json").read_text(encoding="utf-8"))
    previous={p["name"]:p for p in original["pins"]}
    assembly=json.loads((STAGE/"ri8-assembly.json").read_text(encoding="utf-8"))
    for k in ("only_vendor_span_changed","root_vbmeta_only_vendor_descriptor_changed",
              "root_vbmeta_boot_chain_descriptors_preserved","avb_key_rollback_flags_preserved"):
        if assembly[k] is not True:
            raise ValueError("Assembly safety gate not met: "+k)
    if assembly["source_root_vbmeta_sha256"] != previous["vbmeta"]["sha256"]:
        raise ValueError("Old root vbmeta is not the pinned known RI7.1 build")
    if assembly["boot_init_boot_vendor_boot_recovery_kernel_modified"] or assembly["boot_init_boot_vendor_boot_recovery_kernel_flash_allowed"]:
        raise ValueError("Kernel/recovery preservation requirement violated")
    vendor=Path(assembly["output_vendor"])
    vbmeta=Path(assembly["output_vbmeta"])
    images=[
        ("images/vendor_a.img",vendor,assembly["output_vendor_sha256"]),
        ("images/vbmeta_a.img",vbmeta,assembly["output_vbmeta_sha256"]),
    ]
    for name,path,h in images:
        if not path.is_file() or sha(path)!=h:
            raise ValueError("Required target image missing or drifted: "+name)
    installed_vendor=(ROOT/"builder/work/kyneos-ri7-20261005/vendor.img")
    if sha(installed_vendor)!=json.loads((STAGE/"vendor-ri8-repack.json").read_text())["source_vendor_sha256"]:
        raise ValueError("Installed vendor baseline pin changed")
    return {
        "status":"DO_NOT_FLASH__NO_INSTALLER__OPEN_RUNTIME_TESTS",
        "device":"peridot",
        "source_build":"KYNEOS-RI7.1-20261005",
        "target_component":"KyneOS RI8 Qualcomm seccomp policy correction only",
        "source_vendor_a_sha256":sha(installed_vendor),
        "source_vbmeta_a_sha256":previous["vbmeta"]["sha256"],
        "source_vbmeta_a_must_match_live_before_any_write":True,
        "current_custom_kernel_root_avb_compatibility":"UNKNOWN; mismatch MUST abort",
        "required_write_allowlist":["vendor_a","vbmeta_a"],
        "source_super_logical_partition_span":{"offset_bytes":assembly["vendor_a_offset_bytes"],"bytes":assembly["vendor_a_size_bytes"]},
        "must_verify_actual_super_metadata_in_recovery":True,
        "boot_stack_preservation":["boot_a","boot_b","init_boot_a","init_boot_b","vendor_boot_a","vendor_boot_b",
                                   "dtbo_a","dtbo_b","recovery_a","recovery_b"],
        "kernel_ReSukiSU_root_modules_updated":False,
        "user_data_updated":False,
        "changed_original_vendor_paths":[
            "/etc/seccomp_policy/atfwd@2.0.policy",
            "/etc/seccomp_policy/qesdksec.policy",
        ],
        "target_images":{name:{"bytes":path.stat().st_size,"sha256":h} for name,path,h in images},
        "boot_stack_and_userdata_payloads_included":False,
        "device_flashed":False,
        "recovery_installer_present":False,
        "charging_hal_fixed":False,
        "ANR_performance_fixed":False,
        "binder_service_discovery_fixed":False,
        "qualified_release":False,
    },images

def main():
    manifest, images=plan()
    OUT.mkdir(parents=True,exist_ok=True)
    if shutil.disk_usage(OUT).free<5*1024**3:
        raise RuntimeError("Insufficient disk-space reserve")
    target=OUT/NAME
    if target.exists() or (OUT/(NAME+".partial")).exists():
        raise FileExistsError("Refusing to overwrite existing signed evidence archive")
    keys=json.loads((ROOT/"builder/work/installer-ri5-recoveryfix-20261004/signing-public.json").read_text())
    cert=(ROOT/keys["certificate_path"]).read_bytes()
    work=ROOT/"builder/work/kyneos-ri8-20261014"
    work.mkdir(parents=True,exist_ok=True)
    partial=OUT/(NAME+".partial")
    with zipfile.ZipFile(partial,"x",allowZip64=True) as z:
        for name,path,digest in images:
            info=zipfile.ZipInfo(name)
            info.compress_type=zipfile.ZIP_STORED
            info.file_size=path.stat().st_size
            h=hashlib.sha256()
            with z.open(info,"w",force_zip64=True) as dst,path.open("rb") as src:
                for chunk in iter(lambda:src.read(4*1024*1024),b""):
                    dst.write(chunk)
                    h.update(chunk)
            if h.hexdigest()!=digest:
                raise ValueError("Input image changed during packaging")
        z.writestr("RI8-VENDOR-ONLY-MANIFEST.json",json.dumps(manifest,indent=2)+"\n")
        z.writestr("DO-NOT-FLASH.txt",
                   "Not an installable update. Root vbmeta must be matched against running kernel changes before any future flash. "
                   "No recovery updater included. No boot or ReSukiSU changes. The three other requested fixes remain open.\n")
        z.writestr("META-INF/com/android/otacert",cert)
    with zipfile.ZipFile(partial) as z:
        expected={"images/vendor_a.img","images/vbmeta_a.img","RI8-VENDOR-ONLY-MANIFEST.json",
                  "DO-NOT-FLASH.txt","META-INF/com/android/otacert"}
        if set(z.namelist())!=expected:
            raise ValueError("Unexpected ZIP content")
        for name,path,digest in images:
            with z.open(name) as stream:
                if hashlib.file_digest(stream,"sha256").hexdigest()!=digest:
                    raise ValueError("ZIP decoded image readback mismatch")
    partial.rename(target)
    sig=sign_generated_zip(target,ROOT/keys["certificate_path"],ROOT/keys["private_key_path"],
                           generated_root=OUT,generated_parent=OUT.parent,work_dir=work,
                           expected_cert_sha256=keys["certificate_der_sha256"],
                           reserve_bytes=2*1024**3)
    if not sig["verified"]:
        raise ValueError("Signature failed independent verification")
    with zipfile.ZipFile(target) as z:
        if set(z.namelist())!=expected or any("update-binary" in n or "updater-script" in n for n in z.namelist()):
            raise ValueError("Unsafe updater introduced during signing")
        for name,path,digest in images:
            with z.open(name) as stream:
                if hashlib.file_digest(stream,"sha256").hexdigest()!=digest:
                    raise ValueError("Signed ZIP image hash drift")
    receipt={"archive":str(target),"bytes":target.stat().st_size,"sha256":sha(target),
             "signature_verified":True,"signed_image_members_verified":True,
             "exact_write_allowlist":manifest["required_write_allowlist"],
             "root_avb_source_compatibility_unknown":True,
             "boot_stack_root_modules_unchanged":True,
             "recovery_installer_present":False,"safe_to_flash":False}
    (OUT/"RI8-VENDOR-ONLY-VALIDATION.json").write_text(json.dumps(receipt,indent=2)+"\n",encoding="utf-8")
    (OUT/(NAME+".sha256")).write_text(receipt["sha256"]+"  "+NAME+"\n",encoding="utf-8")
    print(json.dumps(receipt,indent=2),flush=True)

if __name__=="__main__":
    main()
