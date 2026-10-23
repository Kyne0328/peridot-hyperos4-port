"""Build an explicitly NON-FLASHABLE signed RI8 staging ZIP.

Only super, vbmeta and vbmeta_system images are included. Kernel and all
separate ReSukiSU/SUSFS modules are untouched, and there is deliberately no
update-binary/updater-script: a kernel-preserving production recovery updater
needs independent design, fixture tests and an authorized live preflight.
"""
from __future__ import annotations
from pathlib import Path
import hashlib
import json
import os
import shutil
import sys
import zipfile

ROOT=Path(__file__).resolve().parents[2]
WORK=Path("D:/hyperos4-peridot-kyneos-ri8-20261014/work")
OUT=Path("D:/hyperos4-peridot-kyneos-ri8-20261014/outputs")
BASE=ROOT/"builder/work/screen-recorder-call-audio-20261007"
NAME="KyneOS-RI8-STAGING-NOT-FLASHABLE-20261014.zip"
sys.path.insert(0,str(ROOT/"tools/installer-ri3/zip-signing"))
from sign_zip import sign_generated_zip

def sha(path):
    with Path(path).open("rb") as f:
        return hashlib.file_digest(f,"sha256").hexdigest()

def main():
    assembly=json.loads((WORK/"ri8-assembly.json").read_text(encoding="utf-8"))
    if not all(assembly[key] for key in ("only_vendor_span_changed",
          "all_other_super_bytes_verified_identical",
          "root_vbmeta_only_vendor_descriptor_changed",
          "root_vbmeta_boot_chain_descriptors_preserved",
          "avb_key_rollback_flags_preserved",
          "system_ri7_3_preserved")):
        raise ValueError("RI8 image assembly safety assertion failed")
    if assembly["boot_init_boot_vendor_boot_recovery_kernel_modified"] or assembly["boot_init_boot_vendor_boot_recovery_kernel_flash_allowed"]:
        raise ValueError("Kernel/boot stack must never be a candidate write")
    prev=json.loads((BASE/"screenrecorder-call-audio-assembly.json").read_text(encoding="utf-8"))
    paths=[
        ("images/super.img",Path(assembly["output_super"]),assembly["output_super_sha256"]),
        ("images/vbmeta.img",Path(assembly["output_vbmeta"]),assembly["output_vbmeta_sha256"]),
        ("images/vbmeta_system.img",Path(prev["output_vbmeta_system"]),prev["output_vbmeta_system_sha256"]),
    ]
    for n,p,hashval in paths:
        if not p.is_file() or sha(p)!=hashval:
            raise ValueError("Image is not pinned: "+n)
    OUT.mkdir(parents=True,exist_ok=True)
    final=OUT/NAME
    partial=OUT/(NAME+".partial")
    if final.exists() or partial.exists():
        raise FileExistsError("Refuse overwrite")
    if shutil.disk_usage(OUT).free<23*1024**3:
        raise RuntimeError("Insufficient reserve for staged ZIP and signature")
    notice=(
        "KYNEOS RI8 DEVELOPMENT IMAGES. DO NOT FLASH OR INSTALL.\n"
        "Only two verified Qualcomm seccomp policy rules are modified relative to the\n"
        "RI7.3 system+vendor base. The other requested groups need additional fixes.\n"
        "No boot/init_boot/vendor_boot/dtbo/recovery/kernel/root-addon payload exists here.\n"
        "This archive intentionally has NO recovery updater-script/update-binary.\n"
        "Flash protection: no untested recovery or fastboot procedure is authorized.\n"
        "The ROM still needs a selective, source/target-hash-guarded installer that\n"
        "writes super and both AVB metadata partitions safely without boot images.\n"
        "Android UI, charging, SELinux binder lookups and performance remain OPEN.\n"
    )
    manifest={
        "identity":"KYNEOS-RI8-STAGING-20261014",
        "release_status":"NOT_FLASHABLE_INCOMPLETE_4_GROUPS",
        "based_on":"KYNEOS-RI7.3-20261007",
        "target":"POCO F6 peridot Android17",
        "image_paths":{n:{"bytes":p.stat().st_size,"sha256":h} for n,p,h in paths},
        "only_vendor_policy_paths_changed":[
          "/vendor/etc/seccomp_policy/atfwd@2.0.policy",
          "/vendor/etc/seccomp_policy/qesdksec.policy"],
        "changes":"Add lseek: 1 to the two exact peridot Qualcomm minijail policies; retain RI7.3 system with call-audio hook unchanged",
        "kernel_recovery_root_addons_changed":False,
        "kernel_recovery_root_addons_in_archive":False,
        "external_modules_touched":False,
        "charging_HAL_fix_implemented":False,
        "ANR_performance_fix_implemented":False,
        "SELinux_binder_producer_compatibility_fix_implemented":False,
        "camera_policy_integrated":False,
        "recoverable_safe_selective_installer_implemented":False,
        "functional_device_regression_tested":False,
        "flashed":False
    }
    with zipfile.ZipFile(partial,"x",allowZip64=True) as z:
        for name,p,h in paths:
            info=zipfile.ZipInfo(name)
            info.compress_type=zipfile.ZIP_STORED
            info.file_size=p.stat().st_size
            digest=hashlib.sha256()
            print("Packing",name,flush=True)
            with z.open(info,"w",force_zip64=True) as dest,p.open("rb") as src:
                for block in iter(lambda:src.read(4*1024*1024),b""):
                    dest.write(block)
                    digest.update(block)
            if digest.hexdigest()!=h:
                raise ValueError("Packed source image drift "+name)
        z.writestr("DO-NOT-FLASH.txt",notice)
        z.writestr("RI8-STAGING-MANIFEST.json",json.dumps(manifest,indent=2)+"\n")
        signing=json.loads((ROOT/"builder/work/installer-ri5-recoveryfix-20261004/signing-public.json").read_text())
        z.writestr("META-INF/com/android/otacert",(ROOT/signing["certificate_path"]).read_bytes())
    with zipfile.ZipFile(partial) as z:
        if len(z.namelist())!=6 or "META-INF/com/google/android/update-binary" in z.namelist() or "META-INF/com/google/android/updater-script" in z.namelist():
            raise ValueError("Unsafe recovery installer unexpectedly present")
        for name,p,h in paths:
            with z.open(name) as f:
                observed=hashlib.file_digest(f,"sha256").hexdigest()
            if observed!=h:
                raise ValueError("ZIP member CRC/hash readback failed "+name)
    partial.rename(final)
    signing=json.loads((ROOT/"builder/work/installer-ri5-recoveryfix-20261004/signing-public.json").read_text())
    (ROOT/"builder/work/kyneos-ri8-20261014").mkdir(parents=True,exist_ok=True)
    signature=sign_generated_zip(final,ROOT/signing["certificate_path"],ROOT/signing["private_key_path"],
       generated_root=OUT,generated_parent=OUT.parent,work_dir=ROOT/"builder/work/kyneos-ri8-20261014",
       expected_cert_sha256=signing["certificate_der_sha256"],reserve_bytes=2*1024**3)
    if not signature["verified"]:
        raise ValueError("Staging ZIP signature not verified")
    result={"archive":str(final),"bytes":final.stat().st_size,"sha256":sha(final),
      "signed":True,"signature_verified":True,"recoverable_update_installer":False,
      "all_three_images_verified":True,"ROM_boot_tested":False,"safe_to_flash":False,
      "kernel_and_addons_not_touched":True,"manifest":manifest}
    (OUT/"STAGING-VALIDATION.json").write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8")
    (OUT/(NAME+".sha256")).write_text(result["sha256"]+"  "+NAME+"\n",encoding="utf-8")
    (OUT/"README-DO-NOT-FLASH.txt").write_text(notice,encoding="utf-8")
    print(json.dumps({k:result[k] for k in ("archive","bytes","sha256","safe_to_flash")},indent=2),flush=True)

if __name__=="__main__":
    main()
