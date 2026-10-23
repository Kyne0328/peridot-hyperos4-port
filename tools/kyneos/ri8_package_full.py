"""Package full RI8 KyneOS 32-partition recovery ROM; ReSukiSU is a separate after-ROM step.

Reuses exact signed RI7.3 37-member parent ZIP, replacing only:
  partitions/super.bin (RI7.3 system + RI8 Qualcomm vendor)
  partitions/vbmeta.bin (new AVB vendor descriptor)
  META-INF/com/google/android/update-binary (fresh RI8 32-image pins)
  META-INF/com/google/android/updater-script (accurate RI8 usage)
  RI5-BUILD-MANIFEST.json (accurate source + target hashes).
All other 32 members, including ROM's normal boot/init_boot/vendor_boot and
existing RI7.3 vbmeta_system, are byte-identical in expanded form.
The existing full-ROM updater reflashes stock ROM boot: user installs ReSukiSU
separately afterward. No root addon, kernel modification, or module is bundled.
"""
from __future__ import annotations
from pathlib import Path
import hashlib
import json
import shutil
import sys
import time
import zipfile

ROOT=Path(__file__).resolve().parents[2]
RI7_OUT=Path("D:/hyperos4-peridot-kyneos-ri7.3-messenger-callaudio-20261007/outputs")
RI8_OUT=Path("D:/hyperos4-peridot-kyneos-ri8-20261014/outputs")
RI8_WORK=Path("D:/hyperos4-peridot-kyneos-ri8-20261014/work")
NATIVE=ROOT/"builder/work/kyneos-ri8-full-20261014/native"
SOURCE_NAME="KyneOS-Global-HyperOS4-POCO-F6-RI7.3-20261007.zip"
NAME="KyneOS-Global-HyperOS4-POCO-F6-RI8-20261014.zip"
sys.path[:0]=[str(ROOT/"tools/installer-ri3/zip-signing"),str(ROOT/"tools/installer-ri5")]
from compressed_copy import copy_member
from sign_zip import sign_generated_zip

def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream,"sha256").hexdigest()

def main():
    start=time.monotonic()
    source=RI7_OUT/SOURCE_NAME
    previous=json.loads((RI7_OUT/"VALIDATION.json").read_text(encoding="utf-8"))
    if previous["archive"]!=str(source) or sha(source)!=previous["sha256"]:
        raise ValueError("RI7.3 trusted signed source archive drift")
    if not previous.get("all_member_crc_sha_checks_passed"):
        raise ValueError("RI7.3 source ZIP not validated")
    native=json.loads((NATIVE/"BUILD-RECEIPT.json").read_text(encoding="utf-8"))
    assembly=json.loads((RI8_WORK/"ri8-assembly.json").read_text(encoding="utf-8"))
    binary=Path(native["updater_binary"])
    if sha(binary)!=native["updater_sha256"] or native["image_count"]!=32:
        raise ValueError("New compiled native installer missing/mismatched")
    if not native["original_boot_images_preserved_in_source_plan"] or native["separately_installed_ReSukiSU_integrated"]:
        raise ValueError("Kernel/addon independence violated")
    overrides={
        "super":(Path(assembly["output_super"]),assembly["output_super_sha256"]),
        "vbmeta":(Path(assembly["output_vbmeta"]),assembly["output_vbmeta_sha256"]),
    }
    for part,(path,digest) in overrides.items():
        if sha(path)!=digest:
            raise ValueError("RI8 image source has changed: "+part)
    signing=json.loads((ROOT/"builder/work/installer-ri5-recoveryfix-20261004/signing-public.json").read_text(encoding="utf-8"))
    RI8_OUT.mkdir(parents=True,exist_ok=True)
    if shutil.disk_usage(RI8_OUT).free < 16*1024**3:
        raise RuntimeError("Free disk does not meet signed full ROM ZIP reserve")
    final=RI8_OUT/NAME
    partial=RI8_OUT/(NAME+".partial")
    if final.exists() or partial.exists():
        raise FileExistsError("Refusing to overwrite final or partial signed release")
    script="""ui_print("KyneOS RI8: Global HyperOS 4 for POCO F6 (peridot).");
ui_print("Includes RI7.3 UI/system updates and two Qualcomm seccomp vendor policy corrections.");
ui_print("Full 32-partition ROM installation; normal boot/init_boot/vendor_boot images overwrite existing custom kernel.");
ui_print("ReSukiSU is NOT bundled. Flash compatible ReSukiSU separately AFTER completing ROM install.");
ui_print("No automatic userdata format. Battery HAL, ANR/performance and service registration remain under investigation.");
assert(ri5_install());
ui_print("All 32 full-ROM images verified and target slot A selected.");
ui_print("Reboot Recovery, then System. Reinstall separately managed ReSukiSU only if compatible.");
"""
    with zipfile.ZipFile(source) as old:
        original_manifest=json.loads(old.read("RI5-BUILD-MANIFEST.json"))
    pin_list=native["image_pins"]
    old_by={row["name"]:row for row in original_manifest["images"]}
    pin_by={row["name"]:row for row in pin_list}
    if len(old_by)!=len(pin_by)!=32:
        raise ValueError("Unexpected flash payload number")
    if len(old_by)!=32 or set(old_by)!=set(pin_by):
        raise ValueError("Unexpected old/new partition set")
    for name in old_by:
        if name not in overrides and pin_by[name]!=old_by[name]:
            raise ValueError("Non-target image pin differs from RI7.3 "+name)
        if name in overrides and (pin_by[name]["sha256"]!=overrides[name][1] or pin_by[name]["bytes"]!=overrides[name][0].stat().st_size):
            raise ValueError("Native pin differs from authored image "+name)
    manifest=dict(original_manifest)
    manifest.update(
        build_id="KYNEOS-RI8-20261014",
        installer_revision="KYNEOS-RI8-FULL-32IMAGE-REPINS",
        images=pin_list,
        base_build_id="KYNEOS-RI7.3-20261007",
        source_full_rom_sha256=previous["sha256"],
        corrected_native_installer_image_pins=True,
        vendor_qualcomm_seccomp_fix={
            "changed_files":[
                "/vendor/etc/seccomp_policy/atfwd@2.0.policy",
                "/vendor/etc/seccomp_policy/qesdksec.policy",
            ],
            "rule_added":"lseek: 1",
            "vendor_files_and_metadata_independently_verified":2910,
            "runtime_boot_regression_tested":False,
            "seccomp_global_disable":False,
        },
        carried_forward_from_RI7_3={
            "screen_recorder_framework_hook":True,
            "device_verified_Messenger_capture":False,
            "vbmeta_system_sha256":pin_by["vbmeta_system"]["sha256"],
        },
        root_addon_policy={
            "ReSukiSU_SUSFS_bundled":False,
            "ReSukiSU_kernel_source_or_binary_modified":False,
            "separate_kernel_after_ROM":"user installs separately after successful normal ROM boot",
            "ROM_writes_normal_boot_init_boot_vendor_boot":True,
        },
        open_issues=["HW-CHARGE-001","POLICY-003","STAB-001","PERF-001","PERF-002","FW-001"],
        modified_logical_partitions=["vendor"],  # system changed earlier by RI7.3
        modified_full_zip_partition_images=["super","vbmeta"],
        normal_boot_and_firmware_images_from_RI7_3_unmodified=True,
        flash_boot_tested=False,
        userdata_erased=False,
    )
    replacements={
        "META-INF/com/google/android/update-binary":binary.read_bytes(),
        "META-INF/com/google/android/updater-script":script.encode(),
        "RI5-BUILD-MANIFEST.json":(json.dumps(manifest,indent=2)+"\n").encode(),
    }
    members={}
    names=[]
    with zipfile.ZipFile(source) as prior,zipfile.ZipFile(partial,"x",allowZip64=True) as target:
        for entry in prior.infolist():
            name=entry.filename
            names.append(name)
            part=name[len("partitions/"):-len(".bin")] if name.startswith("partitions/") and name.endswith(".bin") else None
            if part not in overrides and name not in replacements:
                copy_member(source,prior,target,entry)
                if name not in previous["member_hashes"]:
                    raise ValueError("Parent lacks member hash "+name)
                members[name]=previous["member_hashes"][name]
                continue
            info=zipfile.ZipInfo(name,entry.date_time)
            info.create_system=entry.create_system
            info.external_attr=entry.external_attr
            info.compress_type=zipfile.ZIP_DEFLATED
            info._compresslevel=1
            digest=hashlib.sha256()
            if part in overrides:
                path,expected=overrides[part]
                info.file_size=path.stat().st_size
                print("Compressing changed RI8 partition",part,info.file_size,flush=True)
                size=0
                with target.open(info,"w",force_zip64=True) as dest,path.open("rb") as src:
                    for block in iter(lambda:src.read(4*1024*1024),b""):
                        dest.write(block)
                        digest.update(block)
                        size+=len(block)
                if size!=pin_by[part]["bytes"] or digest.hexdigest()!=expected:
                    raise ValueError("Compressed image write did not preserve authored partition "+part)
            else:
                data=replacements[name]
                info.file_size=len(data)
                with target.open(info,"w",force_zip64=True) as dest:
                    dest.write(data)
                digest.update(data)
            members[name]=digest.hexdigest()
    if len(names)!=len(set(names)) or len(names)!=37 or sum(x.startswith("partitions/") for x in names)!=32:
        raise ValueError("Unexpected RI8 full recovery ZIP member set")
    print("Verifying all 37 decoded ZIP members, CRC and SHA-256",flush=True)
    with zipfile.ZipFile(partial) as z:
        if len(z.namelist())!=37:
            raise ValueError("Lost archive member")
        for member in z.infolist():
            with z.open(member) as inp:
                got=hashlib.file_digest(inp,"sha256").hexdigest()
            if got!=members[member.filename]:
                raise ValueError("Decoded RI8 archive SHA failure "+member.filename)
        manifest_check=json.loads(z.read("RI5-BUILD-MANIFEST.json"))
        if [x["name"] for x in manifest_check["images"]]!=[x["name"] for x in pin_list]:
            raise ValueError("Runtime pin order diverged from ZIP manifest")
        if sha(binary)!=hashlib.sha256(z.read("META-INF/com/google/android/update-binary")).hexdigest():
            raise ValueError("Native binary differs from compiled RI8")
    partial.rename(final)
    print("Signing RI8 full ROM ZIP and independently verifying signature",flush=True)
    identity=sign_generated_zip(final,ROOT/signing["certificate_path"],ROOT/signing["private_key_path"],
                  generated_root=RI8_OUT,generated_parent=RI8_OUT.parent,
                  work_dir=ROOT/"builder/work/kyneos-ri8-full-20261014",
                  expected_cert_sha256=signing["certificate_der_sha256"],reserve_bytes=4*1024**3)
    if not identity.get("verified"):
        raise ValueError("RI8 OTA signature did not pass verification")
    result={
        "build_id":"KYNEOS-RI8-20261014",
        "archive":str(final),"bytes":final.stat().st_size,"sha256":sha(final),
        "native_sha256":native["updater_sha256"],
        "source_sha256":previous["sha256"],
        "partition_payload_count":32,"member_count":37,
        "member_hashes":members,
        "image_pins":pin_list,
        "all_member_crc_sha_checks_passed":True,
        "signature_verified":True,
        "changed_flash_payloads":["super","vbmeta"],
        "full_32_image_native_installer_pins_match":True,
        "rom_boot_images_standard_RI7_3_bytes_preserved":True,
        "ReSukiSU_included":False,
        "existing_ReSukiSU_replaced_by_normal_ROM_boot_install":True,
        "user_installs_ReSukiSU_separately_afterward":True,
        "open_issues":manifest["open_issues"],
        "flash_ready_for_known_ROM_recovery_workflow":True,
        "device_flashed":False,"device_boot_tested":False,
        "elapsed_seconds":round(time.monotonic()-start,2),
    }
    (RI8_OUT/"FULL-ROM-VALIDATION.json").write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8")
    (RI8_OUT/(NAME+".sha256")).write_text(result["sha256"]+"  "+NAME+"\n",encoding="utf-8")
    print(json.dumps({k:result[k] for k in ("archive","bytes","sha256","native_sha256","partition_payload_count","signature_verified","full_32_image_native_installer_pins_match","device_flashed")},indent=2),flush=True)

if __name__=="__main__":
    try:
        main()
    except Exception:
        import traceback
        RI8_OUT.mkdir(parents=True,exist_ok=True)
        (RI8_OUT/"RI8-FULL-PACKAGE-FAILURE.txt").write_text(traceback.format_exc(),encoding="utf-8")
        raise
