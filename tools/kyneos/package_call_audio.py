"""Package the RI7.3 Screen Recorder Messenger call-audio fix as a signed complete recovery ZIP.

The verified RI7.1 delivery is the immutable package base. Only super, vbmeta_system,
the build manifest, and the human-readable updater script are replaced.
"""
from __future__ import annotations

from pathlib import Path
import hashlib
import json
import shutil
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[2]
WORK = ROOT / "builder/work/screen-recorder-call-audio-20261007"
SOURCE_OUT = Path("D:/hyperos4-peridot-kyneos-ri7-20261005/outputs")
OUT = Path("D:/hyperos4-peridot-kyneos-ri7.3-messenger-callaudio-20261007/outputs")
SOURCE_NAME = "KyneOS-Global-HyperOS4-POCO-F6-RI7.1-20261005.zip"
NAME = "KyneOS-Global-HyperOS4-POCO-F6-RI7.3-20261007.zip"

sys.path[:0] = [
    str(ROOT / "tools/installer-ri3/zip-signing"),
    str(ROOT / "tools/installer-ri5"),
]
from sign_zip import sign_generated_zip
from compressed_copy import copy_member


def sha(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main() -> None:
    source = SOURCE_OUT / SOURCE_NAME
    source_validation = json.loads((SOURCE_OUT / "VALIDATION.json").read_text(encoding="utf-8"))
    assembly = json.loads((WORK / "screenrecorder-call-audio-assembly.json").read_text(encoding="utf-8"))
    framework = json.loads((WORK / "screenrecorder-call-audio-framework.json").read_text(encoding="utf-8"))

    if source_validation["archive"] != str(source):
        raise ValueError("RI7.1 validation points at a different source archive")
    if sha(source) != source_validation["sha256"]:
        raise ValueError("RI7.1 signed source archive drift")
    if not source_validation["all_member_crc_sha_checks_passed"]:
        raise ValueError("RI7.1 source archive was not fully member-verified")
    if not source_validation["signature"]["verified"]:
        raise ValueError("RI7.1 source archive signature was not verified")
    for key in (
        "root_vbmeta_unchanged",
        "all_super_bytes_outside_system_a_verified_identical",
        "source_system_a_span_verified_against_source_system_image",
        "target_system_a_span_verified_against_target_system_image",
        "vbmeta_system_unrelated_descriptors_unchanged",
        "vbmeta_system_public_key_unchanged",
        "vbmeta_system_system_descriptor_exactly_replaced",
        "rollback_and_flags_unchanged",
        "avb_verify_image_passed",
        "fec_parity_independently_regenerated_and_verified",
        "fec_helper_stock_ri7_byte_validation",
    ):
        if not assembly.get(key):
            raise ValueError(f"Call-audio assembly gate failed: {key}")
    if assembly["changed_logical_partitions"] != ["system"]:
        raise ValueError("Unexpected logical-partition change set")
    if assembly["changed_flash_payloads"] != ["super", "vbmeta_system"]:
        raise ValueError("Unexpected flash-payload change set")
    if framework["scope_package"] != "com.miui.screenrecorder" or framework["added_usage"] != 2:
        raise ValueError("Unexpected Screen Recorder framework patch scope")
    if framework.get("allow_privileged_playback_capture") is not True:
        raise ValueError("Screen Recorder privileged playback capture hook is missing")
    if framework.get("voice_communication_capture_allowed") is not True:
        raise ValueError("Screen Recorder voice-communication capture hook is missing")
    if framework["screen_recorder_apk_modified"]:
        raise ValueError("Signed Xiaomi Screen Recorder APK must remain untouched")

    target_super = Path(assembly["output_super"])
    target_vbmeta_system = Path(assembly["output_vbmeta_system"])
    if sha(target_super) != assembly["output_super_sha256"]:
        raise ValueError("Verified call-audio super drift")
    if sha(target_vbmeta_system) != assembly["output_vbmeta_system_sha256"]:
        raise ValueError("Verified call-audio vbmeta_system drift")

    OUT.mkdir(parents=True, exist_ok=True)
    if shutil.disk_usage(OUT).free < 18 * 1024**3:
        raise ValueError("Insufficient output-disk reserve for package and signing")
    partial = OUT / (NAME + ".partial")
    final = OUT / NAME
    if partial.exists() or final.exists():
        raise ValueError("Refusing to overwrite an existing RI7.2 output")

    script = """ui_print(\"KyneOS RI7.3: Global HyperOS 4 for POCO F6.\");
ui_print(\"Adds scoped Screen Recorder privileged + voice-communication playback capture.\");
ui_print(\"Xiaomi Screen Recorder APK remains stock-signed and unmodified.\");
assert(ri5_install());
ui_print(\"Complete image set verified; slot A selected after success.\");
ui_print(\"Reboot Recovery, then System. Existing DECRYPT data needs no Format Data.\");
"""

    member_hashes: dict[str, str] = {}
    names: list[str] = []
    with zipfile.ZipFile(source) as old, zipfile.ZipFile(partial, "x", allowZip64=True) as target:
        manifest = json.loads(old.read("RI5-BUILD-MANIFEST.json"))
        if manifest["build_id"] != "KYNEOS-RI7.1-20261005":
            raise ValueError("Unexpected RI7.1 package build id")
        images = [dict(row) for row in manifest["images"]]
        by_name = {row["name"]: row for row in images}
        if set(by_name) != {
            "super", "abl", "aop", "aop_config", "bluetooth", "countrycode", "cpucp",
            "cpucp_dtb", "devcfg", "dsp", "featenabler", "hyp", "imagefv", "keymaster",
            "modem", "modemfirmware", "multiimgqti", "qupfw", "shrm", "tz", "uefi",
            "uefisecapp", "xbl", "xbl_config", "xbl_ramdump", "boot", "dtbo", "init_boot",
            "vendor_boot", "recovery", "vbmeta_system", "vbmeta",
        }:
            raise ValueError("Unexpected partition payload set in RI7.1 manifest")
        by_name["super"].update(
            bytes=target_super.stat().st_size,
            sha256=assembly["output_super_sha256"],
        )
        by_name["vbmeta_system"].update(
            bytes=target_vbmeta_system.stat().st_size,
            sha256=assembly["output_vbmeta_system_sha256"],
        )

        manifest.update(
            build_id="KYNEOS-RI7.3-20261007",
            installer_revision="RI7.3-KYNEOS-MESSENGER-CALLAUDIO",
            images=images,
            compression="RI7.1 unchanged members raw-copied; changed super/vbmeta_system ZIP_DEFLATED level 1",
            install_over="RI7.1 or compatible RI6 POSTBOOT FIX1 DECRYPT",
            userdata_format_required=False,
            partition_AVB_and_raw_image_hashes_unchanged=False,
            integrated_build_flash_tested=False,
            screen_recorder_call_audio={
                "scope_package": framework["scope_package"],
                "framework_hook": framework["target_class"],
                "added_matching_usage": framework["added_usage"],
                "usage_name": "USAGE_VOICE_COMMUNICATION",
                "allow_privileged_playback_capture": framework["allow_privileged_playback_capture"],
                "voice_communication_capture_allowed": framework["voice_communication_capture_allowed"],
                "screen_recorder_apk_modified": False,
                "requires_existing_privileged_permission": "android.permission.CAPTURE_VOICE_COMMUNICATION_OUTPUT",
                "changed_logical_partitions": ["system"],
                "changed_flash_payloads": ["super", "vbmeta_system"],
                "avb_verify_image_passed": True,
                "fec_num_roots": assembly["fec_num_roots"],
                "fec_parity_independently_verified": True,
                "device_tested": False,
            },
        )
        replacements = {
            "META-INF/com/google/android/updater-script": script.encode(),
            "RI5-BUILD-MANIFEST.json": (json.dumps(manifest, indent=2) + "\n").encode(),
        }
        partition_paths = {
            "super": target_super,
            "vbmeta_system": target_vbmeta_system,
        }

        for entry in old.infolist():
            name = entry.filename
            names.append(name)
            partition = name.split("/")[-1][:-4] if name.startswith("partitions/") else None
            if partition not in partition_paths and name not in replacements:
                copy_member(source, old, target, entry)
                member_hashes[name] = source_validation["member_hashes"][name]
                continue

            info = zipfile.ZipInfo(name, entry.date_time)
            info.create_system = entry.create_system
            info.external_attr = entry.external_attr
            info.compress_type = zipfile.ZIP_DEFLATED
            info._compresslevel = 1
            digest = hashlib.sha256()

            if partition in partition_paths:
                path = partition_paths[partition]
                info.file_size = path.stat().st_size
                count = 0
                print("Compressing", partition, flush=True)
                with target.open(info, "w", force_zip64=True) as dst, path.open("rb") as src:
                    for block in iter(lambda: src.read(4 * 1024 * 1024), b""):
                        dst.write(block)
                        digest.update(block)
                        count += len(block)
                expected = by_name[partition]
                if count != expected["bytes"] or digest.hexdigest() != expected["sha256"]:
                    raise ValueError(f"Packaged {partition} source drift")
            else:
                data = replacements[name]
                info.file_size = len(data)
                with target.open(info, "w", force_zip64=True) as dst:
                    dst.write(data)
                digest.update(data)
            member_hashes[name] = digest.hexdigest()

    if len(names) != len(set(names)) or len(names) != 37:
        raise ValueError("Unexpected RI7.3 ZIP member set")

    print("Verifying all 37 decoded members CRC + SHA256 for RI7.3", flush=True)
    with zipfile.ZipFile(partial) as archive:
        if archive.namelist() != names:
            raise ValueError("ZIP member order changed")
        for entry in archive.infolist():
            with archive.open(entry) as stream:
                actual = hashlib.file_digest(stream, "sha256").hexdigest()
            if actual != member_hashes[entry.filename]:
                raise ValueError(f"Member hash mismatch: {entry.filename}")

    partial.rename(final)
    signing = json.loads(
        (ROOT / "builder/work/installer-ri5-recoveryfix-20261004/signing-public.json").read_text(
            encoding="utf-8"
        )
    )
    signature = sign_generated_zip(
        final,
        ROOT / signing["certificate_path"],
        ROOT / signing["private_key_path"],
        generated_root=OUT,
        generated_parent=OUT.parent,
        work_dir=WORK,
        expected_cert_sha256=signing["certificate_der_sha256"],
        reserve_bytes=4 * 1024**3,
    )
    if not signature["verified"]:
        raise ValueError("RI7.3 ZIP signature verification failed")

    result = {
        "build_id": "KYNEOS-RI7.3-20261007",
        "archive": str(final),
        "bytes": final.stat().st_size,
        "sha256": sha(final),
        "source_archive": str(source),
        "source_sha256": source_validation["sha256"],
        "member_hashes": member_hashes,
        "member_count": 37,
        "partition_payload_count": 32,
        "changed_flash_payloads": ["super", "vbmeta_system"],
        "changed_logical_partitions": ["system"],
        "all_member_crc_sha_checks_passed": True,
        "signature": signature,
        "avb_verification_passed": True,
        "fec_parity_verified": True,
        "native_sha256": source_validation["native_sha256"],
        "userdata_format_required": False,
        "integrated_build_device_flash_tested": False,
    }
    (OUT / "VALIDATION.json").write_text(
        json.dumps(result, indent=2) + "\n",
        encoding="utf-8",
    )
    (OUT / (NAME + ".sha256")).write_text(
        result["sha256"] + "  " + NAME + "\n",
        encoding="utf-8",
    )
    print(json.dumps({k: result[k] for k in ("archive", "bytes", "sha256")}, indent=2), flush=True)


if __name__ == "__main__":
    main()
