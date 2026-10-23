#!/usr/bin/env python3
"""Package verified BakaSU/UAPI5 WildKernels candidate and safe rollback ZIPs.

Public GitHub Actions artifacts are intentionally UNSIGNED. Never fetch any
development private signing key into an unattended upstream-code build runner.
They are not flash-certified; re-sign and recovery-test in a trusted release step.
"""
from __future__ import annotations
import hashlib
import packaging_contract as original
import json
import os
from pathlib import Path
import re
import struct
import zipfile

ROOT = Path(__file__).resolve().parents[3]
ASSETS = Path(os.environ.get("BAKASU_CI_ASSET_ROOT", str(ROOT)))
BUILD = Path(os.environ["BAKASU_CI_OUTPUT"])
UPSTREAM = os.environ["BAKASU_CI_SHA"]
PREVIOUS = os.environ.get("BAKASU_CI_PREVIOUS_IMAGE_SHA", "")
DEST = Path(os.environ["BAKASU_CI_PACKAGE_OUT"])
MANIFEST = "BAKASU-PERIDOT-CI-MANIFEST.json"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_sha(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def need(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def add_file(z: zipfile.ZipFile, name: str, data: bytes, executable: bool = False) -> None:
    info = zipfile.ZipInfo(name, (2026, 10, 14, 0, 0, 0))
    info.create_system = 3
    info.external_attr = (0o755 if executable else 0o644) << 16
    info.compress_type = zipfile.ZIP_DEFLATED
    z.writestr(info, data)


def pack_candidate() -> dict:
    need(re.fullmatch(r"[a-f0-9]{40}", UPSTREAM) is not None, "Invalid upstream SHA")
    need(not PREVIOUS or re.fullmatch(r"[a-f0-9]{64}", PREVIOUS) is not None,
         "Invalid previous Image SHA")
    need(not DEST.exists(), "Refusing to overwrite candidate bundle folder")

    receipt = json.loads((BUILD / "build-receipt.json").read_text())
    compat = json.loads((BUILD / "compatibility.json").read_text())
    feature = original.FEATURE_SET
    pins = dict(original.PINS)
    pins["resukisu"] = UPSTREAM
    need(receipt["device"] == "peridot" and receipt["source_pins"] == pins,
         "Unexpected BakaSU/SUSFS/WildKernels build source")
    need(receipt["feature_set"] == feature and receipt["resukisu_uapi_version"] == 5,
         "UAPI/10-feature bundle changed")
    need(receipt["kernel_release"] == original.EXPECTED_RELEASE if hasattr(original, "EXPECTED_RELEASE") else
         receipt["kernel_release"] == "6.1.138-android14-11-g0c3d559bcd85-ab14529422",
         "Kernel release changed")
    need(compat["status"] == "offline-fullbundle-compatibility-passed" and
         compat["source_pins"] == pins and compat["feature_set"] == feature,
         "Stock module compatibility gate failed")
    need(compat["stock_certificate_embedded"] is True and
         not compat["shared_export_crc_mismatches"] and
         not any(m["crc_mismatches"] or m["unresolved_imports"] for m in compat["modules"]),
         "Kernel stock ABI compatibility must pass")
    image = (BUILD / "Image").read_bytes()
    image_sha = sha(image)
    need(image_sha == receipt["image"]["sha256"] == compat["image_sha256"],
         "Authored Image receipt/compatibility drift")
    template = ASSETS / "builder/work/resukisu-susfs-addon/POCO-F6-HyperOS4-ReSukiSU-SUSFS-Addon-20261003.zip"
    old_bundle = ASSETS / (
        "builder/work/resukisu-susfs-addon-uapi5-fullbundle-20261004/"
        "POCO-F6-HyperOS4-ReSukiSU-SUSFS-UAPI5-FullBundle-Update-20261004.zip"
    )
    stock_boot = ASSETS / ".cache/global-single-recovery-ri2/source-images/images/boot.img"
    core_zip = ASSETS / (
        "builder/work/resukisu-susfs-addon-uapi5-20261004/"
        "POCO-F6-HyperOS4-ReSukiSU-SUSFS-UAPI5-Update-20261004.zip"
    )
    need(file_sha(template) == original.TEMPLATE_SHA, "AnyKernel source is not pinned")
    need(file_sha(core_zip) == original.CORE_PACKAGE_SHA, "Original UAPI5 core source changed")
    need(file_sha(old_bundle) ==
         "53d0aeeabad8a55b5b0279ac6067d59a7d89e64769b8040a3b91a8e22936272a",
         "Last device-targeted full WildKernels bundle not pinned")
    boot = stock_boot.read_bytes()
    kernel_size = struct.unpack_from("<I", boot, 8)[0]
    need(len(boot) >= 4096 + kernel_size and kernel_size > 1024*1024, "Stock boot Image bounds invalid")
    stock = boot[4096:4096 + kernel_size]
    need(sha(stock) == original.STOCK_IMAGE, "Stock kernel Image differs")
    with zipfile.ZipFile(old_bundle) as z:
        old_image = z.read("Image")
    need(sha(old_image) == original.FULL_IMAGE, "Rollback full bundle Image differs")
    with zipfile.ZipFile(core_zip) as z:
        core_image = z.read("Image")
    need(sha(core_image) == original.UAPI5_CORE_IMAGE, "Original core rollback mismatch")

    accepted_update = [original.STOCK_IMAGE, original.OLD_WK_IMAGE,
                       original.UAPI5_CORE_IMAGE, original.FULL_IMAGE]
    if PREVIOUS and PREVIOUS not in accepted_update and PREVIOUS != image_sha:
        accepted_update.append(PREVIOUS)
    variants = [
      ("update", image, accepted_update, "POCO F6 BakaSU full WildKernels candidate"),
      ("rollback-fullbundle", old_image, [image_sha], "POCO F6 previous tested-base fullbundle"),
      ("rollback-stock", stock, [image_sha], "POCO F6 original stock kernel"),
    ]
    DEST.mkdir(parents=True)
    results = []
    with zipfile.ZipFile(template) as source:
        base_script = source.read("anykernel.sh")
        need(b"device.name1=peridot" in base_script and b"patch_vbmeta_flag=0" in base_script,
             "Original AnyKernel scope changed")
        for kind, payload, accepted, label in variants:
            name = f"BakaSU-peridot-{UPSTREAM[:12]}-{kind}-UNSIGNED.zip"
            path = DEST / name
            script = original.installer_script(base_script, accepted, label)
            need(b'case "$current_sha"' in script, "Exact source kernel SHA guard missing")
            need(b"patch_vbmeta_flag=0" in script, "VBMeta modification disallowed")
            metadata = {
                "schema_version": 1,
                "status": "UNSIGNED_CI_CANDIDATE_NOT_DEVICE_TESTED",
                "upstream_repo": "Baka-SU/BakaSU",
                "upstream_sha": UPSTREAM,
                "original_name": "ReSukiSU",
                "device": "peridot",
                "kernel_release": receipt["kernel_release"],
                "uapi_version": 5,
                "kind": kind,
                "feature_set": feature,
                "features": feature.split("+"),
                "source_pins": pins,
                "image_sha256": sha(payload),
                "accepted_input_image_sha256": accepted,
                "compatibility_json_sha256": file_sha(BUILD / "compatibility.json"),
                "stock_module_compatibility_passed": True,
                "existing_rom_modified": False,
                "ramdisk_preserved": True,
                "active_boot_only": True,
                "patch_vbmeta_flag": False,
                "recovery_zip_signed": False,
                "recovery_certificate_trust_verified": False,
                "physical_device_tested": False,
            }
            with zipfile.ZipFile(path, "x", allowZip64=True) as out:
                for entry in source.infolist():
                    if entry.filename in ("Image", "anykernel.sh", "META-INF/com/android/otacert") or \
                         entry.filename.startswith("POCO-F6-RESUKISU"):
                        continue
                    out.writestr(entry, source.read(entry.filename))
                add_file(out, "Image", payload)
                add_file(out, "anykernel.sh", script, executable=True)
                add_file(out, MANIFEST, (json.dumps(metadata, indent=2, sort_keys=True)+"\n").encode())
                add_file(out, "UNSIGNED-CI-READ-ME.txt",
                         b"UNSIGNED AUTOMATED CI CANDIDATE. Not flashed or tested on the phone. "
                         b"Stock module compatibility checked offline. "
                         b"Review, independently sign, and test recovery trust before any flash.\n")
            with zipfile.ZipFile(path) as checked:
                need(checked.testzip() is None, "ZIP CRC check failed")
                names = checked.namelist()
                need(len(names) == len(set(names)), "Duplicate ZIP names")
                need("META-INF/com/android/otacert" not in names, "Unexpected implicit certificate")
                need(sha(checked.read("Image")) == sha(payload), "ZIP Image hash mismatch")
                need(checked.read("anykernel.sh") == script, "ZIP guard script mismatch")
                need(json.loads(checked.read(MANIFEST)) == metadata, "ZIP manifest mismatch")
            results.append({"file": name, "bytes": path.stat().st_size, "sha256": file_sha(path),
                            "image_sha256": sha(payload), "kind": kind})
    summary = {
        "status": "candidate-packaging-verified",
        "upstream_sha": UPSTREAM,
        "image_sha256": image_sha,
        "feature_set": feature,
        "stock_module_compatibility_passed": True,
        "update_and_rollback_count": len(results),
        "signed": False,
        "device_tested": False,
        "files": results,
    }
    (DEST / "candidate-validation.json").write_text(json.dumps(summary, indent=2)+"\n")
    (DEST / "SHA256SUMS.txt").write_text(
        "".join(f"{row['sha256']}  {row['file']}\n" for row in results)
    )
    print(json.dumps(summary, indent=2))
    return summary


if __name__ == "__main__":
    pack_candidate()
