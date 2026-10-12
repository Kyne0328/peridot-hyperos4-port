"""Create signed guarded UAPI5 full-WildKernels update and rollback ZIPs.

Uses the validated full-bundle Image and immutable existing kernel payloads. It
never touches a device or modifies the base ROM/source archives.
"""
from __future__ import annotations

from pathlib import Path
import hashlib
import json
import struct
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "builder/work/resukisu-susfs-addon-uapi5-fullbundle-20261004"
BUILD = ROOT / "builder/work/resukisu-uapi5-fullbundle-20261004"
COMPAT = BUILD / "compatibility.json"
BUILD_RECEIPT = BUILD / "build-receipt.json"
IMAGE = BUILD / "Image"

TEMPLATE = ROOT / "builder/work/resukisu-susfs-addon/POCO-F6-HyperOS4-ReSukiSU-SUSFS-Addon-20261003.zip"
CORE_PACKAGE = ROOT / "builder/work/resukisu-susfs-addon-uapi5-20261004/POCO-F6-HyperOS4-ReSukiSU-SUSFS-UAPI5-Update-20261004.zip"
STOCK_BOOT = ROOT / ".cache/global-single-recovery-ri2/source-images/images/boot.img"
SIGNING_PUBLIC = ROOT / "builder/work/installer-ri5-recoveryfix-20261004/signing-public.json"

TEMPLATE_SHA = "2f1c4b9c451e2f6e0161867ca13eb60f38f3f01ba828a33df0c999a0fbff9eba"
CORE_PACKAGE_SHA = "f82fc63dd86b9305420824bf7aa9d86b593a62de79cf8a0c904fa2a3311fed63"
STOCK_IMAGE = "97b2c53022e8c0bd0b279c4c592a196126a6eb0a93647c2957b39dcd5f2dc1c9"
OLD_WK_IMAGE = "f5b148001a01b6b3f498aa6a536ce128dbd4c6a658866e90f5f0b47842861310"
UAPI5_CORE_IMAGE = "142782663ee40536cc6bfbf0c999e9aa7430ae1489b04cc0388dca09d970f2c6"
FULL_IMAGE = "340c3470ece7408fbbf0f307db2d15f6528e9c7d73c0d239638f9e62d0b415e9"

FEATURE_SET = "SUSFS+NoMount+BBG+NET+DS+NTSync+Ptrace+Unicode+BPF+Perf"
FEATURES = FEATURE_SET.split("+")
PINS = {
    "common": "0c3d559bcd85c64dae9c9c9687abbe5347fff3ad",
    "resukisu": "8770c7e324a22895703c4916b8a16520e0b81c79",
    "susfs": "24743360ea08d98f6ad72b856851abed8de5854f",
    "wildkernels": "e0ecd61219baaa0c3eae821246e31136302fd0dc",
    "kernel_patches": "41ae18b35d20e0c6ac04116785a4a1089528ae94",
    "baseband_guard": "a54e0dc6cf0aff4dd87fec49644a02d2eb612905",
    "droidspaces": "ac38c11fef1402c0db8172ea8187db0401a0bc30",
    "nomount": "5fac312b143e632e483c3c8b9ab325b6d4527314",
}
MANIFEST = "POCO-F6-UAPI5-FULLBUNDLE-MANIFEST.json"
INNER_README = "POCO-F6-UAPI5-FULLBUNDLE-README.txt"

sys.path.insert(0, str(ROOT / "tools/installer-ri3/zip-signing"))
from sign_zip import sign_generated_zip
from verify_zip import verify_zip


def sha_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha_file(path: Path) -> str:
    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def need(ok: bool, message: str) -> None:
    if not ok:
        raise RuntimeError(message)


def text_info(name: str, mode: int = 0o644) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, (2026, 10, 4, 0, 0, 0))
    info.create_system = 3
    info.external_attr = mode << 16
    info.compress_type = zipfile.ZIP_DEFLATED
    return info


def installer_script(source: bytes, accepted: list[str], label: str) -> bytes:
    text = source.decode("utf-8")
    old = (
        f'[ "$current_sha" = "{STOCK_IMAGE}" ] || abort '
        '"Current kernel is not the expected RI3/add-on kernel. Refusing to flash."'
    )
    need(text.count(old) == 1, "Template current-kernel guard changed")
    cases = "|".join(accepted)
    new = (
        'case "$current_sha" in\n'
        f'  {cases}) ;;\n'
        '  *) abort "Current kernel is not an explicitly supported input. Refusing to flash." ;;\n'
        'esac'
    )
    text = text.replace(old, new)
    text = text.replace(
        "kernel.string=POCO F6 HyperOS 4 - ReSukiSU + SUSFS",
        "kernel.string=" + label,
    )
    text = text.replace(
        "Target base: F6-Global-HyperOS4-DEV2-RI3-20261003",
        "Exact kernel hash guards; full WildKernels UAPI5 package",
    )
    text = text.replace("Expected current kernel SHA-256:", "Accepted current kernel SHA-256:")
    text = text.replace(
        f'ui_print "{STOCK_IMAGE}"',
        "\n".join(f'ui_print "{value}"' for value in accepted),
    )
    need("device.name1=peridot" in text, "peridot device guard missing")
    need("patch_vbmeta_flag=0" in text, "vbmeta patch must remain disabled")
    return text.encode("utf-8")


def readme() -> str:
    return f"""POCO F6 / peridot ReSukiSU + SUSFS UAPI 5 full WildKernels bundle.

This rebuild includes the complete current WildKernels toggle set:
  {FEATURE_SET}

This differs from the earlier UAPI5 core package: Perf and the rest of the
WildKernels extra-feature integration are included in this kernel.

Kernel release:
  6.1.138-android14-11-g0c3d559bcd85-ab14529422
ReSukiSU:
  {PINS['resukisu']} (UAPI 5)
SUSFS:
  {PINS['susfs']}
Full-bundle Image SHA-256:
  {FULL_IMAGE}

Installer behavior:
  - POCO F6 / peridot only.
  - Active boot slot only.
  - Preserves the current boot ramdisk.
  - Does not patch vbmeta flags.
  - Does not modify super, system_dlkm, vendor_dlkm, vendor_boot, recovery, or userdata.
  - Update accepts only exact stock, old UAPI2 WildKernels addon, or working UAPI5-core kernels.
  - Full-bundle rollback packages accept only the exact full-bundle kernel.

Compatibility evidence:
  - 8,142 shared stock exports checked with zero CRC mismatches.
  - 60 system_dlkm, 314 vendor_dlkm, and 338 vendor_boot modules checked with zero import/CRC gaps.
  - 60 stock-signed modules verified against the retained stock public module key.
  - Exact stock kernel release retained.
  - No physical-device boot, root-runtime, or hardware test has been performed.

Ptrace detail:
  The WildKernels Ptrace toggle is part of the full bundle. Upstream intentionally
  skips its compatibility patch on Linux 6.1 because that patch is only applied
  to kernels <= 5.16.

ZIP signing:
  The packages are cryptographically signed with the retained RI5 development
  ZIP certificate. Recovery trust of that certificate remains unverified; this
  build does not claim OrangeFox will accept that certificate with signature
  verification enabled.

No device flash was performed while creating these files.
"""


def main() -> None:
    need(not OUT.exists(), f"Refusing to overwrite existing output directory: {OUT}")
    for path in (COMPAT, BUILD_RECEIPT, IMAGE, TEMPLATE, CORE_PACKAGE, STOCK_BOOT, SIGNING_PUBLIC):
        need(path.is_file(), f"Missing input: {path}")

    compat = json.loads(COMPAT.read_text(encoding="utf-8"))
    build = json.loads(BUILD_RECEIPT.read_text(encoding="utf-8"))
    need(compat["status"] == "offline-fullbundle-compatibility-passed", "Compatibility gate not passed")
    need(compat["feature_set"] == FEATURE_SET and compat["features"] == FEATURES, "Compatibility feature set mismatch")
    need(compat["source_pins"] == PINS, "Compatibility source pins mismatch")
    need(compat["image_sha256"] == FULL_IMAGE, "Compatibility Image hash mismatch")
    need(not compat["shared_export_crc_mismatches"], "Shared export CRC mismatch remains")
    need(all(not row["crc_mismatches"] and not row["unresolved_imports"] for row in compat["modules"]),
         "Module compatibility gaps remain")
    need(build["feature_set"] == FEATURE_SET and build["source_pins"] == PINS, "Build receipt provenance mismatch")
    need(sha_file(IMAGE) == FULL_IMAGE, "Full-bundle Image hash changed")
    need(sha_file(TEMPLATE) == TEMPLATE_SHA, "AnyKernel template ZIP changed")
    need(sha_file(CORE_PACKAGE) == CORE_PACKAGE_SHA, "Known-good UAPI5 core ZIP changed")

    signing = json.loads(SIGNING_PUBLIC.read_text(encoding="utf-8"))
    cert = ROOT / signing["certificate_path"]
    key = ROOT / signing["private_key_path"]
    need(cert.is_file() and key.is_file(), "RI5 signing material unavailable")

    full_image = IMAGE.read_bytes()
    need(sha_bytes(full_image) == FULL_IMAGE, "Full Image bytes changed")
    with zipfile.ZipFile(CORE_PACKAGE) as core_zip:
        core_image = core_zip.read("Image")
    need(sha_bytes(core_image) == UAPI5_CORE_IMAGE, "Known-good UAPI5 core Image changed")

    boot = STOCK_BOOT.read_bytes()
    kernel_size = struct.unpack_from("<I", boot, 8)[0]
    stock_image = boot[4096:4096 + kernel_size]
    need(sha_bytes(stock_image) == STOCK_IMAGE, "Stock kernel Image changed")

    OUT.mkdir(parents=True)
    outputs = []
    compat_sha = sha_file(COMPAT)
    build_receipt_sha = sha_file(BUILD_RECEIPT)
    package_readme = readme()

    with zipfile.ZipFile(TEMPLATE) as source:
        old_image = source.read("Image")
        need(sha_bytes(old_image) == OLD_WK_IMAGE, "Old WildKernels Image changed")
        choices = [
            (
                "Update",
                "POCO-F6-HyperOS4-ReSukiSU-SUSFS-UAPI5-FullBundle-Update-20261004.zip",
                full_image,
                [STOCK_IMAGE, OLD_WK_IMAGE, UAPI5_CORE_IMAGE],
                "POCO F6 UAPI5 Full WildKernels Bundle",
            ),
            (
                "Rollback-UAPI5-Core",
                "POCO-F6-HyperOS4-ReSukiSU-SUSFS-UAPI5-FullBundle-Rollback-UAPI5-Core-20261004.zip",
                core_image,
                [FULL_IMAGE],
                "POCO F6 restore UAPI5 core kernel",
            ),
            (
                "Rollback-Stock",
                "POCO-F6-HyperOS4-ReSukiSU-SUSFS-UAPI5-FullBundle-Rollback-Stock-20261004.zip",
                stock_image,
                [FULL_IMAGE],
                "POCO F6 restore stock kernel",
            ),
        ]

        for kind, filename, payload, accepted, label in choices:
            path = OUT / filename
            generated = installer_script(source.read("anykernel.sh"), accepted, label)
            manifest = {
                "schema_version": 1,
                "kind": kind,
                "device": {"codename": "peridot", "product": "POCO F6"},
                "accepted_input_image_sha256": accepted,
                "bundled_image_sha256": sha_bytes(payload),
                "new_kernel_uapi": 5,
                "full_wildkernels_bundle": True,
                "feature_set": FEATURE_SET,
                "features": FEATURES,
                "source_pins": PINS,
                "ptrace": compat["ptrace"],
                "kernel_release": compat["kernel_release"],
                "compatibility_report": str(COMPAT.relative_to(ROOT)),
                "compatibility_report_sha256": compat_sha,
                "build_receipt": str(BUILD_RECEIPT.relative_to(ROOT)),
                "build_receipt_sha256": build_receipt_sha,
                "active_boot_only": True,
                "ramdisk_preserved": True,
                "vbmeta_flag_patch": False,
                "base_rom_modified": False,
                "system_dlkm_modified": False,
                "vendor_dlkm_modified": False,
                "runtime_validated": False,
                "recovery_zip_certificate_trust_verified": False,
                "device_tested": False,
                "device_access_performed": False,
            }

            with zipfile.ZipFile(path, "w", allowZip64=True) as dest:
                for info in source.infolist():
                    if (
                        info.filename in {"Image", "anykernel.sh", "META-INF/com/android/otacert"}
                        or info.filename.startswith("POCO-F6-RESUKISU")
                    ):
                        continue
                    dest.writestr(info, source.read(info.filename))
                dest.writestr(text_info("Image", 0o644), payload)
                dest.writestr(text_info("anykernel.sh", 0o755), generated)
                dest.writestr(text_info(MANIFEST), json.dumps(manifest, indent=2, sort_keys=True) + "\n")
                dest.writestr(text_info(INNER_README), package_readme)
                dest.writestr(text_info("META-INF/com/android/otacert"), cert.read_bytes())

            signing_dir = OUT / (kind + "-signing")
            signing_dir.mkdir()
            receipt = sign_generated_zip(
                path,
                cert,
                key,
                generated_root=OUT,
                work_dir=signing_dir,
                expected_cert_sha256=signing["certificate_der_sha256"],
                reserve_bytes=4 * 1024**3,
            )
            independent = verify_zip(path, cert, signing["certificate_der_sha256"])
            need(receipt["verified"] and independent["verified"], "Whole-file ZIP signature verification failed")

            with zipfile.ZipFile(path) as check:
                names = check.namelist()
                need(check.testzip() is None, "ZIP CRC check failed")
                need(len(names) == len(set(names)), "Duplicate ZIP members")
                need(names.count("META-INF/com/android/otacert") == 1, "Expected exactly one otacert")
                need(sha_bytes(check.read("Image")) == sha_bytes(payload), "Bundled Image changed")
                need(check.read("anykernel.sh") == generated, "Installer script changed")
                need(json.loads(check.read(MANIFEST)) == manifest, "Manifest readback changed")

            outputs.append({
                "kind": kind,
                "path": str(path),
                "sha256": sha_file(path),
                "bytes": path.stat().st_size,
                "accepted_input_image_sha256": accepted,
                "bundled_image_sha256": sha_bytes(payload),
                "signing": receipt,
            })

    validation = {
        "schema_version": 1,
        "status": "signed-packages-created",
        "feature_set": FEATURE_SET,
        "features": FEATURES,
        "full_wildkernels_bundle": True,
        "compatibility_report": str(COMPAT),
        "compatibility_report_sha256": compat_sha,
        "build_receipt_sha256": build_receipt_sha,
        "outputs": outputs,
        "recovery_zip_certificate_trust_verified": False,
        "device_tested": False,
        "device_access_performed": False,
        "source_archives_modified": False,
        "base_rom_modified": False,
        "private_key_material_in_artifacts": False,
    }
    (OUT / "validation.json").write_text(json.dumps(validation, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (OUT / "README.txt").write_text(package_readme + "\n" + json.dumps(
        [{k: v for k, v in row.items() if k != "signing"} for row in outputs],
        indent=2,
    ) + "\n", encoding="utf-8")
    print(json.dumps([{k: v for k, v in row.items() if k != "signing"} for row in outputs], indent=2))


if __name__ == "__main__":
    main()
