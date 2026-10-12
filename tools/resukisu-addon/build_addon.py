#!/usr/bin/env python3
"""Build guarded POCO F6 HyperOS 4 ReSukiSU+SUSFS kernel add-on and rollback ZIPs.

The add-on is deliberately separate from the base RI3 ROM. It reuses a pinned
AnyKernel3 runtime but installs the locally source-built ReSukiSU UAPI-5 kernel,
with peridot/RI3 guards. It never mutates the source ROM or stock boot image.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import shutil
import struct
import sys
import tempfile
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
UPSTREAM = ROOT / ".cache/resukisu-addon-upstream/6.1.138-android14-2025-06-ReSukiSU-AnyKernel3.artifact.zip"
BUILT_IMAGE = ROOT / ".cache/resukisu-addon-uapi5/Image"
BUILD_RECEIPT = ROOT / ".cache/resukisu-addon-uapi5/build-receipt.json"
KERNEL_CONFIG = ROOT / ".cache/resukisu-addon-uapi5/kernel.config"
STOCK_BOOT = ROOT / ".cache/global-single-recovery-ri2/source-images/images/boot.img"
CERT = ROOT / "builder/work/installer-ri5-recoveryfix-20261004/source-public-certificate.pem"
PRIVATE_KEY = ROOT / "builder/work/installer-ri3-recovery/.private/development-zip-rsa2048.pem"
SIGNING_AVAILABLE = CERT.is_file() and PRIVATE_KEY.is_file()
OUT = ROOT / "builder/work/resukisu-susfs-addon-uapi5"

UPSTREAM_SHA256 = "99614c2b9260b92ec982bbc4a8195c9223752fefabd1c74a23eb56ae376f3117"
BUILD_RECEIPT_SHA256 = "db39445323401e9e0f48b21aff1e33b354d2bd339b1768515e37719a95e5720f"
KERNEL_CONFIG_SHA256 = "8afe1511847c3bd63e07a9b7ac780554e821fa17165dd4daa98b67a5a397e3d7"
ADDON_IMAGE_SHA256 = "15908eb9fb9a05ce00ca67d74d7dca59a109b3211d3226324bfa6bd6674e4d78"
OLD_ADDON_IMAGE_SHA256 = "f5b148001a01b6b3f498aa6a536ce128dbd4c6a658866e90f5f0b47842861310"
STOCK_BOOT_SHA256 = "e7be9c65e3e6f0af17572a3fa37d43c4e4031d28f391ed17fc625e383c33bf03"
STOCK_IMAGE_SHA256 = "97b2c53022e8c0bd0b279c4c592a196126a6eb0a93647c2957b39dcd5f2dc1c9"
CERT_SHA256 = "099a2c2261110568ef1e48b4929a8d3f4e76ffd71b49ee9bf7fe5074987f31d8"
COMMON_COMMIT = "0c3d559bcd85c64dae9c9c9687abbe5347fff3ad"
ROOT_COMMIT = "8770c7e324a22895703c4916b8a16520e0b81c79"
ROOT_VERSION_CODE = 35203
ROOT_VERSION_NAME = "v4.2.0-rc3-8770c7e3@ReSukiSU"
ROOT_UAPI_VERSION = 5
SUSFS_COMMIT = "24743360ea08d98f6ad72b856851abed8de5854f"
SUSFS_VERSION = "v2.3.0"
KERNEL_RELEASE = "6.1.138-android14-11-g0c3d559bcd85-ab14529422"
TOOLCHAIN = "Ubuntu clang 18.1.3 / LLD 18.1.3"

PACKAGE_SUFFIX = "" if SIGNING_AVAILABLE else "-UNSIGNED"
INSTALL_NAME = f"POCO-F6-HyperOS4-ReSukiSU-UAPI5-SUSFS-Addon-20261004{PACKAGE_SUFFIX}.zip"
ROLLBACK_NAME = f"POCO-F6-HyperOS4-ReSukiSU-UAPI5-SUSFS-Rollback-RI3-20261004{PACKAGE_SUFFIX}.zip"
MANIFEST_NAME = "POCO-F6-RESUKISU-SUSFS-ADDON.json"
README_NAME = "POCO-F6-RESUKISU-SUSFS-README.txt"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def need(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def extract_stock_image(boot: pathlib.Path) -> bytes:
    need(sha256_file(boot) == STOCK_BOOT_SHA256, "Stock RI3 boot image hash mismatch")
    with boot.open("rb") as f:
        header = f.read(4096)
        need(header[:8] == b"ANDROID!", "Not an Android boot image")
        kernel_size = struct.unpack_from("<I", header, 8)[0]
        ramdisk_size = struct.unpack_from("<I", header, 12)[0]
        header_version = struct.unpack_from("<I", header, 40)[0]
        need(header_version == 4, f"Expected boot header v4, got v{header_version}")
        need(ramdisk_size == 0, f"Expected RI3 boot ramdisk size 0, got {ramdisk_size}")
        f.seek(4096)
        image = f.read(kernel_size)
    need(len(image) == kernel_size, "Stock kernel Image truncated")
    need(sha256_bytes(image) == STOCK_IMAGE_SHA256, "Stock kernel Image hash mismatch")
    return image


def clone_info(info: zipfile.ZipInfo) -> zipfile.ZipInfo:
    out = zipfile.ZipInfo(info.filename, date_time=info.date_time)
    out.compress_type = info.compress_type
    out.comment = info.comment
    out.extra = info.extra
    out.create_system = info.create_system
    out.create_version = info.create_version
    out.extract_version = info.extract_version
    out.flag_bits = info.flag_bits
    out.internal_attr = info.internal_attr
    out.external_attr = info.external_attr
    out.volume = info.volume
    return out


def text_info(name: str, mode: int = 0o644) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=(2026, 10, 4, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = (mode & 0xFFFF) << 16
    return info


def anykernel_script(accepted_current_images: tuple[str, ...], label: str) -> bytes:
    need(bool(accepted_current_images), "At least one accepted current kernel hash is required")
    accepted_case = "|".join(accepted_current_images)
    accepted_print = "\n".join(f'ui_print "  {value}"' for value in accepted_current_images)
    return f"""### AnyKernel3 Ramdisk Mod Script
## POCO F6 / peridot HyperOS 4 guarded ReSukiSU+SUSFS add-on
## AnyKernel3 runtime: osm0sis

properties() {{ '
kernel.string={label}
do.devicecheck=1
do.modules=0
do.systemless=0
do.cleanup=1
do.cleanuponabort=0
do.check_boot_version=0
device.name1=peridot
device.name2=
device.name3=
device.name4=
device.name5=
supported.versions=
supported.patchlevels=
supported.vendorpatchlevels=
keycheck.timeout=10
'; }}

block=boot
is_slot_device=auto
ramdisk_compression=auto
patch_vbmeta_flag=0
no_magisk_check=1

. tools/ak3-core.sh

ui_print " "
ui_print "POCO F6 / peridot HyperOS 4 kernel add-on"
ui_print "Target base: F6-Global-HyperOS4-DEV2-RI3-20261003"
ui_print "Accepted current kernel SHA-256 values:"
{accepted_print}

split_boot

current_kernel=""
for candidate in "$SPLITIMG"/kernel "$SPLITIMG"/kernel.* "$SPLITIMG"/kernel-*; do
  [ -f "$candidate" ] || continue
  case "$candidate" in
    *kernel_dtb*) continue ;;
  esac
  current_kernel="$candidate"
  break
done

[ -n "$current_kernel" ] || abort "Could not locate current kernel after boot split."
current_sha="$(sha256sum "$current_kernel" | awk '{{print $1}}')"
case "$current_sha" in
  {accepted_case}) ;;
  *) abort "Current kernel is not an approved RI3/add-on kernel. Refusing to flash." ;;
esac

flash_boot
ui_print "Kernel replacement complete. vbmeta flags were not patched."
""".encode("utf-8")


def readme_text() -> str:
    return f"""POCO F6 HyperOS 4 ReSukiSU + SUSFS add-on

Target:
  POCO F6 / peridot
  F6-Global-HyperOS4-DEV2-RI3-20261003 base
  Android GKI 6.1.138 / android14-2025-06 line

Install package:
  {INSTALL_NAME}
Rollback package:
  {ROLLBACK_NAME}

Safety/compatibility behavior:
  - The add-on is separate from the base ROM and touches only the active boot slot.
  - It requires the device codename peridot.
  - The installer accepts either the exact RI3 stock kernel
    ({STOCK_IMAGE_SHA256}) or the previous UAPI-2 addon kernel
    ({OLD_ADDON_IMAGE_SHA256}), allowing a direct corrective upgrade.
  - The rollback accepts either the corrected UAPI-5 addon kernel
    ({ADDON_IMAGE_SHA256}) or the previous UAPI-2 addon kernel before restoring
    the exact RI3 stock kernel.
  - It preserves the existing boot ramdisk and explicitly leaves vbmeta flags alone.
  - It does not modify super, init_boot, vendor_boot, dtbo, vbmeta, userdata, or
    the base RI3 ROM ZIP.
  - Signing state: {('Android whole-file RSA-SHA256 signed with the existing RI3/RI5 development key; ZIP signature verification may remain enabled.' if SIGNING_AVAILABLE else 'UNSIGNED because the existing approved private development key is currently absent. The package name is explicitly marked UNSIGNED, and ZIP signature verification must be disabled for this package.')}

ReSukiSU/SUSFS provenance:
  Stock common commit: {COMMON_COMMIT}
  ReSukiSU: {ROOT_VERSION_NAME}
  ReSukiSU commit: {ROOT_COMMIT}
  ReSukiSU manager/kernel UAPI: {ROOT_UAPI_VERSION}
  SUSFS: {SUSFS_VERSION}
  SUSFS commit: {SUSFS_COMMIT}
  Kernel release: {KERNEL_RELEASE}
  Toolchain: {TOOLCHAIN}
  Bundled add-on Image SHA-256: {ADDON_IMAGE_SHA256}

The old public AnyKernel3 artifact is used only as the pinned installer runtime
layout. Its old kernel Image is discarded and replaced with the locally compiled
UAPI-5 Image recorded by build-receipt.json.

Build-time validation proves package integrity and guard wiring only. It does not
claim physical-device boot, hardware behavior, or encrypted-storage validation.
"""


def manifest(kind: str, accepted_current: tuple[str, ...], bundled_image: str) -> dict:
    return {
        "schema_version": 1,
        "kind": kind,
        "project": "peridot-hyperos4-port",
        "device": {"codename": "peridot", "product": "POCO F6"},
        "base_rom": "F6-Global-HyperOS4-DEV2-RI3-20261003",
        "boot": {
            "stock_boot_sha256": STOCK_BOOT_SHA256,
            "stock_image_sha256": STOCK_IMAGE_SHA256,
            "accepted_current_image_sha256": list(accepted_current),
            "bundled_image_sha256": bundled_image,
            "partition": "boot",
            "slot_behavior": "active-slot via AnyKernel3",
            "vbmeta_flag_patch": False,
            "ramdisk_preserved": True,
        },
        "kernel_build": {
            "common_commit": COMMON_COMMIT,
            "kernel_release": KERNEL_RELEASE,
            "toolchain": TOOLCHAIN,
            "build_receipt_sha256": BUILD_RECEIPT_SHA256,
            "kernel_config_sha256": KERNEL_CONFIG_SHA256,
        },
        "resukisu": {
            "commit": ROOT_COMMIT,
            "version_code": ROOT_VERSION_CODE,
            "version_name": ROOT_VERSION_NAME,
            "uapi_version": ROOT_UAPI_VERSION,
            "susfs_version": SUSFS_VERSION,
            "susfs_commit": SUSFS_COMMIT,
        },
        "anykernel_runtime": {
            "source_artifact_sha256": UPSTREAM_SHA256,
            "source_kernel_discarded": True,
            "addon_image_sha256": ADDON_IMAGE_SHA256,
            "device_compatibility_claim": "guarded locally against approved RI3/addon kernel hashes",
        },
        "scope": {
            "base_rom_modified": False,
            "partitions_modified_by_addon": ["active boot slot"],
            "device_flash_performed_during_build": False,
        },
    }


def build_one(source: zipfile.ZipFile, output: pathlib.Path, image: bytes,
              accepted_current: tuple[str, ...], label: str, kind: str) -> dict:
    replacement_script = anykernel_script(accepted_current, label)
    m = manifest(kind, accepted_current, sha256_bytes(image))
    manifest_bytes = (json.dumps(m, indent=2, sort_keys=True) + "\n").encode()
    readme_bytes = readme_text().encode()
    cert_bytes = CERT.read_bytes()
    need(sha256_bytes(cert_bytes) == CERT_SHA256, "RI3 development certificate hash mismatch")

    with zipfile.ZipFile(output, "w", allowZip64=True) as dst:
        for info in source.infolist():
            if info.filename in {"Image", "anykernel.sh", MANIFEST_NAME, README_NAME, "META-INF/com/android/otacert"}:
                continue
            dst.writestr(clone_info(info), source.read(info.filename))
        image_info = clone_info(source.getinfo("Image"))
        dst.writestr(image_info, image)
        script_info = clone_info(source.getinfo("anykernel.sh"))
        dst.writestr(script_info, replacement_script)
        dst.writestr(text_info(MANIFEST_NAME), manifest_bytes)
        dst.writestr(text_info(README_NAME), readme_bytes)
        if SIGNING_AVAILABLE:
            dst.writestr(text_info("META-INF/com/android/otacert"), cert_bytes)

    with zipfile.ZipFile(output, "r") as check:
        names = check.namelist()
        need(len(names) == len(set(names)), "Duplicate ZIP members")
        need(sha256_bytes(check.read("Image")) == sha256_bytes(image), "Image changed in ZIP")
        script = check.read("anykernel.sh").decode()
        need("do.devicecheck=1" in script and "device.name1=peridot" in script, "Device guard missing")
        for expected_hash in accepted_current:
            need(expected_hash in script, f"Kernel hash guard missing: {expected_hash}")
        need("case \"$current_sha\" in" in script, "Multi-hash kernel guard missing")
        need("patch_vbmeta_flag=0" in script, "vbmeta preservation guard missing")
        if SIGNING_AVAILABLE:
            need(check.namelist().count("META-INF/com/android/otacert") == 1, "Expected exactly one otacert")
            need(sha256_bytes(check.read("META-INF/com/android/otacert")) == CERT_SHA256, "otacert hash mismatch")
        else:
            need("META-INF/com/android/otacert" not in check.namelist(), "Unsigned package must not imply an embedded signer")
        need(check.comment == b"", "Pre-sign package unexpectedly has a ZIP comment")
        need(json.loads(check.read(MANIFEST_NAME))["boot"]["accepted_current_image_sha256"] == list(accepted_current),
             "Manifest guard mismatch")

    return {
        "path": str(output.relative_to(ROOT)),
        "bytes": output.stat().st_size,
        "sha256": sha256_file(output),
        "kind": kind,
        "accepted_current_image_sha256": list(accepted_current),
        "bundled_image_sha256": sha256_bytes(image),
    }


def sign_one(package: pathlib.Path) -> dict:
    need(CERT.is_file(), f"Missing RI3 development certificate: {CERT}")
    need(PRIVATE_KEY.is_file(), f"Missing RI3 private signing key: {PRIVATE_KEY}")
    need(sha256_file(CERT) == CERT_SHA256, "RI3 development certificate hash mismatch")
    sys.path.insert(0, str(ROOT / "tools/installer-ri3/zip-signing"))
    from sign_zip import sign_generated_zip

    work = OUT / (package.stem + "-signing")
    work.mkdir()
    signed = sign_generated_zip(
        package,
        CERT,
        PRIVATE_KEY,
        generated_root=OUT,
        work_dir=work,
    )
    need(signed["verified"] is True, "Whole-file signature verification did not pass")
    need(signed["certificate_der_sha256"] == "24adea378cba169a0852bce0ffd5ee1874940f16b73c873efc75d57129f080cf",
         "Unexpected signing certificate DER identity")
    return signed


def main() -> None:
    need(UPSTREAM.is_file(), f"Missing pinned upstream artifact: {UPSTREAM}")
    need(BUILT_IMAGE.is_file(), f"Missing UAPI-5 built Image: {BUILT_IMAGE}")
    need(BUILD_RECEIPT.is_file(), f"Missing UAPI-5 build receipt: {BUILD_RECEIPT}")
    need(KERNEL_CONFIG.is_file(), f"Missing UAPI-5 kernel config: {KERNEL_CONFIG}")
    need(STOCK_BOOT.is_file(), f"Missing RI3 stock boot image: {STOCK_BOOT}")
    need(CERT.is_file(), f"Missing RI3/RI5 public development certificate: {CERT}")
    need(sha256_file(UPSTREAM) == UPSTREAM_SHA256, "Pinned AnyKernel3 runtime artifact hash mismatch")
    need(sha256_file(BUILT_IMAGE) == ADDON_IMAGE_SHA256, "UAPI-5 built Image hash mismatch")
    need(sha256_file(BUILD_RECEIPT) == BUILD_RECEIPT_SHA256, "UAPI-5 build receipt hash mismatch")
    need(sha256_file(KERNEL_CONFIG) == KERNEL_CONFIG_SHA256, "UAPI-5 kernel config hash mismatch")
    need(sha256_file(CERT) == CERT_SHA256, "RI3 development certificate hash mismatch")
    build_receipt = json.loads(BUILD_RECEIPT.read_text(encoding="utf-8"))
    need(build_receipt["image_sha256"] == ADDON_IMAGE_SHA256, "Build receipt Image identity mismatch")
    need(build_receipt["resukisu_uapi_version"] == ROOT_UAPI_VERSION == 5, "ReSukiSU UAPI-5 evidence mismatch")
    need(build_receipt["resukisu_version_code"] == ROOT_VERSION_CODE, "ReSukiSU version-code evidence mismatch")
    need(build_receipt["kernel_release"] == KERNEL_RELEASE, "Kernel release evidence mismatch")
    need(build_receipt["patch_reject_count"] == 0, "Build receipt reports patch rejects")

    stock_image = extract_stock_image(STOCK_BOOT)

    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)
    with tempfile.TemporaryDirectory(prefix="verify-", dir=OUT) as _:
        pass

    with zipfile.ZipFile(UPSTREAM, "r") as source:
        need(len(source.namelist()) == len(set(source.namelist())), "Upstream ZIP has duplicate members")
        need("Image" in source.namelist() and "anykernel.sh" in source.namelist(), "Upstream artifact layout changed")
        addon_image = BUILT_IMAGE.read_bytes()
        need(sha256_bytes(addon_image) == ADDON_IMAGE_SHA256, "UAPI-5 add-on Image hash mismatch")

        install = build_one(
            source, OUT / INSTALL_NAME, addon_image,
            (STOCK_IMAGE_SHA256, OLD_ADDON_IMAGE_SHA256),
            "POCO F6 HyperOS 4 - ReSukiSU UAPI 5 + SUSFS", "install"
        )
        rollback = build_one(
            source, OUT / ROLLBACK_NAME, stock_image,
            (ADDON_IMAGE_SHA256, OLD_ADDON_IMAGE_SHA256),
            "POCO F6 HyperOS 4 - restore RI3 stock kernel", "rollback"
        )

    for output in (install, rollback):
        package = ROOT / output["path"]
        unsigned_sha256 = output["sha256"]
        unsigned_bytes = output["bytes"]
        if SIGNING_AVAILABLE:
            signing = sign_one(package)
            need(signing["unsigned_sha256"] == unsigned_sha256, "Signer saw different unsigned package bytes")
            need(signing["unsigned_bytes"] == unsigned_bytes, "Signer saw different unsigned package size")
            output.update({
                "unsigned_sha256": unsigned_sha256,
                "unsigned_bytes": unsigned_bytes,
                "sha256": signing["sha256"],
                "bytes": signing["size"],
                "signed": True,
                "signing": signing,
            })
        else:
            output.update({
                "unsigned_sha256": unsigned_sha256,
                "unsigned_bytes": unsigned_bytes,
                "signed": False,
                "signing": None,
            })

    receipt = {
        "schema_version": 1,
        "status": "offline-package-validation-passed",
        "base_rom_modified": False,
        "kernel_build": build_receipt,
        "built_image": {
            "path": str(BUILT_IMAGE.relative_to(ROOT)),
            "sha256": ADDON_IMAGE_SHA256,
        },
        "anykernel_runtime_artifact": {
            "path": str(UPSTREAM.relative_to(ROOT)),
            "sha256": UPSTREAM_SHA256,
            "kernel_image_used": False,
        },
        "stock_boot": {
            "path": str(STOCK_BOOT.relative_to(ROOT)),
            "sha256": STOCK_BOOT_SHA256,
            "image_sha256": STOCK_IMAGE_SHA256,
        },
        "outputs": [install, rollback],
        "checks": [
            "pinned AnyKernel3 runtime artifact SHA-256",
            "locally compiled ReSukiSU UAPI-5 Image SHA-256",
            "ReSukiSU version code 35203 and UAPI 5 build receipt",
            "stock-identical kernel release string",
            "zero SUSFS patch rejects",
            "pinned kernel config SHA-256",
            "RI3 stock boot SHA-256",
            "RI3 stock boot header v4 and zero ramdisk",
            "RI3 stock raw kernel Image SHA-256",
            "unique ZIP member names",
            "peridot device guard",
            "exact current-kernel SHA-256 guard",
            "vbmeta flag patch disabled",
            "bundled Image SHA-256 after packaging",
            "manifest/installer guard agreement",
            "signing state explicit and filename-consistent",
        ] + ([
            "RI3 otacert embedded exactly once",
            "Android whole-file RSA-SHA256 signing",
            "independent whole-file signature verification",
        ] if SIGNING_AVAILABLE else [
            "unsigned ZIP has no otacert and no signature footer",
            "approved public certificate identity preserved only as provenance",
        ]),
        "zip_signing": {
            "available": SIGNING_AVAILABLE,
            "certificate_pem_sha256": CERT_SHA256,
            "certificate_der_sha256": "24adea378cba169a0852bce0ffd5ee1874940f16b73c873efc75d57129f080cf",
            "private_key_in_artifacts": False,
            "private_key_present_at_build": PRIVATE_KEY.is_file(),
            "recovery_zip_signature_verification_may_remain_enabled": SIGNING_AVAILABLE,
        },
    }
    (OUT / "validation.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    summary_lines = [readme_text(), "\nPackage identities:\n"]
    for output in receipt["outputs"]:
        summary_lines.append(f"  {pathlib.Path(output['path']).name}\n    bytes: {output['bytes']}\n    SHA-256: {output['sha256']}\n")
    (OUT / "README.txt").write_text("".join(summary_lines), encoding="utf-8")
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()
