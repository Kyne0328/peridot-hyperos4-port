"""Final offline delivery verification for the UAPI5 full WildKernels addon set."""
from __future__ import annotations

from pathlib import Path
import hashlib
import json
import zipfile

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "builder/work/resukisu-susfs-addon-uapi5-fullbundle-20261004"
BUILD = ROOT / "builder/work/resukisu-uapi5-fullbundle-20261004"
FEATURE_SET = "SUSFS+NoMount+BBG+NET+DS+NTSync+Ptrace+Unicode+BPF+Perf"
EXPECTED = {
    "POCO-F6-HyperOS4-ReSukiSU-SUSFS-UAPI5-FullBundle-Update-20261004.zip":
        "53d0aeeabad8a55b5b0279ac6067d59a7d89e64769b8040a3b91a8e22936272a",
    "POCO-F6-HyperOS4-ReSukiSU-SUSFS-UAPI5-FullBundle-Rollback-UAPI5-Core-20261004.zip":
        "199e96b33202144bded0b8023af344598af033ea6aa2b4ae21ffc5f40a5fc36f",
    "POCO-F6-HyperOS4-ReSukiSU-SUSFS-UAPI5-FullBundle-Rollback-Stock-20261004.zip":
        "35b49dc8bf95da58d97b4a8609dbc84ab7d97225b247b85201e0d6e541cce82a",
}
MANIFEST = "POCO-F6-UAPI5-FULLBUNDLE-MANIFEST.json"


def sha(path: Path) -> str:
    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def need(ok: bool, message: str) -> None:
    if not ok:
        raise RuntimeError(message)


def main() -> None:
    validation = json.loads((OUT / "validation.json").read_text(encoding="utf-8"))
    compatibility = json.loads((BUILD / "compatibility.json").read_text(encoding="utf-8"))
    guards = json.loads((BUILD / "package-guard-tests.json").read_text(encoding="utf-8"))

    need(validation["status"] == "signed-packages-created", "Package validation status is not complete")
    need(validation["feature_set"] == FEATURE_SET, "Package feature set mismatch")
    need(validation["features"] == FEATURE_SET.split("+"), "Package feature list mismatch")
    need(validation["full_wildkernels_bundle"] is True, "Full WildKernels bundle flag is false")
    need(validation["private_key_material_in_artifacts"] is False, "Private-key exclusion not recorded")
    need(validation["recovery_zip_certificate_trust_verified"] is False,
         "Recovery certificate trust must remain unverified")
    need(validation["device_tested"] is False and validation["device_access_performed"] is False,
         "Offline package incorrectly claims device testing/access")
    need(validation["base_rom_modified"] is False and validation["source_archives_modified"] is False,
         "Package incorrectly records base/source modification")

    need(compatibility["status"] == "offline-fullbundle-compatibility-passed",
         "Compatibility report did not pass")
    need(compatibility["feature_set"] == FEATURE_SET, "Compatibility feature set mismatch")
    need(compatibility["image_sha256"] ==
         "340c3470ece7408fbbf0f307db2d15f6528e9c7d73c0d239638f9e62d0b415e9",
         "Full-bundle Image identity mismatch")
    need(not compatibility["shared_export_crc_mismatches"], "Shared export CRC mismatches remain")
    need(all(not row["crc_mismatches"] and not row["unresolved_imports"]
             for row in compatibility["modules"]), "Stock module compatibility gaps remain")
    need(compatibility["stock_key_module_signatures_verified"] == 60,
         "Expected 60 stock-signed module verifications")

    need(guards["status"] == "passed" and guards["case_count"] == 15,
         "Expected 15 passing inert guard cases")
    need(guards["device_access"] is False and guards["real_boot_write"] is False
         and guards["flash_boot_is_stub"] is True, "Guard tests were not inert")

    output_by_name = {Path(row["path"]).name: row for row in validation["outputs"]}
    need(set(output_by_name) == set(EXPECTED), "Validation output set mismatch")

    for name, expected_sha in EXPECTED.items():
        path = OUT / name
        need(path.is_file(), f"Missing package: {name}")
        need(sha(path) == expected_sha, f"Package hash mismatch: {name}")
        row = output_by_name[name]
        need(row["sha256"] == expected_sha, f"Validation receipt hash mismatch: {name}")
        need(row["signing"]["verified"] is True, f"Signer receipt not verified: {name}")
        need(row["signing"]["certificate_der_sha256"] ==
             "bdb1c8a85676ace21f200b9d235fd94fd17427c06ed22a9d7d05bbbcbe949023",
             f"Unexpected ZIP signing certificate: {name}")
        need(row["signing"]["private_key_material_in_artifacts"] is False,
             f"Signer receipt reports private key material: {name}")

        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
            need(len(names) == len(set(names)), f"Duplicate ZIP member: {name}")
            need(names.count("META-INF/com/android/otacert") == 1,
                 f"Expected one otacert: {name}")
            need(archive.testzip() is None, f"ZIP CRC failure: {name}")
            manifest = json.loads(archive.read(MANIFEST))
            need(manifest["full_wildkernels_bundle"] is True, f"Full-bundle flag missing: {name}")
            need(manifest["feature_set"] == FEATURE_SET and
                 manifest["features"] == FEATURE_SET.split("+"), f"Feature manifest mismatch: {name}")
            need(manifest["new_kernel_uapi"] == 5, f"UAPI manifest mismatch: {name}")
            need(manifest["device"]["codename"] == "peridot", f"Device manifest mismatch: {name}")
            need(manifest["active_boot_only"] is True and
                 manifest["ramdisk_preserved"] is True and
                 manifest["vbmeta_flag_patch"] is False, f"Boot safety manifest mismatch: {name}")
            need(manifest["runtime_validated"] is False and
                 manifest["recovery_zip_certificate_trust_verified"] is False and
                 manifest["device_tested"] is False, f"Runtime/trust claim mismatch: {name}")

            script = archive.read("anykernel.sh")
            need(b"device.name1=peridot" in script, f"peridot guard missing: {name}")
            need(b"patch_vbmeta_flag=0" in script, f"vbmeta guard missing: {name}")
            need(b'case "$current_sha"' in script, f"kernel-hash guard missing: {name}")

            for member in names:
                lower = member.lower()
                need("private" not in lower and not lower.endswith(".pem"),
                     f"Sensitive-looking member name: {name}/{member}")
                body = archive.read(member)
                need(b"-----BEGIN PRIVATE KEY-----" not in body and
                     b"-----BEGIN RSA PRIVATE KEY-----" not in body,
                     f"Private key material found in {name}/{member}")

    result = {
        "schema_version": 1,
        "status": "offline-delivery-validation-passed",
        "feature_set": FEATURE_SET,
        "full_bundle_feature_count": 10,
        "package_sha256": EXPECTED,
        "guard_cases": 15,
        "shared_stock_exports": compatibility["shared_stock_exports"],
        "stock_signed_modules_verified": compatibility["stock_key_module_signatures_verified"],
        "device_tested": False,
        "recovery_zip_certificate_trust_verified": False,
        "private_key_material_in_artifacts": False,
    }
    (OUT / "final-validation.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
