"""Exact-source planning for the Global F6 + Xiaomi 17 combination.

Source checks are mandatory. Planning does not select an AVB trust policy,
authorize device writes, or promote a historical super layout to fact.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .errors import BuilderError
from .models import OtaInspection, PartitionInfo
from .ota import inspect_ota
from .ownership import build_ownership_plan
from .payload_manifest import inspect_payload_manifest


def load_source_profile(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8-sig") as handle:
        profile = json.load(handle)
    if profile.get("schema_version") != 1 or profile.get("target_codename") != "peridot":
        raise BuilderError("Unsupported Global source profile")
    for role, build in (("stock", "OS3.0.303.0.WNPMIXM"),
                        ("donor", "OS4.0.0.9.XPCMIXM")):
        source = profile.get(role, {})
        if source.get("build") != build or source.get("region") != "Global":
            raise BuilderError(f"{role} is not the selected Global build")
        if not re.fullmatch(r"[0-9a-f]{64}", str(source.get("sha256", ""))):
            raise BuilderError(f"{role} archive SHA-256 is not locked")
        if not re.fullmatch(r"[0-9a-f]{64}", str(source.get("manifest_sha256", ""))):
            raise BuilderError(f"{role} payload manifest SHA-256 is not locked")
        if int(source.get("size_bytes", 0)) <= 0:
            raise BuilderError(f"{role} archive size is not locked")
        expected_device = "peridot" if role == "stock" else "pudding"
        if source.get("codename") != expected_device:
            raise BuilderError(f"{role} codename mismatch")
        expected_prefix = "POCO/peridot_global/peridot:" if role == "stock" else "Xiaomi/pudding_global/pudding:"
        metadata = source.get("metadata", {})
        if not str(metadata.get("post-build", "")).startswith(expected_prefix):
            raise BuilderError(f"{role} fingerprint is not Global")
        if metadata.get("pre-device") != expected_device:
            raise BuilderError(f"{role} metadata device is not locked")
    security = profile.get("security", {})
    if security != {
        "preserve_stock_thermal_protections": True,
        "preserve_stock_fbe_and_metadata_encryption": True,
        "disable_avb": False,
        "fake_locked_properties": False,
        "bypass_app_integrity": False,
    }:
        raise BuilderError("Global profile must preserve the approved security baseline")
    return profile


def validate_source(inspection: OtaInspection, manifest: dict[str, Any],
                    expected: dict[str, Any], role: str) -> None:
    if inspection.sha256 != expected["sha256"] or inspection.size_bytes != expected["size_bytes"]:
        raise BuilderError(f"{role} archive identity does not match the locked Global source")
    if not inspection.has_payload or inspection.payload_entry != "payload.bin":
        raise BuilderError(f"{role} requires a root full OTA payload")
    if inspection.device_candidates != [expected["codename"]]:
        raise BuilderError(f"{role} pre-device metadata does not match")
    for key, value in expected["metadata"].items():
        if inspection.metadata.get(key) != value:
            raise BuilderError(f"{role} metadata mismatch for {key}")
    if manifest.get("manifest_sha256") != expected["manifest_sha256"]:
        raise BuilderError(f"{role} payload manifest hash mismatch")
    if not manifest.get("full_payload"):
        raise BuilderError(f"{role} must be a complete, independent payload")


def plan_global_sources(stock: OtaInspection, donor: OtaInspection,
                        stock_manifest: dict[str, Any], donor_manifest: dict[str, Any],
                        profile: dict[str, Any]) -> dict[str, Any]:
    for role, inspection, manifest in (("stock", stock, stock_manifest),
                                       ("donor", donor, donor_manifest)):
        validate_source(inspection, manifest, profile[role], role)
        inspection.partitions = [PartitionInfo(row["partition"], row["size_bytes"])
                                 for row in manifest["partitions"]]
    ownership = build_ownership_plan(stock, donor, "peridot", "pudding")
    expected_stock = {"vendor", "odm", "vendor_dlkm", "system_dlkm"}
    expected_donor = {"system", "system_ext", "product", "mi_ext"}
    if set(ownership["stock"]["take_dynamic_hardware"]) != expected_stock:
        raise BuilderError("Global stock dynamic hardware set is incomplete")
    if set(ownership["donor"]["take_userspace"]) != expected_donor:
        raise BuilderError("Global donor userspace set is incomplete")
    groups = stock_manifest["dynamic_groups"]
    if len(groups) != 1 or set(groups[0]["partitions"]) != expected_stock | expected_donor:
        raise BuilderError("Unexpected Global stock dynamic group membership")
    donor_dynamic = {name for group in donor_manifest["dynamic_groups"]
                     for name in group["partitions"]}
    extra_donor_dynamic = sorted(donor_dynamic - set(groups[0]["partitions"]))
    extra_records = [row for row in donor_manifest["partitions"]
                     if row["partition"] in extra_donor_dynamic]
    inputs = []
    for role, manifest, selected in (("stock", stock_manifest, expected_stock),
                                     ("donor", donor_manifest, expected_donor)):
        for row in manifest["partitions"]:
            if row["partition"] in selected:
                inputs.append({**row, "source": role,
                               "source_archive_sha256": profile[role]["sha256"],
                               "mutation": "none_at_source_planning"})
    inputs.sort(key=lambda row: row["partition"])
    total = sum(row["size_bytes"] for row in inputs)
    maximum = groups[0]["maximum_size_bytes"]
    headroom = maximum - total
    return {
        "schema_version": 1,
        "profile_id": profile["id"],
        "status": "sources_locked",
        "source_identity_verified": True,
        "oem_signature_verification": "not_established_by_archive_hashes",
        "stock": profile["stock"], "donor": profile["donor"],
        "ownership": ownership,
        "logical_inputs": inputs,
        "extra_donor_dynamic_partitions_requiring_review": extra_records,
        "budget": {
            "basis": "exact_stock_payload_dynamic_group",
            "group_name": groups[0]["name"],
            "group_maximum_size_bytes": maximum,
            "source_logical_image_bytes": total,
            "raw_group_headroom_bytes": headroom,
            "source_images_fit_group": headroom >= 0,
            "source_avb_footers_included_in_sizes": True,
            "modified_product_final_size_and_footer_verified": False,
            "physical_super_geometry_verified": False,
            "alignment_and_metadata_allocation_verified": False,
        },
        "security": profile["security"],
        "execution": {"phone_access": False, "flashing": False,
                      "rom_downloads_to_connected_computer": False},
        "release_gates": {
            "exact_physical_super_layout": "pending",
            "extra_donor_dynamic_partition_consumers": ("pending" if extra_donor_dynamic else "none"),
            "product_target_config_and_consumers": "pending",
            "global_avb_policy_and_full_chain": "pending",
            "vintf_and_apex_compatibility": "pending",
            "device_boot_and_thermal_validation": "not_run_no_device_modifications_authorized",
        },
        "boot_ready": False,
        "flash_recommended": False,
        "notes": [
            "China composition, removal lists, AVB fingerprints and rollback indexes are not reused.",
            "No app removal or thermal/performance tuning is selected by this source plan.",
            "The stock update-group limit is measured; physical super geometry is a separate gate.",
            "Source image sizes contain their existing footers; any rebuilt product must be budgeted again with its final AVB footer.",
            "Stock vendor/odm preservation protects source bytes but does not prove compatibility with the donor framework.",
        ],
    }


def prepare_global_sources(stock_path: Path, donor_path: Path,
                           profile_path: Path) -> dict[str, Any]:
    profile = load_source_profile(profile_path)
    inspections = []
    manifests = []
    for role, path in (("stock", stock_path), ("donor", donor_path)):
        inspection = inspect_ota(path)
        if (inspection.sha256 != profile[role]["sha256"] or
                inspection.size_bytes != profile[role]["size_bytes"]):
            raise BuilderError(f"{role} archive identity does not match the locked Global source")
        inspections.append(inspection)
        manifests.append(inspect_payload_manifest(path))
    return plan_global_sources(*inspections, *manifests, profile)
