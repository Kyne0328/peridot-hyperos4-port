from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import OtaInspection


PROFILE_SCHEMA_VERSION = 1


def load_reference(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def build_device_profile(
    inspection: OtaInspection,
    reference: dict[str, Any],
) -> dict[str, Any]:
    device = reference["device"]
    hints = reference["hints"]
    expected_codename = device["codename"]

    partition_by_name = {p.name: p for p in inspection.partitions}
    partition_names = sorted(partition_by_name)

    dynamic_hint = hints.get("dynamic_partitions", [])
    dynamic_present = [name for name in dynamic_hint if name in partition_by_name]
    dynamic_set = set(dynamic_present)
    firmware_present = [
        name for name in partition_names if name not in dynamic_set
    ]

    device_candidates = inspection.device_candidates
    codename_verified = (
        expected_codename in device_candidates if device_candidates else False
    )

    warnings = list(inspection.warnings)
    if device_candidates and not codename_verified:
        warnings.append(
            f"Expected target '{expected_codename}', OTA metadata reports {device_candidates}"
        )
    if not partition_names:
        warnings.append(
            "Partition inventory is unavailable; install payload-dumper-go and rerun profile"
        )

    physical_hints = {
        name: size
        for name, size in hints.get("physical_partition_sizes", {}).items()
        if not partition_names or name in partition_by_name
    }

    return {
        "schema_version": PROFILE_SCHEMA_VERSION,
        "device": device,
        "stock_ota": {
            "path": inspection.path,
            "size_bytes": inspection.size_bytes,
            "sha256": inspection.sha256,
            "metadata": inspection.metadata,
            "payload_properties": inspection.payload_properties,
            "device_candidates": device_candidates,
        },
        "partition_inventory": {
            "verified_from_payload": bool(partition_names),
            "partitions": [
                item.to_dict()
                for item in sorted(inspection.partitions, key=lambda p: p.name)
            ],
            "dynamic_partitions": dynamic_present,
            "firmware_partitions": firmware_present,
        },
        "layout_hints": {
            "source": "reference_device_tree",
            "verified_against_selected_stock_ota": False,
            "super_size_bytes": hints.get("super_size_bytes"),
            "dynamic_partition_group": hints.get("dynamic_partition_group"),
            "physical_partition_sizes": physical_hints,
            "ab_ota": hints.get("ab_ota"),
            "virtual_ab": hints.get("virtual_ab"),
            "boot_image_header_version": hints.get("boot_image_header_version"),
            "platform": hints.get("platform"),
            "architecture": hints.get("architecture"),
        },
        "verification": {
            "codename_matches_stock_metadata": codename_verified,
            "partition_inventory_available": bool(partition_names),
            "super_layout_verified": False,
            "avb_topology_verified": False,
        },
        "reference_sources": reference.get("sources", []),
        "warnings": warnings,
    }


def write_profile(profile: dict[str, Any], path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(profile, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    return path
