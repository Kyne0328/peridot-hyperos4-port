from __future__ import annotations

from typing import Any

from .errors import BuilderError
from .models import OtaInspection


def _sizes(inspection: OtaInspection) -> dict[str, int]:
    return {item.name: item.size_bytes for item in inspection.partitions}


def build_super_budget(
    stock: OtaInspection,
    donor: OtaInspection,
    ownership_plan: dict[str, Any],
    super_size_bytes: int,
) -> dict[str, Any]:
    if super_size_bytes <= 0:
        raise BuilderError("super size must be positive")

    stock_sizes = _sizes(stock)
    donor_sizes = _sizes(donor)

    target_dynamic = ownership_plan["stock"].get("take_dynamic_hardware", [])
    donor_userspace = ownership_plan["donor"].get("take_userspace", [])

    missing_stock = [name for name in target_dynamic if name not in stock_sizes]
    missing_donor = [name for name in donor_userspace if name not in donor_sizes]
    if missing_stock or missing_donor:
        parts: list[str] = []
        if missing_stock:
            parts.append(f"stock missing {missing_stock}")
        if missing_donor:
            parts.append(f"donor missing {missing_donor}")
        raise BuilderError("Cannot build super budget: " + "; ".join(parts))

    stock_rows = [
        {"partition": name, "size_bytes": stock_sizes[name]}
        for name in target_dynamic
    ]
    donor_rows = [
        {"partition": name, "size_bytes": donor_sizes[name]}
        for name in donor_userspace
    ]

    stock_total = sum(item["size_bytes"] for item in stock_rows)
    donor_total = sum(item["size_bytes"] for item in donor_rows)
    composed_total = stock_total + donor_total
    delta = super_size_bytes - composed_total

    return {
        "schema_version": 1,
        "policy": "clean_erofs_first_budget",
        "super_size_bytes": super_size_bytes,
        "target_dynamic_hardware": stock_rows,
        "donor_userspace": donor_rows,
        "target_dynamic_hardware_bytes": stock_total,
        "donor_userspace_bytes": donor_total,
        "composed_bytes": composed_total,
        "headroom_bytes": max(delta, 0),
        "excess_bytes": max(-delta, 0),
        "fits_without_reduction": delta >= 0,
        "minimum_reduction_bytes": max(-delta, 0),
        "notes": [
            "This is a raw logical-image budget from the selected OTA payloads.",
            "Boot, recovery, firmware, and vbmeta are outside super and are not counted.",
            "No filesystem conversion, debloat, mi_ext collapse, AVB change, or encryption change is assumed.",
        ],
    }
