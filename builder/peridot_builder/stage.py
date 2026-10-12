from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from .errors import BuilderError
from .hashing import sha256_file
from .models import OtaInspection
from .tools import PayloadDumperGo


def _partition_sizes(inspection: OtaInspection) -> dict[str, int]:
    return {item.name: item.size_bytes for item in inspection.partitions}


def estimate_stage_bytes(
    stock: OtaInspection, donor: OtaInspection, plan: dict[str, Any]
) -> int:
    stock_sizes = _partition_sizes(stock)
    donor_sizes = _partition_sizes(donor)
    total = sum(stock_sizes.get(name, 0) for name in plan["stock"]["preserve"])
    total += sum(donor_sizes.get(name, 0) for name in plan["donor"]["take_userspace"])
    return total


def _hash_images(directory: Path) -> list[dict[str, Any]]:
    files: list[dict[str, Any]] = []
    for path in sorted(directory.glob("*.img")):
        files.append(
            {
                "name": path.name,
                "size_bytes": path.stat().st_size,
                "sha256": sha256_file(path),
                "path": str(path.resolve()),
            }
        )
    return files


def stage_inputs(
    dumper: PayloadDumperGo,
    stock: OtaInspection,
    donor: OtaInspection,
    plan: dict[str, Any],
    output_root: Path,
) -> dict[str, Any]:
    output_root = output_root.resolve()
    target_dir = output_root / "target"
    donor_dir = output_root / "donor"
    manifest_path = output_root / "stage-manifest.json"

    if target_dir.exists() or donor_dir.exists() or manifest_path.exists():
        raise BuilderError(
            f"Stage output already exists; refusing to mix runs: {output_root}"
        )

    estimate = estimate_stage_bytes(stock, donor, plan)
    probe = output_root.parent if output_root.parent.exists() else Path.cwd()
    free = shutil.disk_usage(probe).free
    required = int(estimate * 1.15)
    if free < required:
        raise BuilderError(
            f"Insufficient free space for staging: need about {required} bytes, "
            f"have {free} bytes"
        )

    output_root.mkdir(parents=True, exist_ok=True)
    try:
        dumper.extract(stock_path := Path(stock.path), target_dir, plan["stock"]["preserve"])
        dumper.extract(donor_path := Path(donor.path), donor_dir, plan["donor"]["take_userspace"])

        manifest = {
            "schema_version": 1,
            "status": "staged",
            "estimated_uncompressed_bytes": estimate,
            "stock": {
                "source": str(stock_path),
                "source_sha256": stock.sha256,
                "images": _hash_images(target_dir),
            },
            "donor": {
                "source": str(donor_path),
                "source_sha256": donor.sha256,
                "images": _hash_images(donor_dir),
            },
            "ownership_plan": plan,
        }
        manifest_path.write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        return manifest
    except Exception:
        # Preserve partial evidence for debugging; do not silently delete extracted data.
        raise
