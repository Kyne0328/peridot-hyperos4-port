from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

from .errors import BuilderError
from .hashing import sha256_file
from .lp import inspect_super_image


EXPECTED_BASE_PARTITIONS = (
    "mi_ext",
    "odm",
    "product",
    "system",
    "system_dlkm",
    "system_ext",
    "vendor",
    "vendor_dlkm",
)


def load_super_reference(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise BuilderError(f"Could not load super reference {path}: {error}") from error
    if not isinstance(data, dict):
        raise BuilderError("Super reference must be a JSON object")
    return data


def build_structural_super_plan(
    reference: dict[str, Any],
    images: dict[str, Path],
    output: Path,
) -> dict[str, Any]:
    expected = set(EXPECTED_BASE_PARTITIONS)
    missing = sorted(expected - set(images))
    extra = sorted(set(images) - expected)
    if missing:
        raise BuilderError("Missing super input images: " + ", ".join(missing))
    if extra:
        raise BuilderError("Unexpected super input images: " + ", ".join(extra))

    geometry = reference.get("geometry")
    header = reference.get("header")
    groups = reference.get("groups")
    block_devices = reference.get("block_devices")
    partitions = reference.get("partitions")
    if not isinstance(geometry, dict) or not isinstance(header, dict):
        raise BuilderError("Super reference is missing geometry/header")
    if not isinstance(groups, list) or not isinstance(block_devices, list):
        raise BuilderError("Super reference is missing groups/block_devices")
    if not isinstance(partitions, list):
        raise BuilderError("Super reference is missing partition metadata")

    super_device = next(
        (
            item
            for item in block_devices
            if isinstance(item, dict) and item.get("name") == "super"
        ),
        None,
    )
    if not isinstance(super_device, dict):
        raise BuilderError("Super reference does not describe the super block device")

    active_group = next(
        (
            item
            for item in groups
            if isinstance(item, dict) and str(item.get("name", "")).endswith("_a")
        ),
        None,
    )
    inactive_group = next(
        (
            item
            for item in groups
            if isinstance(item, dict) and str(item.get("name", "")).endswith("_b")
        ),
        None,
    )
    if not isinstance(active_group, dict) or not isinstance(inactive_group, dict):
        raise BuilderError("Super reference does not contain A/B dynamic groups")

    expected_names = {
        *(f"{name}_a" for name in EXPECTED_BASE_PARTITIONS),
        *(f"{name}_b" for name in EXPECTED_BASE_PARTITIONS),
    }
    observed_names = {
        str(item.get("name")) for item in partitions if isinstance(item, dict)
    }
    absent = sorted(expected_names - observed_names)
    if absent:
        raise BuilderError(
            "Super reference is missing expected logical partitions: "
            + ", ".join(absent)
        )

    input_records: list[dict[str, Any]] = []
    active_total = 0
    for base in EXPECTED_BASE_PARTITIONS:
        image = images[base].resolve()
        if not image.is_file():
            raise BuilderError(f"Super input image does not exist: {image}")
        size = image.stat().st_size
        if size <= 0:
            raise BuilderError(f"Super input image is empty: {image}")
        active_total += size
        input_records.append(
            {
                "partition": base,
                "logical_partition": f"{base}_a",
                "path": str(image),
                "size_bytes": size,
                "sha256": sha256_file(image),
            }
        )

    super_size = int(super_device.get("size_bytes", 0))
    metadata_max_size = int(geometry.get("metadata_max_size", 0))
    metadata_slots = int(geometry.get("metadata_slot_count", 0))
    alignment = int(super_device.get("alignment", 0))
    alignment_offset = int(super_device.get("alignment_offset", 0))
    if min(super_size, metadata_max_size, metadata_slots, alignment) <= 0:
        raise BuilderError("Super reference contains invalid size/alignment metadata")

    first_logical_sector = int(super_device.get("first_logical_sector", 0))
    first_logical_byte = first_logical_sector * 512
    allocatable_after_prefix = super_size - first_logical_byte
    raw_headroom = allocatable_after_prefix - active_total

    args: list[str] = [
        "--metadata-size",
        str(metadata_max_size),
        "--metadata-slots",
        str(metadata_slots),
        "--super-name",
        "super",
        "--device",
        f"super:{super_size}:{alignment}:{alignment_offset}",
        "--group",
        f"{active_group['name']}:{int(active_group.get('maximum_size', super_size))}",
        "--group",
        f"{inactive_group['name']}:{int(inactive_group.get('maximum_size', super_size))}",
        "--virtual-ab",
    ]

    for record in input_records:
        args.extend(
            [
                "--partition",
                f"{record['logical_partition']}:none:{record['size_bytes']}:{active_group['name']}",
                "--image",
                f"{record['logical_partition']}={record['path']}",
            ]
        )

    for base in EXPECTED_BASE_PARTITIONS:
        args.extend(
            [
                "--partition",
                f"{base}_b:none:0:{inactive_group['name']}",
            ]
        )

    args.extend(["--output", str(output.resolve())])

    return {
        "schema_version": 1,
        "mode": "structural_validation_only",
        "boot_ready": False,
        "flash_recommended": False,
        "avb_policy_selected": False,
        "reason_not_boot_ready": (
            "The mixed/rebuilt image set is not authenticated by an explicitly "
            "generated and verified AVB chain yet."
        ),
        "reference": {
            "super_size_bytes": super_size,
            "metadata_max_size": metadata_max_size,
            "metadata_slot_count": metadata_slots,
            "logical_block_size": int(geometry.get("logical_block_size", 0)),
            "first_logical_sector": first_logical_sector,
            "alignment": alignment,
            "alignment_offset": alignment_offset,
            "active_group": active_group["name"],
            "inactive_group": inactive_group["name"],
            "header_flags": int(header.get("flags", 0)),
        },
        "inputs": input_records,
        "active_partition_bytes": active_total,
        "allocatable_after_metadata_prefix_bytes": allocatable_after_prefix,
        "raw_headroom_bytes": raw_headroom,
        "fits_raw_layout": raw_headroom >= 0,
        "output": str(output.resolve()),
        "lpmake_args": args,
    }


def run_structural_super_plan(
    executable: Path,
    plan: dict[str, Any],
) -> dict[str, Any]:
    if plan.get("mode") != "structural_validation_only":
        raise BuilderError("Refusing to execute a non-structural super plan")
    if plan.get("boot_ready") is not False or plan.get("flash_recommended") is not False:
        raise BuilderError("Structural super plan must remain explicitly non-boot-ready")
    if not plan.get("fits_raw_layout"):
        raise BuilderError("Refusing to build a super image that does not fit")

    output = Path(str(plan.get("output", ""))).resolve()
    if not output.name:
        raise BuilderError("Super plan output path is missing")
    if output.exists():
        raise BuilderError(f"Refusing to overwrite existing super image: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)

    args = plan.get("lpmake_args")
    if not isinstance(args, list) or not all(isinstance(item, str) for item in args):
        raise BuilderError("Super plan lpmake_args must be a list of strings")

    process = subprocess.run(
        [str(executable.resolve()), *args],
        capture_output=True,
        text=True,
        errors="replace",
        check=False,
    )
    if process.returncode != 0:
        detail = process.stderr.strip() or process.stdout.strip()
        raise BuilderError(
            f"lpmake failed with exit code {process.returncode}: {detail}"
        )
    if not output.is_file():
        raise BuilderError("lpmake exited successfully but did not create the output")

    expected_size = int(plan["reference"]["super_size_bytes"])
    actual_size = output.stat().st_size
    if actual_size != expected_size:
        raise BuilderError(
            f"Structural super size mismatch: expected {expected_size}, got {actual_size}"
        )

    return {
        "status": "complete",
        "mode": "structural_validation_only",
        "boot_ready": False,
        "flash_recommended": False,
        "avb_policy_selected": False,
        "output": str(output),
        "size_bytes": actual_size,
        "sha256": sha256_file(output),
        "lpmake_stdout": process.stdout.rstrip(),
        "lpmake_stderr": process.stderr.rstrip(),
    }


def _hash_super_extents(
    handle: Any,
    extents: list[dict[str, Any]],
    chunk_size: int = 8 * 1024 * 1024,
) -> str:
    digest = hashlib.sha256()
    for extent in extents:
        if int(extent.get("target_type", -1)) != 0:
            raise BuilderError("Only linear super extents can be content-verified")
        remaining = int(extent.get("size_bytes", 0))
        handle.seek(int(extent.get("offset_bytes", 0)))
        while remaining > 0:
            chunk = handle.read(min(chunk_size, remaining))
            if not chunk:
                raise BuilderError("Unexpected end of super image while hashing extent")
            digest.update(chunk)
            remaining -= len(chunk)
    return digest.hexdigest()


def verify_structural_super(
    image: Path,
    plan: dict[str, Any],
) -> dict[str, Any]:
    image = image.resolve()
    metadata = inspect_super_image(image)

    expected_reference = plan.get("reference")
    if not isinstance(expected_reference, dict):
        raise BuilderError("Structural super plan is missing reference metadata")

    reference_checks = {
        "super_size_bytes": metadata.get("super_size_bytes"),
        "metadata_max_size": metadata["geometry"].get("metadata_max_size"),
        "metadata_slot_count": metadata["geometry"].get("metadata_slot_count"),
        "logical_block_size": metadata["geometry"].get("logical_block_size"),
        "first_logical_sector": metadata["block_devices"][0].get(
            "first_logical_sector"
        ),
        "alignment": metadata["block_devices"][0].get("alignment"),
        "alignment_offset": metadata["block_devices"][0].get("alignment_offset"),
        "header_flags": metadata["header"].get("flags"),
    }
    for key, observed in reference_checks.items():
        expected = expected_reference.get(key)
        if observed != expected:
            raise BuilderError(
                f"Generated super metadata mismatch for {key}: "
                f"expected {expected}, got {observed}"
            )

    partition_by_name = {
        item["name"]: item
        for item in metadata["partitions"]
        if isinstance(item, dict) and "name" in item
    }
    results = []
    with image.open("rb") as handle:
        for record in plan.get("inputs", []):
            logical = str(record["logical_partition"])
            partition = partition_by_name.get(logical)
            if not isinstance(partition, dict):
                raise BuilderError(
                    f"Generated super is missing logical partition {logical}"
                )
            expected_size = int(record["size_bytes"])
            actual_size = int(partition.get("size_bytes", -1))
            if actual_size != expected_size:
                raise BuilderError(
                    f"{logical} size mismatch: expected {expected_size}, got {actual_size}"
                )
            actual_hash = _hash_super_extents(handle, partition.get("extents", []))
            expected_hash = str(record["sha256"])
            if actual_hash != expected_hash:
                raise BuilderError(
                    f"{logical} content hash mismatch: expected {expected_hash}, "
                    f"got {actual_hash}"
                )
            results.append(
                {
                    "logical_partition": logical,
                    "size_bytes": actual_size,
                    "sha256": actual_hash,
                    "matches_input": True,
                }
            )

    inactive = []
    for base in EXPECTED_BASE_PARTITIONS:
        logical = f"{base}_b"
        partition = partition_by_name.get(logical)
        if not isinstance(partition, dict):
            raise BuilderError(f"Generated super is missing inactive partition {logical}")
        if int(partition.get("size_bytes", -1)) != 0:
            raise BuilderError(f"Inactive partition {logical} is unexpectedly non-empty")
        inactive.append(logical)

    return {
        "status": "verified",
        "mode": "structural_validation_only",
        "boot_ready": False,
        "flash_recommended": False,
        "avb_policy_selected": False,
        "image": str(image),
        "size_bytes": image.stat().st_size,
        "input_partitions_verified": results,
        "inactive_zero_sized_partitions": inactive,
        "metadata_matches_plan": True,
        "metadata_integrity": metadata["integrity"],
        "all_input_hashes_match": True,
    }
