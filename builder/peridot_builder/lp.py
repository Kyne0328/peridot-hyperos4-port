from __future__ import annotations

import hashlib
import struct
import zipfile
from pathlib import Path
from typing import Any

from .errors import BuilderError


LP_GEOMETRY_MAGIC = 0x616C4467
LP_HEADER_MAGIC = 0x414C5030
LP_RESERVED_BYTES = 4096
LP_GEOMETRY_SIZE = 4096
LP_SECTOR_SIZE = 512

_GEOMETRY = struct.Struct("<II32sIII")
_HEADER = struct.Struct("<IHHI32sI32s")
_TABLE = struct.Struct("<III")
_PARTITION = struct.Struct("<36sIIII")
_EXTENT = struct.Struct("<QIQI")
_GROUP = struct.Struct("<36sIQ")
_BLOCK_DEVICE = struct.Struct("<QIIQ36sI")


def _name(raw: bytes) -> str:
    return raw.split(b"\0", 1)[0].decode("utf-8", errors="replace")


def _table_descriptor(data: bytes, offset: int) -> tuple[int, int, int]:
    return _TABLE.unpack_from(data, offset)


def _require(data: bytes, end: int, label: str) -> None:
    if len(data) < end:
        raise BuilderError(
            f"Super metadata prefix is truncated while reading {label}: "
            f"need {end} bytes, have {len(data)}"
        )


def _verify_checksum(
    raw: bytes,
    expected: bytes,
    label: str,
    checksum_offset: int | None = None,
) -> None:
    checked = bytearray(raw)
    if checksum_offset is not None:
        checked[checksum_offset:checksum_offset + 32] = b"\0" * 32
    if hashlib.sha256(checked).digest() != expected:
        raise BuilderError(f"Super {label} checksum mismatch")


def _validated_geometry(data: bytes) -> tuple[int, int, int, int]:
    geometry_offset = LP_RESERVED_BYTES
    _require(data, geometry_offset + _GEOMETRY.size, "geometry")
    (
        geometry_magic,
        geometry_struct_size,
        geometry_checksum,
        metadata_max_size,
        metadata_slot_count,
        logical_block_size,
    ) = _GEOMETRY.unpack_from(data, geometry_offset)
    if geometry_magic != LP_GEOMETRY_MAGIC:
        raise BuilderError(
            f"Invalid super geometry magic 0x{geometry_magic:08x}; "
            f"expected 0x{LP_GEOMETRY_MAGIC:08x}"
        )
    if geometry_struct_size != _GEOMETRY.size:
        raise BuilderError(
            f"Unsupported super geometry size: {geometry_struct_size}; "
            f"expected {_GEOMETRY.size}"
        )
    _verify_checksum(
        data[geometry_offset:geometry_offset + geometry_struct_size],
        geometry_checksum, "geometry", checksum_offset=8,
    )
    if metadata_slot_count <= 0:
        raise BuilderError("Super metadata reports zero metadata slots")
    if metadata_max_size <= 0 or metadata_max_size % LP_SECTOR_SIZE != 0:
        raise BuilderError(f"Invalid super metadata_max_size: {metadata_max_size}")
    return (
        geometry_struct_size, metadata_max_size,
        metadata_slot_count, logical_block_size,
    )


def parse_super_metadata_prefix(data: bytes) -> dict[str, Any]:
    (
        geometry_struct_size, metadata_max_size,
        metadata_slot_count, logical_block_size,
    ) = _validated_geometry(data)

    metadata_offset = LP_RESERVED_BYTES + (LP_GEOMETRY_SIZE * 2)
    _require(data, metadata_offset + 128, "metadata header")
    (
        header_magic,
        major_version,
        minor_version,
        header_size,
        header_checksum,
        tables_size,
        tables_checksum,
    ) = _HEADER.unpack_from(data, metadata_offset)

    if header_magic != LP_HEADER_MAGIC:
        raise BuilderError(
            f"Invalid logical-partition header magic 0x{header_magic:08x}; "
            f"expected 0x{LP_HEADER_MAGIC:08x}"
        )
    if major_version != 10 or minor_version not in (0, 1, 2):
        raise BuilderError(
            f"Unsupported LP metadata version: {major_version}.{minor_version}"
        )
    expected_header_size = 256 if minor_version >= 2 else 128
    if header_size != expected_header_size:
        raise BuilderError(
            f"Unsupported LP metadata header size: {header_size}; "
            f"expected {expected_header_size} for {major_version}.{minor_version}"
        )
    if header_size > metadata_max_size or tables_size > metadata_max_size - header_size:
        raise BuilderError("Super header and tables exceed metadata_max_size")
    _require(data, metadata_offset + header_size, "metadata header")
    _verify_checksum(
        data[metadata_offset:metadata_offset + header_size],
        header_checksum, "metadata header", checksum_offset=12,
    )
    tables_offset = metadata_offset + header_size
    _require(data, tables_offset + tables_size, "metadata tables")
    _verify_checksum(
        data[tables_offset:tables_offset + tables_size],
        tables_checksum, "metadata tables",
    )
    descriptors_offset = metadata_offset + _HEADER.size
    partition_desc = _table_descriptor(data, descriptors_offset)
    extent_desc = _table_descriptor(data, descriptors_offset + _TABLE.size)
    group_desc = _table_descriptor(data, descriptors_offset + (_TABLE.size * 2))
    block_desc = _table_descriptor(data, descriptors_offset + (_TABLE.size * 3))

    def rows(
        descriptor: tuple[int, int, int],
        expected_size: int,
        label: str,
    ) -> list[bytes]:
        relative_offset, count, entry_size = descriptor
        if entry_size < expected_size:
            raise BuilderError(
                f"{label} entry size {entry_size} is smaller than expected {expected_size}"
            )
        if (
            relative_offset > tables_size
            or count > (tables_size - relative_offset) // entry_size
        ):
            raise BuilderError(
                f"{label} table lies outside declared metadata tables"
            )
        result: list[bytes] = []
        for index in range(count):
            start = tables_offset + relative_offset + (index * entry_size)
            end = start + entry_size
            _require(data, end, f"{label} table")
            result.append(data[start:end])
        return result

    extent_rows = rows(extent_desc, _EXTENT.size, "extent")
    extents = []
    for raw in extent_rows:
        num_sectors, target_type, target_data, target_source = _EXTENT.unpack_from(raw)
        extents.append(
            {
                "num_sectors": num_sectors,
                "target_type": target_type,
                "target_data": target_data,
                "target_source": target_source,
            }
        )

    group_rows = rows(group_desc, _GROUP.size, "group")
    groups = []
    for raw in group_rows:
        raw_name, flags, maximum_size = _GROUP.unpack_from(raw)
        groups.append(
            {
                "name": _name(raw_name),
                "flags": flags,
                "maximum_size": maximum_size,
            }
        )

    partition_rows = rows(partition_desc, _PARTITION.size, "partition")
    partitions = []
    for raw in partition_rows:
        (
            raw_name,
            attributes,
            first_extent_index,
            num_extents,
            group_index,
        ) = _PARTITION.unpack_from(raw)
        if first_extent_index + num_extents > len(extents):
            raise BuilderError(
                f"Partition {_name(raw_name)} references extents outside the table"
            )
        size_bytes = sum(
            extents[index]["num_sectors"] * LP_SECTOR_SIZE
            for index in range(first_extent_index, first_extent_index + num_extents)
        )
        group_name = (
            groups[group_index]["name"] if group_index < len(groups) else None
        )
        partition_extents = []
        for index in range(first_extent_index, first_extent_index + num_extents):
            extent = extents[index]
            partition_extents.append(
                {
                    **extent,
                    "offset_bytes": extent["target_data"] * LP_SECTOR_SIZE,
                    "size_bytes": extent["num_sectors"] * LP_SECTOR_SIZE,
                }
            )
        partitions.append(
            {
                "name": _name(raw_name),
                "attributes": attributes,
                "group_index": group_index,
                "group_name": group_name,
                "first_extent_index": first_extent_index,
                "num_extents": num_extents,
                "size_bytes": size_bytes,
                "extents": partition_extents,
            }
        )

    block_rows = rows(block_desc, _BLOCK_DEVICE.size, "block device")
    block_devices = []
    for raw in block_rows:
        (
            first_logical_sector,
            alignment,
            alignment_offset,
            block_device_size,
            raw_name,
            flags,
        ) = _BLOCK_DEVICE.unpack_from(raw)
        block_devices.append(
            {
                "name": _name(raw_name),
                "first_logical_sector": first_logical_sector,
                "alignment": alignment,
                "alignment_offset": alignment_offset,
                "size_bytes": block_device_size,
                "flags": flags,
            }
        )

    header_flags = 0
    if header_size >= 132:
        _require(data, metadata_offset + 132, "metadata header flags")
        header_flags = struct.unpack_from("<I", data, metadata_offset + 128)[0]

    return {
        "integrity": {
            "geometry_checksum_verified": True,
            "header_checksum_verified": True,
            "tables_checksum_verified": True,
            "metadata_slot": 0,
            "backup_geometry_checked": False,
            "other_metadata_slots_checked": False,
        },
        "geometry": {
            "struct_size": geometry_struct_size,
            "metadata_max_size": metadata_max_size,
            "metadata_slot_count": metadata_slot_count,
            "logical_block_size": logical_block_size,
        },
        "header": {
            "major_version": major_version,
            "minor_version": minor_version,
            "header_size": header_size,
            "tables_size": tables_size,
            "flags": header_flags,
        },
        "groups": groups,
        "block_devices": block_devices,
        "partitions": partitions,
    }


def _required_prefix_size(initial: bytes) -> int:
    _, metadata_max_size, _, _ = _validated_geometry(initial)
    required = LP_RESERVED_BYTES + (LP_GEOMETRY_SIZE * 2) + metadata_max_size
    if required > 16 * 1024 * 1024:
        raise BuilderError(
            f"Refusing unexpectedly large metadata prefix: {required} bytes"
        )
    return required


def inspect_super_image(path: Path) -> dict[str, Any]:
    path = path.resolve()
    with path.open("rb") as stream:
        initial = stream.read(LP_RESERVED_BYTES + LP_GEOMETRY_SIZE)
        required = _required_prefix_size(initial)
        prefix = initial + stream.read(max(0, required - len(initial)))

    result = parse_super_metadata_prefix(prefix)
    result.update(
        {
            "path": str(path),
            "super_size_bytes": path.stat().st_size,
            "prefix_bytes_read": len(prefix),
        }
    )
    return result


def inspect_super_zip(
    zip_path: Path,
    entry_name: str = "images/super.img",
) -> dict[str, Any]:
    zip_path = zip_path.resolve()
    with zipfile.ZipFile(zip_path) as archive:
        try:
            info = archive.getinfo(entry_name)
        except KeyError as error:
            raise BuilderError(
                f"Super image entry {entry_name!r} was not found in {zip_path}"
            ) from error

        with archive.open(info) as stream:
            initial = stream.read(LP_RESERVED_BYTES + LP_GEOMETRY_SIZE)
            required = _required_prefix_size(initial)
            remainder = stream.read(max(0, required - len(initial)))
            prefix = initial + remainder

    result = parse_super_metadata_prefix(prefix)
    result.update(
        {
            "zip_path": str(zip_path),
            "entry_name": entry_name,
            "super_size_bytes": info.file_size,
            "compressed_size_bytes": info.compress_size,
            "prefix_bytes_read": len(prefix),
        }
    )
    return result
