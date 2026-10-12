from __future__ import annotations

import hashlib
import struct
import tempfile
import unittest
from pathlib import Path

from peridot_builder.errors import BuilderError
from peridot_builder.lp import (
    LP_GEOMETRY_MAGIC,
    LP_HEADER_MAGIC,
    inspect_super_image,
    parse_super_metadata_prefix,
)

GEOMETRY_OFFSET = 4096
METADATA_OFFSET = 12288
GEOMETRY_SIZE = 52


def seal_geometry(data: bytearray) -> None:
    start = GEOMETRY_OFFSET
    data[start + 8:start + 40] = b"\0" * 32
    digest = hashlib.sha256(data[start:start + GEOMETRY_SIZE]).digest()
    data[start + 8:start + 40] = digest


def seal_metadata(data: bytearray) -> None:
    start = METADATA_OFFSET
    header_size = struct.unpack_from("<I", data, start + 8)[0]
    tables_size = struct.unpack_from("<I", data, start + 44)[0]
    tables_start = start + header_size
    digest = hashlib.sha256(data[tables_start:tables_start + tables_size]).digest()
    data[start + 48:start + 80] = digest
    data[start + 12:start + 44] = b"\0" * 32
    digest = hashlib.sha256(data[start:start + header_size]).digest()
    data[start + 12:start + 44] = digest


def valid_prefix(minor_version: int = 2) -> bytearray:
    data = bytearray(20000)
    header_size = 256 if minor_version >= 2 else 128
    records = [
        struct.pack("<36sIIII", b"system_a", 1, 0, 1, 0),
        struct.pack("<QIQI", 100, 0, 2048, 0),
        struct.pack("<36sIQ", b"qti_dynamic_partitions_a", 1, 900000),
        struct.pack("<QIIQ36sI", 256, 1048576, 0, 9126805504, b"super", 0),
    ]
    tables = b"".join(records)
    struct.pack_into(
        "<II32sIII", data, GEOMETRY_OFFSET,
        LP_GEOMETRY_MAGIC, GEOMETRY_SIZE, b"\0" * 32, 4096, 2, 4096,
    )
    struct.pack_into(
        "<IHHI32sI32s", data, METADATA_OFFSET,
        LP_HEADER_MAGIC, 10, minor_version, header_size,
        b"\0" * 32, len(tables), b"\0" * 32,
    )
    relative_offset = 0
    for index, record in enumerate(records):
        struct.pack_into(
            "<III", data, METADATA_OFFSET + 80 + index * 12,
            relative_offset, 1, len(record),
        )
        relative_offset += len(record)
    if minor_version >= 2:
        struct.pack_into("<I", data, METADATA_OFFSET + 128, 1)
    tables_start = METADATA_OFFSET + header_size
    data[tables_start:tables_start + len(tables)] = tables
    seal_geometry(data)
    seal_metadata(data)
    return data


class LogicalPartitionMetadataTests(unittest.TestCase):
    def test_parses_checksum_verified_slot_zero_metadata(self) -> None:
        result = parse_super_metadata_prefix(bytes(valid_prefix()))
        self.assertEqual(result["geometry"]["metadata_slot_count"], 2)
        self.assertEqual(result["header"]["major_version"], 10)
        self.assertEqual(result["header"]["minor_version"], 2)
        self.assertEqual(result["header"]["header_size"], 256)
        self.assertEqual(result["header"]["flags"], 1)
        self.assertEqual(result["groups"][0]["name"], "qti_dynamic_partitions_a")
        partition = result["partitions"][0]
        self.assertEqual(partition["name"], "system_a")
        self.assertEqual(partition["size_bytes"], 100 * 512)
        self.assertEqual(partition["extents"][0]["offset_bytes"], 2048 * 512)
        self.assertEqual(partition["extents"][0]["size_bytes"], 100 * 512)
        self.assertEqual(result["block_devices"][0]["size_bytes"], 9126805504)
        self.assertTrue(result["integrity"]["geometry_checksum_verified"])
        self.assertTrue(result["integrity"]["header_checksum_verified"])
        self.assertTrue(result["integrity"]["tables_checksum_verified"])
        self.assertFalse(result["integrity"]["backup_geometry_checked"])
        self.assertFalse(result["integrity"]["other_metadata_slots_checked"])

    def test_accepts_legacy_header_sizes(self) -> None:
        for minor in (0, 1):
            with self.subTest(minor=minor):
                result = parse_super_metadata_prefix(bytes(valid_prefix(minor)))
                self.assertEqual(result["header"]["header_size"], 128)
                self.assertEqual(result["header"]["flags"], 0)

    def test_rejects_geometry_corruption(self) -> None:
        data = valid_prefix()
        data[GEOMETRY_OFFSET + 48] ^= 1
        with self.assertRaisesRegex(BuilderError, "geometry checksum mismatch"):
            parse_super_metadata_prefix(bytes(data))

    def test_rejects_extended_header_corruption(self) -> None:
        data = valid_prefix()
        data[METADATA_OFFSET + 132] ^= 1
        with self.assertRaisesRegex(BuilderError, "metadata header checksum mismatch"):
            parse_super_metadata_prefix(bytes(data))

    def test_rejects_table_corruption(self) -> None:
        data = valid_prefix()
        data[METADATA_OFFSET + 256] ^= 1
        with self.assertRaisesRegex(BuilderError, "metadata tables checksum mismatch"):
            parse_super_metadata_prefix(bytes(data))

    def test_rejects_zero_geometry_checksum(self) -> None:
        data = valid_prefix()
        data[GEOMETRY_OFFSET + 8:GEOMETRY_OFFSET + 40] = b"\0" * 32
        with self.assertRaisesRegex(BuilderError, "geometry checksum mismatch"):
            parse_super_metadata_prefix(bytes(data))

    def test_rejects_wrong_geometry_struct_size(self) -> None:
        data = valid_prefix()
        struct.pack_into("<I", data, GEOMETRY_OFFSET + 4, 53)
        seal_geometry(data)
        with self.assertRaisesRegex(BuilderError, "geometry size"):
            parse_super_metadata_prefix(bytes(data))

    def test_rejects_wrong_version_header_size(self) -> None:
        data = valid_prefix()
        struct.pack_into("<I", data, METADATA_OFFSET + 8, 128)
        with self.assertRaisesRegex(BuilderError, "header size"):
            parse_super_metadata_prefix(bytes(data))

    def test_rejects_unsupported_versions(self) -> None:
        for major, minor in ((1, 2), (10, 3), (65535, 2)):
            with self.subTest(major=major, minor=minor):
                data = valid_prefix()
                struct.pack_into("<HH", data, METADATA_OFFSET + 4, major, minor)
                seal_metadata(data)
                with self.assertRaisesRegex(BuilderError, "metadata version"):
                    parse_super_metadata_prefix(bytes(data))

    def test_rejects_tables_exceeding_metadata_slot(self) -> None:
        data = valid_prefix()
        struct.pack_into("<I", data, METADATA_OFFSET + 44, 4096)
        with self.assertRaisesRegex(BuilderError, "exceed metadata_max_size"):
            parse_super_metadata_prefix(bytes(data))

    def test_rejects_descriptor_outside_declared_tables(self) -> None:
        data = valid_prefix()
        tables_size = struct.unpack_from("<I", data, METADATA_OFFSET + 44)[0]
        struct.pack_into("<I", data, METADATA_OFFSET + 80, tables_size)
        seal_metadata(data)
        with self.assertRaisesRegex(BuilderError, "outside declared metadata tables"):
            parse_super_metadata_prefix(bytes(data))

    def test_rejects_entry_count_beyond_declared_tables(self) -> None:
        data = valid_prefix()
        struct.pack_into("<I", data, METADATA_OFFSET + 84, 4)
        seal_metadata(data)
        with self.assertRaisesRegex(BuilderError, "outside declared metadata tables"):
            parse_super_metadata_prefix(bytes(data))

    def test_rejects_truncated_tables(self) -> None:
        data = valid_prefix()
        tables_size = struct.unpack_from("<I", data, METADATA_OFFSET + 44)[0]
        del data[METADATA_OFFSET + 256 + tables_size - 1:]
        with self.assertRaisesRegex(BuilderError, "truncated"):
            parse_super_metadata_prefix(bytes(data))

    def test_inspector_checks_geometry_before_trusting_prefix_size(self) -> None:
        data = valid_prefix()
        struct.pack_into("<I", data, GEOMETRY_OFFSET + 40, 0xFFFFFE00)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "super-prefix.img"
            path.write_bytes(data)
            with self.assertRaisesRegex(BuilderError, "geometry checksum mismatch"):
                inspect_super_image(path)


if __name__ == "__main__":
    unittest.main()
