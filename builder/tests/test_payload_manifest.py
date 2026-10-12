from __future__ import annotations

import hashlib
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path

from peridot_builder.errors import BuilderError
from peridot_builder.payload_manifest import _name, inspect_payload_manifest, parse_manifest


def varint(value):
    result = bytearray()
    while value >= 128:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


def integer(number, value):
    return varint(number << 3) + varint(value)


def message(number, value):
    if isinstance(value, str):
        value = value.encode()
    return varint(number << 3 | 2) + varint(len(value)) + value


def fixture(*, duplicate=False, old=False, block=4096, delta=0, bad_hash=False):
    info = integer(1, 4096) + message(2, b"h" * (31 if bad_hash else 32))
    part = message(1, "system") + message(7, info)
    if old:
        part += message(6, info)
    group = message(1, "qti_dynamic_partitions") + integer(2, 8192) + message(3, "system")
    return (integer(3, block) + integer(12, delta) + message(13, part) +
            (message(13, part) if duplicate else b"") +
            message(15, message(1, group) + integer(2, 1)))


class PayloadManifestTests(unittest.TestCase):
    def test_hyphenated_real_partition_name_is_supported(self):
        self.assertEqual(_name(b"vm-bootsys"), "vm-bootsys")
        for value in (b"../system", b"system/evil", b".", b"system\x00"):
            with self.assertRaises(BuilderError):
                _name(value)

    def test_partition_hash_group_limit_and_geometry_scope(self):
        raw = fixture()
        result = parse_manifest(raw)
        self.assertEqual(result["manifest_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(result["partitions"][0]["sha256"], (b"h" * 32).hex())
        self.assertEqual(result["dynamic_groups"][0]["maximum_size_bytes"], 8192)
        self.assertFalse(result["physical_super_geometry_verified"])

    def test_rejects_delta_old_input_bad_block_hash_and_duplicates(self):
        for kwargs in ({"duplicate": True}, {"old": True}, {"delta": 1},
                       {"block": 1024}, {"bad_hash": True}):
            with self.subTest(kwargs=kwargs), self.assertRaises(BuilderError):
                parse_manifest(fixture(**kwargs))

    def test_rejects_truncation_and_invalid_wire_encoding(self):
        for raw in (b"", fixture()[:-1], b"\x80", b"\x0f", b"\x00", b"\x80\x00"):
            with self.subTest(raw=raw), self.assertRaises(BuilderError):
                parse_manifest(raw)

    def test_reads_zip_without_extracting_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rom.zip"
            raw = fixture()
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("payload.bin", struct.pack(">4sQQI", b"CrAU", 2, len(raw), 0) + raw)
            result = inspect_payload_manifest(path)
            self.assertEqual(result["payload_metadata_size_bytes"], 24 + len(raw))
            self.assertEqual(len(list(Path(tmp).iterdir())), 1)

    def test_rejects_wrong_payload_header_and_declared_size(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rom.zip"
            for header in (b"short", struct.pack(">4sQQI", b"CrAU", 3, 1, 0),
                           struct.pack(">4sQQI", b"CrAU", 2, 2**32, 0)):
                with zipfile.ZipFile(path, "w") as archive:
                    archive.writestr("payload.bin", header)
                with self.assertRaises(BuilderError):
                    inspect_payload_manifest(path)


if __name__ == "__main__":
    unittest.main()
