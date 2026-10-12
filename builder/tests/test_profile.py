from __future__ import annotations

import unittest

from peridot_builder.models import OtaInspection, PartitionInfo
from peridot_builder.profile import build_device_profile


class ProfileTests(unittest.TestCase):
    def test_profile_separates_reference_dynamic_partitions(self) -> None:
        inspection = OtaInspection(
            path="stock.zip",
            size_bytes=100,
            sha256="a" * 64,
            is_zip=True,
            has_payload=True,
            payload_entry="payload.bin",
            payload_size_bytes=50,
            metadata={"pre-device": "peridot"},
            device_candidates=["peridot"],
            partitions=[
                PartitionInfo("boot", 100),
                PartitionInfo("system", 200),
                PartitionInfo("vendor", 300),
            ],
        )
        reference = {
            "device": {"codename": "peridot"},
            "hints": {
                "dynamic_partitions": ["system", "vendor"],
                "physical_partition_sizes": {"boot": 100},
                "super_size_bytes": 999,
            },
            "sources": [],
        }

        profile = build_device_profile(inspection, reference)

        self.assertTrue(
            profile["verification"]["codename_matches_stock_metadata"]
        )
        self.assertEqual(
            profile["partition_inventory"]["dynamic_partitions"],
            ["system", "vendor"],
        )
        self.assertEqual(
            profile["partition_inventory"]["firmware_partitions"],
            ["boot"],
        )
        self.assertFalse(profile["verification"]["super_layout_verified"])


if __name__ == "__main__":
    unittest.main()
