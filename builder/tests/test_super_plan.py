from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from peridot_builder.super_plan import (
    EXPECTED_BASE_PARTITIONS,
    build_structural_super_plan,
)


class StructuralSuperPlanTests(unittest.TestCase):
    def test_builds_virtual_ab_lpmake_plan_and_marks_it_non_boot_ready(self) -> None:
        reference = {
            "geometry": {
                "metadata_max_size": 65536,
                "metadata_slot_count": 3,
                "logical_block_size": 4096,
            },
            "header": {"flags": 1},
            "groups": [
                {"name": "default", "maximum_size": 0},
                {"name": "qti_dynamic_partitions_a", "maximum_size": 10000000},
                {"name": "qti_dynamic_partitions_b", "maximum_size": 10000000},
            ],
            "block_devices": [
                {
                    "name": "super",
                    "first_logical_sector": 2048,
                    "alignment": 1048576,
                    "alignment_offset": 0,
                    "size_bytes": 10000000,
                }
            ],
            "partitions": [
                *[{"name": f"{name}_a"} for name in EXPECTED_BASE_PARTITIONS],
                *[{"name": f"{name}_b"} for name in EXPECTED_BASE_PARTITIONS],
            ],
        }

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            images = {}
            for name in EXPECTED_BASE_PARTITIONS:
                path = root / f"{name}.img"
                path.write_bytes(name.encode("ascii"))
                images[name] = path

            plan = build_structural_super_plan(
                reference,
                images,
                root / "super-structural.img",
            )

        self.assertFalse(plan["boot_ready"])
        self.assertFalse(plan["flash_recommended"])
        self.assertTrue(plan["fits_raw_layout"])
        self.assertIn("--virtual-ab", plan["lpmake_args"])
        self.assertIn(
            "product_b:none:0:qti_dynamic_partitions_b",
            plan["lpmake_args"],
        )
        product = next(
            item for item in plan["inputs"] if item["partition"] == "product"
        )
        self.assertEqual(product["logical_partition"], "product_a")


if __name__ == "__main__":
    unittest.main()
