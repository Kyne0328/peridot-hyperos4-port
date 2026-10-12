from __future__ import annotations

import unittest

from peridot_builder.composition import build_super_budget
from peridot_builder.models import OtaInspection, PartitionInfo
from peridot_builder.ownership import build_ownership_plan


def inspection(device: str, sizes: dict[str, int]) -> OtaInspection:
    return OtaInspection(
        path=f"{device}.zip",
        size_bytes=1,
        sha256=device[0] * 64,
        is_zip=True,
        has_payload=True,
        payload_entry="payload.bin",
        payload_size_bytes=1,
        metadata={"pre-device": device},
        device_candidates=[device],
        partitions=[PartitionInfo(name, size) for name, size in sizes.items()],
    )


class SuperBudgetTests(unittest.TestCase):
    def test_budget_counts_only_super_partitions(self) -> None:
        stock = inspection(
            "peridot",
            {
                "boot": 50,
                "vendor": 100,
                "odm": 200,
                "vendor_dlkm": 30,
                "system_dlkm": 20,
                "modem": 500,
                "vbmeta": 4,
            },
        )
        donor = inspection(
            "madrid",
            {
                "system": 400,
                "system_ext": 100,
                "product": 300,
                "mi_ext": 50,
                "boot": 999,
                "vendor": 999,
            },
        )
        plan = build_ownership_plan(stock, donor, expected_donor="madrid")

        budget = build_super_budget(stock, donor, plan, super_size_bytes=1000)

        self.assertEqual(budget["target_dynamic_hardware_bytes"], 350)
        self.assertEqual(budget["donor_userspace_bytes"], 850)
        self.assertEqual(budget["composed_bytes"], 1200)
        self.assertEqual(budget["excess_bytes"], 200)
        self.assertEqual(budget["minimum_reduction_bytes"], 200)
        self.assertFalse(budget["fits_without_reduction"])


if __name__ == "__main__":
    unittest.main()
