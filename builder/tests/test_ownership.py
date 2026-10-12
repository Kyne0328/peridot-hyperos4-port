from __future__ import annotations

import unittest

from peridot_builder.models import OtaInspection, PartitionInfo
from peridot_builder.ownership import build_ownership_plan


def inspection(device: str, names: list[str]) -> OtaInspection:
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
        partitions=[PartitionInfo(name, 1024) for name in names],
    )


class OwnershipTests(unittest.TestCase):
    def test_peridot_hardware_and_donor_userspace_are_separated(self) -> None:
        stock = inspection(
            "peridot",
            ["boot", "init_boot", "vendor_boot", "dtbo", "vendor", "odm", "vendor_dlkm", "system_dlkm", "modem", "dsp", "xbl", "system", "product", "vbmeta"],
        )
        donor = inspection(
            "madrid",
            ["boot", "vendor", "odm", "system", "system_ext", "product", "mi_ext", "modem"],
        )

        plan = build_ownership_plan(stock, donor, expected_donor="madrid")

        self.assertIn("vendor", plan["stock"]["preserve"])
        self.assertIn("modem", plan["stock"]["preserve"])
        self.assertIn("dsp", plan["stock"]["take_firmware"])
        self.assertNotIn("system", plan["stock"]["preserve"])
        self.assertEqual(
            plan["donor"]["take_userspace"],
            ["system", "system_ext", "product", "mi_ext"],
        )
        self.assertIn("vendor", plan["donor"]["explicitly_do_not_take"])
        self.assertIn("vbmeta", plan["stock"]["avb_metadata_deferred"])


if __name__ == "__main__":
    unittest.main()
