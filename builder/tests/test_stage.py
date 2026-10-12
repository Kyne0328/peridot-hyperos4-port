from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from peridot_builder.models import OtaInspection, PartitionInfo
from peridot_builder.ownership import build_ownership_plan
from peridot_builder.stage import stage_inputs


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
        partitions=[PartitionInfo(name, 16) for name in names],
    )


class FakeDumper:
    def extract(self, rom: Path, output_dir: Path, partitions: list[str] | None) -> None:
        output_dir.mkdir(parents=True, exist_ok=True)
        assert partitions is not None
        for name in partitions:
            (output_dir / f"{name}.img").write_bytes((rom.name + ':' + name).encode())


class StageTests(unittest.TestCase):
    def test_stage_separates_and_hashes_inputs(self) -> None:
        stock = inspection(
            "peridot",
            ["boot", "init_boot", "vendor_boot", "dtbo", "vendor", "odm", "vendor_dlkm", "system_dlkm", "modem", "dsp", "system", "product", "vbmeta"],
        )
        donor = inspection(
            "madrid",
            ["boot", "vendor", "odm", "system", "system_ext", "product", "mi_ext", "modem"],
        )
        plan = build_ownership_plan(stock, donor, expected_donor="madrid")

        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "stage"
            manifest = stage_inputs(FakeDumper(), stock, donor, plan, output)

            target_names = {item["name"] for item in manifest["stock"]["images"]}
            donor_names = {item["name"] for item in manifest["donor"]["images"]}
            self.assertIn("vendor.img", target_names)
            self.assertIn("modem.img", target_names)
            self.assertIn("dsp.img", target_names)
            self.assertNotIn("system.img", target_names)
            self.assertIn("system.img", donor_names)
            self.assertNotIn("vendor.img", donor_names)
            self.assertNotIn("modem.img", donor_names)
            self.assertTrue((output / "stage-manifest.json").is_file())
            self.assertTrue(all(len(item["sha256"]) == 64 for item in manifest["donor"]["images"]))


if __name__ == "__main__":
    unittest.main()
