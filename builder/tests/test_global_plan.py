from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from peridot_builder.errors import BuilderError
from peridot_builder.global_plan import load_source_profile, plan_global_sources, validate_source
from peridot_builder.models import OtaInspection


class GlobalSourcePlanTests(unittest.TestCase):
    def setUp(self):
        path = Path(__file__).resolve().parents[1] / "devices/peridot/sources/global-pudding-4.0.0.9-peridot-3.0.303.json"
        self.profile = json.loads(path.read_text())
        self.profile["stock"]["sha256"] = "a" * 64
        self.inspections = []
        self.manifests = []
        group = ["vendor", "odm", "vendor_dlkm", "system_dlkm", "system", "system_ext", "product", "mi_ext"]
        for role in ("stock", "donor"):
            source = self.profile[role]
            self.inspections.append(OtaInspection(
                path=role + ".zip", size_bytes=source["size_bytes"], sha256=source["sha256"],
                is_zip=True, has_payload=True, payload_entry="payload.bin", payload_size_bytes=1,
                metadata=copy.deepcopy(source["metadata"]), device_candidates=[source["codename"]]))
            self.manifests.append({"manifest_sha256": source["manifest_sha256"], "full_payload": True,
                "partitions": [{"partition": name, "size_bytes": 4096, "sha256": "b" * 64}
                               for name in [*group, "boot", "vbmeta"]],
                "dynamic_groups": [{"name": "qti_dynamic_partitions", "maximum_size_bytes": 65536,
                                    "partitions": group}]})

    def plan(self):
        return plan_global_sources(*self.inspections, *self.manifests, self.profile)

    def test_exact_global_plan_preserves_hardware_and_separate_release_gates(self):
        result = self.plan()
        source_map = {row["partition"]: row["source"] for row in result["logical_inputs"]}
        self.assertEqual(source_map["odm"], "stock")
        self.assertEqual(source_map["product"], "donor")
        self.assertEqual(result["budget"]["source_logical_image_bytes"], 32768)
        self.assertEqual(result["budget"]["raw_group_headroom_bytes"], 32768)
        self.assertFalse(result["boot_ready"])
        self.assertFalse(result["budget"]["physical_super_geometry_verified"])

    def test_extra_donor_dynamic_partition_is_exposed_as_a_gate(self):
        self.manifests[1]["dynamic_groups"] = copy.deepcopy(self.manifests[1]["dynamic_groups"])
        self.manifests[1]["dynamic_groups"][0]["partitions"].append("mi_product")
        self.manifests[1]["partitions"].append({"partition": "mi_product", "size_bytes": 4096, "sha256": "c" * 64})
        result = self.plan()
        self.assertEqual(result["extra_donor_dynamic_partitions_requiring_review"][0]["partition"], "mi_product")
        self.assertEqual(result["release_gates"]["extra_donor_dynamic_partition_consumers"], "pending")

    def test_wrong_archive_hash_is_rejected(self):
        self.inspections[0].sha256 = "c" * 64
        with self.assertRaisesRegex(BuilderError, "archive identity"):
            self.plan()

    def test_china_metadata_cannot_satisfy_global_source(self):
        self.inspections[0].metadata["post-build"] = "Redmi/peridot/peridot:16/example"
        with self.assertRaisesRegex(BuilderError, "post-build"):
            self.plan()

    def test_missing_metadata_does_not_silently_pass(self):
        self.inspections[1].metadata.pop("post-build")
        with self.assertRaises(BuilderError):
            self.plan()

    def test_wrong_manifest_hash_is_rejected(self):
        self.manifests[1]["manifest_sha256"] = "c" * 64
        with self.assertRaisesRegex(BuilderError, "manifest hash"):
            self.plan()

    def test_missing_stock_hardware_is_rejected(self):
        self.manifests[0]["partitions"] = [row for row in self.manifests[0]["partitions"]
                                             if row["partition"] != "vendor_dlkm"]
        with self.assertRaisesRegex(BuilderError, "incomplete"):
            self.plan()

    def test_measured_group_overflow_is_reported_without_false_readiness(self):
        self.manifests[0]["dynamic_groups"][0]["maximum_size_bytes"] = 16384
        result = self.plan()
        self.assertFalse(result["budget"]["source_images_fit_group"])
        self.assertEqual(result["budget"]["raw_group_headroom_bytes"], -16384)
        self.assertFalse(result["flash_recommended"])

    def test_profile_rejects_missing_hash_china_build_and_security_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "source.json"
            path.write_text(json.dumps(self.profile))
            self.assertEqual(load_source_profile(path)["id"], self.profile["id"])
            for key, value in (("sha256", None), ("build", "OS3.0.305.0.WNPCNXM")):
                changed = copy.deepcopy(self.profile)
                changed["stock"][key] = value
                path.write_text(json.dumps(changed))
                with self.assertRaises(BuilderError):
                    load_source_profile(path)
            changed = copy.deepcopy(self.profile)
            changed["security"]["disable_avb"] = True
            path.write_text(json.dumps(changed))
            with self.assertRaises(BuilderError):
                load_source_profile(path)


if __name__ == "__main__":
    unittest.main()
