from __future__ import annotations

import json
import unittest
from pathlib import Path

from peridot_builder.reduction import validate_reduction_plan


class CompositionDataTests(unittest.TestCase):
    def setUp(self) -> None:
        self.builder_root = Path(__file__).resolve().parents[1]
        self.composition_dir = (
            self.builder_root / "devices" / "peridot" / "composition"
        )

    def test_product_reduction_plan_clears_budget_with_headroom(self) -> None:
        plan = json.loads(
            (
                self.composition_dir
                / "madrid-4.0.11-product-reduction-candidates.json"
            ).read_text(encoding="utf-8")
        )
        summary = validate_reduction_plan(plan)
        self.assertTrue(summary["meets_minimum"])
        self.assertTrue(summary["meets_headroom_target"])
        self.assertGreaterEqual(
            summary["approved_reduction_bytes"],
            plan["target_reduction_bytes"],
        )

    def test_clean_blueprint_preserves_security_baseline(self) -> None:
        blueprint = json.loads(
            (
                self.composition_dir / "madrid-4.0.11-clean-v0.json"
            ).read_text(encoding="utf-8")
        )
        security = blueprint["security_policy"]
        self.assertEqual(
            security["userdata_encryption"],
            "preserve_stock_fbe_and_metadata_encryption",
        )
        self.assertEqual(
            security["privileged_permission_enforcement"],
            "preserve_stock_enforcement",
        )
        self.assertFalse(security["fake_locked_properties"])
        self.assertIn("userdata decryption", blueprint["explicitly_excluded"])
        self.assertIn("blanket AVB removal", blueprint["explicitly_excluded"])
        gate = blueprint["acceptance_gate_before_super_rebuild"]
        self.assertTrue(gate["dependencies_reviewed"])
        self.assertEqual(
            gate["retained_normal_input_method"],
            "com.sohu.inputmethod.sogou.xiaomi",
        )


if __name__ == "__main__":
    unittest.main()
