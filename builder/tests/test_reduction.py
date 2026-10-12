from __future__ import annotations

import json
import unittest
from pathlib import Path

from peridot_builder.errors import BuilderError
from peridot_builder.reduction import validate_reduction_plan


class ProductReductionPlanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.builder_root = Path(__file__).resolve().parents[1]
        self.plan_path = (
            self.builder_root
            / "devices"
            / "peridot"
            / "composition"
            / "madrid-4.0.11-product-reduction-candidates.json"
        )

    def test_reviewed_plan_meets_budget_and_preserves_an_ime(self) -> None:
        plan = json.loads(self.plan_path.read_text(encoding="utf-8"))
        summary = validate_reduction_plan(plan)

        self.assertEqual(summary["approved_reduction_bytes"], 1243141208)
        self.assertEqual(summary["projected_headroom_bytes"], 297268312)
        self.assertTrue(summary["meets_headroom_target"])
        self.assertTrue(summary["dependencies_reviewed"])
        self.assertIn(
            {"root": "/app/SogouIME", "package": "com.sohu.inputmethod.sogou.xiaomi"},
            summary["retained_input_methods"],
        )
        self.assertNotIn("/app/SogouIME", summary["approved_roots"])
        self.assertIn("/data-app/BaiduIME", summary["approved_roots"])
        self.assertIn("/data-app/iFlytekIME", summary["approved_roots"])

    def test_plan_without_retained_ime_is_rejected(self) -> None:
        plan = json.loads(self.plan_path.read_text(encoding="utf-8"))
        for item in plan["candidates"]:
            if item["root"] == "/app/SogouIME":
                item["decision"] = "approved_remove"
                item["dependencies_reviewed"] = True
                item["regression_tests"] = ["test"]

        with self.assertRaises(BuilderError):
            validate_reduction_plan(plan)


if __name__ == "__main__":
    unittest.main()
