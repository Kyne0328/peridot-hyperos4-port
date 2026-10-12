from __future__ import annotations

import ast
import importlib.util
import unittest
from pathlib import Path
import xml.etree.ElementTree as ET

SCRIPT = Path(__file__).resolve().parents[2] / "tools/global-build/convert_thermal_review.py"
SPEC = importlib.util.spec_from_file_location("global_thermal_converter", SCRIPT)
converter = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(converter)


def curve(low="37", high="39", nit="700"):
    return ("<temperature-brightness-pair><min-inclusive>" + low +
            "</min-inclusive><max-exclusive>" + high + "</max-exclusive><nit>" +
            nit + "</nit></temperature-brightness-pair>")


class GlobalThermalConversionTests(unittest.TestCase):
    def test_duplicate_condition_identifiers_are_rejected(self):
        node = "<thermal-condition-item><identifier>0</identifier><description>Default</description></thermal-condition-item>"
        with self.assertRaisesRegex(ValueError, "duplicate"):
            converter.conditions(ET.fromstring("<thermal-brightness-config>" + node * 2 + "</thermal-brightness-config>"))

    def test_missing_description_and_wrong_root_are_rejected(self):
        for text in ("<wrong/>", "<thermal-brightness-config><thermal-condition-item><identifier>0</identifier></thermal-condition-item></thermal-brightness-config>"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                converter.conditions(ET.fromstring(text))

    def test_nonfinite_empty_gapped_and_reversed_curves_are_rejected(self):
        for text in ("", curve(nit="NaN"), curve(low="39", high="37"),
                     curve() + curve(low="40", high="41")):
            with self.subTest(text=text), self.assertRaises(ValueError):
                converter.triples(ET.fromstring("<condition>" + text + "</condition>"))

    def test_single_lux_bucket_retains_high_lux_fallback_and_reports_invalid_domain(self):
        node = ET.fromstring("<condition><lux-temperature-pair><min-inclusive>0</min-inclusive><max-exclusive>2000000</max-exclusive>" + curve() + "</lux-temperature-pair></condition>")
        for lux in (0, 1, 1000, 1999999, 2000000, 2000001, 3.4e38):
            selected = converter.select_lux(node, lux)
            self.assertIsNotNone(selected)
            self.assertEqual(converter.triples(selected), [("37", "39", "700")])
        self.assertIsNone(converter.select_lux(node, -1))
        self.assertIsNone(converter.select_lux(node, float("nan")))

    def test_temperature_intervals_are_min_inclusive_max_exclusive(self):
        values = [("37", "39", "700"), ("39", "41", "500")]
        self.assertIsNone(converter.select_temp(values, 36.999))
        self.assertEqual(converter.select_temp(values, 37), 700)
        self.assertEqual(converter.select_temp(values, 39), 500)
        self.assertIsNone(converter.select_temp(values, 41))

    def test_optimized_python_cannot_remove_source_guards(self):
        self.assertFalse(any(isinstance(node, ast.Assert) for node in ast.walk(ast.parse(SCRIPT.read_text()))))


if __name__ == "__main__":
    unittest.main()
