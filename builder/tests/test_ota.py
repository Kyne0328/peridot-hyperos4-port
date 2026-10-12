from __future__ import annotations

import tempfile
import unittest
import zipfile
from pathlib import Path

from peridot_builder.ota import inspect_ota, parse_key_value_text


class OtaInspectionTests(unittest.TestCase):
    def test_parse_key_value_text(self) -> None:
        parsed = parse_key_value_text("a=1\n#comment\nb=two=parts\n")
        self.assertEqual(parsed, {"a": "1", "b": "two=parts"})

    def test_inspect_minimal_ab_ota(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "stock.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr(
                    "META-INF/com/android/metadata",
                    "ota-type=AB\npre-device=peridot\npost-sdk-level=35\n",
                )
                archive.writestr("payload_properties.txt", "FILE_SIZE=123\n")
                archive.writestr("payload.bin", b"payload-placeholder")

            inspection = inspect_ota(path)

        self.assertTrue(inspection.has_payload)
        self.assertEqual(inspection.device_candidates, ["peridot"])
        self.assertEqual(inspection.metadata["ota-type"], "AB")
        self.assertEqual(inspection.payload_properties["FILE_SIZE"], "123")
        self.assertEqual(len(inspection.sha256), 64)


if __name__ == "__main__":
    unittest.main()
