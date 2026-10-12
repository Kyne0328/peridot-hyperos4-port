from __future__ import annotations

import unittest
from unittest.mock import patch

from peridot_builder.tools import _candidate_names, parse_payload_dumper_list


class PayloadDumperParserTests(unittest.TestCase):
    def test_machine_readable_partition_list(self) -> None:
        partitions = parse_payload_dumper_list(
            "boot:98304\nsystem:1048576\nproduct:2048\nnoise line\n"
        )
        self.assertEqual(
            [item.name for item in partitions],
            ["boot", "system", "product"],
        )
        self.assertEqual(partitions[0].size_bytes, 98304 * 1024)

    def test_python_tool_candidate_is_discoverable(self) -> None:
        self.assertIn("avbtool.py", _candidate_names("avbtool"))

    def test_dotted_tool_name_is_not_treated_as_a_file_extension(self) -> None:
        with patch("peridot_builder.tools.os.name", "nt"):
            candidates = _candidate_names("mkfs.erofs")
        self.assertIn("mkfs.erofs.exe", candidates)


if __name__ == "__main__":
    unittest.main()
