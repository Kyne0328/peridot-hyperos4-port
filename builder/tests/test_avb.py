from __future__ import annotations

import unittest

from peridot_builder.avb import parse_avb_info


class AvbInfoParserTests(unittest.TestCase):
    def test_parses_header_chain_and_hashtree(self) -> None:
        parsed = parse_avb_info(
            """Minimum libavb version:   1.0
Public key (sha1):        abc123
Algorithm:                SHA256_RSA2048
Flags:                    1
Descriptors:
    Chain Partition descriptor:
      Partition Name:          vbmeta_system
      Rollback Index Location: 2
      Public key (sha1):       abc123
      Flags:                   0
    Prop: com.android.build.product.os_version -> '16'
    Hashtree descriptor:
      Image Size:            4317581312 bytes
      Hash Algorithm:        sha256
      Partition Name:        product
      Root Digest:           deadbeef
      Flags:                 0
"""
        )

        self.assertEqual(parsed["header"]["public_key_sha1"], "abc123")
        self.assertEqual(parsed["header"]["flags"], 1)
        self.assertEqual(parsed["descriptors"][0]["type"], "chain_partition")
        self.assertEqual(
            parsed["descriptors"][0]["partition_name"],
            "vbmeta_system",
        )
        self.assertEqual(parsed["descriptors"][1]["type"], "property")
        self.assertEqual(parsed["descriptors"][1]["value"], "16")
        self.assertEqual(parsed["descriptors"][2]["type"], "hashtree")
        self.assertEqual(parsed["descriptors"][2]["image_size"], 4317581312)
        self.assertEqual(parsed["descriptors"][2]["partition_name"], "product")


if __name__ == "__main__":
    unittest.main()
