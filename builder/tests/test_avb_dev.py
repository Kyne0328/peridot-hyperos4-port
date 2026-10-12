from __future__ import annotations

import unittest

from peridot_builder.avb_dev import validate_development_avb_profile
from peridot_builder.errors import BuilderError


def valid_profile() -> dict:
    return {
        "mode": "development_aosp_testkey",
        "production_trust": False,
        "key": {"algorithm": "SHA256_RSA4096"},
        "security": {
            "vbmeta_flags": 0,
            "hashtree_disabled": False,
            "verification_disabled": False,
            "fake_locked_properties": False,
        },
        "product": {
            "partition_size": 4379996160,
            "generate_fec": False,
        },
        "vbmeta": {
            "chains": [
                {"partition": "boot", "rollback_slot": 3},
                {"partition": "recovery", "rollback_slot": 1},
                {"partition": "vbmeta_system", "rollback_slot": 2},
            ]
        },
    }


class DevelopmentAvbProfileTests(unittest.TestCase):
    def test_accepts_explicit_development_policy(self) -> None:
        validate_development_avb_profile(valid_profile())

    def test_rejects_verification_disable(self) -> None:
        profile = valid_profile()
        profile["security"]["verification_disabled"] = True
        with self.assertRaises(BuilderError):
            validate_development_avb_profile(profile)

    def test_rejects_chain_slot_drift(self) -> None:
        profile = valid_profile()
        profile["vbmeta"]["chains"][0]["rollback_slot"] = 4
        with self.assertRaises(BuilderError):
            validate_development_avb_profile(profile)


if __name__ == "__main__":
    unittest.main()
