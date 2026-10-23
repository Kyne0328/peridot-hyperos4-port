#!/usr/bin/env python3
"""Negative scope tests for the systemless SELinux addon."""
from __future__ import annotations
import tempfile
import unittest
from pathlib import Path
import build as module


class PolicyScopeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.old_root = module.ROOT
        self.addCleanup(lambda: setattr(module, "ROOT", self.old_root))
        module.ROOT = Path(self.tmp.name)
        for f in module.FILES:
            (module.ROOT / f).write_bytes((self.old_root / f).read_bytes())

    def test_exact_policy_packs(self) -> None:
        self.assertEqual(module.validate()["sepolicy.rule"], module.RULE.encode())
        z = module.ROOT / "out.zip"
        self.assertEqual(module.build(z), __import__("hashlib").sha256(z.read_bytes()).hexdigest())

    def test_reject_broad_sysfs(self) -> None:
        (module.ROOT / "sepolicy.rule").write_text("allow system_app sysfs file { read open }\n")
        with self.assertRaises(ValueError):
            module.validate()

    def test_reject_write_permission(self) -> None:
        (module.ROOT / "sepolicy.rule").write_text(module.RULE + "allow system_app vendor_sysfs_kgsl_gpuclk file write\n")
        with self.assertRaises(ValueError):
            module.validate()

    def test_reject_permissive(self) -> None:
        (module.ROOT / "sepolicy.rule").write_text(module.RULE + "permissive system_app\n")
        with self.assertRaises(ValueError):
            module.validate()

    def test_reject_symlink(self) -> None:
        p = module.ROOT / "sepolicy.rule"
        p.unlink()
        try:
            p.symlink_to(self.old_root / "sepolicy.rule")
        except OSError as exc:
            self.skipTest(f"Windows host does not allow symlink creation: {exc}")
        with self.assertRaises(ValueError):
            module.validate()


if __name__ == "__main__":
    unittest.main()
