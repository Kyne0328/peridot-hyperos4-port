#!/usr/bin/env python3
"""Offline negative controls for guarded swappiness A/B/A."""
from __future__ import annotations
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
import swappiness_ab_call as target


class SwappinessTests(unittest.TestCase):
    def test_parse(self):
        sample = (
            "PRESSURE_CPU\nsome avg10=23.20 avg60=22.0 avg300=20.0 total=991\n"
            "full avg10=0.0 avg60=0.0 avg300=0.0 total=0\n"
            "PRESSURE_MEMORY\nsome avg10=1.0 total=10\nfull avg10=0.5 total=5\n"
            "VMSTAT\npswpin 12\npswpout 22\npgscan_kswapd 30\n"
            "SWAPPINESS\n100\n"
        )
        parsed = target.parse(sample)
        self.assertEqual(parsed["swappiness"], 100)
        self.assertEqual(parsed["vmstat"]["pgscan_kswapd"], 30)
        self.assertAlmostEqual(parsed["PRESSURE_CPU"]["some"]["avg10"], 23.2)
        self.assertEqual(parsed["PRESSURE_MEMORY"]["full"]["total"], 5)

    def test_failing_trial_restores(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "trial.json"
            values = {"current": "100"}
            def fake_adb(serial, cmd, timeout=18):
                if cmd == f"cat {target.VM}":
                    return values["current"]
                if cmd == "pidof com.facebook.orca || true":
                    return "14265"
                if cmd == "getenforce":
                    return "Enforcing"
                raise AssertionError(f"unexpected command: {cmd}")
            def fake_set(serial, value):
                values["current"] = str(value)
            with patch.object(target, "adb", side_effect=fake_adb), \
                 patch.object(target, "set_swappiness", side_effect=fake_set), \
                 patch.object(target, "stage", side_effect=[{"label": "A"}, RuntimeError("test failure")]):
                with self.assertRaisesRegex(RuntimeError, "test failure"):
                    target.run("serial", 6, 70, p)
            self.assertEqual(values["current"], "100")
            self.assertTrue(p.exists())
            self.assertTrue(__import__("json").loads(p.read_text())["restored"])

    def test_requires_messenger(self):
        def fake_adb(serial, cmd, timeout=18):
            return "100" if cmd == f"cat {target.VM}" else ""
        with patch.object(target, "adb", side_effect=fake_adb):
            with self.assertRaisesRegex(RuntimeError, "Messenger absent"):
                target.run("serial", 6, 70, Path("ignored-do-not-create.json"))


if __name__ == "__main__":
    unittest.main()
