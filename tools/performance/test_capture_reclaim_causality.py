#!/usr/bin/env python3
"""Offline tests: no connected phone required."""
import copy
import unittest
from capture_reclaim_causality import parse, compare

RAW = """===VMSTAT===
pswpin 20
pswpout 10
pgscan_kswapd 1000
pgsteal_kswapd 200
workingset_refault_file 15
oom_kill 0
===MEMINFO===
MemFree: 1000 kB
MemAvailable: 1600000 kB
SwapFree: 4000000 kB
===PSI_MEMORY===
some avg10=2.50 avg60=1.40 avg300=0.90 total=201
full avg10=1.10 avg60=0.30 avg300=0.20 total=102
===PSI_CPU===
some avg10=35.00 avg60=30.00 avg300=25.00 total=301
full avg10=0.00 avg60=0.00 avg300=0.00 total=0
===ZRAM===
30000000 10000000 12000000 0
===MGLRU===
0x0000
===CAMERA===
14265
"""


class ReclaimTests(unittest.TestCase):
    def test_live_format(self):
        d = parse(RAW)
        self.assertEqual(d["memory_kib"]["MemAvailable"], 1600000)
        self.assertEqual(d["vmstat"]["pgscan_kswapd"], 1000)
        self.assertEqual(d["psi_memory"]["full"]["total"], 102)
        self.assertEqual(d["zram_bytes"]["mem_used_total"], 12000000)
        self.assertEqual(d["mglru_enabled"], "0x0000")
        self.assertEqual(d["messenger_pid"], "14265")

    def test_delta(self):
        a = parse(RAW)
        b = copy.deepcopy(a)
        b["vmstat"]["pgscan_kswapd"] += 250
        b["vmstat"]["pgsteal_kswapd"] += 100
        b["vmstat"]["pswpin"] += 2
        b["psi_memory"]["full"]["avg10"] = 2.4
        out = compare(a, b, 10)
        self.assertEqual(out["counter_delta"]["pgscan_kswapd"], 250)
        self.assertEqual(out["counter_per_second"]["pgscan_kswapd"], 25)
        self.assertEqual(out["max_mem_full_avg10"], 2.4)

    def test_reset_rejected(self):
        a = parse(RAW)
        b = copy.deepcopy(a)
        b["vmstat"]["pgscan_kswapd"] -= 1
        with self.assertRaisesRegex(ValueError, "reset"):
            compare(a, b, 10)

    def test_missing_counters_rejected(self):
        with self.assertRaisesRegex(ValueError, "Missing critical"):
            parse(RAW.replace("pswpin 20", "unrelated_counter 20"))

    def test_nonpositive_time_rejected(self):
        d = parse(RAW)
        with self.assertRaisesRegex(ValueError, "Non-positive"):
            compare(d, d, 0)


if __name__ == "__main__":
    unittest.main()
