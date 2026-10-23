#!/usr/bin/env python3
"""Read-only, bounded POCO F6 memory reclaim telemetry during active calls.

Collects counters/PSI only. Does not record camera, audio, screen, message
content, credentials, or logcat. Does not change sysctls, apps or services.
"""
from __future__ import annotations
import argparse
import os
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import time

COUNTERS = (
    "pgscan_kswapd", "pgsteal_kswapd", "pgscan_direct", "pgsteal_direct",
    "pswpin", "pswpout", "pgmajfault", "allocstall_normal",
    "allocstall_movable", "workingset_refault_file", "workingset_refault_anon",
    "workingset_activate_file", "workingset_activate_anon", "oom_kill",
)
# Keep the entire capture limited to non-content counters; no logcat or dumpsys.
COMMAND = (
    "echo ===VMSTAT===; cat /proc/vmstat; "
    "echo ===MEMINFO===; cat /proc/meminfo; "
    "echo ===PSI_MEMORY===; cat /proc/pressure/memory; "
    "echo ===PSI_CPU===; cat /proc/pressure/cpu; "
    "echo ===ZRAM===; cat /sys/block/zram0/mm_stat; "
    "echo ===MGLRU===; cat /sys/kernel/mm/lru_gen/enabled; "
    "echo ===CAMERA===; pidof com.facebook.orca || true"
)


def run_adb(serial: str, command: str) -> str:
    p = subprocess.run(
        ["adb", "-s", serial, "shell", command],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, timeout=25,
    )
    if p.returncode != 0:
        raise RuntimeError(f"adb read failed: {p.stderr[:200]}")
    return p.stdout


def sections(raw: str) -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}
    tag: str | None = None
    for line in raw.splitlines():
        if line.startswith("===") and line.endswith("==="):
            tag = line.strip("=").strip()
            found[tag] = []
        elif tag is not None:
            found[tag].append(line)
    return found


def keyints(lines: list[str]) -> dict[str, int]:
    found = {}
    for line in lines:
        cells = line.split()
        if len(cells) >= 2 and cells[1].isdigit():
            found[cells[0].rstrip(":")] = int(cells[1])
    return found


def psi(lines: list[str]) -> dict[str, dict[str, float | int]]:
    result = {}
    for line in lines:
        cells = line.split()
        if not cells or cells[0] not in ("some", "full"):
            continue
        values = {}
        for cell in cells[1:]:
            if "=" in cell:
                key, value = cell.split("=", 1)
                values[key] = int(value) if key == "total" else float(value)
        result[cells[0]] = values
    return result


def parse(raw: str) -> dict:
    group = sections(raw)
    needed = ("VMSTAT", "MEMINFO", "PSI_MEMORY", "PSI_CPU", "ZRAM", "MGLRU")
    if not all(group.get(k) for k in needed):
        raise ValueError(f"Missing telemetry: {[k for k in needed if not group.get(k)]}")
    vm = keyints(group["VMSTAT"])
    if not all(k in vm for k in ("pswpin", "pswpout", "pgscan_kswapd")):
        raise ValueError("Missing critical VM counters")
    mm = keyints(group["MEMINFO"])
    zram = list(map(int, group["ZRAM"][0].split()))
    return {
        "vmstat": {k: vm[k] for k in COUNTERS if k in vm},
        "memory_kib": {k: mm[k] for k in
                       ("MemFree", "MemAvailable", "Cached", "SwapFree", "SwapTotal")
                       if k in mm},
        "psi_memory": psi(group["PSI_MEMORY"]),
        "psi_cpu": psi(group["PSI_CPU"]),
        "zram_bytes": {"orig_data_size": zram[0], "compr_data_size": zram[1],
                       "mem_used_total": zram[2]},
        "mglru_enabled": group["MGLRU"][0].strip(),
        "messenger_pid": group.get("CAMERA", [""])[0].strip()
    }


def compare(before: dict, after: dict, seconds: float) -> dict:
    if seconds <= 0:
        raise ValueError("Non-positive duration")
    changes: dict[str, int] = {}
    for key in before["vmstat"].keys() & after["vmstat"].keys():
        diff = after["vmstat"][key] - before["vmstat"][key]
        if diff < 0:
            raise ValueError(f"VM counter unexpectedly reset: {key}")
        changes[key] = diff
    memory = [before, after]
    return {
        "duration_s": round(seconds, 3),
        "counter_delta": changes,
        "counter_per_second": {k: round(v / seconds, 2) for k, v in changes.items()},
        "mem_available_kib_min": min(x["memory_kib"].get("MemAvailable", 0)
                                      for x in memory),
        "max_cpu_some_avg10": max(x["psi_cpu"].get("some", {}).get("avg10", 0)
                                  for x in memory),
        "max_mem_full_avg10": max(x["psi_memory"].get("full", {}).get("avg10", 0)
                                  for x in memory),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--serial", default=os.environ.get("ANDROID_SERIAL"))
    ap.add_argument("--seconds", type=int, default=30)
    ap.add_argument("--interval", type=int, default=3)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    if not args.serial:
        ap.error("Set ANDROID_SERIAL or provide --serial")
    if not 6 <= args.seconds <= 120 or not 2 <= args.interval <= 15:
        ap.error("seconds must be 6..120, interval must be 2..15")
    if args.seconds // args.interval < 2:
        ap.error("Need at least two samples")
    data = {
        "device": args.serial,
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "method": "Read-only kernel, PSI, and compressed swap counters; no media/content",
        "samples": [], "interval_seconds": args.interval,
    }
    ticks = time.monotonic()
    deadline = ticks + args.seconds
    while True:
        now = time.monotonic()
        snap = parse(run_adb(args.serial, COMMAND))
        data["samples"].append({
            "time_utc": datetime.now(timezone.utc).isoformat(),
            "elapsed_s": round(time.monotonic() - ticks, 3), "data": snap,
        })
        if time.monotonic() + args.interval > deadline:
            break
        time.sleep(args.interval)
    measurements = data["samples"]
    before, after = measurements[0], measurements[-1]
    data["summary"] = compare(before["data"], after["data"],
                              after["elapsed_s"] - before["elapsed_s"])
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(data["summary"], indent=2))
    print("Saved:", args.out)


if __name__ == "__main__":
    main()
