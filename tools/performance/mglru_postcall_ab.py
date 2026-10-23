#!/usr/bin/env python3
"""Guarded no-call A/B/A of kernel MGLRU switch; original state restored.

Trial is MGLRU ON with Xiaomi SmartCache services/properties unchanged. It is
NOT evidence of a full SmartCache OFF-vs-MGLRU ON comparison. No call content,
app data, thermal, sysctl, or persistent properties collected/modified.
"""
from __future__ import annotations
import argparse
import os
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import subprocess
import sys
import time
import capture_reclaim_causality as metrics

LRU = "/sys/kernel/mm/lru_gen/enabled"
GUARD_REMOTE = "/data/local/tmp/kyneos_mglru_guard_20261019.sh"


def adb(serial: str, *args: str, timeout=22) -> str:
    p = subprocess.run(["adb", "-s", serial, *args], text=True,
                       capture_output=True, timeout=timeout)
    if p.returncode:
        raise RuntimeError(f"adb {args[:2]} failed ({p.returncode}): {p.stderr[:180]}")
    return p.stdout.strip()


def shell(serial: str, line: str, timeout=25) -> str:
    return adb(serial, "shell", line, timeout=timeout)


def lru_state(serial: str) -> int:
    return int(shell(serial, f"cat {LRU}").strip(), 0)


def safe_preflight(serial: str, original: int) -> None:
    boot_age = float(shell(serial, "cat /proc/uptime").split()[0])
    if boot_age < 600:
        raise RuntimeError(f"Device has only {boot_age:.0f}s uptime; refuse first 10 minutes after reboot.")
    if shell(serial, "getenforce") != "Enforcing":
        raise RuntimeError("SELinux unexpected state; not trialing.")
    if shell(serial, "getprop ro.product.device") != "peridot":
        raise RuntimeError("Not peridot.")
    if shell(serial, "getprop persist.sys.stability.SmartCacheEnable") != "true":
        raise RuntimeError("SmartCache property differs from expected baseline.")
    dump = shell(serial, "dumpsys media.camera", timeout=38)
    active = re.search(r"Active Camera Clients:\s*(\[\s*\])", dump)
    if not active:
        raise RuntimeError("Camera active or camera state unknown: abort.")
    if lru_state(serial) != original:
        raise RuntimeError("MGLRU changed since baseline.")
    if shell(serial, "cat /proc/sys/vm/swappiness /proc/sys/vm/watermark_scale_factor") != "100\n65":
        raise RuntimeError("VM baseline changed; abort.")


def set_lru(serial: str, value: int) -> int:
    if value not in (0, 7):
        raise ValueError("Only original=0 and candidate=7 supported")
    # Bound all writes to the one documented runtime sysfs interface.
    shell(serial, f"su -c 'echo {value} > {LRU}'")
    current = lru_state(serial)
    if bool(current & 1) != bool(value & 1):
        raise RuntimeError(f"MGLRU verification failed: requested {value}, read {current}")
    return current


def install_watchdog(serial: str) -> str:
    # Autonomous rollback if host connection or benchmark process is lost.
    guard = "#!/system/bin/sh\nsleep 55\necho 0 > " + LRU + "\nrm -f " + GUARD_REMOTE + "\n"
    tmp = Path("builder/work/performance-call-observations/20261019-postcall/mglru-watchdog.sh")
    tmp.parent.mkdir(parents=True, exist_ok=True)
    tmp.write_text(guard, encoding="utf-8", newline="\n")
    adb(serial, "push", str(tmp), GUARD_REMOTE, timeout=30)
    shell(serial, f"su -c 'chmod 700 {GUARD_REMOTE}'")
    result = shell(serial, f"su -c 'nohup /system/bin/sh {GUARD_REMOTE} >/dev/null 2>&1 </dev/null & echo $!'")
    if not result or not re.search(r"\d+", result):
        raise RuntimeError("Could not confirm watchdog process started")
    return result


def stage(serial: str, name: str, seconds: int, interval: int, expected: int) -> dict:
    samples = []
    started = time.monotonic()
    while True:
        val = metrics.parse(metrics.run_adb(serial, metrics.COMMAND))
        state = int(val["mglru_enabled"], 0)
        if bool(state & 1) != bool(expected & 1):
            raise RuntimeError(f"{name}: MGLRU unexpectedly changed ({state})")
        samples.append({"elapsed_s": round(time.monotonic()-started, 3),
                        "recorded_utc": datetime.now(timezone.utc).isoformat(),
                        "data": val})
        if time.monotonic() - started + interval >= seconds:
            break
        time.sleep(interval)
    time_elapsed = samples[-1]["elapsed_s"] - samples[0]["elapsed_s"]
    if time_elapsed <= 0:
        raise ValueError("no usable sampling window")
    comparison = metrics.compare(samples[0]["data"], samples[-1]["data"], time_elapsed)
    comparison["max_mem_full_avg10_all_samples"] = max(
        v["data"]["psi_memory"].get("full", {}).get("avg10", 0) for v in samples)
    comparison["mean_mem_full_avg10_all_samples"] = round(
        sum(v["data"]["psi_memory"].get("full", {}).get("avg10", 0) for v in samples)
        / len(samples), 3)
    comparison["max_cpu_some_avg10_all_samples"] = max(
        v["data"]["psi_cpu"].get("some", {}).get("avg10", 0) for v in samples)
    return {"label": name, "samples": samples, "summary": comparison}


def trial(serial: str, seconds: int, interval: int, path: Path) -> dict:
    original = lru_state(serial)
    if original != 0:
        raise RuntimeError(f"baseline MGLRU not 0: {original}")
    safe_preflight(serial, original)
    result = {"serial": serial, "started_utc": datetime.now(timezone.utc).isoformat(),
              "baseline_smartcache": "true", "original_mglru": original,
              "candidate_requested_mglru": 7, "stages": [],
              "restored": False,
              "caution": "MGLRU enabled with SmartCache property unchanged, not a full replacement study"}
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        result["stages"].append(stage(serial, "A_stock_smartcache", seconds, interval, 0))
        safe_preflight(serial, original)
        result["watchdog_pid"] = install_watchdog(serial)
        result["mglru_trial_actual"] = set_lru(serial, 7)
        result["stages"].append(stage(serial, "B_mglru_overlay", seconds, interval, 7))
    finally:
        # Always reset, even when A/B sample or ADB command raises. Independent
        # on-device delayed watchdog also restores the original if ADB dies.
        try:
            set_lru(serial, original)
            result["restored"] = lru_state(serial) == original
        except Exception as e:
            result["restore_error"] = str(e)
        path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    if not result["restored"]:
        raise RuntimeError("MGLRU restoration failed; watchdog scheduled")
    result["stages"].append(stage(serial, "A2_stock_restored", seconds, interval, 0))
    result["finish_utc"] = datetime.now(timezone.utc).isoformat()
    path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--serial", default=os.environ.get("ANDROID_SERIAL"))
    p.add_argument("--seconds", type=int, default=15)
    p.add_argument("--interval", type=int, default=3)
    p.add_argument("--out", required=True, type=Path)
    args = p.parse_args()
    if not args.serial:
        p.error("Set ANDROID_SERIAL or provide --serial")
    if not (12 <= args.seconds <= 18 and 2 <= args.interval <= 6):
        p.error("for safety, only 12–18 s stages and 2–6 s samples accepted")
    answer = trial(args.serial, args.seconds, args.interval, args.out)
    for rec in answer["stages"]:
        summary = rec["summary"]
        print(rec["label"], "scan/s", summary["counter_per_second"].get("pgscan_kswapd"),
              "refault_file/s", summary["counter_per_second"].get("workingset_refault_file"),
              "swapin/s", summary["counter_per_second"].get("pswpin"),
              "mem_full_max", summary["max_mem_full_avg10_all_samples"],
              "cpu_some_max", summary["max_cpu_some_avg10_all_samples"])
    print("RESTORED", answer["restored"], "receipt:", args.out)


if __name__ == "__main__":
    main()
