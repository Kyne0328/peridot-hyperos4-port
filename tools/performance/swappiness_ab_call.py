#!/usr/bin/env python3
"""Guarded A/B/A swappiness experiment for POCO F6 video-call reclaim.

Restores the original VM setting in finally. Does not kill apps, change zRAM
algorithm/size, adjust CPU or thermal controls, or read call content. Never
installs changes on boot. A limited trial is evidence, not a production fix.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import subprocess
import time


VM = "/proc/sys/vm/swappiness"
METRICS = (
    "echo PRESSURE_CPU; cat /proc/pressure/cpu; "
    "echo PRESSURE_MEMORY; cat /proc/pressure/memory; "
    "echo PRESSURE_IO; cat /proc/pressure/io; "
    "echo VMSTAT; grep -E '^(pswpin|pswpout|pgscan_kswapd|pgsteal_kswapd|pgmajfault|pgscan_direct|oom_kill) ' /proc/vmstat; "
    "echo RAM; grep -E '^(MemAvailable|MemFree|SwapFree|SwapTotal):' /proc/meminfo; "
    "echo SWAPPINESS; cat /proc/sys/vm/swappiness; "
    "echo MESSENGER; pidof com.facebook.orca || true; "
    "echo PROVIDER; getprop init.svc.vendor.camera-provider; "
    "echo SCENARIO; cat /sys/class/thermal/thermal_message/sconfig 2>/dev/null"
)


def adb(serial: str, command: str, timeout: float = 18) -> str:
    result = subprocess.run(["adb", "-s", serial, "shell", command],
                            capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"ADB failure: {command[:60]}: {result.stderr[:160]}")
    return result.stdout.strip()


def set_swappiness(serial: str, value: int) -> None:
    if not 0 <= value <= 200:
        raise ValueError("outside Linux swappiness bounds")
    adb(serial, f"su -c 'echo {value} > {VM}'")
    actual = adb(serial, f"cat {VM}")
    if actual != str(value):
        raise RuntimeError(f"VM write not verified: requested={value}, actual={actual}")


def parse(text: str) -> dict:
    parts = re.split(r"(?m)^([A-Z_]+)\r?\n", text)
    sections = {parts[i]: parts[i + 1].strip() for i in range(1, len(parts) - 1, 2)}
    result = {"raw": sections}
    for label in ("PRESSURE_CPU", "PRESSURE_MEMORY", "PRESSURE_IO"):
        out = {}
        for line in sections.get(label, "").splitlines():
            cells = line.split()
            if cells and cells[0] in ("some", "full"):
                out[cells[0]] = {k: float(v) if k != "total" else int(v)
                                 for cell in cells[1:] if "=" in cell
                                 for k, v in [cell.split("=", 1)]}
        result[label] = out
    result["vmstat"] = {k: int(v) for k, v in
                        re.findall(r"(?m)^([a-z_]+)\s+(\d+)\s*$",
                                   sections.get("VMSTAT", ""))}
    result["swappiness"] = int(sections["SWAPPINESS"])
    return result


def snapshot(serial: str) -> dict:
    result = parse(adb(serial, METRICS, timeout=25))
    result["time_utc"] = datetime.now(timezone.utc).isoformat()
    return result


def stage(serial: str, label: str, seconds: int) -> dict:
    start = snapshot(serial)
    time.sleep(seconds)
    end = snapshot(serial)
    vm = {k: end["vmstat"][k] - value
          for k, value in start["vmstat"].items()
          if k in end["vmstat"]}
    elapsed = (datetime.fromisoformat(end["time_utc"]) -
               datetime.fromisoformat(start["time_utc"])).total_seconds()
    return {"label": label, "elapsed_s": elapsed, "start": start,
            "end": end, "vmstat_delta": vm}


def run(serial: str, seconds: int, candidate: int, output: Path) -> dict:
    original_text = adb(serial, f"cat {VM}")
    original = int(original_text)
    if candidate == original:
        raise ValueError("candidate must differ from original")
    if not adb(serial, "pidof com.facebook.orca || true"):
        raise RuntimeError("Messenger absent: refuse mismatched workload")
    if adb(serial, "getenforce") != "Enforcing":
        raise RuntimeError("SELinux not enforcing; abnormal baseline")
    output.parent.mkdir(parents=True, exist_ok=True)
    receipt: dict = {"serial": serial, "started_utc": datetime.now(timezone.utc).isoformat(),
                     "original": original, "candidate": candidate, "seconds": seconds,
                     "results": [], "restored": False}
    try:
        receipt["results"].append(stage(serial, "A_original", seconds))
        set_swappiness(serial, candidate)
        receipt["results"].append(stage(serial, "B_candidate", seconds))
    finally:
        set_swappiness(serial, original)
        receipt["restored"] = (adb(serial, f"cat {VM}") == original_text)
        receipt["restored_at_utc"] = datetime.now(timezone.utc).isoformat()
        output.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    receipt["results"].append(stage(serial, "A2_restored", seconds))
    output.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    return receipt


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--seconds", type=int, default=10)
    parser.add_argument("--candidate", type=int, default=70)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if not 6 <= args.seconds <= 25:
        parser.error("sample durations must be 6 to 25 seconds")
    receipt = run(args.serial, args.seconds, args.candidate, args.out)
    for item in receipt["results"]:
        delta = item["vmstat_delta"]
        st, en = item["start"], item["end"]
        print(f'{item["label"]}: duration={item["elapsed_s"]:.1f}s '
              f'pgscan_kswapd={delta.get("pgscan_kswapd")} '
              f'pswpout={delta.get("pswpout")} '
              f'pgmajfault={delta.get("pgmajfault")} '
              f'cpu_psi={st["PRESSURE_CPU"].get("some",{}).get("avg10")}'
              f'->{en["PRESSURE_CPU"].get("some",{}).get("avg10")} '
              f'mem_full={st["PRESSURE_MEMORY"].get("full",{}).get("avg10")}'
              f'->{en["PRESSURE_MEMORY"].get("full",{}).get("avg10")}')
    print("restored:", receipt["restored"], "archive:", args.out)


if __name__ == "__main__":
    main()
