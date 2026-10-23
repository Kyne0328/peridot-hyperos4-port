#!/usr/bin/env python3
"""Manual read-only POCO F6 camera / call performance sampler.

Does not modify the phone or read private audio/video/messages. Start this
manually during one of: no-call, audio call, video call, and post-call.
Each recording lasts --seconds (default 8) and captures metadata only.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import subprocess
import time


WATCHED = (
    "com.facebook.orca", "vendor.qti.camera.provider-service_64",
    "surfaceflinger", "system_server", "com.android.systemui",
    "vendor.qti.hardware.display.composer-service", "cameraserver",
    "media.hwcodec", "media.swcodec", "kswapd0", "com.microsoft.appmanager",
)


def adb(command: str, serial: str | None, timeout: float = 18) -> str:
    args = ["adb"]
    if serial:
        args += ["-s", serial]
    result = subprocess.run(
        [*args, "shell", "sh", "-c", command],
        capture_output=True, text=True, timeout=timeout, check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"ADB command failed ({result.returncode}): {command[:100]}, "
            f"stderr={result.stderr[:300]!r}"
        )
    return result.stdout


def parse_psi(text: str) -> dict:
    stats = {}
    for line in text.splitlines():
        parts = line.split()
        if parts and parts[0] in {"some", "full"}:
            stats[parts[0]] = {}
            for item in parts[1:]:
                if "=" in item:
                    key, val = item.split("=", 1)
                    stats[parts[0]][key] = float(val) if key != "total" else int(val)
    return stats


def parse_memory(text: str) -> dict:
    result = {}
    for line in text.splitlines():
        m = re.match(r"^(\w+):\s+(\d+)\s+kB", line)
        if m and m.group(1) in {
            "MemTotal", "MemAvailable", "MemFree", "SwapTotal", "SwapFree",
        }:
            result[m.group(1) + "_KiB"] = int(m.group(2))
    result["SwapUsed_KiB"] = result.get("SwapTotal_KiB", 0) - result.get("SwapFree_KiB", 0)
    return result


def parse_vmstat(text: str) -> dict:
    result = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0] in {
            "pswpin", "pswpout", "pgmajfault", "pgscan_kswapd",
            "pgsteal_kswapd", "pgscan_direct", "oom_kill",
        } and parts[1].isdigit():
            result[parts[0]] = int(parts[1])
    return result


def snapshot(serial: str | None) -> dict:
    script = """
    echo SNAPSHOT_START
    echo SEC_GENERAL
    getprop ro.product.device
    getprop ro.build.version.incremental
    echo SEC_PRESSURE_CPU
    cat /proc/pressure/cpu
    echo SEC_PRESSURE_MEMORY
    cat /proc/pressure/memory
    echo SEC_PRESSURE_IO
    cat /proc/pressure/io
    echo SEC_MEMINFO
    grep -E '^(MemTotal|MemAvailable|MemFree|SwapTotal|SwapFree):' /proc/meminfo
    echo SEC_VMSTAT
    grep -E '^(pswpin|pswpout|pgmajfault|pgscan_kswapd|pgsteal_kswapd|pgscan_direct|oom_kill) ' /proc/vmstat
    echo SEC_SCENARIO
    cat /sys/class/thermal/thermal_message/sconfig 2>/dev/null
    echo SEC_BOARD_TEMP
    cat /sys/class/thermal/thermal_message/board_sensor_temp 2>/dev/null
    echo SEC_CPU_FREQ
    for n in 0 3 7; do
       printf 'cpu%s ' "$n"
       for k in scaling_cur_freq scaling_max_freq cpuinfo_max_freq; do
           cat /sys/devices/system/cpu/cpu$n/cpufreq/$k 2>/dev/null | tr '\\n' ' '
       done
       echo
    done
    echo SEC_TOP
    top -b -n 1 | grep -E 'com.facebook.orca|camera.provider-service|surfaceflinger|system_server|com.android.systemui|display.composer-service|cameraserver|media.hwcodec|media.swcodec|kswapd0|com.microsoft.appmanager' | head -n 24
    echo SEC_CAMERA_CLIENTS
    dumpsys media.camera | head -n 12
    echo SEC_GRAPHICS
    dumpsys SurfaceFlinger | grep -E 'activeMode=|Total missed frame count:' | head -n 3
    echo SEC_CODEC_RESOURCES
    dumpsys media.resource_manager | grep -E 'Name:|Pid:|non-secure-codec/(hw|sw)-video-codec' | head -n 45
    echo SEC_BATTERY
    dumpsys battery | grep -E 'level:|temperature:'
    echo SEC_AUDIO_MODE
    dumpsys audio | grep -m 1 'mAudioModeOwner:'
    """.strip()
    raw = adb(script, serial, timeout=45)
    sections: dict[str, list[str]] = {}
    active = None
    for row in raw.splitlines():
        if row.startswith("SEC_") and row.strip() == row:
            active = row.removeprefix("SEC_")
            sections[active] = []
        elif active:
            sections[active].append(row)
    if "PRESSURE_CPU" not in sections or "VMSTAT" not in sections:
        raise RuntimeError("Missing mandatory ADB snapshot sections")
    raw_section = lambda key: "\n".join(sections.get(key, []))
    cpu_frequencies = {}
    for entry in sections.get("CPU_FREQ", []):
        parts = entry.split()
        if len(parts) == 4 and parts[0].startswith("cpu"):
            try:
                cpu_frequencies[parts[0]] = dict(zip(
                    ("current_kHz", "limit_kHz", "hardware_max_kHz"),
                    (int(x) for x in parts[1:]),
                ))
            except ValueError:
                pass
    return {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "device": [s for s in sections.get("GENERAL", []) if s][:2],
        "psi": {
            "cpu": parse_psi(raw_section("PRESSURE_CPU")),
            "memory": parse_psi(raw_section("PRESSURE_MEMORY")),
            "io": parse_psi(raw_section("PRESSURE_IO")),
        },
        "memory": parse_memory(raw_section("MEMINFO")),
        "vmstat": parse_vmstat(raw_section("VMSTAT")),
        "thermal_scenario": raw_section("SCENARIO").strip(),
        "board_sensor_mC": raw_section("BOARD_TEMP").strip(),
        "cpu_frequency": cpu_frequencies,
        "top_process_lines": sections.get("TOP", []),
        "camera_service_header": sections.get("CAMERA_CLIENTS", []),
        "display_lines": sections.get("GRAPHICS", []),
        "codec_resource_metadata": sections.get("CODEC_RESOURCES", []),
        "battery_lines": sections.get("BATTERY", []),
        "audio_mode_lines": sections.get("AUDIO_MODE", []),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--label", choices=("idle", "voice", "video", "postcall"), required=True)
    parser.add_argument("--seconds", type=int, default=8)
    parser.add_argument("--serial", default=None, help="ADB serial (optional if only one device)")
    parser.add_argument("--output-dir", type=Path, default=Path(
        "builder/work/performance-call-observations",
    ))
    args = parser.parse_args()
    if not 4 <= args.seconds <= 30:
        parser.error("--seconds must be 4..30")
    start = snapshot(args.serial)
    time.sleep(args.seconds)
    end = snapshot(args.serial)
    deltas = {}
    for key in start["vmstat"].keys() & end["vmstat"].keys():
        deltas[key] = end["vmstat"][key] - start["vmstat"][key]
    observed = {
        "label": args.label,
        "duration_requested_s": args.seconds,
        "capture_description": "Read-only Android performance metadata. No audio/video/call content.",
        "start": start,
        "end": end,
        "vmstat_delta": deltas,
    }
    output_dir = args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = output_dir / f"peridot-call-{args.label}-{stamp}.json"
    with path.open("x", encoding="utf-8") as f:
        json.dump(observed, f, indent=2)
        f.write("\n")
    before, after = start["psi"]["cpu"]["some"], end["psi"]["cpu"]["some"]
    print("Saved:", path)
    print("CPU pressure avg10:", before.get("avg10"), "->", after.get("avg10"))
    print("Memory full avg10:",
          start["psi"]["memory"]["full"].get("avg10"),
          "->", end["psi"]["memory"]["full"].get("avg10"))
    print("Scenario:", start["thermal_scenario"], "->", end["thermal_scenario"])
    print("CPU clock limits:", start["cpu_frequency"], "->", end["cpu_frequency"])
    print("Swap pages in/out over sample:",
          deltas.get("pswpin"), deltas.get("pswpout"))
    print("Only review camera client package IDs and codec resource metadata; no call content collected.")


if __name__ == "__main__":
    main()
