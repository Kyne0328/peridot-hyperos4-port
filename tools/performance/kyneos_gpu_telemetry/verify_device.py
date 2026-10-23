#!/usr/bin/env python3
"""Read-only post-install validation of the scoped POCO F6 GPU telemetry addon.

No reset, call interruption, app data access, service restart or reboot.
"""
from __future__ import annotations

import argparse
import subprocess

RULE = "allow system_app vendor_sysfs_kgsl_gpuclk file { open read getattr }"
MODULE = "kyneos_gpuclk_telemetry"


def shell(serial: str | None, command: str) -> str:
    cmd = ["adb"] + (["-s", serial] if serial else []) + ["shell", command]
    r = subprocess.run(cmd, text=True, capture_output=True, timeout=25)
    if r.returncode:
        raise RuntimeError(f"ADB command failed: {command[:90]}: {r.stderr[:160]}")
    return r.stdout.strip()


def check(serial: str | None) -> None:
    checks = {
        "build": "getprop ro.build.version.incremental",
        "selinux": "getenforce",
        "doze": "cmd deviceidle whitelist | grep -F com.facebook.orca || true",
        "gpu_label": "ls -Z /sys/devices/platform/soc/3d00000.qcom,kgsl-3d0/kgsl/kgsl-3d0/gpuclk",
        "chrome_angle_packages": "settings get global angle_gl_driver_selection_pkgs",
        "chrome_angle_values": "settings get global angle_gl_driver_selection_values",
        "watermark": "cat /proc/sys/vm/watermark_scale_factor",
        "qesd_hals": "service list | grep -i qesd || true",
        "camera_provider": "getprop init.svc.vendor.camera-provider",
    }
    readings = {name: shell(serial, command) for name, command in checks.items()}
    for name, value in readings.items():
        print(f"{name}: {value[:250]}")
    errors = []
    if readings["selinux"] != "Enforcing":
        errors.append("SELinux not enforcing")
    if "com.facebook.orca" not in readings["doze"]:
        errors.append("Messenger user Doze exemption missing")
    if "vendor_sysfs_kgsl_gpuclk" not in readings["gpu_label"]:
        errors.append("GPU clock file unexpected SELinux label")
    if readings["camera_provider"] != "running":
        errors.append("Camera provider not running")
    pkgs = readings["chrome_angle_packages"].split(",")
    vals = readings["chrome_angle_values"].split(",")
    if len(pkgs) != len(vals) or "com.android.chrome" not in pkgs or vals[pkgs.index("com.android.chrome")] != "angle":
        errors.append("Chrome-only ANGLE override not preserved")
    if errors:
        raise SystemExit("FAILED:\n" + "\n".join(errors))
    print("PASS: installation/settings intact. Reboot-only policy effect and camera quality remain UNVERIFIED.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial")
    a = parser.parse_args()
    check(a.serial)
