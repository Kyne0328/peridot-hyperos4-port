#!/usr/bin/env python3
"""Read-only status report for the POCO F6 experimental camera EIS module."""
import argparse
import json
import subprocess

ORIGINAL = "9ca1ddd03029e30c8f1e261f149985a626c14dbd79c7476d8c58897883892da4"
TRIAL = "7526d8325a7b6d820ea643cce0a58d93833f10381a8b9124d25c23639f738a53"
LOG_AB2 = "098516ece81777b6e153b9db8eb3d43d302b81184876373345d21eb32155aefe"
MODULE = "kyneos_camera_3rdeis_ab"


def adb(*args):
    x = subprocess.run(["adb", *args], text=True, encoding="utf-8", errors="replace", capture_output=True, timeout=13)
    if x.returncode:
        raise RuntimeError(f"ADB command {args[0]!r} failed: {x.stderr[:250]}")
    return x.stdout.strip()


def inspect():
    device = adb("shell", "getprop", "ro.product.device")
    if device != "peridot":
        raise RuntimeError(f"Unexpected device {device!r}, expected peridot")
    visible = adb("shell", "sha256sum", "/odm/etc/camera/camxoverridesettings.txt").split()[0]
    def present(path: str) -> bool:
        result = subprocess.run(
            ["adb", "shell", "ls", "-l", path],
            text=True, encoding="utf-8", errors="replace", capture_output=True, timeout=12,
        )
        return result.returncode == 0

    if present(f"/data/adb/modules_update/{MODULE}/module.prop"):
        install = "PENDING_NEXT_REBOOT"
    elif present(f"/data/adb/modules/{MODULE}/module.prop"):
        install = "INSTALLED"
    else:
        install = "NOT_INSTALLED"
    metamodules = []
    # Known first-party device currently uses meta-overlayfsx; query it directly
    # instead of spawning ADB once per installed module during an active call.
    meta_path = "/data/adb/modules/meta-overlayfsx/module.prop"
    if present(meta_path):
        content = adb("shell", "cat", meta_path)
        if any(x.strip() in {"metamodule=1", "metamodule=true"} for x in content.splitlines()):
            metamodules.append(meta_path)
    if visible == LOG_AB2:
        status = "ACTIVE_EIS_OFF_AND_TEXT_LOGGING_OFF_AB2"
    elif visible == TRIAL:
        status = "ACTIVE_EIS_OFF_ONLY_CONFIG"
    elif visible == ORIGINAL:
        status = "STOCK_CONFIG_VISIBLE"
    else:
        status = "UNEXPECTED_CAMERA_CONFIG"
    if install == "INSTALLED" and status == "STOCK_CONFIG_VISIBLE" and not metamodules:
        reason = "NO_KSU_METAMODULE: KernelSU does not mount regular module system/ directories without an active metamodule"
    elif install == "INSTALLED" and status == "STOCK_CONFIG_VISIBLE":
        reason = "MODULE_OVERLAY_NOT_VISIBLE: investigate active metamodule / mount handling"
    elif status in {"ACTIVE_EIS_OFF_ONLY_CONFIG", "ACTIVE_EIS_OFF_AND_TEXT_LOGGING_OFF_AB2"}:
        reason = "CAMERA_OVERLAY_VERIFIED: trial enabled; runtime performance benefit still requires matched A/B evidence"
    else:
        reason = "Pending or unexpected configuration; no performance conclusions"
    return {
        "device": device,
        "module_id": MODULE,
        "module_installation": install,
        "visible_config_state": status,
        "visible_config_sha256": visible,
        "expected_eis_off_only_sha256": TRIAL,
        "expected_eis_and_logging_off_sha256": LOG_AB2,
        "active_metamodule_manifests": metamodules,
        "mount_status_reason": reason,
        "thermal_scenario_readonly": adb(
            "shell", "cat", "/sys/class/thermal/thermal_message/sconfig",
        ),
        "selinux_readonly": adb("shell", "getenforce"),
        "note": "Hash verifies mounted camera configuration only. Compare call workload after reboot; performance improvement remains unproven.",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    print(json.dumps(inspect(), indent=2))
