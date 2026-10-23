"""Read-only peridot optimization checks during an owner-operated workload."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import shlex
import subprocess
import time


SNAPSHOT = r'''date; echo SEC_UPTIME; cat /proc/uptime
echo SEC_MEMORY; cat /proc/meminfo
echo SEC_VMSTAT; cat /proc/vmstat
for n in cpu memory io; do echo SEC_PSI_$n; cat /proc/pressure/$n; done
echo SEC_ZRAM; cat /sys/block/zram0/mm_stat
echo SEC_CPU; cat /proc/stat | head -n 9
echo SEC_SERVICES; getprop init.svc.vendor.atfwd; getprop init.svc.vendor.qesdk-securitymgr
getprop init.svc_debug_pid.vendor.atfwd; getprop init.svc_debug_pid.vendor.qesdk-securitymgr
echo SEC_APPS
for name in com.zhiliaoapp.musically com.facebook.orca com.miui.miwallpaper system_server com.android.systemui surfaceflinger; do
 for pid in $(pidof $name); do
  echo APP:$name:$pid
  cat /proc/$pid/stat
  grep -E '^(Threads|VmRSS|VmSwap|VmPTE):' /proc/$pid/status
  cat /proc/$pid/oom_score_adj
  grep -E '^(Pss|SwapPss):' /proc/$pid/smaps_rollup
 done
done
echo SEC_THERMAL
cat /sys/class/thermal/thermal_message/sconfig /sys/class/thermal/thermal_message/board_sensor_temp
for n in 0 3 7; do echo CPU:$n; cat /sys/devices/system/cpu/cpu$n/cpufreq/scaling_cur_freq /sys/devices/system/cpu/cpu$n/cpufreq/scaling_max_freq; done
echo SEC_BATTERY; dumpsys battery | grep -E 'powered:|temperature:|level:'
echo SEC_WINDOW; dumpsys window windows | grep -E 'mCurrentFocus=|mFocusedApp='
'''

DETAILS = {
    "vendor_policy": r'''date; uname -a; getenforce; getprop ro.boot.slot_suffix
getprop ro.build.display.id; getprop ro.build.version.incremental
for f in /vendor/etc/seccomp_policy/atfwd@2.0.policy /vendor/etc/seccomp_policy/qesdksec.policy; do echo FILE:$f; sha256sum "$f"; cat "$f"; done
grep -A 16 '^service vendor.atfwd' /vendor/etc/init/hw/init.qcom.rc
cat /vendor/etc/init/qesdk-secmanager.rc
sha256sum /vendor/bin/ATFWD-daemon /vendor/bin/qesdk-secmanager /apex/com.android.runtime/lib64/bionic/libc.so
echo MOUNTS; cat /proc/mounts | grep -E ' /vendor | /odm '
echo VBMETA; sha256sum /dev/block/by-name/vbmeta_a
''',
    "errors_start": "date; dmesg | grep -Ei 'SIGSYS|blocked syscall|atfwd|qesdk|temp_aware' | tail -n 120; logcat -b all -d -v threadtime -t 5000 | grep -Ei 'libminijail|SIGSYS|blocked syscall|atfwd|qesdk' | tail -n 100",
    "memory_details_start": "date; dumpsys meminfo; echo WALLPAPER; dumpsys meminfo -s com.miui.miwallpaper; dumpsys wallpaper | grep -E 'mWallpaperComponent|mWidth=|mHeight='",
    "policy_and_bindings": "date; dumpsys activity settings; device_config list lmkd_native; settings get global cached_apps_freezer; cat /proc/sys/vm/swappiness /proc/sys/vm/page-cluster; dumpsys activity services com.facebook.orca; dumpsys activity services com.mi.globalminusscreen; dumpsys activity services com.microsoft.appmanager; pm list packages --user 0",
    "camera_codec": "date; dumpsys media.camera | head -n 40; dumpsys audio | grep -m 1 mAudioModeOwner; dumpsys media.resource_manager | head -n 150; dumpsys thermalservice | head -n 130",
    "frame_start": "date; dumpsys gfxinfo com.zhiliaoapp.musically; dumpsys gfxinfo com.android.systemui",
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--workload", required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    receipt = {"serial": args.serial, "workload_owner_selected": args.workload,
               "read_only": True, "commands": {}}

    def capture(name, command, timeout=35):
        entry = {"command": command, "utc_start": datetime.now(timezone.utc).isoformat()}
        receipt["commands"][name] = entry
        try:
            result = subprocess.run(["adb", "-s", args.serial, "exec-out", "su -c " + shlex.quote(command)], capture_output=True, timeout=timeout)
            data = result.stdout
            entry.update(returncode=result.returncode, stderr=result.stderr.decode(errors="replace"))
        except subprocess.TimeoutExpired as exc:
            data = exc.stdout or b""
            entry["error"] = "timeout; partial data only"
        entry["utc_end"] = datetime.now(timezone.utc).isoformat()
        (args.out / (name + ".txt")).write_bytes(data)
        (args.out / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
        return data.decode(errors="replace")

    identity = capture("identity", "getprop ro.product.device; getprop ro.build.version.incremental; id")
    if identity.splitlines()[0].strip() != "peridot" or "uid=0" not in identity:
        raise RuntimeError("Expected rooted owner peridot")
    capture("sample_0", SNAPSHOT)
    for name, command in DETAILS.items():
        capture(name, command)
        print(name, flush=True)
    for index in range(1, 5):
        if index > 1:
            time.sleep(10)
        capture(f"sample_{index}", SNAPSHOT)
        print(f"sample_{index}", flush=True)
    capture("errors_end", DETAILS["errors_start"])
    capture("frame_end", DETAILS["frame_start"])
    capture("wallpaper_end", "date; dumpsys meminfo -s com.miui.miwallpaper; dumpsys wallpaper | grep -E 'mWallpaperComponent|mWidth=|mHeight='")
    capture("top_end", "top -b -n 1 -m 18; getprop sys.boot_completed; getenforce")
    print(args.out.resolve())


if __name__ == "__main__":
    main()
