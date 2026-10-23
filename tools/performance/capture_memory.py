"""Read-only, explicitly targeted Android memory capture. No app or VM changes."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import shlex
import subprocess
import time


COMMANDS = {
    "identity": "date; uptime; getprop ro.product.device; getprop ro.build.version.incremental; getprop ro.build.fingerprint; uname -a; getenforce; dumpsys battery",
    "meminfo": "dumpsys meminfo",
    "processes": "ps -A -o PID,PPID,USER,NI,PRI,VSZ,RSS,NAME; ps -A -T -o PID,TID,NAME | wc -l; top -b -n 1 -m 25",
    "process_memory": r'''for p in /proc/[0-9]*; do
        [ -r "$p/smaps_rollup" ] || continue
        printf '\nPID %s ' "${p##*/}"
        tr '\000' ' ' < "$p/cmdline"; echo
        grep -E '^(Name|Threads|VmPTE|VmSwap):' "$p/status"
        cat "$p/oom_score_adj"
        grep -E '^(Rss|Pss|Pss_Anon|Pss_File|Pss_Shmem|Swap|SwapPss):' "$p/smaps_rollup"
    done''',
    "kernel_memory": "cat /proc/meminfo; cat /proc/slabinfo; cat /proc/buddyinfo; cat /proc/pagetypeinfo; cat /sys/kernel/dma_heap/total_pools_kb; cat /sys/kernel/dmabuf/buffers/*/size 2>/dev/null",
    "swap_config": "cat /proc/swaps; for f in /sys/block/zram0/{disksize,comp_algorithm,mm_stat,io_stat,bd_stat,backing_dev,mem_limit,writeback_limit,writeback_limit_enable}; do echo FILE:$f; cat $f; done; for n in swappiness page-cluster watermark_scale_factor min_free_kbytes extra_free_kbytes vfs_cache_pressure; do echo VM:$n; cat /proc/sys/vm/$n; done; getprop | grep -Ei 'lmk|zram|swap|memory|low_ram|heap|preload|memplus|per_app_memcg'; device_config list activity_manager; settings list global | grep -Ei 'memory|ram|swap|cached|background|process_limit'; dumpsys activity settings",
    "lmk_events": "logcat -b all -d -v threadtime -t 5000 | grep -Ei 'lmkd|lowmemorykiller|am_kill|am_low_memory|am_anr|thrash|swap.*fail|Out of memory' | tail -n 220; dmesg | grep -Ei 'oom|out of memory|lowmemory|blocked syscall|SIGSYS' | tail -n 120",
    "services": "getprop | grep -E 'init.svc.*(restarting|atfwd|qesdk)'; dumpsys media.camera | head -n 16; dumpsys audio | grep -m 1 mAudioModeOwner; dumpsys activity processes; dumpsys activity services com.facebook.orca; dumpsys activity services com.microsoft.appmanager; dumpsys -l | grep -Ei 'memory|process|perf|power'",
    "modules": "for d in /data/adb/modules/*; do echo MODULE:$d; cat $d/module.prop; ls $d/disable $d/remove 2>/dev/null; done; ps -A -o PID,PPID,ARGS | grep -E 'perfetto|traced|camera|kswapd'; cat /proc/sys/kernel/perf_event_paranoid",
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--interval", type=float, default=15)
    args = parser.parse_args()
    if args.interval < 1:
        parser.error("--interval must be at least 1 second")
    args.out.mkdir(parents=True, exist_ok=False)
    receipts = {}

    def capture(name, command, timeout=60):
        started = datetime.now(timezone.utc).isoformat()
        try:
            result = subprocess.run(
                ["adb", "-s", args.serial, "exec-out", "su -c " + shlex.quote(command)],
                capture_output=True, timeout=timeout,
            )
            (args.out / (name + ".txt")).write_bytes(result.stdout)
            receipts[name] = {"started_utc": started, "command": command,
                              "returncode": result.returncode,
                              "stderr": result.stderr.decode(errors="replace")}
        except subprocess.TimeoutExpired as exc:
            (args.out / (name + ".txt")).write_bytes(exc.stdout or b"")
            receipts[name] = {"started_utc": started, "command": command, "error": "timeout"}
        (args.out / "capture.json").write_text(json.dumps(receipts, indent=2) + "\n", encoding="utf-8")

    metrics = "date; cat /proc/uptime; cat /proc/meminfo; cat /proc/vmstat; for p in cpu memory io; do echo PSI:$p; cat /proc/pressure/$p; done; cat /sys/block/zram0/mm_stat"
    for name, command in COMMANDS.items():
        capture(name, command)
        print(name, receipts[name].get("returncode", receipts[name].get("error")), flush=True)
    for index in range(3):
        if index:
            time.sleep(args.interval)
        capture(f"sample_{index}", metrics)
    print(args.out.resolve())


if __name__ == "__main__":
    main()
