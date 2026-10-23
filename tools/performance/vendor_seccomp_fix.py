"""Guarded, reversible two-file peridot seccomp repair; never flashes partitions."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import time
import zipfile

MODULE = "kyneos_vendor_seccomp_fix"
REMOTE = "/data/adb/kyneos_vendor_seccomp_fix_20261016"
POLICIES = {
    "atfwd@2.0.policy": ("ed4f8abfaf93e828759d8783831f4ae90145cf400843071859b224cae4802056", "9f7a4c41be28dac0e6fdb71ea10d9be34fa88eadd2e82afb2f0488afa701363f"),
    "qesdksec.policy": ("c071ae4c25381ee4f74501b018c6edfd9be122c5222667983dee687ef41c6bc7", "3857e582a277c5fe9e8d699056013193eb2f0e4f25c24331b2778f3f1089ba51"),
}
SAMPLE = r'''date; cat /proc/uptime; getenforce
for svc in vendor.atfwd vendor.qesdk-securitymgr; do
 echo SERVICE:$svc
 getprop init.svc.$svc
 pid=$(getprop init.svc_debug_pid.$svc)
 echo PID:$pid
 if [ -n "$pid" ] && [ -r /proc/$pid/status ]; then
  cat /proc/$pid/stat
  grep -E '^(Name|Uid|Gid|NoNewPrivs|Seccomp|Seccomp_filters|VmRSS|VmSwap|Threads|CapEff):' /proc/$pid/status
  cat /proc/$pid/attr/current
 fi
done
echo MEMORY; grep -E '^(MemAvailable|MemFree|SwapFree):' /proc/meminfo
cat /proc/pressure/memory
echo RADIO; getprop gsm.sim.state; getprop gsm.network.type
echo CORE; pidof system_server com.android.systemui com.miui.home
'''


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "apply", "stage", "monitor", "rollback"))
    parser.add_argument("--serial", required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--minutes", type=float, default=31)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    log = args.out / (args.action + "-commands.json")
    operations = []

    def save():
        log.write_text(json.dumps(operations, indent=2) + "\n", encoding="utf-8")

    def shell(name, command, timeout=30):
        entry = {"name": name, "command": command, "utc": datetime.now(timezone.utc).isoformat()}
        operations.append(entry)
        save()
        try:
            r = subprocess.run(["adb", "-s", args.serial, "exec-out", "su -c " + shlex.quote(command)], capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            entry["uncertain_timeout"] = True
            save()
            (args.out / (name + ".txt")).write_bytes(exc.stdout or b"")
            raise RuntimeError("Timed out: reconcile state; do not replay mutation automatically") from exc
        (args.out / (name + ".txt")).write_bytes(r.stdout)
        entry.update(returncode=r.returncode, stderr=r.stderr.decode(errors="replace"))
        save()
        if r.returncode:
            raise RuntimeError(name + ": " + r.stdout.decode(errors="replace")[-1200:] + r.stderr.decode(errors="replace")[-500:])
        return r.stdout

    identity = shell("identity_" + args.action, "getprop ro.product.device; getprop ro.build.version.sdk; getenforce; id")
    if identity.splitlines()[:3] != [b"peridot", b"37", b"Enforcing"] or b"uid=0" not in identity:
        raise RuntimeError("Expected peridot SDK37, root and enforcing")

    if args.action == "prepare":
        files = {}
        manifest = {}
        for name, (old, new) in POLICIES.items():
            data = shell("original_" + name, "cat /vendor/etc/seccomp_policy/" + shlex.quote(name))
            if sha(data) != old or data.count(b"\npread64: 1\n") != 1 or b"lseek:" in data:
                raise RuntimeError("Original policy drift: " + name)
            patched = data.replace(b"\npread64: 1\n", b"\npread64: 1\nlseek: 1\n", 1)
            if sha(patched) != new or patched.replace(b"lseek: 1\n", b"", 1) != data:
                raise RuntimeError("Unexpected patch: " + name)
            (args.out / name).write_bytes(patched)
            files["system/vendor/etc/seccomp_policy/" + name] = patched
            manifest[name] = {"old_sha256": old, "new_sha256": new}
        files["module.prop"] = ("id=" + MODULE + "\nname=KyneOS Qualcomm Vendor Seccomp Repair\nversion=1.0\nversionCode=1\nauthor=KyneOS\ndescription=Peridot SDK37: adds only lseek to atfwd and qesdk seccomp policies; sandbox retained.\n").encode()
        customize = ["#!/system/bin/sh", "[ \"$(getprop ro.product.device)\" = peridot ] || abort 'Wrong device'", "[ \"$(getprop ro.build.version.sdk)\" = 37 ] || abort 'Wrong SDK'", "[ -d /data/adb/modules/meta-overlayfsx ] && [ ! -e /data/adb/modules/meta-overlayfsx/disable ] || abort 'Expected active OverlayFS Enhanced metamodule'" ]
        for name, (old, new) in POLICIES.items():
            path = "/vendor/etc/seccomp_policy/" + name
            customize += [f"current=$(sha256sum '{path}' | cut -d ' ' -f 1)", f"[ \"$current\" = '{old}' ] || [ \"$current\" = '{new}' ] || abort 'Unexpected {name}'", f"set_perm \"$MODPATH/system/vendor/etc/seccomp_policy/{name}\" 0 0 0644 u:object_r:vendor_configs_file:s0"]
        customize += ["ui_print '- Only two lseek policy additions staged; next-boot activation must be checked'"]
        files["customize.sh"] = ("\n".join(customize) + "\n").encode()
        files["README.txt"] = b"Two hash-pinned lseek additions only. No SELinux rule or thermal/kernel change. Disable module and reboot to undo next-boot overlay. Current live bind mounts are separate; use owner rollback script to undo them. No daemon or privileged file mutation from module scripts.\n"
        zpath = args.out / "KyneOS-Vendor-Seccomp-Repair-v1.zip"
        with zipfile.ZipFile(zpath, "x", compression=zipfile.ZIP_DEFLATED) as z:
            for name, data in files.items():
                info = zipfile.ZipInfo(name, date_time=(2026, 10, 16, 0, 0, 0))
                info.create_system = 3
                info.external_attr = (0o755 if name.endswith(".sh") else 0o644) << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                z.writestr(info, data)
        with zipfile.ZipFile(zpath) as z:
            assert z.testzip() is None and set(z.namelist()) == set(files)
            assert all(z.read(name) == data for name, data in files.items())
        (args.out / "manifest.json").write_text(json.dumps({"policies": manifest, "zip_sha256": sha(zpath.read_bytes()), "module_id": MODULE}, indent=2) + "\n", encoding="utf-8")
        print(zpath)

    elif args.action == "apply":
        shell("before_live", SAMPLE + "\ncat /proc/1/mountinfo; sha256sum /vendor/etc/seccomp_policy/{atfwd@2.0.policy,qesdksec.policy}")
        shell("create_backup_directory", f"[ ! -e '{REMOTE}' ] && mkdir -m 0700 '{REMOTE}' && mkdir -m 0700 '{REMOTE}/original' '{REMOTE}/patched'")
        for name, (old, new) in POLICIES.items():
            source = args.out / name
            if sha(source.read_bytes()) != new:
                raise RuntimeError("Local candidate drift")
            remote_tmp = "/data/local/tmp/kyneos-seccomp-" + name
            subprocess.run(["adb", "-s", args.serial, "push", str(source), remote_tmp], check=True, capture_output=True, timeout=30)
            command = f"set -e; [ \"$(sha256sum '/vendor/etc/seccomp_policy/{name}' | cut -d ' ' -f 1)\" = '{old}' ]; cp -p '/vendor/etc/seccomp_policy/{name}' '{REMOTE}/original/{name}'; cp '{remote_tmp}' '{REMOTE}/patched/{name}'; chown 0:0 '{REMOTE}/patched/{name}'; chmod 0644 '{REMOTE}/patched/{name}'; chcon u:object_r:vendor_configs_file:s0 '{REMOTE}/patched/{name}'; [ \"$(sha256sum '{REMOTE}/patched/{name}' | cut -d ' ' -f 1)\" = '{new}' ]; sha256sum '{REMOTE}/original/{name}' '{REMOTE}/patched/{name}'"
            shell("stage_live_" + name, command)
        rollback = ["#!/system/bin/sh", "set -e", "[ \"$(getprop ro.product.device)\" = peridot ] || exit 1"]
        for name, (old, new) in POLICIES.items():
            rollback += [f"test \"$(sha256sum '/vendor/etc/seccomp_policy/{name}' | cut -d ' ' -f 1)\" = '{new}'", f"umount '/vendor/etc/seccomp_policy/{name}'", f"test \"$(sha256sum '/vendor/etc/seccomp_policy/{name}' | cut -d ' ' -f 1)\" = '{old}'"]
        rollback += [f"if [ -d /data/adb/modules/{MODULE} ] || [ -d /data/adb/modules_update/{MODULE} ]; then /data/adb/ksu/bin/ksud module disable {MODULE}; fi", "echo 'Original policies restored; current processes retain prior seccomp filters until restarted or rebooted.'"]
        (args.out / "rollback.sh").write_text("\n".join(rollback) + "\n", encoding="utf-8", newline="\n")
        for name, (old, new) in POLICIES.items():
            command = f"set -e; [ \"$(readlink /proc/self/ns/mnt)\" = \"$(readlink /proc/1/ns/mnt)\" ]; [ -z \"$(awk '$5 == \"/vendor/etc/seccomp_policy/{name}\"' /proc/self/mountinfo)\" ]; mount -o bind '{REMOTE}/patched/{name}' '/vendor/etc/seccomp_policy/{name}'; [ \"$(sha256sum '/vendor/etc/seccomp_policy/{name}' | cut -d ' ' -f 1)\" = '{new}' ]; ls -lZ '/vendor/etc/seccomp_policy/{name}'"
            shell("bind_" + name, command)
        print("Two live file bind mounts applied; waiting for existing init retry cycle", flush=True)
        time.sleep(8)
        shell("after_live", SAMPLE + "\nsha256sum /vendor/etc/seccomp_policy/{atfwd@2.0.policy,qesdksec.policy}; dmesg | tail -n 100")
        print((args.out / "after_live.txt").read_text()[:2500])

    elif args.action == "stage":
        zpath = args.out / "KyneOS-Vendor-Seccomp-Repair-v1.zip"
        manifest = json.loads((args.out / "manifest.json").read_text())
        if sha(zpath.read_bytes()) != manifest["zip_sha256"]:
            raise RuntimeError("Module archive drift")
        remote_zip = "/data/local/tmp/KyneOS-Vendor-Seccomp-Repair-v1.zip"
        subprocess.run(["adb", "-s", args.serial, "push", str(zpath), remote_zip], check=True, capture_output=True, timeout=30)
        shell("install_module", f"set -e; [ \"$(sha256sum '{remote_zip}' | cut -d ' ' -f 1)\" = '{manifest['zip_sha256']}' ]; /data/adb/ksu/bin/ksud module install '{remote_zip}'", timeout=60)
        shell("module_readback", f"cat /data/adb/modules_update/{MODULE}/module.prop; sha256sum /data/adb/modules_update/{MODULE}/system/vendor/etc/seccomp_policy/*; /data/adb/ksu/bin/ksud module list")
        print("Module installed; next-boot activation remains untested")

    elif args.action == "monitor":
        if args.minutes < 1:
            raise ValueError("Monitor at least one minute")
        start = time.monotonic()
        sample = 0
        while True:
            shell(f"stability_{sample:03d}", SAMPLE)
            elapsed = time.monotonic() - start
            print(f"Stability sample {sample}; elapsed {elapsed:.1f}s", flush=True)
            if elapsed >= args.minutes * 60:
                break
            time.sleep(min(30, args.minutes * 60 - elapsed))
            sample += 1
        shell("stability_final_logs", "date; cat /proc/uptime; logcat -b all -d -v threadtime -t 9000 | grep -Ei 'libminijail|SIGSYS|atfwd|qesdk' | tail -n 160; dmesg | grep -E 'SIGSYS|avc:.*(atfwd|qesdk|vendor_configs_file)' | tail -n 60; getenforce")
        print("Monitor collection finished; analyze service PID/start-time continuity and seccomp state")

    else:
        script = (args.out / "rollback.sh").read_text()
        shell("rollback_live", script)
        shell("after_rollback", SAMPLE)


if __name__ == "__main__":
    main()
