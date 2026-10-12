#!/usr/bin/env python3
"""Read-only host capability survey; this never invokes the updater or emulator."""
import ctypes, hashlib, json, os, pathlib, platform, shutil, subprocess, sys
ROOT=pathlib.Path(__file__).resolve().parents[3]
REPORT=ROOT/"09-reports/installer-ri3/arm64-harness"
WORK=ROOT/"builder/work/installer-ri3-qemu"
for p in (REPORT,WORK/"tmp",WORK/"home",WORK/"cache"):p.mkdir(parents=True,exist_ok=True)
env={"PATH":"/usr/bin:/bin","HOME":str(WORK/"home"),"TMPDIR":str(WORK/"tmp"),"TMP":str(WORK/"tmp"),"TEMP":str(WORK/"tmp"),"XDG_CACHE_HOME":str(WORK/"cache"),"LANG":"C"}
r={"kernel":platform.release(),"machine":platform.machine(),"uid":os.getuid(),"cwd":str(ROOT),
   "tools":{x:shutil.which(x) for x in ("bwrap","unshare","setpriv","qemu-aarch64","qemu-aarch64-static","gpgv","curl","python3","dpkg-deb")},
   "target_executed":False,"mount_performed":False,"host_settings_changed":False}
key=pathlib.Path("/usr/share/keyrings/ubuntu-archive-keyring.gpg")
r["ubuntu_keyring"]={"path":str(key),"sha256":hashlib.sha256(key.read_bytes()).hexdigest()} if key.is_file() else None
for p in ("/proc/sys/user/max_user_namespaces","/proc/sys/kernel/unprivileged_userns_clone","/proc/sys/kernel/apparmor_restrict_unprivileged_userns"):
    try:r[p]=pathlib.Path(p).read_text().strip()
    except FileNotFoundError:r[p]=None
try:
    q=subprocess.run(["/usr/bin/unshare","--user","--map-root-user","--mount","--propagation","unchanged","--net","--ipc","--pid","--fork","/bin/true"],env=env,cwd=ROOT,capture_output=True,text=True,timeout=10)
    r["ephemeral_namespace_probe"]={"returncode":q.returncode,"stdout":q.stdout,"stderr":q.stderr}
except subprocess.TimeoutExpired:r["ephemeral_namespace_probe"]={"timeout":True}
c=ctypes.CDLL(None,use_errno=True)
abi=c.syscall(444,0,0,1)
r["landlock_abi"]={"result":abi,"errno":ctypes.get_errno()}
out=REPORT/"capabilities.json";out.write_text(json.dumps(r,indent=2)+"\n")
print(json.dumps(r,indent=2),flush=True)
