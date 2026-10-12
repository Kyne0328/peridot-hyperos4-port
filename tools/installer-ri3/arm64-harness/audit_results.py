#!/usr/bin/env python3
"""Audit already-recorded guest traces; this never executes the target."""
import collections,hashlib,json,pathlib,re
ROOT=pathlib.Path(__file__).resolve().parents[3]
REPORT=ROOT/"09-reports/installer-ri3/arm64-harness"
source=REPORT/"arm64-results.json"
r=json.loads(source.read_text())
assert r["status"]=="passed" and r["passed"]==r["total"]==r["expected_cases"]==44 and r["root_unchanged"]
audit={"status":"incomplete","results_sha256":hashlib.sha256(source.read_bytes()).hexdigest(),"trace_scope":"QEMU guest syscall traces, not complete host-kernel traces","cases":44,"successful_opens":[],"device_path_attempts":[],"write_destination_anomalies":[],"mutation_syscalls":[],"api_early_abort":[],"unknown_syscalls":[]}
mutation={"mount","umount2","pivot_root","chroot","unlink","unlinkat","rename","renameat","renameat2","mkdir","mkdirat","mknod","mknodat","symlink","symlinkat","link","linkat","truncate","ftruncate","chmod","fchmod","fchmodat","chown","fchown","lchown","fchownat","setxattr","fsetxattr","lsetxattr"}
for row in r["results"]:
    fds={0:"stdin pipe",1:"stdout pipe",2:"stderr pipe"};opened=[]
    for line in row["stderr"].splitlines():
        syscall=re.match(r"^\d+ ([a-zA-Z_0-9]+)\(",line)
        if not syscall:
            if "Unknown syscall" in line:audit["unknown_syscalls"].append({"case":row["name"],"line":line})
            continue
        op=syscall[1]
        if "/dev/" in line:audit["device_path_attempts"].append({"case":row["name"],"line":line,"denied_enoent":" = -1 errno=2 " in line})
        if op in mutation:audit["mutation_syscalls"].append({"case":row["name"],"line":line})
        m=re.match(r"^\d+ (?:open|openat|creat)\(.*?\"([^\"]+)\".*\) = (-?\d+)(?: |$)",line)
        if m:
            path,fd=m[1],int(m[2])
            if fd>=0:
                entry={"case":row["name"],"path":path,"fd":fd,"line":line}
                audit["successful_opens"].append(entry);opened.append(path);fds[fd]="regular:"+path
                if not path.startswith("/fixtures/") or any(x in line for x in ("O_WRONLY","O_RDWR","O_CREAT","O_TRUNC")):audit["write_destination_anomalies"].append(entry)
        m=re.match(r"^\d+ dup\((\d+)\) = (\d+)",line)
        if m:fds[int(m[2])]=fds.get(int(m[1]),"unknown")
        m=re.match(r"^\d+ close\((\d+)\) = 0",line)
        if m:fds.pop(int(m[1]),None)
        m=re.match(r"^\d+ (?:write|writev|pwrite64|pwritev|pwritev2)\((\d+),",line)
        if m and fds.get(int(m[1]),"unknown") not in ("stdout pipe","stderr pipe"):
            audit["write_destination_anomalies"].append({"case":row["name"],"destination":fds.get(int(m[1]),"unknown"),"line":line})
    if row["name"].startswith("API "):
        audit["api_early_abort"].append({"case":row["name"],"returncode":row["returncode"],"package_open_count":len(opened),"passed":row["returncode"]==80 and not opened})
audit["device_path_attempts_count"]=len(audit["device_path_attempts"])
audit["all_device_path_attempts_returned_ENOENT"]=all(x["denied_enoent"] for x in audit["device_path_attempts"])
audit["successful_device_opens"]=sum(x["path"].startswith("/dev/") for x in audit["successful_opens"])
audit["status"]="passed" if not audit["write_destination_anomalies"] and not audit["mutation_syscalls"] and audit["all_device_path_attempts_returned_ENOENT"] and len(audit["api_early_abort"])==3 and all(x["passed"] for x in audit["api_early_abort"]) else "failed"
(REPORT/"trace-audit.json").write_text(json.dumps(audit,indent=2)+"\n")
print(json.dumps({k:v for k,v in audit.items() if k not in ("successful_opens","device_path_attempts")},indent=2))
if audit["status"]!="passed":raise SystemExit(1)
