#!/usr/bin/env python3
"""Exact RI3 ARM64 read-only verification. No production install entry is invoked."""
from pathlib import Path
import argparse,datetime,difflib,hashlib,json,os,re,resource,selectors,shutil,signal,stat,subprocess,sys,time
ROOT=Path(__file__).resolve().parents[4]
WORK=ROOT/"builder/work/installer-ri3-native/final-arm64"
ROM=ROOT/"builder/work/installer-ri3-package/F6-Global-HyperOS4-DEV2-RI3-20261003.zip"
ROM_SHA="fc466f7326b455b8df2f500fcdeefae5ef5b96a6c8e7afb86529af2f04c6b896"
ROM_SIZE=9710127062
NATIVE=ROOT/"builder/work/installer-ri3-native/runtime-integration/android-release-20261003T1018/update-binary"
NATIVE_SHA="04eb94933170c8d5de0345860ffa18b3d8c0a677ad32eeebcdb770fefffb871c"
EDIFY=ROOT/"tools/installer-ri3/native-updater/runtime/updater-script"
EDIFY_SHA="4d485206947acf128a0d418d74010376ea6604e0396330222ab49aa762c7f64c"
JAIL_SOURCE=ROOT/"tools/installer-ri3/arm64-harness/jail.c"
JAIL_SHA="e01ae304a7958ff123e2da5c342811264091243308a1d66340924510d5e141f0"
QEMU=ROOT/"builder/work/installer-ri3-qemu/crypto-readonly-20261003T0530/qemu-aarch64-static"
QEMU_SHA="e4f8d99e9ff69c3cefffab71cee358ce2af1ecba1282d04c3eeb44ef76f5a71e"
TINY=ROOT/"builder/work/installer-ri3-native/runtime-fixture/fixture-signed.zip"
TINY_SHA="2a0eb42179215f9bb2b2e1e4b4932326c0d8699a1d454d54248795aedb1379fe"
CPU_SECONDS=7200
WALL_SECONDS=9000
AS_BYTES=24*1024**3
STDOUT_CAP=1024**2
STDERR_CAP=256*1024**2
OUT=None
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def put(path,value):
    tmp=path.with_name(path.name+".next")
    tmp.write_text(json.dumps(value,indent=2)+"\n")
    tmp.replace(path)
def progress(phase,**fields):
    put(OUT/"progress.json",dict(phase=phase,updated=now(),runner_pid=os.getpid(),**fields))
def identity(path):
    s=path.lstat()
    if not stat.S_ISREG(s.st_mode):raise RuntimeError("regular file required: "+str(path))
    return dict(device=s.st_dev,inode=s.st_ino,bytes=s.st_size,mtime_ns=s.st_mtime_ns,ctime_ns=s.st_ctime_ns)
def digest(path,phase="hash"):
    before=identity(path);h=hashlib.sha256();done=0;report=0
    with path.open("rb") as f:
        for block in iter(lambda:f.read(1024**2),b""):
            h.update(block);done+=len(block)
            if done>=report:
                progress(phase,path=str(path.relative_to(ROOT)),bytes_done=done,bytes_total=before["bytes"])
                report=done+256*1024**2
    if identity(path)!=before:raise RuntimeError("file identity changed while hashing: "+str(path))
    return h.hexdigest()
def checked(path,wanted):
    value=digest(path,"verify_input")
    if value!=wanted:raise RuntimeError("input hash mismatch: "+str(path))
    return value
def copy_small(source,destination):
    if identity(source)["bytes"]>64*1024**2:raise RuntimeError("large copy forbidden")
    with source.open("rb") as a,destination.open("xb") as b:shutil.copyfileobj(a,b,1024**2)
def inventory(root,phase):
    result={}
    for p in sorted(root.rglob("*")):
        s=p.lstat()
        if stat.S_ISDIR(s.st_mode):
            if p.name in ("dev","proc"):raise RuntimeError("device/proc directory forbidden")
            continue
        if not stat.S_ISREG(s.st_mode):raise RuntimeError("nonregular jail input")
        result[str(p.relative_to(root))]=dict(identity=identity(p),sha256=digest(p,phase))
    return result
def prepare():
    OUT.mkdir(parents=True,exist_ok=False);(OUT/"tmp").mkdir();root=OUT/"root";root.mkdir()
    for k in ("TMPDIR","TMP","TEMP","HOME","XDG_CACHE_HOME"):os.environ[k]=str(OUT/"tmp")
    checked(JAIL_SOURCE,JAIL_SHA);checked(NATIVE,NATIVE_SHA);checked(EDIFY,EDIFY_SHA);checked(QEMU,QEMU_SHA);checked(TINY,TINY_SHA)
    if identity(ROM)["bytes"]!=ROM_SIZE:raise RuntimeError("ROM size mismatch")
    if ROM.stat().st_dev!=root.stat().st_dev:raise RuntimeError("hardlink requires the same filesystem")
    original=JAIL_SOURCE.read_text()
    a="cpu={20,20}"
    b="cpu={7200,7200},address={(rlim_t)24*1024*1024*1024,(rlim_t)24*1024*1024*1024}"
    c='setrlimit(RLIMIT_CORE,&core)||setrlimit(RLIMIT_CPU,&cpu)'
    d=c+'||setrlimit(RLIMIT_AS,&address)'
    if original.count(a)!=1 or original.count(c)!=1:raise RuntimeError("unexpected jail resource block")
    patched=original.replace(a,b).replace(c,d)
    source=OUT/"jail.c";source.write_text(patched)
    diff="".join(difflib.unified_diff(original.splitlines(True),patched.splitlines(True),fromfile="verified/jail.c",tofile="final-budget/jail.c"))
    (OUT/"jail-budget.diff").write_text(diff)
    command=["/usr/bin/clang","-O2","-Wall","-Wextra","-Werror",str(source),"-o",str(OUT/"ri3-final-file-jail")]
    p=subprocess.run(command,capture_output=True,timeout=45)
    put(OUT/"compile.json",dict(argv=command,rc=p.returncode,stdout=p.stdout.decode(errors="replace"),stderr=p.stderr.decode(errors="replace")))
    if p.returncode:raise RuntimeError("jail compilation failed")
    copy_small(QEMU,root/"qemu-aarch64-static");copy_small(NATIVE,root/"update-binary")
    os.chmod(root/"qemu-aarch64-static",0o755);os.chmod(root/"update-binary",0o755)
    copy_small(TINY,root/"tiny-signed.zip")
    data=bytearray(TINY.read_bytes());data[-7]^=1
    with (root/"tiny-tampered.zip").open("xb") as f:f.write(data)
    os.link(ROM,root/"rom.zip",follow_symlinks=False)
    # Never chmod the ROM hardlink: that would change the original inode.
    if not os.path.samefile(ROM,root/"rom.zip"):raise RuntimeError("ROM was not hardlinked")
    before=inventory(root,"prepared_input_hash")
    if before["rom.zip"]["sha256"]!=ROM_SHA:raise RuntimeError("staged ROM hash mismatch")
    receipt=dict(prepared=now(),script_sha256=digest(Path(__file__)),rom=str(ROM.relative_to(ROOT)),rom_bytes=ROM_SIZE,rom_sha256=ROM_SHA,
        native_sha256=NATIVE_SHA,script_pin=EDIFY_SHA,qemu_sha256=QEMU_SHA,original_jail_source_sha256=JAIL_SHA,
        modified_jail_source_sha256=digest(source),jail_sha256=digest(OUT/"ri3-final-file-jail"),budget_diff=diff,
        budgets=dict(cpu_seconds=CPU_SECONDS,wall_seconds=WALL_SECONDS,address_space_bytes=AS_BYTES,stdout_cap=STDOUT_CAP,stderr_cap=STDERR_CAP),
        hardlink=True,rom_original_mode=stat.S_IMODE(ROM.stat().st_mode),inputs=before,
        isolation="Unchanged user/mount/network/PID/IPC namespaces; chroot; readonly Landlock ABI>=5; capabilities dropped; original seccomp; no dev/proc")
    put(OUT/"prepared.json",receipt);progress("prepared",rom_sha256=ROM_SHA,native_sha256=NATIVE_SHA)
    print(json.dumps(dict(prepared=str(OUT/"prepared.json"),jail_sha256=receipt["jail_sha256"],rom_sha256=ROM_SHA)),flush=True)
def own_process_stats(pid):
    pending=[pid];seen=set();cpu=0.0;rss=0;anon=0
    ticks=os.sysconf("SC_CLK_TCK")
    while pending and len(seen)<16:
        current=pending.pop()
        if current in seen:continue
        seen.add(current)
        try:
            text=Path(f"/proc/{current}/stat").read_text();fields=text[text.rindex(")")+2:].split()
            cpu+=(int(fields[11])+int(fields[12]))/ticks
            rss+=int(fields[21])*os.sysconf("SC_PAGE_SIZE")
            for line in Path(f"/proc/{current}/status").read_text().splitlines():
                if line.startswith("RssAnon:"):anon+=int(line.split()[1])*1024
            pending.extend(map(int,Path(f"/proc/{current}/task/{current}/children").read_text().split()))
        except (FileNotFoundError,ProcessLookupError,PermissionError,ValueError):pass
    return dict(cpu_seconds_observed=round(cpu,3),rss_bytes_observed=rss,anonymous_rss_bytes_observed=anon,pids_observed=sorted(seen))
def run_case(name,args,expected_rc,needle,global_deadline,caps):
    root=OUT/"root";prefix=["/usr/bin/unshare","--user","--map-root-user","--mount","--net","--pid","--fork","--kill-child","--ipc","--propagation","unchanged",
        str(OUT/"ri3-final-file-jail"),str(root),"/qemu-aarch64-static","-strace","/update-binary"]
    command=prefix+args;start=time.monotonic();deadline=min(global_deadline,start+(WALL_SECONDS if name=="verify_exact_signed_rom" else 120))
    p=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,bufsize=0)
    selector=selectors.DefaultSelector();streams={};sizes={"stdout":0,"stderr":0};hashes={k:hashlib.sha256() for k in sizes};problem=None;kill_started=None;peak_rss=0;peak_anon=0;last_report=0
    for key,pipe in (("stdout",p.stdout),("stderr",p.stderr)):
        os.set_blocking(pipe.fileno(),False);selector.register(pipe,selectors.EVENT_READ,key);streams[key]=(OUT/(name+"."+key+".log")).open("xb")
    admitted=dict(case=name,argv=command,started=now(),host_process_pid=p.pid,expected_rc=expected_rc,wall_limit_seconds=deadline-start)
    put(OUT/(name+"-admitted.json"),admitted)
    try:
        while selector.get_map():
            current=time.monotonic()
            if current>=deadline and problem is None:problem="wall deadline exceeded"
            if problem and kill_started is None:
                kill_started=current
                if p.poll() is None:os.killpg(p.pid,signal.SIGKILL)
            for key,_ in selector.select(timeout=1):
                try:chunk=os.read(key.fileobj.fileno(),65536)
                except BlockingIOError:continue
                if not chunk:
                    selector.unregister(key.fileobj);key.fileobj.close();continue
                stream=key.data;sizes[stream]+=len(chunk);caps[stream]+=len(chunk);hashes[stream].update(chunk)
                cap=STDOUT_CAP if stream=="stdout" else STDERR_CAP
                if caps[stream]>cap:problem=stream+" log cap exceeded"
                # All retained output is bounded, and over-limit output fails the case.
                if sizes[stream]<=cap:streams[stream].write(chunk)
            if current-last_report>=5:
                measured=own_process_stats(p.pid);peak_rss=max(peak_rss,measured["rss_bytes_observed"]);peak_anon=max(peak_anon,measured["anonymous_rss_bytes_observed"])
                progress("running",case=name,host_process_pid=p.pid,elapsed_seconds=round(current-start,3),log_bytes=sizes,problem=problem,**measured);last_report=current
            if kill_started is not None and time.monotonic()>kill_started+10:break
        if p.poll() is None and problem:os.killpg(p.pid,signal.SIGKILL)
        rc=p.wait(timeout=10)
    except BaseException:
        if p.poll() is None:os.killpg(p.pid,signal.SIGKILL)
        try:p.wait(timeout=10)
        except subprocess.TimeoutExpired:pass
        raise
    finally:
        selector.close()
        for stream in streams.values():stream.flush();stream.close()
        for pipe in (p.stdout,p.stderr):
            if not pipe.closed:pipe.close()
    stdout=(OUT/(name+".stdout.log")).read_bytes()
    stderr_path=OUT/(name+".stderr.log")
    found=False;device_open_success=[];write_fd_success=[];forbidden_success=[]
    with stderr_path.open("rb") as f:
        for raw in f:
            line=raw.decode(errors="replace")
            if needle and needle in line:found=True
            if re.search(r'\b(?:open|openat)\([^\n]*"/dev/[^\n]*\)\s*=\s*[0-9]+',line):device_open_success.append(line[:512])
            if re.search(r'\b(?:write|pwrite64|writev)\(([3-9]|[1-9][0-9]+),[^\n]*\)\s*=\s*[1-9][0-9]*',line):write_fd_success.append(line[:512])
            if re.search(r'\b(?:mount|umount2|unlink|unlinkat|rename|renameat|mkdir|mknod|truncate|ftruncate)\([^\n]*\)\s*=\s*0',line):forbidden_success.append(line[:512])
    if expected_rc==0:found=stdout==b"RI3_READONLY_PAYLOADS_AND_EDIFY_VERIFIED\n"
    else:found=found and b"RI3_READONLY_PAYLOADS_AND_EDIFY_VERIFIED" not in stdout
    passed=problem is None and rc==expected_rc and found and not device_open_success and not write_fd_success and not forbidden_success
    result=dict(**admitted,finished=now(),elapsed_seconds=round(time.monotonic()-start,3),rc=rc,passed=passed,limit_error=problem,expected_marker_or_error=needle,
        expected_output_observed=found,stdout_bytes=sizes["stdout"],stderr_bytes=sizes["stderr"],
        stdout_sha256=hashes["stdout"].hexdigest(),stderr_sha256=hashes["stderr"].hexdigest(),peak_sampled_rss_bytes=peak_rss,peak_sampled_anonymous_rss_bytes=peak_anon,
        successful_device_opens=device_open_success,successful_data_writes=write_fd_success,successful_mutations=forbidden_success)
    put(OUT/(name+"-result.json"),result);print(json.dumps(result),flush=True)
    return result
def run():
    prepared=json.loads((OUT/"prepared.json").read_text())
    checked(OUT/"ri3-final-file-jail",prepared["jail_sha256"]);checked(Path(__file__),prepared["script_sha256"])
    if stat.S_IMODE(ROM.stat().st_mode)!=prepared["rom_original_mode"]:raise RuntimeError("ROM mode changed")
    before=inventory(OUT/"root","before_execution_hash")
    if before!=prepared["inputs"]:raise RuntimeError("prepared inputs changed")
    cases=[
        ("reject_tampered_signature",["--verify-rom","/tiny-tampered.zip"],8,"Fixed-key PKCS1-v1_5 SHA256 signature rejected"),
        ("reject_fixture_payload",["--verify-rom","/tiny-signed.zip"],8,"expanded sparse size mismatch"),
        ("reject_fixture_cli",["--fixture"],2,"Usage: update-binary"),
        ("verify_exact_signed_rom",["--verify-rom","/rom.zip"],0,"RI3_READONLY_PAYLOADS_AND_EDIFY_VERIFIED")]
    deadline=time.monotonic()+WALL_SECONDS;caps={"stdout":0,"stderr":0};results=[]
    for case in cases:
        result=run_case(*case,deadline,caps);results.append(result)
        if not result["passed"]:break
    after=inventory(OUT/"root","after_execution_hash")
    unchanged=before==after
    if digest(ROM,"final_original_zip_hash")!=ROM_SHA:unchanged=False
    passed=unchanged and len(results)==len(cases) and all(x["passed"] for x in results)
    receipt=dict(completed=now(),passed=passed,rom=str(ROM.relative_to(ROOT)),rom_bytes=ROM_SIZE,rom_sha256=ROM_SHA,native_sha256=NATIVE_SHA,script_pin=EDIFY_SHA,
        prepared_sha256=digest(OUT/"prepared.json"),jail_sha256=prepared["jail_sha256"],jail_source_sha256=prepared["modified_jail_source_sha256"],
        qemu_sha256=QEMU_SHA,budgets=prepared["budgets"],input_hashes_before=before,input_hashes_after=after,inputs_unchanged=unchanged,
        completed_cases=len(results),required_cases=len(cases),cases=results,device_backend_invoked=False,
        scope="Exact activated ARM64 updater under QEMU in read-only no-device jail; signed real ZIP and payload hashes plus Edify parse. No physical flash/boot/FBE/rollback/OEM trust validation.")
    put(OUT/"result.json",receipt);progress("completed",passed=passed,completed_cases=len(results),rom_sha256=ROM_SHA)
    print(json.dumps(dict(result=str(OUT/"result.json"),passed=passed,completed_cases=len(results),rom_sha256=ROM_SHA)),flush=True)
    return 0 if passed else 1
def main():
    global OUT
    ap=argparse.ArgumentParser();ap.add_argument("--phase",choices=("prepare","run"),required=True);ap.add_argument("--label",required=True);a=ap.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9_-]+",a.label):raise ValueError("invalid label")
    OUT=WORK/a.label
    if a.phase=="prepare":prepare();return 0
    for k in ("TMPDIR","TMP","TEMP","HOME","XDG_CACHE_HOME"):os.environ[k]=str(OUT/"tmp")
    return run()
if __name__=="__main__":
    try:sys.exit(main())
    except Exception as error:
        if OUT and OUT.is_dir():
            put(OUT/"failure.json",dict(time=now(),error=repr(error)))
            progress("failed",error=repr(error))
        raise
