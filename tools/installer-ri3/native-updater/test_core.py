#!/usr/bin/env python3
"""Host-only fixtures. Never opens a device or supplies an output destination to updater code."""
import hashlib,json,os,pathlib,struct,subprocess,sys,zipfile,warnings,shutil,argparse,datetime,re
ROOT=pathlib.Path(__file__).resolve().parents[3]
WORK=ROOT/"builder/work/installer-ri3-native"
FIX=WORK/"fixtures"
SCRIPT="META-INF/com/google/android/updater-script"
results=[]
suite_completed=False
terminal_error=None
EXPECTED_CASES=50
parser=argparse.ArgumentParser()
parser.add_argument("binary",nargs="?",default=str(WORK/"build-host/prep-update-binary"))
parser.add_argument("--run-label",default="core")
options=parser.parse_args()
if not re.fullmatch(r"[A-Za-z0-9_-]{1,80}",options.run_label):raise RuntimeError("invalid run label")
started_utc=datetime.datetime.now(datetime.timezone.utc).isoformat()
script_sha256=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest()
binary=pathlib.Path(options.binary).resolve()
if not binary.is_relative_to(WORK.resolve()): raise RuntimeError("binary must be in work tree")
FIX.mkdir(parents=True,exist_ok=True)
os.environ.update({x:str(WORK/"tmp") for x in ["TMPDIR","TMP","TEMP"]})
os.environ.update({"HOME":str(WORK/"home"),"XDG_CACHE_HOME":str(WORK/"cache")})
env=os.environ.copy()
env.update({"TMPDIR":str(WORK/"tmp"),"TMP":str(WORK/"tmp"),"TEMP":str(WORK/"tmp"),
            "ASAN_OPTIONS":"detect_leaks=0:halt_on_error=1","UBSAN_OPTIONS":"halt_on_error=1"})
# AOSP's generated parser owns process-lifetime scanner/string allocations. Leak checking is not a pass claim.
def check(name,condition,detail=""):
    results.append({"name":name,"passed":bool(condition),"detail":detail})
    if not condition: raise AssertionError(name+": "+detail)
def handled(r,code):
    diagnostics=[b"AddressSanitizer",b"UndefinedBehaviorSanitizer",b"LeakSanitizer",b"runtime error:"]
    return r.returncode==code and not any(x in r.stderr for x in diagnostics)
def sparse_open(path):
    if not path.resolve().is_relative_to(FIX.resolve()) or path.is_symlink():
        raise RuntimeError("sparse fixture path is outside owned fixture directory")
    with path.open("wb"):pass
    fsutil=pathlib.Path("/mnt/c/Windows/System32/fsutil.exe")
    if fsutil.exists():
        windows=subprocess.check_output(["/usr/bin/wslpath","-w",str(path.resolve())],text=True,env=env).strip()
        subprocess.run([str(fsutil),"sparse","setflag",windows],check=True,capture_output=True,timeout=10,env=env)
    return path.open("r+b")
def writezip(name,entries,compression=zipfile.ZIP_STORED,force=False,offset=0):
    path=FIX/name
    with (sparse_open(path) if offset else path.open("wb")) as file:
        if offset: file.seek(offset)
        with zipfile.ZipFile(file,"w",compression=compression,allowZip64=True) as z:
            for key,value in entries:
                if isinstance(value,str):value=value.encode()
                if force:
                    info=zipfile.ZipInfo(key);info.compress_type=compression
                    with z.open(info,"w",force_zip64=True) as member:member.write(value)
                else:z.writestr(key,value)
    return path
def run_read(path,entry="data"):
    return subprocess.run([str(binary),"--read-entry",str(path),entry],capture_output=True,timeout=20,env=env)
def recovery(path,api="3",fixture=True):
    read,write=os.pipe()
    try:
        argv=[str(binary)]+(["--test-recovery"] if fixture else [])+[api,str(write),str(path)]
        p=subprocess.run(argv,pass_fds=(write,),capture_output=True,timeout=20,env=env)
    finally:os.close(write)
    with os.fdopen(read,"rb") as stream:protocol=stream.read()
    return p,protocol
try:
    payload=b"read-only ZIP data\n"*193
    for method,label in [(zipfile.ZIP_STORED,"stored"),(zipfile.ZIP_DEFLATED,"deflate")]:
        p=writezip(label+".zip",[("data",payload)],method)
        r=run_read(p);check(label+" extraction",r.returncode==0 and r.stdout==payload,r.stderr.decode())
    for method,label in [(zipfile.ZIP_STORED,"stored-empty"),(zipfile.ZIP_DEFLATED,"deflate-empty")]:
        p=writezip(label+".zip",[("data",b"")],method)
        r=run_read(p);check(label,handled(r,0) and r.stdout==b"",r.stderr.decode())
    p=writezip("zip64-local.zip",[("data",payload)],force=True)
    r=run_read(p);check("forced ZIP64 local header",r.returncode==0 and r.stdout==payload,r.stderr.decode())
    before=shutil.disk_usage(WORK).free
    probe=FIX/"sparse-probe"
    with sparse_open(probe) as file:file.seek(64*1024*1024);file.write(b"probe")
    probe_stat=probe.stat()
    allocated=probe_stat.st_blocks*512
    check("sparse filesystem support",allocated<1024*1024,str({"logical":probe_stat.st_size,"allocated":allocated}))
    check("free-space reserve before large fixtures",before>=12*1024**3,str(before))
    (binary.parent/"fixture-storage-before.json").write_text(json.dumps({"free_bytes":before,"probe_logical":probe_stat.st_size,"probe_allocated":allocated,"reserve_bytes":11*1024**3},indent=2))
    # A sparse REGULAR FILE checks actual central/local offsets above UINT32_MAX with low physical storage.
    p=writezip("zip64-offset.zip",[("data",payload)],offset=2**32+4096)
    check("ZIP64 fixture logical length",p.stat().st_size>2**32,str(p.stat().st_size))
    r=run_read(p);check("ZIP64 >4GiB offset extraction",r.returncode==0 and r.stdout==payload,r.stderr.decode())
    p=writezip("zip64-count.zip",[(f"e/{i}",b"") for i in range(65536)]+[("data",payload)])
    r=run_read(p);check("ZIP64 >65535 entries",r.returncode==0 and r.stdout==payload,r.stderr.decode())
    # A single DEFLATE member exceeds 4GiB while its on-disk fixture remains small.
    p=FIX/"zip64-entry-size.zip"
    with zipfile.ZipFile(p,"w",compression=zipfile.ZIP_DEFLATED,compresslevel=1,allowZip64=True) as z:
        with z.open("data","w",force_zip64=True) as member:
            chunk=b"\0"*(1024*1024)
            for _ in range(4097):member.write(chunk)
    r=subprocess.run([str(binary),"--verify-entry",str(p),"data"],capture_output=True,timeout=120,env=env)
    check("ZIP64 individual entry >4GiB CRC streaming",r.returncode==0 and r.stdout.strip()==str(4097*1024*1024).encode(),r.stderr.decode())
    class SparseZeroWriter:
        def __init__(self,file):self.file=file
        def __getattr__(self,name):return getattr(self.file,name)
        def write(self,data):
            if len(data)>=1024*1024 and bytes(data).count(0)==len(data):
                self.file.seek(len(data),1);return len(data)
            return self.file.write(data)
    stored=FIX/"zip64-stored-entry.zip"
    with sparse_open(stored) as raw:
        with zipfile.ZipFile(SparseZeroWriter(raw),"w",compression=zipfile.ZIP_STORED,allowZip64=True) as z:
            with z.open("data","w",force_zip64=True) as member:
                chunk=b"\0"*(1024*1024)
                for _ in range(4097):member.write(chunk)
    st=stored.stat()
    check("ZIP64 >4GiB stored sparse fixture footprint",st.st_size>2**32 and st.st_blocks*512<64*1024*1024,str({"logical":st.st_size,"allocated":st.st_blocks*512}))
    r=subprocess.run([str(binary),"--verify-entry",str(stored),"data"],capture_output=True,timeout=120,env=env)
    check("ZIP64 >4GiB stored member CRC streaming",handled(r,0) and r.stdout.strip()==str(4097*1024*1024).encode(),r.stderr.decode())
    script='ui_print("hello", "\\nworld"); assert("a" + "b" == "ab"); if "t" then assert(greater_than_int("4294967296","4294967295")); else abort("wrong branch"); endif; show_progress("0.5","1"); set_progress("1"); "done";'
    p=writezip("edify.zip",[(SCRIPT,script)])
    for api in ["1","2","3"]:
        r,pipe=recovery(p,api)
        check("recovery API "+api,r.returncode==0 and b"ui_print hello\nui_print world\n" in pipe and b"progress 0.500000 1\n" in pipe and b"set_progress 1.000000\n" in pipe,r.stderr.decode()+pipe.decode())
    verify=subprocess.run([str(binary),"--verify-package",str(p)],capture_output=True,timeout=20,env=env)
    check("direct read-only package verification",handled(verify,0) and b"read-only evaluation complete" in verify.stdout)
    for api in ["1","2","3"]:
        r,pipe=recovery(p,api=api,fixture=False)
        check("production installation interlock "+api,handled(r,80) and b"installation is disabled" in pipe,pipe.decode())
    invalid=subprocess.run([str(binary),"3","not-a-fd",str(p)],capture_output=True,timeout=20,env=env)
    check("handled invalid command fd",handled(invalid,8))
    closed_read,broken_write=os.pipe();os.close(closed_read)
    try:
        broken=subprocess.run([str(binary),"3",str(broken_write),str(p)],pass_fds=(broken_write,),capture_output=True,timeout=20,env=env)
    finally:os.close(broken_write)
    check("handled broken command pipe",handled(broken,8))
    blob=writezip("blob.zip",[(SCRIPT,'ifelse("t",package_extract_file("data"),abort("bad")); "done";'),("data",payload)])
    r,pipe=recovery(blob)
    check("positive in-memory BLOB extraction",handled(r,0))
    r,pipe=recovery(p,api="4")
    check("reject unknown recovery API",r.returncode==2)
    failures={
      "assert-false":'assert(""); ui_print("MUST_NOT_EXECUTE");',
      "abort":'abort("stop"); ui_print("MUST_NOT_EXECUTE");',
      "unknown-function":'does_not_exist();',
      "malformed-grammar":'if then ("x";',
      "invalid-progress":'set_progress("NaN");',
      "progress-outside-range":'show_progress("1.1","1");',
      "progress-newline":'set_progress("0.5\\nset_progress 1");',
      "disabled-sparse":'package_unsparse_file("image","fixture");',
      "disabled-destination":'package_extract_file("data","fixture");',
      "disabled-sleep":'sleep();',
      "substring-arity":'is_substring();',
      "integer-overflow":'assert(greater_than_int("18446744073709551616","1"));',
      "nul-script":b'ui_print("before");\0ui_print("after");',
    }
    for name,script in failures.items():
        p=writezip(name+".zip",[(SCRIPT,script),("data",payload)])
        r,pipe=recovery(p)
        check(name,handled(r,8 if name=="nul-script" else 7) and b"MUST_NOT_EXECUTE" not in pipe,(r.stderr+pipe).decode())
    for name,entry in [("traversal","../data"),("absolute","/data"),("windows","C:\\data"),("double-slash","a//data")]:
        p=writezip(name+".zip",[(entry,payload)])
        r=run_read(p,entry);check("reject "+name,handled(r,8))
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        p=writezip("duplicate.zip",[("data",payload),("data",payload)])
    r=run_read(p);check("reject duplicate entry",handled(r,8))
    p=writezip("crc.zip",[("data",payload)])
    data=bytearray(p.read_bytes());data[30+len("data")]=data[30+len("data")]^1;p.write_bytes(data)
    r=run_read(p);check("reject CRC mismatch",handled(r,8))
    p=writezip("bad-central-crc.zip",[("data",payload)])
    data=bytearray(p.read_bytes());pos=data.index(b"PK\x01\x02");data[pos+16]^=1;p.write_bytes(data)
    r=run_read(p);check("reject central/local mismatch",handled(r,8))
    p=writezip("encrypted-flag.zip",[("data",payload)])
    data=bytearray(p.read_bytes());data[6]|=1;pos=data.index(b"PK\x01\x02");data[pos+8]|=1;p.write_bytes(data)
    r=run_read(p);check("reject encrypted entry",handled(r,8))
    p=writezip("unsupported-method.zip",[("data",payload)],zipfile.ZIP_BZIP2)
    r=run_read(p);check("reject unsupported method",handled(r,8))
    p=writezip("truncated.zip",[("data",payload)])
    p.write_bytes(p.read_bytes()[:-9]);r=run_read(p);check("reject truncated ZIP",handled(r,8))
    p=writezip("over-limit.zip",[("data",b"x"*(8*1024*1024+1))],zipfile.ZIP_DEFLATED)
    r=run_read(p);check("reject bounded extraction overflow",handled(r,8))
    p=FIX/"not-zip";p.write_bytes(b"not a ZIP")
    r=run_read(p);check("reject malformed ZIP",handled(r,8))
    p=FIX/"symlink.zip"
    if p.exists() or p.is_symlink():p.unlink()
    p.symlink_to(FIX/"stored.zip")
    r=run_read(p);check("reject symlink package",handled(r,8))
    if len(results)!=EXPECTED_CASES: raise AssertionError("coverage count mismatch: "+str(len(results)))
    suite_completed=True
except BaseException as exc:
    terminal_error=repr(exc)
    raise
finally:
    receipt={"run_label":options.run_label,"started_utc":started_utc,"finished_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),"test_source_sha256":script_sha256,"binary":str(binary),"binary_sha256":hashlib.sha256(binary.read_bytes()).hexdigest(),
      "installation_enabled":False,"test_scope":"host regular-file ZIP fixtures; no device operations",
      "aarch64_runtime_executed":False,"suite_completed":suite_completed,"terminal_error":terminal_error,"expected_cases":EXPECTED_CASES,"status":"passed" if suite_completed and all(x["passed"] for x in results) else "incomplete_or_failed","asan_leak_check":False,"results":results,
      "passed":sum(x["passed"] for x in results),"total":len(results),
      "fixture_logical_bytes":sum(x.stat().st_size for x in FIX.iterdir() if x.is_file() and not x.is_symlink()),
      "fixture_allocated_bytes":sum(x.stat().st_blocks*512 for x in FIX.iterdir() if x.is_file() and not x.is_symlink()),
      "free_bytes_after":shutil.disk_usage(WORK).free,
      "fixture_storage":[{"name":x.name,"logical":x.stat().st_size,"allocated":x.stat().st_blocks*512} for x in FIX.iterdir() if x.is_file() and not x.is_symlink()]}
    path=binary.parent/("tests-"+options.run_label+".json")
    path.write_text(json.dumps(receipt,indent=2)+"\n")
    (binary.parent/"tests.json").write_text(json.dumps(receipt,indent=2)+"\n")
    print(json.dumps({"receipt":str(path),"passed":receipt["passed"],"total":receipt["total"]}))
