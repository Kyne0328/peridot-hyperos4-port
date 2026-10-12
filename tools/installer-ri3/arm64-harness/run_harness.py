#!/usr/bin/env python3
"""Build/validate an enforcing file jail, then explicitly run bounded ARM64 checks."""
import argparse,datetime,hashlib,json,os,pathlib,shutil,stat,struct,subprocess,warnings,zipfile
ROOT=pathlib.Path(__file__).resolve().parents[3]
SRC=ROOT/"tools/installer-ri3/arm64-harness"
WORK=ROOT/"builder/work/installer-ri3-qemu"
REPORT=ROOT/"09-reports/installer-ri3/arm64-harness"
TARGET=ROOT/"builder/work/installer-ri3-native/build-android/prep-update-binary"
PIN="f9971227115889e534bc181d4a749205037c2577f55959562caf5beb01bed6c0"
SCRIPT="META-INF/com/google/android/updater-script"
ENV={"PATH":"/usr/bin:/bin","HOME":str(WORK/"home"),"TMPDIR":str(WORK/"tmp"),"TMP":str(WORK/"tmp"),"TEMP":str(WORK/"tmp"),"XDG_CACHE_HOME":str(WORK/"cache"),"LANG":"C"}
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def call(argv,timeout=30):
    return subprocess.run([str(x) for x in argv],input=b"",stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd=ROOT,env=ENV,close_fds=True,timeout=timeout)
def logged(r):return {"returncode":r.returncode,"stdout":r.stdout.decode(errors="replace"),"stderr":r.stderr.decode(errors="replace")}
def static_elf(path,machine):
    b=path.read_bytes()
    if b[:6]!=b"\x7fELF\x02\x01" or struct.unpack_from("<H",b,18)[0]!=machine:raise RuntimeError("wrong ELF architecture")
    off=struct.unpack_from("<Q",b,32)[0];ents,num=struct.unpack_from("<HH",b,54)
    if any(struct.unpack_from("<I",b,off+i*ents)[0]==3 for i in range(num)):raise RuntimeError("ELF interpreter prohibited")
def inspect_tree(root):
    result=[]
    for p in sorted(root.rglob("*")):
        st=p.lstat()
        if p.is_symlink() or not (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode)) or st.st_mode&0o6000:raise RuntimeError("nonregular or privileged root entry")
        if p.is_file():result.append({"path":str(p.relative_to(root)),"sha256":sha(p),"bytes":st.st_size})
    return result
def launch(root,args):
    return ["/usr/bin/unshare","--user","--map-root-user","--mount","--propagation","unchanged","--net","--ipc","--pid","--fork","--kill-child",str(WORK/"tools/ri3-file-jail"),str(root)]+args
def putzip(root,name,entries,method=zipfile.ZIP_STORED,force=False):
    p=root/"fixtures"/name
    with zipfile.ZipFile(p,"w",compression=method,allowZip64=True) as z:
        for name,value in entries:
            if isinstance(value,str):value=value.encode()
            if force:
                info=zipfile.ZipInfo(name);info.compress_type=method
                with z.open(info,"w",force_zip64=True) as out:out.write(value)
            else:z.writestr(name,value)
    return "/fixtures/"+p.name
def prepare():
    if os.getuid()==0:raise RuntimeError("never run with host elevation")
    provenance=json.loads((REPORT/"tool-provenance.json").read_text())
    if provenance["status"]!="verified":raise RuntimeError("package provenance incomplete")
    qemu=WORK/"tools/qemu-aarch64-static"
    qp=next(x for p in provenance["packages"] for x in p["extracted"] if x["member"]=="usr/bin/qemu-aarch64-static")
    if sha(qemu)!=qp["sha256"]:raise RuntimeError("QEMU pin changed")
    if sha(TARGET)!=PIN:raise RuntimeError("updater pin changed")
    static_elf(qemu,62);static_elf(TARGET,183)
    stamp=datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    root=WORK/"jails"/stamp
    (root/"fixtures").mkdir(parents=True,exist_ok=False)
    commands=[]
    for name,dest,flags in [("jail.c",WORK/"tools/ri3-file-jail",[]),("probe.c",root/"probe",["-static"])]:
        argv=["/usr/bin/clang","-O2","-Wall","-Wextra","-Werror"]+flags+[str(SRC/name),"-o",str(dest)]
        r=call(argv,60);commands.append({"argv":argv,**logged(r)})
        if r.returncode:raise RuntimeError("host harness compilation failed: "+r.stderr.decode())
    shutil.copyfile(qemu,root/"qemu-aarch64-static");(root/"qemu-aarch64-static").chmod(0o755)
    shutil.copyfile(TARGET,root/"prep-update-binary");(root/"prep-update-binary").chmod(0o755)
    (root/"fixtures/sentinel.txt").write_bytes(b"RI3 fixture\n")
    outside=WORK/("outside-sentinel-"+stamp+".txt");outside.write_bytes(b"not available inside jail\n")
    payload=b"read-only ZIP data\n"*193
    cases=[]
    for method,label in [(zipfile.ZIP_STORED,"stored"),(zipfile.ZIP_DEFLATED,"deflated")]:
        for data,suffix in [(payload,""),(b"","-empty")]:
            p=putzip(root,label+suffix+".zip",[("data",data)],method)
            cases.append({"name":label+suffix,"args":["--verify-entry",p,"data"],"code":0,"out":str(len(data))+"\n"})
    p=putzip(root,"zip64-local.zip",[("data",payload)],force=True)
    cases.append({"name":"ZIP64 local header","args":["--verify-entry",p,"data"],"code":0,"out":str(len(payload))+"\n"})
    good='ui_print("hello", "\\nworld"); assert("a"+"b"=="ab"); if "t" then assert(greater_than_int("4294967296","4294967295")); else abort("bad"); endif; show_progress("0.5","1"); set_progress("1"); "done";'
    p=putzip(root,"edify.zip",[(SCRIPT,good)])
    cases.append({"name":"real Edify evaluation","args":["--verify-package",p],"code":0,"contains":["ui_print hello\nui_print world\n","progress 0.500000 1\n","set_progress 1.000000\n","read-only evaluation complete"]})
    p=putzip(root,"blob.zip",[(SCRIPT,'ifelse("t",package_extract_file("data"),abort("bad")); "done";'),("data",payload)])
    cases.append({"name":"in-memory BLOB extraction","args":["--verify-package",p],"code":0,"contains":["read-only evaluation complete"]})
    failures={"assert-false":'assert(""); ui_print("MUST_NOT_EXECUTE");',"abort":'abort("stop"); ui_print("MUST_NOT_EXECUTE");',"unknown-function":'does_not_exist();',"malformed":'if then ("x";',"invalid-progress":'set_progress("NaN");',"progress-range":'show_progress("1.1","1");',"progress-newline":'set_progress("0.5\\nset_progress 1");',"disabled-sparse":'package_unsparse_file("image","fixture");',"disabled-write":'write_raw_image("data","fixture");',"disabled-program":'run_program("fixture");',"disabled-mount":'mount("fixture");',"disabled-destination":'package_extract_file("data","fixture");',"disabled-sleep":'sleep();',"substring-arity":'is_substring();',"integer-overflow":'assert(greater_than_int("18446744073709551616","1"));',"nul-script":b'ui_print("before");\0ui_print("after");'}
    for name,script in failures.items():
        p=putzip(root,name+".zip",[(SCRIPT,script),("data",payload)])
        cases.append({"name":name,"args":["--verify-package",p],"code":8 if name=="nul-script" else 7,"absent":["MUST_NOT_EXECUTE"]})
    for name,entry in [("traversal","../data"),("absolute","/data"),("windows","C:\\data"),("double-slash","a//data")]:
        p=putzip(root,name+".zip",[(entry,payload)])
        cases.append({"name":"reject "+name,"args":["--verify-entry",p,entry],"code":8})
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        p=putzip(root,"duplicate.zip",[("data",payload),("data",payload)])
    cases.append({"name":"reject duplicate","args":["--verify-entry",p,"data"],"code":8})
    for name in ("crc","central-crc","encrypted","truncated"):
        p=putzip(root,name+".zip",[("data",payload)])
        local=root/p.lstrip("/");b=bytearray(local.read_bytes());pos=b.index(b"PK\x01\x02")
        if name=="crc":b[34]^=1
        elif name=="central-crc":b[pos+16]^=1
        elif name=="encrypted":b[6]|=1;b[pos+8]|=1
        else:b=b[:-9]
        local.write_bytes(b);cases.append({"name":"reject "+name,"args":["--verify-entry",p,"data"],"code":8})
    p=putzip(root,"unsupported.zip",[("data",payload)],zipfile.ZIP_BZIP2)
    cases.append({"name":"reject compression","args":["--verify-entry",p,"data"],"code":8})
    (root/"fixtures/not-zip").write_bytes(b"not a ZIP")
    cases.append({"name":"reject malformed ZIP","args":["--verify-entry","/fixtures/not-zip","data"],"code":8})
    cases.append({"name":"missing member","args":["--verify-entry","/fixtures/stored.zip","missing"],"code":8})
    for api in ("1","2","3"):
        cases.append({"name":"API "+api+" early installation abort","args":[api,"1","/fixtures/absent-package.zip"],"code":80,"contains":["installation is disabled"]})
    for name,args,code in [("unknown API",["4","1","/fixtures/absent.zip"],2),("invalid fd",["3","invalid","/fixtures/absent.zip"],8),("closed fd",["3","99","/fixtures/absent.zip"],8),("host read helper absent",["--read-entry","/fixtures/stored.zip","data"],2),("host recovery helper absent",["--test-recovery","3","1","/fixtures/edify.zip"],2),("wrong argc",[],2)]:
        cases.append({"name":name,"args":args,"code":code})
    before=inspect_tree(root)
    argv=launch(root,["/probe",str(outside)])
    r=call(argv,30)
    after=inspect_tree(root)
    evidence={"status":"passed" if r.returncode==0 and before==after else "failed","root":str(root),"target_sha256":PIN,"qemu_sha256":sha(qemu),"jail_sha256":sha(WORK/"tools/ri3-file-jail"),"jail_source_sha256":sha(SRC/"jail.c"),"probe_sha256":sha(root/"probe"),"probe_source_sha256":sha(SRC/"probe.c"),"host_uid":os.getuid(),"commands":commands,"probe_command":argv,"probe":logged(r),"root_files":before,"root_unchanged":before==after,"mounts_performed":False,"target_executed":False,"cases":cases}
    (REPORT/"isolation.json").write_text(json.dumps(evidence,indent=2)+"\n")
    print(json.dumps({"isolation":evidence["status"],"cases_prepared":len(cases),"probe":logged(r)}),flush=True)
    if evidence["status"]!="passed":raise RuntimeError("confinement probe failed; no target executed")
def test():
    isolation=json.loads((REPORT/"isolation.json").read_text())
    if isolation["status"]!="passed":raise RuntimeError("isolation prerequisite failed")
    root=pathlib.Path(isolation["root"])
    if sha(SRC/"jail.c")!=isolation["jail_source_sha256"] or sha(WORK/"tools/ri3-file-jail")!=isolation["jail_sha256"]:raise RuntimeError("launcher changed")
    if inspect_tree(root)!=isolation["root_files"]:raise RuntimeError("jail content changed")
    receipt={"status":"incomplete","target_sha256":PIN,"qemu_sha256":isolation["qemu_sha256"],"isolation_receipt_sha256":sha(REPORT/"isolation.json"),"target_executed":False,"results":[],"scope":"isolated read-only AArch64 user-mode small-fixture tests; no device compatibility claim"}
    try:
        for case in isolation["cases"]:
            argv=launch(root,["/qemu-aarch64-static","-strace","/prep-update-binary"]+case["args"])
            receipt["target_executed"]=True
            r=call(argv,30)
            row={"name":case["name"],"argv":argv,**logged(r)}
            row["passed"]=r.returncode==case["code"] and all(s in row["stdout"] for s in case.get("contains",[])) and all(s not in row["stdout"] for s in case.get("absent",[])) and ("out" not in case or row["stdout"]==case["out"])
            receipt["results"].append(row)
            if not row["passed"]:raise RuntimeError("case failed: "+case["name"])
        receipt["root_unchanged"]=inspect_tree(root)==isolation["root_files"]
        if not receipt["root_unchanged"]:raise RuntimeError("root changed")
        receipt["status"]="passed"
    except BaseException as e:
        receipt["error"]=repr(e);raise
    finally:
        receipt["passed"]=sum(x["passed"] for x in receipt["results"]);receipt["total"]=len(receipt["results"]);receipt["expected_cases"]=len(isolation["cases"])
        (REPORT/"arm64-results.json").write_text(json.dumps(receipt,indent=2)+"\n")
        print(json.dumps({k:receipt[k] for k in ("status","target_sha256","passed","total","expected_cases")}),flush=True)
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("action",choices=["prepare","test"]);a=p.parse_args()
    for x in (WORK/"tmp",WORK/"home",WORK/"cache",REPORT):x.mkdir(parents=True,exist_ok=True)
    (prepare if a.action=="prepare" else test)()
