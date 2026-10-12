#!/usr/bin/env python3
"""Acquire bounded, pinned source inputs for the production integration stage."""
import argparse,base64,concurrent.futures,hashlib,io,json,pathlib,tarfile,time,urllib.request
ROOT=pathlib.Path(__file__).resolve().parents[3]
HERE=ROOT/"tools/installer-ri3/native-updater"
WORK=ROOT/"builder/work/installer-ri3-native"
DEST=WORK/"production-vendor"
CORE="b5d7447b9990ff245725011e6189e06b3527c2f3"
BASE="5290a0114274c48b4b6a12bbf7e6e88a84b1438c"
LOCK=HERE/"production-sources.lock.json"
def sha(data):return hashlib.sha256(data).hexdigest()
DEADLINE=time.monotonic()+27

def get(url,limit=64*1024*1024):
    last=None
    for attempt in range(2):
        try:
            req=urllib.request.Request(url,headers={"User-Agent":"RI3-source-build/1"})
            remaining=DEADLINE-time.monotonic()
            if remaining<=1:raise RuntimeError("bounded acquisition deadline")
            with urllib.request.urlopen(req,timeout=min(8,remaining)) as r:
                data=r.read(limit+1)
            if len(data)>limit:raise RuntimeError("source response size limit exceeded")
            return data
        except Exception as e:
            last=e
            if attempt<1:time.sleep(0.25)
    raise last
def tree(repo,commit,path):
    url=f"https://android.googlesource.com/{repo}/+/{commit}/{path}/?format=JSON"
    return json.loads(get(url).decode()[4:])["entries"]
def save(path,data):
    path.parent.mkdir(parents=True,exist_ok=True)
    if path.exists() and path.read_bytes()!=data:raise RuntimeError("source content drift: "+str(path))
    if not path.exists():path.write_bytes(data)
def main():
    ap=argparse.ArgumentParser();ap.add_argument("--run-label",required=True);ap.add_argument("--part",choices=["core","base","crypto"],required=True);args=ap.parse_args()
    old=json.loads(LOCK.read_text()) if LOCK.exists() else {}
    records={r["path"]:r for r in old.get("files",[])}
    requests=[]
    specs=[("core","platform/system/core",CORE,"libsparse"),
           ("core","platform/system/core",CORE,"fs_mgr/libdm"),
           ("base","platform/system/libbase",BASE,"include")]
    def collect(name,repo,commit,path):
        for item in tree(repo,commit,path):
            child=path+"/"+item["name"]
            if item["type"]=="tree":
                if child.endswith("/include") or "/include/" in child or path=="include":
                    collect(name,repo,commit,child)
            elif child.endswith((".h",".cpp")) or item["name"] in ("Android.bp","NOTICE","LICENSE"):
                if "_test" not in child and "_fuzzer" not in child and "test_utils" not in child:
                    requests.append((name,repo,commit,child))
    for spec in specs:
        if (args.part=="core" and spec[0]=="core") or (args.part=="base" and spec[0]=="base"):collect(*spec)
    # libbase implementation files needed by libsparse/libdm, selected after build dependency review.
    for path in (["file.cpp","logging.cpp","properties.cpp","chrono_utils.cpp","threads.cpp","errors_unix.cpp"] if args.part=="base" else []):
        requests.append(("base","platform/system/libbase",BASE,path))
    def fetch(item):
        name,repo,commit,path=item
        relative=name+"/"+path; dest=DEST/relative
        url=f"https://android.googlesource.com/{repo}/+/{commit}/{path}?format=TEXT"
        data=dest.read_bytes() if dest.exists() else base64.b64decode(get(url))
        if relative in records and sha(data)!=records[relative]["sha256"]:raise RuntimeError("cached source drift")
        save(dest,data)
        return {"path":relative,"url":url,"repository":repo,"commit":commit,"sha256":sha(data),"bytes":len(data)}
    errors=[]
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        futures={pool.submit(fetch,item):item for item in requests}
        for future in concurrent.futures.as_completed(futures):
            try:
                record=future.result();records[record["path"]]=record
            except Exception as error:errors.append(str(error))
    url="https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-3.6.7/mbedtls-3.6.7.tar.bz2"
    expected="a7e8bcbec0e6f761b4af24f25677626b35f762f68eef79c08677a363212d11f6"
    archive=WORK/"downloads/mbedtls-3.6.7.tar.bz2"
    data=archive.read_bytes() if archive.exists() else (get(url) if args.part=="crypto" else None)
    if data is None:
        lock={"schema":1,"run_label":args.run_label,"core_commit":CORE,"base_commit":BASE,"aosp_tag":"aml_adb_331011040","files":sorted(records.values(),key=lambda x:x["path"]),"mbedtls":old.get("mbedtls"),"errors":errors,"completed_parts":sorted(set(old.get("completed_parts",[])+([args.part] if not errors else []))),"complete":False}
        lock["complete"]=set(lock["completed_parts"])=={"core","base","crypto"}
        LOCK.write_text(json.dumps(lock,indent=2)+"\n",encoding="utf-8")
        print(json.dumps({"part":args.part,"files":len(records),"errors":errors,"completed_parts":lock["completed_parts"]}),flush=True)
        return
    if sha(data)!=expected:raise RuntimeError("official Mbed TLS archive hash mismatch")
    save(archive,data)
    selected=[]
    with tarfile.open(fileobj=io.BytesIO(data)) as tf:
        for member in tf:
            path=pathlib.PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or "\\" in member.name or ":" in member.name:
                raise RuntimeError("unsafe source archive name")
            if not path.parts or path.parts[0]!="mbedtls-3.6.7":raise RuntimeError("unexpected archive root")
            if len(path.parts)<2:continue
            if path.parts[1] not in ("include","library","LICENSE","README.md","LICENSES"):continue
            if member.isdir():continue
            if not member.isfile():raise RuntimeError("non-regular selected source member")
            raw=tf.extractfile(member).read();relative=str(path)
            save(DEST/pathlib.Path(*path.parts),raw)
            selected.append({"path":relative,"sha256":sha(raw),"bytes":len(raw)})
    lock={"schema":1,"run_label":args.run_label,"core_commit":CORE,"base_commit":BASE,
          "aosp_tag":"aml_adb_331011040","files":sorted(records.values(),key=lambda x:x["path"]),
          "mbedtls":{"release":"3.6.7 LTS","url":url,"archive_sha256":expected,"archive_bytes":len(data),"files":selected},
          "errors":errors,"completed_parts":sorted(set(old.get("completed_parts",[])+([args.part] if not errors else []))),"complete":False}
    lock["complete"]=set(lock["completed_parts"])=={"core","base","crypto"}
    LOCK.write_text(json.dumps(lock,indent=2)+"\n",encoding="utf-8")
    print(json.dumps({"run_label":args.run_label,"aosp_files":len(records),"mbedtls_files":len(selected),"complete":not errors,"errors":errors}),flush=True)
    if errors:raise RuntimeError("source acquisition incomplete")
if __name__=="__main__":main()
