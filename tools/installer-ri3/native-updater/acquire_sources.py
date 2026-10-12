#!/usr/bin/env python3
"""Acquire exact reviewed upstream source inputs; never installs system software."""
import base64, hashlib, io, json, os, pathlib, tarfile, urllib.request
ROOT = pathlib.Path(__file__).resolve().parents[3]
HERE = ROOT / "tools/installer-ri3/native-updater"
WORK = ROOT / "builder/work/installer-ri3-native"
TAG = "aml_adb_331011040"
REPOS = {
 "recovery": ("platform/bootable/recovery", "4bb77cd29253746942b2abca072c159bf660eeae", [
 "edify/expr.cpp", "edify/parser.yy", "edify/lexer.ll", "edify/yydefs.h",
 "edify/include/edify/expr.h", "edify/include/edify/updater_interface.h",
 "otautil/include/otautil/error_code.h", "NOTICE"]),
 "libbase": ("platform/system/libbase", "5290a0114274c48b4b6a12bbf7e6e88a84b1438c", [
 "stringprintf.cpp", "strings.cpp", "posix_strerror_r.cpp",
 "include/android-base/stringprintf.h", "include/android-base/strings.h",
 "include/android-base/parseint.h", "include/android-base/macros.h", "NOTICE"]),
}
ARCHIVES = {
 "zlib-1.3.2": ("https://zlib.net/zlib-1.3.2.tar.gz", "bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16"),
 "m4-1.4.20": ("https://ftp.gnu.org/gnu/m4/m4-1.4.20.tar.xz", None),
 "bison-3.8.2": ("https://ftp.gnu.org/gnu/bison/bison-3.8.2.tar.xz", None),
 "flex-2.6.4": ("https://github.com/westes/flex/releases/download/v2.6.4/flex-2.6.4.tar.gz", None),
}
def get(url):
    with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent":"RI3-source-build/1"}), timeout=120) as r:
        return r.read()
def sha(b): return hashlib.sha256(b).hexdigest()
def save(p,b):
    p.parent.mkdir(parents=True,exist_ok=True)
    if p.exists() and p.read_bytes()!=b: raise RuntimeError("Refusing to replace different source: "+str(p))
    p.write_bytes(b)
def main():
    WORK.mkdir(parents=True,exist_ok=True)
    lockpath=HERE/"sources.lock.json"
    old=json.loads(lockpath.read_text()) if lockpath.exists() else {}
    lock={"aosp_release_tag": TAG, "aosp": {}, "archives": {}}
    for name,(repo,commit,paths) in REPOS.items():
        base="https://android.googlesource.com/"+repo+"/+/"+commit+"/"
        records=[]
        for path in paths:
            url=base+path+"?format=TEXT"; dest=WORK/"vendor"/name/path
            data=dest.read_bytes() if dest.exists() else base64.b64decode(get(url))
            prior={f["path"]:f["sha256"] for f in old.get("aosp",{}).get(name,{}).get("files",[])}
            if path in prior and sha(data)!=prior[path]: raise RuntimeError("Cached AOSP source digest mismatch: "+path)
            save(dest,data); records.append({"path":path,"sha256":sha(data),"url":url})
        lock["aosp"][name]={"repository":repo,"commit":commit,"files":records}
        print("Acquired",name,commit,flush=True)
    for name,(url,expected) in ARCHIVES.items():
        dest=WORK/"downloads"/url.rsplit("/",1)[1]
        data=dest.read_bytes() if dest.exists() else get(url)
        digest=sha(data)
        pin=old.get("archives",{}).get(name,{}).get("sha256",expected)
        if pin and digest!=pin: raise RuntimeError("Source digest mismatch "+name)
        save(dest,data)
        with tarfile.open(fileobj=io.BytesIO(data)) as tf:
            for m in tf:
                p=pathlib.PurePosixPath(m.name)
                if p.is_absolute() or ".." in p.parts or "\\" in m.name or ":" in m.name or not p.parts or p.parts[0]!=name:
                    raise RuntimeError("Unsafe source archive path "+m.name)
                if m.isdir(): continue
                if not m.isfile(): raise RuntimeError("Non-regular source archive member "+m.name)
                target=WORK/"vendor"/pathlib.Path(*p.parts)
                save(target,tf.extractfile(m).read())
                os.utime(target,(m.mtime,m.mtime))
                os.chmod(target,m.mode & 0o777)
        lock["archives"][name]={"url":url,"sha256":digest,"bytes":len(data)}
        lockpath.write_text(json.dumps(lock,indent=2)+"\n",encoding="utf-8")
        print("Acquired",name,digest,flush=True)
    lockpath.write_text(json.dumps(lock,indent=2)+"\n",encoding="utf-8")
if __name__=="__main__": main()
