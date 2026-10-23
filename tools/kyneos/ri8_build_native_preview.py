"""Compile RI8 Android recovery PREVIEW-ONLY native updater from pinned existing toolchain.

The generated install_runtime.cpp refuses all device writes in InstallHeldPackage;
the binary can only perform native signed-ZIP verification and read-only device preflight.
No existing ROM source, original updater executable, or phone image is changed.
"""
from __future__ import annotations
from pathlib import Path
import hashlib,json,subprocess

ROOT=Path(__file__).resolve().parents[2]
WORK=ROOT/"builder/work/kyneos-ri8-20261014/native"
REF=ROOT/"builder/work/installer-ri5-recoveryfix-20261004/native-android-new-kyneosri7otgfix/build-receipt.json"
OLD=ROOT/"builder/work/installer-ri5-recoveryfix-20261004/native-android-new-kyneosri7otgfix"

def digest(p):
    with p.open("rb") as f:return hashlib.file_digest(f,"sha256").hexdigest()

def main():
    old=json.loads(REF.read_text(encoding="utf-8"))
    if old.get("target")!="android" or len(old["objects"])<55:
        raise ValueError("Unexpected trusted RI7 Android native baseline")
    for p,d in old["objects"].items():
        source=ROOT/p
        if not source.is_file() or digest(source)!=d:
            raise ValueError("Reused dependency binary drift: "+str(source))
    ri8runtime=WORK/"install_runtime.cpp"
    ri8main=WORK/"main.cpp"
    pins=WORK/"image_pins.h"
    for p in (ri8runtime,ri8main,pins):
        if not p.is_file():raise FileNotFoundError(p)
    rt=ri8runtime.read_text(encoding="utf-8")
    if "r.mutations_started=true" in rt or "RI8 recovery install disabled" not in rt:
        raise ValueError("Native device mutation disabled gate missing")
    if 'constexpr unsigned kImageCount=2' not in pins.read_text():
        raise ValueError("Updater is not restricted to exactly two images")
    if (WORK/"update-binary").exists() or (WORK/"native-build.json").exists():
        raise FileExistsError("Refusing to overwrite a previous native build")
    commands=old["commands"]
    failures=[]
    # Use the compiler and audited include flags from the exact previous build.
    new_objects={}
    for index,newpath in ((36,ri8runtime),(37,ri8main)):
        cmd=list(commands[index]["argv"])
        old_cpp=next((v for v in cmd if v.endswith(".cpp")),None)
        if not old_cpp:
            raise ValueError("Unexpected compiled entrypoint")
        cmd[cmd.index(old_cpp)]=str(newpath)
        dest=WORK/("ri8-"+str(index)+".o")
        cmd[cmd.index("-o")+1]=str(dest)
        # Explicit include own pins first, no leakage from previous updater.
        cmd.insert(1,"-I"+str(WORK))
        p=subprocess.run(cmd,capture_output=True,text=True)
        failures.append({"stage":"compile "+newpath.name,"exit":p.returncode,
                         "stderr":p.stderr[-4500:],"stdout":p.stdout[-1500:]})
        if p.returncode:
            (WORK/"compile-failure.json").write_text(json.dumps(failures,indent=2))
            raise RuntimeError("RI8 native compile failed: "+p.stderr[-2500:])
        new_objects[index]=dest
    link=list(commands[-1]["argv"])
    for old_path,dest in new_objects.items():
        original=str(OLD/("%d-%s.o"%(old_path,"install_runtime" if old_path==36 else "main")))
        if original not in link:
            raise ValueError("Original native object not found in link plan "+original)
        link[link.index(original)]=str(dest)
    target=WORK/"update-binary"
    link[link.index("-o")+1]=str(target)
    result=subprocess.run(link,capture_output=True,text=True)
    failures.append({"stage":"link","exit":result.returncode,
                    "stderr":result.stderr[-4200:],"stdout":result.stdout[-1500:]})
    if result.returncode:
        (WORK/"compile-failure.json").write_text(json.dumps(failures,indent=2))
        raise RuntimeError("RI8 native link failed: "+result.stderr[-2500:])
    binary=target.read_bytes()[:64]
    if binary[:4]!=b"\x7fELF" or binary[4]!=2 or int.from_bytes(binary[18:20],"little")!=183:
        raise RuntimeError("Updater is not ELF64 AArch64")
    record={"target":"android aarch64 preview-only",
       "binary":str(target),"bytes":target.stat().st_size,"sha256":digest(target),
       "source_hashes":{str(p.relative_to(ROOT)):digest(p) for p in (ri8runtime,ri8main,pins)},
       "reused_binary_objects":len(old["objects"])-2,
       "reused_dependencies_sha_verified":True,
       "device_write_entrypoint_enabled":False,"device_flash_tests":False,
       "commands":failures}
    (WORK/"native-build.json").write_text(json.dumps(record,indent=2)+"\n",encoding="utf-8")
    print(json.dumps({k:record[k] for k in ("target","binary","bytes","sha256",
                  "reused_binary_objects","device_write_entrypoint_enabled")},indent=2))

if __name__=="__main__":
    main()
