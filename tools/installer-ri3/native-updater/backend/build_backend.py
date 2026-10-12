#!/usr/bin/env python3
"""Build isolated storage backend; execute only regular-file/mock tests."""
import argparse,datetime,hashlib,json,os,pathlib,subprocess
ROOT=pathlib.Path(__file__).resolve().parents[4]
HERE=ROOT/"tools/installer-ri3/native-updater/backend"
WORK=ROOT/"builder/work/installer-ri3-native/backend"
VENDOR=ROOT/"builder/work/installer-ri3-native/production-vendor"
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 ap=argparse.ArgumentParser()
 ap.add_argument("--target",choices=["host","android"],required=True)
 ap.add_argument("--phase",choices=["tests","adapter","libdm"],default="tests")
 ap.add_argument("--sanitize",action="store_true")
 ap.add_argument("--label",required=True)
 a=ap.parse_args()
 if not a.label or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for c in a.label):raise RuntimeError("invalid label")
 if a.sanitize and a.target!="host":raise RuntimeError("host sanitizers only")
 out=WORK/(a.label+"-"+a.target+"-"+a.phase+("-san" if a.sanitize else ""))
 out.mkdir(parents=True,exist_ok=False)
 tmp=out/"tmp";tmp.mkdir()
 env=os.environ.copy();env.update({k:str(tmp) for k in ["TMPDIR","TMP","TEMP"]})
 env.update({"HOME":str(tmp),"XDG_CACHE_HOME":str(tmp),"LC_ALL":"C","TZ":"UTC","SOURCE_DATE_EPOCH":"1661990400"})
 flags=["-std=c++17","-O2","-Wall","-Wextra","-Werror","-fno-ident","-ffunction-sections","-fdata-sections","-D_FILE_OFFSET_BITS=64","-D_LARGEFILE64_SOURCE=1","-D_POSIX_C_SOURCE=200809L",f"-ffile-prefix-map={ROOT}=."]
 cxx=pathlib.Path("/usr/bin/clang++")
 if a.target=="android":
  ndk=pathlib.Path(os.environ["LOCALAPPDATA"])/"Android/Sdk/ndk/28.2.13676358"
  if "Pkg.Revision = 28.2.13676358" not in (ndk/"source.properties").read_text():raise RuntimeError("NDK mismatch")
  cxx=ndk/"toolchains/llvm/prebuilt/windows-x86_64/bin/clang++.exe";flags+=["--target=aarch64-linux-android30"]
 if a.sanitize:flags+=["-fsanitize=address,undefined","-fno-omit-frame-pointer"]
 logs=[]
 def run(args):
  args=[str(x) for x in args]
  p=subprocess.run(args,env=env,capture_output=True,text=True,timeout=120 if args[0]==str(cxx) else 35)
  logs.append({"command":args,"returncode":p.returncode,"stdout":p.stdout,"stderr":p.stderr})
  (out/"commands.json").write_text(json.dumps(logs,indent=2)+"\n")
  if p.returncode:raise RuntimeError(p.stderr or p.stdout)
  return p.stdout
 version=run([cxx,"--version"])
 sources=[HERE/"storage_backend.cpp",HERE/"topology.cpp",HERE/"verity_table.cpp",HERE/"unmount.cpp"]
 outputs=[];checks=[]
 if a.phase in ["adapter","libdm"]:
  flags += ["-Wno-error=inconsistent-missing-override"]  # Pristine AOSP dm.h has one legacy missing override.
  lock=json.loads((HERE.parent/"production-sources.lock.json").read_text())
  relevant=[x for x in lock["files"] if x["path"].startswith("core/fs_mgr/libdm/") or x["path"].startswith("base/")]
  for x in relevant:
   if sha(VENDOR/x["path"])!=x["sha256"]:raise RuntimeError("vendor source mismatch")
  flags += ["-I"+str(VENDOR/"core/fs_mgr/libdm/include"),"-I"+str(VENDOR/"base/include")]
  sources=[HERE/"libdm_adapter.cpp"]
  if a.phase=="libdm":
   record=json.loads((HERE/"vendor/uuid/source.json").read_text())
   if sha(HERE/"vendor/uuid/uuid.h")!=record["sha256"]:raise RuntimeError("UUID header mismatch")
   flags += ["-I"+str(HERE/"vendor")]
   sources=[VENDOR/"core/fs_mgr/libdm"/name for name in ["dm.cpp","dm_table.cpp","dm_target.cpp","loop_control.cpp","utility.cpp"]]
 if a.target=="host" and a.phase=="tests":
  binary=out/"test-backend"
  sources+=[HERE/"test_backend.cpp"]
  run([cxx,*flags,*sources,"-Wl,--wrap=read","-Wl,--wrap=open","-Wl,--wrap=open64","-o",binary])
  raw=run([binary,out/"output.fixture"])
  checks=[s[5:] for s in raw.splitlines() if s.startswith("PASS ")]
  if len(checks)!=len(set(checks)) or not any(s.startswith("RESULT "+str(len(checks))+" ") for s in raw.splitlines()):raise RuntimeError("test receipt invalid")
  outputs=[binary]
 else:
  for source in sources:
   obj=out/(source.stem+".o");run([cxx,*flags,"-c",source,"-o",obj]);outputs.append(obj)
 if a.phase=="libdm":
  ar=cxx.parent/("llvm-ar.exe" if a.target=="android" else "llvm-ar")
  archive=out/"libdm-source-built.a"
  run([ar,"rcD",archive,*outputs]);outputs.append(archive)
 provenance=list(HERE.glob("*.h"))+list(HERE.glob("*.cpp"))+[HERE/"build_backend.py",HERE.parent/"guard/guard_policy.h",HERE.parent/"extract/image_extract.h"]
 if a.phase=="adapter":
  provenance += [VENDOR/x["path"] for x in relevant]
  if a.phase=="libdm":provenance += [HERE/"vendor/uuid/source.json",HERE/"vendor/uuid/uuid.h"]
 receipt={"target":a.target,"phase":a.phase,"label":a.label,"sanitizers":a.sanitize,"compiler":str(cxx),"compiler_sha256":sha(cxx.resolve()),"compiler_version":version,"device_operations_executed":False,"production_activation_enabled":False,"checks_passed":len(checks),"checks":checks,"outputs":{str(p.relative_to(ROOT)):sha(p) for p in outputs},"sources":{str(p.relative_to(ROOT)):sha(p) for p in provenance},"commands":logs,"limits":"Host tests exercise regular-file descriptors and explicit mocked DM state only. Android outputs are compiled, not device-executed. Adapter object compilation is not a complete libdm static linkage or device validation."}
 (out/"receipt.json").write_text(json.dumps(receipt,indent=2)+"\n")
 print(json.dumps({"receipt":str(out/"receipt.json"),"checks_passed":len(checks),"outputs":receipt["outputs"],"device_operations_executed":False}))
if __name__=="__main__":main()
