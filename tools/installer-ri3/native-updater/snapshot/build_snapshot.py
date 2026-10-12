#!/usr/bin/env python3
"""Reproducible bounded build. Executes only the owned host fixture helper."""
import argparse,datetime,hashlib,json,os,pathlib,subprocess
ROOT=pathlib.Path(__file__).resolve().parents[4]
HERE=ROOT/"tools/installer-ri3/native-updater"
WORK=ROOT/"builder/work/installer-ri3-native/snapshot"
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 ap=argparse.ArgumentParser()
 ap.add_argument("--target",choices=["host","android"],required=True)
 ap.add_argument("--phase",choices=["compile","test"],required=True)
 ap.add_argument("--label",required=True);ap.add_argument("--sanitize",action="store_true")
 a=ap.parse_args()
 if not a.label or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for c in a.label):raise ValueError("label")
 if a.target=="android" and (a.sanitize or a.phase=="test"):raise ValueError("no Android execution")
 out=WORK/a.label/a.target;out.mkdir(parents=True,exist_ok=True)
 for n in ("tmp","home","cache"):(out/n).mkdir(exist_ok=True)
 env=os.environ.copy();env.update({n:str(out/"tmp") for n in ("TMPDIR","TMP","TEMP")})
 env.update({"HOME":str(out/"home"),"XDG_CACHE_HOME":str(out/"cache"),"LC_ALL":"C","TZ":"UTC"})
 mb=ROOT/"builder/work/installer-ri3-native/production-vendor/mbedtls-3.6.7"
 sources=[HERE/"snapshot"/n for n in ("metadata.cpp","hal_query.cpp")]
 if a.target=="host":sources.append(HERE/"snapshot/test_snapshot.cpp")
 sources += [mb/"library"/(n+".c") for n in ("sha256","platform_util","constant_time")]
 includes=[HERE/"snapshot",HERE/"crypto",mb/"include",mb/"library"]
 flags=["-O1","-g","-fno-ident","-ffunction-sections","-fdata-sections","-D_FILE_OFFSET_BITS=64","-D_GNU_SOURCE",'-DMBEDTLS_CONFIG_FILE="ri3_mbedtls_config.h"',f"-ffile-prefix-map={ROOT}=."]+[f"-I{x}" for x in includes]
 links=["-Wl,--gc-sections","-Wl,-z,noexecstack"]
 if a.target=="host":
  cc="/usr/bin/clang";cxx="/usr/bin/clang++";flags+=["-DRI3_SNAPSHOT_TESTING"]
 else:
  ndk=pathlib.Path(os.environ["LOCALAPPDATA"])/"Android/Sdk/ndk/28.2.13676358"
  if "Pkg.Revision = 28.2.13676358" not in (ndk/"source.properties").read_text():raise ValueError("NDK mismatch")
  bin=ndk/"toolchains/llvm/prebuilt/windows-x86_64/bin"
  cc=str(bin/"clang.exe");cxx=str(bin/"clang++.exe");flags+=["--target=aarch64-linux-android30"]
 if a.sanitize:flags+=["-fsanitize=address,undefined","-fno-omit-frame-pointer"];links+=["-fsanitize=address,undefined"]
 inputs={str(p.relative_to(ROOT)):sha(p) for p in sources+[HERE/"snapshot/snapshot_collect.h",HERE/"guard/guard_policy.h",HERE/"crypto/ri3_mbedtls_config.h",pathlib.Path(__file__)]}
 for d in (mb/"include",mb/"library"):inputs.update({str(p.relative_to(ROOT)):sha(p) for p in d.rglob("*.h")})
 ident=hashlib.sha256(json.dumps(inputs,sort_keys=True).encode()).hexdigest()
 stamp={"id":ident,"inputs":inputs,"flags":flags,"compiler":cxx};sp=out/"inputs.json"
 if sp.exists() and json.loads(sp.read_text())!=stamp:raise ValueError("changed inputs: new label required")
 sp.write_text(json.dumps(stamp,indent=2)+"\n")
 def run(cmd):
  start=datetime.datetime.now(datetime.timezone.utc).isoformat()
  p=subprocess.run([str(x) for x in cmd],env=env,capture_output=True,timeout=25)
  rec={"argv":[str(x) for x in cmd],"started":start,"completed":datetime.datetime.now(datetime.timezone.utc).isoformat(),"exit":p.returncode,"stdout":p.stdout.decode(errors="replace"),"stderr":p.stderr.decode(errors="replace")}
  with (out/"commands.jsonl").open("a") as f:f.write(json.dumps(rec)+"\n")
  if p.returncode:print(rec["stdout"],rec["stderr"]);raise RuntimeError("command failed")
  return rec
 if a.phase=="compile":
  objects=[]
  for i,s in enumerate(sources):
   obj=out/(str(i)+"-"+s.stem+".o")
   lang=["-std=c++17","-Wall","-Wextra","-Werror","-Wno-misleading-indentation"] if s.suffix==".cpp" else ["-std=c11"]
   run([cxx if s.suffix==".cpp" else cc,*flags,*lang,"-c",s,"-o",obj]);objects.append(obj)
  if a.target=="host":run([cxx,*objects,*links,"-o",out/"test-snapshot"])
  rec={"input_id":ident,"objects":{p.name:sha(p) for p in objects},"target":a.target,"installation_enabled":False,"executed_recovery_code":False}
  if a.target=="host":rec["helper_sha256"]=sha(out/"test-snapshot")
  (out/"build-receipt.json").write_text(json.dumps(rec,indent=2)+"\n");print(json.dumps(rec))
 else:
  rec=json.loads((out/"build-receipt.json").read_text())
  if rec["input_id"]!=ident or rec["helper_sha256"]!=sha(out/"test-snapshot"):raise ValueError("stale helper")
  fixture=out/("fixtures-"+datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%f"));fixture.mkdir()
  got=run([out/"test-snapshot",fixture,out/"test-snapshot"])
  passed=[l[5:] for l in got["stdout"].splitlines() if l.startswith("PASS\t")]
  total=[l[6:] for l in got["stdout"].splitlines() if l.startswith("TOTAL\t")]
  if len(total)!=1 or int(total[0])!=len(passed) or len(set(passed))!=len(passed):raise ValueError("incomplete results")
  rec={"input_id":ident,"passed":len(passed),"checks":passed,"helper_sha256":sha(out/"test-snapshot"),"command":got,"phone_io":False,"mount_calls":False,"recovery_binary_execution":False,"live_metadata_authority":False}
  (out/"test-receipt.json").write_text(json.dumps(rec,indent=2)+"\n");print(json.dumps(rec))
if __name__=="__main__":main()
