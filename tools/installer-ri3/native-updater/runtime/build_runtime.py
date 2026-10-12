#!/usr/bin/env python3
"""Build fixed RI3 runtime or compile-time regular-file fixture harness; no device execution."""
import argparse,datetime,hashlib,json,os,pathlib,subprocess,sys
ROOT=pathlib.Path(__file__).resolve().parents[4]
HERE=ROOT/"tools/installer-ri3/native-updater";WORK=ROOT/"builder/work/installer-ri3-native"
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--target",choices=["android","fixture"],required=True)
 ap.add_argument("--phase",choices=["compile","link"],required=True);ap.add_argument("--label",required=True)
 ap.add_argument("--backend-archive");ap.add_argument("--activate",action="store_true");a=ap.parse_args()
 if any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for c in a.label):raise ValueError("bad label")
 if a.activate and a.target!="android":raise ValueError("activation only belongs to production Android")
 out=WORK/"runtime-integration"/a.label;out.mkdir(parents=True,exist_ok=True)
 for d in ("tmp","home","cache"):(out/d).mkdir(exist_ok=True)
 env=os.environ.copy();env.update({k:str(out/"tmp") for k in ("TMPDIR","TMP","TEMP")});env.update(HOME=str(out/"home"),XDG_CACHE_HOME=str(out/"cache"),LC_ALL="C",TZ="UTC",SOURCE_DATE_EPOCH="1661990400")
 inc=[HERE,HERE/"runtime",WORK/"vendor/recovery/edify/include",WORK/"vendor/recovery/otautil/include",WORK/"vendor/libbase/include",WORK/"vendor/zlib-1.3.2",WORK/"vendor/zlib-1.3.2/contrib/minizip",WORK/"generated",WORK/"production-vendor/base/include",WORK/"production-vendor/core/fs_mgr/libdm/include"]
 flags=["-std=c++17","-O2","-g","-fno-ident","-ffunction-sections","-fdata-sections","-D_FILE_OFFSET_BITS=64","-D_LARGEFILE64_SOURCE=1","-D_POSIX_C_SOURCE=200809L",f"-ffile-prefix-map={ROOT}=."]+["-I"+str(p) for p in inc]
 links=["-Wl,--gc-sections","-Wl,-z,noexecstack","-Wl,-z,relro","-Wl,-z,now"]
 sources=[HERE/"guard/guard_policy.cpp",HERE/"runtime/install_runtime.cpp"]
 if a.target=="android":
  ndk=pathlib.Path(os.environ["LOCALAPPDATA"])/"Android/Sdk/ndk/28.2.13676358"
  if "Pkg.Revision = 28.2.13676358" not in (ndk/"source.properties").read_text():raise ValueError("NDK mismatch")
  cxx=ndk/"toolchains/llvm/prebuilt/windows-x86_64/bin/clang++.exe";flags+=["--target=aarch64-linux-android30"];links+=["--target=aarch64-linux-android30","-static"]
  if a.activate:flags+=["-DRI3_ENABLE_DEVICE_INSTALL=1"]
  sources += [HERE/"runtime/main.cpp"]
  ext=WORK/"extract/extract-android-v3-20261003T0440/android";crypto=WORK/"crypto/crypto-v2-20261003T0404-android"
  output=out/"update-binary"
 else:
  cxx=pathlib.Path("/usr/bin/clang++");flags+=["-DRI3_FILE_FIXTURE_RUNTIME=1"]
  sources += [HERE/"backend"/(s+".cpp") for s in ("storage_backend","topology","verity_table","unmount")]
  sources += [HERE/"runtime/fixture/fixture_backend.cpp",HERE/"runtime/fixture/fixture_main.cpp"]
  ext=WORK/"extract/extract-v3-20261003T0431/host";crypto=WORK/"crypto/crypto-host-20261003T0424-host"
  output=out/"fixture-install"
 tracked=set(sources)
 for d in (HERE/"guard",HERE/"runtime",HERE/"backend",HERE/"crypto",HERE/"snapshot",HERE/"extract"):
  tracked.update(d.rglob("*.h"))
 if a.target=="android":tracked={p for p in tracked if "fixture" not in p.parts}
 hashes={str(p.relative_to(ROOT)):sha(p) for p in sorted(tracked)}
 source_id=hashlib.sha256(json.dumps(hashes,sort_keys=True).encode()).hexdigest()
 frame={"source_id":source_id,"sources":hashes,"flags":flags,"target":a.target,"activation":a.activate}
 frame_path=out/"inputs.json"
 if frame_path.exists() and json.loads(frame_path.read_text())!=frame:raise ValueError("source changed: use a new build label")
 frame_path.write_text(json.dumps(frame,indent=2)+"\n")
 commands=[]
 def run(cmd):
  record={"argv":[str(x) for x in cmd],"started":datetime.datetime.now(datetime.timezone.utc).isoformat()}
  try:
   r=subprocess.run(record["argv"],env=env,capture_output=True,timeout=45)
   record.update(rc=r.returncode,stdout=r.stdout.decode(errors="replace"),stderr=r.stderr.decode(errors="replace"))
  except Exception as e:record.update(rc=1,error=repr(e))
  finally:
   record["finished"]=datetime.datetime.now(datetime.timezone.utc).isoformat();commands.append(record)
   with (out/"commands.jsonl").open("a") as f:f.write(json.dumps(record)+"\n")
  if record["rc"]:print(json.dumps(record,indent=2));raise RuntimeError("compiler/linker failed")
 objects=[out/(str(i)+"-"+p.stem+".o") for i,p in enumerate(sources)]
 if a.phase=="compile":
  for p,o in zip(sources,objects):
   run([cxx,*flags,"-c",p,"-o",o]);(out/(o.name+".json")).write_text(json.dumps({"source_id":source_id,"object_sha256":sha(o)})+"\n")
 else:
  for o in objects:
   receipt=json.loads((out/(o.name+".json")).read_text())
   if receipt["source_id"]!=source_id or receipt["object_sha256"]!=sha(o):raise ValueError("stale runtime object")
  shared=[]
  for i in range(3,28):
   matches=list(ext.glob(str(i)+"-*.o"))
   if len(matches)!=1:raise ValueError("missing extraction object "+str(i))
   shared+=matches
  crypt=[p for p in sorted(crypto.glob("*.o")) if "test_crypto" not in p.name and "verify_crypto" not in p.name]
  if len(crypt)!=14:raise ValueError("crypto object inventory: "+str([p.name for p in crypt]))
  shared+=crypt
  if a.target=="android":
   core=WORK/"build-android"
   for i in (15,16,17,18,21,22):
    matches=list(core.glob(str(i)+"-*.o"))
    if len(matches)!=1:raise ValueError("missing Edify/minizip object "+str(i))
    shared+=matches
   snap=WORK/"snapshot/snapshot-v2-final/android";shared += [snap/"0-metadata.o",snap/"1-hal_query.o"]
   if not a.backend_archive:raise ValueError("actual source-built backend archive required")
   archive=pathlib.Path(a.backend_archive).resolve()
   if not archive.is_relative_to(WORK.resolve()) or not archive.is_file():raise ValueError("backend archive scope")
   shared+=[archive]
  else:
   # Fixture coordinator's held ZIP reader still uses the genuine minizip parser.
   core=WORK/"build-host";shared += [next(core.glob("15-*.o")),next(core.glob("16-*.o"))]
  run([cxx,*objects,*shared,*links,"-o",output])
  receipt={"source_id":source_id,"target":a.target,"activation":a.activate,"fixture_profile":a.target=="fixture","binary":str(output),"binary_bytes":output.stat().st_size,"binary_sha256":sha(output),"input_objects":{str(p.relative_to(ROOT)):sha(p) for p in objects+shared},"commands":commands}
  (out/"build-receipt.json").write_text(json.dumps(receipt,indent=2)+"\n")
  print(json.dumps({k:receipt[k] for k in ("binary","binary_bytes","binary_sha256","target","activation","fixture_profile")}))
 print("COMPLETED",a.phase,a.target,a.label,source_id)
if __name__=="__main__":main()
