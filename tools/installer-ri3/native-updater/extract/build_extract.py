#!/usr/bin/env python3
"""Bounded resumable native extraction builds. Host tests use owned regular files only."""
import argparse,datetime,hashlib,json,os,pathlib,subprocess,sys
ROOT=pathlib.Path(__file__).resolve().parents[4]
HERE=ROOT/"tools/installer-ri3/native-updater"
WORK=ROOT/"builder/work/installer-ri3-native"
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 ap=argparse.ArgumentParser()
 ap.add_argument("--target",choices=["host","android"],required=True)
 ap.add_argument("--phase",choices=["compile","link","test"],required=True)
 ap.add_argument("--start",type=int,default=0);ap.add_argument("--count",type=int,default=6)
 ap.add_argument("--label",required=True);ap.add_argument("--sanitize",action="store_true")
 a=ap.parse_args()
 if not a.label or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for c in a.label):raise ValueError("invalid label")
 if a.sanitize and a.target!="host":raise ValueError("sanitizers are host only")
 out=WORK/"extract"/a.label/a.target;out.mkdir(parents=True,exist_ok=True)
 for n in ("tmp","home","cache"):(out/n).mkdir(exist_ok=True)
 env=os.environ.copy();env.update({n:str(out/"tmp") for n in ("TMPDIR","TMP","TEMP")})
 env.update({"HOME":str(out/"home"),"XDG_CACHE_HOME":str(out/"cache"),"LC_ALL":"C","TZ":"UTC","SOURCE_DATE_EPOCH":"1661990400"})
 v=WORK/"production-vendor";base=v/"base";sp=v/"core/libsparse";mb=v/"mbedtls-3.6.7";z=WORK/"vendor/zlib-1.3.2"
 sources=[mb/"library"/(s+".c") for s in ("sha256","platform_util","constant_time")]
 sources += [z/(s+".c") for s in ("adler32","crc32","deflate","infback","inffast","inflate","inftrees","trees","zutil","compress","uncompr","gzclose","gzlib","gzread","gzwrite")]
 sources += [sp/(s+".cpp") for s in ("backed_block","output_file","sparse","sparse_crc32","sparse_err","sparse_read")]
 sources += [base/"mapped_file.cpp", WORK/"vendor/libbase/stringprintf.cpp", WORK/"vendor/libbase/posix_strerror_r.cpp"]
 sources += [HERE/"extract/image_extract.cpp",HERE/"extract/test_extract.cpp"]
 includes=[HERE/"extract",HERE/"crypto",mb/"include",mb/"library",sp/"include",sp,base/"include",z]
 flags=["-O1","-g","-fno-ident","-ffunction-sections","-fdata-sections","-D_FILE_OFFSET_BITS=64","-D_LARGEFILE64_SOURCE=1","-D_POSIX_C_SOURCE=200809L","-DHAVE_UNISTD_H",'-DMBEDTLS_CONFIG_FILE="ri3_mbedtls_config.h"',f"-ffile-prefix-map={ROOT}=."]+[f"-I{p}" for p in includes]
 links=["-Wl,--gc-sections","-Wl,-z,noexecstack"]
 if a.target=="host":cc="/usr/bin/clang";cxx="/usr/bin/clang++"
 else:
  ndk=pathlib.Path(os.environ["LOCALAPPDATA"])/"Android/Sdk/ndk/28.2.13676358"
  if "Pkg.Revision = 28.2.13676358" not in (ndk/"source.properties").read_text():raise ValueError("NDK mismatch")
  p=ndk/"toolchains/llvm/prebuilt/windows-x86_64/bin";cc=str(p/"clang.exe");cxx=str(p/"clang++.exe")
  flags+=["--target=aarch64-linux-android30"];links+=["--target=aarch64-linux-android30","-static"]
 if a.sanitize:flags+=["-fsanitize=address,undefined","-fno-omit-frame-pointer"];links+=["-fsanitize=address,undefined"]
 files=set(sources+[HERE/"crypto/ri3_mbedtls_config.h",HERE/"extract/image_extract.h",pathlib.Path(__file__)])
 for d in includes:
  if d.exists():files.update(d.rglob("*.h"))
 hashes={str(p.relative_to(ROOT)):sha(p) for p in sorted(files)}
 input_id=hashlib.sha256(json.dumps(hashes,sort_keys=True).encode()).hexdigest()
 stamp={"input_id":input_id,"sources":hashes,"flags":flags,"compiler":cxx}
 stamp_path=out/"inputs.json"
 if stamp_path.exists() and json.loads(stamp_path.read_text())!=stamp:raise ValueError("source changed: choose a new build label")
 stamp_path.write_text(json.dumps(stamp,indent=2)+"\n")
 log=[]
 def run(cmd):
  started=datetime.datetime.now(datetime.timezone.utc).isoformat();print("RUN",cmd,flush=True)
  p=subprocess.run([str(x) for x in cmd],env=env,capture_output=True,text=True,timeout=30)
  record={"command":[str(x) for x in cmd],"started":started,"completed":datetime.datetime.now(datetime.timezone.utc).isoformat(),"exit":p.returncode,"stdout":p.stdout,"stderr":p.stderr}
  log.append(record)
  with (out/"commands.jsonl").open("a") as f:f.write(json.dumps(record)+"\n")
  if p.returncode:print(p.stdout,p.stderr);raise RuntimeError("command failed")
  return p.stdout
 objects=[out/(str(i)+"-"+s.stem+".o") for i,s in enumerate(sources)]
 if a.phase=="compile":
  if a.start<0 or not 1<=a.count<=32:raise ValueError("invalid group")
  for i in range(a.start,min(a.start+a.count,len(sources))):
   s=sources[i];obj=objects[i];lang=["-std=c++17"] if s.suffix==".cpp" else ["-std=c11"]
   extra=["-Wall","-Wextra","-Werror","-Wno-missing-field-initializers"] if s.parent==HERE/"extract" else []
   run([cxx if s.suffix==".cpp" else cc,*flags,*lang,*extra,"-c",s,"-o",obj])
   (out/(str(i)+".json")).write_text(json.dumps({"input_id":input_id,"source":sha(s),"object":sha(obj),"commands":log[-1:]},indent=2)+"\n")
   print("COMPILED",i,s.name,flush=True)
 elif a.phase=="link":
  for i,obj in enumerate(objects):
   stamp=json.loads((out/(str(i)+".json")).read_text())
   if stamp["input_id"]!=input_id or stamp["object"]!=sha(obj):raise ValueError("stale object")
  run([cxx,*objects,*links,"-o",out/"test-extract"])
  (out/"build-receipt.json").write_text(json.dumps({"input_id":input_id,"target":a.target,"binary_sha256":sha(out/"test-extract"),"source_built_libraries":["AOSP libsparse","Mbed TLS SHA256","zlib"],"installation_enabled":False,"commands":log},indent=2)+"\n")
 else:
  if a.target!="host":raise ValueError("Android execution requires separate enforcing harness")
  build=json.loads((out/"build-receipt.json").read_text())
  if build["input_id"]!=input_id or build["binary_sha256"]!=sha(out/"test-extract"):raise ValueError("stale test binary")
  fixtures=out/("fixtures-"+datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%f"));fixtures.mkdir()
  text=run([out/"test-extract",fixtures]);passed=[l[5:] for l in text.splitlines() if l.startswith("PASS\t")];total=[l[6:] for l in text.splitlines() if l.startswith("TOTAL\t")]
  if len(total)!=1 or int(total[0])!=len(passed) or len(set(passed))!=len(passed):raise ValueError("incomplete test output")
  (out/"test-receipt.json").write_text(json.dumps({"input_id":input_id,"passed":len(passed),"checks":passed,"commands":log,"fixture_bytes":sum(p.stat().st_size for p in fixtures.iterdir()),"device_io":False,"installation_enabled":False},indent=2)+"\n")
  print("PASSED",len(passed))
 print(json.dumps({"phase":a.phase,"target":a.target,"total_sources":len(sources),"out":str(out),"input_id":input_id}))
if __name__=="__main__":main()
