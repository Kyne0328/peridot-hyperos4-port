#!/usr/bin/env python3
"""Build read-only verifier CLI from completed pinned crypto objects; run tiny host controls."""
import argparse,hashlib,json,os,pathlib,subprocess,datetime
from build_crypto import ROOT,HERE,WORK,SIGNER,c_sources,includes,definitions,sha
ap=argparse.ArgumentParser();ap.add_argument("--target",choices=["host","android"],required=True);ap.add_argument("--label",required=True);ap.add_argument("--tests",action="store_true");ap.add_argument("--fixture",default="builder/work/installer-ri3-zipsign/fixtures-20261003T040023Z");a=ap.parse_args()
out=WORK/(a.label+"-"+a.target);r=json.loads((out/"build-receipt.json").read_text())
for rel,digest in r["source_sha256"].items():
 p=ROOT/pathlib.Path(rel.replace("\\","/"))
 if sha(p)!=digest:raise RuntimeError("Source changed since crypto build: "+rel)
env=os.environ.copy();env.update({"HOME":str(out/"home"),"TMPDIR":str(out/"tmp"),"TMP":str(out/"tmp"),"TEMP":str(out/"tmp"),"XDG_CACHE_HOME":str(out/"cache")})
if a.target=="host": cxx="/usr/bin/clang++";target=[]
else:
 cxx=pathlib.Path(os.environ["ANDROID_NDK_HOME"]) / "toolchains/llvm/prebuilt/windows-x86_64/bin/clang++.exe";target=["--target=aarch64-linux-android30"]
commands=[]
def run(cmd):
 p=subprocess.run([str(v) for v in cmd],cwd=ROOT,env=env,capture_output=True,text=True,timeout=20)
 q={"argv":[str(v) for v in cmd],"exit_code":p.returncode,"stdout":p.stdout,"stderr":p.stderr};commands.append(q)
 if p.returncode:print(json.dumps(q),flush=True);raise RuntimeError("CLI build/test failed")
 return q
binary=out/"verify-crypto";obj=out/"verify_crypto.o"
if binary.exists():raise RuntimeError("CLI output already exists; inspect receipt before retry")
flags=target+["-O2","-std=c++17"]+definitions()+["-I"+str(p) for p in includes()]
if r["sanitized"]:flags+=["-fsanitize=address,undefined","-fno-omit-frame-pointer"]
run([cxx,*flags,"-c",HERE/"verify_crypto.cpp","-o",obj])
objects=[out/(p.stem+".o") for p in c_sources()+[HERE/"native_zip_crypto.cpp",SIGNER/"zip_verify_adapter.cpp",SIGNER/"asn1_decoder.cpp"]]
link=target+["-Wl,--gc-sections"]+(["-static"] if a.target=="android" else [])
if r["sanitized"]:link+=["-fsanitize=address,undefined"]
run([cxx,*link,*objects,obj,"-o",binary])
receipt={"timestamp":datetime.datetime.now(datetime.timezone.utc).isoformat(),"target":a.target,"source":sha(HERE/"verify_crypto.cpp"),"objects":{p.name:sha(p) for p in objects+[obj]},"crypto_build_receipt":sha(out/"build-receipt.json"),"binary_sha256":sha(binary),"commands":commands,"tests_run":False}
(out/"cli-receipt.json").write_text(json.dumps(receipt,indent=2)+"\n")
if a.tests:
 if a.target!="host":raise RuntimeError("ARM runtime belongs in reviewed isolated harness")
 fixture=ROOT/a.fixture
 scratch=out/"tiny-test-fixtures";scratch.mkdir(exist_ok=False)
 base=run([out/"test-crypto",ROOT/"builder/work/installer-ri3-zipsign/fixtures-20261003T034032Z",scratch]);profile=run([binary,"--profile",fixture]);positive=run([binary,"--verify",fixture/"unsigned.zip"])
 proof=json.loads(positive["stdout"]);actual=hashlib.sha256((fixture/"unsigned.zip").read_bytes()).hexdigest()
 if proof["full_file_sha256"]!=actual:raise RuntimeError("Independent hashlib full SHA mismatch")
 receipt["tests_run"]=True;receipt["base_checks"]=int(base["stdout"].split("CHECKS_PASSED=")[-1].strip());receipt["profile_checks"]=int(profile["stdout"].split("CHECKS_PASSED=")[-1].strip());receipt["positive_receipt"]=proof;receipt["independent_full_sha256"]=actual;receipt["commands"]=commands
 (out/"host-tests.json").write_text(json.dumps(receipt,indent=2)+"\n")
 print(json.dumps({"base_checks":receipt["base_checks"],"profile_checks":receipt["profile_checks"],"full_sha256":actual,"receipt":str(out/"host-tests.json")}),flush=True)
else:print(json.dumps({"cli":str(binary),"sha256":sha(binary),"receipt":str(out/"cli-receipt.json")}),flush=True)
