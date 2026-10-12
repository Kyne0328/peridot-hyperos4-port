import datetime,hashlib,json,os,pathlib,subprocess,sys
from build_crypto import ROOT,WORK,sha
label=sys.argv[1]
out=WORK/(label+"-host")
base=ROOT/"builder/work/installer-ri3-zipsign/fixtures-20261003T034032Z"
profile=ROOT/"builder/work/installer-ri3-zipsign/fixtures-20261003T040023Z"
stamp=datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
scratch=out/("test-"+stamp);scratch.mkdir()
env=os.environ.copy();env.update({"HOME":str(out/"home"),"TMPDIR":str(out/"tmp"),"XDG_CACHE_HOME":str(out/"cache")})
r={"timestamp":stamp,"scope":"host regular files only","binary_sha256":sha(out/"test-crypto"),"cli_sha256":sha(out/"verify-crypto"),"results":[]}
for name,args in [("base",[out/"test-crypto",base,scratch]),("profile",[out/"verify-crypto","--profile",profile]),("positive",[out/"verify-crypto","--verify",profile/"unsigned.zip"])]:
 p=subprocess.run([str(v) for v in args],cwd=ROOT,env=env,capture_output=True,text=True,timeout=15)
 item={"name":name,"exit":p.returncode,"stdout":p.stdout,"stderr":p.stderr};r["results"].append(item)
 (out/("host-tests-"+stamp+".json")).write_text(json.dumps(r,indent=2)+"\n")
 print(json.dumps(item),flush=True)
 if p.returncode:raise RuntimeError("crypto test failed: "+name)
proof=json.loads(r["results"][-1]["stdout"]);actual=hashlib.sha256((profile/"unsigned.zip").read_bytes()).hexdigest()
assert proof["full_file_sha256"]==actual
b=(profile/"unsigned.zip").read_bytes();assert proof["signed_sha256"]==hashlib.sha256(b[:proof["signed_bytes"]]).hexdigest()
r["base_checks"]=int(r["results"][0]["stdout"].split("CHECKS_PASSED=")[-1].strip())
r["profile_checks"]=int(r["results"][1]["stdout"].split("CHECKS_PASSED=")[-1].strip())
r["independent_hashlib_full_and_signed_match"]=True;r["passed"]=True
path=out/("host-tests-"+stamp+".json");path.write_text(json.dumps(r,indent=2)+"\n")
print(json.dumps({"receipt":str(path),"checks":r["base_checks"]+r["profile_checks"],"independent_hashlib_match":True}),flush=True)
