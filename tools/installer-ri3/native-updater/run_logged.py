#!/usr/bin/env python3
"""Windows entry point: bounded, durable logs for approved native module builds."""
import argparse,datetime,hashlib,json,os,pathlib,subprocess,sys,time
ROOT=pathlib.Path(__file__).resolve().parents[3]
WORK=ROOT/"builder/work/installer-ri3-native"
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--label",required=True)
 ap.add_argument("--runtime",choices=["wsl","windows"],required=True)
 ap.add_argument("--script",required=True);ap.add_argument("args",nargs=argparse.REMAINDER);a=ap.parse_args()
 if any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for c in a.label):raise ValueError("bad label")
 p=(ROOT/a.script).resolve()
 if not p.is_relative_to((ROOT/"tools/installer-ri3/native-updater").resolve()) or p.suffix!=".py":raise ValueError("script scope")
 out=WORK/"logged"/a.label;out.mkdir(parents=True,exist_ok=False)
 for n in ("tmp","home","cache"):(out/n).mkdir()
 env=os.environ.copy();env.update({n:str(out/"tmp") for n in ("TMP","TEMP","TMPDIR")})
 args=a.args[1:] if a.args and a.args[0]=="--" else a.args
 def linux(path):
  s=str(path.resolve()).replace("\\","/");return "/mnt/"+s[0].lower()+s[2:]
 if a.runtime=="windows":cmd=[sys.executable,"-B",str(p),*args]
 else:cmd=["wsl.exe","-d","Ubuntu","--","env","TMPDIR="+linux(out/"tmp"),"TMP="+linux(out/"tmp"),"TEMP="+linux(out/"tmp"),"HOME="+linux(out/"home"),"XDG_CACHE_HOME="+linux(out/"cache"),"python3","-B",linux(p),*args]
 receipt={"label":a.label,"started":datetime.datetime.now(datetime.timezone.utc).isoformat(),"command":cmd,"source_sha256":hashlib.sha256(p.read_bytes()).hexdigest(),"completed":False}
 (out/"receipt.json").write_text(json.dumps(receipt,indent=2)+"\n")
 rc=1
 try:
  proc=subprocess.run(cmd,env=env,capture_output=True,timeout=90)
  (out/"stdout.txt").write_bytes(proc.stdout);(out/"stderr.txt").write_bytes(proc.stderr)
  rc=proc.returncode;receipt.update({"completed":True,"returncode":rc})
 except subprocess.TimeoutExpired as e:
  (out/"stdout.txt").write_bytes(e.stdout or b"");(out/"stderr.txt").write_bytes(e.stderr or b"")
  receipt.update({"error":"outer_timeout","wsl_child_termination_proven":False})
 except Exception as e:receipt["error"]=repr(e)
 finally:
  receipt["finished"]=datetime.datetime.now(datetime.timezone.utc).isoformat()
  (out/"receipt.json").write_text(json.dumps(receipt,indent=2)+"\n")
 print(json.dumps(receipt));print((out/"stdout.txt").read_text(errors="replace")[-10000:] if (out/"stdout.txt").exists() else "")
 print((out/"stderr.txt").read_text(errors="replace")[-10000:] if (out/"stderr.txt").exists() else "")
 return rc
if __name__=="__main__":sys.exit(main())
