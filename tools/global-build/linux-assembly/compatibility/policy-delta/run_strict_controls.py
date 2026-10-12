from pathlib import Path
import concurrent.futures,json,subprocess,shlex
R=Path(__file__).resolve().parent

def run(name,status):
 j=json.loads((R/status).read_text());cmd=[x for x in j['command'] if x!='-N'];cmd[cmd.index('-o')+1]=str(R/(name+'.policy'));cmd[cmd.index('-f')+1]=str(R/(name+'.contexts'));(R/(name+'.command.txt')).write_text(shlex.join(cmd)+'\n');p=subprocess.run(cmd,capture_output=True,text=True);(R/(name+'.stdout.txt')).write_text(p.stdout);(R/(name+'.stderr.txt')).write_text(p.stderr);out={'command':cmd,'returncode':p.returncode,'neverallow_check_failed_count':p.stderr.count('neverallow check failed'),'all_neverallow_assertions_enabled':True};(R/(name+'.status.json')).write_text(json.dumps(out,indent=2));print(name,p.returncode,out['neverallow_check_failed_count'],flush=True)
with concurrent.futures.ThreadPoolExecutor(max_workers=2) as e:list(e.map(lambda x:run(*x),[('pcc-proposed-strict','pcc-proposed-runtime.status.json'),('donor-strict','donor-runtime.status.json')]))
