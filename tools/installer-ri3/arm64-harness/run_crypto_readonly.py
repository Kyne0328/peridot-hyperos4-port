import pathlib,hashlib,json,os,stat,subprocess,time,re,datetime
R=pathlib.Path.cwd()
BASE=R/'builder/work/installer-ri3-qemu'
run=BASE/'crypto-readonly-20261003T0530'
report=R/'09-reports/installer-ri3/arm64-harness/crypto-readonly-20261003T0530'
if run.exists(): raise RuntimeError('distinct run root already exists; inspect receipt, do not rerun')
report.mkdir(parents=True,exist_ok=True)
def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''): h.update(b)
 return h.hexdigest()
def find(name,expected):
 for p in BASE.rglob(name):
  if p.is_file() and not p.is_symlink() and sha(p)==expected:return p
 raise RuntimeError('verified tool absent: '+name)
qemu=find('qemu-aarch64-static','e4f8d99e9ff69c3cefffab71cee358ce2af1ecba1282d04c3eeb44ef76f5a71e')
launcher=find('ri3-file-jail','d931d5da04a06d783faf36480dce74e7466b5c8f8c41e21bad8ecb0e2eedd609')
cli=R/'builder/work/installer-ri3-native/crypto/crypto-v2-20261003T0404-android/verify-crypto'
assert sha(cli)=='daf1a612e56bcf59e78191f3c49d76b2da43e0b6d32a5468d39ba02764b91424'
src=R/'builder/work/installer-ri3-zipsign/fixtures-20261003T040023Z'
assert sha(src/'unsigned.zip')=='354978289160d599795e8d1ab872328cc8562e96bf112562192f0f7f6d63bb04'
files=[src/'unsigned.zip']+sorted((src/'cms-profile').rglob('*'))
files=[p for p in files if p.is_file()]
assert len(files)==11
assert all(not p.is_symlink() and p.stat().st_size<=65536 for p in files)
run.mkdir()
def copy(p,d):
 d.parent.mkdir(parents=True,exist_ok=True)
 with d.open('xb') as f:f.write(p.read_bytes())
 assert sha(p)==sha(d)
copy(qemu,run/'qemu-aarch64-static');copy(cli,run/'verify-crypto')
for p in files:copy(p,run/'fixtures'/p.relative_to(src))
os.chmod(run/'qemu-aarch64-static',0o755);os.chmod(run/'verify-crypto',0o755)
def inventory():
 return {str(p.relative_to(run)).replace('\\','/'):sha(p) for p in sorted(run.rglob('*')) if p.is_file()}
before=inventory()
assert not any(p.is_symlink() for p in run.rglob('*'))
assert not (run/'dev').exists() and not (run/'proc').exists()
def linux(p):return '/mnt/'+p.drive[0].lower()+str(p)[2:].replace('\\','/')
prefix=['wsl.exe','-d','Ubuntu','--','/usr/bin/unshare','--user','--map-root-user','--mount','--net','--pid','--fork','--kill-child','--ipc','--propagation','unchanged',linux(launcher),linux(run),'/qemu-aarch64-static','-strace','/verify-crypto']
cases=[]
for name,args in [('profile',['--profile','/fixtures']),('positive',['--verify','/fixtures/unsigned.zip'])]:
 command=prefix+args
 entry={'name':name,'argv':command,'start_utc':datetime.datetime.now(datetime.timezone.utc).isoformat()}
 (report/(name+'-admitted.json')).write_text(json.dumps(entry,indent=2))
 start=time.monotonic()
 try:
  p=subprocess.run(command,input=b'',stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=90)
  out=p.stdout.decode('utf-8','replace');err=p.stderr.decode('utf-8','replace')
  entry.update(returncode=p.returncode,stdout=out,elapsed_seconds=time.monotonic()-start)
  (report/(name+'.stdout.txt')).write_text(out)
  (report/(name+'.stderr.txt')).write_text(err)
  entry['trace_scope']='QEMU guest syscalls, not complete host-kernel trace'
  entry['device_attempt_lines']=[x for x in err.splitlines() if '/dev/' in x or '/proc/' in x]
  entry['passed']=p.returncode==0 and ('CHECKS_PASSED=12' in out if name=='profile' else ('354978289160d599795e8d1ab872328cc8562e96bf112562192f0f7f6d63bb04' in out and '7f46b8d7b49204b00acc6c84b38add2f1a2b10d6edf6b5331e72f757b3aaa1b4' in out))
 except subprocess.TimeoutExpired as e:
  entry.update(passed=False,timeout=True,elapsed_seconds=time.monotonic()-start)
  (report/(name+'.stdout.txt')).write_bytes(e.stdout or b'')
  (report/(name+'.stderr.txt')).write_bytes(e.stderr or b'')
 finally:
  (report/(name+'-result.json')).write_text(json.dumps(entry,indent=2))
 cases.append(entry)
 if not entry['passed']:break
after=inventory()
result={'cli_sha256':sha(cli),'launcher_sha256':sha(launcher),'qemu_sha256':sha(qemu),'fixture_before':before,'fixture_after':after,'root_unchanged':before==after,'cases':cases,'passed':len(cases)==2 and all(x['passed'] for x in cases) and before==after,'no_device_backend':True,'unchanged_reviewed_readonly_jail':True}
(report/'result.json').write_text(json.dumps(result,indent=2))
print(json.dumps(result,indent=2))
if not result['passed']:raise SystemExit(1)
