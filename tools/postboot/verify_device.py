"""Copy the update and run only the installer's read-only verification mode."""
import os
from pathlib import Path
import hashlib,json,subprocess,time
ROOT=Path(__file__).resolve().parents[2];WORK=Path('D:/hyperos4-peridot-postboot-20261004');OUT=WORK/'outputs'
v=json.loads((OUT/'VALIDATION.json').read_text());archive=Path(v['archive'])
assert v['all_member_crc_sha_checks_passed'] and v['avb_chain_verification']['passed']
before=archive.stat();assert before.st_size==v['bytes']
native=json.loads((ROOT/'builder/work/installer-ri5-recoveryfix-20261004/native-android-new-postboot1/build-receipt.json').read_text())
binary=Path(native['binary']);assert hashlib.sha256(binary.read_bytes()).hexdigest()==v['native_sha256']
commands=[]
def run(args,timeout=1200):
 started=time.monotonic();p=subprocess.run(['adb','-s',os.environ['ANDROID_SERIAL'],*args],capture_output=True,text=True,timeout=timeout)
 row={'args':args,'exit_code':p.returncode,'stdout':p.stdout[-16000:],'stderr':p.stderr[-16000:],'seconds':round(time.monotonic()-started,3)}
 commands.append(row)
 assert p.returncode==0,p.stdout+p.stderr
 return p.stdout.strip()
assert run(['get-state'],30)=='device'
remote='/sdcard/'+archive.name;verifier='/data/local/tmp/peridot-ri6-readonly-verifier'
print('Copying verified RI6 ZIP to the phone; no flashing or rebooting',flush=True)
run(['push','-Z',str(archive),remote])
run(['push',str(binary),verifier]);run(['shell','chmod','755',verifier])
print('Checking exact copied ZIP hash',flush=True)
assert run(['shell','sha256sum',remote]).split()[0]==v['sha256']
assert int(run(['shell','stat','-c','%s',remote]))==v['bytes']
print('Running ARM64 installer read-only payload/signature/Edify verification',flush=True)
output=run(['shell',verifier,'--verify-rom',remote])
assert 'RI5_READONLY_PAYLOADS_AND_EDIFY_VERIFIED' in output
after=archive.stat();assert (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns)
receipt={'passed':True,'device':os.environ['ANDROID_SERIAL'],'device_archive':remote,'archive_sha256':v['sha256'],'archive_bytes':v['bytes'],
 'copied_archive_local_identity':{'device':after.st_dev,'inode':after.st_ino,'bytes':after.st_size,'mtime_ns':after.st_mtime_ns},
 'native_sha256':v['native_sha256'],'mode':'--verify-rom','partition_writes_reboot_and_wipes_performed':False,
 'postboot_fixes_device_tested':False,'commands':commands}
(OUT/'DEVICE-READONLY-VERIFICATION.json').write_text(json.dumps(receipt,indent=2)+'\n')
print(json.dumps({k:receipt[k] for k in ['passed','device_archive','partition_writes_reboot_and_wipes_performed']},indent=2),flush=True)
