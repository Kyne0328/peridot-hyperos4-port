"""Copy INSTALLFIX1 to internal storage and run only real-recovery read-only preflight."""
import os
from pathlib import Path
import json,subprocess,time
ROOT=Path(__file__).resolve().parents[2]
OUT=Path('D:/hyperos4-peridot-kyneos-ri7-installfix1-20261005/outputs')
WORK=ROOT/'builder/work/kyneos-ri7-install-failure-20261005'
v=json.loads((OUT/'VALIDATION.json').read_text());archive=Path(v['archive'])
native=ROOT/'builder/work/installer-ri5-recoveryfix-20261004/native-android-new-kyneosri7otgfix/update-binary'
prefix=['adb','-s',os.environ['ANDROID_SERIAL']];steps=[]
def run(args,timeout=1500,required=True):
 start=time.monotonic();p=subprocess.run(prefix+args,capture_output=True,text=True,timeout=timeout)
 steps.append({'argv':prefix+args,'exit_code':p.returncode,'stdout':p.stdout,'stderr':p.stderr,'seconds':round(time.monotonic()-start,2)})
 (WORK/'RECOVERY-PROGRESS.json').write_text(json.dumps(steps,indent=2)+'\n',encoding='utf-8')
 assert not required or p.returncode==0,p.stdout+p.stderr
 return p
assert run(['get-state']).stdout.strip()=='recovery'
before=run(['shell','/system/bin/bootctl','get-active-boot-slot']).stdout.strip()
remote='/data/media/0/'+archive.name
assert run(['shell','test','-e',remote],required=False).returncode!=0,'Refuse existing phone archive overwrite'
print('Copying fixed ZIP to internal storage; no flash is run',flush=True)
run(['push',str(archive),remote]);run(['push',str(native),'/tmp/ri7-installfix1-verifier']);run(['shell','chmod','700','/tmp/ri7-installfix1-verifier'])
print('Checking exact recovery environment with read-only installer preflight',flush=True)
result=run(['shell','/tmp/ri7-installfix1-verifier','--preflight-readonly',remote])
after=run(['shell','/system/bin/bootctl','get-active-boot-slot']).stdout.strip()
passed='READONLY_INSTALL_ENVIRONMENT_PASSED' in result.stdout and before==after
receipt={'passed':passed,'archive_sha256':v['sha256'],'remote_zip':remote,'native_sha256':v['native_sha256'],'active_slot_before':before,'active_slot_after':after,'stdout':result.stdout,'steps':steps,'partition_writes_unmounts_mapping_removals_slot_changes_wipes_reboots':False}
(OUT/'RECOVERY-READONLY-PREFLIGHT.json').write_text(json.dumps(receipt,indent=2)+'\n',encoding='utf-8');print(result.stdout,flush=True);assert passed
