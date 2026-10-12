"""Copy the finalized candidate to a new filename and run ONLY read-only verification/preflight."""
from pathlib import Path
import argparse,hashlib,json,subprocess,time

ROOT=Path(__file__).resolve().parents[2];WORK=ROOT/'builder/work/installer-ri5-recoveryfix-20261004'
ap=argparse.ArgumentParser();ap.add_argument('--serial',required=True);a=ap.parse_args()
validation=json.loads((WORK/'package/VALIDATION.json').read_text());archive=Path(validation['archive'])
binary=WORK/'native-android-new/update-binary'
assert hashlib.sha256(binary.read_bytes()).hexdigest()==validation['native_sha256']
prefix=['adb','-s',a.serial]
steps=[]
def run(args,required=True):
    started=time.monotonic();p=subprocess.run(prefix+args,capture_output=True,text=True)
    record={'argv':prefix+args,'exit_code':p.returncode,'stdout':p.stdout,'stderr':p.stderr,'seconds':round(time.monotonic()-started,2)}
    steps.append(record)
    (WORK/'phone-verification-progress.json').write_text(json.dumps(steps,indent=2)+'\n',encoding='utf-8')
    if required:assert p.returncode==0,p.stdout+p.stderr
    return p
assert run(['get-state']).stdout.strip()=='recovery','Phone must be in recovery'
before=run(['shell','/system/bin/bootctl','get-active-boot-slot']).stdout.strip()
remote='/sdcard/'+archive.name
assert run(['shell','test','-e',remote],False).returncode!=0,'Refuse existing device ZIP overwrite'
print('Copying finalized candidate to new phone filename; no flash command is run',flush=True)
run(['push',str(archive),remote])
run(['push',str(binary),'/tmp/ri5-recoveryfix-verifier'])
run(['shell','chmod','700','/tmp/ri5-recoveryfix-verifier'])
print('Running complete read-only installer preflight in actual OrangeFox',flush=True)
preview=run(['shell','/tmp/ri5-recoveryfix-verifier','--preflight-readonly',remote])
assert 'READONLY_INSTALL_ENVIRONMENT_PASSED' in preview.stdout
print(preview.stdout,flush=True)
print('Verifying the whole signed ZIP and every image using the actual ARM64 updater',flush=True)
images=run(['shell','/tmp/ri5-recoveryfix-verifier','--verify-rom',remote])
assert 'RI5_READONLY_PAYLOADS_AND_EDIFY_VERIFIED' in images.stdout
after=run(['shell','/system/bin/bootctl','get-active-boot-slot']).stdout.strip()
assert before==after=='1','Active slot changed or was not the expected working B slot'
result={'passed':True,'remote_zip':remote,'archive_sha256':validation['sha256'],'native_sha256':validation['native_sha256'],
    'active_slot_before':before,'active_slot_after':after,'preflight_stdout':preview.stdout,'image_verification_stdout':images.stdout,
    'image_partition_writes_unmounts_mapping_removals_wipes_or_reboots_performed':False,
    'phone_file_copy_performed':True,'steps':steps}
(WORK/'phone-verification.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
validation['phone_readonly_verification']=result
(WORK/'package/VALIDATION.json').write_text(json.dumps(validation,indent=2)+'\n',encoding='utf-8')
print(json.dumps({k:result[k] for k in ['passed','remote_zip','active_slot_before','active_slot_after']},indent=2),flush=True)
