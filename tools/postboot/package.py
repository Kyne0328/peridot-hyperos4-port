"""Emit a separate compressed RI6 update without changing source ROMs or userdata policy."""
from pathlib import Path
import hashlib,json,shutil,sys,time,zipfile

ROOT=Path(__file__).resolve().parents[2];WORK=Path('D:/hyperos4-peridot-postboot-20261004');OUT=WORK/'outputs'
EVIDENCE=ROOT/'builder/work/postboot-20261004'
sys.path[:0]=[str(ROOT/'tools/installer-ri3/zip-signing'),str(ROOT/'tools/installer-ri5')]
from sign_zip import sign_generated_zip
from compressed_copy import copy_member
NAME='F6-Global-HyperOS4-DEV2-RI6-POSTBOOT-FIX1-20261004.zip'

def sha(path):
 with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def save(path,value):path.write_text(json.dumps(value,indent=2)+'\n',encoding='utf-8')
def main():
 assembly=json.loads((WORK/'ASSEMBLY.json').read_text());assert assembly['avb_root_and_system_signatures_verified']
 chain=json.loads((WORK/'AVB-VERIFICATION.json').read_text());assert chain['passed']
 for name in ['super','vbmeta','vbmeta_system']:assert sha(WORK/(name+'.img'))==chain[name+'_sha256']
 previous=json.loads((ROOT/'builder/work/installer-ri5-recoveryfix-20261004/package/VALIDATION.json').read_text());source=Path(previous['archive'])
 assert sha(source)==previous['sha256']==assembly['source_zip_sha256']
 native=json.loads((ROOT/'builder/work/installer-ri5-recoveryfix-20261004/native-android-new-postboot1/build-receipt.json').read_text())
 binary=Path(native['binary']).read_bytes();assert hashlib.sha256(binary).hexdigest()==native['binary_sha256']
 for name,digest in native['sources'].items():assert sha(ROOT/name)==digest,'Compiled source drift'
 pins={x['name']:x for x in assembly['pins']};assert len(pins)==32
 OUT.mkdir(exist_ok=True);assert shutil.disk_usage(OUT).free>20*1024**3
 final=OUT/NAME;partial=OUT/(NAME+'.partial');assert not final.exists() and not partial.exists()
 script='''ui_print("F6 Global HyperOS4 RI6 POSTBOOT FIX1: launcher, corners and haptics update.");
ui_print("Install the complete image set; slot A is selected after verified success.");
assert(ri5_install());
ui_print("Update verified. Reboot Recovery to load the installed A boot environment, then reboot System.");
ui_print("Existing RI5 DECRYPT userdata is preserved. No Format Data is needed for this update.");
'''
 member_hashes={};new_images={name:WORK/(name+'.img') for name in ['super','vbmeta','vbmeta_system']}
 with zipfile.ZipFile(source) as old,zipfile.ZipFile(partial,'x',allowZip64=True) as target:
  manifest=json.loads(old.read('RI5-BUILD-MANIFEST.json'))
  manifest.update(build_id='F6-Global-HyperOS4-DEV2-RI6-POSTBOOT-FIX1',installer_revision='RI6-POSTBOOT-FIX1',
   images=[{k:v for k,v in p.items() if k in ['name','bytes','sha256']} for p in assembly['pins']],
   postboot_fixes=['MiuiHome Recents binding','Home settings package property','F6 20dp corner resources','default vibrator service instance and matching framework lookup'],
   install_over='Booted RI5 RECOVERYFIX3 DECRYPT',userdata_format_required=False,device_postboot_fixes_tested=False)
  replacements={'META-INF/com/google/android/update-binary':binary,'META-INF/com/google/android/updater-script':script.encode(),
   'RI5-BUILD-MANIFEST.json':(json.dumps(manifest,indent=2)+'\n').encode()}
  for entry in old.infolist():
   name=entry.filename;partition=name.split('/')[-1][:-4] if name.startswith('partitions/') else None
   if partition not in new_images and name not in replacements:
    copy_member(source,old,target,entry)
    if partition:member_hashes[name]=pins[partition]['sha256']
    else:member_hashes[name]=hashlib.sha256(old.read(entry)).hexdigest()
    continue
   info=zipfile.ZipInfo(name,entry.date_time);info.create_system=entry.create_system;info.external_attr=entry.external_attr
   info.compress_type=zipfile.ZIP_DEFLATED;info._compresslevel=6
   h=hashlib.sha256();count=0
   if partition in new_images:
    path=new_images[partition];info.file_size=path.stat().st_size;print('Compressing updated',partition,flush=True)
    with target.open(info,'w',force_zip64=True) as dst,path.open('rb') as src:
     for block in iter(lambda:src.read(1024*1024),b''):dst.write(block);h.update(block);count+=len(block)
    assert count==pins[partition]['bytes'] and h.hexdigest()==pins[partition]['sha256']
   else:
    data=replacements[name];info.file_size=len(data)
    with target.open(info,'w',force_zip64=True) as dst:dst.write(data)
    h.update(data)
   member_hashes[name]=h.hexdigest()
 print('Verifying all 37 output member CRCs and decoded hashes',flush=True)
 with zipfile.ZipFile(partial) as z:
  assert len(z.namelist())==len(set(z.namelist()))==37
  for entry in z.infolist():
   with z.open(entry) as f:assert hashlib.file_digest(f,'sha256').hexdigest()==member_hashes[entry.filename]
 partial.rename(final)
 signing=json.loads((ROOT/'builder/work/installer-ri5-recoveryfix-20261004/signing-public.json').read_text())
 signature=sign_generated_zip(final,ROOT/signing['certificate_path'],ROOT/signing['private_key_path'],generated_root=OUT,
  generated_parent=WORK,work_dir=EVIDENCE,expected_cert_sha256=signing['certificate_der_sha256'],reserve_bytes=4*1024**3)
 result={'archive':str(final),'bytes':final.stat().st_size,'sha256':sha(final),'native_sha256':native['binary_sha256'],
  'all_member_crc_sha_checks_passed':True,'signature':signature,'assembly':assembly,'avb_chain_verification':chain,'userdata_format_required':False,
  'postboot_fixes_device_verified':False,'no_automatic_phone_partition_flash_or_wipes':True}
 save(OUT/'VALIDATION.json',result);(OUT/(NAME+'.sha256')).write_text(result['sha256']+'  '+NAME+'\n')
 print(json.dumps({k:result[k] for k in ['archive','bytes','sha256']},indent=2),flush=True)

if __name__=='__main__':main()
