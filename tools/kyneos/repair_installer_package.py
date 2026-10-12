"""Create INSTALLFIX1 by replacing only the RI7 installer and informational manifest."""
from pathlib import Path
import hashlib,json,sys,zipfile
ROOT=Path(__file__).resolve().parents[2]
WORK=ROOT/'builder/work/kyneos-ri7-install-failure-20261005'
OLD=Path('D:/hyperos4-peridot-kyneos-ri7-20261005/outputs')
OUT=Path('D:/hyperos4-peridot-kyneos-ri7-installfix1-20261005/outputs')
sys.path[:0]=[str(ROOT/'tools/installer-ri5'),str(ROOT/'tools/installer-ri3/zip-signing')]
from compressed_copy import copy_member
from sign_zip import sign_generated_zip
def sha(p):
 with Path(p).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 old=json.loads((OLD/'VALIDATION.json').read_text());source=Path(old['archive']);assert sha(source)==old['sha256']
 tests=json.loads((WORK/'BACKEND-TESTS.json').read_text());assert tests['passed']
 native=json.loads((ROOT/'builder/work/installer-ri5-recoveryfix-20261004/native-android-new-kyneosri7otgfix/build-receipt.json').read_text())
 for name,digest in native['sources'].items():assert sha(ROOT/name)==digest,name
 binary=Path(native['binary']).read_bytes();assert hashlib.sha256(binary).hexdigest()==native['binary_sha256']
 OUT.mkdir(parents=True,exist_ok=True)
 name='KyneOS-Global-HyperOS4-POCO-F6-RI7.1-INSTALLFIX1-20261005.zip'
 final=OUT/name;partial=OUT/(name+'.partial');assert not final.exists() and not partial.exists()
 hashes=dict(old['member_hashes'])
 with zipfile.ZipFile(source) as src,zipfile.ZipFile(partial,'x',allowZip64=True) as dst:
  manifest=json.loads(src.read('RI5-BUILD-MANIFEST.json'));manifest['installer_revision']='RI7.1-INSTALLFIX1';manifest['installer_fix']='Retain unnamed MBR partitions by exact device identity without aliasing named ROM targets'
  replacements={'META-INF/com/google/android/update-binary':binary,'RI5-BUILD-MANIFEST.json':(json.dumps(manifest,indent=2)+'\n').encode()}
  for entry in src.infolist():
   if entry.filename not in replacements:copy_member(source,src,dst,entry);continue
   data=replacements[entry.filename];info=zipfile.ZipInfo(entry.filename,entry.date_time);info.create_system=entry.create_system;info.external_attr=entry.external_attr;info.compress_type=zipfile.ZIP_DEFLATED
   dst.writestr(info,data);hashes[entry.filename]=hashlib.sha256(data).hexdigest()
 print('Verifying all unchanged image hashes and replacement members',flush=True)
 with zipfile.ZipFile(partial) as z:
  assert len(z.namelist())==37
  for entry in z.infolist():
   with z.open(entry) as f:assert hashlib.file_digest(f,'sha256').hexdigest()==hashes[entry.filename]
 partial.rename(final)
 keys=json.loads((ROOT/'builder/work/installer-ri5-recoveryfix-20261004/signing-public.json').read_text())
 sig=sign_generated_zip(final,ROOT/keys['certificate_path'],ROOT/keys['private_key_path'],generated_root=OUT,generated_parent=OUT.parent,work_dir=WORK,expected_cert_sha256=keys['certificate_der_sha256'],reserve_bytes=4*1024**3)
 receipt={'archive':str(final),'bytes':final.stat().st_size,'sha256':sha(final),'source_archive_sha256':old['sha256'],'native_sha256':native['binary_sha256'],'member_hashes':hashes,'all_member_crc_sha_checks_passed':True,'all_32_image_payloads_byte_identical_to_RI7':True,'signature':sig,'backend_tests':str(WORK/'BACKEND-TESTS.json'),'device_flash_performed':False,'recommended_source_location':'/data/media/0 (internal storage), not exfat-fuse USB mount'}
 (OUT/'VALIDATION.json').write_text(json.dumps(receipt,indent=2)+'\n',encoding='utf-8');(OUT/(name+'.sha256')).write_text(receipt['sha256']+'  '+name+'\n')
 print(json.dumps({k:receipt[k] for k in ['archive','bytes','sha256']},indent=2),flush=True)
if __name__=='__main__':main()
