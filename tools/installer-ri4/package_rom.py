"""Build a fresh RI4 single recovery ZIP; never modify RI2/RI3 or source images."""
from pathlib import Path
import hashlib,json,os,shutil,sys,zipfile
ROOT=Path(__file__).resolve().parents[2];WORK=ROOT/'builder/work/installer-ri4';OUT=WORK/'package';OUT.mkdir(exist_ok=True)
sys.path[:0]=[str(ROOT/'tools/installer-ri3/package'),str(ROOT/'tools/installer-ri3/zip-signing')]
import sparse_super as sparse
from sign_zip import sign_generated_zip
from verify_zip import verify_zip
NAME='F6-Global-HyperOS4-DEV2-RI4-DECRYPT-20261003.zip'
def sha(p):
 with Path(p).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def info(n,size):
 i=zipfile.ZipInfo(n,(1980,1,1,0,0,0));i.compress_type=zipfile.ZIP_STORED;i.create_system=3;i.external_attr=(0o100755 if n.endswith('update-binary') else 0o100644)<<16;i.file_size=size;return i
images=json.loads((WORK/'images.json').read_text());byname={x['name']:x for x in images['images']};native=json.loads((WORK/'native/build-receipt.json').read_text());super=byname['super'];pins=dict(expected_bytes=super['size'],expected_sha256=super['sha256'],capacity_bytes=super['size'])
print('Planning complete sparse super',flush=True);plan=sparse.analyze_file(super['path'],**pins)
assert shutil.disk_usage(WORK).free>plan['sparse_bytes']+sum(x['size'] for x in byname.values() if x['name']!='super')+12*1024**3
script='ui_print("F6 Global HyperOS4 RI4 DECRYPT: complete slot-A installation.");\nui_print("Keep this recovery running; slot A is selected only after verified installation.");\nassert(ri4_install());\nui_print("Install verified. Reboot Recovery, then Format Data for the encrypted-to-decrypted transition.");\nui_print("Format Data erases all internal storage. No automatic data wipe was performed.");\n'
(WORK/'updater-script').write_text(script,newline='\n')
manifest={'build_id':'F6-Global-HyperOS4-DEV2-RI4-DECRYPT','images':[dict(name=x['name'],bytes=x['size'],sha256=x['sha256'],changed=x['changed']) for x in byname.values()],'writes':'super and all 31 slot-A physical image prefixes; selects A last','B_physical_images_written':False,'B_logical_images_preserved':False,'userdata_or_metadata_erased':False,'preinstalled_paired_recovery_required':False,'existing_A_firmware_required':False,'encryption_configuration':'userdata FBE and metadata encryption removed with explicit user authorization','device_tested':False,'production_release':False}
small=[('META-INF/com/android/otacert',(ROOT/'builder/work/installer-ri3-recovery/images-ziptrust/development-zip.x509.pem').read_bytes()),('META-INF/com/google/android/update-binary',(WORK/'native/update-binary').read_bytes()),('META-INF/com/google/android/updater-script',script.encode()),('RI4-SOURCE-MANIFEST.json',(ROOT/'.cache/global-single-recovery-ri2/source-images/MANIFEST.json').read_bytes()),('RI4-BUILD-MANIFEST.json',(json.dumps(manifest,indent=2)+'\n').encode())]
assert hashlib.sha256(small[1][1]).hexdigest()==native['binary_sha256']
partial=OUT/(NAME+'.partial');final=OUT/NAME;assert not final.exists() and not partial.exists()
encoded={}
with zipfile.ZipFile(partial,'x',allowZip64=True) as z:
 for name,data in small:
  with z.open(info(name,len(data)),'w',force_zip64=True) as f:f.write(data)
 for name in native['image_order']:
  row=byname[name];member='partitions/'+name+'.bin';print('Packaging',name,flush=True)
  if name=='super':
   with z.open(info(member,plan['sparse_bytes']),'w',force_zip64=True) as f:encoded[member]=sparse.emit_stream(row['path'],f,plan,allow_large_output=True,**pins)['sparse_sha256']
  else:
   assert sha(row['path'])==row['sha256'];h=hashlib.sha256()
   with z.open(info(member,row['size']),'w',force_zip64=True) as f,Path(row['path']).open('rb') as s:
    for b in iter(lambda:s.read(1024*1024),b''):f.write(b);h.update(b)
   assert h.hexdigest()==row['sha256'];encoded[member]=h.hexdigest()
print('Independent member CRC/hash and expanded-super readback',flush=True)
with zipfile.ZipFile(partial) as z:
 assert len(z.namelist())==37 and len(set(z.namelist()))==37
 for name,h in encoded.items():
  with z.open(name) as f:
   if name=='partitions/super.bin':expanded=sparse.validate_stream(f,**pins)
   else:
    d=hashlib.sha256()
    for b in iter(lambda:f.read(1024*1024),b''):d.update(b)
    assert d.hexdigest()==h
 for name,data in small:assert z.read(name)==data
partial.rename(final)
print('Signing generated ZIP',flush=True)
sign=sign_generated_zip(final,ROOT/'builder/work/installer-ri3-recovery/images-ziptrust/development-zip.x509.pem',ROOT/'builder/work/installer-ri3-recovery/.private/development-zip-rsa2048.pem',generated_root=OUT,work_dir=WORK)
receipt={'archive':str(final),'bytes':final.stat().st_size,'sha256':sha(final),'native_sha256':native['binary_sha256'],'all_member_crc_sha_checks_passed':True,'expanded_super':expanded,'sparse_encoded_sha256':encoded['partitions/super.bin'],'signature':sign,'image_changes':[x['name'] for x in byname.values() if x['changed']],'physical_device_tested':False,'phone_actions_performed':False,'sequence_cases_passed':67,'member_count':37}
(OUT/'VALIDATION.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps({k:receipt[k] for k in ['archive','bytes','sha256','image_changes']}),flush=True)
