"""Repackage the immutable signed RI5 input with corrected installer and new ZIP-only signature."""
from pathlib import Path
import hashlib,json,shutil,sys,time,zipfile

ROOT=Path(__file__).resolve().parents[2]
WORK=ROOT/'builder/work/installer-ri5-recoveryfix-20261004'
OLD=ROOT/'builder/work/installer-ri5-stream-20261004/package'
NAME='F6-Global-HyperOS4-DEV2-RI5-COMPRESSED-DECRYPT-RECOVERYFIX3-20261004.zip'
sys.path.insert(0,str(ROOT/'tools/installer-ri3/zip-signing'))
from sign_zip import sign_generated_zip
from verify_zip import verify_zip
from compressed_copy import copy_member

def sha(path):
    with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()

def main():
    started=time.monotonic();previous=json.loads((OLD/'VALIDATION.json').read_text())
    source=Path(previous['archive']);assert sha(source)==previous['sha256']=='0b5fd8ae1a9aac7412c2d63b0ed0a930248f389d0784c2663824fcb5dda3e828'
    with zipfile.ZipFile(source) as z:
        cert=z.read('META-INF/com/android/otacert')
    old_cert=WORK/'source-public-certificate.pem';old_cert.write_bytes(cert)
    verify_zip(source,old_cert)
    native=json.loads((WORK/'native-android-new/build-receipt.json').read_text())
    assert native['trust']=='new'
    for name,digest in native['sources'].items():assert sha(ROOT/name)==digest,'Compiled source changed'
    binary=Path(native['binary']).read_bytes();assert hashlib.sha256(binary).hexdigest()==native['binary_sha256']
    signing=json.loads((WORK/'signing-public.json').read_text())
    out=WORK/'package';out.mkdir(exist_ok=True)
    assert shutil.disk_usage(out).free>source.stat().st_size+4*1024**3
    final=out/NAME;partial=out/(NAME+'.partial');assert not final.exists() and not partial.exists()
    member_hashes={};images_verified={}
    with zipfile.ZipFile(source) as prior,zipfile.ZipFile(partial,'x',allowZip64=True) as target:
        manifest=json.loads(prior.read('RI5-BUILD-MANIFEST.json'))
        image_pins={x['name']:x for x in manifest['images']};assert len(image_pins)==32
        manifest.update(installer_revision='RECOVERYFIX3-20261004',bounded_fresh_observation_pairs=4,memory_ramdisk_driver_support=True,
            exited_task_mount_namespace_support=True,mount_namespace_identity_independent_of_process_churn=True,
            new_zip_certificate_der_sha256=signing['certificate_der_sha256'],partition_AVB_and_raw_image_hashes_unchanged=True,
            device_flash_or_boot_tested=False)
        script=prior.read('META-INF/com/google/android/updater-script').replace(b'RI5 COMPRESSED DECRYPT:',b'RI5 COMPRESSED DECRYPT RECOVERYFIX3:')
        replacements={'META-INF/com/android/otacert':(ROOT/signing['certificate_path']).read_bytes(),
            'META-INF/com/google/android/update-binary':binary,'META-INF/com/google/android/updater-script':script,
            'RI5-BUILD-MANIFEST.json':(json.dumps(manifest,indent=2)+'\n').encode()}
        for entry in prior.infolist():
            name=entry.filename;data=replacements.get(name);h=hashlib.sha256();count=0
            if name.startswith('partitions/'):
                print('Copying unchanged compressed image',name,flush=True)
                copy_member(source,prior,target,entry)
                part=name.split('/')[-1][:-4];pin=image_pins[part]
                assert entry.file_size==pin['bytes']
                member_hashes[name]=pin['sha256'];images_verified[part]=pin['sha256']
                continue
            info=zipfile.ZipInfo(name,entry.date_time);info.compress_type=zipfile.ZIP_DEFLATED;info._compresslevel=6
            info.create_system=entry.create_system;info.external_attr=entry.external_attr;info.file_size=len(data) if data is not None else entry.file_size
            print('Packaging',name,flush=True)
            with target.open(info,'w',force_zip64=True) as dst:
                if data is not None:dst.write(data);h.update(data);count=len(data)
                else:
                    with prior.open(entry) as src:
                        for block in iter(lambda:src.read(1024*1024),b''):dst.write(block);h.update(block);count+=len(block)
            member_hashes[name]=h.hexdigest()
            if name.startswith('partitions/'):
                part=name.split('/')[-1][:-4];pin=image_pins[part]
                assert count==pin['bytes'] and h.hexdigest()==pin['sha256'],'Partition image changed'
                images_verified[part]=h.hexdigest()
    assert len(images_verified)==32
    print('Independent output decompression/CRC/SHA256 verification',flush=True)
    with zipfile.ZipFile(partial) as z:
        assert len(z.namelist())==len(set(z.namelist()))==37
        for entry in z.infolist():
            with z.open(entry) as f:assert hashlib.file_digest(f,'sha256').hexdigest()==member_hashes[entry.filename]
    partial.rename(final)
    print('Signing corrected ZIP',flush=True)
    signature=sign_generated_zip(final,ROOT/signing['certificate_path'],ROOT/signing['private_key_path'],
        generated_root=out,work_dir=WORK,expected_cert_sha256=signing['certificate_der_sha256'],reserve_bytes=4*1024**3)
    result={'archive':str(final),'bytes':final.stat().st_size,'sha256':sha(final),'source_archive_sha256':previous['sha256'],
        'native_sha256':native['binary_sha256'],'all_32_partition_image_hashes_unchanged':True,'partition_hashes':images_verified,
        'all_member_decompression_crc_sha_passed':True,'signature':signature,'signing_identity':signing,
        'phone_flash_boot_or_wipe_performed':False,'build_seconds':round(time.monotonic()-started,2)}
    (out/'VALIDATION.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    (out/(NAME+'.sha256')).write_text(result['sha256']+'  '+NAME+'\n',encoding='utf-8')
    print(json.dumps({k:result[k] for k in ['archive','bytes','sha256','build_seconds']},indent=2),flush=True)

if __name__=='__main__':main()
