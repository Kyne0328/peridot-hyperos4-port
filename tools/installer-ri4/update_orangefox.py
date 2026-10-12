"""Replace only RI4's OrangeFox payload and necessary installer hash bindings."""
from pathlib import Path
import hashlib,json,os,struct,sys,zipfile,shutil
ROOT=Path(__file__).resolve().parents[2];OLD=ROOT/'builder/work/installer-ri4';WORK=ROOT/'builder/work/installer-ri4-orangefox-202610021801'
sys.path[:0]=[str(ROOT/'tools/installer-ri4'),str(ROOT/'tools/installer-ri3/recovery-pair'),str(ROOT/'tools/installer-ri3/zip-signing')]
import rebuild_images as author
from pair_format import *
from sign_zip import sign_generated_zip
from cryptography.hazmat.primitives import serialization
SOURCE=ROOT/'OrangeFox-R12.0_202610021801_crypto-Unofficial-peridot_final.zip'
SOURCE_SHA='3ddcf53e0fb6e7fd7a83a491a350ce51e30d818f466bd2429b3ce2ee0659c72a'
NAME='F6-Global-HyperOS4-DEV2-RI4-DECRYPT-OF202610021801-20261003.zip'
def digest(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def save(p,o):p.write_text(json.dumps(o,indent=2)+'\n')
def files(raw):return {e['name']:(e,raw[e['offset']:e['offset']+e['size']]) for e in cpio_entries(raw)}
def prepare():
 assert digest(SOURCE)==SOURCE_SHA
 with zipfile.ZipFile(SOURCE) as z:source=z.read('recovery.img')
 h,blocks=unpack_boot(source);raw=b''.join(v for c,v in blocks);original=files(raw)
 oh,oldblocks=unpack_boot((OLD/'recovery.img').read_bytes());oldfiles=files(b''.join(v for c,v in oldblocks))
 data=bytearray();changes=[];last=0
 for e in cpio_entries(raw):
  body=raw[e['offset']:e['offset']+e['size']];new=body
  if 'fstab' in e['name']:new,removed=author.patch_fstab(body)
  if e['name'] in ['system/bin/pre_rom_flash.sh','system/bin/post_rom_flash_completion.sh']:new=oldfiles[e['name']][1]
  if new!=body:changes.append(e['name'])
  header=bytearray(raw[e['header_offset']:e['offset']]);header[54:62]=f'{len(new):08x}'.encode();data+=header+new;data+=bytes((-len(data))%4);last=e['end']
 data+=raw[last:];assert set(changes)=={'system/etc/recovery.fstab','system/bin/pre_rom_flash.sh','system/bin/post_rom_flash_completion.sh'}
 after=files(bytes(data));assert original.keys()==after.keys()
 for n,(e,b) in original.items():
  ae,ab=after[n];assert e['fields'][:6]+e['fields'][7:]==ae['fields'][:6]+ae['fields'][7:]
  if n not in changes:assert b==ab
 author.WORK=WORK;rd=author.compress(bytes(data),'new-recovery');header=bytearray(source[:4096]);struct.pack_into('<I',header,12,len(rd));payload=bytes(header)+rd+bytes(align(len(rd))-len(rd))
 key=serialization.load_pem_private_key((ROOT/'builder/work/installer-ri3-recovery/.private/development-recovery-rsa2048.pem').read_bytes(),None)
 image=recovery_signed(payload,parse_avb(source),1,key,len(source));a=verify_avb(image);(WORK/'recovery.img').write_bytes(image)
 root=verify_avb((OLD/'vbmeta.img').read_bytes());chain=next(d for d in root['descriptors'] if struct.unpack_from('>Q',d)[0]==4 and d[92:100]==b'recovery');n,k=struct.unpack_from('>II',chain,20);assert chain[92+n:92+n+k]==a['pk'];assert root['header'][17]==0
 images=json.loads((OLD/'images.json').read_text())
 for row in images['images']:
  if row['name']=='recovery':row.update(path=str(WORK/'recovery.img'),sha256=digest(WORK/'recovery.img'))
 save(WORK/'images.json',images);shutil.copyfile(OLD/'updater-script',WORK/'updater-script')
 pins=[]
 for name in ['system/bin/bootctl','system/lib64/libboot_control_client.so','vendor/bin/hw/android.hardware.boot-service.qti.recovery','vendor/lib64/libboot_control_qti.so']:
  e,b=original[name];pins.append((name,len(b),hashlib.sha256(b).hexdigest()))
 for cmd in ['get-snapshot-merge-status','get-active-boot-slot','set-active-boot-slot']:assert cmd.encode() in original['system/bin/bootctl'][1]
 t=(ROOT/'tools/installer-ri3/native-updater/snapshot/hal_query.cpp').read_text()
 start=t.index('constexpr Pin pins[]={');end=t.index('\n};',start)+3
 newer='constexpr Pin new_pins[]={\n'+''.join(' {"'+n+'",'+str(size)+',"'+sha+'"},\n' for n,size,sha in pins)+'};\n'
 selection='''
const Pin* SelectPinnedSet(const std::vector<std::string>& hashes,const std::vector<uint64_t>& sizes){
 Need(hashes.size()==4&&sizes.size()==4,"incomplete recovery tool set");
 bool old_set=true,new_set=true;
 for(size_t i=0;i<4;++i){old_set=old_set&&(sizes[i]==pins[i].bytes&&hashes[i]==pins[i].hash);new_set=new_set&&(sizes[i]==new_pins[i].bytes&&hashes[i]==new_pins[i].hash);}
 Need(old_set||new_set,"unsupported or mixed recovery boot-control set");return old_set?pins:new_pins;
}
'''
 t=t[:end]+'\n'+newer+selection+t[end:]
 old='for(const auto& pin:pins){fds.push_back(OpenArtifact(pin.path));identity.push_back(Stat(fds.back().n));CheckPin(fds.back().n,pin,identity.back());}'
 new='''for(const auto& pin:pins){fds.push_back(OpenArtifact(pin.path));identity.push_back(Stat(fds.back().n));}
  std::vector<std::string> hashes;std::vector<uint64_t> sizes;
  for(size_t i=0;i<fds.size();++i){auto size=identity[i].st_size;Need(S_ISREG(identity[i].st_mode)&&size>0&&size<=512*1024,"invalid recovery artifact");hashes.push_back(Hash(fds[i].n,size));sizes.push_back(size);}
  const Pin* selected=SelectPinnedSet(hashes,sizes);
  for(size_t i=0;i<fds.size();++i)CheckPin(fds[i].n,selected[i],identity[i]);'''
 assert t.count(old)==1;t=t.replace(old,new);t=t.replace('CheckPin(fds[i].n,pins[i],identity[i]);','CheckPin(fds[i].n,selected[i],identity[i]);')
 (WORK/'hal_query.cpp').write_text(t)
 save(WORK/'recovery-update.json',{'source_archive_sha256':SOURCE_SHA,'source_recovery_sha256':hashlib.sha256(source).hexdigest(),'new_recovery_sha256':digest(WORK/'recovery.img'),'recovery_version':'202610021801','CPIO_payload_changes':changes,'all_other_cpio_payloads_and_metadata_identical_to_new_source':True,'decrypted_storage_retained':True,'root_vbmeta_byte_identical':True,'root_recovery_child_key_matches':True,'running_recovery_supported_pin_sets':'original 202610011528 and supplied 202610021801; mixed sets rejected','new_boot_control_pins':pins,'kernel_and_all_other_images_unchanged':True,'phone_actions_performed':False})
 print('RECOVERY PREPARED',digest(WORK/'recovery.img'),flush=True)
def package():
 out=WORK/'package';out.mkdir(exist_ok=True);oldv=json.loads((OLD/'package/VALIDATION.json').read_text());old=Path(oldv['archive']);assert digest(old)==oldv['sha256'];native=(WORK/'native/update-binary').read_bytes();rec=(WORK/'recovery.img').read_bytes();changes={};hashes={}
 final=out/NAME;partial=out/(NAME+'.partial');assert not final.exists() and not partial.exists()
 with zipfile.ZipFile(old) as source,zipfile.ZipFile(partial,'x',allowZip64=True) as z:
  build=json.loads(source.read('RI4-BUILD-MANIFEST.json'));build.update(orangefox_version='202610021801',orangefox_only_update=True)
  for row in build['images']:
   if row['name']=='recovery':row['sha256']=hashlib.sha256(rec).hexdigest()
  replace={'partitions/recovery.bin':rec,'META-INF/com/google/android/update-binary':native,'RI4-BUILD-MANIFEST.json':(json.dumps(build,indent=2)+'\n').encode()}
  for entry in source.infolist():
   name=entry.filename;print('Copying',name,flush=True);h=hashlib.sha256();oldh=hashlib.sha256();data=replace.get(name);i=zipfile.ZipInfo(name,entry.date_time);i.create_system=entry.create_system;i.external_attr=entry.external_attr;i.compress_type=zipfile.ZIP_STORED;i.file_size=len(data) if data is not None else entry.file_size
   with z.open(i,'w',force_zip64=True) as target:
    if data is not None:target.write(data);h.update(data)
    else:
     with source.open(entry) as s:
      for b in iter(lambda:s.read(1024*1024),b''):target.write(b);h.update(b)
   with source.open(entry) as s:
    for b in iter(lambda:s.read(1024*1024),b''):oldh.update(b)
   hashes[name]=h.hexdigest()
   if h.hexdigest()!=oldh.hexdigest():changes[name]={'old_sha256':oldh.hexdigest(),'new_sha256':h.hexdigest()}
 assert set(changes)==set(replace)
 with zipfile.ZipFile(partial) as z:
  for entry in z.infolist():
   with z.open(entry) as f:assert hashlib.file_digest(f,'sha256').hexdigest()==hashes[entry.filename]
 partial.rename(final)
 sign=sign_generated_zip(final,ROOT/'builder/work/installer-ri3-recovery/images-ziptrust/development-zip.x509.pem',ROOT/'builder/work/installer-ri3-recovery/.private/development-zip-rsa2048.pem',generated_root=out,work_dir=WORK)
 save(out/'VALIDATION.json',{'archive':str(final),'bytes':final.stat().st_size,'sha256':digest(final),'native_sha256':hashlib.sha256(native).hexdigest(),'changes':changes,'all_unchanged_members_byte_identical_to_RI4':True,'all_member_crc_sha_checks_passed':True,'expanded_super_unchanged_verified_by_encoded_identity':oldv['expanded_super'],'signing':sign,'recovery_update':json.loads((WORK/'recovery-update.json').read_text()),'phone_actions_performed':False,'device_tested':False})
 print('PACKAGE COMPLETE',digest(final),flush=True)
if __name__=='__main__':WORK.mkdir(exist_ok=True);{'prepare':prepare,'package':package}[sys.argv[1]]()
