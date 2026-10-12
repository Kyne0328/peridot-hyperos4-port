#!/usr/bin/env python3
"""Independent readback gates for the exact offline pair; never executes recovery code."""
import hashlib,json,pathlib,struct,zipfile,runpy,sys,io
from cryptography import x509
from pair_format import *
ROOT=pathlib.Path.cwd();SUFFIX='-ziptrust' if '--ziptrust' in sys.argv else '';OUT=ROOT/('builder/work/installer-ri3-recovery/images'+SUFFIX);REPORT=ROOT/'09-reports/installer-ri3/recovery-pair'
def verify_recovery(image):
 p=verify_avb(image);f=p['footer'];require(f is not None,'missing recovery footer');count=0
 for d in p['descriptors']:
  if struct.unpack_from('>Q',d)[0]!=2:continue
  require(len(d)>=132,'short hash descriptor');_,_,size,alg,n,s,z,flags=struct.unpack_from('>QQQ32sIIII',d)
  require(alg.rstrip(b'\0')==b'sha256' and z==32 and flags==0 and 132+n+s+z<=len(d),'unexpected hash descriptor')
  require(d[132:132+n]==b'recovery' and size==f['original_size'],'wrong recovery hash extent')
  salt=d[132+n:132+n+s];digest=d[132+n+s:132+n+s+z]
  require(hashlib.sha256(salt+image[:size]).digest()==digest,'recovery content digest mismatch');count+=1
 require(count==1,'hash descriptor count mismatch');require(not any(image[f['original_size']:f['offset']]),'nonzero leading AVB padding');require(not any(image[f['offset']+f['size']:-64]),'nonzero trailing AVB padding')
 return p

def main():
 manifest=json.loads((REPORT/('pair-build'+SUFFIX+'.json')).read_text());images={}
 for n,r in manifest['files'].items():
  b=(ROOT/r['path']).read_bytes();require(len(b)==r['size'] and sha(b)==r['sha256'],'manifest identity mismatch');images[n]=b
 rp=verify_recovery(images['recovery.img']);vp=verify_avb(images['vbmeta.img'])
 require(rp['pk']==images['development-recovery.avbpubkey'] and vp['pk']==images['development-root.avbpubkey'],'public key mismatch')
 recchains=[]
 for d in vp['descriptors']:
  if struct.unpack_from('>Q',d)[0]!=4:continue
  loc,n,k,flags=struct.unpack_from('>IIII',d,16)
  if d[92:92+n]==b'recovery':recchains.append((loc,flags,d[92+n:92+n+k]))
 require(recchains==[(1,0,rp['pk'])],'root-to-recovery chain mismatch')
 with zipfile.ZipFile(ROOT/'F6-Global-HyperOS4-DEV2-RI2.zip') as z:old=z.read('images/vbmeta.img')
 original=verify_avb(old);require(vp['header']==original['header'],'root header/rollback/flags changed')
 diffs=[]
 for i,(a,b) in enumerate(zip(original['descriptors'],vp['descriptors'])):
  if a!=b:diffs.append(i);require(struct.unpack_from('>Q',a)[0]==4 and a[92:100]==b'recovery','unexpected descriptor change')
 require(len(diffs)==1,'expected exactly one changed root child descriptor')
 # Separate original inspector must recover the exact final hook content and untouched executable.
 m=runpy.run_path(str(ROOT/'tools/local-recovery/inspect_recovery.py'));h,files=m['ramdisk'](images['recovery.img'])
 for n,r in manifest['hooks'].items():require(sha(files[n])==r['sha256'] and files[n].decode()==r['text'],'hook readback mismatch')
 require(sha(files['system/bin/recovery'])=='b9416f70f6403ffe6cadc51626515f49f66a9961bbb7ef14898fdd9173c44a49','recovery executable changed')
 for r in manifest['hooks'].values():
  meaningful=[x.strip() for x in r['text'].splitlines() if x.strip() and not x.lstrip().startswith('#')]
  require(meaningful==['exit 0'],'outer hook contains executable operation')
 result={'passed':True,'signatures':['recovery SHA256_RSA2048','vbmeta SHA256_RSA4096'],'root_to_recovery_child_key':True,'recovery_payload_salted_hash':True,'canonical_partition_padding':True,'all_output_full_sha256':True,'root_header_exact':True,'only_changed_root_descriptor_index':diffs[0],'independent_original_ramdisk_parser':True,'hooks_only_exit_zero':True,'running_executable_unchanged':True,'runtime_settings_ipc_tested':False,'device_tested':False}
 if SUFFIX:
  store=files['system/etc/security/otacerts.zip'];r=manifest['additional_ramdisk_change'];require(sha(store)==r['new_sha256'],'trust store identity mismatch')
  with zipfile.ZipFile(io.BytesIO(store)) as z:
   cert_receipt=json.loads((REPORT/'zip-certificate.json').read_text());require(set(z.namelist())==set(cert_receipt['original_certificates'])|{cert_receipt['added_certificate']['name']},'unexpected trusted certificate')
   for name,record in cert_receipt['original_certificates'].items():require(sha(z.read(name))==record['sha256'],'original trusted certificate changed')
   pem=z.read(cert_receipt['added_certificate']['name']);require(sha(pem)==cert_receipt['added_certificate']['pem_sha256'],'dedicated certificate mismatch');cert=x509.load_pem_x509_certificate(pem);require(cert.public_key().key_size==2048 and cert.signature_hash_algorithm.name=='sha256','certificate format mismatch')
  with zipfile.ZipFile(ROOT/'OrangeFox-R12.0_202610011528_crypto-Unofficial-peridot.zip') as z:source_image=z.read('recovery.img')
  _,sb=unpack_boot(source_image);_,fb=unpack_boot(images['recovery.img']);sraw=b''.join(x[1] for x in sb);fraw=b''.join(x[1] for x in fb);se=cpio_entries(sraw);fe=cpio_entries(fraw);require(len(se)==len(fe),'final CPIO topology changed');changed=[]
  for a,b in zip(se,fe):
   require(a['name']==b['name'],'final CPIO order changed')
   if a['sha256']!=b['sha256']:changed.append(a['name'])
   af=list(a['fields']);bf=list(b['fields'])
   if a['name']=='system/etc/security/otacerts.zip':af[6]=bf[6]
   require(af==bf,'unrelated CPIO metadata changed')
  require(set(changed)==set(manifest['hooks'])|{'system/etc/security/otacerts.zip'},'unexpected changed final CPIO payload')
  result.update(exact_changed_cpio_paths=changed,all_existing_certificates_preserved=True,dedicated_zip_certificate_valid=True,trust_store_sha256=sha(store),fresh_boot_and_signature_enabled_setup_required=True)
 (REPORT/('pair-verification'+SUFFIX+'.json')).write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
if __name__=='__main__':main()
