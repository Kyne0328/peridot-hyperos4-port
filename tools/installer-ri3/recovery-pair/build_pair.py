#!/usr/bin/env python3
"""Build authorized offline development pair. No device operations. Immutable inputs."""
import hashlib,json,os,pathlib,struct,subprocess,sys,zipfile
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pair_format import *
ROOT=pathlib.Path.cwd();WORK=ROOT/'builder/work/installer-ri3-recovery';OUT=WORK/'images';REPORT=ROOT/'09-reports/installer-ri3/recovery-pair'
SOURCE='OrangeFox-R12.0_202610011528_crypto-Unofficial-peridot.zip';ROM='F6-Global-HyperOS4-DEV2-RI2.zip'
FOX_SHA='b04ec7c0add35457fe7f53e308acf23cdf0a62d8d4ed05f1392ac23e6cbb5cf4'
STOCK_REC='936a66e4ae8bc3fba7b004696c4d94d291abea6ce474e44445e7b6e857231a7f';STOCK_ROOT='864f618a35b3c6ca23303b41a7f9620d1cd934eeb8d746060f17fb19af33c1d6'
HOOKS={'system/bin/pre_rom_flash.sh':'e8cdeb9de21370903f0a948fa8126fcaf6c2d8e09224225831fc8274e4cf05a5','system/bin/post_rom_flash_completion.sh':'0b00278abf4121c03e8537fad4ff5a20de7d4ae83ad9937aabd86f437fb5e507'}
def write_exact(path,data):
 path.parent.mkdir(parents=True,exist_ok=True)
 if path.exists():require(path.read_bytes()==data,'existing output differs: '+str(path));return
 with path.open('xb') as f:f.write(data)
def run(argv):
 p=subprocess.run(argv,cwd=ROOT,capture_output=True,text=True,timeout=180)
 require(p.returncode==0,'subprocess failed: '+p.stderr[:1000]);return p.stdout
def key(bits,name):
 private=WORK/'.private';private.mkdir(parents=True,exist_ok=True);relative=(private/name).relative_to(ROOT).as_posix()
 p=subprocess.run(['git','check-ignore','--quiet',relative],cwd=ROOT);require(p.returncode==0,'private key location is not ignored')
 require(not run(['git','ls-files','--',relative]).strip(),'private key path already tracked');path=private/name
 if path.exists():k=serialization.load_pem_private_key(path.read_bytes(),password=None)
 else:
  k=rsa.generate_private_key(public_exponent=65537,key_size=bits);fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
  with os.fdopen(fd,'wb') as f:f.write(k.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
 require(k.key_size==bits,'private key width mismatch');return k

def main():
 OUT.mkdir(parents=True,exist_ok=True);REPORT.mkdir(parents=True,exist_ok=True)
 with (ROOT/SOURCE).open('rb') as f:require(hashlib.file_digest(f,'sha256').hexdigest()==FOX_SHA,'recovery source hash mismatch')
 with zipfile.ZipFile(ROOT/SOURCE) as z:image=z.read('recovery.img')
 with zipfile.ZipFile(ROOT/ROM) as z:stockrec=z.read('images/recovery.img');stockroot=z.read('images/vbmeta.img')
 require(sha(stockrec)==STOCK_REC and sha(stockroot)==STOCK_ROOT,'RI2 member hash mismatch')
 source_avb=parse_avb(image);stock_rec_avb=verify_avb(stockrec);root_avb=verify_avb(stockroot)
 require(source_avb['header'][5]==0 and source_avb['header'][16]==0 and source_avb['header'][17]==0,'unexpected base AVB')
 require(stock_rec_avb['header'][16]==1 and root_avb['header'][16]==0,'unexpected rollback policy')
 head,blocks=unpack_boot(image);require(head['payload_end']==source_avb['footer']['original_size'],'unexpected boot suffix')
 raw=b''.join(x[1] for x in blocks);entries=cpio_entries(raw);index={x['name']:x for x in entries};modified=bytearray(raw);hook_receipts={}
 for name,oldhash in HOOKS.items():
  e=index[name];require(e['sha256']==oldhash and (e['fields'][1]&0o170000)==0o100000,'hook identity/type mismatch')
  base=('#!/system/bin/sh\n# RI3_RECOVERY_CONTRACT_V1: '+name+'\n# Intentionally nonmutating. Native RI3 preflight owns all guards and writes.\n# RunFoxScript does not propagate shell exit status as installation failure.\nexit 0\n').encode()
  require(len(base)+2<=e['size'],'hook exceeds source entry size');replacement=base+b'#'+b' '*(e['size']-len(base)-2)+b'\n'
  modified[e['offset']:e['offset']+e['size']]=replacement;hook_receipts[name]={'source_sha256':oldhash,'sha256':sha(replacement),'size':len(replacement),'text':replacement.decode()}
 new_entries=cpio_entries(bytes(modified));require([x['name'] for x in entries]==[x['name'] for x in new_entries],'CPIO topology changed')
 for old,new in zip(entries,new_entries):
  require(old['fields']==new['fields'] and old['offset']==new['offset'],'CPIO metadata changed')
  if old['name'] not in HOOKS:require(old==new,'non-hook CPIO entry changed')
 segments=sorted((index[n]['offset'],index[n]['offset']+index[n]['size']) for n in HOOKS);p=0
 for a,b in segments:require(raw[p:a]==modified[p:a],'non-hook raw CPIO changed');p=b
 require(raw[p:]==modified[p:],'CPIO trailing bytes changed');compressed=[];block_receipts=[];p=0
 for i,(comp,oldraw) in enumerate(blocks):
  newraw=bytes(modified[p:p+len(oldraw)]);p+=len(oldraw)
  if newraw!=oldraw:
   src=WORK/'blocks'/f'block-{i}.raw';dst=WORK/'blocks'/f'block-{i}.lz4';write_exact(src,newraw)
   receipt=json.loads(run(['wsl.exe','-d','Ubuntu','--cd','/mnt/c/Dev/peridot-hyperos4-port','--','python3','-B','tools/installer-ri3/recovery-pair/lz4_compress.py',src.relative_to(ROOT).as_posix(),dst.relative_to(ROOT).as_posix()]))
   c=dst.read_bytes();require(lz4_decode(c)==newraw,'compression roundtrip failed');block_receipts.append({'index':i,**receipt})
  else:c=comp
  compressed.append(struct.pack('<I',len(c))+c)
 ramdisk=b'\x02\x21\x4c\x18'+b''.join(compressed);header=bytearray(image[:4096]);struct.pack_into('<I',header,12,len(ramdisk))
 require(bytes(header[:12])+bytes(header[16:])==image[:12]+image[16:4096],'non-size boot header changed');payload=bytes(header)+ramdisk+bytes(align(len(ramdisk))-len(ramdisk))
 # Complete all transformation checks before offline key generation.
 rootkey=key(4096,'development-root-rsa4096.pem');reckey=key(2048,'development-recovery-rsa2048.pem')
 recovery=recovery_signed(payload,source_avb,1,reckey,len(image));vbmeta=root_signed(stockroot,public_blob(reckey),rootkey)
 rp=verify_avb(recovery);vp=verify_avb(vbmeta);require(rp['pk']==public_blob(reckey) and vp['pk']==public_blob(rootkey),'final public key mismatch')
 require(len(root_avb['descriptors'])==len(vp['descriptors']),'root descriptor count changed')
 for old,new in zip(root_avb['descriptors'],vp['descriptors']):
  if struct.unpack_from('>Q',old)[0]==4 and old[92:100]==b'recovery':continue
  require(old==new,'unrelated root descriptor changed')
 _,finalblocks=unpack_boot(recovery);require(b''.join(x[1] for x in finalblocks)==modified,'final ramdisk mismatch')
 require(len(recovery)==len(image)==104857600 and len(vbmeta)==len(stockroot)==12288,'partition size changed')
 require(recovery==recovery_signed(payload,source_avb,1,reckey,len(image)),'recovery signing not reproducible');require(vbmeta==root_signed(stockroot,public_blob(reckey),rootkey),'root signing not reproducible')
 outputs={'recovery.img':recovery,'vbmeta.img':vbmeta,'development-root.avbpubkey':public_blob(rootkey),'development-recovery.avbpubkey':public_blob(reckey)}
 for name,data in outputs.items():write_exact(OUT/name,data)
 report={'schema_version':1,'contract':'RI3_RECOVERY_CONTRACT_V1','mode':'offline-development-pair','source_archive':SOURCE,'source_archive_sha256':FOX_SHA,'source_recovery_sha256':sha(image),'source_ri2_recovery_sha256':STOCK_REC,'source_ri2_root_sha256':STOCK_ROOT,'files':{n:{'path':(OUT/n).relative_to(ROOT).as_posix(),'size':len(b),'sha256':sha(b)} for n,b in outputs.items()},'hooks':hook_receipts,'recompressed_blocks':block_receipts,'cpio_entry_count':len(entries),'all_non_hook_cpio_bytes_and_metadata_preserved':True,'all_unrelated_root_descriptors_exact':True,'source_recovery_rollback_index':0,'candidate_recovery_rollback_index':1,'ri2_recovery_rollback_preserved':True,'root_rollback_index':0,'recovery_chain_rollback_location':1,'avb_flags':0,'root_algorithm':'SHA256_RSA4096','recovery_algorithm':'SHA256_RSA2048','same_key_reproducible':True,'private_keys_excluded_from_git_and_outputs':True,'device_tested':False,'setup_prerequisite':'Before writes, native preflight must pin runtime recovery executable/config/hooks and full recovery_a bytes, and require a bounded live read-only twrp getval tw_auto_reflashtwrp result exactly 0. Keep recovery_a byte-identical and recovery_b untouched.','unresolved':['Native preflight integration and full lifecycle failure-path harness acceptance pending.','CLI IPC availability during GUI installation, device trust acceptance, recovery boot, hardware state, partition accessibility and installation remain untested.']}
 (REPORT/'pair-build.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:report[k] for k in ['files','recompressed_blocks','cpio_entry_count','avb_flags','same_key_reproducible']},indent=2))
if __name__=='__main__':main()
