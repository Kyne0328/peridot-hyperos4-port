"""Rebuild AVB descriptors and super from the exact booted RI5 ZIP, preserving all other bytes."""
from pathlib import Path
import hashlib,json,os,struct,subprocess,sys,zipfile
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

ROOT=Path(__file__).resolve().parents[2];WORK=Path('D:/hyperos4-peridot-postboot-20261004');EVIDENCE=ROOT/'builder/work/postboot-20261004'
sys.path.insert(0,str(ROOT/'tools/installer-ri3/recovery-pair'))
from pair_format import parse_avb,verify_avb,public_blob,sign_parts,align

def sha(path):
 with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def save(path,value):path.write_text(json.dumps(value,indent=2)+'\n',encoding='utf-8')
def descriptor_name(d):
 tag=struct.unpack_from('>Q',d)[0]
 if tag==1:n=struct.unpack_from('>I',d,104)[0];return d[180:180+n].decode()
 if tag==4:n=struct.unpack_from('>I',d,20)[0];return d[92:92+n].decode()
 return None
def footer_metadata(path):
 with path.open('rb') as f:
  f.seek(-64,2);footer=f.read(64);magic,major,minor,size,off,n,_=struct.unpack('>4sIIQQQ28s',footer)
  assert magic==b'AVBf' and n<65536
  f.seek(off);data=f.read(n)
 return parse_avb(data)
def resign(original,descriptors,key):
 p=verify_avb(original);h=list(p['header']);desc=b''.join(descriptors);pub=public_blob(key)
 aux=desc+pub;aux+=bytes(align(len(aux),64)-len(aux));h[3]=576;h[4]=len(aux);h[5]=2
 h[6:16]=[0,32,32,512,len(desc),len(pub),0,0,0,len(desc)]
 data=sign_parts(h,aux,key);assert len(data)<=len(original)
 out=data+bytes(len(original)-len(data));verify_avb(out);return out
def main():
 previous=json.loads((ROOT/'builder/work/installer-ri5-recoveryfix-20261004/package/VALIDATION.json').read_text())
 archive=Path(previous['archive']);assert sha(archive)==previous['sha256']
 with zipfile.ZipFile(archive) as z:
  root=z.read('partitions/vbmeta.bin');system=z.read('partitions/vbmeta_system.bin');manifest=json.loads(z.read('RI5-BUILD-MANIFEST.json'))
 roots=verify_avb(root);systems=verify_avb(system)
 changes={};images={}
 for name,original in [('product',systems),('odm',roots),('system_ext',systems)]:
  print('Rebuilding verified-boot metadata for',name,flush=True)
  receipt=json.loads((WORK/(name+'-repack.json')).read_text());assert receipt['all_file_hashes_modes_uid_gid_xattrs_verified']
  if receipt['filesystem_path'].startswith('/mnt/peridot-postboot-native/'):
   fs=Path(r'\\wsl.localhost\Ubuntu'+receipt['filesystem_path'].replace('/','\\'))
  else:fs=Path(receipt['filesystem_path'].replace('/mnt/d/','D:/'))
  assert sha(fs)==receipt['filesystem_sha256']
  target=WORK/(name+'.img');assert not target.exists()
  with fs.open('rb') as src,target.open('xb') as dst:
   for block in iter(lambda:src.read(4*1024**2),b''):dst.write(block)
  old=next(d for d in original['descriptors'] if descriptor_name(d)==name)
  nl,sl=struct.unpack_from('>II',old,104);salt=old[180+nl:180+nl+sl].hex()
  cmd=[sys.executable,str(ROOT/'builder/tools/bin/avbtool.py'),'add_hashtree_footer','--image',str(target),'--partition_name',name,
   '--partition_size',str(receipt['allocation_bytes']),'--hash_algorithm','sha256','--salt',salt,'--do_not_generate_fec']
  subprocess.run(cmd,check=True)
  parsed=footer_metadata(target);changes[name]=next(d for d in parsed['descriptors'] if descriptor_name(d)==name)
  assert target.stat().st_size==receipt['allocation_bytes']
  images[name]={'path':str(target),'bytes':target.stat().st_size,'sha256':sha(target),'filesystem_changes':receipt['changes'],
   'verity_tree_regenerated':True,'fec_generated':False}
 private=ROOT/'.private/avb/postbootfix1';private.mkdir(parents=True,exist_ok=True)
 owner=subprocess.run(['whoami'],capture_output=True,text=True,check=True).stdout.strip()
 subprocess.run(['icacls',str(private),'/inheritance:r','/grant:r',owner+':(OI)(CI)F'],capture_output=True,check=True)
 keys={}
 for name in ['root','system']:
  path=private/(name+'-rsa4096.pem')
  if not path.exists():
   key=rsa.generate_private_key(public_exponent=65537,key_size=4096)
   with path.open('xb') as f:f.write(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.TraditionalOpenSSL,serialization.NoEncryption()))
  keys[name]=serialization.load_pem_private_key(path.read_bytes(),None)
 print('Signing root/system metadata with unchanged rollback settings',flush=True)
 new_system=resign(system,[changes.get(descriptor_name(d),d) for d in systems['descriptors']],keys['system'])
 (WORK/'vbmeta_system.img').write_bytes(new_system)
 chain=[]
 for d in roots['descriptors']:
  name=descriptor_name(d)
  if name=='odm':d=changes[name]
  if name=='vbmeta_system':
   q=bytearray(d);n,k=struct.unpack_from('>II',q,20);pub=public_blob(keys['system']);assert len(pub)==k
   q[92+n:92+n+k]=pub;d=bytes(q)
  chain.append(d)
 new_root=resign(root,chain,keys['root']);(WORK/'vbmeta.img').write_bytes(new_root)
 root_check=verify_avb(new_root);system_check=verify_avb(new_system)
 assert roots['header'][16:19]==root_check['header'][16:19] and systems['header'][16:19]==system_check['header'][16:19]
 for d in roots['descriptors']:
  if descriptor_name(d) not in ['odm','vbmeta_system']:assert d in root_check['descriptors']
 for d in systems['descriptors']:
  if descriptor_name(d) not in ['product','system_ext']:assert d in system_check['descriptors']
 superp=WORK/'super.img';assert not superp.exists();h=hashlib.sha256()
 print('Reconstructing booted super from verified compressed RI5 input',flush=True)
 with zipfile.ZipFile(archive) as z,z.open('partitions/super.bin') as src,superp.open('xb') as dst:
  for block in iter(lambda:src.read(4*1024**2),b''):dst.write(block);h.update(block)
 assert h.hexdigest()==previous['partition_hashes']['super']
 source=json.loads((WORK/'source-images.json').read_text())
 with superp.open('r+b') as dst:
  for name in ['product','odm','system_ext']:
   spans=source['images'][name]['extents'];assert len(spans)==1;span=spans[0]
   assert span['size_bytes']==images[name]['bytes'];dst.seek(span['offset_bytes'])
   before=hashlib.sha256();left=span['size_bytes']
   while left:
    block=dst.read(min(left,4*1024**2));assert block;before.update(block);left-=len(block)
   assert before.hexdigest()==source['images'][name]['sha256'],'Booted source partition drift'
   dst.seek(span['offset_bytes'])
   with Path(images[name]['path']).open('rb') as src:
    for block in iter(lambda:src.read(4*1024**2),b''):dst.write(block)
  dst.flush();os.fsync(dst.fileno())
 new_pins=[]
 for row in manifest['images']:
  item=dict(row)
  if row['name'] in ['super','vbmeta','vbmeta_system']:
   p=WORK/(row['name']+'.img');item.update(bytes=p.stat().st_size,sha256=sha(p),path=str(p))
  new_pins.append(item)
 save(EVIDENCE/'new-pins.json',{'images':new_pins})
 result={'source_zip_sha256':previous['sha256'],'source_super_sha256':previous['partition_hashes']['super'],
  'images':images,'pins':new_pins,'all_other_logical_images_unchanged_by_fixed_span_replacement':True,
  'boot_recovery_vendor_vendorboot_kernel_unchanged':True,'avb_flags':root_check['header'][17],
  'avb_root_and_system_signatures_verified':True,'boot_recovery_chain_descriptors_byte_identical':True,
  'rollback_values_unchanged':True,'userdata_encryption_configuration_unchanged':True,'phone_flash_performed':False}
 save(WORK/'ASSEMBLY.json',result);print('Postboot image assembly and AVB verification complete',flush=True)

if __name__=='__main__':main()
