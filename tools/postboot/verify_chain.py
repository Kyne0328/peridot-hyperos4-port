"""Independently verify regenerated verity trees and every complete AVB chain."""
from pathlib import Path
import hashlib,json,os,struct,subprocess,sys,zipfile
from cryptography.hazmat.primitives import serialization

ROOT=Path(__file__).resolve().parents[2];WORK=Path('D:/hyperos4-peridot-postboot-20261004')
sys.path.insert(0,str(ROOT/'builder'))
from peridot_builder.lp import parse_super_metadata_prefix
sys.path.insert(0,str(ROOT/'tools/installer-ri3/recovery-pair'))
from pair_format import verify_avb,public_blob,decode_key
from assemble import footer_metadata

def sha(path):
 with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()

assembly=json.loads((WORK/'ASSEMBLY.json').read_text())
source=json.loads((ROOT/'builder/work/installer-ri5-recoveryfix-20261004/package/VALIDATION.json').read_text())
assert source['sha256']==assembly['source_zip_sha256']
superp=WORK/'super.img'
with superp.open('rb') as f:metadata=parse_super_metadata_prefix(f.read(1048576))
for part in metadata['partitions']:
 if not part['size_bytes']:continue
 name=part['name'][:-2];path=WORK/(name+'.img')
 if path.exists():continue
 with superp.open('rb') as src,path.open('xb') as dst:
  for e in part['extents']:
   src.seek(e['offset_bytes']);left=e['size_bytes']
   while left:
    block=src.read(min(left,4*1024**2));assert block;dst.write(block);left-=len(block)
with zipfile.ZipFile(source['archive']) as z:
 for name in ['boot','recovery','countrycode','dtbo','init_boot','vendor_boot']:
  path=WORK/(name+'.img')
  data=z.read('partitions/'+name+'.bin');assert hashlib.sha256(data).hexdigest()==source['partition_hashes'][name]
  if path.exists():assert sha(path)==source['partition_hashes'][name]
  else:path.write_bytes(data)
key=ROOT/'.private/avb/postbootfix1/root-rsa4096.pem'
openssl=Path('C:/Program Files/Git/usr/bin/openssl.exe');assert openssl.is_file()
env=os.environ.copy();env['PATH']=str(openssl.parent)+os.pathsep+env['PATH']
public=WORK/'avb-public';public.mkdir(exist_ok=True);metadata={};bindings=[]
def visit(name,expected_key):
 path=WORK/(name+'.img')
 parsed=verify_avb(path.read_bytes()) if name.startswith('vbmeta') else verify_avb(footer_metadata(path)['data'])
 assert parsed['pk']==expected_key,'Parent public-key binding differs: '+name
 if name in metadata:return
 metadata[name]=parsed
 (public/(name+'.avbpubkey')).write_bytes(parsed['pk'])
 (public/(name+'.pem')).write_bytes(decode_key(parsed['pk']).public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
 for d in parsed['descriptors']:
  if struct.unpack_from('>Q',d)[0]!=4:continue
  location,n,k=struct.unpack_from('>III',d,16);child=d[92:92+n].decode();child_key=d[92+n:92+n+k]
  assert n>0 and k>0 and '/' not in child and '\\' not in child
  bindings.append({'parent':name,'child':child,'rollback_location':location,'public_key_sha256':hashlib.sha256(child_key).hexdigest()})
  visit(child,child_key)
visit('vbmeta',public_blob(serialization.load_pem_private_key(key.read_bytes(),None)))
commands=[]
for name,parsed in metadata.items():
 cmd=[sys.executable,str(ROOT/'builder/tools/bin/avbtool.py'),'verify_image','--image',name+'.img','--key','avb-public/'+name+'.pem']
 for binding in bindings:
  if binding['parent']==name:cmd+=['--expected_chain_partition',binding['child']+':'+str(binding['rollback_location'])+':avb-public/'+binding['child']+'.avbpubkey']
 p=subprocess.run(cmd,capture_output=True,text=True,env=env,cwd=WORK)
 commands.append({'partition':name,'argv':cmd,'exit_code':p.returncode,'stdout':p.stdout,'stderr':p.stderr})
 print('AVB image check',name,'passed' if p.returncode==0 else 'FAILED',flush=True)
 if p.returncode:break
receipt={'passed':all(c['exit_code']==0 for c in commands) and len(commands)==len(metadata),'commands':commands,'parent_public_key_bindings':bindings,
 'scope':'AOSP avbtool verifies root signature, child public-key relationships, signed metadata and actual image hashes/verity trees',
 'super_sha256':sha(superp),'vbmeta_sha256':sha(WORK/'vbmeta.img'),'vbmeta_system_sha256':sha(WORK/'vbmeta_system.img'),
 'avbtool_sha256':sha(ROOT/'builder/tools/bin/avbtool.py'),'openssl_sha256':sha(openssl)}
(WORK/'AVB-VERIFICATION.json').write_text(json.dumps(receipt,indent=2)+'\n',encoding='utf-8')
assert receipt['passed'],p.stdout+p.stderr
print(json.dumps({k:receipt[k] for k in ['passed','scope','super_sha256']},indent=2))
