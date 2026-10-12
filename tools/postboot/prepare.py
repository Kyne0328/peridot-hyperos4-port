"""Read-only source hashing and exact product/ODM extraction for postboot fixes."""
from pathlib import Path
import argparse,hashlib,json,sys

ROOT=Path(__file__).resolve().parents[2]
WORK=Path('D:/hyperos4-peridot-postboot-20261004')
sys.path.insert(0,str(ROOT/'builder'))
from peridot_builder.lp import parse_super_metadata_prefix

def sha(path):
 with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()

WORK.mkdir(exist_ok=True)
source=ROOT/'.cache/global-single-recovery-ri2/source-images/images/super.img'
manifest=json.loads((ROOT/'.cache/global-single-recovery-ri2/source-images/MANIFEST.json').read_text())
pin=next(x for x in manifest['images'] if x['path']=='images/super.img')
assert source.stat().st_size==pin['size'] and sha(source)==pin['sha256']
with source.open('rb') as f:metadata=parse_super_metadata_prefix(f.read(1024*1024))
ap=argparse.ArgumentParser();ap.add_argument('--additional-system-ext',action='store_true');a=ap.parse_args()
images={}
if a.additional_system_ext:
 previous=json.loads((WORK/'source-images.json').read_text());assert previous['source_super_sha256']==pin['sha256'];images=previous['images']
for name in (['system_ext'] if a.additional_system_ext else ['product','odm']):
 part=next(x for x in metadata['partitions'] if x['name']==name+'_a')
 output=WORK/(name+'-source.img')
 assert not output.exists()
 h=hashlib.sha256()
 with source.open('rb') as src,output.open('xb') as dst:
  for e in part['extents']:
   src.seek(e['offset_bytes']);left=e['size_bytes']
   while left:
    block=src.read(min(left,4*1024**2));assert block;dst.write(block);h.update(block);left-=len(block)
 images[name]={'path':str(output),'sha256':h.hexdigest(),'size':output.stat().st_size,'extents':part['extents']}
 print('Extracted',name,images[name],flush=True)
result={'source_super_sha256':pin['sha256'],'images':images,'metadata':metadata}
(WORK/'source-images.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
print('Exact source partitions prepared',flush=True)
