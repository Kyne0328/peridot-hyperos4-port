#!/usr/bin/env python3
"""Read selected EROFS files from hash-pinned OTA using bounded sparse inspection."""
import argparse,hashlib,json,os,pathlib,re,subprocess,tempfile,zipfile,io
from payload_stream import Payload,Invalid
from inspect_erofs_payload import Erofs
TOOL='/workspace/shared/peridot-global-base/tools/erofs-utils/usr/bin/dump.erofs'
def extract(p,partition,paths,out):
 out=pathlib.Path(out);out.mkdir(parents=True,exist_ok=True);e=Erofs(p,partition);rows={i['path']:i for i in e.inventory()};records=[]
 with tempfile.TemporaryDirectory(prefix='sparse-inspection-',dir=out) as tmp:
  image=pathlib.Path(tmp)/'partial-erofs-inspection-only.img'
  with image.open('w+b') as f:
   f.truncate(e.part.size)
   def fill(off,n):
    if off<0 or n<0 or off+n>e.part.size:raise Invalid('sparse range out of bounds')
    f.seek(off);f.write(e.read(off,n));f.flush()
   fill(0,4096)
   for path in paths:
    if path not in rows:raise Invalid('EROFS path absent: '+path)
    i=rows[path];off=(e.meta+32*i['nid'])//4096*4096;fill(off,min(16384+((i['size']+4095)//4096)*8,e.part.size-off))
    cmd=[TOOL,f'--nid={i["nid"]}','-e',str(image)];r=subprocess.run(cmd,capture_output=True,text=True)
    if r.returncode:raise Invalid('extent lookup failed '+r.stderr)
    ranges=[tuple(map(int,m)) for m in re.findall(r'^\s*\d+:\s*\d+\.\.\s*\d+\s*\|\s*\d+\s*:\s*(\d+)\.\.\s*(\d+)\s*\|\s*(\d+)',r.stdout,re.M)]
    if not ranges and i['size']:raise Invalid('no physical extents')
    for start,end,n in ranges:
     if end-start!=n:raise Invalid('extent bounds mismatch')
     fill(start,n)
    data=subprocess.run([TOOL,'--cat',f'--nid={i["nid"]}',str(image)],capture_output=True,check=True).stdout
    if len(data)!=i['size']:raise Invalid('decoded size mismatch')
    dst=out/partition/path.lstrip('/');dst.parent.mkdir(parents=True,exist_ok=True)
    if dst.exists():raise Invalid('refuse overwrite '+str(dst))

    if path.endswith(('.apk','.jar','.apex','.capex')):
     with zipfile.ZipFile(io.BytesIO(data)) as archive:
      if archive.testzip() is not None:raise Invalid('decoded ZIP CRC mismatch')
    dst.write_bytes(data);rec={'path':path,'partition':partition,'output':str(dst),'size':len(data),'sha256':hashlib.sha256(data).hexdigest(),'source_archive_sha256':p.sha256,'source_operation_sha256_verified':True,'metadata':{k:i[k] for k in ('uid','gid','mode','xattrs')},'physical_extents':ranges};records.append(rec);print(json.dumps({k:v for k,v in rec.items() if k!='physical_extents'}),flush=True)
 e.raw.cache_clear();return records
if __name__=='__main__':
 a=argparse.ArgumentParser(description=__doc__);a.add_argument('--archive',required=True);a.add_argument('--sha256',required=True);a.add_argument('--select',action='append',required=True,help='partition:/absolute/path');a.add_argument('--out',required=True);x=a.parse_args();by={}
 for s in x.select:
  part,path=s.split(':',1);by.setdefault(part,[]).append(path)
 p=Payload(x.archive,x.sha256);r=[]
 for part,paths in by.items():r+=extract(p,part,paths,x.out)
 with (pathlib.Path(x.out)/'extraction-report.json').open('x') as f:json.dump(r,f,indent=2)
 p.close()
