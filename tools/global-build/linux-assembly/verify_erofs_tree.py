#!/usr/bin/env python3
"""Compare rebuilt EROFS metadata and streamed file hashes with reviewed inputs."""
import hashlib,json,os,pathlib,stat,struct,subprocess,sys
from inspect_erofs_payload import Erofs
from payload_stream import Invalid
DUMP='/workspace/shared/peridot-global-base/tools/erofs-utils/usr/bin/dump.erofs'
class ErofsImage(Erofs):
 def __init__(self,path,offset=0):
  self.f=open(path,'rb');self.fd=self.f.fileno();self.offset=offset;self.path=path
  s=self.read(1024,128)
  if struct.unpack_from('<I',s)[0]!=0xe0f5e1e2:raise Invalid('not EROFS')
  self.bs=1<<s[12];self.root=struct.unpack_from('<H',s,14)[0];self.meta=struct.unpack_from('<I',s,40)[0]*self.bs;self.xattr_base=struct.unpack_from('<I',s,44)[0]*self.bs
 def read(self,off,n):
  data=os.pread(self.fd,n,self.offset+off)
  if len(data)!=n:raise Invalid('short EROFS image read')
  return data
 def __del__(self):
  if hasattr(self,'f'):self.f.close()
 def close(self):self.f.close()

def hash_from_image(path,logical,nid=None,offset=0):
 args=[DUMP,'--cat',f'--nid={nid}' if nid is not None else '--path='+logical]
 if offset:args.append('--offset='+str(offset))
 args.append(str(path));p=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE);h=hashlib.sha256();size=0
 while b:=p.stdout.read(4*1024**2):h.update(b);size+=len(b)
 stderr=p.stderr.read();code=p.wait();p.stdout.close();p.stderr.close()
 if code:raise Invalid('dump.erofs failed '+logical+': '+stderr.decode(errors='replace'))
 return size,h.hexdigest()

def verify(image,expected,report,offset=0):
 inv=json.loads(pathlib.Path(expected).read_text());e=ErofsImage(image,offset);rows=e.inventory();actual={i['path']:i for i in rows};exp={i['path']:i for i in inv['entries']}
 if actual.keys()!=exp.keys():raise Invalid('image path set differs: extra '+str(actual.keys()-exp.keys())+' missing '+str(exp.keys()-actual.keys()))
 hashes=[]
 for name,i in sorted(exp.items()):
  a=actual[name]
  for k in ('uid','gid','mode','xattrs'):
   if a[k]!=i[k]:raise Invalid(f'image {name} metadata differs on {k}: {a[k]} != {i[k]}')
  if stat.S_ISREG(i['mode']):
   size,sha=hash_from_image(image,name,a['nid'],offset)
   if size!=i['size'] or sha!=i['sha256']:raise Invalid('image file content differs '+name)
   hashes.append({'path':name,'size':size,'sha256':sha})
 r={'status':'verified','filesystem_path':str(image),'offset':offset,'entries':len(rows),'regular_files':len(hashes),'all_file_bytes_sha256_verified':True,'all_uid_gid_modes_selinux_xattrs_verified':True,'files':hashes}
 with pathlib.Path(report).open('x') as f:json.dump(r,f,indent=2)
 e.close();print(json.dumps({k:v for k,v in r.items() if k!='files'}),flush=True);return r
if __name__=='__main__':verify(*sys.argv[1:])
