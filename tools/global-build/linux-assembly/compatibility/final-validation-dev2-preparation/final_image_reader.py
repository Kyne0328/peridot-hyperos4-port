#!/usr/bin/env python3
"""Read only a hash-verified finalized raw super. No flashing or ROM execution."""
from pathlib import Path
import bisect,hashlib,io,json,os,stat,struct,subprocess,sys
from types import SimpleNamespace
sys.path.insert(0,'/workspace/shared/peridot-global-assembly')
from inspect_erofs_payload import Erofs
from payload_stream import Invalid,fingerprint
from super_stream import inspect_all
DUMP='/workspace/shared/peridot-global-base/tools/erofs-utils/usr/bin/dump.erofs'
CHUNK=4*1024**2

def digest_file(path):
 h=hashlib.sha256()
 with Path(path).open('rb') as f:
  while b:=f.read(CHUNK):h.update(b)
 return h.hexdigest()

class ExtentReader:
 def __init__(self,fd,extents,size):
  self.fd=fd;self.extents=[];self.starts=[];cursor=0
  for physical,length in extents:
   if physical<0 or length<=0:raise Invalid('invalid extent')
   self.starts.append(cursor);self.extents.append((cursor,int(physical),int(length)));cursor+=length
  if cursor!=size:raise Invalid('extent size mismatch')
  self.size=size
 def read(self,off,n):
  if off<0 or n<0 or off+n>self.size:raise Invalid('logical partition read outside bounds')
  out=bytearray()
  while n:
   ix=bisect.bisect_right(self.starts,off)-1
   if ix<0:raise Invalid('unmapped logical offset')
   logical,physical,length=self.extents[ix];take=min(n,logical+length-off);b=os.pread(self.fd,take,physical+off-logical)
   if len(b)!=take:raise Invalid('short image read')
   out.extend(b);off+=take;n-=take
  return bytes(out)
 def digest(self):
  h=hashlib.sha256()
  for off in range(0,self.size,CHUNK):h.update(self.read(off,min(CHUNK,self.size-off)))
  return h.hexdigest()

class SuperReader:
 def __init__(self,assembly_path):
  self.assembly_path=Path(assembly_path).resolve();self.assembly_hash=digest_file(self.assembly_path);self.assembly=json.loads(self.assembly_path.read_text());a=self.assembly
  if a.get('status')!='byte_complete_offline_candidate' or a.get('all_partition_sha256_verified') is not True:raise Invalid('super is not finalized')
  self.path=Path(a['final_output']).resolve()
  if self.path.name.endswith('.partial'):raise Invalid('partial output is not final validation input')
  self.f=self.path.open('rb');self.identity=fingerprint(self.f)
  if self.identity[2]!=a['super_size_bytes']:raise Invalid('super length mismatch')
  if digest_file(self.path)!=a['super_sha256']:raise Invalid('full super digest mismatch')
  self.metadata=inspect_all(self.path)
  if self.metadata!=a['layout']:raise Invalid('actual LP metadata differs from final map')
  entries={p['name']:p for p in self.metadata['partitions']};self.parts={};self.extents={};self.records=[]
  if {i['partition'] for i in a['inputs']}!={'mi_ext','odm','product','system','system_dlkm','system_ext','vendor','vendor_dlkm'}:raise Invalid('unexpected logical partition set')
  for i in a['inputs']:
   name=i['partition'];p=entries[name+'_a'];ex=[(x['offset_bytes'],x['size_bytes']) for x in p['extents']]
   if list(map(tuple,i['physical_extents']))!=ex or p['size_bytes']!=i['size_bytes']:raise Invalid('partition extent map mismatch '+name)
   if entries[name+'_b']['size_bytes']!=0:raise Invalid('unexpected populated inactive slot')
   reader=ExtentReader(self.f.fileno(),ex,i['size_bytes']);got=reader.digest()
   if got!=i['sha256']:raise Invalid('final partition span digest mismatch '+name)
   self.parts[name]=reader;self.extents[name]=ex;self.records.append({'partition':name,'bytes':i['size_bytes'],'sha256':got,'physical_extents':ex,'verified_directly_in_final_super':True})
  self.check_unchanged()
 def check_unchanged(self):
  if fingerprint(self.f)!=self.identity or digest_file(self.assembly_path)!=self.assembly_hash:raise Invalid('final super or assembly map changed during validation')
 def close(self):self.check_unchanged();self.f.close()

class FinalErofs(Erofs):
 def __init__(self,super_reader,name):
  self.s=super_reader;self.name=name;self.r=super_reader.parts[name];self.size=self.r.size;s=self.read(1024,128)
  if struct.unpack_from('<I',s)[0]!=0xe0f5e1e2:raise Invalid('not EROFS: '+name)
  self.bs=1<<s[12];self.root=struct.unpack_from('<H',s,14)[0];self.meta=struct.unpack_from('<I',s,40)[0]*self.bs;self.xattr_base=struct.unpack_from('<I',s,44)[0]*self.bs
  if self.bs!=4096:raise Invalid('unsupported EROFS block size')
 def read(self,off,n):return self.r.read(off,n)
 def data(self,i):
  if i['layout'] not in [0,2]:raise Invalid('compressed/chunked EROFS file data unsupported')
  size=i['size'];full=size//self.bs*self.bs if i['layout']==2 else size
  # Inline-only and empty EROFS inodes use a sentinel block address; never read it.
  head=self.read(i['addr']*self.bs,full) if full else b''
  return head+(self.read(i['inline'],size-full) if full<size else b'')
 def file_bytes(self,row):
  if row['layout'] in [0,2]:return self.data(row)
  ex=self.s.extents[self.name]
  if len(ex)!=1:raise Invalid('compressed file in fragmented partition needs bounded staged reader; do not silently concatenate')
  cmd=[DUMP,'--cat',f'--nid={row["nid"]}',f'--offset={ex[0][0]}',str(self.s.path)]
  p=subprocess.run(cmd,capture_output=True)
  if p.returncode:raise Invalid('dump.erofs failed: '+p.stderr.decode(errors='replace'))
  if len(p.stdout)!=row['size']:raise Invalid('decoded file length differs')
  return p.stdout
 def open_file(self,row):
  if row['layout'] in [0,2]:return ErofsFile(self,row)
  return io.BytesIO(self.file_bytes(row))

class ErofsFile(io.RawIOBase):
 def __init__(self,e,row):self.e=e;self.row=row;self.pos=0
 def readable(self):return True
 def seekable(self):return True
 def tell(self):return self.pos
 def seek(self,o,w=0):
  p=o if w==0 else self.pos+o if w==1 else self.row['size']+o
  if p<0:raise ValueError('negative seek')
  self.pos=p;return p
 def read(self,n=-1):
  if n<0:n=self.row['size']-self.pos
  n=max(0,min(n,self.row['size']-self.pos));out=b''
  if not n:return out
  full=self.row['size']//4096*4096 if self.row['layout']==2 else self.row['size']
  if self.pos<full:
   take=min(n,full-self.pos);out=self.e.read(self.row['addr']*4096+self.pos,take);self.pos+=take;n-=take
  if n:out+=self.e.read(self.row['inline']+self.pos-full,n);self.pos+=n
  return out
