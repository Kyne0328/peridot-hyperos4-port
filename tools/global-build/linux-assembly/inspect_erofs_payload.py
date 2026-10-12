"""Read-only bounded EROFS metadata inventory directly from verified OTA operations."""
import bisect,collections,functools,hashlib,json,stat,struct,sys
from payload_stream import Payload,Invalid
class Erofs:
 def __init__(self,payload,name):
  self.payload=payload;self.part=payload.partitions[name];self.map=[]
  for ix,op in enumerate(self.part.ops):
   ro=0
   for off,n in op.extents:self.map.append((off,n,ix,ro));ro+=n
  self.map.sort();self.starts=[x[0] for x in self.map]
  s=self.read(1024,128)
  if struct.unpack_from('<I',s)[0]!=0xe0f5e1e2:raise Invalid('not EROFS')
  self.bs=1<<s[12];self.root=struct.unpack_from('<H',s,14)[0];self.meta=struct.unpack_from('<I',s,40)[0]*self.bs;self.xattr_base=struct.unpack_from('<I',s,44)[0]*self.bs
  if self.bs!=4096:raise Invalid('unsupported EROFS block size')
 @functools.lru_cache(maxsize=32)
 def raw(self,ix):return self.payload.raw(self.part.ops[ix])
 def read(self,off,n):
  out=bytearray()
  while n:
   ix=bisect.bisect_right(self.starts,off)-1
   if ix<0:raise Invalid('unmapped offset')
   start,size,opix,ro=self.map[ix]
   if not start<=off<start+size:raise Invalid('unmapped offset')
   take=min(n,start+size-off);out.extend(self.raw(opix)[ro+off-start:ro+off-start+take]);off+=take;n-=take
  return bytes(out)
 def inode(self,nid):
  off=self.meta+32*nid;b=self.read(off,64);fmt,xc,mode=struct.unpack_from('<HHH',b);isz=64 if fmt&1 else 32;size=struct.unpack_from('<Q' if fmt&1 else '<I',b,8)[0];addr=struct.unpack_from('<I',b,16)[0]
  uid,gid=struct.unpack_from('<II' if fmt&1 else '<HH',b,24)
  xa=self.xattrs(off+isz,xc)
  return {'nid':nid,'mode':mode,'uid':uid,'gid':gid,'size':size,'addr':addr,'layout':(fmt>>1)&7,'inline':off+isz+(12+4*(xc-1) if xc else 0),'xattrs':xa}
 def xattr_entry(self,off):
  nl,ni,vl=struct.unpack('<BBH',self.read(off,4))
  prefixes={1:'user.',2:'system.posix_acl_access',3:'system.posix_acl_default',4:'trusted.',5:'lustre.',6:'security.'}
  if ni not in prefixes:raise Invalid(f'unsupported xattr name prefix {ni}')
  data=self.read(off+4,nl+vl);name=prefixes[ni]+data[:nl].decode()
  return name,data[nl:].hex(),(4+nl+vl+3)//4*4
 def xattrs(self,off,icount):
  if not icount:return {}
  size=12+4*(icount-1);h=self.read(off,12);shared=h[4];p=12+4*shared
  if p>size:raise Invalid('xattr shared ids exceed body')
  out={}
  for i in range(shared):
   xid=struct.unpack('<I',self.read(off+12+4*i,4))[0];name,value,_=self.xattr_entry(self.xattr_base+xid*4)
   if name in out:raise Invalid('duplicate xattr')
   out[name]=value
  while p<size:
   name,value,n=self.xattr_entry(off+p)
   if p+n>size or name in out:raise Invalid('invalid inline xattr')
   out[name]=value;p+=n
  return out
 def data(self,i):
  if i['layout'] not in [0,2]:raise Invalid('compressed/chunked EROFS file data unsupported')
  size=i['size'];full=size//self.bs*self.bs if i['layout']==2 else size
  return self.read(i['addr']*self.bs,full)+(self.read(i['inline'],size-full) if full<size else b'')
 def entries(self,nid):
  raw=self.data(self.inode(nid));out=[]
  for off in range(0,len(raw),self.bs):
   d=raw[off:off+self.bs]
   if len(d)<12:raise Invalid('short directory')
   count=struct.unpack_from('<H',d,8)[0]//12
   if count<=0 or count*12>len(d):raise Invalid('invalid directory entry count')
   ds=[struct.unpack_from('<QHBB',d,n*12) for n in range(count)]
   for x,(nid,no,ft,res) in enumerate(ds):
    ne=ds[x+1][1] if x+1<len(ds) else len(d)
    if not count*12<=no<ne<=len(d):raise Invalid('invalid directory name bounds')
    name=d[no:ne].split(b'\0')[0].decode()
    if name not in ['.','..']:out.append((name,nid,ft))
  return out
 def inventory(self):
  rows=[];todo=[('',self.root)];seen_dirs=set()
  while todo:
   path,nid=todo.pop();i=self.inode(nid);rows.append({'path':path or '/',**i})
   if stat.S_ISDIR(i['mode']):
    if nid in seen_dirs:raise Invalid('directory cycle')
    seen_dirs.add(nid)
    todo.extend((path+'/'+n,child) for n,child,ft in self.entries(nid))
  return rows
if __name__=='__main__':
 p=Payload(sys.argv[1],sys.argv[2]);e=Erofs(p,sys.argv[3]);rows=e.inventory();summary={'partition':sys.argv[3],'entries':len(rows),'regular_files':sum(stat.S_ISREG(i['mode']) for i in rows),'regular_logical_bytes':sum(i['size'] for i in rows if stat.S_ISREG(i['mode'])),'file_layouts':dict(collections.Counter(i['layout'] for i in rows if stat.S_ISREG(i['mode']))),'metadata_only':True,'source_archive_sha256':p.sha256,'top_large_files':sorted([{'path':i['path'],'size':i['size']} for i in rows if stat.S_ISREG(i['mode'])],key=lambda i:i['size'],reverse=True)[:30]};print(json.dumps(summary,indent=2));open(sys.argv[4],'x').write(json.dumps({'summary':summary,'entries':rows},indent=2));p.close()
