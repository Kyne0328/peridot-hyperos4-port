from pathlib import Path
import sys,struct
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools/global-build/linux-assembly'))
from inspect_erofs_payload import Erofs
class Image(Erofs):
 def __init__(self,path,offset=0):
  self.f=Path(path).open('rb');self.offset=offset
  s=self.read(1024,128)
  if struct.unpack_from('<I',s)[0]!=0xe0f5e1e2:raise ValueError('not EROFS')
  self.bs=1<<s[12];self.root=struct.unpack_from('<H',s,14)[0];self.meta=struct.unpack_from('<I',s,40)[0]*self.bs;self.xattr_base=struct.unpack_from('<I',s,44)[0]*self.bs
 def read(self,off,n):
  self.f.seek(self.offset+off);data=self.f.read(n)
  if len(data)!=n:raise ValueError('short EROFS read')
  return data
 def close(self):self.f.close()
