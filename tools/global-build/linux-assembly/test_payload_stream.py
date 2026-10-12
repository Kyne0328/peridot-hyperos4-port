import base64,bz2,hashlib,io,json,lzma,os,pathlib,struct,tempfile,unittest,zipfile
from payload_stream import Payload,Invalid

def vi(x):
 b=b''
 while x>=128:b+=bytes([(x&127)|128]);x>>=7
 return b+bytes([x])
def f(n,v):
 return vi(n<<3)+(vi(v)) if isinstance(v,int) else vi((n<<3)|2)+vi(len(v))+v

def fixture(path,kind=8,bad_op=False,bad_part=False,overlap=False):
 data=(b'abc123'*683)[:4096]
 blob=data if kind==0 else bz2.compress(data) if kind==1 else lzma.compress(data)
 extent=f(1,0)+f(2,1)
 op=f(1,kind)+f(2,0)+f(3,len(blob))+f(6,extent)+f(8,(b'x'*32 if bad_op else hashlib.sha256(blob).digest()))
 info=f(1,len(data))+f(2,(b'x'*32 if bad_part else hashlib.sha256(data).digest()))
 part=f(1,b'product')+f(7,info)+f(8,op)+(f(8,op) if overlap else b'')
 mf=f(3,4096)+f(13,part);mh=struct.pack('>4sQQI',b'CrAU',2,len(mf),0)+mf;payload=mh+blob
 props=f'FILE_SIZE={len(payload)}\nFILE_HASH={base64.b64encode(hashlib.sha256(payload).digest()).decode()}\nMETADATA_SIZE={len(mh)}\nMETADATA_HASH={base64.b64encode(hashlib.sha256(mh).digest()).decode()}\n'
 with zipfile.ZipFile(path,'w') as z:z.writestr('payload.bin',payload);z.writestr('payload_properties.txt',props)
 return hashlib.sha256(path.read_bytes()).hexdigest(),data

class TestPayload(unittest.TestCase):
 def setUp(self):self.t=tempfile.TemporaryDirectory();self.p=pathlib.Path(self.t.name)/'ota.zip'
 def tearDown(self):self.t.cleanup()
 def test_all_supported_codecs_and_physical_splits(self):
  for k in [0,1,8]:
   sha,data=fixture(self.p,kind=k);p=Payload(self.p,sha)
   with open(pathlib.Path(self.t.name)/'out','w+b') as out:
    out.truncate(16384);r=p.stream('product',out,[(4096,2048),(12288,2048)]);self.assertTrue(r['manifest_partition_sha256_verified'])
    out.seek(4096);a=out.read(2048);out.seek(12288);a+=out.read(2048);self.assertEqual(a,data)
   p.close()
 def test_wrong_archive_hash(self):
  sha,data=fixture(self.p)
  with self.assertRaisesRegex(Invalid,'archive SHA256'):Payload(self.p,'0'*64)
 def test_bad_operation_hash(self):
  sha,data=fixture(self.p,bad_op=True);p=Payload(self.p,sha)
  with open(pathlib.Path(self.t.name)/'out','w+b') as out:
   with self.assertRaisesRegex(Invalid,'operation compressed hash'):p.stream('product',out)
  p.close()
 def test_bad_partition_hash(self):
  sha,data=fixture(self.p,bad_part=True);p=Payload(self.p,sha)
  with open(pathlib.Path(self.t.name)/'out','w+b') as out:
   with self.assertRaisesRegex(Invalid,'full partition hash'):p.stream('product',out)
  p.close()
 def test_overlap_rejected(self):
  sha,data=fixture(self.p,overlap=True)
  with self.assertRaisesRegex(Invalid,'overlapping'):Payload(self.p,sha)
 def test_partial_archive_rejected(self):
  sha,data=fixture(self.p);new=self.p.with_suffix('.partial');self.p.rename(new)
  with self.assertRaisesRegex(Invalid,'partial archive'):Payload(new,sha)
 def test_no_trailing_compressed_data(self):
  sha,data=fixture(self.p);p=Payload(self.p,sha);op=p.partitions['product'].ops[0]
  self.assertEqual(p.raw(op),data);p.close()
if __name__=='__main__':unittest.main()
