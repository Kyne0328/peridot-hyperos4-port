import hashlib,json,pathlib,subprocess,tempfile,unittest
from verify_erofs_tree import ErofsImage,verify,Invalid
MKFS='/workspace/shared/peridot-cloud/tools/otatools-minimal/bin/mkfs.erofs'
class TestTree(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory();r=self.r=pathlib.Path(self.t.name);src=r/'product';src.mkdir();(src/'check').write_bytes(b'metadata test\n')
  (r/'fsconfig').write_text('/ 0 0 0755 capabilities=0x0\nproduct 0 0 0755 capabilities=0x0\nproduct/check 123 456 0644 capabilities=0x0\n')
  (r/'contexts').write_text('/product u:object_r:system_file:s0\n/product/check u:object_r:vendor_file:s0\n')
  subprocess.run([MKFS,'-T','1230768000','--mount-point=/product','--fs-config-file='+str(r/'fsconfig'),'--file-contexts='+str(r/'contexts'),'-zlz4hc,level=12',str(r/'image'),str(src)],check=True,capture_output=True)
  e=ErofsImage(r/'image');rows=e.inventory();e.close()
  for i in rows:
   if i['path']=='/check':i['sha256']=hashlib.sha256(b'metadata test\n').hexdigest()
  self.rows=rows;(r/'expected.json').write_text(json.dumps({'entries':rows}))
 def tearDown(self):self.t.cleanup()
 def test_metadata_and_bytes_preserved(self):
  i=next(x for x in self.rows if x['path']=='/check');self.assertEqual((i['uid'],i['gid'],i['mode']&0o7777),(123,456,0o644));self.assertEqual(bytes.fromhex(i['xattrs']['security.selinux']),b'u:object_r:vendor_file:s0')
  report=verify(self.r/'image',self.r/'expected.json',self.r/'report.json');self.assertTrue(report['all_file_bytes_sha256_verified'])
 def test_changed_uid_rejected(self):
  self.rows[-1]['uid']=999;(self.r/'expected.json').write_text(json.dumps({'entries':self.rows}))
  with self.assertRaisesRegex(Invalid,'metadata differs'):verify(self.r/'image',self.r/'expected.json',self.r/'report.json')
 def test_changed_file_hash_rejected(self):
  self.rows[-1]['sha256']='0'*64;(self.r/'expected.json').write_text(json.dumps({'entries':self.rows}))
  with self.assertRaisesRegex(Invalid,'file content differs'):verify(self.r/'image',self.r/'expected.json',self.r/'report.json')
if __name__=='__main__':unittest.main()
