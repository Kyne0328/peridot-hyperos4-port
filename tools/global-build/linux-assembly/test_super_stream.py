import hashlib,json,pathlib,tempfile,unittest
from super_stream import prepare,stage_product,inspect_all,Invalid,verify_image_span
class TestSuper(unittest.TestCase):
 def setUp(self):self.temp=tempfile.TemporaryDirectory();self.root=pathlib.Path(self.temp.name)
 def tearDown(self):self.temp.cleanup()
 def ready(self):
  p=self.root/'product.img';p.write_bytes(bytes(range(256))*16)
  return prepare('/workspace/shared/peridot-global-builder/global-source-plan.json','/workspace/shared/peridot-global-base/geometry/super_geometry.json',str(p),hashlib.sha256(p.read_bytes()).hexdigest(),self.root/'stage')
 def test_prepare_all_copies_and_stage_product(self):
  r=self.ready();self.assertTrue(r['layout']['integrity']['all_six_metadata_copies_verified']);self.assertEqual(len(r['layout']['partitions']),16)
  r=stage_product(self.root/'stage');self.assertEqual(r['status'],'product_staged')
  i=next(x for x in r['inputs'] if x['partition']=='product')
  with open(r['partial_output'],'rb') as f:self.assertEqual(verify_image_span(f,i['physical_extents']),i['sha256'])
 def test_corrupt_backup_slot_rejected(self):
  r=self.ready()
  with open(r['partial_output'],'r+b') as f:f.seek(12288+5*65536+20);f.write(b'broken')
  with self.assertRaises(Exception):inspect_all(r['partial_output'])
 def test_refuse_existing_stage(self):
  r=self.ready()
  with self.assertRaisesRegex(Invalid,'stage already exists'):self.ready()
 def test_source_product_change_rejected(self):
  r=self.ready();(self.root/'product.img').write_bytes(b'0'*4096)
  with self.assertRaisesRegex(Invalid,'source SHA256 changed'):stage_product(self.root/'stage')
if __name__=='__main__':unittest.main()
