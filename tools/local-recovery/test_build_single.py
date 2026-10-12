import json,unittest,struct
from pathlib import Path
import build_single as b
class SingleTests(unittest.TestCase):
 def setUp(self):
  self.m=json.loads((b.REPO/'09-reports/global-4.0.0.9-on-f6-3.0.303/dev2/image-set-manifest.json').read_text())
 def test_alignment_large_offsets(self):
  for off in [0,1,511,4096,2**31-1,2**32,2**33,9909477376]:
   z=b.info('super/super.033',268435456,off,True)
   self.assertEqual((off+30+len(z.filename)+len(z.extra))%512,0)
   self.assertEqual(struct.unpack('<H',z.extra[:2])[0],0xCAFE)
 def test_render_contract(self):
  s=b.render([[2**33,'super/super.000',268435456,'a'*64]],self.m['images']).decode()
  self.assertEqual(len(s),b.RESERVE)
  self.assertNotIn('unzip',s);self.assertNotIn('payload_path',s)
  self.assertIn('8589934592 super/super.000 268435456',s)
  for guard in ['Live device-mapper','Target is mounted','Target has a live holder','OTA state listing failed','ZIP storage is not removable','Partition aliases overlap','Super capacity mismatch','Unlocked-state prerequisite','get-snapshot-merge-status','get-active-boot-slot','384 MiB']:
   self.assertIn(guard,s)
  self.assertEqual(s.count('read_payload "$offset" "$size"'),3)
  self.assertLess(s.index('[ "$#" = 3 ]'),s.index('OUTFD=$2'))
  self.assertLess(s.index('Payload hash mismatch'),s.index('WRITES_STARTED=1'))
  self.assertLess(s.index('Firmware must match exact Global'),s.index('WRITES_STARTED=1'))
  for banned in ['set-active-boot-slot','mkfs','fastboot','adb ','--disable-verity']:
   self.assertNotIn(banned,s)
 def test_erofs_empty_read(self):
  e=object.__new__(b.MappedErofs);e.size=4096
  self.assertEqual(e.read(0xffffffff*4096,0),b'')
  with self.assertRaises(ValueError):e.read(4096,1)
 def test_manifest_rejects_bad_size(self):
  self.m['images'][0]['size']+=1
  with self.assertRaises(ValueError):b.checked_manifest(self.m)
if __name__=='__main__':unittest.main(verbosity=2)
