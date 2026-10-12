import tempfile,pathlib,unittest
from final_image_reader import ExtentReader,FinalErofs,Invalid
class TestExtentReader(unittest.TestCase):
 def test_cross_extent_reads_and_hash(self):
  with tempfile.TemporaryFile() as f:
   f.write(b'A'*4096+b'B'*4096+b'C'*4096);f.flush();r=ExtentReader(f.fileno(),[(8192,4096),(0,4096)],8192)
   self.assertEqual(r.read(4090,12),b'C'*6+b'A'*6)
   import hashlib
   self.assertEqual(r.digest(),hashlib.sha256(b'C'*4096+b'A'*4096).hexdigest())
   for off,n in [(-1,1),(8192,1),(0,8193),(0,-1)]:
    with self.assertRaises(Invalid):r.read(off,n)
 def test_inline_and_empty_sentinel_inode(self):
  with tempfile.TemporaryFile() as f:
   f.write(b'X'*4096);f.flush();e=FinalErofs.__new__(FinalErofs);e.bs=4096;e.r=ExtentReader(f.fileno(),[(0,4096)],4096)
   self.assertEqual(e.data({'layout':2,'size':12,'addr':0xffffffff,'inline':128}),b'X'*12)
   self.assertEqual(e.data({'layout':0,'size':0,'addr':0xffffffff,'inline':128}),b'')
 def test_reject_wrong_size(self):
  with self.assertRaises(Invalid):ExtentReader(0,[(0,8)],9)
if __name__=='__main__':unittest.main()
