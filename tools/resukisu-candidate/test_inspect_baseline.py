"""Read-only regression checks against immutable, hash-pinned RI2 evidence."""
import hashlib, json, struct, unittest
from pathlib import Path
from inspect_baseline import ROOT, avb
SRC=ROOT/'.cache/global-single-recovery-ri2/source-images/images'
class TestBaselineInspection(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.boot=(SRC/'boot.img').read_bytes()
        cls.meta=avb(cls.boot)
    def test_known_signed_images(self):
        for name in ['boot','recovery','vbmeta','vbmeta_system']:
            with self.subTest(name=name):
                self.assertTrue(avb((SRC/(name+'.img')).read_bytes())['signature_verified'])
    def test_kernel_tamper_rejected(self):
        b=bytearray(self.boot);b[4096+100]^=1
        with self.assertRaisesRegex(ValueError,'image hash mismatch'):avb(b)
    def test_signature_tamper_rejected(self):
        b=bytearray(self.boot);off=self.meta['offset'];sig_off=struct.unpack_from('>Q',b,off+48)[0];b[off+256+sig_off]^=1
        with self.assertRaisesRegex(ValueError,'signature mismatch'):avb(b)
    def test_auxiliary_tamper_rejected(self):
        b=bytearray(self.boot);off=self.meta['offset'];auth=struct.unpack_from('>Q',b,off+12)[0];b[off+256+auth]^=1
        with self.assertRaisesRegex(ValueError,'authentication hash mismatch'):avb(b)
    def test_bad_magic_rejected(self):
        with self.assertRaisesRegex(ValueError,'magic'):avb(bytes(1024))
    def test_unsigned_metadata_not_claimed_signed(self):
        for name in ['init_boot','vendor_boot','dtbo']:
            with self.subTest(name=name):self.assertFalse(avb((SRC/(name+'.img')).read_bytes())['signature_verified'])
    def test_top_child_keys_match(self):
        top=avb((SRC/'vbmeta.img').read_bytes());count=0
        for d in top['descriptors']:
            if d['tag']==4:
                child=avb((SRC/(d['partition']+'.img')).read_bytes())
                self.assertEqual(d['public_key_sha256'],child['public_key_sha256']);count+=1
        self.assertEqual(count,3)
    def test_top_physical_hash_descriptors(self):
        top=avb((SRC/'vbmeta.img').read_bytes());count=0
        for d in top['descriptors']:
            if d['tag']==2:
                b=(SRC/(d['partition']+'.img')).read_bytes()
                got=hashlib.new(d['hash_algorithm'],bytes.fromhex(d['salt'])+b[:d['image_size']]).hexdigest()
                self.assertEqual(got,d['digest']);count+=1
        self.assertEqual(count,4)
if __name__=='__main__':unittest.main()
