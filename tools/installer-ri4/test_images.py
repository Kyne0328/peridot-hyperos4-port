"""Readback and regression checks for the actual RI4 authored images."""
from pathlib import Path
import hashlib,json,struct,sys,unittest
ROOT=Path(__file__).resolve().parents[2];WORK=ROOT/'builder/work/installer-ri4';SRC=ROOT/'.cache/global-single-recovery-ri2/source-images/images'
sys.path[:0]=[str(ROOT/'builder'),str(ROOT/'tools/global-build/linux-assembly'),str(ROOT/'tools/installer-ri3/recovery-pair')]
from rebuild_images import patch_fstab,decode
from pair_format import verify_avb,parse_avb,cpio_entries,unpack_boot
from super_stream import inspect_all
def files(raw):return {e['name']:(e['fields'][:6]+e['fields'][7:],raw[e['offset']:e['offset']+e['size']]) for e in cpio_entries(raw)}
def vendor_rd(p):
 b=p.read_bytes();n=struct.unpack_from('<I',b,24)[0];return decode(b[4096:4096+n])
def named(d):
 t=struct.unpack_from('>Q',d)[0]
 if t==1:n=struct.unpack_from('>I',d,104)[0];return d[180:180+n].decode()
 if t==2:n=struct.unpack_from('>I',d,56)[0];return d[132:132+n].decode()
 return None
class Images(unittest.TestCase):
 def test_patch_only_userdata(self):
  src=b'/dev/user /data f2fs inlinecrypt wait,fileencryption=x,keydirectory=y,metadata_encryption=z,quota\n/dev/usb /usb vfat defaults wait,encryptable=footer\n'
  out,changes=patch_fstab(src);self.assertEqual(out,b'/dev/user /data f2fs inlinecrypt wait,quota\n/dev/usb /usb vfat defaults wait,encryptable=footer\n');self.assertEqual(len(changes),1);self.assertEqual(patch_fstab(out),(out,[]))
 def test_vendor_boot_only_fstab_changed(self):
  before=files(vendor_rd(SRC/'vendor_boot.img'));after=files(vendor_rd(WORK/'vendor_boot.img'));self.assertEqual(before.keys(),after.keys());changed=[]
  for n,(meta,b) in before.items():
   self.assertEqual(meta,after[n][0],n)
   if b!=after[n][1]:changed.append(n);self.assertEqual(patch_fstab(b)[0],after[n][1])
  self.assertEqual(changed,['first_stage_ramdisk/fstab.qcom'])
 def test_recovery_only_fstab_changed(self):
  before=(ROOT/'builder/work/installer-ri3-recovery/images-ziptrust/recovery.img').read_bytes();after=(WORK/'recovery.img').read_bytes();a=files(b''.join(x[1] for x in unpack_boot(before)[1]));b=files(b''.join(x[1] for x in unpack_boot(after)[1]));self.assertEqual(a.keys(),b.keys());changed=[]
  for n,(meta,data) in a.items():
   self.assertEqual(meta,b[n][0],n)
   if data!=b[n][1]:changed.append(n);self.assertEqual(patch_fstab(data)[0],b[n][1])
  self.assertEqual(changed,['system/etc/recovery.fstab']);verify_avb(after)
 def test_root_descriptors_and_signatures(self):
  before=verify_avb((ROOT/'builder/work/installer-ri3-recovery/images-ziptrust/vbmeta.img').read_bytes());after=verify_avb((WORK/'vbmeta.img').read_bytes());self.assertEqual(before['header'][16:19],after['header'][16:19]);self.assertEqual(before['header'][17],0);self.assertEqual(len(before['descriptors']),len(after['descriptors']));changed=[]
  for a,b in zip(before['descriptors'],after['descriptors']):
   if a!=b:changed.append(named(a));self.assertEqual(named(a),named(b))
  self.assertEqual(set(changed),{'vendor','vendor_boot'})
  for name in changed:
   p=parse_avb((WORK/(name+'.img')).read_bytes());d=next(x for x in p['descriptors'] if named(x)==name);self.assertIn(d,after['descriptors'])
 def test_super_layout_all_copies_unchanged(self):self.assertEqual(inspect_all(SRC/'super.img'),inspect_all(WORK/'super.img'))
 def test_vendor_verified_readback(self):
  r=json.loads((WORK/'vendor-receipt.json').read_text());self.assertTrue(r['metadata_and_all_file_bytes_verified']);self.assertEqual(r['filesystem_entries'],2910);self.assertEqual([x['path'] for x in r['changes']],['/etc/fstab.qcom']);self.assertTrue(r['verity_retained'])
if __name__=='__main__':unittest.main(verbosity=2)
