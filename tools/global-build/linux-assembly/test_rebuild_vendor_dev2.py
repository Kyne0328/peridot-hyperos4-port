import json,os,pathlib,stat,struct,subprocess,tempfile,unittest
from unittest import mock
import rebuild_vendor_dev2 as V
from verify_erofs_tree import ErofsImage

class VendorPreservationTests(unittest.TestCase):
 def attrs(self,mask=None):
  a={'security.selinux':b'u:object_r:vendor_file:s0'.hex()}
  if mask is not None:a['security.capability']=struct.pack('<IIIII',0x02000001,mask&0xffffffff,0,mask>>32,0).hex()
  return a
 def test_capabilities_roundtrip(self):
  for mask in [1,0x1800000400,0x1000001400,0xc0]:self.assertEqual(V.capability_mask(self.attrs(mask)),mask)
  self.assertEqual(V.capability_mask(self.attrs()),0)
 def test_unknown_xattrs_rejected(self):
  for a in [{},{**self.attrs(),'user.unreviewed':'00'}]:
   with self.assertRaises(V.Invalid):V.capability_mask(a)
 def test_unsupported_caps_rejected(self):
  for cap in ['00',struct.pack('<IIIII',0x02000000,1,0,0,0).hex(),struct.pack('<IIIII',0x02000001,1,1,0,0).hex()]:
   with self.assertRaises(V.Invalid):V.capability_mask({**self.attrs(),'security.capability':cap})
 def test_symlink_ancestors_rejected(self):
  with tempfile.TemporaryDirectory() as tmp:
   root=pathlib.Path(tmp);(root/'escape').symlink_to('/tmp')
   with self.assertRaises(V.Invalid):V.safe_path(root,'/escape/file')
   with self.assertRaises(V.Invalid):V.safe_path(root,'/../file')
   for name in ['/a/./b','//a/b','/a//b','/a/']:
    with self.assertRaises(V.Invalid):V.safe_path(root,name)
 def test_official_mkfs_metadata_and_symlink_roundtrip(self):
  with tempfile.TemporaryDirectory() as tmp:
   w=pathlib.Path(tmp);tree=w/'tree';tree.mkdir();(tree/'bin').mkdir();data=b'file bytes with no host capabilities\n';(tree/'bin/service').write_bytes(data);(tree/'alias').symlink_to('/vendor/bin/service')
   entries=[{'path':'/','mode':stat.S_IFDIR|0o755,'uid':0,'gid':2000,'xattrs':self.attrs()}, {'path':'/bin','mode':stat.S_IFDIR|0o755,'uid':0,'gid':2000,'xattrs':self.attrs()}, {'path':'/bin/service','mode':stat.S_IFREG|0o751,'uid':1001,'gid':1002,'size':len(data),'sha256':V.sha(data),'xattrs':self.attrs(0x1800000400)}, {'path':'/alias','mode':stat.S_IFLNK|0o777,'uid':0,'gid':2000,'size':len('/vendor/bin/service'),'sha256':V.sha(b'/vendor/bin/service'),'symlink_target':'/vendor/bin/service','xattrs':self.attrs()}]
   with mock.patch.object(V,'WORK',w):V.make_metadata(entries)
   image=w/'vendor.erofs';args=[str(V.MKFS),'-T','1230768000','-zlz4hc,level=12','--mount-point=/vendor','--fs-config-file='+str(w/'composed_fs_config'),'--file-contexts='+str(w/'composed_file_contexts'),str(image),str(tree)]
   result=subprocess.run(args,capture_output=True);self.assertEqual(result.returncode,0,result.stderr.decode())
   expected=w/'expected.json';expected.write_text(json.dumps({'entries':entries}));report=V.verify(image,expected,w/'report.json');self.assertIsInstance(report,dict);self.assertEqual(report['filesystem_size_bytes'],image.stat().st_size);self.assertEqual(report['status'],'verified')
   self.assertNotIn('security.capability',os.listxattr(tree/'bin/service'))
 def test_system_root_layout_and_0644_symlink(self):
  with tempfile.TemporaryDirectory() as tmp:
   w=pathlib.Path(tmp);tree=w/'tree';(tree/'system/bin').mkdir(parents=True);(tree/'system/bin/run-as').write_bytes(b'unchanged executable');(tree/'etc').symlink_to('/system/etc')
   entries=[{'path':'/','mode':stat.S_IFDIR|0o755,'uid':0,'gid':0,'xattrs':{'security.selinux':b'u:object_r:rootfs:s0'.hex()}}, {'path':'/system','mode':stat.S_IFDIR|0o755,'uid':0,'gid':0,'xattrs':self.attrs()}, {'path':'/system/bin','mode':stat.S_IFDIR|0o755,'uid':0,'gid':2000,'xattrs':self.attrs()}, {'path':'/system/bin/run-as','mode':stat.S_IFREG|0o750,'uid':0,'gid':2000,'size':20,'sha256':V.sha(b'unchanged executable'),'xattrs':self.attrs(0xc0)}, {'path':'/etc','mode':stat.S_IFLNK|0o644,'uid':0,'gid':0,'size':11,'sha256':V.sha(b'/system/etc'),'symlink_target':'/system/etc','xattrs':self.attrs()}]
   with mock.patch.object(V,'WORK',w):V.make_metadata(entries,'system')
   image=w/'system.erofs';args=[str(V.MKFS),'-T','1230768000','-zlz4hc,level=12','--mount-point=/','--fs-config-file='+str(w/'composed_fs_config'),'--file-contexts='+str(w/'composed_file_contexts'),str(image),str(tree)]
   result=subprocess.run(args,capture_output=True);self.assertEqual(result.returncode,0,result.stderr.decode())
   expected=w/'expected.json';expected.write_text(json.dumps({'entries':entries}));V.verify(image,expected,w/'report.json')

if __name__=='__main__':unittest.main()
