import contextlib, hashlib, io, json, pathlib, struct, tempfile, unittest
from unittest import mock
import global_avb as g

class MappedTests(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory(dir=g.ROOT);self.d=pathlib.Path(self.t.name);self.p=self.d/'sample';self.p.write_bytes(bytes(range(256))*32)
 def tearDown(self):self.t.cleanup()
 def test_physical_file(self):
  r=g.MappedReader({'path':str(self.p)});self.assertEqual(r.sha256(),g.digest_file(self.p));r.close()
 def test_cross_extent(self):
  r=g.MappedReader({'path':str(self.p),'extents':[{'offset':1000,'size':100},{'offset':0,'size':100}]});r.seek(90);self.assertEqual(r.read(20),self.p.read_bytes()[1090:1100]+self.p.read_bytes()[:10]);r.close()
 def test_full_mapped_hash(self):
  r=g.MappedReader({'path':str(self.p),'extents':[{'offset':1000,'size':100},{'offset':0,'size':100}]});self.assertEqual(r.sha256(),hashlib.sha256(self.p.read_bytes()[1000:1100]+self.p.read_bytes()[:100]).hexdigest());r.close()
 def test_overlap_rejected(self):
  with self.assertRaises(g.Invalid):g.MappedReader({'path':str(self.p),'extents':[{'offset':10,'size':100},{'offset':50,'size':100}]})
 def test_negative_offset_rejected(self):
  with self.assertRaises(g.Invalid):g.MappedReader({'path':str(self.p),'extents':[{'offset':-1,'size':100}]})
 def test_outside_file_rejected(self):
  with self.assertRaises(g.Invalid):g.MappedReader({'path':str(self.p),'extents':[{'offset':8190,'size':100}]})
 def test_size_mismatch_rejected(self):
  with self.assertRaises(g.Invalid):g.MappedReader({'path':str(self.p),'size':8000})
 def test_read_bounds(self):
  r=g.MappedReader({'path':str(self.p)});r.seek(8190)
  with self.assertRaises(g.Invalid):r.read(3)
  r.close()
 def test_mutation_detected(self):
  r=g.MappedReader({'path':str(self.p)});self.p.write_bytes(b'changed')
  with self.assertRaises(g.Invalid):r.stable()
  r.close()
 def test_malformed_header_rejected(self):
  r=g.MappedReader({'path':str(self.p)})
  with self.assertRaises((g.Invalid,LookupError,g.A.AvbError)):g.parse_image(r)
  r.close()
 def test_official_unsigned_hashtree_and_fec(self):
  p=self.d/'fixture.img';p.write_bytes(bytes(range(256))*4096);original=p.read_bytes()
  g.command(['add_hashtree_footer','--image',p,'--partition_name','fixture','--partition_size',2*1024**2,'--salt','00'*32,'--hash_algorithm','sha256','--fec_num_roots',2,'--algorithm','NONE','--flags',0])
  v=g.load_meta(p);self.assertEqual(v[0].original_image_size,len(original));self.assertEqual(p.read_bytes()[:len(original)],original)
  ht=[d for d in v[2] if isinstance(d,g.A.AvbHashtreeDescriptor)][0];self.assertEqual(ht.fec_num_roots,2);self.assertGreater(ht.fec_size,0)
  r=g.MappedReader({'path':str(p)});offsets,size=g.A.calc_hash_level_offsets(ht.image_size,4096,32);root,tree=g.A.generate_hash_tree(r,ht.image_size,4096,'sha256',ht.salt,0,offsets,size);self.assertEqual(root,ht.root_digest);r.seek(ht.tree_offset);self.assertEqual(r.read(ht.tree_size),tree);r.close()

class GlobalSourceTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):cls.src=g.source_meta()
 def test_all_source_signatures(self):
  for path,v in self.src.values():self.assertTrue(g.A.verify_vbmeta_signature(v[1],v[3]))
 def test_exact_key(self):self.assertEqual(g.digest_file(g.KEY),g.KEY_SHA)
 def test_global_chains(self):
  top,_=g.get_descriptors(self.src);chains=[d for d in top if isinstance(d,g.A.AvbChainPartitionDescriptor)];self.assertEqual({d.partition_name:d.rollback_index_location for d in chains},{'boot':3,'recovery':1,'vbmeta_system':2})
  for d in chains:self.assertEqual(hashlib.sha1(d.public_key).hexdigest(),g.KEY_PUBLIC_SHA1 if d.partition_name=='vbmeta_system' else g.OEM_SHA1)
 def test_unchanged_descriptor_provenance(self):
  top,system=g.get_descriptors(self.src)
  for d in top:
   if isinstance(d,g.A.AvbChainPartitionDescriptor) and d.partition_name=='vbmeta_system':continue
   source=self.src['donor/vbmeta' if g.belongs(d,'mi_ext') else 'base/vbmeta'][1][2];self.assertIn(d.encode(),[x.encode() for x in source])
  for d in system:self.assertIn(d.encode(),[x.encode() for x in self.src['donor/vbmeta_system'][1][2]])
 def test_flags_zero(self):
  top,system=g.get_descriptors(self.src)
  for d in top+system:self.assertEqual(getattr(d,'flags',0),0)
 def test_product_properties_global(self):
  p=g.product_properties(self.src,None);self.assertEqual(p['com.android.build.product.os_version'],'17');self.assertIn('OS4.0.0.9.XPCMIXM',p['com.android.build.product.fingerprint'])
 def test_recovery_rollback_is_one(self):self.assertEqual(g.load_meta(g.ROOT/'stock-recovery-vbmeta.img')[1].rollback_index,1)
 def test_wrong_input_hash_fails_before_command(self):
  with tempfile.NamedTemporaryFile(dir=g.ROOT) as f:
   f.write(b'A'*4096);f.flush()
   with mock.patch.object(g,'command') as cmd:
    with self.assertRaises(g.Invalid):g.sign_product(f.name,'0'*64,4096,1048576,None)
    cmd.assert_not_called()
 def test_wrong_input_size_fails_before_command(self):
  with mock.patch.object(g,'command') as cmd:
   with self.assertRaises(g.Invalid):g.sign_product(g.ROOT/'stock-recovery-vbmeta.img','0'*64,4096,1048576,None)
   cmd.assert_not_called()
 def test_missing_full_hash_rejected(self):
  with tempfile.TemporaryDirectory(dir=g.ROOT) as t:
   p=pathlib.Path(t);f=p/'map.json';f.write_text(json.dumps({'images':{'vbmeta':{'path':str(g.BASE/'vbmeta.img')}}}))
   with self.assertRaises(g.Invalid):g.verify_mapped(f,p/'report.json')

if __name__=='__main__':unittest.main(verbosity=2)

class AdditionalGuards(unittest.TestCase):
 def test_mi_ext_properties_use_global_source(self):
  props=g.product_properties(g.source_meta(),None,'mi_ext');self.assertEqual(props['com.android.build.mi_ext.os_version'],'17');self.assertIn('OS4.0.0.9.XPCMIXM',props['com.android.build.mi_ext.fingerprint'])
 def test_mi_ext_budget_rejected(self):
  with tempfile.NamedTemporaryFile(dir=g.ROOT) as f:
   f.write(b'A'*4096);f.flush()
   with mock.patch.object(g,'command') as cmd:
    with self.assertRaises(g.Invalid):g.sign_product(f.name,g.digest_file(f.name),4096,1142345728+4096,None,'mi_ext')
    cmd.assert_not_called()
 def test_mutated_source_signature_rejected(self):
  with tempfile.TemporaryDirectory(dir=g.ROOT) as t:
   p=pathlib.Path(t)/'vbmeta.img';b=bytearray((g.BASE/'vbmeta.img').read_bytes());b[256]^=1;p.write_bytes(b)
   with self.assertRaises(g.Invalid):g.load_meta(p)
 def test_stock_expected_hashes(self):
  pins=g.preserved_sources();self.assertEqual(pins['recovery']['sha256'],'936a66e4ae8bc3fba7b004696c4d94d291abea6ce474e44445e7b6e857231a7f');self.assertEqual(pins['mi_ext']['size'],1142345728)
 def test_metadata_physical_fit(self):
  geom=json.loads(pathlib.Path('/workspace/shared/peridot-global-base/geometry/vbmeta_physical_capacity.json').read_text());self.assertEqual({x['physical_capacity_bytes'] for x in geom['partitions']},{131072});self.assertTrue(geom['candidate_capacity_check']['fits_each_top_level_vbmeta_partition'])
