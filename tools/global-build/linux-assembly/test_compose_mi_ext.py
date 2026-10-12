import copy,hashlib,json,pathlib,unittest
from compose_mi_ext import patch_props,patch_cust,cust_nodes,R
class TestMiExt(unittest.TestCase):
 def setUp(self):
  self.props=json.loads(pathlib.Path('/workspace/shared/peridot-global-builder/builder/devices/peridot/composition/global-mi-ext-target-properties-v0.json').read_text())
  self.cust=json.loads(pathlib.Path('/workspace/shared/peridot-global-builder/review-cust-features/narrow-policy-v1.json').read_text())
  self.pb=(R/'mi-ext-metadata/original_build.prop').read_bytes();self.cb=(R/'mi-ext-metadata/original_device_features.xml').read_bytes()
 def test_properties_exact_guarded_output(self):
  out,keys=patch_props(self.pb,self.props);self.assertEqual(hashlib.sha256(out).hexdigest(),'970492c022d25b490281cd27263fadd791fe94113e595daeb43189cf3731ffe9');self.assertEqual(len(keys),9);self.assertIn(b'ro.thermal.iec.enable=true',out)
 def test_cust_six_changes_other_nodes_preserved(self):
  out,keys=patch_cust(self.cb,self.cust);self.assertEqual(len(keys),6);old,new=cust_nodes(self.cb),cust_nodes(out)
  for k in old.keys()&new.keys():
   if k not in keys:self.assertEqual(old[k],new[k])
  self.assertEqual(new[('integer','config_wifi_sar_pattern')][2],'8')
 def test_bad_property_hash_rejected(self):
  with self.assertRaisesRegex(ValueError,'source hash'):patch_props(self.pb+b'\n',self.props)
 def test_duplicate_property_rejected(self):
  b=self.pb+b'ro.product.mod_device=pudding_global\n';p=copy.deepcopy(self.props);p['source_file_sha256']=hashlib.sha256(b).hexdigest()
  with self.assertRaisesRegex(ValueError,'count'):patch_props(b,p)
 def test_bad_xml_hash_rejected(self):
  with self.assertRaisesRegex(ValueError,'source hash'):patch_cust(self.cb+b'\n',self.cust)
 def test_duplicate_xml_name_rejected(self):
  b=self.cb.replace(b'</cust_feature>',b'<bool name="device_on_platform_8850">true</bool></cust_feature>');p=copy.deepcopy(self.cust);p['target_file']['expected_sha256']=hashlib.sha256(b).hexdigest()
  with self.assertRaisesRegex(ValueError,'duplicate'):patch_cust(b,p)
if __name__=='__main__':unittest.main()
