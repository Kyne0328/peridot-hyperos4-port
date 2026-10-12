import copy,io,json,pathlib,unittest
import assemble_dev2_from_frozen as A

class FreshAssemblyTests(unittest.TestCase):
 def setUp(self):self.original=json.loads((A.DEV1/'assembly.json').read_text())
 def test_source_manifest_identity(self):self.assertEqual(A.digest(A.DEV1/'assembly.json'),A.DEV1_ASSEMBLY_SHA)
 def test_exact_source_input_layout_binding(self):A.bind_inputs_to_layout(self.original,self.original['layout'])
 def test_wrong_input_extents_rejected(self):
  for field,new in [('size_bytes',4096),('physical_extents',[[1048576,4096]])]:
   changed=copy.deepcopy(self.original);changed['inputs'][0][field]=new
   with self.assertRaises(A.Invalid):A.bind_inputs_to_layout(changed,self.original['layout'])
 def test_duplicate_or_missing_input_rejected(self):
  changed=copy.deepcopy(self.original);changed['inputs'][0]=changed['inputs'][1]
  with self.assertRaises(A.Invalid):A.bind_inputs_to_layout(changed,self.original['layout'])
 def test_nonempty_inactive_slot_rejected(self):
  layout=copy.deepcopy(self.original['layout']);layout['partitions'][1]['size_bytes']=4096
  with self.assertRaises(A.Invalid):A.bind_inputs_to_layout(self.original,layout)
 def test_copy_short_source_rejected(self):
  with self.assertRaises(A.Invalid):A.copy_exact(io.BytesIO(b'a'),io.BytesIO(),2)
 def test_authoring_scope_binding(self):
  review='/tmp/review.json';h='a'*64;v='b'*64
  r={'schema':2,'build_id':'DEV2','partition':'vendor','source_partition_sha256':A.STOCK_VENDOR_SHA,'composition_review_approved':True,'composition_review':{'path':review,'sha256':h},'output':{'sha256':v,'size':430030848}}
  A.bind_authoring_receipt(r,v,review,h)
  for k,val in [('build_id','DEV1'),('source_partition_sha256','c'*64),('composition_review_approved',False),('composition_review',{'path':review,'sha256':'d'*64})]:
   changed=copy.deepcopy(r);changed[k]=val
   with self.assertRaises(A.Invalid):A.bind_authoring_receipt(changed,v,review,h)

if __name__=='__main__':unittest.main()
