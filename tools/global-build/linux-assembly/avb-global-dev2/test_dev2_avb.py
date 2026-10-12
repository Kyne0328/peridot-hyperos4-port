import copy,json,pathlib,tempfile,unittest
from unittest import mock
import dev2_avb as d

class GateTests(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory(dir=d.ROOT);self.p=pathlib.Path(self.t.name);self.profile=d.checked(d.LOCK['source_profile'])
  inventory=mock.patch.object(d,'source_file_inventory',side_effect=lambda part: {'/etc/selinux/plat_pub_versioned.cil':{'sha256':'1'*64,'size':10}} if part=='vendor' else {'/system/etc/selinux/plat_sepolicy.cil':{'sha256':'7'*64,'size':10}});inventory.start();self.addCleanup(inventory.stop)
  self.semantic={'status':'PASS','expected_scope_exactly_matches_effective_removals':True,'all_other_ordinary_permissions_identical':True,'all_extended_permissions_audit_rules_transitions_constraints_labels_capabilities_permissive_state_identical':True,'normal_compile_returncode':0,'effective_added_permission_tuples':0,'effective_removed_permission_tuples':82,'existing_attribute_memberships_identical':True,'all_original_assertions_retained_byte_identically':True,'source_files':[{'before':'/captured/vendor/etc/selinux/plat_pub_versioned.cil','after':'/reviewed/vendor/etc/selinux/plat_pub_versioned.cil','before_sha256':'1'*64,'after_sha256':'2'*64}]}
  self.readback={'status':'verified','filesystem_sha256':'3'*64,'filesystem_size_bytes':4096,'all_file_bytes_sha256_verified':True,'all_uid_gid_modes_selinux_xattrs_verified':True,'all_regular_and_symlink_bytes_verified':True,'all_uid_gid_modes_labels_capability_xattrs_verified':True,'hardlink_groups_preserved':True,'files':[{'path':'/etc/selinux/plat_pub_versioned.cil','sha256':'2'*64}]}
  self.independent={'status':'PASS','static_source_composition_verified':True}
  self.approval={'schema':1,'build_id':'DEV2','partition':'vendor','status':'APPROVED_OFFLINE_VENDOR_COMPOSITION','approved_for_offline_authoring':True,'source':{'sha256':self.profile['preserved_sources']['vendor']['sha256'],'size':430030848},'filesystem':{'path':'/reviewed/vendor.erofs','size':4096,'sha256':'3'*64},'preserve_other_files_and_metadata':True,'policy_delta':{'kind':'exclusion_only','effective_added_permission_tuples':0,'effective_removed_permission_tuples':82,'existing_attribute_memberships_identical':True,'all_original_assertions_retained_byte_identically':True},'patched_files':[{'path':'/etc/selinux/plat_pub_versioned.cil','before_sha256':'1'*64,'after_sha256':'2'*64,'semantic_source_before':'/captured/vendor/etc/selinux/plat_pub_versioned.cil','semantic_source_after':'/reviewed/vendor/etc/selinux/plat_pub_versioned.cil'}]}
 def tearDown(self):self.t.cleanup()
 def reference(self,name,value):
  p=self.p/name;p.write_text(json.dumps(value));return d.ref(p)
 def receipt(self):
  evidence={}
  for name,value,status in [('independent_policy_review',self.independent,'PASS'),('semantic_policy_review',self.semantic,'PASS'),('filesystem_readback',self.readback,'verified')]:
   evidence[name]={'reference':self.reference(name+'.json',value),'assertions':[{'path':['status'],'equals':status}]}
  self.approval['evidence']=evidence;return self.reference('approval.json',self.approval)
 def check(self):return d.validate_vendor_approval(self.receipt(),self.profile)
 def test_reviewed_extended_exclusion_allowed(self):self.assertEqual(self.check()['policy_delta']['effective_removed_permission_tuples'],82)
 def test_wrong_source_denied(self):
  self.approval['source']['sha256']='0'*64
  with self.assertRaises(ValueError):self.check()
 def test_added_permissions_denied(self):
  self.approval['policy_delta']['effective_added_permission_tuples']=1;self.semantic['effective_added_permission_tuples']=1
  with self.assertRaises(ValueError):self.check()
 def test_missing_approval_denied(self):
  self.approval['approved_for_offline_authoring']=False
  with self.assertRaises(ValueError):self.check()
 def test_unreviewed_removal_count_denied(self):
  self.approval['policy_delta']['effective_removed_permission_tuples']=83
  with self.assertRaises(ValueError):self.check()
 def test_changed_existing_membership_denied(self):
  self.approval['policy_delta']['existing_attribute_memberships_identical']=False
  with self.assertRaises(ValueError):self.check()
 def test_assertion_change_denied(self):
  self.semantic['all_original_assertions_retained_byte_identically']=False
  with self.assertRaises(ValueError):self.check()
 def test_failed_independent_review_denied(self):
  self.independent['status']='FAIL'
  with self.assertRaises(ValueError):self.check()
 def test_stale_same_path_readback_denied(self):
  self.readback['filesystem_sha256']='4'*64
  with self.assertRaises(ValueError):self.check()
 def test_patch_posthash_mismatch_denied(self):
  self.readback['files'][0]['sha256']='4'*64
  with self.assertRaises(ValueError):self.check()
 def test_unaccounted_patch_denied(self):
  self.semantic['source_files'].append({'before':'/captured/x','after':'/reviewed/x','before_sha256':'4'*64,'after_sha256':'5'*64})
  with self.assertRaises(ValueError):self.check()
 def test_patch_outside_selinux_denied(self):
  self.approval['patched_files'][0]['path']='/build.prop'
  with self.assertRaises(ValueError):self.check()
 def test_reference_content_mutation_denied(self):
  r=self.receipt();pathlib.Path(r['path']).write_text('{}')
  with self.assertRaises(ValueError):d.validate_vendor_approval(r,self.profile)
 def test_blank_evidence_assertions_denied(self):
  r=self.receipt();self.approval['evidence']['independent_policy_review']['assertions']=[];r=self.reference('approval.json',self.approval)
  with self.assertRaises(ValueError):d.validate_vendor_approval(r,self.profile)
 def test_authoring_report_binds_receipt(self):
  a=self.receipt();v={'schema':2,'build_id':'DEV2','partition':'vendor','composition_review_approved':True,'filesystem_bytes_unchanged':True,'hashtree_verified':True,'approval':a,'source':self.approval['source'],'source_partition_sha256':self.approval['source']['sha256'],'composition_review':{'path':a['path'],'sha256':a['sha256']},'input_sha256':'3'*64,'input_size':4096,'output':{'path':'/signed/vendor.img','size':430030848,'sha256':'5'*64},'fec_num_roots':2,'verification_flags':0}
  r=self.reference('authored.json',v);self.assertEqual(d.validate_vendor_report(r,self.profile)['output']['sha256'],'5'*64)
  v['composition_review']['sha256']='6'*64;r=self.reference('authored.json',v)
  with self.assertRaises(ValueError):d.validate_vendor_report(r,self.profile)

class SourceMapTests(unittest.TestCase):
 def setUp(self):self.spec=d.load_spec(d.ROOT/'dev1-explicit-map.json')
 def test_dev1_explicit_reference_map_valid(self):d.validate_policy(self.spec)
 def test_original_verifier_hash_unchanged(self):d.checked(d.LOCK['dev1_verifier'],False)
 def test_metadata_reference_required(self):
  del self.spec['metadata_signing_report']
  with self.assertRaises(ValueError):d.validate_policy(self.spec)
 def test_arbitrary_vendor_override_denied(self):
  self.spec['images']['vendor']['expected_sha256']='0'*64
  with self.assertRaises(ValueError):d.validate_policy(self.spec)
 def test_dev1_cannot_add_vendor_authoring(self):
  self.spec['authored_partitions']['vendor']=d.LOCK['product_report']
  with self.assertRaises(ValueError):d.validate_policy(self.spec)
 def test_retained_product_hash_immutable(self):
  self.spec['images']['product']['expected_sha256']='0'*64
  with self.assertRaises(ValueError):d.validate_policy(self.spec)
 def test_dev2_requires_vendor_receipt(self):
  self.spec['build_id']='DEV2'
  with self.assertRaises(ValueError):d.validate_policy(self.spec)
 def test_wrong_metadata_output_hash_denied(self):
  self.spec['images']['vbmeta']['expected_sha256']='0'*64
  with self.assertRaises(ValueError):d.validate_policy(self.spec)
 def test_footer_capture_is_small_and_retains_roots(self):
  report=json.loads((d.ROOT/'captured-dev1-footers/capture-report.json').read_text());self.assertFalse(report['large_image_extraction'])
  for name,part in report['partitions'].items():
   self.assertLess(part['captured_vbmeta']['size'],4096);d.checked(part['captured_vbmeta'],False)
   trees=[x for x in part['descriptors'] if x['type']=='AvbHashtreeDescriptor'];self.assertEqual(len(trees),1);self.assertEqual(trees[0]['fec_num_roots'],2);self.assertEqual(trees[0]['flags'],0)

if __name__=='__main__':unittest.main(verbosity=2)

class JointApprovalTests(unittest.TestCase):
 reference=GateTests.reference
 def setUp(self):
  GateTests.setUp(self)
  guard=mock.patch.object(d,'validate_derived_metadata',return_value=None);guard.start();self.addCleanup(guard.stop)
  self.system_readback={'status':'verified','filesystem_sha256':'6'*64,'filesystem_size_bytes':8192,'all_file_bytes_sha256_verified':True,'all_uid_gid_modes_selinux_xattrs_verified':True,'all_regular_and_symlink_bytes_verified':True,'all_uid_gid_modes_labels_capability_xattrs_verified':True,'hardlink_groups_preserved':True,'files':[{'path':'/system/etc/selinux/plat_sepolicy.cil','sha256':'8'*64}]}
  self.semantic['source_files'].append({'before':'/captured/system/etc/selinux/plat_sepolicy.cil','after':'/reviewed/system/etc/selinux/plat_sepolicy.cil','before_sha256':'7'*64,'after_sha256':'8'*64})
  old=self.approval
  self.approval={k:old[k] for k in ['build_id','approved_for_offline_authoring','preserve_other_files_and_metadata','policy_delta']}
  self.approval.update(schema=2,status='APPROVED_OFFLINE_POLICY_COMPOSITION',sources={'vendor':old['source'],'system':{'sha256':'88142dce1788b9e105ebbc97b1945c0071fb840f827545a57c213b2e6298c32d','size':751255552}},filesystems={'vendor':old['filesystem'],'system':{'path':'/reviewed/system.erofs','sha256':'6'*64,'size':8192}},patched_files=[{'partition':'vendor',**old['patched_files'][0]},{'partition':'system','path':'/system/etc/selinux/plat_sepolicy.cil','before_sha256':'7'*64,'after_sha256':'8'*64,'semantic_source_before':'/captured/system/etc/selinux/plat_sepolicy.cil','semantic_source_after':'/reviewed/system/etc/selinux/plat_sepolicy.cil'}])
 def tearDown(self):GateTests.tearDown(self)
 def receipt(self):
  def evidence(name,value,status):return {'reference':self.reference(name+'.json',value),'assertions':[{'path':['status'],'equals':status}]}
  self.approval['evidence']={'independent_policy_review':evidence('independent',self.independent,'PASS'),'semantic_policy_review':evidence('semantic',self.semantic,'PASS'),'filesystem_readbacks':{'vendor':evidence('vendor-readback',self.readback,'verified'),'system':evidence('system-readback',self.system_readback,'verified')}}
  return self.reference('joint-approval.json',self.approval)
 def test_joint_exact_global_sources_accepted(self):
  r=self.receipt();self.assertEqual(d.validate_composition_approval(r,self.profile)['partitions'],['system','vendor']);self.assertEqual(d.validate_partition_approval(r,self.profile,'system')['filesystem']['sha256'],'6'*64)
 def test_wrong_system_source_denied(self):
  self.approval['sources']['system']['sha256']='0'*64
  with self.assertRaises(ValueError):d.validate_composition_approval(self.receipt(),self.profile)
 def test_missing_system_readback_denied(self):
  r=self.receipt();del self.approval['evidence']['filesystem_readbacks']['system'];r=self.reference('joint-approval.json',self.approval)
  with self.assertRaises(ValueError):d.validate_composition_approval(r,self.profile)
 def test_system_as_root_exact_path_required(self):
  self.approval['patched_files'][1]['path']='/etc/selinux/plat_sepolicy.cil'
  with self.assertRaises(ValueError):d.validate_composition_approval(self.receipt(),self.profile)
 def test_canonical_path_required(self):
  self.approval['patched_files'][1]['path']='/system/etc/selinux/../selinux/plat_sepolicy.cil'
  with self.assertRaises(ValueError):d.validate_composition_approval(self.receipt(),self.profile)
 def test_unaccounted_third_partition_denied(self):
  self.semantic['source_files'].append({'before':'/captured/odm/etc/selinux/odm_sepolicy.cil','after':'/reviewed/odm/etc/selinux/odm_sepolicy.cil','before_sha256':'9'*64,'after_sha256':'a'*64})
  with self.assertRaises(ValueError):d.validate_composition_approval(self.receipt(),self.profile)
 def test_third_partition_override_denied(self):
  self.approval['sources']['odm']=self.approval['sources']['vendor']
  with self.assertRaises(ValueError):d.validate_composition_approval(self.receipt(),self.profile)
 def test_mislabeled_semantic_partition_denied(self):
  self.semantic['source_files'][1]['before']='/captured/odm/etc/selinux/plat_sepolicy.cil';self.approval['patched_files'][1]['semantic_source_before']=self.semantic['source_files'][1]['before']
  with self.assertRaises(ValueError):d.validate_composition_approval(self.receipt(),self.profile)
 def test_stale_system_readback_denied(self):
  self.system_readback['filesystem_sha256']='9'*64
  with self.assertRaises(ValueError):d.validate_composition_approval(self.receipt(),self.profile)
 def test_joint_membership_change_denied(self):
  self.semantic['existing_attribute_memberships_identical']=False;self.approval['policy_delta']['existing_attribute_memberships_identical']=False
  with self.assertRaises(ValueError):d.validate_composition_approval(self.receipt(),self.profile)
 def test_system_authoring_report_does_not_relax_size(self):
  a=self.receipt();v={'schema':2,'build_id':'DEV2','partition':'system','composition_review_approved':True,'filesystem_bytes_unchanged':True,'hashtree_verified':True,'approval':a,'source':self.approval['sources']['system'],'source_partition_sha256':self.approval['sources']['system']['sha256'],'composition_review':{'path':a['path'],'sha256':a['sha256']},'input_sha256':'6'*64,'input_size':8192,'output':{'path':'/signed/system.img','size':751255552,'sha256':'b'*64},'fec_num_roots':2,'verification_flags':0}
  r=self.reference('system-authored.json',v);self.assertEqual(d.validate_authored_report(r,self.profile,'system')['output']['size'],751255552)
  v['output']['size']+=4096;r=self.reference('system-authored.json',v)
  with self.assertRaises(ValueError):d.validate_authored_report(r,self.profile,'system')
 def test_joint_approval_cannot_be_used_for_unlisted_partition(self):
  with self.assertRaises(ValueError):d.validate_partition_approval(self.receipt(),self.profile,'odm')

class JointMapTests(unittest.TestCase):
 reference=GateTests.reference
 setUp=JointApprovalTests.setUp
 tearDown=JointApprovalTests.tearDown
 receipt=JointApprovalTests.receipt
 def authored(self,partition,approval_ref,out_hash):
  a=d.validate_partition_approval(approval_ref,self.profile,partition)
  value={'schema':2,'build_id':'DEV2','partition':partition,'composition_review_approved':True,'filesystem_bytes_unchanged':True,'hashtree_verified':True,'approval':approval_ref,'source':a['source'],'source_partition_sha256':a['source']['sha256'],'composition_review':{'path':approval_ref['path'],'sha256':approval_ref['sha256']},'input_sha256':a['filesystem']['sha256'],'input_size':a['filesystem']['size'],'output':{'path':'/signed/'+partition+'.img','size':self.profile['preserved_sources'][partition]['size'],'sha256':out_hash},'fec_num_roots':2,'verification_flags':0}
  return self.reference(partition+'-authored.json',value)
 def jointmap(self,system_approval=None):
  approval=self.receipt();v=self.authored('vendor',approval,'5'*64);s=self.authored('system',system_approval or approval,'b'*64)
  spec=d.load_spec(d.ROOT/'dev1-explicit-map.json');spec['build_id']='DEV2';spec['authored_partitions'].update(vendor=v,system=s);spec['images']['vendor']['expected_sha256']='5'*64;spec['images']['system']['expected_sha256']='b'*64
  return spec
 def test_joint_reports_pin_all_changed_images(self):d.validate_policy(self.jointmap(),require_metadata=False)
 def test_joint_map_cannot_omit_system_report(self):
  spec=self.jointmap();del spec['authored_partitions']['system']
  with self.assertRaises(ValueError):d.validate_policy(spec,require_metadata=False)
 def test_joint_map_rejects_distinct_composition_receipts(self):
  first=self.receipt();second=self.reference('different-receipt.json',json.loads(pathlib.Path(first['path']).read_text()));spec=self.jointmap(second)
  with self.assertRaises(ValueError):d.validate_policy(spec,require_metadata=False)
 def test_metadata_must_pin_matching_system_report(self):
  spec=self.jointmap();meta={'schema':2,'build_id':'DEV2','source_profile':spec['source_profile'],'authored_vendor_report':spec['authored_partitions']['vendor'],'authored_system_report':spec['authored_partitions']['vendor'],'images':d.checked(d.LOCK['metadata_report'])};spec['metadata_signing_report']=self.reference('metadata.json',meta)
  with self.assertRaises(ValueError):d.validate_policy(spec)

class PreservationGateTests(unittest.TestCase):
 reference=GateTests.reference
 setUp=GateTests.setUp
 tearDown=GateTests.tearDown
 receipt=GateTests.receipt
 def test_capability_metadata_must_pass(self):
  self.readback['all_uid_gid_modes_labels_capability_xattrs_verified']=False
  with self.assertRaises(ValueError):d.validate_vendor_approval(self.receipt(),self.profile)
 def test_symlink_bytes_must_pass(self):
  self.readback['all_regular_and_symlink_bytes_verified']=False
  with self.assertRaises(ValueError):d.validate_vendor_approval(self.receipt(),self.profile)
 def test_hardlink_groups_must_pass(self):
  self.readback['hardlink_groups_preserved']=False
  with self.assertRaises(ValueError):d.validate_vendor_approval(self.receipt(),self.profile)

class DerivedDigestTests(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory(dir=d.ROOT);self.p=pathlib.Path(self.t.name);self.addCleanup(self.t.cleanup)
  p=d.ROOT.parent/'compatibility/policy-delta/cache-digest-proposal.json';self.proposal=json.loads(p.read_text())
  self.patches=[{'partition':'system','path':d.PLAT_PATH,'after_sha256':self.proposal['ordered_inputs'][0]['sha256']}]
  self.rows={'system':{'files':[{'path':x['semantic_path'],'sha256':x['sha256'],'size':x['size']} for x in self.proposal['ordered_inputs']]+[{'path':d.CACHE_PATH,'sha256':self.proposal['output_sha256'],'size':65}]}}
 def receipt(self):
  p=self.p/'derivation.json';p.write_text(json.dumps(self.proposal));return {'derived_files':[{'partition':'system','path':d.CACHE_PATH,'before_sha256':self.proposal['source_sha256'],'after_sha256':self.proposal['output_sha256'],'derivation_report':d.ref(p)}]}
 def test_exact_derived_bytes_recompute(self):d.validate_derived_metadata(self.receipt(),self.patches,self.rows)
 def test_derived_change_cannot_be_omitted(self):
  with self.assertRaises(ValueError):d.validate_derived_metadata({'derived_files':[]},self.patches,self.rows)
 def test_order_reversal_rejected(self):
  self.proposal['ordered_inputs'].reverse()
  with self.assertRaises(ValueError):d.validate_derived_metadata(self.receipt(),self.patches,self.rows)
 def test_unreviewed_mapping_rejected(self):
  self.proposal['ordered_inputs'][1]['sha256']='0'*64
  with self.assertRaises(ValueError):d.validate_derived_metadata(self.receipt(),self.patches,self.rows)
 def test_hash_self_consistency_is_insufficient(self):
  p=self.p/'bad.sha256';p.write_bytes(b'0'*64+b'\n');self.proposal['output']=str(p);self.proposal['output_sha256']=d.sha(p);self.rows['system']['files'][-1]['sha256']=d.sha(p)
  with self.assertRaises(ValueError):d.validate_derived_metadata(self.receipt(),self.patches,self.rows)
 def test_readback_hash_must_match_derived(self):
  self.rows['system']['files'][-1]['sha256']='0'*64
  with self.assertRaises(ValueError):d.validate_derived_metadata(self.receipt(),self.patches,self.rows)
 def test_only_fixed_derived_path_allowed(self):
  a=self.receipt();a['derived_files'][0]['path']='/system/etc/selinux/other.sha256'
  with self.assertRaises(ValueError):d.validate_derived_metadata(a,self.patches,self.rows)
 def test_platform_source_must_match_review(self):
  self.patches[0]['after_sha256']='0'*64
  with self.assertRaises(ValueError):d.validate_derived_metadata(self.receipt(),self.patches,self.rows)
 def test_derived_metadata_not_permitted_vendor_only(self):
  with self.assertRaises(ValueError):d.validate_derived_metadata(self.receipt(),[],{'vendor':{}})

class FrozenSourceHashTests(unittest.TestCase):
 def test_original_vendor_policy_hashes_are_pinned(self):
  rows=d.source_file_inventory('vendor');self.assertEqual(rows['/etc/selinux/plat_pub_versioned.cil']['sha256'],'0054137d674ba0e3a16711d6ee716e671f55f5313c107cb470e93fd4dfc0979d');self.assertEqual(rows['/etc/selinux/vendor_sepolicy.cil']['sha256'],'17155b0a0469706f3dd82bcdd1feec29bb9604866244e83389f2c854f223963b')
 def test_original_system_policy_hash_is_pinned(self):
  rows=d.source_file_inventory('system');self.assertEqual(rows[d.PLAT_PATH]['sha256'],'96320f4ed4f982adb0e69cf3e61a92d2677f8fc357123f2f2e3d43daa9aaff45')

class CompleteFileCoverageTests(unittest.TestCase):
 reference=GateTests.reference
 setUp=GateTests.setUp
 tearDown=GateTests.tearDown
 receipt=GateTests.receipt
 def test_wrong_before_hash_cannot_be_blessed_by_review(self):
  self.approval['patched_files'][0]['before_sha256']='4'*64;self.semantic['source_files'][0]['before_sha256']='4'*64
  with self.assertRaises(ValueError):d.validate_vendor_approval(self.receipt(),self.profile)
 def test_extra_regular_file_rejected(self):
  self.readback['files'].append({'path':'/extra','sha256':'4'*64,'size':100})
  with self.assertRaises(ValueError):d.validate_vendor_approval(self.receipt(),self.profile)

class UnrelatedPermissionGateTests(unittest.TestCase):
 reference=GateTests.reference
 setUp=GateTests.setUp
 tearDown=GateTests.tearDown
 receipt=GateTests.receipt
 def test_unrelated_ordinary_permissions_cannot_change(self):
  self.semantic['all_other_ordinary_permissions_identical']=False
  with self.assertRaises(ValueError):d.validate_vendor_approval(self.receipt(),self.profile)
 def test_unrelated_extended_permissions_cannot_change(self):
  self.semantic['all_extended_permissions_audit_rules_transitions_constraints_labels_capabilities_permissive_state_identical']=False
  with self.assertRaises(ValueError):d.validate_vendor_approval(self.receipt(),self.profile)
 def test_final_removal_scope_must_match(self):
  self.semantic['expected_scope_exactly_matches_effective_removals']=False
  with self.assertRaises(ValueError):d.validate_vendor_approval(self.receipt(),self.profile)
 def test_normal_policy_compile_must_pass(self):
  self.semantic['normal_compile_returncode']=1
  with self.assertRaises(ValueError):d.validate_vendor_approval(self.receipt(),self.profile)
 def test_independent_review_must_verify_static_composition(self):
  self.independent['static_source_composition_verified']=False
  with self.assertRaises(ValueError):d.validate_vendor_approval(self.receipt(),self.profile)
