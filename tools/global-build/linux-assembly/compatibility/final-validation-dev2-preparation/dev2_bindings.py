"""Explicit pinned exceptions for this reviewed DEV2 system/vendor composition."""
import hashlib,importlib.util,json,pathlib,struct
from final_image_reader import digest_file,Invalid,CHUNK
A=pathlib.Path('/workspace/shared/peridot-global-assembly');H=A/'compatibility'
APPROVAL_SHA='e9479eea365ef4091b1ea829ede12bc4eb411bfbf04bd0472d69bd565284d0cb'
DEV1_MAP_SHA='53436b756367ccfdef5c5cfdb10002c9247c173457c671c567c2239471bafce3'
DEV1_SUPER_SHA='66575ccfb8998539fbac2a8a12d2450445566024f89ee1d750e29e89be5094f7'

def bind(reader,root):
 d=reader.assembly
 if d.get('schema_version')!=2 or d.get('source_frozen_candidate',{}).get('sha256')!=DEV1_SUPER_SHA:raise Invalid('not the reviewed DEV2 assembly lineage')
 original_path=A/'candidate/assembly.json'
 if digest_file(original_path)!=DEV1_MAP_SHA:raise Invalid('frozen DEV1 map changed')
 old=json.loads(original_path.read_text());old_parts={x['partition']:x for x in old['inputs']}
 changed={x['partition'] for x in d['inputs'] if x['sha256']!=old_parts[x['partition']]['sha256']}
 if changed!={'system','vendor'}:raise Invalid('DEV2 may change exactly the reviewed system/vendor spans')
 validation=d.get('policy_evidence_validation',{});reference=validation.get('composition_review',{})
 if reference.get('sha256')!=APPROVAL_SHA:raise Invalid('DEV2 approval is not the exact parent-approved receipt')
 tool=pathlib.Path(validation['validator_path'])
 if tool.resolve()!=A/'avb-global-dev2/dev2_avb.py' or digest_file(tool)!=validation['validator_sha256']:raise Invalid('assembly evidence validator differs')
 spec=importlib.util.spec_from_file_location('final_dev2_approval_validator',tool);v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)
 profile=v.checked(v.LOCK['source_profile']);approval=v.validate_composition_approval(reference,profile)
 if set(approval['partitions'])!=changed:raise Invalid('reviewed partition set differs')
 receipt=approval['receipt'];authored={};records=[]
 for part in ['system','vendor']:
  item=next(x for x in d['inputs'] if x['partition']==part)
  if item.get('source_image_sha256')!=old_parts[part]['sha256'] or item.get('composition_review_sha256')!=APPROVAL_SHA:raise Invalid('explicit original/final partition binding missing')
  report_ref=v.ref(item['authoring_report'])
  if report_ref['sha256']!=item['authoring_report_sha256']:raise Invalid('authoring report differs from assembly pin')
  report=v.validate_authored_report(report_ref,profile,part)
  if not v.same_ref(report['approval'],reference) or report['output']['sha256']!=item['sha256'] or report['output']['size']!=item['size_bytes']:raise Invalid('authored output is not the actual final span')
  rb_ref=receipt['evidence']['filesystem_readbacks'][part]['reference'];rb=v.checked(rb_ref);body=approval['filesystems'][part]
  footer=reader.parts[part].read(reader.parts[part].size-64,64);magic,major,minor,size,vo,vs,res=struct.unpack('>4sIIQQQ28s',footer)
  if magic!=b'AVBf' or size!=body['size']:raise Invalid('reviewed policy filesystem footer/body mismatch')
  h=hashlib.sha256()
  for off in range(0,size,CHUNK):h.update(reader.parts[part].read(off,min(CHUNK,size-off)))
  if h.hexdigest()!=body['sha256']:raise Invalid('actual policy filesystem prefix differs from approved readback')
  authored[part]={x['path']:x for x in rb['files']};records.append({'partition':part,'original_span_sha256':item['source_image_sha256'],'actual_final_span_sha256':item['sha256'],'authoring_report':report_ref,'filesystem_readback':rb_ref,'actual_filesystem_prefix_bytes':size,'actual_filesystem_prefix_sha256':h.hexdigest()})
 result={'status':'EXACT_REVIEWED_DEV2_EXCEPTIONS_VERIFIED','approval':reference,'validator_sha256':validation['validator_sha256'],'other_six_partitions_DEV1_byte_identical':True,'authored':records,'semantic_review':receipt['evidence']['semantic_policy_review']['reference'],'independent_review':receipt['evidence']['independent_policy_review']['reference'],'no_generic_source_equality_bypass':True}
 (root/'dev2-policy-source-binding.json').write_text(json.dumps(result,indent=2))
 return authored,receipt,v

def verify_compilation(root,receipt,v):
 semantic=v.checked(receipt['evidence']['semantic_policy_review']['reference']);independent=v.checked(receipt['evidence']['independent_policy_review']['reference'])
 actual=[]
 for row in semantic['source_files']:
  before=pathlib.Path(row['before']);rel=before.relative_to(H/'final-global-v2/inputs');path=root/'inputs'/rel
  if digest_file(path)!=row['after_sha256']:raise Invalid('final compile input differs from reviewed policy source '+str(rel))
  actual.append({'path':str(path),'sha256':digest_file(path)})
 if len(actual)!=11:raise Invalid('normal loader must select exactly eleven reviewed CIL inputs')
 expected=independent['control_artifacts']['proposal']['binary_sha256'];got=digest_file(root/'compiled-policy-offline-only')
 if got!=expected:raise Invalid('fresh final compiled policy differs from independently reviewed binary')
 vendor=root/'inputs/vendor/etc/selinux';system=root/'inputs/system/etc/selinux'
 if (vendor/'genfs_labels_version.txt').exists() or (system/'plat_sepolicy_genfs_202404.cil').exists():raise Invalid('packaged genfs selection differs from reviewed default')
 if (vendor/'plat_sepolicy_vers.txt').read_text().splitlines()[0]!='34.0':raise Invalid('vendor mapping version differs')
 recomputed=hashlib.sha256((system/'plat_sepolicy.cil').read_bytes()+(system/'mapping/202604.cil').read_bytes()).hexdigest()+'\n'
 if (system/'plat_sepolicy_and_mapping.sha256').read_bytes()!=recomputed.encode('ascii'):raise Invalid('final derived cache metadata is not accurate')
 pairs=[]
 for part,label in [('system','plat'),('system_ext','system_ext'),('product','product')]:
  framework=(root/f'inputs/{part}/etc/selinux/{label}_sepolicy_and_mapping.sha256').read_bytes();precompiled=(root/f'inputs/odm/etc/selinux/precompiled_sepolicy.{label}_sepolicy_and_mapping.sha256').read_bytes()
  f=framework.split(b'\n',1)[0];p=precompiled.split(b'\n',1)[0];pairs.append({'partition':part,'framework_first_line':f.decode(),'precompiled_first_line':p.decode(),'match':f==p,'framework_bytes_sha256':hashlib.sha256(framework).hexdigest(),'precompiled_bytes_sha256':hashlib.sha256(precompiled).hexdigest()})
 if any(x['match'] for x in pairs):raise Invalid('cache comparison changed from reviewed all-mismatch outcome')
 report={'status':'FRESH_REVIEWED_POLICY_BINARY_REPRODUCED','compiled_policy_sha256':got,'source_files':actual,'exact_normal_input_count':11,'vendor_mapping_version':'34.0','absent_vendor_genfs_version_defaults_to':202404,'absent_genfs_202404_cil_not_appended':True,'full_donor_202504_control_not_used':True,'normal_loader_flags':['-m','-M','true','-G','-N','-v','-c','30'],'metadata_derived_from_actual_final_bytes':True,'actual_packaged_sidecar_first_line_comparisons':pairs,'strict_policy_pass_claimed':False}
 (root/'fresh-semantic-loader-input-proof.json').write_text(json.dumps(report,indent=2))
 return report
