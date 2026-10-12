#!/usr/bin/env python3
"""Bind the final independent source review to exact filesystem composition evidence."""
import argparse,json,pathlib
import rebuild_vendor_dev2 as V
from rebuild_policy_filesystems import PINS
R=V.ROOT;D=R/'compatibility/policy-delta';OUT=R/'policy-dev2'
REVIEW_SHA='8ca1f37bb0e407ee4d7d68bc6dd0b81bc21678de94cee09d800d34409d79898f'
SEMANTIC_SHA='9adabe6ab141e7afd820fa166fe0e36cdc5aca72936fd921d33a6cc4763009ff'
def ref(path):
 p=pathlib.Path(path);return {'path':str(p),'size':p.stat().st_size,'sha256':V.digest(p)}
def assertions(**values):return [{'path':[k],'equals':v} for k,v in values.items()]
def instruction():
 review_path=D/'independent-complete-review/review.json';semantic_path=D/'complete-semantic-review.json';V.require(V.digest(review_path)==REVIEW_SHA and V.digest(semantic_path)==SEMANTIC_SHA,'final reviewed evidence changed')
 review=json.loads(review_path.read_text());semantic=json.loads(semantic_path.read_text());V.require(review['static_source_composition_verified'] is True and review['status']=='STATIC_EXCLUSION_ONLY_COMPOSITION_VERIFIED_RUNTIME_NOT_CERTIFIED','independent acceptance missing')
 V.require(V.digest(review['patch']['path'])==review['patch']['sha256'],'reviewed patch changed')
 operations=[]
 for f in review['patch']['files']:
  partition=f['path'].split('/')[0];name='/'+f['path'] if partition=='system' else '/'+f['path'].split('/',1)[1]
  V.require(V.digest(f['before_path'])==f['before_sha256'] and V.digest(f['after_path'])==f['after_sha256'],'reviewed policy bytes changed')
  op={'partition':partition,'path':name,'before_sha256':f['before_sha256'],'after_sha256':f['after_sha256'],'reviewed_output':f['after_path']}
  if name.endswith('.cil'):op.update(semantic_source_before=f['before_path'],semantic_source_after=f['after_path'])
  operations.append(op)
 evidence={
  'independent_review':{**ref(review_path),'assertions':assertions(status=review['status'],static_source_composition_verified=True)},
  'semantic_verification':{**ref(semantic_path),'assertions':assertions(status='PASS_COMPLETE_SCOPED_EXCLUSION_ONLY_SEMANTICS',effective_added_permission_tuples=0,effective_removed_permission_tuples=181,expected_scope_exactly_matches_effective_removals=True,all_other_ordinary_permissions_identical=True)},
  'loader_verification':{**ref(D/'load-selection/summary.json'),'assertions':assertions(selection_with_packaged_files='compile_split_cil')},
  'derived_digest':{**ref(D/'cache-digest-proposal.json'),'assertions':assertions(original_algorithm_matches_published_digest=True,still_rejects_stale_precompiled=True)}}
 result={'schema':1,'build_id':'DEV2','status':'APPROVED_EXCLUSION_ONLY_COPY_FOR_REBUILD','scope':'Offline composition under the requested compatibility/security remediation; no device or runtime approval','removed_permission_tuples':181,'evidence':evidence,'operations':operations,'remaining_runtime_evidence':review['essential_remaining_evidence'],'strict_policy_all_constraints_passed':False}
 OUT.mkdir(exist_ok=True);path=OUT/'composition-instruction.json';V.save(path,result);print(json.dumps(ref(path)),flush=True)
def approve():
 m=json.loads((OUT/'composition-instruction.json').read_text());V.require(m['status']=='APPROVED_EXCLUSION_ONLY_COPY_FOR_REBUILD','wrong instruction')
 semantic=json.loads((D/'complete-semantic-review.json').read_text());V.require(V.digest(D/'complete-semantic-review.json')==SEMANTIC_SHA,'semantic report changed')
 def evidence(name):
  e=m['evidence'][name];return {'reference':{k:e[k] for k in ('path','size','sha256')},'assertions':e['assertions']}
 filesystems={};readbacks={}
 for part in ('system','vendor'):
  w=R/(part+'-dev2');f=json.loads((w/'reviewed-filesystem.json').read_text());V.require(V.digest(f['image'])==f['sha256'] and pathlib.Path(f['image']).stat().st_size==f['size'],'final pre-footer filesystem changed')
  filesystems[part]={k:f[k] for k in ('size','sha256')};filesystems[part]['path']=f['image'];readbacks[part]={'reference':ref(w/'filesystem-readback.json'),'assertions':assertions(status='verified',all_regular_and_symlink_bytes_verified=True,all_uid_gid_modes_labels_capability_xattrs_verified=True,hardlink_groups_preserved=True)}
 patched=[{k:o[k] for k in ('partition','path','before_sha256','after_sha256','semantic_source_before','semantic_source_after')} for o in m['operations'] if o['path'].endswith('.cil')]
 derived=[{**{k:o[k] for k in ('partition','path','before_sha256','after_sha256')},'derivation_report':ref(D/'cache-digest-proposal.json')} for o in m['operations'] if o['path'].endswith('.sha256')]
 result={'schema':2,'build_id':'DEV2','status':'APPROVED_OFFLINE_POLICY_COMPOSITION','approved_for_offline_authoring':True,'preserve_other_files_and_metadata':True,'preservation_scope':'All non-reviewed file bytes, symlink targets, UID/GID/modes, SELinux/capability xattrs and hardlink groups; timestamps regenerated and not claimed identical','sources':{p:{'sha256':PINS[p][0],'size':PINS[p][1]} for p in filesystems},'filesystems':filesystems,'policy_delta':{'kind':'exclusion_only',**{k:semantic[k] for k in ('effective_added_permission_tuples','effective_removed_permission_tuples','existing_attribute_memberships_identical','all_original_assertions_retained_byte_identically')}},'patched_files':patched,'derived_files':derived,'evidence':{'independent_policy_review':evidence('independent_review'),'semantic_policy_review':evidence('semantic_verification'),'filesystem_readbacks':readbacks},'composition_instruction':ref(OUT/'composition-instruction.json'),'loader_evidence':evidence('loader_verification'),'device_boot_tested':False,'runtime_limits':m['remaining_runtime_evidence'],'full_strict_policy_pass':False}
 path=OUT/'composition-approval.json';V.save(path,result);print(json.dumps(ref(path)),flush=True)
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('action',choices=['instruction','approve']);a=p.parse_args();instruction() if a.action=='instruction' else approve()
