from classify_delta import Policy,source_list,R,H
from pathlib import Path
import hashlib,json,re
before=Policy('before',R/'mixed-runtime-decoded.cil',source_list(H/'final-global-v2/final-selinux-init-style.status.json'))
after=Policy('after',R/'complete-proposed-runtime-decoded.cil',source_list(R/'complete-proposed-runtime.status.json'))
diff=json.loads((R/'complete-semantic-diff.json').read_text());assert diff['added_permission_tuples']==0 and diff['removed_permission_tuples']==181
assert before.types==after.types and before.classes==after.classes and before.alias==after.alias
assert before.attrnames<=after.attrnames
assert all(before.members(x)==after.members(x) for x in before.attrnames)
expected={(x['source'],x['target'],x['class'],p) for x in json.loads((R/'complete-proposal-scope.json').read_text())['records'] for p in x['permissions']}
removed={(x['source'],x['target'],x['class'],p) for x in diff['removed'] for p in x['permissions']}
assert removed==expected and not diff['added']
old=set((R/'mixed-runtime-decoded.cil').read_text().splitlines());new=set((R/'complete-proposed-runtime-decoded.cil').read_text().splitlines());old_other={x for x in old if x and not x.startswith('(allow ')};new_other={x for x in new if x and not x.startswith('(allow ')};extra=new_other-old_other;missing=old_other-new_other
assert not missing
added_names=after.attrnames-before.attrnames
assert len(added_names)==13
assert len(extra)==26 and all(any(x.startswith('(typeattribute '+n+')') or x.startswith('(typeattributeset '+n+' ') for n in added_names) for x in extra)
source_files=[];bs=source_list(H/'final-global-v2/final-selinux-init-style.status.json');ps=source_list(R/'complete-proposed-runtime.status.json')
for b,a in zip(bs,ps):
 ob=Path(b).read_bytes();nb=Path(a).read_bytes();oldn=[x for x in ob.splitlines() if x.startswith(b'(neverallow')];newn=[x for x in nb.splitlines() if x.startswith(b'(neverallow')];assert oldn==newn
 source_files.append({'before':b,'after':a,'before_sha256':hashlib.sha256(ob).hexdigest(),'after_sha256':hashlib.sha256(nb).hexdigest(),'all_original_assertions_retained_byte_identically':True})
report={'status':'PASS_COMPLETE_SCOPED_EXCLUSION_ONLY_SEMANTICS','kind':'exclusion_only','effective_added_permission_tuples':0,'effective_removed_permission_tuples':181,'existing_attribute_memberships_identical':True,'all_original_assertions_retained_byte_identically':True,'all_other_ordinary_permissions_identical':True,'all_extended_permissions_audit_rules_transitions_constraints_labels_capabilities_permissive_state_identical':True,'new_helper_attribute_count':13,'source_files':source_files,'expected_scope_exactly_matches_effective_removals':True,'scope_sha256':hashlib.sha256((R/'complete-proposal-scope.json').read_bytes()).hexdigest(),'removed':diff['removed'],'ordinary_allow_candidate_pairs_exhaustively_queried':diff['affected_concrete_pairs_queried'],'normal_compile_returncode':0,'strict_compile_returncode':255,'strict_failed_assertions_before':89,'strict_failed_assertions_after':77,'full_strict_pass':False,'unrelated_baseline_donor_feature_and_assertion_alias_diagnostics_remain':True,'images_modified':False,'runtime_compatibility_not_tested':True,'derived_metadata_separate':str(R/'cache-digest-proposal.json')}
(R/'complete-semantic-review.json').write_text(json.dumps(report,indent=2));print(report['status'],len(source_files),'input files',sum(x['before_sha256']!=x['after_sha256'] for x in source_files),'changed')
