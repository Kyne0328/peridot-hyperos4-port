#!/usr/bin/env python3
"""Build a copy-only, tuple-scoped exclusion proposal from reviewed isolation scope."""
from classify_delta import Policy,source_list,R,H,parse
from pathlib import Path
from collections import defaultdict
import hashlib,json,re,difflib,subprocess,shlex
BASE=H/'final-global-v2/inputs';OUT=R/'complete-proposal';OUT.mkdir(exist_ok=True)
m=Policy('mixed',R/'mixed-runtime-decoded.cil',source_list(H/'final-global-v2/final-selinux-init-style.status.json'))
items=json.loads((R/'donor-cross-comparison.json').read_text())['records']
scope=defaultdict(set)
for item in items:
 if item['donor_comparison']=='absent_from_full_donor' and item['category'] in ['new_mixed_access','preexisting_access_newly_reported']:
  scope[item['source'],item['target'],item['class']].update(item['permissions'])
assert sum(map(len,scope.values()))==181
scope_rows=[{'source':s,'target':t,'class':c,'permissions':sorted(p)} for (s,t,c),p in sorted(scope.items())]
(R/'complete-proposal-scope.json').write_text(json.dumps({'status':'REVIEWED_SOURCE_SCOPE_COPY_TEST_NOT_IMAGE_APPROVAL','permission_tuples':181,'PCC':59,'other_new_vs_stock_absent_donor':90,'preexisting_stock_newly_forbidden_absent_donor':32,'records':scope_rows},indent=2))
def sexpr(x):return '('+' '.join(map(sexpr,x))+')' if isinstance(x,list) else x
selectors={};names=set();selector_info=[]

def selector(symbol,excluded,label):
 excluded=frozenset(excluded);members=m.members(symbol)
 assert excluded and excluded<=members
 if excluded==members:return None
 key=(symbol,tuple(sorted(excluded)))
 if key in selectors:return selectors[key]
 name=label
 if name in names:
  ix=2
  while name+'_'+str(ix) in names:ix+=1
  name+='_'+str(ix)
 names.add(name);selectors[key]=name
 negative=sorted(excluded)
 if excluded==m.members('crosvm_domain')|{'crosvm_vu_fs'}:negative=['crosvm_domain','crosvm_vu_fs']
 expression=['and',[symbol],['not',negative]]
 assert m.expr(expression)==members-excluded
 selector_info.append({'name':name,'original_symbol':symbol,'excluded_concrete_types':sorted(excluded),'remaining_members':len(members-excluded),'expression':expression})
 return name

def source_label(src,target,cls,excluded):
 if excluded=={'pcc_component'}:return 'peridot_netdomain_without_pcc'
 if target=='vendor_vm_data_file' and cls=='lnk_file':return 'peridot_vmdata_symlink_clients'
 if target=='vendor_vm_data_file' and cls=='file':return 'peridot_vmdata_execute_clients'
 if target=='vendor_apex_metadata_file':return 'peridot_vendor_metadata_read_clients'
 if excluded=={'vendor_eid_app'}:return 'peridot_'+('secure_element' if target=='secure_element_service' else 'binder_stats')+'_clients_without_vendor_eid'
 if excluded=={'otapreopt_chroot'}:return 'peridot_'+('cgroup' if target=='cgroup_desc_file' else 'tool_exec')+'_clients_without_legacy_otapreopt'
 return 'peridot_isolation_clients'

def target_label(symbol,excluded):
 if excluded=={'vendor_vm_data_file'}:return 'peridot_vendor_types_without_vmdata'
 if excluded=={'vendor_apex_metadata_file'}:return 'peridot_vendor_configs_without_apex_metadata'
 if excluded=={'proc'}:return 'peridot_associable_filesystems_without_proc'
 if symbol=='base_typeattr_552_34_0':return 'peridot_shell_visible_services'
 return 'peridot_isolation_targets'

changes=defaultdict(dict);change_records=[]
for node,loc in m.source_allow:
 _,src,tgt,cp=node;cls,permissions=cp;ss=m.members(src);tt=None if tgt=='self' else m.members(tgt)
 per_permission={}
 for perm in permissions:
  denied=defaultdict(set)
  for (s,t,c),ps in scope.items():
   if c==cls and perm in ps and s in ss and (t==s if tt is None else t in tt):denied[t].add(s)
  per_permission[perm]=tuple(sorted((t,tuple(sorted(v))) for t,v in denied.items()))
 if not any(per_permission.values()):continue
 groups=defaultdict(list)
 for perm,denied in per_permission.items():groups[denied].append(perm)
 replacements=[]
 for denied,perms in groups.items():
  if not denied:replacements.append(['allow',src,tgt,[cls,perms]]);continue
  dm={t:set(v) for t,v in denied}
  if tt is None:
   assert all(v=={t} for t,v in dm.items());ex=set(dm);sel=selector(src,ex,source_label(src,src,cls,ex))
   if sel:replacements.append(['allow',sel,'self',[cls,perms]])
   continue
  all_exclusions=list(dm.values())
  if set(dm)==set(tt) and all(x==all_exclusions[0] for x in all_exclusions):
   ex=all_exclusions[0];sel=selector(src,ex,source_label(src,next(iter(dm)),cls,ex))
   if sel:replacements.append(['allow',sel,tgt,[cls,perms]])
   continue
  other_targets=tt-set(dm)
  if other_targets:
   target=selector(tgt,set(dm),target_label(tgt,set(dm)))
   assert target;replacements.append(['allow',src,target,[cls,perms]])
  for target,excluded in sorted(dm.items()):
   sel=selector(src,excluded,source_label(src,target,cls,excluded))
   if sel:replacements.append(['allow',sel,target,[cls,perms]])
 rendered='\n'.join(sexpr(x) for x in replacements)
 if not rendered:rendered=';; Removed a legacy allowance that violates the paired donor isolation boundary.'
 changes[loc['file']][loc['line']]=rendered
 change_records.append({'file':loc['file'],'line':loc['line'],'before':loc['expression'],'after':rendered,'restricted_permission_tuples':sum(len(v) for v in per_permission.values())})
assert len(changes)==3
records=[];diffs=[]
for path,edits in sorted(changes.items()):
 src=Path(path);rel=src.relative_to(BASE);old=src.read_text();lines=old.splitlines(True)
 for line,new in sorted(edits.items(),reverse=True):
  assert lines[line-1].strip().startswith('(allow ');lines[line-1]=new+'\n'
 new=''.join(lines)
 if rel==Path('vendor/etc/selinux/plat_pub_versioned.cil'):
  new+='\n;; Exclusion-only compatibility selectors for exact Android 17 isolation boundaries.\n'
  for info in selector_info:new+='(typeattribute '+info['name']+')\n(typeattributeset '+info['name']+' '+sexpr(info['expression'])+')\n'
 assert [x for x in old.splitlines() if x.startswith('(neverallow')]==[x for x in new.splitlines() if x.startswith('(neverallow')]
 dst=OUT/rel;dst.parent.mkdir(parents=True,exist_ok=True);dst.write_text(new)
 diffs.extend(difflib.unified_diff(old.splitlines(True),new.splitlines(True),fromfile='a/'+str(rel),tofile='b/'+str(rel)))
 records.append({'path':str(rel),'source':str(src),'output':str(dst),'source_sha256':hashlib.sha256(src.read_bytes()).hexdigest(),'output_sha256':hashlib.sha256(dst.read_bytes()).hexdigest(),'changed_original_allow_rules':len(edits),'all_assertions_byte_identical':True})
patch=''.join(diffs);(R/'complete-proposal.patch').write_text(patch);(R/'complete-proposal.json').write_text(json.dumps({'status':'COPY_ONLY_PROPOSAL_TEST_PENDING','frozen_images_modified':False,'files':records,'patch_sha256':hashlib.sha256(patch.encode()).hexdigest(),'new_selectors':selector_info,'transformations':change_records,'existing_attribute_membership_edits':False,'expected_removed_permission_tuples':181,'expected_added_permission_tuples':0},indent=2))
cmd=json.loads((H/'final-global-v2/final-selinux-init-style.status.json').read_text())['command'];substitutions={x['source']:x['output'] for x in records};cmd=[substitutions.get(x,x) for x in cmd];cmd[cmd.index('-o')+1]=str(R/'complete-proposed-runtime.policy');cmd[cmd.index('-f')+1]=str(R/'complete-proposed-runtime.contexts');(R/'complete-proposed-runtime.command.txt').write_text(shlex.join(cmd)+'\n');p=subprocess.run(cmd,capture_output=True,text=True);(R/'complete-proposed-runtime.stdout.txt').write_text(p.stdout);(R/'complete-proposed-runtime.stderr.txt').write_text(p.stderr);(R/'complete-proposed-runtime.status.json').write_text(json.dumps({'command':cmd,'returncode':p.returncode},indent=2));print('rules changed',len(change_records),'selectors',len(selector_info),'compile',p.returncode,p.stderr)
