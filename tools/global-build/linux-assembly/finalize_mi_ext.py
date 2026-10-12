#!/usr/bin/env python3
"""Apply the stable, guard-checked final mi_ext XML amendments to a staged tree."""
import hashlib,json,pathlib,re,xml.etree.ElementTree as ET
from compose_mi_ext import R,TREE,META,cust_nodes
POLICY=pathlib.Path('/workspace/shared/peridot-global-builder/review-cust-features/final-manifest-v2.json')
POLICY_SHA='45c529274697bdadde9c41e56434704b9cea0f67ac8d71571c12e57d6e1d7575'
SCAN=pathlib.Path('/workspace/shared/peridot-global-builder/review-cust-features/final-guard-scan.json')
SCAN_SHA='ed65876a802e9e093296d8b4f910fa97d845b8d294eda53793cc8173b9268017'
def sha(b):return hashlib.sha256(b).hexdigest()
def main():
 approval=META/'ramdisk-guard-reviewed.json'
 if not approval.exists():raise ValueError('explicit reviewed ramdisk guard is required')
 guard=json.loads(approval.read_text())
 if guard.get('status')!='passed_packaged_input_guard' or guard.get('on_device_values_verified') is not False:raise ValueError('invalid ramdisk guard qualification')
 evidence=pathlib.Path(guard['source_report'])
 if sha(evidence.read_bytes())!=guard['source_report_sha256']:raise ValueError('ramdisk source report changed')
 raw=POLICY.read_bytes()
 if sha(raw)!=POLICY_SHA or sha(SCAN.read_bytes())!=SCAN_SHA:raise ValueError('reviewed guard/policy identity changed')
 policy=json.loads(raw);scan=json.loads(SCAN.read_text())
 if not scan['xml_scope_complete'] or scan['missing_paths'] or scan['xml_errors'] or scan['additional_declarations_outside_planned_removals'] or not scan['euicc_guard_pass']:raise ValueError('incomplete feature guard')
 report_path=META/'final-amendment.json'
 if report_path.exists():raise ValueError('amendment already applied')
 ep=META/'composed-expected.json';expected=json.loads(ep.read_text());entries={i['path']:i for i in expected['entries']};updates=[]
 allowed={'/product/etc/cust_features/device_features.xml','/product/etc/cust_features/cust_features.xml','/product/etc/sysconfig/android.hardware.telephony.euicc.xml','/product/etc/sysconfig/android.hardware.telephony.euicc.mep.xml'}
 if {c['path'] for c in policy['changes']}!=allowed:raise ValueError('unreviewed path set')
 for change in policy['changes']:
  name=change['path'];dest=TREE/name.lstrip('/');before=dest.read_bytes();h=sha(before)
  if change.get('action')=='replace_file_content_in_composed_output':
   permitted={change['source_preimage_sha256']}
   if name.endswith('/device_features.xml'):permitted.add('dae14136e3a12a1186d42d982ad6b0aa24656549acff3054297f80d0fd99d351')
   if h not in permitted:raise ValueError('XML preimage mismatch '+name)
   after=pathlib.Path(change['candidate_path']).read_bytes()
   if sha(after)!=change['expected_output_sha256']:raise ValueError('candidate hash mismatch')
   old,new=cust_nodes(before),cust_nodes(after);diff={k[1] for k in old.keys()|new.keys() if old.get(k)!=new.get(k)}
   required={'turbosched_check_is_special_topology'} if h=='dae14136e3a12a1186d42d982ad6b0aa24656549acff3054297f80d0fd99d351' or name.endswith('/cust_features.xml') else set(change['changed_keys_only'])
   if diff!=required:raise ValueError('unexpected XML semantic changes '+str(diff))
   updates.append((dest,after,{'path':name,'before_sha256':h,'after_sha256':sha(after),'changed_keys':sorted(diff)}))
  else:
   if h!=change['expected_sha256']:raise ValueError('declaration removal preimage mismatch')
   updates.append((dest,None,{'path':name,'before_sha256':h,'action':'remove_unsupported_target_feature_declaration'}))
 for dest,data,rec in updates:
  if data is None:dest.unlink();entries.pop(rec['path'])
  else:dest.write_bytes(data);entries[rec['path']].update(size=len(data),sha256=sha(data))
 expected['entries']=list(entries.values());expected['status']='final_reviewed_mi_ext_composition';ep.write_text(json.dumps(expected,indent=2));fs=['/ 0 0 0755 capabilities=0x0'];ctx=[]
 for i in entries.values():
  name='mi_ext'+('' if i['path']=='/' else i['path']);fs.append(f"{name} {i['uid']} {i['gid']} {i['mode']&0o7777:04o} capabilities=0x0");ctx.append('/'+re.escape(name)+' '+bytes.fromhex(i['xattrs']['security.selinux']).decode())
 (META/'composed_fs_config').write_text('\n'.join(sorted(fs))+'\n');(META/'composed_file_contexts').write_text('\n'.join(sorted(ctx))+'\n')
 result={'status':'applied_after_packaged_input_guards','manifest':str(POLICY),'manifest_sha256':POLICY_SHA,'xml_guard_scan':str(SCAN),'xml_guard_sha256':SCAN_SHA,'ramdisk_guard':str(approval),'changes':[rec for _,_,rec in updates],'entries':len(entries),'no_on_device_behavior_claim':True,'untraced_donor_hardware_configuration_differences':policy['unchanged_unverified_gates'],'runtime_gates':policy['runtime_gates']}
 report_path.write_text(json.dumps(result,indent=2));print(json.dumps(result,indent=2))
if __name__=='__main__':main()
