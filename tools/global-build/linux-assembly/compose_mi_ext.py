#!/usr/bin/env python3
"""Apply exact reviewed Global target declarations, with unchanged-node guards."""
import hashlib,json,pathlib,re,stat,xml.etree.ElementTree as ET
R=pathlib.Path(__file__).resolve().parent;TREE=R/'mi-ext-work/mi_ext';META=R/'mi-ext-metadata'
def sha(b):return hashlib.sha256(b).hexdigest()
def canonical(e):return (e.tag,tuple(sorted(e.attrib.items())),(e.text or '').strip(),tuple(canonical(c) for c in e))
def cust_nodes(b):
 root=ET.fromstring(b)
 if root.tag!='cust_features' or len(root)!=1 or root[0].tag!='cust_feature':raise ValueError('unexpected feature root')
 nodes={}
 for e in root[0]:
  key=(e.tag,e.attrib.get('name'))
  if key in nodes:raise ValueError('duplicate named feature')
  nodes[key]=canonical(e)
 return nodes

def patch_cust(original,policy):
 if sha(original)!=policy['target_file']['expected_sha256']:raise ValueError('cust source hash mismatch')
 old=cust_nodes(original);text=original.decode();adds=[]
 for c in policy['changes']:
  key=(c['type'],c['name']);token=lambda v:f'<{c["type"]} name="{c["name"]}">{v}</{c["type"]}>'
  if c['op']=='add':
   if key in old:raise ValueError('feature already present')
   adds.append('        '+token(c['value'])+'\n')
  else:
   needle=token(c['expected_donor_value'])
   if key not in old or text.count(needle)!=1:raise ValueError('feature old value/count mismatch')
   text=text.replace(needle,'' if c['op']=='remove' else token(c['value']))
 anchor='    </cust_feature>'
 if text.count(anchor)!=1:raise ValueError('feature closing block not unique')
 text=text.replace(anchor,''.join(adds)+anchor);out=text.encode();new=cust_nodes(out)
 specified={(c['type'],c['name']) for c in policy['changes']}
 changed={k for k in old.keys()|new.keys() if old.get(k)!=new.get(k)}
 if changed!=specified:raise ValueError('unexpected XML semantic changes')
 for c in policy['changes']:
  key=(c['type'],c['name'])
  if c['op']=='remove':
   if key in new:raise ValueError('removed key present')
  elif new[key][2]!=c['value']:raise ValueError('new value mismatch')
 return out,sorted(changed)

def patch_props(original,policy):
 if sha(original)!=policy['source_file_sha256']:raise ValueError('property source hash mismatch')
 text=original.decode();changed=[]
 for c in policy['operations']:
  pattern='^'+re.escape(c['key'])+'=(.*)$';found=re.findall(pattern,text,re.M)
  if found!=[c['old_value']]:raise ValueError('property old value/count mismatch')
  if c['operation']=='remove':text=re.sub('^'+re.escape(c['key'])+'=.*\n','',text,flags=re.M)
  else:text=re.sub(pattern,c['key']+'='+c['value'],text,flags=re.M)
  changed.append(c['key'])
 out=text.encode()
 if sha(out)!=policy['expected_output_sha256']:raise ValueError('reviewed property output hash mismatch')
 return out,changed

def main():
 log=META/'composition.json'
 if log.exists():raise ValueError('mi_ext already composed')
 prop_path=pathlib.Path('/workspace/shared/peridot-global-builder/builder/devices/peridot/composition/global-mi-ext-target-properties-v0.json');prop=json.loads(prop_path.read_text());cust_path=pathlib.Path('/workspace/shared/peridot-global-builder/review-cust-features/narrow-policy-v1.json');cust_data=cust_path.read_bytes()
 if sha(cust_data)!='85776d576e6b8646919a1cd1155b150e1c57068bb5cf9a4371a8e0594b5ad802':raise ValueError('cust policy changed')
 cust=json.loads(cust_data);inv=json.loads((R/'donor-mi_ext-metadata.json').read_text());files=json.loads((META/'donor-tree-files.json').read_text())['files'];expected={i['path']:dict(i) for i in inv['entries']}
 for f in files:
  path=TREE/f['path'].lstrip('/');b=path.read_bytes()
  if sha(b)!=f['sha256']:raise ValueError('mi_ext source tree changed '+f['path'])
  expected[f['path']]['sha256']=f['sha256']
 if (TREE/'etc/private/build.prop').exists() or (TREE/'private/build.prop').exists():raise ValueError('later private property input unexpectedly exists')
 updates=[]
 for name,policy,func,ref in [('/etc/build.prop',prop,patch_props,prop_path),('/product/etc/cust_features/device_features.xml',cust,patch_cust,cust_path)]:
  path=TREE/name.lstrip('/');before=path.read_bytes();after,changed=func(before,policy);updates.append((path,after,{'path':name,'before_sha256':sha(before),'after_sha256':sha(after),'reviewed_policy':str(ref),'policy_sha256':sha(ref.read_bytes()),'changed_keys':changed}))
 for path,data,rec in updates:path.write_bytes(data);expected[rec['path']].update(size=len(data),sha256=sha(data))
 entries=list(expected.values());fs=['/ 0 0 0755 capabilities=0x0'];ctx=[]
 for i in entries:
  name='mi_ext'+('' if i['path']=='/' else i['path'])
  if set(i['xattrs'])!={'security.selinux'}:raise ValueError('unsupported xattr set')
  fs.append(f"{name} {i['uid']} {i['gid']} {i['mode']&0o7777:04o} capabilities=0x0")
  ctx.append('/'+re.escape(name)+' '+bytes.fromhex(i['xattrs']['security.selinux']).decode())
 (META/'composed_fs_config').write_text('\n'.join(sorted(fs))+'\n');(META/'composed_file_contexts').write_text('\n'.join(sorted(ctx))+'\n');(META/'composed-expected.json').write_text(json.dumps({'entries':entries,'source_archive_sha256':inv['summary']['source_archive_sha256']},indent=2))
 result={'status':'reviewed_narrow_changes_applied','operations':[r for _,_,r in updates],'all_other_file_bytes_unchanged':True,'all_other_xml_nodes_semantically_unchanged':True,'private_build_prop_absent':True,'metadata_preserved':True,'runtime_hardware_thermal_RF_validation':False,'remaining_review_limitations':cust['unresolved']}
 log.write_text(json.dumps(result,indent=2));print(json.dumps(result,indent=2))
if __name__=='__main__':main()
