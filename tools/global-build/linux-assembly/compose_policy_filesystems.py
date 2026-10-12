#!/usr/bin/env python3
"""Apply an immutable reviewed four-file policy change and rebuild two scratch EROFS images."""
import argparse,copy,hashlib,json,os,pathlib,shutil,stat,subprocess,sys,uuid
import rebuild_vendor_dev2 as V
import rebuild_policy_filesystems as P
ROOT=V.ROOT
SOURCE_MANIFESTS={'vendor':'4790f46c46af37cd1999829944d5c4cd391ef16faef428e9265fb0e1355c73d3','system':'f4a51c050a712cb277fad170079d7412571080903c290330f2c326d599da7ac0'}
ALLOWED={('vendor','/etc/selinux/plat_pub_versioned.cil'),('vendor','/etc/selinux/vendor_sepolicy.cil'),('system','/system/etc/selinux/plat_sepolicy.cil'),('system','/system/etc/selinux/plat_sepolicy_and_mapping.sha256')}
def tree_check(tree,entries):
 expected={i['path']:i for i in entries};V.require(len(expected)==len(entries),'duplicate expected paths')
 actual={'/'}
 for base,dirs,files in os.walk(tree,followlinks=False):
  for name in dirs+files:actual.add('/'+str((pathlib.Path(base)/name).relative_to(tree)))
 V.require(actual==set(expected),'host tree path set changed')
 for name,i in expected.items():
  p=V.safe_path(tree,name);s=p.lstat();V.require(stat.S_IFMT(s.st_mode)==stat.S_IFMT(i['mode']),'host file type differs '+name)
  if stat.S_ISREG(s.st_mode):V.require(s.st_size==i['size'] and V.digest(p)==i['sha256'],'host bytes differ '+name)
  elif stat.S_ISLNK(s.st_mode):V.require(os.readlink(p)==i['symlink_target'],'host symlink differs '+name)
  else:V.require(stat.S_ISDIR(s.st_mode),'unsupported inode type')
def checked_json(reference):
 p=pathlib.Path(reference['path']);V.require(p.stat().st_size==reference['size'] and V.digest(p)==reference['sha256'],'evidence identity changed')
 x=json.loads(p.read_text())
 V.require(isinstance(reference['assertions'],list) and reference['assertions'],'successful review assertions required')
 for assertion in reference['assertions']:
  y=x
  for key in assertion['path']:y=y[key]
  V.require(y==assertion['equals'],'review assertion failed')
 return x
def main(manifest,expected_sha):
 manifest=pathlib.Path(manifest);V.require(V.digest(manifest)==expected_sha,'composition instruction hash changed');m=json.loads(manifest.read_text())
 V.require(m['status']=='APPROVED_EXCLUSION_ONLY_COPY_FOR_REBUILD' and m['build_id']=='DEV2','composition not approved')
 V.require(set(m['evidence'])=={'independent_review','semantic_verification','loader_verification','derived_digest'},'incomplete final review evidence')
 evidence={k:checked_json(v) for k,v in m['evidence'].items()}
 semantic=evidence['semantic_verification']
 for key,value in [('effective_added_permission_tuples',0),('existing_attribute_memberships_identical',True),('all_original_assertions_retained_byte_identically',True)]:V.require(semantic[key]==value,'semantic exclusion gate failed')
 V.require(semantic['effective_removed_permission_tuples']==m['removed_permission_tuples']>0,'semantic removal count mismatch')
 ops=m['operations'];V.require(len(ops)==len(ALLOWED) and {(i['partition'],i['path']) for i in ops}==ALLOWED,'wrong or duplicate mutation scope')
 changed={(i['before'],i['after']):(i['before_sha256'],i['after_sha256']) for i in semantic['source_files'] if i['before_sha256']!=i['after_sha256']}
 planned={(i['semantic_source_before'],i['semantic_source_after']):(i['before_sha256'],i['after_sha256']) for i in ops if i['path'].endswith('.cil')}
 V.require(changed==planned and len(planned)==3,'CIL mutations differ from complete semantic review')
 expected={};prepared=[]
 for partition,sha in SOURCE_MANIFESTS.items():
  work=ROOT/(partition+'-dev2');p=work/'source-expected.json';V.require(V.digest(p)==sha,'source expectation changed');expected[partition]=json.loads(p.read_text());tree_check(work/'tree',expected[partition]['entries'])
  for name in ['composition.json','composed-expected.json','mkfs-command.json','mkfs.log','fsck.log','filesystem-readback.json','reviewed-filesystem.json','reviewed-filesystem.erofs']:
   V.require(not (work/name).exists(),'existing composition state requires explicit inspection, not blind retry: '+str(work/name))
 V.require(shutil.disk_usage(ROOT).free>3*1024**3,'insufficient conservative two-filesystem scratch budget')
 for op in ops:
  partition=op['partition'];rows={i['path']:i for i in expected[partition]['entries']};i=rows[op['path']]
  V.require(stat.S_ISREG(i['mode']) and i['sha256']==op['before_sha256'],'preimage differs from exact source')
  p=pathlib.Path(op['reviewed_output']);V.require(not p.is_symlink() and p.is_file(),'reviewed output must be regular');data=p.read_bytes();V.require(V.sha(data)==op['after_sha256'] and op['after_sha256']!=op['before_sha256'],'reviewed postimage changed')
  target=V.safe_path(ROOT/(partition+'-dev2')/'tree',op['path']);V.require(stat.S_ISREG(target.lstat().st_mode),'target changed inode type');prepared.append((partition,target,data,op))
 by_path={(partition,op['path']):data for partition,target,data,op in prepared}
 mapping=(ROOT/'system-dev2/tree/system/etc/selinux/mapping/202604.cil').read_bytes()
 expected_digest=hashlib.sha256(by_path['system','/system/etc/selinux/plat_sepolicy.cil']+mapping).hexdigest().encode()+b'\n'
 V.require(by_path['system','/system/etc/selinux/plat_sepolicy_and_mapping.sha256']==expected_digest,'derived policy digest does not match exact ordered inputs')
 # Every precondition is checked before the first tree mutation.
 for partition,target,data,op in prepared:
  temp=target.with_name(target.name+'.dev2-new');V.require(not temp.exists(),'unexpected patch staging file')
  with temp.open('xb') as f:f.write(data);f.flush();os.fsync(f.fileno())
  os.replace(temp,target);entry=next(i for i in expected[partition]['entries'] if i['path']==op['path']);entry['size']=len(data);entry['sha256']=op['after_sha256']
 for partition in sorted(expected):
  P.select(partition);tree_check(V.TREE,expected[partition]['entries']);V.make_metadata(expected[partition]['entries'],partition)
  exp=V.WORK/'composed-expected.json';V.save(exp,expected[partition]);V.save(V.WORK/'composition.json',{'instruction':{'path':str(manifest),'sha256':expected_sha},'operations':[o for o in ops if o['partition']==partition],'all_other_file_bytes_and_metadata_unchanged':True,'timestamp_identity_claimed':False})
  image=V.WORK/'reviewed-filesystem.erofs';V.require(not image.exists(),'refuse filesystem overwrite')
  cmd=[str(V.MKFS),'-T','1230768000','-U',str(uuid.uuid5(uuid.NAMESPACE_URL,'peridot-global-dev2:'+partition+':'+expected_sha)),'-zlz4hc,level=12','--mount-point='+('/vendor' if partition=='vendor' else '/'),'--fs-config-file='+str(V.WORK/'composed_fs_config'),'--file-contexts='+str(V.WORK/'composed_file_contexts'),str(image),str(V.TREE)]
  V.save(V.WORK/'mkfs-command.json',{'command':cmd,'composition_instruction_sha256':expected_sha})
  with (V.WORK/'mkfs.log').open('x') as log:r=subprocess.run(cmd,stdout=log,stderr=subprocess.STDOUT)
  V.require(r.returncode==0,'mkfs failed')
  with (V.WORK/'fsck.log').open('x') as log:r=subprocess.run([str(V.MKFS.parent/'fsck.erofs'),str(image)],stdout=log,stderr=subprocess.STDOUT)
  V.require(r.returncode==0,'official fsck failed')
  result=V.verify(image,exp,V.WORK/'filesystem-readback.json')
  sys.path.insert(0,str(ROOT/'avb-global'));import global_avb as G
  sizing=G.command(['add_hashtree_footer','--partition_size',P.PINS[partition][1],'--hash_algorithm','sha256','--block_size',4096,'--fec_num_roots',2,'--calc_max_image_size'])
  V.require(result['filesystem_size_bytes']<=int(sizing['stdout'].strip()),'reviewed filesystem exceeds source allocation')
  V.save(V.WORK/'reviewed-filesystem.json',{'partition':partition,'image':str(image),'size':result['filesystem_size_bytes'],'sha256':result['filesystem_sha256'],'source_allocation':P.PINS[partition][1],'official_avb_sizing':sizing,'readback_report_sha256':V.digest(V.WORK/'filesystem-readback.json'),'signed':False})
  print(partition,'reviewed filesystem verified',result['filesystem_sha256'],flush=True)
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--manifest',required=True);p.add_argument('--sha256',required=True);a=p.parse_args();main(a.manifest,a.sha256)
