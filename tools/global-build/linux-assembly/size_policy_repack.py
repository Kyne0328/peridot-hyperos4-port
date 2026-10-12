#!/usr/bin/env python3
"""Build unmodified source scratch filesystems to verify repack bounds and metadata."""
import json,pathlib,subprocess,uuid
import rebuild_policy_filesystems as P
import rebuild_vendor_dev2 as V
R=V.ROOT
for name,expected_hash in [('vendor','4790f46c46af37cd1999829944d5c4cd391ef16faef428e9265fb0e1355c73d3'),('system','f4a51c050a712cb277fad170079d7412571080903c290330f2c326d599da7ac0')]:
 P.select(name);src=V.WORK/'source-expected.json';V.require(V.digest(src)==expected_hash,'source tree manifest changed');entries=json.loads(src.read_text())['entries'];V.make_metadata(entries,name)
 for field in ['fs_config','file_contexts']:(V.WORK/('composed_'+field)).rename(V.WORK/('source_'+field))
 dest=V.WORK/'unmodified-source-sizing.erofs';V.require(not dest.exists(),'sizing output exists')
 cmd=[str(V.MKFS),'-T','1230768000','-U',str(uuid.uuid5(uuid.NAMESPACE_URL,'peridot-global-source-sizing:'+name)),'-zlz4hc,level=12','--mount-point='+('/vendor' if name=='vendor' else '/'),'--fs-config-file='+str(V.WORK/'source_fs_config'),'--file-contexts='+str(V.WORK/'source_file_contexts'),str(dest),str(V.TREE)]
 V.save(V.WORK/'source-sizing-command.json',{'purpose':'Unmodified source scratch only; not a candidate image','command':cmd,'expected_source_manifest_sha256':expected_hash})
 with (V.WORK/'source-sizing.log').open('x') as f:result=subprocess.run(cmd,stdout=f,stderr=subprocess.STDOUT)
 V.require(result.returncode==0,'source repack sizing failed');size=dest.stat().st_size
 V.save(V.WORK/'source-sizing-result.json',{'partition':name,'body_size':size,'body_sha256':V.digest(dest),'source_allocation':P.PINS[name][1],'modified_files':False,'signed_candidate':False})
 print(name,size,flush=True)
 V.verify(dest,src,V.WORK/'source-sizing-readback.json')
