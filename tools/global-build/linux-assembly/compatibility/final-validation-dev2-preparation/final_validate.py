#!/usr/bin/env python3
"""Final exact-image offline validation. Requires completed super and boot artifacts.

The program reads final images, writes only a fresh report/scratch directory,
and runs official HOST tools. It never executes ROM binaries or contacts a device.
"""
import argparse,ast,collections,gzip,hashlib,json,os,pathlib,re,shlex,shutil,stat,struct,subprocess,sys,xml.etree.ElementTree as ET,zipfile
from final_image_reader import SuperReader,FinalErofs,digest_file,Invalid,CHUNK
from dev2_bindings import bind as bind_dev2,verify_compilation
from loader_readback import check as check_loader
A=pathlib.Path('/workspace/shared/peridot-global-assembly');H=A/'compatibility';TOOLS=pathlib.Path('/workspace/shared/peridot-cloud/tools/otatools-minimal');CHECK=pathlib.Path('/workspace/shared/peridot-cloud/tools/checkvintf');SIGN=A/'avb-global/calibration-signing';REVIEW=pathlib.Path('/workspace/shared/peridot-global-builder/review-product')
# Reuse only the pure binary XML parser, never the old source-audit entrypoint.
module=ast.parse((H/'check_packages.py').read_text());ns={'struct':struct};node=next(x for x in module.body if isinstance(x,ast.FunctionDef) and x.name=='parse');exec(compile(ast.Module(body=[node],type_ignores=[]),'audited-binary-xml-parser','exec'),ns);parse_xml=ns['parse']

def write(path,obj):path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(obj,indent=2)+'\n')
def run(root,name,cmd,env=None):
 cmd=list(map(str,cmd));(root/(name+'.command.txt')).write_text(shlex.join(cmd)+'\n');p=subprocess.run(cmd,capture_output=True,text=True,env=env);(root/(name+'.stdout.txt')).write_text(p.stdout);(root/(name+'.stderr.txt')).write_text(p.stderr);r={'name':name,'command':cmd,'returncode':p.returncode};write(root/(name+'.status.json'),r);print(name,p.returncode,flush=True);return r

def bind_authored(reader,part,readback_path,filesystem_hash_path,out):
 rb=json.loads(readback_path.read_text())
 if rb.get('status')!='verified' or not rb.get('all_file_bytes_sha256_verified') or not rb.get('all_uid_gid_modes_selinux_xattrs_verified'):raise Invalid('incomplete authored readback '+part)
 footer=reader.parts[part].read(reader.parts[part].size-64,64);magic,major,minor,original,vo,vs,reserved=struct.unpack('>4sIIQQQ28s',footer)
 if magic!=b'AVBf' or not 0<original<reader.parts[part].size:raise Invalid('authored AVB footer invalid '+part)
 h=hashlib.sha256()
 for off in range(0,original,CHUNK):h.update(reader.parts[part].read(off,min(CHUNK,original-off)))
 expected=filesystem_hash_path.read_text().split()[0]
 if h.hexdigest()!=expected:raise Invalid('authored filesystem prefix differs from readback hash '+part)
 rec={'partition':part,'readback_report':str(readback_path),'readback_report_sha256':digest_file(readback_path),'filesystem_hash_record':str(filesystem_hash_path),'filesystem_hash_record_sha256':digest_file(filesystem_hash_path),'filesystem_prefix_bytes':original,'filesystem_prefix_sha256':expected,'prefix_read_directly_from_final_super':True,'file_manifest_entries':len(rb['files'])};write(out/(part+'-authored-binding.json'),rec);return {x['path']:x for x in rb['files']}

def extract_kernel(boot,root):
 expected='e7be9c65e3e6f0af17572a3fa37d43c4e4031d28f391ed17fc625e383c33bf03'
 if digest_file(boot)!=expected:raise Invalid('final boot image differs from exact stock base')
 dst=root/'kernel-extract';dst.mkdir();res=run(root,'unpack-final-stock-boot',[TOOLS/'bin/unpack_bootimg','--boot_img',boot,'--out',dst])
 if res['returncode']:raise Invalid('official boot unpack failed')
 k=dst/'kernel';b=k.read_bytes();start=b.find(b'IKCFG_ST');end=b.find(b'IKCFG_ED',start)
 if not 0<start<end:raise Invalid('embedded stock kernel config not found')
 cfg=gzip.decompress(b[start+8:end]);version=re.search(rb'Linux version (\S+)',b).group(1).decode();(root/'stock-kernel.config').write_bytes(cfg);(root/'stock-kernel-release.txt').write_text(version+'\n');write(root/'kernel-provenance.json',{'boot_image':str(boot),'boot_image_sha256':expected,'kernel_sha256':hashlib.sha256(b).hexdigest(),'kernel_release':version,'config_sha256':hashlib.sha256(cfg).hexdigest(),'config_bytes':len(cfg),'IKCFG_ST':start,'IKCFG_ED':end,'genuine_embedded_config':True});shutil.rmtree(dst)

def main(a):
 root=pathlib.Path(a.output).resolve()
 if root.exists():raise Invalid('final validation output must be fresh')
 root.mkdir(parents=True);write(root/'STATUS.json',{'status':'RUNNING_NO_FINAL_VERDICT','assembly':a.assembly})
 evidence_paths=[pathlib.Path(x) for x in [a.product_readback,a.product_filesystem_hash,a.mi_ext_readback,a.mi_ext_filesystem_hash,a.signer_report,a.idmap_report]]
 evidence_hashes={str(p):digest_file(p) for p in evidence_paths}
 reader=SuperReader(a.assembly)
 if reader.assembly['super_sha256']!='04842fd6988f96e6e9784adab37d71ec1602ffe35a966f7043658fb84feefd9b':raise Invalid('not the explicitly frozen DEV2 super')
 policy_authored,policy_receipt,policy_validator=bind_dev2(reader,root)
 known={x['partition']:x['source_partition_sha256'] for x in json.loads((H/'input-provenance.json').read_text())['inputs']}
 for rec in reader.records:
  if rec['partition'] in ['system_ext','odm'] and rec['sha256']!=known[rec['partition']]:raise Invalid('unmodified source partition differs from pinned exact Global source '+rec['partition'])
 for path,rec in json.loads((H/'host-tools-verification.json').read_text()).items():
  if digest_file(path)!=rec['sha256']:raise Invalid('validated host tool changed '+path)
 write(root/'final-super-binding.json',{'assembly':str(reader.assembly_path),'assembly_sha256':reader.assembly_hash,'super_path':str(reader.path),'super_sha256':reader.assembly['super_sha256'],'super_bytes':reader.assembly['super_size_bytes'],'partitions':reader.records,'actual_LP_metadata_verified':True})
 authored={part:bind_authored(reader,part,pathlib.Path(rb),pathlib.Path(h),root) for part,rb,h in [('product',a.product_readback,a.product_filesystem_hash),('mi_ext',a.mi_ext_readback,a.mi_ext_filesystem_hash)]}
 authored.update(policy_authored)
 inventories={};erofs={};inputs=[]
 for part in ['system','system_ext','product','vendor','odm','mi_ext']:
  e=FinalErofs(reader,part);erofs[part]=e;rows=e.inventory();inventories[part]=rows;write(root/(part+'-final-inventory.json'),rows)
  if part in authored:
   actual_files={x['path'] for x in rows if stat.S_ISREG(x['mode'])}
   if actual_files!=set(authored[part]):raise Invalid('authored final file-path set mismatch '+part)
  for row in rows:
   if not stat.S_ISREG(row['mode']):continue
   path=row['path'];logical=path[len('/system'):] if part=='system' and path.startswith('/system/') else path
   selected=('/etc/vintf/' in logical or '/etc/selinux/' in logical or logical in ['/build.prop','/etc/build.prop'])
   if not selected:continue
   if part=='mi_ext' and ('/etc/vintf/' in logical or '/etc/selinux/' in logical):raise Invalid('mi_ext changes effective VINTF/SELinux view; explicit layer handling required')
   data=e.file_bytes(row);sha=hashlib.sha256(data).hexdigest()
   if part in authored and authored[part][path]['sha256']!=sha:raise Invalid('authored selected file content mismatch '+path)
   dst=root/'inputs'/part/logical.lstrip('/');dst.parent.mkdir(parents=True,exist_ok=True);dst.write_bytes(data);inputs.append({'partition':part,'image_path':path,'output':str(dst.relative_to(root)),'sha256':sha,'bytes':len(data),'from_verified_final_super':True})
  print(part,'final files inventoried; compatibility metadata extracted',flush=True)
 write(root/'final-input-provenance.json',inputs)
 # Fresh official host APEX validation, directly from final partition bytes.
 scratch=root/'apex-scratch';scratch.mkdir();tmp=scratch/'tmp';tmp.mkdir();apexout=root/'apex-metadata';apexout.mkdir();logs=root/'apex-logs';logs.mkdir();env=os.environ.copy();env['TMPDIR']=str(tmp);apexrows=[];elements=[];names=set();nested_apks=[];nested_errors=[];nested_empty=[]
 for part in ['system','system_ext','product','vendor','odm']:
  for row in inventories[part]:
   if '/apex/' not in row['path'] or not stat.S_ISREG(row['mode']):continue
   data=erofs[part].file_bytes(row);sha=hashlib.sha256(data).hexdigest();stage=scratch/part/'apex';stage.mkdir(parents=True,exist_ok=True);apk=stage/pathlib.Path(row['path']).name;apk.write_bytes(data);del data
   if part in authored and authored[part][row['path']]['sha256']!=sha:raise Invalid('authored APEX hash mismatch')
   inf=subprocess.run([str(TOOLS/'bin/deapexer'),'info',str(apk)],capture_output=True,text=True)
   if inf.returncode:raise Invalid('deapexer info failed '+row['path']+inf.stderr)
   info=json.loads(inf.stdout);name=info['name']
   if name in names or not re.fullmatch('[a-zA-Z0-9_.-]+',name):raise Invalid('duplicate or unsafe APEX identity')
   names.add(name);act=scratch/'activated';act.mkdir();res=run(logs,name,[TOOLS/'bin/apexd_host','--tool_path',TOOLS,'--apex_path',act,f'--{part}_path',scratch/part],env)
   if res['returncode']:raise Invalid('official final APEX extraction failed '+name)
   raw=(act/'apex-info-list.xml').read_bytes();(logs/(name+'.apex-info-list.xml')).write_bytes(raw);entries=ET.fromstring(raw).findall('apex-info')
   if len(entries)!=1 or entries[0].get('moduleName')!=name:raise Invalid('APEX generated entry mismatch')
   elements.append(entries[0]);mod=act/name;dest=apexout/name;dest.mkdir();retained=[]
   for f in mod.rglob('*'):
    if f.is_file() and not f.is_symlink() and (str(f.relative_to(mod)).startswith('etc/vintf/') or f.name in ['apex_manifest.json','apex_manifest.pb']):
     d=dest/f.relative_to(mod);d.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(f,d);retained.append({'path':str(d.relative_to(root)),'sha256':digest_file(d)})
   for f in mod.rglob('*.apk'):
    if not f.is_file() or f.is_symlink():continue
    rel=str(f.relative_to(mod));rec={'partition':part,'apex_module':name,'payload_path':rel,'bytes':f.stat().st_size,'container_sha256':sha,'path_classification':'apex_app_directory' if pathlib.PurePosixPath(rel).parts[0] in ['app','priv-app'] else 'other_apex_payload_path'}
    if not f.stat().st_size:nested_empty.append(rec);continue
    try:
     with zipfile.ZipFile(f) as z:b=z.read('AndroidManifest.xml');nodes=parse_xml(b);abis=sorted({x.split('/')[1] for x in z.namelist() if x.startswith('lib/') and x.count('/')>=2})
     rec.update(sha256=digest_file(f),manifest_sha256=hashlib.sha256(b).hexdigest(),nodes=nodes,native_abis=abis,manifest=next(x['attributes'] for x in nodes if x['tag']=='manifest'),sdk=next((x['attributes'] for x in nodes if x['tag']=='uses-sdk'),{}));nested_apks.append(rec)
     md=root/'apex-apk-manifests'/name/rel;md.parent.mkdir(parents=True,exist_ok=True);md.with_suffix('.AndroidManifest.xml.bin').write_bytes(b)
    except Exception as ex:rec['error']=str(ex);nested_errors.append(rec)
   apexrows.append({'partition':part,'image_path':row['path'],'bytes':row['size'],'sha256':sha,'manifest':info,'host_generated_entry':entries[0].attrib,'host_extraction_returncode':0,'retained_files':retained,'from_verified_final_super':True});write(root/'final-apex-report.json',apexrows);shutil.rmtree(act);apk.unlink()
 doc=ET.Element('apex-info-list')
 for el in elements:doc.append(el)
 ET.indent(doc);ET.ElementTree(doc).write(apexout/'apex-info-list.xml',encoding='utf-8',xml_declaration=True);shutil.rmtree(scratch)
 write(root/'nested-apex-apk-packages.json',nested_apks);write(root/'nested-apex-apk-errors.json',nested_errors);write(root/'nested-apex-empty-apks.json',nested_empty)
 # Actual kernel, VINTF and normal policy compiler rerun follow final byte binding.
 extract_kernel(pathlib.Path(a.boot_image).resolve(),root);I=root/'inputs';cmd=[CHECK,'--check-compat']
 for part in ['system','system_ext','product','vendor','odm']:cmd+=['--dirmap',f'/{part}:{I/part}']
 cmd+=['--dirmap',f'/apex:{apexout}','--property','ro.boot.product.vendor.sku=cliffs','--property','ro.boot.product.hardware.sku=peridot','--property','ro.product.first_api_level=34','--kernel',f'{root}/stock-kernel-release.txt:{root}/stock-kernel.config'];vintf=run(root,'final-vintf-with-stock-kernel',cmd)
 se=I/'system/etc/selinux';xe=I/'system_ext/etc/selinux';pe=I/'product/etc/selinux';ve=I/'vendor/etc/selinux';oe=I/'odm/etc/selinux';vers=(ve/'plat_sepolicy_vers.txt').read_text().strip()
 if vers!='34.0':raise Invalid('vendor policy version changed')
 files=[se/'plat_sepolicy.cil',se/f'mapping/{vers}.cil',se/f'mapping/{vers}.compat.cil',xe/'system_ext_sepolicy.cil',xe/f'mapping/{vers}.cil',xe/f'mapping/{vers}.compat.cil',pe/'product_sepolicy.cil',pe/f'mapping/{vers}.cil',ve/'plat_pub_versioned.cil',ve/'vendor_sepolicy.cil',oe/'odm_sepolicy.cil']
 if not all(p.is_file() for p in files):raise Invalid('expected normal compilation input missing')
 policy=run(root,'final-selinux-init-style',[H/'secilc',files[0],'-m','-M','true','-G','-N','-v','-c','30','-o',root/'compiled-policy-offline-only','-f',root/'compiled-contexts-offline-only',*files[1:]])
 semantic_proof=verify_compilation(root,policy_receipt,policy_validator)
 loader_proof=check_loader(root,erofs,inventories,pathlib.Path(a.init_boot_image),run)
 strict_cmd=[x for x in policy['command'] if x!='-N'];strict_cmd[strict_cmd.index('-o')+1]=str(root/'strict-policy-not-accepted');strict_cmd[strict_cmd.index('-f')+1]=str(root/'strict-contexts-not-accepted');strict_result=run(root,'final-strict-policy-diagnostic',strict_cmd)
 strict_count=(root/'final-strict-policy-diagnostic.stderr.txt').read_text().count('neverallow check failed')
 if strict_result['returncode']!=255 or strict_count!=77:raise Invalid('final strict diagnostics differ from reviewed residual77')
 # Full nonempty APK container scan includes the additional mi_ext layering files.
 packages=[];empty=[];parse_errors=[];anchors={};anchor_map={('system','/system/framework/framework-res.apk'):'framework-res.apk',('system_ext','/framework/framework-ext-res/framework-ext-res.apk'):'framework-ext-res.apk',('product','/overlay/MiuiFrameworkResOverlay.apk'):'MiuiFrameworkResOverlay-stock.apk',('product','/overlay/AospFrameworkResOverlay.apk'):'AospFrameworkResOverlay-original-donor.apk',('product','/overlay/F6Calibration-DEV-TESTKEY.apk'):'F6Calibration-DEV-TESTKEY.apk'}
 for part,rows in inventories.items():
  for row in rows:
   if not row['path'].endswith('.apk') or not stat.S_ISREG(row['mode']):continue
   rec={'partition':part,'image_path':row['path'],'bytes':row['size'],'from_verified_final_super':True}
   if row['size']==0:empty.append(rec);continue
   try:
    f=erofs[part].open_file(row)
    with zipfile.ZipFile(f) as z:b=z.read('AndroidManifest.xml');nodes=parse_xml(b);abis=sorted({n.split('/')[1] for n in z.namelist() if n.startswith('lib/') and n.count('/')>=2})
    f.close();rec.update(nodes=nodes,native_abis=abis,manifest_sha256=hashlib.sha256(b).hexdigest(),manifest=next(x['attributes'] for x in nodes if x['tag']=='manifest'),sdk=next((x['attributes'] for x in nodes if x['tag']=='uses-sdk'),{}));packages.append(rec)
    dest=root/'apk-manifests'/part/row['path'].lstrip('/');dest.parent.mkdir(parents=True,exist_ok=True);dest.with_suffix('.AndroidManifest.xml.bin').write_bytes(b)
    if (part,row['path']) in anchor_map:
     data=erofs[part].file_bytes(row);sha=hashlib.sha256(data).hexdigest();label=anchor_map[(part,row['path'])];anchors[label]={'partition':part,'image_path':row['path'],'bytes':len(data),'sha256':sha};dest=root/'overlay-provenance-inputs'/label;dest.parent.mkdir(exist_ok=True);dest.write_bytes(data)
   except Exception as e:rec['error']=str(e);parse_errors.append(rec)
  print(part,'APK containers inspected',flush=True)
 write(root/'final-apk-packages.json',packages);write(root/'final-apk-empty-layer-placeholders.json',empty);write(root/'overlay-final-input-hashes.json',anchors)
 minbad=[x for x in packages if isinstance(x['sdk'].get('minSdkVersion'),int) and x['sdk']['minSdkVersion']>37];preview=[x for x in packages if isinstance(x['sdk'].get('minSdkVersion'),str) and not x['sdk']['minSdkVersion'].isdigit()];abibad=[x for x in packages if x['native_abis'] and 'arm64-v8a' not in x['native_abis']]
 combined=packages+nested_apks
 duplicates=collections.defaultdict(list)
 for x in combined:duplicates[x['manifest'].get('package')].append({'partition':x['partition'],'image_path':x.get('image_path'),'apex_module':x.get('apex_module'),'payload_path':x.get('payload_path'),'split':x['manifest'].get('split'),'versionCode':x['manifest'].get('versionCode')})
 write(root/'combined-apk-duplicate-packages.json',{k:v for k,v in duplicates.items() if len(v)>1})
 nested_bad=[x for x in nested_apks if isinstance(x['sdk'].get('minSdkVersion'),int) and x['sdk']['minSdkVersion']>37 or isinstance(x['sdk'].get('minSdkVersion'),str) and not x['sdk']['minSdkVersion'].isdigit() or x['native_abis'] and 'arm64-v8a' not in x['native_abis']]
 write(root/'nested-apex-apk-summary.json',{'nonempty_apks':len(nested_apks),'module_counts':dict(collections.Counter(x['apex_module'] for x in nested_apks)),'empty_containers':nested_empty,'parse_errors':nested_errors,'SDK_ABI_findings':nested_bad,'runtime_installation_selection_not_proven':True})
 summary={'filesystem_nonempty_apk_containers':len(packages),'nested_apex_nonempty_apk_containers':len(nested_apks),'combined_container_count':len(combined),'partition_counts':dict(collections.Counter(x['partition'] for x in packages)),'empty_layer_placeholder_count':len(empty),'parse_errors':parse_errors,'min_sdk_above_framework_37':minbad,'preview_min_sdk':preview,'native_payload_without_arm64':abibad,'runtime_layer_resolution':'not established by manifest scan; mi_ext may shadow normal partition paths'};write(root/'final-apk-summary.json',summary)
 # Fresh signature validation; provenance bound to final target + overlay APK bytes.
 signing=json.loads(pathlib.Path(a.signer_report).read_text());idmap=json.loads(pathlib.Path(a.idmap_report).read_text());expected_anchors=json.loads((REVIEW/'idmap-test-inputs.json').read_text())
 for name in ['framework-res.apk','framework-ext-res.apk','MiuiFrameworkResOverlay-stock.apk','AospFrameworkResOverlay-original-donor.apk']:
  if anchors.get(name,{}).get('sha256')!=expected_anchors[name]['sha256']:raise Invalid('idmap target/overlay input differs from final image '+name)
 cal=root/'overlay-provenance-inputs/F6Calibration-DEV-TESTKEY.apk';sha=digest_file(cal)
 if sha!=signing['output']['sha256'] or sha!=idmap['signed_sha256']:raise Invalid('signed calibration report not bound to final APK')
 if digest_file(pathlib.Path(a.idmap_report))!=signing['idmap_validation']['sha256']:raise Invalid('idmap report differs from signer provenance')
 if idmap.get('policy')!='product' or idmap.get('enforce_overlayable') is not True or idmap.get('signature_policy_claimed') is not False or idmap.get('negative_public_policy')!='REJECTED':raise Invalid('normal idmap policy evidence missing')
 if any('value=true' not in idmap['privacy'][k] for k in ['camera','microphone']):raise Invalid('merged privacy result missing')
 for item in json.loads((SIGN/'tool-key-provenance.json').read_text())['files']:
  if item['archive_entry'] in ['bin/apksigner','framework/apksigner.jar'] and digest_file(item['path'])!=item['sha256']:raise Invalid('APK verification host tool differs from pinned official tool')
 sig=run(root,'final-calibration-apksigner-verify',[SIGN/'bin/apksigner','verify','--verbose','--print-certs',cal]);cert=signing['certificate_sha256']
 if sig['returncode'] or cert not in (root/'final-calibration-apksigner-verify.stdout.txt').read_text():raise Invalid('new APK signature/certificate verification failed')
 write(root/'final-overlay-provenance-binding.json',{'final_apk_sha256':sha,'certificate_sha256':cert,'development_public_testkey_only':True,'signer_report_sha256':digest_file(pathlib.Path(a.signer_report)),'idmap_report_sha256':digest_file(pathlib.Path(a.idmap_report)),'idmap_input_report_sha256':digest_file(REVIEW/'idmap-test-inputs.json'),'final_target_and_overlay_hashes':anchors,'fresh_host_signature_verification':sig,'previous_normal_policy_idmap_results_bound_to_final_bytes':True,'idmap_rerun_in_this_task':False,'phone_runtime_activation_unknown':True})
 for rec in inputs:
  if digest_file(root/rec['output'])!=rec['sha256']:raise Invalid('extracted final check input changed')
 for path,expected in evidence_hashes.items():
  if digest_file(path)!=expected:raise Invalid('final composition evidence changed during check '+path)
 write(root/'external-evidence-hashes.json',evidence_hashes)
 reader.check_unchanged();reader.close();fail=[]
 if vintf['returncode']:fail.append('VINTF')
 if policy['returncode']:fail.append('SELinux normal compile')
 if parse_errors or minbad or preview or abibad or nested_errors or nested_bad:fail.append('APK declared compatibility or input parsing')
 result={'status':'FINAL_OFFLINE_GATES_COMPLETED_WITH_FAILURES' if fail else 'FINAL_OFFLINE_METADATA_GATES_PASS_WITH_RUNTIME_LIMITS','super_sha256':reader.assembly['super_sha256'],'assembly_sha256':reader.assembly_hash,'apex_count':len(apexrows),'compiled_reviewed_policy_sha256':semantic_proof['compiled_policy_sha256'],'strict_returncode':strict_result['returncode'],'strict_remaining_failed_assertions':strict_count,'vintf_returncode':vintf['returncode'],'normal_selinux_returncode':policy['returncode'],'apk_summary':summary,'known_failures':fail,'scope':'Final exact DEV2 super/boot/init_boot; explicit source-pinned approved system/vendor exceptions; fresh official host APEX/VINTF/kernel/normal-policy checks; exact reviewed policy binary reproduced; nested APEX and filesystem APK manifests; actual loader byte/sidecar proof. No ROM executable or phone actions.','runtime_unknowns':['bootability and physical hardware behavior','PackageManager/layer/overlay activation on phone','full binary ABI and API behavior','production/OEM signer trust'],'strict_policy_note':'Fresh strict diagnostic remains77 failures with assertions enabled, matching reviewed residual baseline/donor-feature/selector diagnostics. It is not a full strict pass.'};write(root/'FINAL-RESULT.json',result);write(root/'STATUS.json',{'status':result['status']});print(json.dumps({k:v for k,v in result.items() if k!='apk_summary'},indent=2))
 files=[]
 for p in sorted(root.rglob('*')):
  if p.is_file() and p.name!='artifact-sha256.json':files.append({'path':str(p.relative_to(root)),'bytes':p.stat().st_size,'sha256':digest_file(p)})
 write(root/'artifact-sha256.json',files)

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for key in ['assembly','boot-image','init-boot-image','product-readback','product-filesystem-hash','mi-ext-readback','mi-ext-filesystem-hash','signer-report','idmap-report','output']:p.add_argument('--'+key,required=True)
 a=p.parse_args()
 try:main(a)
 except Exception as e:
  out=pathlib.Path(a.output)
  if out.is_dir():write(out/'STATUS.json',{'status':'BLOCKED_NO_FINAL_PASS','error':type(e).__name__+': '+str(e)})
  raise
