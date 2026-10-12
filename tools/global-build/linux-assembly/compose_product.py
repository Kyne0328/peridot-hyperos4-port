#!/usr/bin/env python3
"""Apply reviewed offline product substitutions to assistant-created staging tree.

Source archives and images are never changed. Metadata comes from the exact
original EROFS inode inventories and is checked again after filesystem rebuild.
"""
import hashlib,json,pathlib,re,shutil,stat,datetime
R=pathlib.Path(__file__).resolve().parent;TREE=R/'product-work/product'
BASE=pathlib.Path('/workspace/shared/peridot-global-base/selected_files/product')
REVIEW=pathlib.Path('/workspace/shared/peridot-global-builder/review-product')
def sha(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def compose():
 log=R/'product-metadata/composition.json'
 if log.exists():raise ValueError('already composed; no implicit reapplication')
 donor=json.loads((R/'donor-product-metadata.json').read_text());base=json.loads((R/'base-product-metadata.json').read_text());files=json.loads((R/'product-metadata/donor-tree-files.json').read_text())['files']
 metadata={i['path']:dict(i) for i in donor['entries']};bm={i['path']:i for i in base['entries']};fh={i['path']:i for i in files}
 for name,i in fh.items():
  if sha(TREE/name.lstrip('/'))!=i['sha256']:raise ValueError('input tree changed before review '+name)
 selected=['/etc/device_features/peridot.xml','/etc/displayconfig/display_id_4630946545580055171.xml','/etc/displayconfig/display_id_4630947033261136259.xml','/etc/displayconfig/display_id_4630947195234848131.xml','/overlay/MiuiFrameworkResOverlay.apk']
 pinned_copy_hashes={'/etc/device_features/peridot.xml':'a0c28d49771932bb47396954caa08d39d0b66cb3a95c9e01167501e3e2f03eba','/etc/displayconfig/display_id_4630946545580055171.xml':'92907ab3620fa7caf3be093ea9d32de38c9d2d53ac7dc0f4faae280071307e3d','/etc/displayconfig/display_id_4630947033261136259.xml':'92907ab3620fa7caf3be093ea9d32de38c9d2d53ac7dc0f4faae280071307e3d','/etc/displayconfig/display_id_4630947195234848131.xml':'92907ab3620fa7caf3be093ea9d32de38c9d2d53ac7dc0f4faae280071307e3d','/overlay/MiuiFrameworkResOverlay.apk':'d9837e85f6d3bf75917c4334ae9c5ab7f90edaa541ae9c47d3337139c63f71b3','/overlay/AospFrameworkResOverlay.apk':'959f0eb55ee85a45e265288eebacfa7351153dc6f651c43eff1bcb2c6cf4022c'}
 copies=[]
 for name in selected:
  src=BASE/name.lstrip('/')
  if name not in bm or src.stat().st_size!=bm[name]['size']:raise ValueError('stock copied input missing/mismatched '+name)
  if sha(src)!=pinned_copy_hashes[name]:raise ValueError('reviewed source copy hash mismatch '+name)
  copies.append((name,src,sha(src),dict(bm[name])))
 thermal=REVIEW/'proposed_multi_factor_thermal_brightness_control.xml';th='2fb22baf874e85e6e0cde5790c8a83713e987b926038002c4fcf4daa5036ed21'
 if sha(thermal)!=th:raise ValueError('reviewed thermal artifact changed')
 up= '/app/Updater';apk=TREE/'app/Updater/Updater.apk'
 if sha(apk)!='73cf027408c00aa0fe09a37c296b6080001ea019d8896b22c2115b51047a416a':raise ValueError('factory Updater identity gate failed')
 changes=[]
 for name,src,h,meta in copies:
  dst=TREE/name.lstrip('/');before=sha(dst) if dst.exists() else None;shutil.copyfile(src,dst);dst.chmod(meta['mode']&0o7777);metadata[name]=meta;metadata[name]['sha256']=h
  changes.append({'operation':'copy_exact_stock_file','path':name,'source':str(src),'before_sha256':before,'after_sha256':h,'stock_metadata':{k:meta[k] for k in ('uid','gid','mode','xattrs')}})
 name='/etc/displayconfig/multi_factor_thermal_brightness_control.xml';dst=TREE/name.lstrip('/');before=sha(dst);shutil.copyfile(thermal,dst);metadata[name]['size']=dst.stat().st_size;metadata[name]['sha256']=th
 changes.append({'operation':'replace_with_reviewed_stock_curve_schema_conversion','path':name,'source':str(thermal),'before_sha256':before,'after_sha256':th,'validation':str(REVIEW/'thermal-conversion-validation.json')})
 removed=[n for n in metadata if n==up or n.startswith(up+'/')];shutil.rmtree(TREE/up.lstrip('/'))
 for n in removed:metadata.pop(n)
 changes.append({'operation':'remove_factory_rom_updater_frontend','path':up,'removed_paths':removed,'removed_file_sha256':{n:fh[n]['sha256'] for n in removed if n in fh},'retained':['/priv-app/ConfigUpdater','/app/MIUISystemAppUpdater','update_engine','recovery','AVB','rollback controls']})
 name='/etc/build.prop';dst=TREE/name.lstrip('/');olddata=dst.read_bytes();text=olddata.decode();target_values={'ro.product.product.name':('miproduct_pudding','miproduct_peridot'),'ro.product.ab_ota_partitions':('product,pvmfw','product'),'persist.miui.density_v2':('520','480'),'ro.sf.lcd_density':('520','480')};prop_changes=[]
 for key,(before_value,after_value) in target_values.items():
  found=re.findall('^'+re.escape(key)+r'=(.*)$',text,re.M)
  if found!=[before_value]:raise ValueError('reviewed property before-value differs '+key)
  text=re.sub('^'+re.escape(key)+r'=.*$',key+'='+after_value,text,flags=re.M);prop_changes.append({'key':key,'from':before_value,'to':after_value})
 dst.write_text(text);metadata[name]['size']=dst.stat().st_size;metadata[name]['sha256']=sha(dst)
 changes.append({'operation':'replace_exact_reviewed_target_properties','path':name,'before_sha256':hashlib.sha256(olddata).hexdigest(),'after_sha256':sha(dst),'changes':prop_changes,'software_version_fingerprint_sdk_security_properties_changed':False})
 expected=[]
 for name,i in sorted(metadata.items()):
  p=TREE/name.lstrip('/');s=p.lstat()
  if stat.S_IFMT(s.st_mode)!=stat.S_IFMT(i['mode']):raise ValueError('changed path type '+name)
  if stat.S_ISREG(s.st_mode):i['size']=s.st_size;i['sha256']=sha(p)
  expected.append(i)
 expected_file=R/'product-metadata/composed-expected.json'
 expected_file.write_text(json.dumps({'status':'reviewed_product_base_changes_applied_calibration_overlay_pending','source_donor_archive_sha256':donor['summary']['source_archive_sha256'],'source_stock_archive_sha256':base['summary']['source_archive_sha256'],'entries':expected},indent=2))
 write_metadata(expected)
 result={'status':'reviewed_product_base_changes_applied_calibration_overlay_pending','time_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'operations':changes,'entries':len(expected),'regular_files':sum(stat.S_ISREG(i['mode']) for i in expected),'expected_metadata':str(expected_file),'runtime_thermal_validation':False,'all_preexisting_files_and_source_archives_preserved':True}
 log.write_text(json.dumps(result,indent=2));print(json.dumps(result,indent=2));return result

def write_metadata(entries):
 fs=['/ 0 0 0755 capabilities=0x0'];ctx=[]
 for i in entries:
  name='product'+('' if i['path']=='/' else i['path']);attrs=i['xattrs']
  if set(attrs)!={'security.selinux'}:raise ValueError('unexpected xattrs require explicit preservation support')
  label=bytes.fromhex(attrs['security.selinux']).rstrip(b'\0').decode()
  fs.append(f"{name} {i['uid']} {i['gid']} {i['mode']&0o7777:04o} capabilities=0x0")
  ctx.append('/'+re.escape(name)+' '+label)
 (R/'product-metadata/composed_fs_config').write_text('\n'.join(sorted(fs))+'\n')
 (R/'product-metadata/composed_file_contexts').write_text('\n'.join(sorted(ctx))+'\n')
if __name__=='__main__':compose()
