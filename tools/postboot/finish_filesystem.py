"""Finish a prepared, source-generated tar with scoped scratch paths and independent readback."""
from pathlib import Path
import argparse,base64,hashlib,json,os,shutil,stat,subprocess,tarfile,uuid
from image import Image
from repack_windows import sha,output_hash

ROOT=Path(__file__).resolve().parents[2];WORK=Path('D:/hyperos4-peridot-postboot-20261004');TOOLS=ROOT/'builder/tools/bin/windows'
ap=argparse.ArgumentParser();ap.add_argument('partition',choices=['product','odm','system_ext']);ap.add_argument('--verify-existing',action='store_true');ap.add_argument('--ssd-scratch',action='store_true');a=ap.parse_args();name=a.partition
source=WORK/(name+'-source.img');pin=json.loads((WORK/'source-images.json').read_text())['images'][name]
assert source.stat().st_size==pin['size'] and sha(source)==pin['sha256']
original=Image(source);rows=original.inventory();by={x['path']:x for x in rows};expected=[];changes=[]
tar=WORK/(name+'-windows-clean.tar' if name=='system_ext' else name+'-windows.tar');assert tar.is_file()
with tarfile.open(tar,'r') as archive:
 for t in archive:
  clean=t.name[2:] if t.name.startswith('./') else t.name
  path='/'+clean.lstrip('/') if clean!='.' else '/'
  attrs={k[len('LIBARCHIVE.xattr.'):]:base64.b64decode(v).hex() for k,v in t.pax_headers.items() if k.startswith('LIBARCHIVE.xattr.')}
  if path=='/overlay/F6PostBootFix.apk':original_row=by['/overlay/F6Calibration-DEV-TESTKEY.apk']
  else:original_row=by[path]
  mode=(stat.S_IFDIR if t.isdir() else stat.S_IFLNK if t.issym() else stat.S_IFREG)|t.mode
  e={'path':path,'mode':mode,'uid':t.uid,'gid':t.gid,'xattrs':attrs}
  for k in ['mode','uid','gid','xattrs']:assert e[k]==original_row[k],(path,k,'prepared input metadata differs')
  if t.issym():data=t.linkname.encode();e.update(size=len(data),sha256=hashlib.sha256(data).hexdigest())
  elif t.isfile() or t.islnk():
   h=hashlib.sha256();count=0
   with archive.extractfile(t) as f:
    for block in iter(lambda:f.read(1024*1024),b''):count+=len(block);h.update(block)
   e.update(size=count,sha256=h.hexdigest())
  expected.append(e)
 if name=='product':
  assert {x['path'] for x in expected}==set(by)|{'/overlay/F6PostBootFix.apk'}
  apk=ROOT/'builder/work/postboot-20261004/overlay/F6PostBootFix.apk'
  assert next(x for x in expected if x['path']=='/overlay/F6PostBootFix.apk')['sha256']==sha(apk)
  prop=archive.extractfile('etc/build.prop').read();assert prop.count(b'ro.miui.product.home=com.miui.home')==1
  changes=[{'path':'/etc/build.prop','description':'Initialize home-package property to installed com.miui.home'},
   {'path':'/overlay/F6PostBootFix.apk','description':'Exact Recents binding and 20dp F6 corner values','sha256':sha(apk)}]
 elif name=='odm':
  assert {x['path'] for x in expected}==set(by)
  binary=archive.extractfile('bin/hw/vendor.xiaomi.hardware.vibratorfeature.service').read()
  assert len(binary)==204960 and hashlib.sha256(binary).hexdigest()=='40ad9e642124e8fce60af136e62dcae16c8aba0037f4b65ae8d26e8d00e8c3b7'
  xml=archive.extractfile('etc/vintf/manifest/vendor.xiaomi.hardware.vibratorfeature.service.xml').read()
  assert b'IVibrator/default' in xml and b'IVibrator/vibratorfeature' not in xml
  changes=[{'path':'/bin/hw/vendor.xiaomi.hardware.vibratorfeature.service','different_bytes':15,'sha256':hashlib.sha256(binary).hexdigest()},
   {'path':'/etc/vintf/manifest/vendor.xiaomi.hardware.vibratorfeature.service.xml','description':'Declare IVibrator/default'}]
 else:
  removal=json.loads((WORK/'framework-cache-removal.json').read_text())
  assert sha(tar)==removal['output_tar_sha256'] and pin['sha256']==removal['source_image_sha256']
  assert {x['path'] for x in expected}==set(by)-set(removal['removed_paths'])
  patch=json.loads((ROOT/'builder/work/postboot-20261004/vibrator-framework-patch.json').read_text())
  assert next(x for x in expected if x['path']=='/framework/miui-services.jar')['sha256']==patch['patched_jar_sha256']
  changes=[{'path':'/framework/miui-services.jar','description':'One service lookup operand; all other methods unchanged','sha256':patch['patched_jar_sha256']},
   {'removed_generated_companions':removal['removed_paths'],'description':removal['reason']}]
original.close();output=WORK/(name+'-filesystem-v2.img')
temp=WORK/'tmp-native';temp.mkdir(exist_ok=True)
env=os.environ.copy();env.update(TMPDIR=str(temp),TMP=str(temp),TEMP=str(temp))
with source.open('rb') as f:f.seek(1072);ident=uuid.UUID(bytes=f.read(16))
if not a.verify_existing:
 assert not output.exists()
 output.touch();subprocess.run(['fsutil','sparse','setflag',str(output)],check=True)
 print('Building',name,'with sparse task output and task-local temporary storage',flush=True)
 subprocess.run([str(TOOLS/'mkfs.erofs.exe'),'-d0','-T1230768000','-U',str(ident),'-zlz4hc,level=12','--tar=f',str(output),str(tar)],env=env,check=True)
else:
 assert output.is_file()
 print('Resuming independent verification of',name,flush=True)
assert output.stat().st_size<source.stat().st_size-8*1024**2
check_output=output;scratch=None;filesystem_digest=None;output_identity=output.stat()
if a.ssd_scratch:
 scratch=ROOT/'builder/work/postboot-20261004/ssd-verify'/(name+'-filesystem.img');scratch.parent.mkdir(exist_ok=True)
 assert not scratch.exists() and shutil.disk_usage(scratch.parent).free>output.stat().st_size+512*1024**2
 print('Copying bounded',name,'verification input to SSD',flush=True)
 h=hashlib.sha256()
 with output.open('rb') as src,scratch.open('xb') as dst:
  for block in iter(lambda:src.read(4*1024**2),b''):dst.write(block);h.update(block)
 filesystem_digest=h.hexdigest();check_output=scratch
subprocess.run([str(TOOLS/'fsck.erofs.exe'),'--extract',str(check_output)],env=env,check=True)
image=Image(check_output);actual={x['path']:x for x in image.inventory()};assert actual.keys()=={x['path'] for x in expected}
for index,row in enumerate(expected):
 got=actual[row['path']]
 for k in ['mode','uid','gid','xattrs']:assert got[k]==row[k],(row['path'],k,'output metadata differs')
 if 'sha256' in row:assert output_hash(check_output,got['nid'],row['size'])==row['sha256'],row['path']
 if index%400==0:print('Verified',name,index,'/',len(expected),flush=True)
image.close()
assert output.stat().st_size==output_identity.st_size and output.stat().st_mtime_ns==output_identity.st_mtime_ns
if scratch:
 assert sha(scratch)==filesystem_digest
 scratch.unlink()
result={'partition':name,'source_sha256':pin['sha256'],'prepared_tar_sha256':sha(tar),'filesystem_path':str(output),
 'filesystem_sha256':filesystem_digest or sha(output),'filesystem_bytes':output.stat().st_size,'allocation_bytes':source.stat().st_size,
 'all_file_hashes_modes_uid_gid_xattrs_verified':True,'changes':changes,'entries':expected,
 'tools':{str(p.relative_to(ROOT)):sha(p) for p in [TOOLS/'mkfs.erofs.exe',TOOLS/'fsck.erofs.exe',TOOLS/'dump.erofs.exe']},'phone_actions_performed':False}
(WORK/(name+'-repack.json')).write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
print(json.dumps({k:result[k] for k in ['partition','filesystem_bytes','all_file_hashes_modes_uid_gid_xattrs_verified']},indent=2),flush=True)
