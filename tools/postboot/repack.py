"""Reproduce narrow product/ODM fixes with complete metadata and file-hash readback."""
from pathlib import Path
import argparse,base64,hashlib,io,json,os,shutil,stat,subprocess,sys,tarfile,uuid
from image import Image

ROOT=Path(__file__).resolve().parents[2];WORK=Path(os.environ.get('POSTBOOT_WORK','/mnt/d/hyperos4-peridot-postboot-20261004'))
TOOLS=Path('/mnt/c/Dev/peridot-hyperos4-port/.cache/global-single-recovery-ri2/host-tools/extracted/usr/bin')
assert WORK.resolve() in [Path('/mnt/d/hyperos4-peridot-postboot-20261004').resolve(),Path('/mnt/peridot-postboot-native').resolve()]

def sha(path):
 with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()

def file_hash(path):
 if path.is_symlink():return hashlib.sha256(os.readlink(path).encode()).hexdigest()
 return sha(path)

def main():
 ap=argparse.ArgumentParser();ap.add_argument('partition',choices=['product','odm']);a=ap.parse_args();name=a.partition
 source=WORK/(name+'-source.img');tree=WORK/(name+'-tree');original=Image(source);rows=original.inventory();changes=[]
 def replace(path,new):
  p=tree/path.lstrip('/');before=p.read_bytes()
  if before!=new:p.write_bytes(new);changes.append({'path':path,'before_sha256':hashlib.sha256(before).hexdigest(),'after_sha256':hashlib.sha256(new).hexdigest()})
 if name=='product':
  p=tree/'etc/build.prop';before=p.read_bytes();lines=before.decode().splitlines(keepends=True);hits=0
  for i,line in enumerate(lines):
   if line.startswith('ro.miui.product.home='):
    hits+=1;lines[i]='ro.miui.product.home=com.miui.home\n'
  assert hits<=1
  if not hits:lines.append('\n# Match the installed Global HyperOS 4 launcher.\nro.miui.product.home=com.miui.home\n')
  replace('/etc/build.prop',''.join(lines).encode())
  overlay=ROOT/'builder/work/postboot-20261004/overlay/F6PostBootFix.apk'
  # ROOT is the Windows path; convert it to the same WSL workspace.
  overlay=Path('/mnt/c/Dev/peridot-hyperos4-port/builder/work/postboot-20261004/overlay/F6PostBootFix.apk')
  target=tree/'overlay/F6PostBootFix.apk';assert not target.exists();target.write_bytes(overlay.read_bytes())
  template=next(x for x in rows if x['path']=='/overlay/F6Calibration-DEV-TESTKEY.apk')
  entry=dict(template,path='/overlay/F6PostBootFix.apk',nid=max(x['nid'] for x in rows)+1,size=target.stat().st_size)
  rows.append(entry);changes.append({'path':entry['path'],'before_sha256':None,'after_sha256':sha(target)})
 else:
  p=tree/'bin/hw/vendor.xiaomi.hardware.vibratorfeature.service';before=p.read_bytes();old=b'/vibratorfeature\0';new=b'/default\0'+bytes(len(old)-len(b'/default\0'))
  assert len(before)==204960 and before.count(old)==1 and before.startswith(b'\x7fELF')
  replaced=before.replace(old,new);assert len(replaced)==len(before)
  assert sum(x!=y for x,y in zip(before,replaced))==15
  replace('/bin/hw/vendor.xiaomi.hardware.vibratorfeature.service',replaced)
  p=tree/'etc/vintf/manifest/vendor.xiaomi.hardware.vibratorfeature.service.xml';before=p.read_bytes()
  assert before.count(b'IVibrator/vibratorfeature')==1
  replace('/etc/vintf/manifest/vendor.xiaomi.hardware.vibratorfeature.service.xml',before.replace(b'IVibrator/vibratorfeature',b'IVibrator/default'))
 tar=WORK/(name+'-patched.tar');assert not tar.exists();expected=[];seen={}
 with tarfile.open(tar,'x',format=tarfile.PAX_FORMAT) as archive:
  for row in sorted(rows,key=lambda x:(x['path'].count('/'),x['path'])):
   logical=row['path'];p=tree/logical.lstrip('/');t=tarfile.TarInfo(logical.lstrip('/') or '.');t.mode=row['mode']&0o7777;t.uid=row['uid'];t.gid=row['gid'];t.mtime=1230768000
   t.pax_headers={'LIBARCHIVE.xattr.'+k:base64.b64encode(bytes.fromhex(v)).decode() for k,v in row['xattrs'].items()}
   e={k:row[k] for k in ['path','mode','uid','gid','xattrs']}
   if stat.S_ISDIR(row['mode']):t.type=tarfile.DIRTYPE;archive.addfile(t)
   elif stat.S_ISLNK(row['mode']):
    t.type=tarfile.SYMTYPE;t.linkname=os.readlink(p);archive.addfile(t);e.update(size=len(t.linkname.encode()),sha256=hashlib.sha256(t.linkname.encode()).hexdigest())
   elif stat.S_ISREG(row['mode']):
    e.update(size=p.stat().st_size,sha256=sha(p))
    if row['nid'] in seen:t.type=tarfile.LNKTYPE;t.linkname=seen[row['nid']];archive.addfile(t)
    else:
     t.size=e['size']
     with p.open('rb') as f:archive.addfile(t,f)
     seen[row['nid']]=t.name
   else:raise ValueError('Unsupported special inode: '+logical)
   expected.append(e)
 original.close()
 output=WORK/(name+'-filesystem.img');assert not output.exists()
 with source.open('rb') as f:f.seek(1024+48);ident=uuid.UUID(bytes=f.read(16))
 subprocess.run([str(TOOLS/'mkfs.erofs'),'-T1230768000','-U',str(ident),'-zlz4hc,12','--tar=f',str(output),str(tar)],check=True)
 assert output.stat().st_size<source.stat().st_size-8*1024**2,'Image exceeds retained partition allocation'
 # These are exclusively task-created decoded staging files. Original pinned
 # image evidence remains in D: and in the immutable source ROM archive.
 assert tree.resolve().parent==WORK.resolve() and tree.name==name+'-tree' and not tree.is_symlink()
 shutil.rmtree(tree)
 assert tar.resolve().parent==WORK.resolve() and tar.name==name+'-patched.tar'
 tar.unlink()
 verify_tree=WORK/(name+'-verified-tree');verify_tree.mkdir()
 subprocess.run([str(TOOLS/'fsck.erofs'),'--extract='+str(verify_tree),'--no-preserve',str(output)],check=True)
 verified=Image(output);actual={x['path']:x for x in verified.inventory()};assert actual.keys()=={x['path'] for x in expected}
 for row in expected:
  got=actual[row['path']]
  for k in ['mode','uid','gid','xattrs']:assert got[k]==row[k],(row['path'],k,'metadata differs')
  if 'sha256' in row:assert file_hash(verify_tree/row['path'].lstrip('/'))==row['sha256'],'File content mismatch: '+row['path']
 verified.close()
 receipt={'partition':name,'source_sha256':sha(source),'filesystem_path':str(output),'filesystem_sha256':sha(output),
  'filesystem_bytes':output.stat().st_size,'allocation_bytes':source.stat().st_size,'changes':changes,
  'all_file_hashes_modes_uid_gid_xattrs_verified':True,'entries':expected,'phone_actions_performed':False}
 (WORK/(name+'-repack.json')).write_text(json.dumps(receipt,indent=2)+'\n')
 print(json.dumps({k:receipt[k] for k in ['partition','filesystem_bytes','changes','all_file_hashes_modes_uid_gid_xattrs_verified']},indent=2),flush=True)

if __name__=='__main__':main()
