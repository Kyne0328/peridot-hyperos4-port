"""Native Windows EROFS authoring with bounded file streaming and exact metadata readback."""
from pathlib import Path
import argparse,base64,hashlib,io,json,stat,subprocess,tarfile,uuid
from image import Image

ROOT=Path(__file__).resolve().parents[2];WORK=Path('D:/hyperos4-peridot-postboot-20261004');TOOLS=ROOT/'builder/tools/bin/windows'
def sha(path):
 with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def small(path,nid):
 p=subprocess.run([str(TOOLS/'dump.erofs.exe'),'--cat','--nid='+str(nid),str(path)],capture_output=True)
 assert p.returncode==0,p.stderr.decode(errors='replace')
 assert len(p.stdout)<8*1024**2
 return p.stdout
class Reader:
 def __init__(self,stream):self.stream=stream;self.h=hashlib.sha256();self.count=0
 def read(self,n):
  assert 0<=n<=1024**2
  data=self.stream.read(n);self.h.update(data);self.count+=len(data);return data
def output_hash(path,nid,expected):
 p=subprocess.Popen([str(TOOLS/'dump.erofs.exe'),'--cat','--nid='+str(nid),str(path)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 h=hashlib.sha256();count=0
 for block in iter(lambda:p.stdout.read(1024*1024),b''):count+=len(block);assert count<=expected;h.update(block)
 errors=p.stderr.read();assert p.wait()==0,errors.decode(errors='replace');assert count==expected
 return h.hexdigest()
def main():
 ap=argparse.ArgumentParser();ap.add_argument('partition',choices=['product','odm','system_ext']);ap.add_argument('--tar-only',action='store_true');a=ap.parse_args();name=a.partition
 source=WORK/(name+'-source.img');pin=json.loads((WORK/'source-images.json').read_text())['images'][name]
 assert source.stat().st_size==pin['size'] and sha(source)==pin['sha256']
 original=Image(source);rows=original.inventory();by={x['path']:x for x in rows};replacements={};changes=[]
 def patch(path,new):
  row=by[path];before=small(source,row['nid']);assert len(before)==row['size']
  if before!=new:replacements[path]=new;changes.append({'path':path,'before_sha256':hashlib.sha256(before).hexdigest(),'after_sha256':hashlib.sha256(new).hexdigest()})
 if name=='product':
  before=small(source,by['/etc/build.prop']['nid']);lines=before.decode().splitlines(keepends=True);hits=0
  for i,line in enumerate(lines):
   if line.startswith('ro.miui.product.home='):hits+=1;lines[i]='ro.miui.product.home=com.miui.home\n'
  assert hits<=1
  if not hits:lines.append('\n# Match the installed Global HyperOS 4 launcher.\nro.miui.product.home=com.miui.home\n')
  patch('/etc/build.prop',''.join(lines).encode())
  path='/overlay/F6PostBootFix.apk';assert path not in by
  apk=(ROOT/'builder/work/postboot-20261004/overlay/F6PostBootFix.apk').read_bytes()
  template=by['/overlay/F6Calibration-DEV-TESTKEY.apk']
  new=dict(template,path=path,nid=max(x['nid'] for x in rows)+1,size=len(apk));rows.append(new);replacements[path]=apk
  changes.append({'path':path,'before_sha256':None,'after_sha256':hashlib.sha256(apk).hexdigest()})
 elif name=='odm':
  path='/bin/hw/vendor.xiaomi.hardware.vibratorfeature.service';before=small(source,by[path]['nid'])
  old=b'/vibratorfeature\0';new=b'/default\0'+bytes(len(old)-len(b'/default\0'))
  assert len(before)==204960 and hashlib.sha256(before).hexdigest()=='f7767dcef32bc0f6e4fad85ab96052db66f714216f223b58b2b25c050b19f3cb' and before.count(old)==1
  after=before.replace(old,new);assert len(after)==len(before) and sum(x!=y for x,y in zip(before,after))==15
  patch(path,after)
  path='/etc/vintf/manifest/vendor.xiaomi.hardware.vibratorfeature.service.xml';before=small(source,by[path]['nid'])
  assert before.count(b'IVibrator/vibratorfeature')==1;patch(path,before.replace(b'IVibrator/vibratorfeature',b'IVibrator/default'))
 else:
  path='/framework/miui-services.jar';before_row=by[path]
  expected=json.loads((ROOT/'builder/work/postboot-20261004/vibrator-framework-patch.json').read_text())
  assert output_hash(source,before_row['nid'],before_row['size'])==expected['source_jar_sha256']
  new=(ROOT/'builder/work/postboot-20261004/miui-services-postboot.jar').read_bytes()
  assert hashlib.sha256(new).hexdigest()==expected['patched_jar_sha256']
  replacements[path]=new;changes.append({'path':path,'before_sha256':expected['source_jar_sha256'],'after_sha256':expected['patched_jar_sha256']})
 tar=WORK/(name+'-windows.tar');assert not tar.exists();seen={};hashes={};expected=[]
 print('Streaming source files to metadata-preserving',name,'tar',flush=True)
 with tarfile.open(tar,'x',format=tarfile.PAX_FORMAT) as archive:
  for index,row in enumerate(sorted(rows,key=lambda x:(x['path'].count('/'),x['path']))):
   path=row['path'];t=tarfile.TarInfo(path.lstrip('/') or '.');t.mode=row['mode']&0o7777;t.uid=row['uid'];t.gid=row['gid'];t.mtime=1230768000
   t.pax_headers={'LIBARCHIVE.xattr.'+k:base64.b64encode(bytes.fromhex(v)).decode() for k,v in row['xattrs'].items()}
   e={k:row[k] for k in ['path','mode','uid','gid','xattrs']}
   if stat.S_ISDIR(row['mode']):t.type=tarfile.DIRTYPE;archive.addfile(t)
   elif stat.S_ISLNK(row['mode']):
    data=small(source,row['nid']);assert len(data)==row['size'];t.type=tarfile.SYMTYPE;t.linkname=data.decode();archive.addfile(t)
    e.update(size=len(data),sha256=hashlib.sha256(data).hexdigest())
   elif stat.S_ISREG(row['mode']):
    if path in replacements:
     data=replacements[path];t.size=len(data);archive.addfile(t,io.BytesIO(data));digest=hashlib.sha256(data).hexdigest()
    elif row['nid'] in seen:
     t.type=tarfile.LNKTYPE;t.linkname=seen[row['nid']];archive.addfile(t);t.size=row['size'];digest=hashes[row['nid']]
    else:
     t.size=row['size'];p=subprocess.Popen([str(TOOLS/'dump.erofs.exe'),'--cat','--nid='+str(row['nid']),str(source)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
     reader=Reader(p.stdout);archive.addfile(t,reader);assert reader.count==t.size and not p.stdout.read(1)
     errors=p.stderr.read();assert p.wait()==0,errors.decode(errors='replace');digest=reader.h.hexdigest()
    if row['nid'] not in seen:seen[row['nid']]=t.name;hashes[row['nid']]=digest
    e.update(size=t.size,sha256=digest)
   else:raise ValueError('Unsupported special inode '+path)
   expected.append(e)
   if index%400==0:print('Prepared',name,index,'/',len(rows),flush=True)
 original.close()
 if a.tar_only:
  print('Prepared metadata-preserving tar for',name,flush=True);return
 output=WORK/(name+'-filesystem.img');assert not output.exists()
 with source.open('rb') as f:f.seek(1072);ident=uuid.UUID(bytes=f.read(16))
 subprocess.run([str(TOOLS/'mkfs.erofs.exe'),'-T1230768000','-U',str(ident),'-zlz4hc,level=12','--tar=f',str(output),str(tar)],check=True)
 assert output.stat().st_size<source.stat().st_size-8*1024**2
 subprocess.run([str(TOOLS/'fsck.erofs.exe'),'--extract',str(output)],check=True)
 image=Image(output);actual={x['path']:x for x in image.inventory()};assert actual.keys()=={x['path'] for x in expected}
 print('Independent file contents and metadata readback:',name,flush=True)
 for index,row in enumerate(expected):
  got=actual[row['path']]
  for k in ['mode','uid','gid','xattrs']:assert got[k]==row[k],(row['path'],k,'metadata differs')
  if 'sha256' in row:assert output_hash(output,got['nid'],row['size'])==row['sha256'],row['path']
  if index%400==0:print('Verified',name,index,'/',len(rows),flush=True)
 image.close()
 receipt={'partition':name,'source_sha256':pin['sha256'],'filesystem_path':str(output),'filesystem_sha256':sha(output),'filesystem_bytes':output.stat().st_size,
  'allocation_bytes':source.stat().st_size,'changes':changes,'all_file_hashes_modes_uid_gid_xattrs_verified':True,'entries':expected,
  'tools':{str(p.relative_to(ROOT)):sha(p) for p in [TOOLS/'mkfs.erofs.exe',TOOLS/'fsck.erofs.exe',TOOLS/'dump.erofs.exe']},'phone_actions_performed':False}
 (WORK/(name+'-repack.json')).write_text(json.dumps(receipt,indent=2)+'\n',encoding='utf-8')
 print(json.dumps({k:receipt[k] for k in ['partition','filesystem_bytes','changes','all_file_hashes_modes_uid_gid_xattrs_verified']},indent=2),flush=True)
if __name__=='__main__':main()
