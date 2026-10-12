"""Offline RI4 decrypted image authoring. Inputs are never opened for writing."""
from pathlib import Path
import base64, gzip, hashlib, io, json, os, stat, struct, subprocess, sys, tarfile
ROOT=Path(__file__).resolve().parents[2]
WORK=ROOT/'builder/work/installer-ri4'
SRC=ROOT/'.cache/global-single-recovery-ri2/source-images'
TOOLS=ROOT/'builder/tools/bin/windows'
sys.path[:0]=[str(ROOT/'builder'),str(ROOT/'tools/global-build/linux-assembly'),str(ROOT/'tools/installer-ri3/recovery-pair')]
from inspect_erofs_payload import Erofs
from peridot_builder.lp import parse_super_metadata_prefix
from pair_format import parse_avb, verify_avb, sign_parts, public_blob, unpack_boot, cpio_entries, lz4_decode, recovery_signed, align
from cryptography.hazmat.primitives import serialization
CHUNK=4*1024**2
def need(v,msg):
 if not v: raise RuntimeError(msg)
def digest(p):
 with Path(p).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def save(p,d):p.write_text(json.dumps(d,indent=2)+'\n',encoding='utf-8')
def run(cmd):
 r=subprocess.run([str(x) for x in cmd],capture_output=True)
 need(r.returncode==0,r.stderr.decode(errors='replace')[-2500:]);return r.stdout
def patch_fstab(data):
 text=data.decode();out=[];changes=[]
 for line in text.splitlines(keepends=True):
  fields=line.split()
  if len(fields)>=5 and fields[1]=='/data' and not line.lstrip().startswith('#'):
   old=fields[4];opts=old.split(',');remove=[x for x in opts if x.split('=')[0] in {'fileencryption','keydirectory','metadata_encryption','forceencrypt','forcefdeorfbe','encryptable'}]
   if remove:
    new=','.join(x for x in opts if x not in remove);line=line.replace(old,new,1);changes.append(remove)
  out.append(line)
 return ''.join(out).encode(),changes
class Image(Erofs):
 def __init__(self,path):
  self.f=open(path,'rb');self.offset=0
  s=self.read(1024,128);need(struct.unpack_from('<I',s)[0]==0xe0f5e1e2,'not EROFS')
  self.bs=1<<s[12];self.root=struct.unpack_from('<H',s,14)[0];self.meta=struct.unpack_from('<I',s,40)[0]*self.bs;self.xattr_base=struct.unpack_from('<I',s,44)[0]*self.bs
 def read(self,off,n):
  self.f.seek(off);b=self.f.read(n);need(len(b)==n,'short EROFS read');return b
def cat(p,nid):return run([TOOLS/'dump.erofs.exe','--cat',f'--nid={nid}',p])
def vendor():
 p=WORK/'vendor-source.img';superp=SRC/'images/super.img'
 with superp.open('rb') as f:m=parse_super_metadata_prefix(f.read(1024*1024))
 part=next(x for x in m['partitions'] if x['name']=='vendor_a');need(len(part['extents'])==1,'unexpected vendor extents')
 ex=part['extents'][0]
 if not p.exists():
  with superp.open('rb') as f,p.open('xb') as o:
   f.seek(ex['offset_bytes']);left=ex['size_bytes']
   while left:b=f.read(min(CHUNK,left));need(b,'short vendor');o.write(b);left-=len(b)
 e=Image(p);rows=e.inventory();expected=[];seen={};tar=WORK/'vendor-decrypted.tar';changes=[]
 if tar.exists():raise RuntimeError('use a new work directory; tar already exists')
 with tarfile.open(tar,'x',format=tarfile.PAX_FORMAT) as tf:
  for count,row in enumerate(sorted(rows,key=lambda x:(x['path'].count('/'),x['path']))):
   name=row['path'].lstrip('/') or '.';t=tarfile.TarInfo(name);t.mode=row['mode']&0o7777;t.uid=row['uid'];t.gid=row['gid'];t.mtime=1230768000
   t.pax_headers={'LIBARCHIVE.xattr.'+k:base64.b64encode(bytes.fromhex(v)).decode() for k,v in row['xattrs'].items()}
   entry=dict(row)
   if stat.S_ISDIR(row['mode']):t.type=tarfile.DIRTYPE;tf.addfile(t)
   elif stat.S_ISREG(row['mode']) or stat.S_ISLNK(row['mode']):
    data=cat(p,row['nid']);need(len(data)==row['size'],'file size mismatch')
    if 'fstab' in name:
     new,removed=patch_fstab(data)
     if removed:changes.append({'path':row['path'],'removed':removed,'before_sha256':hashlib.sha256(data).hexdigest(),'after_sha256':hashlib.sha256(new).hexdigest()});data=new
    entry['size']=len(data);entry['sha256']=hashlib.sha256(data).hexdigest()
    if stat.S_ISLNK(row['mode']):t.type=tarfile.SYMTYPE;t.linkname=data.decode();entry['symlink_target']=t.linkname;tf.addfile(t)
    elif row['nid'] in seen:t.type=tarfile.LNKTYPE;t.linkname=seen[row['nid']];tf.addfile(t)
    else:t.size=len(data);tf.addfile(t,io.BytesIO(data));seen[row['nid']]=name
   else:raise RuntimeError('unsupported vendor special file '+name)
   expected.append(entry)
   if count%300==0:print('Vendor tar',count,'/',len(rows),flush=True)
 e.f.close();need(changes,'no vendor encryption changes');save(WORK/'vendor-expected.json',{'entries':expected,'changes':changes,'source_sha256':digest(p)})
 out=WORK/'vendor.img'
 run([TOOLS/'mkfs.erofs.exe','-T1230768000','-U','096238ed-81be-52be-b02d-60bc7d61cbf0','-zlz4hc,level=12','--tar=f',out,tar])
 need(out.stat().st_size<part['size_bytes']-8*1024**2,'rebuilt vendor exceeds allocation reserve')
 run([TOOLS/'fsck.erofs.exe',out])
 verify=Image(out);actual={x['path']:x for x in verify.inventory()};need(set(actual)=={x['path'] for x in expected},'vendor path set changed')
 for count,row in enumerate(expected):
  a=actual[row['path']]
  for k in ['mode','uid','gid','xattrs']:need(a[k]==row[k],f'vendor metadata changed {row["path"]} {k}')
  if stat.S_ISREG(row['mode']) or stat.S_ISLNK(row['mode']):need(hashlib.sha256(cat(out,a['nid'])).hexdigest()==row['sha256'],'vendor byte mismatch '+row['path'])
  if count%300==0:print('Vendor verified',count,'/',len(expected),flush=True)
 verify.f.close()
 info=parse_avb(p.read_bytes());d=next(x for x in info['descriptors'] if struct.unpack_from('>Q',x)[0]==1)
 # The complete new tree is authenticated by root vbmeta. FEC isn't silently retained with stale parity.
 name_len,salt_len=struct.unpack_from('>II',d,104);salt=d[180+name_len:180+name_len+salt_len].hex()
 props=[]
 for q in info['descriptors']:
  if struct.unpack_from('>Q',q)[0]==0:
   kl,vl=struct.unpack_from('>QQ',q,16);props += ['--prop',q[32:32+kl].decode()+':'+q[33+kl:33+kl+vl].decode()]
 run([sys.executable,TOOLS/'avbtool.py','add_hashtree_footer','--image',out,'--partition_name','vendor','--partition_size',part['size_bytes'],'--hash_algorithm','sha256','--salt',salt,'--do_not_generate_fec',*props])
 save(WORK/'vendor-receipt.json',{'changes':changes,'metadata_and_all_file_bytes_verified':True,'filesystem_entries':len(rows),'source_sha256':digest(p),'output_sha256':digest(out),'size':out.stat().st_size,'verity_retained':True,'fec_generated':False})
def cpio_patch(raw):
 entries=cpio_entries(raw);out=bytearray();changes=[];last=0
 for e in entries:
  body=raw[e['offset']:e['offset']+e['size']];new=body
  if 'fstab' in e['name']:
   new,removed=patch_fstab(body)
   if removed:changes.append({'path':e['name'],'removed':removed})
  header=bytearray(raw[e['header_offset']:e['offset']]);header[54:62]=f'{len(new):08x}'.encode();out+=header+new;out+=bytes((-len(out))%4);last=e['end']
 # Keep the exact trailer record; alignment after its terminal zeros is regenerated.
 trailer=raw[last:];out+=trailer;return bytes(out),changes
def compress(raw,label):
 blocks=[]
 for off in range(0,len(raw),8*1024**2):
  a=WORK/(label+f'-{off}.raw');b=WORK/(label+f'-{off}.lz4');a.write_bytes(raw[off:off+8*1024**2])
  linux_root='/mnt/c/Dev/peridot-hyperos4-port/'
  run(['wsl','-d','Ubuntu','--','python3',linux_root+'tools/installer-ri3/recovery-pair/lz4_compress.py',linux_root+a.relative_to(ROOT).as_posix(),linux_root+b.relative_to(ROOT).as_posix()]);v=b.read_bytes();blocks.append(struct.pack('<I',len(v))+v)
 return b'\x02\x21\x4c\x18'+b''.join(blocks)
def decode(data):
 need(data[:4]==b'\x02\x21\x4c\x18','expected legacy LZ4');out=bytearray();pos=4
 while pos<len(data):n=struct.unpack_from('<I',data,pos)[0];pos+=4;out+=lz4_decode(data[pos:pos+n]);pos+=n
 need(pos==len(data),'LZ4 bounds');return bytes(out)
def ramdisks():
 original=(SRC/'images/vendor_boot.img').read_bytes();h=bytearray(original[:4096]);size=struct.unpack_from('<I',h,24)[0];dtbs=struct.unpack_from('<I',h,2100)[0];ts,tc,es,bc=struct.unpack_from('<IIII',h,2112)
 need(tc==1 and es==108,'unsupported vendor boot table');rd=original[4096:4096+size];dtboff=4096+align(size);dtb=original[dtboff:dtboff+dtbs];taboff=dtboff+align(dtbs);table=bytearray(original[taboff:taboff+ts]);bootconf=original[taboff+align(ts):taboff+align(ts)+bc]
 raw=decode(rd);changed,changes=cpio_patch(raw);need(changes,'no vendor_boot encryption changes');rd=compress(changed,'vendorboot');struct.pack_into('<I',h,24,len(rd));struct.pack_into('<II',table,0,len(rd),0)
 body=bytes(h)+rd+bytes(align(len(rd))-len(rd))+dtb+bytes(align(len(dtb))-len(dtb))+table+bytes(align(len(table))-len(table))+bootconf;body+=bytes(align(len(body))-len(body))
 out=WORK/'vendor_boot.img';out.write_bytes(body)
 info=parse_avb(original);d=next(x for x in info['descriptors'] if struct.unpack_from('>Q',x)[0]==2);n,s=struct.unpack_from('>II',d,56);salt=d[132+n:132+n+s].hex();props=[]
 for q in info['descriptors']:
  if struct.unpack_from('>Q',q)[0]==0:
   kl,vl=struct.unpack_from('>QQ',q,16);props+=['--prop',q[32:32+kl].decode()+':'+q[33+kl:33+kl+vl].decode()]
 run([sys.executable,TOOLS/'avbtool.py','add_hash_footer','--image',out,'--partition_name','vendor_boot','--partition_size',len(original),'--salt',salt,*props])
 # Final recovery is installed by the ZIP, never required before ZIP selection.
 rec=(ROOT/'builder/work/installer-ri3-recovery/images-ziptrust/recovery.img').read_bytes();head,blocks=unpack_boot(rec);raw=b''.join(v for c,v in blocks);changed,rc=cpio_patch(raw);rd=compress(changed,'recovery');hh=bytearray(rec[:4096]);struct.pack_into('<I',hh,12,len(rd));payload=bytes(hh)+rd+bytes(align(len(rd))-len(rd))
 key=serialization.load_pem_private_key((ROOT/'builder/work/installer-ri3-recovery/.private/development-recovery-rsa2048.pem').read_bytes(),None)
 final=recovery_signed(payload,parse_avb(rec),1,key,len(rec));verify_avb(final);(WORK/'recovery.img').write_bytes(final)
 save(WORK/'ramdisk-receipt.json',{'vendor_boot_changes':changes,'recovery_changes':rc,'vendor_boot_sha256':digest(out),'recovery_sha256':hashlib.sha256(final).hexdigest(),'kernel_replaced':False})
def assemble():
 root=(ROOT/'builder/work/installer-ri3-recovery/images-ziptrust/vbmeta.img').read_bytes();a=verify_avb(root);replacements={}
 for name,tag in [('vendor',1),('vendor_boot',2)]:
  img=parse_avb((WORK/(name+'.img')).read_bytes());replacements[name]=next(d for d in img['descriptors'] if struct.unpack_from('>Q',d)[0]==tag)
 ds=[];replaced=[]
 for d in a['descriptors']:
  tag=struct.unpack_from('>Q',d)[0];name=None
  if tag==1:n=struct.unpack_from('>I',d,104)[0];name=d[180:180+n].decode()
  elif tag==2:n=struct.unpack_from('>I',d,56)[0];name=d[132:132+n].decode()
  if name in replacements:d=replacements[name];replaced.append(name)
  ds.append(d)
 need(set(replaced)==set(replacements),'missing root descriptors');key=serialization.load_pem_private_key((ROOT/'builder/work/installer-ri3-recovery/.private/development-root-rsa4096.pem').read_bytes(),None);desc=b''.join(ds);pub=public_blob(key);aux=desc+pub;aux+=bytes(align(len(aux),64)-len(aux));h=list(a['header']);h[4]=len(aux);h[6:16]=[0,32,32,512,len(desc),len(pub),0,0,0,len(desc)];vb=sign_parts(h,aux,key);need(len(vb)<=len(root),'root allocation exceeded');vb+=bytes(len(root)-len(vb));verify_avb(vb);(WORK/'vbmeta.img').write_bytes(vb)
 src=SRC/'images/super.img';out=WORK/'super.img'
 with src.open('rb') as f:m=parse_super_metadata_prefix(f.read(1024*1024))
 part=next(x for x in m['partitions'] if x['name']=='vendor_a');need(len(part['extents'])==1,'vendor extent count')
 with src.open('rb') as f,out.open('xb') as o:
  for b in iter(lambda:f.read(CHUNK),b''):o.write(b)
  o.seek(part['extents'][0]['offset_bytes'])
  with (WORK/'vendor.img').open('rb') as v:
   for b in iter(lambda:v.read(CHUNK),b''):o.write(b)
  o.flush();os.fsync(o.fileno())
 changed={'super','vendor_boot','recovery','vbmeta'};rows=[]
 manifest=json.loads((SRC/'MANIFEST.json').read_text())
 for i in manifest['images']:
  name=Path(i['path']).stem;p=WORK/(name+'.img') if name in changed else SRC/i['path'];h=digest(p)
  if name not in changed:need(h==i['sha256'],'source image mismatch '+name)
  rows.append({'name':name,'path':str(p),'size':p.stat().st_size,'sha256':h,'changed':name in changed,'original_sha256':i['sha256']})
 save(WORK/'images.json',{'images':rows,'source_manifest_sha256':digest(SRC/'MANIFEST.json'),'decrypted':True,'encryption_configuration_changed_with_user_authorization':True,'device_tested':False,'root_flags':a['header'][17]})
 print('IMAGE SET COMPLETE',flush=True)
if __name__=='__main__':
 WORK.mkdir(parents=True,exist_ok=True)
 {'vendor':vendor,'ramdisks':ramdisks,'assemble':assemble}[sys.argv[1]]()
