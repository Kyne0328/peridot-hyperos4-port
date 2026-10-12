#!/usr/bin/env python3
"""Preserve exact vendor contents and metadata for a reviewed exclusion-only fix.

No device interfaces. Frozen DEV1 is read only. Capability metadata is passed to
mkfs rather than installed on the host. Source symlinks are never followed.
"""
from __future__ import annotations
import argparse, collections, hashlib, json, os, pathlib, re, stat, struct, subprocess
from verify_erofs_tree import ErofsImage, DUMP
from payload_stream import hash_range, Invalid

ROOT=pathlib.Path(__file__).resolve().parent
WORK=ROOT/'vendor-dev2'
TREE=WORK/'tree'
SUPER=ROOT/'candidate/super.raw.img'
SOURCE_SHA='c8bf2bf866e08644dd113adf55804bd867a00282346d7d5542ea3206e7eb771b'
SOURCE_SIZE=430030848
PARTITION='vendor'
MKFS=pathlib.Path('/workspace/shared/peridot-cloud/tools/otatools-minimal/bin/mkfs.erofs')

def require(ok,msg):
 if not ok:raise Invalid(msg)
def sha(data):return hashlib.sha256(data).hexdigest()
def digest(path):
 with pathlib.Path(path).open('rb') as f:return hash_range(f,0,os.fstat(f.fileno()).st_size)
def save(path,obj):
 with pathlib.Path(path).open('x') as f:json.dump(obj,f,indent=2);f.write('\n')
def safe_path(root,name):
 require(name=='/' or name.startswith('/'),'expected absolute image path')
 require(name=='/' or all(x not in ('','.','..') for x in name.split('/')[1:]),'noncanonical image path')
 parts=pathlib.PurePosixPath(name).parts[1:]
 require(not any(x in ('','.','..') for x in parts),'unsafe image path')
 p=root.joinpath(*parts)
 for parent in p.parents:
  if parent==root.parent:break
  require(not parent.is_symlink(),'symlink ancestor in host extraction')
 return p
def capability_mask(attrs):
 require(set(attrs)<= {'security.selinux','security.capability'} and 'security.selinux' in attrs,'unhandled xattr')
 if 'security.capability' not in attrs:return 0
 raw=bytes.fromhex(attrs['security.capability'])
 require(len(raw)==20,'unsupported capability size')
 magic,low,inherit_low,high,inherit_high=struct.unpack('<IIIII',raw)
 require(magic==0x02000001 and inherit_low==inherit_high==0,'unsupported capability encoding')
 require(low or high,'unexpected explicit zero capability')
 return low|(high<<32)
def cat(image,offset,nid):
 p=subprocess.run([DUMP,'--cat',f'--nid={nid}',f'--offset={offset}',str(image)],capture_output=True)
 require(p.returncode==0,'dump.erofs failed: '+p.stderr.decode(errors='replace'))
 return p.stdout

def extract():
 require(not TREE.exists(),'refuse existing extraction tree')
 src=json.loads((WORK/'source-metadata.json').read_text());part=src['source_partition']
 require(part['sha256']==SOURCE_SHA and part['size_bytes']==SOURCE_SIZE,'vendor source identity mismatch')
 require(len(part['physical_extents'])==1,'unexpected vendor extents')
 offset,size=part['physical_extents'][0]
 with SUPER.open('rb') as f:require(hash_range(f,offset,size)==SOURCE_SHA,'frozen vendor bytes changed')
 image=ErofsImage(SUPER,offset);entries=image.inventory()
 require(entries==src['entries'],'vendor inode inventory changed')
 TREE.mkdir();by_inode={};hardlinks=collections.defaultdict(list)
 for i in sorted(entries,key=lambda i:(i['path'].count('/'),i['path'])):
  name=i['path'];path=safe_path(TREE,name);mode=i['mode'];capability_mask(i['xattrs'])
  if stat.S_ISDIR(mode):path.mkdir(exist_ok=True)
  elif stat.S_ISREG(mode):
   if i['nid'] in by_inode:
    os.link(by_inode[i['nid']],path);datahash=digest(path)
   else:
    p=subprocess.Popen([DUMP,'--cat',f'--nid={i["nid"]}',f'--offset={offset}',str(SUPER)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    h=hashlib.sha256();n=0
    with path.open('xb') as f:
     while b:=p.stdout.read(4*1024**2):f.write(b);h.update(b);n+=len(b)
    err=p.stderr.read();code=p.wait();p.stdout.close();p.stderr.close()
    require(code==0 and n==i['size'],'file extraction failed '+name+' '+err.decode(errors='replace'))
    datahash=h.hexdigest();by_inode[i['nid']]=path
   i['sha256']=datahash;hardlinks[i['nid']].append(name)
  elif stat.S_ISLNK(mode):
   data=cat(SUPER,offset,i['nid']);require(len(data)==i['size'] and b'\0' not in data,'invalid symlink bytes')
   target=data.decode();os.symlink(target,path);i['symlink_target']=target;i['sha256']=sha(data)
  else:raise Invalid('unsupported inode type '+name)
 # Ownership/mode/labels/capabilities stay declarative and do not alter host security.
 save(WORK/'source-expected.json',{'source_sha256':SOURCE_SHA,'entries':entries,'hardlink_groups':[x for x in hardlinks.values() if len(x)>1]})
 image.close();print(json.dumps({'status':'exact_source_tree_extracted','partition':PARTITION,'entries':len(entries),'regular_files':sum(stat.S_ISREG(i['mode']) for i in entries),'symlinks':sum(stat.S_ISLNK(i['mode']) for i in entries)}),flush=True)

def make_metadata(entries,partition='vendor'):
 require(partition in ('vendor','system'),'unsupported filesystem partition')
 roots=[i for i in entries if i['path']=='/'];require(len(roots)==1,'exactly one root inode required');root=roots[0]
 fs=[f"/ {root['uid']} {root['gid']} {root['mode']&0o7777:04o} capabilities=0x{capability_mask(root['xattrs']):x}"];contexts=[]
 for i in entries:
  name=('vendor'+('' if i['path']=='/' else i['path'])) if partition=='vendor' else i['path'].lstrip('/')
  cap=capability_mask(i['xattrs'])
  if name:fs.append(f"{name} {i['uid']} {i['gid']} {i['mode']&0o7777:04o} capabilities=0x{cap:x}")
  context=bytes.fromhex(i['xattrs']['security.selinux']).decode().rstrip('\0')
  require('\n' not in context and ' ' not in context,'invalid SELinux context')
  contexts.append('/'+re.escape(name)+' '+context)
 (WORK/'composed_fs_config').write_text('\n'.join(sorted(fs))+'\n')
 (WORK/'composed_file_contexts').write_text('\n'.join(sorted(contexts))+'\n')

def verify(image,expected,report,offset=0,filesystem_size=None):
 require(offset>=0 and (not offset or filesystem_size is not None),'mapped readback requires explicit filesystem size')
 backing_size=pathlib.Path(image).stat().st_size
 if filesystem_size is None:filesystem_size=backing_size
 require(filesystem_size>0 and offset+filesystem_size<=backing_size,'filesystem span outside backing file')
 exp=json.loads(pathlib.Path(expected).read_text());e=ErofsImage(image,offset);actual=e.inventory();a={i['path']:i for i in actual};old={i['path']:i for i in exp['entries']}
 require(len(a)==len(actual) and len(old)==len(exp['entries']),'duplicate image paths')
 require(a.keys()==old.keys(),'vendor path set changed');files=[];links=[]
 for name,i in sorted(old.items()):
  j=a[name]
  for key in ('mode','uid','gid','xattrs'):require(i[key]==j[key],f'vendor metadata mismatch {name}: {key}')
  if stat.S_ISREG(i['mode']) or stat.S_ISLNK(i['mode']):
   data=cat(image,offset,j['nid']);require(len(data)==i['size'] and sha(data)==i['sha256'],'filesystem content differs '+name)
   if stat.S_ISLNK(i['mode']):require(data.decode()==i['symlink_target'],'symlink target differs');links.append(name)
   else:files.append({'path':name,'size':len(data),'sha256':sha(data)})
 for group in exp.get('hardlink_groups',[]):require(len({a[n]['nid'] for n in group})==1,'hardlink group broken')
 with pathlib.Path(image).open('rb') as f:image_sha=hash_range(f,offset,filesystem_size)
 result={'status':'verified','backing_path':str(pathlib.Path(image).resolve()),'backing_offset':offset,'filesystem_sha256':image_sha,'filesystem_size_bytes':filesystem_size,'expected_manifest':{'path':str(pathlib.Path(expected).resolve()),'sha256':digest(expected)},'entries':len(actual),'regular_files':len(files),'symlinks':len(links),'all_file_bytes_sha256_verified':True,'all_uid_gid_modes_selinux_xattrs_verified':True,'all_regular_and_symlink_bytes_verified':True,'all_uid_gid_modes_labels_capability_xattrs_verified':True,'hardlink_groups_preserved':True,'timestamps_preserved':False,'files':files}
 save(report,result);e.close();print(json.dumps({k:v for k,v in result.items() if k!='files'}),flush=True);return result

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='action',required=True);sub.add_parser('extract');v=sub.add_parser('verify');v.add_argument('image');v.add_argument('expected');v.add_argument('report');a=p.parse_args()
 if a.action=='extract':extract()
 else:verify(a.image,a.expected,a.report)
