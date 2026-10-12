#!/usr/bin/env python3
"""Create and validate an offline mixed-source raw super candidate without duplicates.

Fresh staging directories only. All source partitions must be full-data OTAs with
SHA256 pins. Product is staged first; its separate generated intermediate can be
retired after byte verification, before streaming remaining partitions.
"""
from __future__ import annotations
import argparse,hashlib,json,os,stat,struct,subprocess,sys
from pathlib import Path
sys.path.insert(0,'/workspace/shared/peridot-global-builder/builder')
from peridot_builder.lp import parse_super_metadata_prefix
from payload_stream import Payload,Invalid,hash_range,CHUNK,exact
ROOT=Path(__file__).resolve().parent
LPM=Path('/workspace/shared/peridot-cloud/tools/otatools-minimal/bin/lpmake')
SOURCES={
 'stock':('/workspace/shared/peridot-global-base/peridot_global_OS3.0.303.0.WNPMIXM.zip','13958bfdfcbaf72709302b6d4806a39e55ed9bd72e23d5a53dbf5606c52340b5'),
 'donor':('/workspace/shared/peridot-regional-research/pudding_global_OS4.0.0.9.XPCMIXM.zip','b6bc69ddddc7750a4e453c514fd945ca22d166c5ab0704d955b0e6ab81ac5dbd')}

def save(path,data):
 tmp=path.with_suffix(path.suffix+'.new')
 with tmp.open('x') as f:json.dump(data,f,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
 os.replace(tmp,path)

def decode_metadata_sparse(data):
 if len(data)<28:raise Invalid('short sparse header')
 magic,major,minor,fh,ch,bs,blocks,chunks,crc=struct.unpack_from('<IHHHHIIII',data)
 if magic!=0xed26ff3a or major!=1 or minor!=0 or fh!=28 or ch!=12 or bs!=4096 or blocks*bs!=9126805504 or chunks>100:raise Invalid('unexpected metadata sparse header')
 out=bytearray(1048576);pos=fh;logical=0
 for _ in range(chunks):
  if pos+ch>len(data):raise Invalid('short sparse chunk header')
  kind,res,count,total=struct.unpack_from('<HHII',data,pos);n=count*bs;start=pos+ch;end=pos+total
  if total<ch or end>len(data) or logical+n>blocks*bs:raise Invalid('sparse chunk out of bounds')
  take=max(0,min(n,len(out)-logical))
  if kind==0xcac1:
   if total!=ch+n:raise Invalid('raw sparse chunk length mismatch')
   if take:out[logical:logical+take]=data[start:start+take]
   if any(data[start+take:end]):raise Invalid('nonzero metadata outside prefix')
  elif kind==0xcac2:
   if total!=ch+4:raise Invalid('fill chunk length mismatch')
   word=data[start:end]
   if take:out[logical:logical+take]=word*(take//4)
   if n>take and any(word):raise Invalid('nonzero fill beyond metadata prefix')
  elif kind==0xcac3:
   if total!=ch:raise Invalid('DONT_CARE length mismatch')
  else:raise Invalid('unsupported sparse metadata chunk')
  logical+=n;pos=end
 if pos!=len(data) or logical!=blocks*bs:raise Invalid('sparse metadata coverage mismatch')
 return bytes(out)

def inspect_all(path):
 with Path(path).open('rb') as f:raw=f.read(1024*1024)
 if len(raw)<12288:raise Invalid('short super metadata')
 copies=[]
 for off in (4096,8192):
  magic,n=struct.unpack_from('<II',raw,off)
  if magic!=0x616c4467 or n!=52:raise Invalid('invalid geometry')
  geo=bytearray(raw[off:off+n]);h=geo[8:40];geo[8:40]=bytes(32)
  if hashlib.sha256(geo).digest()!=h:raise Invalid('geometry checksum mismatch')
  copies.append(raw[off:off+n])
 if copies[0]!=copies[1]:raise Invalid('geometry copies differ')
 maximum,slots,bs=struct.unpack_from('<III',raw,4096+40)
 if maximum!=65536 or slots!=3 or bs!=4096:raise Invalid('unexpected verified peridot geometry')
 if len(raw)<12288+2*slots*maximum:raise Invalid('short metadata copies')
 reports=[];tables=[]
 for index in range(2*slots):
  off=12288+index*maximum;buffer=bytearray(raw[:12288+maximum]);buffer[12288:]=raw[off:off+maximum]
  meta=parse_super_metadata_prefix(bytes(buffer));tables.append(buffer[12288:]);reports.append({'slot':index%slots,'backup':index>=slots,'offset':off,'verified':True,'metadata_sha256':hashlib.sha256(tables[-1]).hexdigest()})
 if len(set(bytes(x) for x in tables))!=1:raise Invalid('metadata slot copies differ')
 if meta['header']['flags']!=1:raise Invalid('Virtual A/B flag mismatch')
 devs=meta['block_devices']
 if len(devs)!=1 or devs[0]['name']!='super' or devs[0]['size_bytes']!=9126805504 or devs[0]['alignment']!=1048576 or devs[0]['alignment_offset']!=0 or devs[0]['first_logical_sector']!=2048:raise Invalid('physical super geometry mismatch')
 ranges=[];names=set();group_sizes={g['name']:0 for g in meta['groups']}
 for p in meta['partitions']:
  if p['name'] in names:raise Invalid('duplicate logical partition')
  names.add(p['name'])
  if p['attributes']!=1:raise Invalid('logical partition readonly attribute changed')
  if p['group_name'] not in group_sizes:raise Invalid('unknown group')
  group_sizes[p['group_name']]+=p['size_bytes']
  for ex in p['extents']:
   start,end=ex['offset_bytes'],ex['offset_bytes']+ex['size_bytes']
   if ex['target_type']!=0 or ex['target_source']!=0 or start<1048576 or end>9126805504:raise Invalid('invalid physical extent')
   ranges.append((start,end,p['name']))
 for a,b in zip(sorted(ranges),sorted(ranges)[1:]):
  if b[0]<a[1]:raise Invalid('physical extents overlap')
 for g in meta['groups']:
  if group_sizes[g['name']]>g['maximum_size']:raise Invalid('group budget exceeded')
 meta['integrity']={'both_geometry_copies_verified':True,'all_six_metadata_copies_verified':True,'all_metadata_copies_identical':True,'physical_extent_bounds_verified':True,'physical_extent_nonoverlap_verified':True,'readonly_attributes_preserved':True,'copies':reports}
 return meta

def prepare(plan_path,geometry_path,product_path,product_sha,stage,mi_ext_path=None,mi_ext_sha=None):
 stage=Path(stage)
 if stage.exists():raise Invalid('stage already exists')
 plan=json.loads(Path(plan_path).read_text());geo=json.loads(Path(geometry_path).read_text())['summary'];product=Path(product_path).resolve()
 with product.open('rb') as f:
  psize=os.fstat(f.fileno()).st_size
  if hash_range(f,0,psize)!=product_sha:raise Invalid('rebuilt product SHA256 mismatch')
 inputs=plan['logical_inputs']
 if {x['partition'] for x in inputs}!={'mi_ext','odm','product','system','system_dlkm','system_ext','vendor','vendor_dlkm'}:raise Invalid('unreviewed logical source map')
 for i in inputs:
  if i['partition']=='product':i.update(source='rebuilt_product',size_bytes=psize,sha256=product_sha,source_path=str(product),mutation='reviewed_product_rebuild')
  elif i['partition']=='mi_ext' and mi_ext_path:
   mp=Path(mi_ext_path).resolve()
   with mp.open('rb') as mf:
    msize=os.fstat(mf.fileno()).st_size
    if msize!=i['size_bytes'] or hash_range(mf,0,msize)!=mi_ext_sha:raise Invalid('reviewed mi_ext source identity mismatch')
   i.update(source='rebuilt_mi_ext',sha256=mi_ext_sha,source_path=str(mp),mutation='reviewed_mi_ext_rebuild')
  elif SOURCES[i['source']][1]!=i['source_archive_sha256']:raise Invalid('source pin mismatch')
 if sum(i['size_bytes'] for i in inputs)>9116319744:raise Invalid('partition sizes exceed group budget')
 stage.mkdir();metadata=stage/'super.metadata';sparse_metadata=stage/'super.metadata.sparse';partial=stage/'super.raw.img.partial'
 args=['--metadata-size',str(geo['metadata_max_size']),'--metadata-slots',str(geo['metadata_slot_count']),'--super-name','super','--device',f"super:{geo['physical_super_size']}:{geo['alignment']}:{geo['alignment_offset']}",'--virtual-ab']
 for g in geo['groups']:
  if g['name']!='default':args+=['--group',f"{g['name']}:{g['maximum_size']}"]
 for i in inputs:
  for slot in ('a','b'):args+=['--partition',f"{i['partition']}_{slot}:readonly:{i['size_bytes'] if slot=='a' else 0}:qti_dynamic_partitions_{slot}"]
 args+=['--sparse','--force-full-image','--output',str(sparse_metadata)]
 process=subprocess.run([str(LPM),*args],capture_output=True,text=True)
 (stage/'lpmake.stdout').write_text(process.stdout);(stage/'lpmake.stderr').write_text(process.stderr)
 if process.returncode:raise Invalid('lpmake metadata generation failed: '+process.stderr)
 metadata.write_bytes(decode_metadata_sparse(sparse_metadata.read_bytes()))
 meta=inspect_all(metadata);mapping={p['name']:p for p in meta['partitions']}
 for i in inputs:
  p=mapping[i['partition']+'_a']
  if p['size_bytes']!=i['size_bytes']:raise Invalid('lpmake changed partition size')
  i['physical_extents']=[(e['offset_bytes'],e['size_bytes']) for e in p['extents']]
  if mapping[i['partition']+'_b']['size_bytes']!=0:raise Invalid('inactive slot not empty')
 with partial.open('x+b') as f:f.write(metadata.read_bytes());f.truncate(geo['physical_super_size']);f.flush();os.fsync(f.fileno())
 result={'schema_version':1,'status':'layout_ready','production_release':False,'device_boot_tested':False,'flash_recommended':False,'source_plan':str(Path(plan_path).resolve()),'geometry_reference':str(Path(geometry_path).resolve()),'inputs':inputs,'completed':[],'lpmake_command':[str(LPM),*args],'layout':meta,'source_archives':SOURCES,'partial_output':str(partial.resolve()),'final_output':str((stage/'super.raw.img').resolve())}
 save(stage/'assembly.json',result)
 return result

def verify_image_span(out,extents):
 h=hashlib.sha256()
 for off,size in extents:
  out.seek(off)
  while size:
   b=exact(out,min(size,CHUNK));h.update(b);size-=len(b)
 return h.hexdigest()

def stage_product(stage,partition='product'):
 stage=Path(stage);r=json.loads((stage/'assembly.json').read_text())
 if partition=='product':
  if r['status']!='layout_ready' or r['completed']:raise Invalid('product staging state mismatch')
 elif partition=='mi_ext':
  if r['status']!='product_staged' or {x['partition'] for x in r['completed']}!={'product'}:raise Invalid('mi_ext staging state mismatch')
 else:raise Invalid('unsupported rebuilt partition')
 i=next(x for x in r['inputs'] if x['partition']==partition);src=Path(i['source_path'])
 with src.open('rb') as f,Path(r['partial_output']).open('r+b') as out:
  if hash_range(f,0,i['size_bytes'])!=i['sha256']:raise Invalid('product source SHA256 changed')
  f.seek(0)
  for off,size in i['physical_extents']:
   out.seek(off)
   while size:
    b=exact(f,min(CHUNK,size));out.write(b);size-=len(b)
  out.flush();os.fsync(out.fileno())
  if verify_image_span(out,i['physical_extents'])!=i['sha256']:raise Invalid('product span SHA256 mismatch')
 r['completed'].append({'partition':partition,'sha256':i['sha256'],'size':i['size_bytes'],'verified_in_super':True});r['status']='product_staged' if partition=='product' else 'rebuilt_staged'
 save(stage/'assembly.json',r);return r

def finish(stage):
 stage=Path(stage);r=json.loads((stage/'assembly.json').read_text())
 if r['status'] not in ('product_staged','rebuilt_staged','streaming'):raise Invalid('assembly not in streaming state')
 sources={};completed={i['partition'] for i in r['completed']}
 try:
  with Path(r['partial_output']).open('r+b') as out:
   for i in r['inputs']:
    if i['partition'] in completed:
     if verify_image_span(out,i['physical_extents'])!=i['sha256']:raise Invalid('previous span changed')
     continue
    source=i['source']
    if source.startswith('rebuilt_'):raise Invalid('rebuilt partition must be staged first')
    if source not in sources:sources[source]=Payload(*SOURCES[source])
    payload=sources[source];part=payload.partitions[i['partition']]
    if part.size!=i['size_bytes'] or part.digest.hex()!=i['sha256']:raise Invalid('plan differs from pinned OTA manifest')
    rec=payload.stream(i['partition'],out,i['physical_extents']);rec['verified_in_super']=True;r['completed'].append(rec);r['status']='streaming';save(stage/'assembly.json',r);print(json.dumps({'partition':i['partition'],'status':'verified','size':part.size}),flush=True)
   for i in r['inputs']:
    if verify_image_span(out,i['physical_extents'])!=i['sha256']:raise Invalid('final span hash mismatch')
   meta=inspect_all(r['partial_output'])
   if meta!=r['layout']:raise Invalid('super metadata changed during stream')
   r['super_sha256']=hash_range(out,0,9126805504);r['super_size_bytes']=9126805504
  final=Path(r['final_output'])
  if final.exists():raise Invalid('refuse final overwrite')
  Path(r['partial_output']).rename(final);r['status']='byte_complete_offline_candidate';r['all_partition_sha256_verified']=True;r['all_six_metadata_copies_verified']=True;save(stage/'assembly.json',r)
  return r
 finally:
  for p in sources.values():p.close()

def physical_images(stage,source_images,output):
 stage=Path(stage);r=json.loads((stage/'assembly.json').read_text())
 if r['status']!='byte_complete_offline_candidate':raise Invalid('super must finish before physical packaging')
 outdir=Path(output)
 if outdir.exists():raise Invalid('physical output already exists')
 outdir.mkdir(parents=True);stock=Payload(*SOURCES['stock']);records=[];dynamic={i['partition'] for i in r['inputs']}
 try:
  for name,p in stock.partitions.items():
   if name in dynamic or name in ('vbmeta','vbmeta_system'):continue
   dest=outdir/(name+'.img');existing=Path(source_images)/(name+'.img')
   if existing.is_file():
    with existing.open('rb') as f:
     if existing.stat().st_size!=p.size or hash_range(f,0,p.size)!=p.digest.hex():raise Invalid('existing physical source mismatch '+name)
    os.link(existing,dest);rec={'partition':name,'size':p.size,'sha256':p.digest.hex(),'source_archive_sha256':stock.sha256,'source_image_hardlinked':str(existing.resolve()),'operation_and_partition_hash_previously_verified':True}
   else:
    part=dest.with_suffix('.img.partial')
    with part.open('x+b') as f:f.truncate(p.size);rec=stock.stream(name,f)
    part.rename(dest)
   rec['output']=str(dest.resolve());records.append(rec);print(json.dumps({'physical_partition':name,'size':p.size,'status':'source_identity_verified'}),flush=True)
  save(outdir/'stock-physical-integrity.json',{'source_archive_sha256':stock.sha256,'all_images_byte_identical_to_target_base':True,'stock_vbmeta_excluded_new_metadata_required':True,'images':records})
 finally:stock.close()
 return records

if __name__=='__main__':
 a=argparse.ArgumentParser(description=__doc__);sub=a.add_subparsers(dest='cmd',required=True)
 p=sub.add_parser('prepare');p.add_argument('--plan',required=True);p.add_argument('--geometry',required=True);p.add_argument('--product',required=True);p.add_argument('--product-sha256',required=True);p.add_argument('--stage',required=True);p.add_argument('--mi-ext');p.add_argument('--mi-ext-sha256')
 for name in ('stage-product','stage-mi-ext','finish','inspect'):
  p=sub.add_parser(name);p.add_argument('--stage',required=True)
 p=sub.add_parser('physical');p.add_argument('--stage',required=True);p.add_argument('--source-images',required=True);p.add_argument('--output',required=True)
 x=a.parse_args()
 if x.cmd=='prepare':r=prepare(x.plan,x.geometry,x.product,x.product_sha256,x.stage,x.mi_ext,x.mi_ext_sha256)
 elif x.cmd=='stage-product':r=stage_product(x.stage)
 elif x.cmd=='stage-mi-ext':r=stage_product(x.stage,'mi_ext')
 elif x.cmd=='finish':r=finish(x.stage)
 elif x.cmd=='physical':r={'status':'physical_images_verified','images':physical_images(x.stage,x.source_images,x.output)}
 else:r=inspect_all(x.stage)
 print(json.dumps({'status':r.get('status','verified'),'super_sha256':r.get('super_sha256')},indent=2))
