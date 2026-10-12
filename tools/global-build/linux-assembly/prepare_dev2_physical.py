#!/usr/bin/env python3
"""Bind unchanged exact-base physical images and newly signed metadata to DEV2."""
import copy,json,os,pathlib
from assemble_dev2_from_frozen import ROOT,digest,require
from super_stream import save,inspect_all
STOCK_REPORT_SHA='a41b4fae8b76764a51dcbad043c7742aa958b29aad92061cc22f25b793ac93a4'
META_REPORT_SHA='e6c85492095ecde6b46af6fdf5f60c16dd9fe4129684871d52e063ae0aacf65f'
PUBLIC_SHA='7728e30f50bfa5cea165f473175a08803f6a8346642b5aa10913e9d9e6defef6'
def main():
 stage=ROOT/'candidate-dev2';old=ROOT/'candidate';meta_dir=ROOT/'final-avb-dev2';a=json.loads((stage/'assembly.json').read_text());require(a['status']=='byte_complete_offline_candidate','super incomplete');require(inspect_all(stage/'super.raw.img')==a['layout'],'metadata changed')
 require(digest(old/'physical/stock-physical-integrity.json')==STOCK_REPORT_SHA,'stock physical source report changed');physical=json.loads((old/'physical/stock-physical-integrity.json').read_text());require(len(physical['images'])==29 and len({i['partition'] for i in physical['images']})==29,'wrong physical set')
 require(digest(meta_dir/'metadata-signing-report.json')==META_REPORT_SHA,'signed metadata report changed');metadata=json.loads((meta_dir/'metadata-signing-report.json').read_text());require(metadata['build_id']=='DEV2' and set(metadata['images'])=={'vbmeta','vbmeta_system'},'wrong metadata outputs')
 out=stage/'physical';require(not out.exists(),'physical outputs already exist');out.mkdir();records=[]
 for i in physical['images']:
  name=i['partition'];require('/' not in name and '..' not in name,'invalid physical name');source=old/'physical'/(name+'.img');require(source.stat().st_size==i['size'] and digest(source)==i['sha256'],'stock physical image changed '+name);dest=out/source.name;os.link(source,dest);r=copy.deepcopy(i);r.update(output=str(dest),frozen_source_path=str(source),hardlinked_byte_identical=True);records.append(r)
 for name,info in metadata['images'].items():
  source=meta_dir/(name+'.img');expected=info['output'];require(source.stat().st_size==expected['size'] and digest(source)==expected['sha256'],'signed metadata bytes changed');os.link(source,out/source.name)
 physical['images']=records;physical['source_report_sha256']=STOCK_REPORT_SHA;save(out/'stock-physical-integrity.json',physical)
 pub=old/'development.avbpubkey';require(digest(pub)==PUBLIC_SHA,'public key changed');os.link(pub,stage/pub.name)
 images={}
 for i in a['inputs']:images[i['partition']]={'path':str(stage/'super.raw.img'),'size':i['size_bytes'],'expected_sha256':i['sha256'],'extents':[{'offset':o,'size':s} for o,s in i['physical_extents']]}
 by={i['partition']:i for i in records}
 for name in ['boot','recovery','countrycode','dtbo','init_boot','vendor_boot','vbmeta','vbmeta_system']:
  i=metadata['images'][name]['output'] if name in metadata['images'] else by[name];images[name]={'path':str(out/(name+'.img')),'size':i['size'],'expected_sha256':i['sha256']}
 save(stage/'avb-image-map.raw.json',{'images':images,'super_sha256':a['super_sha256'],'purpose':'Exact DEV2 mapped verification input; requires explicit authoring reports'})
 print(json.dumps({'status':'physical_images_and_raw_map_ready','stock_physical_images':29,'development_metadata_images':2,'avb_mapped_images':len(images)}))
if __name__=='__main__':main()
