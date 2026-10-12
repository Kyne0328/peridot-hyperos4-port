#!/usr/bin/env python3
"""Fresh byte and metadata readback of all four authored filesystems in final DEV2."""
import json,pathlib
import rebuild_vendor_dev2 as V
from verify_erofs_tree import verify as verify_simple
R=V.ROOT;stage=R/'candidate-dev2';a=json.loads((stage/'assembly.json').read_text());image=stage/'super.raw.img';records=[]
for partition,folder in [('system','system-dev2'),('vendor','vendor-dev2'),('product','product-metadata'),('mi_ext','mi-ext-metadata')]:
 i=next(x for x in a['inputs'] if x['partition']==partition);V.require(len(i['physical_extents'])==1,'mapped EROFS expects contiguous source');offset,size=i['physical_extents'][0]
 report=stage/(partition+'-filesystem-readback.json');expected=R/folder/'composed-expected.json'
 if partition in ('system','vendor'):
  body=json.loads((R/folder/'reviewed-filesystem.json').read_text());r=V.verify(image,expected,report,offset,body['size']);V.require(r['filesystem_sha256']==body['sha256'],'filesystem prefix changed during assembly')
 else:r=verify_simple(str(image),str(expected),str(report),offset)
 records.append({'partition':partition,'report':str(report),'report_sha256':V.digest(report),'expected_manifest_sha256':V.digest(expected),'logical_partition_sha256':i['sha256'],'entries':r['entries'],'regular_files':r['regular_files']})
V.save(stage/'authored-filesystem-readback.json',{'super_sha256':a['super_sha256'],'all_four_authored_filesystems_verified_from_final_super':True,'reports':records,'timestamps_preserved':False})
print(json.dumps({'status':'all_four_authored_filesystems_verified_from_final_super','reports':records},indent=2))
