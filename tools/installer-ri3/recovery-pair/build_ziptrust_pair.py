#!/usr/bin/env python3
"""Final RI3 variant: preserved no-op hooks plus one approved public ZIP certificate."""
import json,pathlib,struct,zipfile
from build_pair import ROOT,WORK,REPORT,write_exact,run,key,STOCK_ROOT
from pair_format import *
OUT=WORK/'images-ziptrust'
def main():
 prior=json.loads((REPORT/'pair-build.json').read_text());receipt=json.loads((REPORT/'zip-certificate.json').read_text());old=(WORK/'images/recovery.img').read_bytes()
 require(sha(old)==prior['files']['recovery.img']['sha256'],'intermediate recovery mismatch');avb=verify_avb(old);head,blocks=unpack_boot(old);raw=b''.join(r for _,r in blocks);es=cpio_entries(raw)
 name='system/etc/security/otacerts.zip';target=next(e for e in es if e['name']==name);payload=(WORK/'otacerts-ziptrust.zip').read_bytes();require(sha(payload)==receipt['candidate_store_sha256'],'trust store mismatch');pieces=[]
 for e in es:
  if e['name']!=name:pieces.append(raw[e['header_offset']:e['end']]);continue
  h=bytearray(raw[e['header_offset']:e['offset']]);h[54:62]=f'{len(payload):08x}'.encode();part=bytes(h)+payload;part+=bytes(align(len(part),4)-len(part));pieces.append(part)
 pieces.append(raw[es[-1]['end']:]);updated=b''.join(pieces);newes=cpio_entries(updated);require(len(newes)==len(es),'CPIO count changed')
 for a,b in zip(es,newes):
  require(a['name']==b['name'],'CPIO order changed')
  if a['name']==name:
   x=list(a['fields']);x[6]=len(payload);require(b['fields']==x,'trust-store metadata changed unexpectedly')
  else:require(a['fields']==b['fields'] and a['sha256']==b['sha256'],'unrelated CPIO entry changed')
 comp=[];block_receipts=[]
 for i,p in enumerate(range(0,len(updated),MAX_BLOCK)):
  chunk=updated[p:p+MAX_BLOCK]
  if i<len(blocks) and chunk==blocks[i][1]:c=blocks[i][0]
  else:
   src=WORK/'ziptrust-blocks'/f'block-{i}.raw';dst=WORK/'ziptrust-blocks'/f'block-{i}.lz4';write_exact(src,chunk)
   cr=json.loads(run(['wsl.exe','-d','Ubuntu','--cd','/mnt/c/Dev/peridot-hyperos4-port','--','python3','-B','tools/installer-ri3/recovery-pair/lz4_compress.py',src.relative_to(ROOT).as_posix(),dst.relative_to(ROOT).as_posix()]))
   c=dst.read_bytes();require(lz4_decode(c)==chunk,'LZ4 mismatch');block_receipts.append({'index':i,**cr})
  comp.append(struct.pack('<I',len(c))+c)
 ramdisk=b'\x02\x21\x4c\x18'+b''.join(comp);h=bytearray(old[:4096]);struct.pack_into('<I',h,12,len(ramdisk));body=bytes(h)+ramdisk+bytes(align(len(ramdisk))-len(ramdisk))
 rootkey=key(4096,'development-root-rsa4096.pem');reckey=key(2048,'development-recovery-rsa2048.pem');recovery=recovery_signed(body,avb,1,reckey,len(old))
 with zipfile.ZipFile(ROOT/'F6-Global-HyperOS4-DEV2-RI2.zip') as z:root=z.read('images/vbmeta.img')
 require(sha(root)==STOCK_ROOT,'RI2 root mismatch');vbmeta=root_signed(root,public_blob(reckey),rootkey)
 require(vbmeta==(WORK/'images/vbmeta.img').read_bytes(),'unneeded root vbmeta change');verify_avb(recovery);verify_avb(vbmeta)
 _,fb=unpack_boot(recovery);require(b''.join(r for _,r in fb)==updated,'final archive mismatch');require(recovery==recovery_signed(body,avb,1,reckey,len(old)),'signing not reproducible')
 outputs={'recovery.img':recovery,'vbmeta.img':vbmeta,'development-root.avbpubkey':public_blob(rootkey),'development-recovery.avbpubkey':public_blob(reckey)}
 for n,b in outputs.items():write_exact(OUT/n,b)
 final=dict(prior);final['contract']='RI3_RECOVERY_CONTRACT_V2_ZIPTRUST';final['files']={n:{'path':(OUT/n).relative_to(ROOT).as_posix(),'size':len(b),'sha256':sha(b)} for n,b in outputs.items()}
 final['additional_ramdisk_change']={'path':name,'old_sha256':receipt['source_store_sha256'],'new_sha256':receipt['candidate_store_sha256'],'old_size':target['size'],'new_size':len(payload),'existing_certificates_preserved':True,'added_certificate':receipt['added_certificate'],'cpio_metadata_change':'filesize only; later record offsets and compression necessarily change'}
 final['all_non_hook_cpio_bytes_and_metadata_preserved']=False;final['all_unrelated_cpio_entry_metadata_and_payloads_preserved']=True;final['recompressed_blocks_after_zip_trust']=block_receipts
 final['setup_prerequisite']='Freshly boot this exact paired recovery before selecting the ZIP. Native preflight pins live executable, both hooks, configuration, tools and trusted cert store; verifies complete recovery_a identity; requires bounded read-only live tw_auto_reflashtwrp=0 and tw_signed_zip_verify=1. Keep recovery_a identical and recovery_b untouched.'
 (REPORT/'pair-build-ziptrust.json').write_text(json.dumps(final,indent=2)+'\n');print(json.dumps({'files':final['files'],'store':final['additional_ramdisk_change'],'changed_blocks':[x['index'] for x in block_receipts]},indent=2))
if __name__=='__main__':main()
