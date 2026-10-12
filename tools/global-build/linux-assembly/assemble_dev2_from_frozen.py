#!/usr/bin/env python3
"""Construct a fresh same-layout candidate from immutable DEV1 and reviewed vendor.

The original source archive hashes remain provenance. An explicit new vendor
authoring receipt replaces only that source-image hash. DEV1 is never opened for
writing. Staged output is not promoted until all spans and six LP copies pass.
"""
import argparse,copy,hashlib,importlib.util,json,os,pathlib
from payload_stream import hash_range,exact,CHUNK,Invalid
from super_stream import inspect_all,verify_image_span,save
ROOT=pathlib.Path(__file__).resolve().parent
DEV1=ROOT/'candidate'
DEV1_SHA='66575ccfb8998539fbac2a8a12d2450445566024f89ee1d750e29e89be5094f7'
DEV1_ASSEMBLY_SHA='53436b756367ccfdef5c5cfdb10002c9247c173457c671c567c2239471bafce3'
PARTITIONS={'system','system_ext','product','mi_ext','vendor','odm','vendor_dlkm','system_dlkm'}
STOCK_VENDOR_SHA='c8bf2bf866e08644dd113adf55804bd867a00282346d7d5542ea3206e7eb771b'
POLICY_SOURCES={'vendor':(STOCK_VENDOR_SHA,430030848),'system':('88142dce1788b9e105ebbc97b1945c0071fb840f827545a57c213b2e6298c32d',751255552)}
def require(ok,message):
 if not ok:raise Invalid(message)
def digest(path):
 with pathlib.Path(path).open('rb') as f:return hash_range(f,0,os.fstat(f.fileno()).st_size)
def copy_exact(src,dst,n):
 while n:
  b=exact(src,min(CHUNK,n));dst.write(b);n-=len(b)
def bind_inputs_to_layout(original,layout):
 inputs=original['inputs'];names=[i['partition'] for i in inputs]
 require(len(names)==len(PARTITIONS) and set(names)==PARTITIONS,'unexpected or duplicate logical input names')
 actual={p['name']:p for p in layout['partitions']}
 require(len(actual)==len(layout['partitions']) and set(actual)=={n+'_'+s for n in PARTITIONS for s in ('a','b')},'unexpected or duplicate layout names')
 for i in inputs:
  p=actual[i['partition']+'_a'];empty=actual[i['partition']+'_b']
  require(i['size_bytes']==p['size_bytes'],'input size differs from actual LP metadata')
  require(i['physical_extents']==[[e['offset_bytes'],e['size_bytes']] for e in p['extents']],'input extents differ from actual LP metadata')
  require(empty['size_bytes']==0 and not empty['extents'],'inactive allocation is not empty')
def bind_authoring_receipt(authored,vendor_sha,review,review_sha,partition='vendor'):
 require(partition in POLICY_SOURCES,'unreviewed authored partition')
 expected_source,expected_size=POLICY_SOURCES[partition]
 require(authored.get('schema')==2 and authored.get('build_id')=='DEV2' and authored.get('partition')==partition,'wrong authoring receipt scope')
 require(authored.get('source_partition_sha256')==expected_source,'wrong original filesystem source')
 require(authored.get('composition_review_approved') is True,'vendor review approval not recorded')
 bound=authored.get('composition_review',{})
 require(bound.get('sha256')==review_sha and pathlib.Path(bound.get('path','')).resolve()==pathlib.Path(review).resolve(),'signing receipt bound to different composition review')
 require(authored['output']['sha256']==vendor_sha and authored['output']['size']==expected_size,'signature receipt identity mismatch')
def validate_complete_evidence(review,changes):
 validator=ROOT/'avb-global-dev2/dev2_avb.py';spec=importlib.util.spec_from_file_location('dev2_assembly_evidence',validator);v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)
 profile=v.checked(v.LOCK['source_profile']);reference=v.ref(review);approval=v.validate_composition_approval(reference,profile)
 require(set(changes)==set(approval['partitions']),'replacement set omits or adds an approved policy partition')
 for partition,change in changes.items():
  report=v.validate_authored_report(v.ref(change['report']),profile,partition)
  require(v.same_ref(report['approval'],reference),'authored partitions use different composition receipts')
 return {'validator_path':str(validator),'validator_sha256':digest(validator),'composition_review':reference,'reviewed_partitions':approval['partitions'],'all_independent_semantic_and_readback_evidence_validated':True}
def build(vendor,vendor_sha,signing_report,signing_report_sha,review,review_sha,output,system=None,system_sha=None,system_report=None,system_report_sha=None):
 vendor=pathlib.Path(vendor);signing_report=pathlib.Path(signing_report);review=pathlib.Path(review);output=pathlib.Path(output)
 require(not output.exists(),'refuse existing candidate directory')
 require(digest(signing_report)==signing_report_sha and digest(review)==review_sha,'review/signing report identity changed')
 authored=json.loads(signing_report.read_text())
 bind_authoring_receipt(authored,vendor_sha,review,review_sha)
 require(vendor.stat().st_size==430030848 and digest(vendor)==vendor_sha,'reviewed vendor image identity mismatch')
 changes={'vendor':{'image':vendor,'sha256':vendor_sha,'report':signing_report,'report_sha256':signing_report_sha}}
 if system is not None:
  require(all([system_sha,system_report,system_report_sha]),'incomplete system replacement inputs')
  sp=pathlib.Path(system);sr=pathlib.Path(system_report);require(digest(sr)==system_report_sha,'system report identity changed')
  bind_authoring_receipt(json.loads(sr.read_text()),system_sha,review,review_sha,'system')
  require(sp.stat().st_size==POLICY_SOURCES['system'][1] and digest(sp)==system_sha,'reviewed system image identity mismatch')
  changes['system']={'image':sp,'sha256':system_sha,'report':sr,'report_sha256':system_report_sha}
 else:require(not any([system_sha,system_report,system_report_sha]),'system arguments without image')
 evidence_validation=validate_complete_evidence(review,changes)
 require(digest(DEV1/'assembly.json')==DEV1_ASSEMBLY_SHA,'frozen assembly report changed')
 original=json.loads((DEV1/'assembly.json').read_text());require(original['super_sha256']==DEV1_SHA,'unexpected source super identity')
 source=DEV1/'super.raw.img';require(digest(source)==DEV1_SHA,'frozen source super changed')
 layout=inspect_all(source);require(layout==original['layout'],'frozen metadata does not match report')
 bind_inputs_to_layout(original,layout)
 replacements=[i for i in original['inputs'] if i['partition'] in changes]
 require(len(replacements)==len(changes),'replacement input missing/duplicate')
 for i in replacements:require(i['size_bytes']==changes[i['partition']]['image'].stat().st_size,'replacement changes partition allocation')
 output.mkdir();partial=output/'super.raw.img.partial';final=output/'super.raw.img'
 with source.open('rb') as src,partial.open('x+b') as dst:
  copy_exact(src,dst,original['super_size_bytes']);dst.flush();os.fsync(dst.fileno())
  require(hash_range(dst,0,original['super_size_bytes'])==DEV1_SHA,'fresh copy failed full source hash')
  for i in replacements:
   with changes[i['partition']]['image'].open('rb') as replacement:
    for off,size in i['physical_extents']:dst.seek(off);copy_exact(replacement,dst,size)
  dst.flush();os.fsync(dst.fileno());complete=[]
  for i in original['inputs']:
   expected=changes[i['partition']]['sha256'] if i['partition'] in changes else i['sha256']
   require(verify_image_span(dst,i['physical_extents'])==expected,'new image span hash mismatch '+i['partition'])
   complete.append({'partition':i['partition'],'sha256':expected,'size':i['size_bytes'],'verified_in_super':True})
  result=copy.deepcopy(original);result['super_sha256']=hash_range(dst,0,original['super_size_bytes'])
 require(inspect_all(partial)==layout,'layout changed during copy/replace')
 for i in result['inputs']:
  if i['partition'] in changes:
   c=changes[i['partition']]
   i.update(source='rebuilt_'+i['partition'],source_image_sha256=i['sha256'],sha256=c['sha256'],source_path=str(c['image'].resolve()),mutation='reviewed_exclusion_only_selinux_compatibility_fix',authoring_report=str(c['report'].resolve()),authoring_report_sha256=c['report_sha256'],composition_review=str(review.resolve()),composition_review_sha256=review_sha)
 result.update(schema_version=2,status='byte_complete_offline_candidate',completed=complete,partial_output=str(partial),final_output=str(final),source_frozen_candidate={'path':str(source),'sha256':DEV1_SHA,'status':'superseded_security_hold'},policy_evidence_validation=evidence_validation,all_partition_sha256_verified=True,all_six_metadata_copies_verified=True,production_release=False,device_boot_tested=False,flash_recommended=False)
 require(digest(source)==DEV1_SHA,'source super changed during assembly')
 partial.rename(final);save(output/'assembly.json',result)
 print(json.dumps({'status':result['status'],'super_sha256':result['super_sha256'],'size':result['super_size_bytes']}),flush=True)
 return result
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for field in ['vendor','vendor-sha256','signing-report','signing-report-sha256','review','review-sha256','output']:p.add_argument('--'+field,required=True)
 for field in ['system','system-sha256','system-signing-report','system-signing-report-sha256']:p.add_argument('--'+field)
 a=p.parse_args();build(a.vendor,a.vendor_sha256,a.signing_report,a.signing_report_sha256,a.review,a.review_sha256,a.output,a.system,a.system_sha256,a.system_signing_report,a.system_signing_report_sha256)
