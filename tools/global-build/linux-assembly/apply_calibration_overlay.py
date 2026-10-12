#!/usr/bin/env python3
"""Install only the separately reviewed, development-signed calibration overlay."""
import copy,hashlib,json,pathlib,shutil,sys
from compose_product import write_metadata
R=pathlib.Path(__file__).resolve().parent
SRC=R/'avb-global/calibration-signing/F6Calibration-DEV-TESTKEY.apk'
SHA='e7aeabd02cd53ec14feae8139b8cfac4fa89e3cd65fefe0cb7c2865d1ce727c1'
NAME='/overlay/F6Calibration-DEV-TESTKEY.apk'
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 if digest(SRC)!=SHA:raise ValueError('signed calibration hash changed')
 original=R/'product-work/product/overlay/AospFrameworkResOverlay.apk'
 if digest(original)!='80c5f2694bf27c30dfc7dffa51507bf1e12aa1e3950287d59f8b61cbcb25882e':raise ValueError('original donor privacy overlay must be retained')
 ep=R/'product-metadata/composed-expected.json';e=json.loads(ep.read_text());entries=e['entries']
 if any(i['path']==NAME for i in entries):raise ValueError('calibration already added')
 meta=copy.deepcopy(next(i for i in entries if i['path']=='/overlay/AospFrameworkResOverlay.apk'));meta.update(path=NAME,nid=None,size=SRC.stat().st_size,sha256=SHA);meta.pop('addr',None);meta.pop('inline',None);meta.pop('layout',None)
 dest=R/'product-work/product'/NAME.lstrip('/')
 if dest.exists():raise ValueError('calibration destination already exists')
 shutil.copyfile(SRC,dest);dest.chmod(meta['mode']&0o7777);entries.append(meta);e['status']='reviewed_privacy_preserving_product_composition_complete';ep.write_text(json.dumps(e,indent=2));write_metadata(entries)
 lp=R/'product-metadata/composition.json';log=json.loads(lp.read_text());log['status']=e['status'];log['entries']=len(entries);log['regular_files']+=1;log['operations'].append({'operation':'add_development_signed_calibration_only_overlay','path':NAME,'source':str(SRC),'sha256':SHA,'size':SRC.stat().st_size,'package':'org.peridot.port.displaycalibration.dev','resource_count':10,'typed_values_verified':393,'apk_contains_executable_code':False,'normal_product_overlay_policy_verified':True,'public_only_negative_policy_rejected':True,'merged_camera_toggle':True,'merged_microphone_toggle':True,'certificate_sha256':'a40da80a59d170caa950cf15c18c454d47a39b26989d8b640ecd745ba71bf5dc','validation_report':'/workspace/shared/peridot-global-builder/review-product/signed-calibration-validation.json'});lp.write_text(json.dumps(log,indent=2));print('Privacy-preserving product composition complete:',len(entries),'entries')
if __name__=='__main__':main()
