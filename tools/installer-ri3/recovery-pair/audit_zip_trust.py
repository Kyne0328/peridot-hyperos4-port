#!/usr/bin/env python3
"""Read-only discovery of the exact legacy ZIP verifier and certificate store."""
import ast,hashlib,json,lzma,pathlib,re,runpy,struct,zipfile
ROOT=pathlib.Path.cwd();OUT=ROOT/'09-reports/installer-ri3/recovery-pair';source=ROOT/'tools/install-readiness-launcher/audit_launcher.py'
tree=ast.parse(source.read_text());env={};exec(compile(ast.Module(body=[n for n in tree.body if isinstance(n,(ast.Import,ast.ImportFrom,ast.FunctionDef))],type_ignores=[]),str(source),'exec'),env)
env['rx']=re.compile('TWinstall_zip|verify_file|verify_package|VerifyPackage|VerifySignature|LoadKeys|load_keys|load_key|VerifyWhole|LoadCertificate|verify_otapackage')
env['sha_rx']=re.compile('LoadKeys|verify|Verify|certificate|RSA|PKCS|SHA|EVP')
p=ROOT/'OrangeFox-R12.0_202610011528_crypto-Unofficial-peridot.zip'
with p.open('rb') as f:assert hashlib.file_digest(f,'sha256').hexdigest()=='b04ec7c0add35457fe7f53e308acf23cdf0a62d8d4ed05f1392ac23e6cbb5cf4'
with zipfile.ZipFile(p) as z:image=z.read('recovery.img')
m=runpy.run_path(str(ROOT/'tools/local-recovery/inspect_recovery.py'));h,files=m['ramdisk'](image)
report={'stores':{},'binaries':{},'aliases':{},'untrusted_code_executed':False}
for n,b in files.items():
 if re.search('otacert|(^|/)keys$|(^|/)(cert|certificate)',n,re.I):
  report['stores'][n]={'size':len(b),'sha256':hashlib.sha256(b).hexdigest(),'prefix_hex':b[:24].hex(),'text':b.decode('utf-8','replace') if len(b)<12000 and b'\0' not in b else None}
for n in ['sbin','system/bin/twrp','sbin/twrp','sbin/afterromflash.sh','system/bin/afterromflash.sh']:
 if n in files:report['aliases'][n]={'size':len(files[n]),'text':files[n].decode('utf-8','replace') if len(files[n])<500 else None}
 else:report['aliases'][n]=None
for n in ['system/bin/recovery','system/lib64/libaosprecovery.so','system/bin/twrp']:
 b=files[n];a=env['analyze'](b);a['trust_strings']=[];e,ss,ns=env['sections'](b)
 for mt in re.finditer(rb'[ -~]{4,}',b):
  t=mt[0].decode()
  if re.search('otacert|/keys|twcmd|twoutput|signature|certificate|signer|PKCS|signed_zip|getval',t,re.I):
   for s in ss:
    if s[1]!=8 and s[4]<=mt.start()<s[4]+s[5]:a['trust_strings'].append({'address':hex(s[3]+mt.start()-s[4]),'text':t});break
 report['binaries'][n]=a
(OUT/'zip-trust-evidence.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'stores':report['stores'],'aliases':report['aliases'],'binaries':{n:{'functions':[(f,v['address'],v['size']) for f,v in b['functions'].items()],'trust_strings':b['trust_strings']} for n,b in report['binaries'].items()}},indent=2))
