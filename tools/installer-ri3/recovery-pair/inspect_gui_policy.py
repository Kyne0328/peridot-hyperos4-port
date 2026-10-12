#!/usr/bin/env python3
"""Read exact GUI resources and flash action sequences; no recovery execution."""
import hashlib,io,json,pathlib,re,runpy,zipfile
ROOT=pathlib.Path.cwd();OUT=ROOT/'09-reports/installer-ri3/recovery-pair';m=runpy.run_path(str(ROOT/'tools/local-recovery/inspect_recovery.py'))
with zipfile.ZipFile(ROOT/'OrangeFox-R12.0_202610011528_crypto-Unofficial-peridot.zip') as z:h,files=m['ramdisk'](z.read('recovery.img'))
report={'xml':{},'resource_archives':{},'related_scripts':{}}
def inspect(name,b):
 t=b.decode('utf-8','replace');ls=t.splitlines();hits=[]
 for i,s in enumerate(ls):
  if re.search('function="(flash|queuezip|clearzipqueue|set|cmd)"|tw_signed_zip_verify|tw_auto_reflashtwrp|ui.zip|custom.theme|load.*theme',s,re.I):
   if 'function="set"' in s and not any(x in s for x in ['tw_signed_zip_verify','tw_auto_reflashtwrp']):continue
   hits.append({'line':i+1,'context':'\n'.join(ls[max(0,i-7):min(len(ls),i+8)])})
 if hits:report['xml'][name]={'sha256':hashlib.sha256(b).hexdigest(),'size':len(b),'hits':hits}
for name,b in files.items():
 if name.endswith('.xml') and any(x in name for x in ['twres','res/','fox']):inspect(name,b)
 if name.endswith('.zip') and any(x in name for x in ['theme','twres','ui.zip']):
  report['resource_archives'][name]={'sha256':hashlib.sha256(b).hexdigest(),'size':len(b)}
  with zipfile.ZipFile(io.BytesIO(b)) as z:
   for i in z.infolist():
    if i.filename.endswith('.xml') and i.file_size<5*1024*1024:inspect(name+'!'+i.filename,z.read(i))
 if name.endswith('.sh') and any(x in b for x in [b'ui.zip',b'theme',b'/sbin']):report['related_scripts'][name]={'sha256':hashlib.sha256(b).hexdigest(),'text':b.decode('utf-8','replace')}
(OUT/'gui-policy-evidence.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'xml':{n:{'sha256':v['sha256'],'size':v['size'],'hits':v['hits']} for n,v in report['xml'].items()},'resource_archives':report['resource_archives']},indent=2))
