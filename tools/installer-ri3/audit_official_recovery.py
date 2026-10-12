"""Static official recovery audit: parse immutable archive, do not execute embedded code."""
import hashlib,json,pathlib,runpy,zipfile,re
ROOT=pathlib.Path(__file__).resolve().parents[2]
P=ROOT/'downloads/recovery-audit/OrangeFox-R12.0_7_crypto-peridot.zip'
OUT=ROOT/'09-reports/installer-ri3'
PIN='f0f04589b68fe096b6ff1fb522bc1b3598d1cb15d3692615b5e9607de30e62b0'
assert P.stat().st_size==56565915
with P.open('rb') as f: assert hashlib.file_digest(f,'sha256').hexdigest()==PIN
parser=runpy.run_path(str(ROOT/'tools/local-recovery/inspect_recovery.py'))
with zipfile.ZipFile(P) as z:
    assert len(z.namelist())==len(set(z.namelist()))
    assert z.testzip() is None
    img=z.read('recovery.img')
header,files=parser['ramdisk'](img)
report={'path':str(P),'size':P.stat().st_size,'sha256':PIN,'recovery_image_sha256':hashlib.sha256(img).hexdigest(),'ramdisk':header,'executed':False,'scripts':{},'properties':[]}
for name,data in files.items():
    if name.endswith('.sh') and (any(x in name for x in ['rom_flash','reflash','recovery','ota']) or b'fox_backup' in data or b'/metadata/ota' in data):
        report['scripts'][name]={'sha256':hashlib.sha256(data).hexdigest(),'text':data.decode('utf-8','replace')}
    if name.endswith('prop.default'):
        report['properties']=[l for l in data.decode('utf-8','replace').splitlines() if re.search(r'ro.build.(fox|version.sdk)|ro.virtual_ab|ro.boot.dynamic',l)]
binary=files.get('system/bin/recovery')
if binary:
    report['recovery_executable_sha256']=hashlib.sha256(binary).hexdigest()
    report['hook_strings']=[s.decode('utf-8','replace') for s in re.findall(rb'[ -~]{6,}',binary) if any(x in s for x in [b'pre_rom_flash',b'post_rom_flash',b'fox_backup',b'auto_reflash'])]
(OUT/'official-r12_0_7-static.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
