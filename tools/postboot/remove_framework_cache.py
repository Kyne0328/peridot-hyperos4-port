"""Remove generated companions that authenticate or compile the replaced framework JAR."""
from pathlib import Path
import hashlib,json,tarfile
from image import Image
ROOT=Path(__file__).resolve().parents[2];WORK=Path('D:/hyperos4-peridot-postboot-20261004')
source=WORK/'system_ext-source.img';image=Image(source);rows=image.inventory();image.close()
exact={'/framework/miui-services.jar.fsv_meta','/framework/miui-services.jar.prof','/framework/miui-services.jar.prof.fsv_meta'}
for suffix in ['odex','vdex','art']:
 exact.add('/framework/oat/arm64/miui-services.'+suffix);exact.add('/framework/oat/arm64/miui-services.'+suffix+'.fsv_meta')
removed=[r for r in rows if r['path'] in exact];assert {r['path'] for r in removed}==exact
old=WORK/'system_ext-windows.tar';new=WORK/'system_ext-windows-clean.tar';assert not new.exists()
with tarfile.open(old,'r') as src,tarfile.open(new,'x',format=tarfile.PAX_FORMAT) as dst:
 for entry in src:
  path='/'+entry.name.removeprefix('./').lstrip('/')
  if path in exact:continue
  # A remaining hardlink must never refer to a removed companion.
  if entry.islnk():assert '/'+entry.linkname.removeprefix('./').lstrip('/') not in exact
  dst.addfile(entry,src.extractfile(entry) if entry.isfile() else None)
def sha(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
receipt={'removed_paths':sorted(exact),'reason':'Discard stale default-JAR ART and fsverity companions; ART must use the changed DEX',
 'input_tar_sha256':sha(old),'output_tar_sha256':sha(new),'source_image_sha256':sha(source)}
(WORK/'framework-cache-removal.json').write_text(json.dumps(receipt,indent=2)+'\n')
print(json.dumps(receipt,indent=2))
