"""Compile RI4 using the retained, source-built RI3 dependencies. No device calls."""
from pathlib import Path
import hashlib,json,os,subprocess,sys
ROOT=Path(__file__).resolve().parents[2];HERE=ROOT/'tools/installer-ri3/native-updater';WORK=Path(os.environ.get('RI4_BUILD_WORK',str(ROOT/'builder/work/installer-ri4'))).resolve();assert WORK.is_relative_to(ROOT/'builder/work');OUT=WORK/'native';OUT.mkdir(exist_ok=True)
images=json.loads((WORK/'images.json').read_text())['images'];rows={x['name']:x for x in images}
firmware=sorted(set(rows)-{'super','boot','dtbo','init_boot','vendor_boot','recovery','vbmeta_system','vbmeta'})
order=['super',*firmware,'boot','dtbo','init_boot','vendor_boot','recovery','vbmeta_system','vbmeta']
assert len(order)==32 and len(set(order))==32
header='#pragma once\n#include <cstdint>\nnamespace ri4 {struct Pin{const char*name;uint64_t bytes;const char*sha;};\nconstexpr unsigned kImageCount=32;\ninline const Pin kPins[]={\n'+''.join('{"'+n+'",'+str(rows[n]['size'])+'ULL,"'+rows[n]['sha256']+'"},\n' for n in order)+'};}\n'
(OUT/'image_pins.h').write_text(header)
source=(HERE/'runtime/main.cpp').read_text().replace('ri3_install','ri4_install').replace('RI3_READONLY','RI4_READONLY').replace('RI3 core','RI4 core')
anchor='    std::string signature_error;'
assert source.count(anchor)==1
source=source.replace(anchor,'    UiPrint("Verifying complete signed ZIP ("+std::to_string(package_stat.st_size/(1024*1024))+" MiB); no writes yet...");\n'+anchor)
anchor='#ifdef RI3_ENABLE_DEVICE_INSTALL\n    context.installation_allowed=true;'
assert source.count(anchor)==1
source=source.replace(anchor,'    UiPrint("Complete ZIP signature verified.");\n'+anchor)
(OUT/'main.cpp').write_text(source)
ndk=Path(os.environ['LOCALAPPDATA'])/'Android/Sdk/ndk/28.2.13676358';cxx=ndk/'toolchains/llvm/prebuilt/windows-x86_64/bin/clang++.exe'
old=ROOT/'builder/work/installer-ri3-native'
incs=[ROOT/'tools/installer-ri4',HERE,HERE/'runtime',HERE/'backend',HERE/'snapshot',OUT,old/'vendor/recovery/edify/include',old/'vendor/recovery/otautil/include',old/'vendor/libbase/include',old/'vendor/zlib-1.3.2',old/'vendor/zlib-1.3.2/contrib/minizip',old/'generated',old/'production-vendor/base/include',old/'production-vendor/core/fs_mgr/libdm/include']
flags=['--target=aarch64-linux-android30','-std=c++17','-O2','-g','-ffunction-sections','-fdata-sections','-D_FILE_OFFSET_BITS=64','-D_LARGEFILE64_SOURCE=1','-D_POSIX_C_SOURCE=200809L','-DRI3_ENABLE_DEVICE_INSTALL=1',*[f'-I{p}' for p in incs]]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
commands=[]
def run(cmd):
 r=subprocess.run([str(x) for x in cmd],capture_output=True,text=True);commands.append({'argv':[str(x) for x in cmd],'rc':r.returncode,'stderr':r.stderr});assert r.returncode==0,r.stderr
objects=[]
for i,p in enumerate([ROOT/'tools/installer-ri4/install_runtime.cpp',OUT/'main.cpp']):
 o=OUT/(str(i)+'.o');run([cxx,*flags,'-c',p,'-o',o]);objects.append(o)
receipt=json.loads((old/'runtime-integration/android-release-20261003T1018/build-receipt.json').read_text())
backend_override=os.environ.get('RI4_BACKEND_ARCHIVE')
backend=Path(backend_override).resolve() if backend_override else None
if backend is not None:
 assert backend.is_relative_to((old/'backend').resolve()) and backend.name=='libbackend-ri3.a' and backend.is_file(),'Invalid RI4_BACKEND_ARCHIVE'
 backend_receipt=json.loads((backend.parent/'receipt.json').read_text())
 assert Path(backend_receipt['archive']).resolve()==backend and sha(backend)==backend_receipt['archive_sha256'],'Backend receipt mismatch'
shared=[]
for name,h in receipt['input_objects'].items():
 p=ROOT/name
 if '/runtime-integration/' in name.replace('\\','/') and not p.name.startswith('0-'):continue
 if p.name=='libbackend-ri3.a' and backend is not None:p=backend;h=backend_receipt['archive_sha256']
 assert sha(p)==h,'Dependency changed: '+str(p);shared.append(p)
variant=WORK/'hal_query.cpp'
if variant.exists():
 o=OUT/'hal-query-variant.o'
 run([cxx,*flags,'-I'+str(HERE/'crypto'),'-I'+str(old/'production-vendor/mbedtls-3.6.7/include'),'-DMBEDTLS_CONFIG_FILE="ri3_mbedtls_config.h"','-c',variant,'-o',o])
 shared=[p for p in shared if p.name!='1-hal_query.o'];shared.append(o)
run([cxx,'--target=aarch64-linux-android30','-static',*objects,*shared,'-Wl,--gc-sections','-Wl,-z,noexecstack','-Wl,-z,relro','-Wl,-z,now','-o',OUT/'update-binary'])
save={'binary_sha256':sha(OUT/'update-binary'),'bytes':(OUT/'update-binary').stat().st_size,'image_order':order,'source_sha256':sha(ROOT/'tools/installer-ri4/install_runtime.cpp'),'main_sha256':sha(OUT/'main.cpp'),'pins_sha256':sha(OUT/'image_pins.h'),'hal_variant_sha256':sha(variant) if variant.exists() else None,'dependencies':{str(p.relative_to(ROOT)):sha(p) for p in shared},'commands':commands,'device_actions_performed':False}
(OUT/'build-receipt.json').write_text(json.dumps(save,indent=2)+'\n');print(json.dumps({k:save[k] for k in ['binary_sha256','bytes','image_order']}))
