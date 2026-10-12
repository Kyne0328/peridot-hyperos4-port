"""Build the same RI4 parser/verifier for fast host readback. Device mode is disabled."""
from pathlib import Path
import hashlib,json,subprocess,os
ROOT=Path(__file__).resolve().parents[2];HERE=ROOT/'tools/installer-ri3/native-updater';WORK=Path(os.environ.get('RI4_BUILD_WORK',str(ROOT/'builder/work/installer-ri4'))).resolve();assert WORK.is_relative_to(ROOT/'builder/work');OUT=WORK/'native';old=ROOT/'builder/work/installer-ri3-native'
incs=[ROOT/'tools/installer-ri4',HERE,HERE/'runtime',HERE/'backend',HERE/'snapshot',OUT,old/'vendor/recovery/edify/include',old/'vendor/recovery/otautil/include',old/'vendor/libbase/include',old/'vendor/zlib-1.3.2',old/'vendor/zlib-1.3.2/contrib/minizip',old/'generated',old/'production-vendor/base/include',old/'production-vendor/core/fs_mgr/libdm/include']
flags=['-std=c++17','-O2','-ffunction-sections','-fdata-sections','-D_FILE_OFFSET_BITS=64','-DRI3_ENABLE_DEVICE_INSTALL=1',*[f'-I{p}' for p in incs]]
objects=[]
for i,p in enumerate([ROOT/'tools/installer-ri4/install_runtime.cpp',OUT/'main.cpp']):
 o=OUT/(str(i)+'-host.o');subprocess.run(['clang++',*flags,'-c',str(p),'-o',str(o)],check=True);objects.append(o)
shared=[]
for i in range(3,28):
 found=list((old/'extract/extract-v3-20261003T0431/host').glob(str(i)+'-*.o'));assert len(found)==1;shared+=found
shared += [p for p in (old/'crypto/crypto-host-20261003T0424-host').glob('*.o') if 'test_crypto' not in p.name and 'verify_crypto' not in p.name]
for i in [15,16,17,18,21,22]:
 found=list((old/'build-host').glob(str(i)+'-*.o'));assert len(found)==1;shared+=found
subprocess.run(['clang++',*map(str,objects+shared),'-Wl,--gc-sections','-o',str(OUT/'verify-host')],check=True)
print('HOST VERIFIER BUILT')
