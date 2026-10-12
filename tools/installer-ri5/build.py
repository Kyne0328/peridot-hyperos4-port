"""Build the compressed RI5 updater using retained pinned Android/host objects."""
from pathlib import Path
import argparse, hashlib, json, os, subprocess

ROOT = Path(__file__).resolve().parents[2]
HERE = ROOT / 'tools/installer-ri5'
CORE = ROOT / 'tools/installer-ri3/native-updater'
WORK = ROOT / 'builder/work/installer-ri5-stream-20261004'
OLD = ROOT / 'builder/work/installer-ri3-native'

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--target', choices=['android', 'host'], required=True)
    a = ap.parse_args()
    out = WORK / 'native'
    out.mkdir(exist_ok=True)
    rows = {x['name']: x for x in json.loads((WORK / 'images.json').read_text())['images']}
    boot = ['boot', 'dtbo', 'init_boot', 'vendor_boot', 'recovery', 'vbmeta_system', 'vbmeta']
    order = ['super', *sorted(set(rows) - {'super', *boot}), *boot]
    assert len(order) == len(set(order)) == 32
    header = '#pragma once\n#include <cstdint>\nnamespace ri4 {struct Pin{const char*name;uint64_t bytes;const char*sha;};\nconstexpr unsigned kImageCount=32;\ninline const Pin kPins[]={\n'
    header += ''.join('{"' + n + '",' + str(rows[n]['size']) + 'ULL,"' + rows[n]['sha256'] + '"},\n' for n in order) + '};}\n'
    (out / 'image_pins.h').write_text(header)
    # Keep the tested command-FD, signature, Edify and disabled-operation core.
    main_cpp = (ROOT / 'builder/work/installer-ri4-dmfix-20261004/native/main.cpp').read_text()
    main_cpp = main_cpp.replace('ri4_install', 'ri5_install').replace('RI4_READONLY', 'RI5_READONLY').replace('RI4 core', 'RI5 core')
    (out / 'main.cpp').write_text(main_cpp)
    incs = [HERE, ROOT / 'tools/installer-ri4', CORE, CORE / 'runtime', CORE / 'extract', CORE / 'backend', CORE / 'snapshot', CORE / 'crypto', out,
        OLD / 'vendor/recovery/edify/include', OLD / 'vendor/recovery/otautil/include', OLD / 'vendor/libbase/include',
        OLD / 'vendor/zlib-1.3.2', OLD / 'vendor/zlib-1.3.2/contrib/minizip', OLD / 'generated',
        OLD / 'production-vendor/base/include', OLD / 'production-vendor/core/fs_mgr/libdm/include', OLD / 'production-vendor/mbedtls-3.6.7/include']
    flags = ['-std=c++17', '-O2', '-ffunction-sections', '-fdata-sections', '-D_FILE_OFFSET_BITS=64', '-D_LARGEFILE64_SOURCE=1',
        '-D_POSIX_C_SOURCE=200809L', '-DRI3_ENABLE_DEVICE_INSTALL=1', '-DMBEDTLS_CONFIG_FILE="ri3_mbedtls_config.h"', *['-I' + str(p) for p in incs]]
    cxx = 'clang++'
    if a.target == 'android':
        ndk = Path(os.environ['LOCALAPPDATA']) / 'Android/Sdk/ndk/28.2.13676358'
        assert 'Pkg.Revision = 28.2.13676358' in (ndk / 'source.properties').read_text()
        cxx = str(ndk / 'toolchains/llvm/prebuilt/windows-x86_64/bin/clang++.exe')
        flags += ['--target=aarch64-linux-android30']
    logs = []
    def run(cmd):
        cmd = list(map(str, cmd))
        p = subprocess.run(cmd, capture_output=True, text=True)
        logs.append({'argv': cmd, 'exit_code': p.returncode, 'stdout': p.stdout, 'stderr': p.stderr})
        (out / (a.target + '-commands.json')).write_text(json.dumps(logs, indent=2) + '\n')
        assert p.returncode == 0, p.stdout + p.stderr
    objects = []
    for i, source in enumerate([HERE / 'install_runtime.cpp', out / 'main.cpp']):
        obj = out / (str(i) + '-' + a.target + '.o')
        run([cxx, *flags, '-c', source, '-o', obj]); objects.append(obj)
    shared = []
    if a.target == 'android':
        receipt = json.loads((ROOT / 'builder/work/installer-ri4-dmfix-20261004/native/build-receipt.json').read_text())
        for name, digest in receipt['dependencies'].items():
            path = ROOT / name
            assert sha(path) == digest, 'Dependency changed: ' + str(path)
            shared.append(path)
    else:
        for i in range(3, 28):
            found = list((OLD / 'extract/extract-v3-20261003T0431/host').glob(str(i) + '-*.o'))
            assert len(found) == 1; shared += found
        shared += [p for p in (OLD / 'crypto/crypto-host-20261003T0424-host').glob('*.o') if 'test_crypto' not in p.name and 'verify_crypto' not in p.name]
        for i in [15, 16, 17, 18, 21, 22]:
            found = list((OLD / 'build-host').glob(str(i) + '-*.o'))
            assert len(found) == 1; shared += found
    binary = out / ('update-binary' if a.target == 'android' else 'verify-host')
    link_flags = ['--target=aarch64-linux-android30', '-static', '-Wl,-z,noexecstack', '-Wl,-z,relro', '-Wl,-z,now'] if a.target == 'android' else []
    run([cxx, *link_flags, *objects, *shared, '-Wl,--gc-sections', '-o', binary])
    result = {'target': a.target, 'binary': str(binary), 'binary_sha256': sha(binary), 'bytes': binary.stat().st_size, 'image_order': order,
        'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in [HERE / 'install_runtime.cpp', HERE / 'stream_image.h', CORE / 'runtime/held_package.h', out / 'main.cpp', out / 'image_pins.h', HERE / 'build.py']},
        'dependencies': {str(p.relative_to(ROOT)): sha(p) for p in shared}, 'device_actions_performed': False, 'commands': logs}
    (out / (a.target + '-build-receipt.json')).write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k: result[k] for k in ['target', 'binary', 'binary_sha256', 'bytes']}, indent=2))

if __name__ == '__main__':
    main()
