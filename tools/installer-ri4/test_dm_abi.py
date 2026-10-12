"""Run actual adapter ABI tests and two regression negative controls, offline."""
from pathlib import Path
import hashlib, json, os, subprocess

ROOT = Path(__file__).resolve().parents[2]
WORK = ROOT / 'builder/work/installer-ri4-dmfix-20261004'
BACKEND = ROOT / 'tools/installer-ri3/native-updater/backend'
WORK.mkdir(exist_ok=True)

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def linux(path):
    if os.name != 'nt':
        return str(path)
    return '/mnt/' + path.drive[0].lower() + str(path)[2:].replace('\\', '/')

def run(args):
    if os.name == 'nt':
        args = ['wsl', '-d', 'Ubuntu', '--', *args]
    return subprocess.run(args, capture_output=True, text=True, timeout=60)

adapter = (BACKEND / 'libdm_adapter.cpp').read_text()
test = (ROOT / 'tools/installer-ri4/test_dm_abi.cpp').read_text()
test = test.replace('../installer-ri3/native-updater/backend/storage_backend.h', linux(BACKEND / 'storage_backend.h'))
variants = {
    'fixed': adapter,
    'old-ndk-version': adapter.replace('io.version[0]=DM_VERSION0;io.version[1]=DM_VERSION1;io.version[2]=DM_VERSION2;',
        'io.version[0]=DM_VERSION_MAJOR;io.version[1]=DM_VERSION_MINOR;io.version[2]=DM_VERSION_PATCHLEVEL;'),
    'old-status-size': adapter.replace('io.data_size<offsetof(dm_ioctl,data)||io.data_size>sizeof(io)', 'io.data_size!=sizeof(io)'),
}
results = {}
for name, body in variants.items():
    # Sanitizer global metadata otherwise retains the unrelated live adapter
    # vtable and libdm dependencies. Keep production ioctl helpers verbatim;
    # omit only the class/factory that opens live devices and collects sysfs.
    body = body[:body.index('class LibDmAdapter final')] + '\n}\n}\n'
    source = WORK / (name + '-adapter.cpp')
    source.write_text(body.replace('#include "storage_backend.h"', '#include "' + linux(BACKEND / 'storage_backend.h') + '"')
        .replace('#include "verity_table.h"', '#include "' + linux(BACKEND / 'verity_table.h') + '"'))
    entry = WORK / (name + '-test.cpp')
    entry.write_text(test.replace('../installer-ri3/native-updater/backend/libdm_adapter.cpp', linux(source)))
    binary = WORK / ('test-' + name)
    args = ['clang++', '-std=c++17', '-O2', '-ffunction-sections', '-fdata-sections', '-fsanitize=address,undefined',
        '-fno-omit-frame-pointer', '-Wno-inconsistent-missing-override']
    args += ['-I' + linux(ROOT / 'builder/work/installer-ri3-native/production-vendor' / p)
        for p in ['core/fs_mgr/libdm/include', 'base/include']]
    compile_result = run([*args, linux(entry), '-Wl,--gc-sections', '-o', linux(binary)])
    assert compile_result.returncode == 0, compile_result.stderr
    result = run([linux(binary)])
    assert (result.returncode == 0) == (name == 'fixed'), result.stdout + result.stderr
    if name == 'fixed':
        assert '26 actual DM ABI cases passed' in result.stdout
    elif name == 'old-ndk-version':
        assert 'errno=22' in result.stderr and 'kernel DM ABI=4.47.0' in result.stderr
    else:
        assert 'dm_status_incomplete' in result.stderr
    results[name] = {'returncode': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr}
receipt = {'passed': True, 'cases': 26, 'negative_controls': 2, 'sanitizers': 'address,undefined',
    'device_access': False, 'source_sha256': sha(BACKEND / 'libdm_adapter.cpp'),
    'test_sha256': sha(ROOT / 'tools/installer-ri4/test_dm_abi.cpp'), 'results': results}
(WORK / 'dm-abi-tests.json').write_text(json.dumps(receipt, indent=2) + '\n')
print(json.dumps(receipt, indent=2))
