"""Build/run a collector-only probe in recovery tmpfs; never mutate storage state."""
from pathlib import Path
import argparse, hashlib, json, os, subprocess

ROOT = Path(__file__).resolve().parents[2]
WORK = ROOT / 'builder/work/installer-ri5-recoveryfix-20261004'
HERE = ROOT / 'tools/installer-ri3/native-updater/backend'

ap = argparse.ArgumentParser()
ap.add_argument('--backend')
ap.add_argument('--native-receipt', type=Path)
ap.add_argument('--baseline', action='store_true')
ap.add_argument('--snapshot', action='store_true')
ap.add_argument('--repeat',type=int,default=1)
ap.add_argument('--label', required=True)
ap.add_argument('--serial', required=True)
a = ap.parse_args()
assert a.label.replace('-', '').isalnum()
WORK.mkdir(exist_ok=True)
assert bool(a.backend) != bool(a.native_receipt)
objects=[]
if a.native_receipt:
    receipt=json.loads(a.native_receipt.read_text())
    assert receipt['target']=='android'
    for name,digest in receipt['objects'].items():
        path=ROOT/name
        assert hashlib.sha256(path.read_bytes()).hexdigest()==digest
        if not path.name.endswith(('-main.o','-install_runtime.o')):objects.append(path)
else:
    archive = ROOT / 'builder/work/installer-ri3-native/backend' / a.backend / 'libbackend-ri3.a'
    receipt = json.loads((archive.parent / 'receipt.json').read_text())
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == receipt['archive_sha256']
    objects=[archive]
cxx = Path(os.environ['LOCALAPPDATA']) / 'Android/Sdk/ndk/28.2.13676358/toolchains/llvm/prebuilt/windows-x86_64/bin/clang++.exe'
binary = WORK / ('storage-probe-' + a.label)
if a.baseline:
    baseline=WORK/'baseline-topology.o'
    p=subprocess.run([str(cxx),'--target=aarch64-linux-android30','-std=c++17','-O2','-ffunction-sections','-fdata-sections','-I'+str(HERE),'-c',str(WORK/'baseline-topology.cpp'),'-o',str(baseline)],capture_output=True,text=True)
    assert p.returncode==0,p.stderr
    objects=[path for path in objects if not path.name.endswith('-topology.o')]+[baseline]
cmd = [str(cxx), '--target=aarch64-linux-android30', '-std=c++17', '-O2', '-ffunction-sections', '-fdata-sections',
    '-I' + str(HERE), '-I'+str(HERE.parent/'snapshot'), *(['-DRI5_PROBE_SNAPSHOT=1'] if a.snapshot else []),
    str(ROOT / 'tools/installer-ri5/storage_probe.cpp'), *map(str,objects), '-static', '-Wl,--gc-sections', '-o', str(binary)]
p = subprocess.run(cmd, capture_output=True, text=True)
assert p.returncode == 0, p.stdout + p.stderr
remote = '/tmp/ri5-storage-probe-' + a.label
for command in [['adb', '-s', a.serial, 'push', str(binary), remote], ['adb', '-s', a.serial, 'shell', 'chmod', '700', remote]]:
    p = subprocess.run(command, capture_output=True, text=True)
    assert p.returncode == 0, p.stdout + p.stderr
p = subprocess.run(['adb', '-s', a.serial, 'shell', remote,str(a.repeat)], capture_output=True, text=True)
result = {'exit_code': p.returncode, 'stdout': p.stdout, 'stderr': p.stderr, 'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
    'native_build_sha256': receipt.get('binary_sha256',receipt.get('archive_sha256')), 'baseline':a.baseline,
    'persistent_phone_writes': False, 'block_writes_unmounts_mapping_removals_slot_changes': False}
(WORK / ('collector-' + a.label + '.json')).write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
print(json.dumps(result, indent=2))
