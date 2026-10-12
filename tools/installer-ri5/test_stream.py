"""Generate malformed ZIP/ZIP64 fixtures and test the real streaming path offline."""
from pathlib import Path
import hashlib, json, os, struct, subprocess, warnings, zipfile, zlib

ROOT = Path(__file__).resolve().parents[2]
HERE = ROOT / 'tools/installer-ri5'
CORE = ROOT / 'tools/installer-ri3/native-updater'
WORK = Path(os.environ.get('RI5_TEST_WORK', str(ROOT / 'builder/work/installer-ri5-stream-20261004'))).resolve()
assert WORK.is_relative_to((ROOT / 'builder/work').resolve())
FIXTURES = WORK / 'stream-fixtures'
OLD = ROOT / 'builder/work/installer-ri3-native'
FIXTURES.mkdir(exist_ok=False)
payload = bytes(range(256)) * 12288 + bytes(range(173))
digest = hashlib.sha256(payload).hexdigest()
(FIXTURES / 'payload.bin').write_bytes(payload)
(FIXTURES / 'fixture_pin.h').write_text('#pragma once\n#include <cstdint>\nconstexpr uint64_t fixture_bytes=' + str(len(payload)) + 'ULL;\nconstexpr const char*fixture_sha="' + digest + '";\n')

def raw_zip(name, data, *, declared=None, tail=b'', trim=0, crc=None, method=8):
    c = zlib.compressobj(6, zlib.DEFLATED, -15)
    compressed = c.compress(data) + c.flush()
    if trim:
        compressed = compressed[:-trim]
    compressed += tail
    declared = len(data) if declared is None else declared
    crc = zlib.crc32(data) if crc is None else crc
    member = b'image.bin'
    local = struct.pack('<IHHHHHIIIHH', 0x04034b50, 20, 0, method, 0, 0, crc, len(compressed), declared, len(member), 0) + member
    central = struct.pack('<IHHHHHHIIIHHHHHII', 0x02014b50, 20, 20, 0, method, 0, 0, crc, len(compressed), declared, len(member), 0, 0, 0, 0, 0, 0) + member
    end = struct.pack('<IHHHHIIH', 0x06054b50, 0, 0, 1, 1, len(central), len(local) + len(compressed), 0)
    (FIXTURES / (name + '.zip')).write_bytes(local + compressed + central + end)

for name, method in [('deflate', zipfile.ZIP_DEFLATED), ('stored', zipfile.ZIP_STORED), ('zip64', zipfile.ZIP_DEFLATED)]:
    with zipfile.ZipFile(FIXTURES / (name + '.zip'), 'x', compression=method) as archive:
        if name == 'zip64':
            info = zipfile.ZipInfo('image.bin'); info.compress_type = method
            with archive.open(info, 'w', force_zip64=True) as stream:
                stream.write(payload)
        else:
            archive.writestr('image.bin', payload)
raw_zip('bad-crc', payload, crc=zlib.crc32(payload) ^ 1)
raw_zip('trailing', payload, tail=b'not-part-of-deflate')
raw_zip('truncated', payload, trim=2)
raw_zip('oversized-output', payload + b'x' * 65536, declared=len(payload))
raw_zip('undersized-output', payload[:-200], declared=len(payload))
raw_zip('wrong-size', payload, declared=len(payload) - 1)
raw_zip('unsupported-method', payload, method=99)
with warnings.catch_warnings():
    warnings.simplefilter('ignore', UserWarning)
    with zipfile.ZipFile(FIXTURES / 'duplicate.zip', 'x') as archive:
        archive.writestr('image.bin', payload); archive.writestr('image.bin', payload)

def linux(path):
    return '/mnt/' + path.drive[0].lower() + str(path)[2:].replace('\\', '/') if os.name == 'nt' else str(path)

def run(args):
    if os.name == 'nt':
        args = ['wsl', '-d', 'Ubuntu', '--', *args]
    p = subprocess.run(args, capture_output=True, text=True, timeout=90)
    assert p.returncode == 0, p.stdout + p.stderr
    return p.stdout

incs = [HERE, ROOT / 'tools/installer-ri4', CORE / 'runtime', CORE / 'extract', CORE / 'crypto', FIXTURES,
    OLD / 'vendor/zlib-1.3.2', OLD / 'vendor/zlib-1.3.2/contrib/minizip', OLD / 'production-vendor/mbedtls-3.6.7/include']
shared = []
rebuilt_receipt = os.environ.get('RI5_TEST_NATIVE_RECEIPT')
if rebuilt_receipt:
    receipt_path = Path(rebuilt_receipt).resolve()
    assert receipt_path.is_relative_to((ROOT / 'builder/work').resolve())
    receipt = json.loads(receipt_path.read_text())
    assert receipt['target'] == 'host'
    for name, digest in receipt['objects'].items():
        p = ROOT / name
        assert hashlib.sha256(p.read_bytes()).hexdigest() == digest
        if not p.name.endswith(('-main.o', '-install_runtime.o')):
            shared.append(p)
else:
    for i in range(3, 28):
        found = list((OLD / 'extract/extract-v3-20261003T0431/host').glob(str(i) + '-*.o'))
        assert len(found) == 1; shared += found
    shared += [p for p in (OLD / 'crypto/crypto-host-20261003T0424-host').glob('*.o') if 'test_crypto' not in p.name and 'verify_crypto' not in p.name]
    for i in [15, 16]:
        found = list((OLD / 'build-host').glob(str(i) + '-*.o'))
        assert len(found) == 1; shared += found
binary = FIXTURES / 'test-stream'
flags = ['-std=c++17', '-O2', '-ffunction-sections', '-fdata-sections', '-D_FILE_OFFSET_BITS=64', '-DMBEDTLS_CONFIG_FILE="ri3_mbedtls_config.h"',
    '-fsanitize=address,undefined', '-fno-omit-frame-pointer']
run(['clang++', *flags, *['-I' + linux(p) for p in incs], linux(HERE / 'test_stream.cpp'), *[linux(p) for p in shared], '-Wl,--gc-sections', '-o', linux(binary)])
stdout = run([linux(binary), linux(FIXTURES)])
assert '21 compressed-stream cases passed' in stdout
receipt = {'passed': True, 'cases': 21, 'sanitizers': 'address,undefined', 'stdout': stdout, 'device_access': False,
    'source_sha256': {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in [HERE / 'stream_image.h', HERE / 'test_stream.cpp', CORE / 'runtime/held_package.h']}}
(WORK / 'stream-tests.json').write_text(json.dumps(receipt, indent=2) + '\n')
print(json.dumps(receipt, indent=2))
