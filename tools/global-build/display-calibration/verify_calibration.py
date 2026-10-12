#!/usr/bin/env python3
"""Verify an unsigned calibration-only resource artifact against pinned stock values."""
import hashlib
import json
import struct
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent

def string_pool(data, offset):
    _, header, _ = struct.unpack_from('<HHI', data, offset)
    count, _, flags, start, _ = struct.unpack_from('<5I', data, offset + 8)
    strings = []
    for i in range(count):
        p = offset + start + struct.unpack_from('<I', data, offset + header + 4 * i)[0]
        if flags & 256:
            p += 2 if data[p] & 128 else 1
            size = data[p]
            p += 1
            if size & 128:
                size = (size & 127) * 256 + data[p]
                p += 1
            strings.append(data[p:p + size].decode('utf-8'))
        else:
            size = struct.unpack_from('<H', data, p)[0]
            p += 2
            if size & 32768:
                size = (size & 32767) * 65536 + struct.unpack_from('<H', data, p)[0]
                p += 2
            strings.append(data[p:p + size * 2].decode('utf-16le'))
    return strings

def read_resources(apk):
    with zipfile.ZipFile(apk) as archive:
        if any(name.endswith('.dex') for name in archive.namelist()):
            raise ValueError('Data-only artifact must have no DEX')
        data = archive.read('resources.arsc')
    result = {}
    p = struct.unpack_from('<H', data, 2)[0]
    while p < len(data):
        kind, header, size = struct.unpack_from('<HHI', data, p)
        if kind == 0x200:
            types = string_pool(data, p + struct.unpack_from('<I', data, p + 268)[0])
            keys = string_pool(data, p + struct.unpack_from('<I', data, p + 276)[0])
            q = p + header
            while q < p + size:
                typ, hs, sz = struct.unpack_from('<HHI', data, q)
                if typ == 0x201:
                    tid, flags, _, count, start = struct.unpack_from('<BBHII', data, q + 8)
                    if flags != 0:
                        raise ValueError('Unexpected sparse/offset16 resource encoding')
                    for i in range(count):
                        off = struct.unpack_from('<I', data, q + hs + 4 * i)[0]
                        if off == 0xffffffff:
                            continue
                        entry = q + start + off
                        eh, ef, key = struct.unpack_from('<HHI', data, entry)
                        name = types[tid - 1] + '/' + keys[eh if ef & 8 else key]
                        if name in result:
                            raise ValueError('Duplicate resource or configuration')
                        if ef & 8:
                            values = [(ef >> 8, hex(key))]
                        elif ef & 1:
                            _, n = struct.unpack_from('<II', data, entry + 8)
                            values = []
                            for j in range(n):
                                _, _, value_type, raw = struct.unpack_from('<HBBI', data, entry + eh + 12 * j + 4)
                                values.append((value_type, hex(raw)))
                        else:
                            _, _, value_type, raw = struct.unpack_from('<HBBI', data, entry + eh)
                            values = [(value_type, hex(raw))]
                        result[name] = values
                q += sz
        p += size
    return result

def main():
    scope = json.loads((ROOT / 'calibration-scope.json').read_text())
    apk = ROOT / 'F6Calibration-UNSIGNED-REVIEW-ONLY.apk'
    actual = read_resources(apk)
    expected = {r['key']: [(v['value_type'], v['raw']) for v in r['source_values']] for r in scope['resources']}
    if actual != expected:
        raise ValueError('Compiled calibration resource values/types differ from pinned stock extraction')
    if len(actual) != 10:
        raise ValueError('Calibration allowlist changed')
    report = {'status': 'PASS', 'unsigned_review_apk_sha256': hashlib.sha256(apk.read_bytes()).hexdigest(), 'resource_count': len(actual), 'raw_value_type_pairs_compared': sum(len(values) for values in actual.values()), 'privacy_or_security_resources_present': False, 'dex_present': False, 'signing': 'UNSIGNED; not installable release artifact', 'idmap_execution': 'NOT_RUN', 'compiled_values': actual}
    (ROOT / 'compiled-resource-validation.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: v for k, v in report.items() if k != 'compiled_values'}, indent=2))

if __name__ == '__main__':
    main()
