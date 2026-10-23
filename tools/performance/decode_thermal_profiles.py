"""Offline decoder for the retained mi_thermald AES-CBC configuration path.

Addresses come from readelf relocations and disassembly: 0xa9010 calls
EVP_CipherInit, x2/x3 originate in relocations 0xb62b0/0xb62b8 pointing
to 0xb7ad4/0xb7ae5 in .data (file-offset delta 0x1000).
No phone or source ROM input is modified.
"""
from pathlib import Path
import hashlib
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

ROOT = Path(__file__).resolve().parents[2]
WORK = ROOT / 'builder/work/performance-static-20261005'
BINARY = WORK / 'vendor/bin/mi_thermald'

def main():
    binary = BINARY.read_bytes()
    assert hashlib.sha256(binary).hexdigest() == '8ea24cb0d7b68011f8ec3c3c1bcecfc0946b13e520fe117aa924dd548be088d4', 'Consumer changed; rederive offsets before decoding'
    key = binary[0xb6ad4:0xb6ad4 + 16]
    iv = binary[0xb6ae5:0xb6ae5 + 16]
    output = WORK / 'decoded'
    output.mkdir(exist_ok=True)
    report = {'consumer': str(BINARY), 'consumer_sha256': hashlib.sha256(binary).hexdigest(),
              'method': 'AES-128-CBC, EVP default PKCS7 padding; static key/IV path',
              'device_access': False, 'source_mutations': False, 'files': []}
    for path in list((WORK / 'odm/etc').glob('thermal-*.conf')) + [WORK / 'vendor/etc/thermal-map.conf']:
        data = path.read_bytes()
        if data.startswith(b'['):
            report['files'].append({'path': str(path), 'status': 'already_plaintext'})
            continue
        try:
            decrypt = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
            padded = decrypt.update(data) + decrypt.finalize()
            unpad = PKCS7(128).unpadder()
            decoded = unpad.update(padded) + unpad.finalize()
            text = decoded.decode('utf-8')
            assert text.strip() and all(c.isprintable() or c in '\r\n\t' for c in text)
            pad = PKCS7(128).padder()
            padded2 = pad.update(decoded) + pad.finalize()
            encrypt = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
            assert encrypt.update(padded2) + encrypt.finalize() == data
            target = output / (path.parts[-3] + '-' + path.name)
            target.write_bytes(decoded)
            report['files'].append({'path': str(path), 'status': 'decoded_and_exact_roundtrip',
                                   'output': str(target), 'bytes': len(decoded),
                                   'input_sha256': hashlib.sha256(data).hexdigest(),
                                   'output_sha256': hashlib.sha256(decoded).hexdigest()})
        except (ValueError, AssertionError) as error:
            report['files'].append({'path': str(path), 'status': 'not_decoded', 'error': str(error)})
    (output / 'receipt.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))

if __name__ == '__main__':
    main()
