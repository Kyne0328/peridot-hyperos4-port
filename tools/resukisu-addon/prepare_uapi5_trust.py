"""Record immutable inputs and retain the stock kernel's public module trust key."""
from pathlib import Path
import hashlib, json
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

ROOT = Path(__file__).resolve().parents[2]
OLD = ROOT / 'builder/work/resukisu-susfs-addon/POCO-F6-HyperOS4-ReSukiSU-SUSFS-Addon-20261003.zip'
BOOT = ROOT / '.cache/global-single-recovery-ri2/source-images/images/boot.img'
OUT = ROOT / '.cache/resukisu-uapi5-finalize'
RECEIPT = ROOT / '00-manifest/resukisu-addon-update-20261004.json'

def main():
    inputs = []
    for path, expected in [(OLD, '2f1c4b9c451e2f6e0161867ca13eb60f38f3f01ba828a33df0c999a0fbff9eba'),
                           (BOOT, 'e7be9c65e3e6f0af17572a3fa37d43c4e4031d28f391ed17fc625e383c33bf03')]:
        with path.open('rb') as f:
            digest = hashlib.file_digest(f, 'sha256').hexdigest()
        assert digest == expected, f'Immutable input mismatch: {path}'
        inputs.append(dict(path=str(path), sha256=digest, bytes=path.stat().st_size))
    receipt = dict(inputs=inputs, source_common='0c3d559bcd85c64dae9c9c9687abbe5347fff3ad',
                   resukisu='8770c7e324a22895703c4916b8a16520e0b81c79',
                   susfs='24743360ea08d98f6ad72b856851abed8de5854f',
                   manager_reported_by_owner='4.2.0-rc3 (35203/5)',
                   old_kernel_uapi=2, candidate_kernel_uapi=5,
                   compiler='Ubuntu Clang 18.1.3; differs from stock Android Clang 17.0.2',
                   source_archives_modified=False, device_flash_performed=False)
    RECEIPT.write_text(json.dumps(receipt, indent=2)+'\n', encoding='utf-8')
    data = BOOT.read_bytes()
    found = []
    offset = 0
    while (offset := data.find(b'\x30\x82', offset)) >= 0:
        length = int.from_bytes(data[offset+2:offset+4], 'big') + 4
        der = data[offset:offset+length]
        try:
            cert = x509.load_der_x509_certificate(der)
            found.append((offset, der, cert))
        except ValueError:
            pass
        offset += 2
    assert len(found) == 1, 'Stock certificate count changed'
    offset, der, cert = found[0]
    OUT.mkdir(exist_ok=True)
    pem = cert.public_bytes(Encoding.PEM)
    (OUT/'stock-module-public.pem').write_bytes(pem)
    receipt['stock_public_module_certificate'] = dict(offset=offset, der_sha256=hashlib.sha256(der).hexdigest(),
        subject=cert.subject.rfc4514_string(), serial=str(cert.serial_number), private_key_acquired=False)
    RECEIPT.write_text(json.dumps(receipt, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(receipt['stock_public_module_certificate'], indent=2))

if __name__ == '__main__':
    main()
