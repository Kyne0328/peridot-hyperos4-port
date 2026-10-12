"""Offline candidate/module compatibility checks; never loads modules or flashes."""
from pathlib import Path
import hashlib, json, re, struct, subprocess, sys, tempfile
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

ROOT = Path(__file__).resolve().parents[2]
BASE = Path(r'\\wsl.localhost\Ubuntu\home\kyne\peridot-resukisu-uapi5')
OUT = ROOT/'builder/work/resukisu-uapi5-20261004-audit'
sys.path.insert(0, str(ROOT/'tools/resukisu-candidate'))
from check_module_crcs import imports
from inspect_baseline import ramdisk

def digest(p):
    with p.open('rb') as f: return hashlib.file_digest(f, 'sha256').hexdigest()

def exports(data):
    off = struct.unpack_from('<Q', data, 40)[0]
    ent, count, si = struct.unpack_from('<HHH', data, 58)
    assert ent == 64
    sections = [struct.unpack_from('<IIQQQQIIQQ', data, off+i*ent) for i in range(count)]
    sh = sections[si]; names = data[sh[4]:sh[4]+sh[5]]
    for s in sections:
        if names[s[0]:].split(b'\0')[0] == b'__ksymtab_strings':
            return {n.decode() for n in data[s[4]:s[4]+s[5]].split(b'\0') if n}
    return set()

def symbol_map(p):
    return {row[1]: int(row[0], 16) for line in p.read_text().splitlines() if len(row := line.split()) >= 2}

def main():
    OUT.mkdir(exist_ok=True)
    image_path = BASE/'out-uapi5/arch/arm64/boot/Image'
    image = image_path.read_bytes()
    cert_path = ROOT/'.cache/resukisu-uapi5-finalize/stock-module-public.pem'
    der = x509.load_pem_x509_certificate(cert_path.read_bytes()).public_bytes(Encoding.DER)
    assert der in image, 'Stock public module key absent from final Image'
    config = (BASE/'out-uapi5/.config').read_text()
    for option in ['CONFIG_KSU=y', 'CONFIG_KSU_SUSFS=y', 'CONFIG_CFI_CLANG=y',
                   'CONFIG_MODVERSIONS=y', 'CONFIG_MODULE_SIG_PROTECT=y']:
        assert option in config.splitlines(), option
    assert 'KERNEL_SU_UAPI_VERSION = 5' in (BASE/'ReSukiSU/uapi/supercall.h').read_text()
    release = (BASE/'out-uapi5/include/config/kernel.release').read_text().strip()
    assert release == '6.1.138-android14-11-g0c3d559bcd85-ab14529422'
    candidate = symbol_map(BASE/'out-uapi5/vmlinux.symvers')
    stock = symbol_map(ROOT/'00-manifest/resukisu-candidate/kernel_aarch64_Module.symvers')
    modules = []
    for origin in ['system_dlkm', 'vendor_dlkm']:
        tree = ROOT/'.cache/resukisu-candidate'/(origin+'-extracted')/'lib'
        for p in sorted(tree.rglob('*.ko')):
            modules.append((origin, p.relative_to(tree).as_posix(), p.read_bytes()))
    vendor = ROOT/'.cache/global-single-recovery-ri2/source-images/images/vendor_boot.img'
    receipt_path = ROOT/'00-manifest/resukisu-addon-update-20261004.json'
    receipt = json.loads(receipt_path.read_text())
    receipt['vendor_boot_input'] = dict(path=str(vendor), sha256=digest(vendor))
    receipt_path.write_text(json.dumps(receipt, indent=2)+'\n', encoding='utf-8')
    vb = vendor.read_bytes(); size = struct.unpack_from('<I', vb, 24)[0]
    synthetic = bytearray(4096); synthetic[:8] = b'ANDROID!'
    struct.pack_into('<II', synthetic, 8, 0, size); struct.pack_into('<I', synthetic, 40, 4)
    _, files = ramdisk(bytes(synthetic)+vb[4096:4096+size])
    modules += [('vendor_boot', n, b) for n, b in files.items() if n.endswith('.ko')]
    module_exports = set().union(*(exports(b) for _, _, b in modules))
    rows = []
    signed_count = 0
    with tempfile.TemporaryDirectory(dir=OUT) as temp:
        temp = Path(temp)
        for origin, name, data in modules:
            versions = imports(data)
            bad = [dict(symbol=s, module_crc=hex(c), kernel_crc=hex(candidate[s]))
                   for s, c in versions if s in candidate and candidate[s] != c]
            missing = [s for s, _ in versions if s not in candidate and s not in module_exports]
            signature = 'unsigned'
            marker = b'~Module signature appended~\n'
            if data.endswith(marker):
                end = len(data)-len(marker)
                length = int.from_bytes(data[end-4:end], 'big')
                start = end-12-length
                (temp/'signature.der').write_bytes(data[start:end-12])
                (temp/'content.bin').write_bytes(data[:start])
                result = subprocess.run(['C:/Program Files/Git/usr/bin/openssl.exe', 'cms', '-verify',
                    '-binary', '-inform', 'DER', '-in', str(temp/'signature.der'),
                    '-content', str(temp/'content.bin'), '-certfile', str(cert_path), '-noverify',
                    '-out', str(temp/'verified.bin')], capture_output=True)
                signature = 'stock-key-signature-verified' if result.returncode == 0 else 'verification-failed'
                assert result.returncode == 0, f'Module signature failed: {origin}/{name}'
                signed_count += 1
            rows.append(dict(origin=origin, path=name, sha256=hashlib.sha256(data).hexdigest(),
                             imports=len(versions), crc_mismatches=bad, unresolved_imports=missing,
                             signature=signature))
    shared = stock.keys() & candidate.keys()
    report = dict(status='offline-compatibility-checked', image_sha256=hashlib.sha256(image).hexdigest(),
        image_bytes=len(image), kernel_release=release, uapi_version=5,
        stock_certificate_embedded=True, stock_key_module_signatures_verified=signed_count,
        shared_stock_exports=len(shared), shared_export_crc_mismatches=[s for s in shared if stock[s]!=candidate[s]],
        summary={origin:dict(modules=sum(r['origin']==origin for r in rows),
            crc_mismatches=sum(len(r['crc_mismatches']) for r in rows if r['origin']==origin),
            unresolved_imports=sum(len(r['unresolved_imports']) for r in rows if r['origin']==origin))
            for origin in ['vendor_boot','system_dlkm','vendor_dlkm']}, modules=rows,
        compiler='Ubuntu Clang 18.1.3; not the stock Android Clang 17.0.2',
        trim_unused_ksyms=False, device_boot_tested=False, runtime_root_tested=False)
    (OUT/'compatibility.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
    print(json.dumps({k:v for k,v in report.items() if k!='modules'}, indent=2))
    assert not report['shared_export_crc_mismatches']
    assert all(not r['crc_mismatches'] and not r['unresolved_imports'] for r in rows), 'Module compatibility gaps remain'

if __name__ == '__main__': main()
