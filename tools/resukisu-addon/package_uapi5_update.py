"""Create separate guarded update/rollback ZIPs from validated immutable inputs."""
from pathlib import Path
import hashlib, json, sys, zipfile

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT/'builder/work/resukisu-susfs-addon-uapi5-20261004'
OLD = ROOT/'builder/work/resukisu-susfs-addon/POCO-F6-HyperOS4-ReSukiSU-SUSFS-Addon-20261003.zip'
AUDIT = ROOT/'builder/work/resukisu-uapi5-20261004-audit/compatibility.json'
IMAGE = Path(r'\\wsl.localhost\Ubuntu\home\kyne\peridot-resukisu-uapi5\out-uapi5\arch\arm64\boot\Image')
OLD_IMAGE = 'f5b148001a01b6b3f498aa6a536ce128dbd4c6a658866e90f5f0b47842861310'
STOCK_IMAGE = '97b2c53022e8c0bd0b279c4c592a196126a6eb0a93647c2957b39dcd5f2dc1c9'
sys.path.insert(0, str(ROOT/'tools/installer-ri3/zip-signing'))
from sign_zip import sign_generated_zip
from verify_zip import verify_zip

def sha(data): return hashlib.sha256(data).hexdigest()

def text_info(name, mode=0o644):
    info = zipfile.ZipInfo(name, (2026, 10, 4, 0, 0, 0))
    info.create_system = 3; info.external_attr = mode << 16
    info.compress_type = zipfile.ZIP_DEFLATED
    return info

def script(source, accepted, label):
    text = source.decode()
    before = f'[ "$current_sha" = "{STOCK_IMAGE}" ] || abort "Current kernel is not the expected RI3/add-on kernel. Refusing to flash."'
    assert text.count(before) == 1
    cases = '|'.join(accepted)
    after = f'case "$current_sha" in\n  {cases}) ;;\n  *) abort "Current kernel is not an explicitly supported input. Refusing to flash." ;;\nesac'
    text = text.replace(before, after)
    text = text.replace('kernel.string=POCO F6 HyperOS 4 - ReSukiSU + SUSFS', 'kernel.string='+label)
    text = text.replace('Target base: F6-Global-HyperOS4-DEV2-RI3-20261003', 'Exact kernel hash guards; stock or explicitly supported addon only')
    text = text.replace('Expected current kernel SHA-256:', 'Accepted current kernel SHA-256:')
    text = text.replace(f'ui_print "{STOCK_IMAGE}"', '\n'.join(f'ui_print "{h}"' for h in accepted))
    return text.encode()

def main():
    assert not OUT.exists(), 'Refusing to overwrite an existing output directory'
    report = json.loads(AUDIT.read_text())
    assert not report['shared_export_crc_mismatches']
    assert all(not r['crc_mismatches'] and not r['unresolved_imports'] for r in report['modules'])
    assert report['stock_certificate_embedded'] and report['uapi_version'] == 5
    assert sha(OLD.read_bytes()) == '2f1c4b9c451e2f6e0161867ca13eb60f38f3f01ba828a33df0c999a0fbff9eba'
    image = IMAGE.read_bytes(); new_hash = sha(image)
    assert new_hash == report['image_sha256']
    provenance = json.loads((ROOT/'00-manifest/resukisu-addon-update-20261004.json').read_text())
    signing = json.loads((ROOT/'builder/work/installer-ri5-recoveryfix-20261004/signing-public.json').read_text())
    cert = ROOT/signing['certificate_path']; key = ROOT/signing['private_key_path']
    OUT.mkdir()
    outputs = []
    readme = ('POCO F6 / peridot UAPI 5 kernel update for manager 4.2.0-rc3 (35203/5).\n'
              'Separate update; original addon and ROM unchanged. Active boot slot only.\n'
              'Update accepts only exact stock kernel or exact 20261003 addon kernel.\n'
              'Rollback-to-previous accepts only the exact new kernel and restores the old addon kernel.\n'
              'Stock rollback accepts only the exact new kernel and restores the original stock kernel.\n'
              'Preserves boot ramdisk; no vbmeta flag patch; no userdata wipe.\n'
              'This does not update super, system_dlkm, vendor_dlkm, vendor_boot or recovery.\n'
              'ReSukiSU: 8770c7e324a22895703c4916b8a16520e0b81c79; UAPI 5.\n'
              'SUSFS: 24743360ea08d98f6ad72b856851abed8de5854f.\n'
              'Kernel base: 0c3d559bcd85c64dae9c9c9687abbe5347fff3ad; 6.1.138.\n'
              'Source-built candidate; not a replacement WildKernels download.\n'
              'Compiler: Ubuntu Clang 18.1.3, differs from stock Android Clang 17.0.2.\n'
              'Stock public module key retained; module signatures and import CRC checks recorded.\n'
              'Symbol trimming disabled; exported symbol set is larger than stock.\n'
              'Existing candidate enables multiple-manager support; toolkit support disabled.\n'
              'The old WildKernels extra feature bundle was not recreated; this is the inspected source candidate.\n'
              'Development ZIP signing uses the retained RI5 certificate, not the missing RI3 key.\n'
              'Recovery trust of this ZIP certificate is unverified; cryptographic verification is offline.\n'
              'No physical-device boot/root/hardware test or flash performed.\n')
    with zipfile.ZipFile(OLD) as source:
        old_image = source.read('Image'); assert sha(old_image) == OLD_IMAGE
        stock_boot = ROOT/'.cache/global-single-recovery-ri2/source-images/images/boot.img'
        import struct
        boot = stock_boot.read_bytes(); size = struct.unpack_from('<I', boot, 8)[0]
        stock_image = boot[4096:4096+size]; assert sha(stock_image) == STOCK_IMAGE
        choices = [('Update', image, [STOCK_IMAGE, OLD_IMAGE]),
                   ('Rollback-Previous', old_image, [new_hash]),
                   ('Rollback-Stock', stock_image, [new_hash])]
        for kind, payload, accepted in choices:
            name = f'POCO-F6-HyperOS4-ReSukiSU-SUSFS-UAPI5-{kind}-20261004.zip'
            path = OUT/name
            manifest = dict(kind=kind, device='peridot', accepted_input_image_sha256=accepted,
                bundled_image_sha256=sha(payload), new_kernel_uapi=5, provenance=provenance,
                active_boot_only=True, vbmeta_flag_patch=False, runtime_validated=False,
                recovery_zip_certificate_trust_verified=False)
            generated_script = script(source.read('anykernel.sh'), accepted, 'POCO F6 UAPI5 '+kind)
            with zipfile.ZipFile(path, 'w') as dest:
                for info in source.infolist():
                    if info.filename in {'Image','anykernel.sh','META-INF/com/android/otacert'} or info.filename.startswith('POCO-F6-RESUKISU'):
                        continue
                    dest.writestr(info, source.read(info.filename))
                dest.writestr(text_info('Image', 0o644), payload)
                dest.writestr(text_info('anykernel.sh', 0o755), generated_script)
                dest.writestr(text_info('POCO-F6-UAPI5-MANIFEST.json'), json.dumps(manifest, indent=2)+'\n')
                dest.writestr(text_info('POCO-F6-UAPI5-README.txt'), readme)
                dest.writestr(text_info('META-INF/com/android/otacert'), cert.read_bytes())
            work = OUT/(kind+'-signing'); work.mkdir()
            receipt = sign_generated_zip(path, cert, key, generated_root=OUT, work_dir=work,
                expected_cert_sha256=signing['certificate_der_sha256'], reserve_bytes=4*1024**3)
            verify_zip(path, cert, signing['certificate_der_sha256'])
            with zipfile.ZipFile(path) as check:
                assert check.testzip() is None and len(check.namelist()) == len(set(check.namelist()))
                assert sha(check.read('Image')) == sha(payload)
                assert check.read('anykernel.sh') == generated_script
                assert b'patch_vbmeta_flag=0' in generated_script and b'device.name1=peridot' in generated_script
                assert b'current_sha' in generated_script and b'case "$current_sha"' in generated_script
            outputs.append(dict(path=str(path), sha256=sha(path.read_bytes()), bytes=path.stat().st_size,
                accepted_input_image_sha256=accepted, bundled_image_sha256=sha(payload), signing=receipt))
    (OUT/'README.txt').write_text(readme+'\n'+json.dumps(outputs, indent=2)+'\n', encoding='utf-8')
    (OUT/'validation.json').write_text(json.dumps(dict(outputs=outputs, compatibility_report=str(AUDIT),
        device_tested=False, source_archives_modified=False), indent=2)+'\n', encoding='utf-8')
    print(json.dumps([{k:v for k,v in r.items() if k!='signing'} for r in outputs], indent=2))

if __name__ == '__main__': main()
