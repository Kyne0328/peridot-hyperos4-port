"""Package RI7 as a separate signed complete recovery ZIP; never alter RI6."""
from pathlib import Path
import hashlib, json, shutil, sys, zipfile

ROOT = Path(__file__).resolve().parents[2]
WORK = ROOT / 'builder/work/kyneos-ri7-20261005'
OUT = Path('D:/hyperos4-peridot-kyneos-ri7-20261005/outputs')
NAME = 'KyneOS-Global-HyperOS4-POCO-F6-RI7.1-20261005.zip'
sys.path[:0] = [str(ROOT / 'tools/installer-ri3/zip-signing'), str(ROOT / 'tools/installer-ri5')]
from sign_zip import sign_generated_zip
from compressed_copy import copy_member

def sha(path):
    with Path(path).open('rb') as f: return hashlib.file_digest(f, 'sha256').hexdigest()

def main():
    inputs = json.loads((WORK / 'INPUTS.json').read_text()); source = Path(inputs['source_archive'])
    assembly = json.loads((WORK / 'ASSEMBLY.json').read_text())
    avb = json.loads((WORK / 'AVB-VERIFICATION.json').read_text()); assert avb['passed']
    native = json.loads((ROOT / 'builder/work/installer-ri5-recoveryfix-20261004/native-android-new-kyneosri7/build-receipt.json').read_text())
    binary = Path(native['binary']).read_bytes(); assert hashlib.sha256(binary).hexdigest() == native['binary_sha256']
    for name, digest in native['sources'].items(): assert sha(ROOT / name) == digest, 'Compiled source drift: ' + name
    assert sha(source) == inputs['source_archive_sha256']
    pins = {row['name']: row for row in assembly['pins']}; assert len(pins) == 32
    for name in assembly['changed_image_payloads']: assert sha(WORK / (name + '.img')) == pins[name]['sha256']
    OUT.mkdir(parents=True, exist_ok=True); assert shutil.disk_usage(OUT).free > 15 * 1024**3
    partial = OUT / (NAME + '.partial'); final = OUT / NAME; assert not partial.exists() and not final.exists()
    script = '''ui_print("KyneOS RI7.1: Global HyperOS 4 for POCO F6.");
ui_print("Port maintained by Kyne. Bluetooth, lock style and Settings information update.");
assert(ri5_install());
ui_print("Complete image set verified; slot A selected after success.");
ui_print("Reboot Recovery, then System. Existing RI6 DECRYPT data needs no Format Data.");
'''
    member_hashes = {}; names = []
    with zipfile.ZipFile(source) as old, zipfile.ZipFile(partial, 'x', allowZip64=True) as target:
        manifest = json.loads(old.read('RI5-BUILD-MANIFEST.json'))
        manifest.update(build_id=inputs['build_id'], installer_revision='RI7.1-KYNEOS',
                        images=[{k: v for k, v in row.items() if k in ['name', 'bytes', 'sha256']} for row in assembly['pins']],
                        kyneos={'name': 'KyneOS', 'description': 'Global HyperOS 4 for POCO F6', 'maintainer': 'Kyne',
                                'properties': {'debug.hwui.renderer': 'skiavk', 'persist.sys.support.sar.device': 'peridot'},
                                'settings_information_activity': 'com.android.updater/com.android.updater.UpdateActivity'},
                        install_over='RI6 POSTBOOT FIX1 DECRYPT', userdata_format_required=False,
                        preintegration_owner_validation={'lock_style_open_customize_apply_lock_unlock': True, 'bluetooth_discovery_pairing': True},
                        integrated_build_flash_tested=False)
        replacements = {'META-INF/com/google/android/update-binary': binary,
                        'META-INF/com/google/android/updater-script': script.encode(),
                        'RI5-BUILD-MANIFEST.json': (json.dumps(manifest, indent=2) + '\n').encode()}
        for entry in old.infolist():
            name = entry.filename; names.append(name)
            partition = name.split('/')[-1][:-4] if name.startswith('partitions/') else None
            if partition not in assembly['changed_image_payloads'] and name not in replacements:
                copy_member(source, old, target, entry)
                member_hashes[name] = pins[partition]['sha256'] if partition else hashlib.sha256(old.read(entry)).hexdigest()
                continue
            info = zipfile.ZipInfo(name, entry.date_time); info.create_system = entry.create_system; info.external_attr = entry.external_attr
            info.compress_type = zipfile.ZIP_DEFLATED; info._compresslevel = 6
            h = hashlib.sha256(); count = 0
            if partition in assembly['changed_image_payloads']:
                path = WORK / (partition + '.img'); info.file_size = path.stat().st_size
                print('Compressing', partition, flush=True)
                with target.open(info, 'w', force_zip64=True) as dst, path.open('rb') as src:
                    for block in iter(lambda: src.read(1024**2), b''): dst.write(block); h.update(block); count += len(block)
                assert count == pins[partition]['bytes'] and h.hexdigest() == pins[partition]['sha256']
            else:
                data = replacements[name]; info.file_size = len(data)
                with target.open(info, 'w', force_zip64=True) as dst: dst.write(data)
                h.update(data)
            member_hashes[name] = h.hexdigest()
    print('Verifying every decoded member CRC and SHA256', flush=True)
    with zipfile.ZipFile(partial) as z:
        assert z.namelist() == names and len(names) == len(set(names)) == 37
        for entry in z.infolist():
            with z.open(entry) as f: assert hashlib.file_digest(f, 'sha256').hexdigest() == member_hashes[entry.filename], entry.filename
    partial.rename(final)
    signing = json.loads((ROOT / 'builder/work/installer-ri5-recoveryfix-20261004/signing-public.json').read_text())
    signature = sign_generated_zip(final, ROOT / signing['certificate_path'], ROOT / signing['private_key_path'],
                                   generated_root=OUT, generated_parent=OUT.parent, work_dir=WORK,
                                   expected_cert_sha256=signing['certificate_der_sha256'], reserve_bytes=4 * 1024**3)
    result = {'archive': str(final), 'bytes': final.stat().st_size, 'sha256': sha(final), 'source_sha256': inputs['source_archive_sha256'],
              'member_hashes': member_hashes, 'member_count': 37, 'partition_payload_count': 32, 'native_sha256': native['binary_sha256'],
              'all_member_crc_sha_checks_passed': True, 'signature': signature, 'avb_verification_passed': True,
              'userdata_format_required': False, 'integrated_build_device_flash_tested': False}
    (OUT / 'VALIDATION.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    (OUT / (NAME + '.sha256')).write_text(result['sha256'] + '  ' + NAME + '\n', encoding='utf-8')
    print(json.dumps({k: result[k] for k in ['archive', 'bytes', 'sha256']}, indent=2), flush=True)

if __name__ == '__main__': main()
