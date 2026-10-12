"""Emit a separately named RI4 updater repair, preserving all source archives."""
from pathlib import Path
import hashlib, json, os, shutil, subprocess, sys, zipfile

ROOT = Path(__file__).resolve().parents[2]
OLD = ROOT / 'builder/work/installer-ri4-orangefox-202610021801'
WORK = ROOT / 'builder/work/installer-ri4-dmfix-20261004'
NAME = 'F6-Global-HyperOS4-DEV2-RI4-DECRYPT-OF202610021801-DMFIX-20261004.zip'
sys.path.insert(0, str(ROOT / 'tools/installer-ri3/zip-signing'))
from sign_zip import sign_generated_zip

def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')

def prepare():
    WORK.mkdir(exist_ok=True)
    for name in ['images.json', 'hal_query.cpp']:
        target = WORK / name
        assert not target.exists(), 'Refuse overwrite: ' + str(target)
        shutil.copyfile(OLD / name, target)
    env = os.environ.copy()
    env['RI4_BUILD_WORK'] = str(WORK)
    env['RI4_BACKEND_ARCHIVE'] = str(ROOT / 'builder/work/installer-ri3-native/backend/closure-ri4-dm-abi-20261004/libbackend-ri3.a')
    subprocess.run([sys.executable, str(ROOT / 'tools/installer-ri4/build_updater.py')], env=env, check=True)

def package():
    tests = json.loads((WORK / 'dm-abi-tests.json').read_text())
    assert tests['passed'] and tests['source_sha256'] == digest(ROOT / 'tools/installer-ri3/native-updater/backend/libdm_adapter.cpp')
    old_receipt = json.loads((OLD / 'package/VALIDATION.json').read_text())
    old = Path(old_receipt['archive'])
    assert digest(old) == old_receipt['sha256'], 'Source archive hash mismatch'
    native_receipt = json.loads((WORK / 'native/build-receipt.json').read_text())
    native = (WORK / 'native/update-binary').read_bytes()
    assert hashlib.sha256(native).hexdigest() == native_receipt['binary_sha256']
    out = WORK / 'package'
    out.mkdir(exist_ok=True)
    assert shutil.disk_usage(out).free > old.stat().st_size + 12 * 1024**3
    final, partial = out / NAME, out / (NAME + '.partial')
    assert not final.exists() and not partial.exists()
    hashes, changed = {}, {}
    with zipfile.ZipFile(old) as source, zipfile.ZipFile(partial, 'x', allowZip64=True) as target:
        manifest = json.loads(source.read('RI4-BUILD-MANIFEST.json'))
        manifest.update(installer_revision='DMFIX-20261004', device_mapper_request_abi='4.0.0',
            accepts_kernel_header_without_tail_padding=True, topology_probe_before_image_scan=True,
            verification_stage_messages=True, device_tested=False)
        script = source.read('META-INF/com/google/android/updater-script').replace(b'RI4 DECRYPT:', b'RI4 DECRYPT DMFIX:')
        replacements = {'META-INF/com/google/android/update-binary': native,
            'META-INF/com/google/android/updater-script': script,
            'RI4-BUILD-MANIFEST.json': (json.dumps(manifest, indent=2) + '\n').encode()}
        for entry in source.infolist():
            name = entry.filename
            print('Packaging', name, flush=True)
            data = replacements.get(name)
            info = zipfile.ZipInfo(name, entry.date_time)
            info.create_system, info.external_attr = entry.create_system, entry.external_attr
            info.compress_type = zipfile.ZIP_STORED
            info.file_size = len(data) if data is not None else entry.file_size
            h, prior = hashlib.sha256(), hashlib.sha256()
            with target.open(info, 'w', force_zip64=True) as dst, source.open(entry) as src:
                if data is not None:
                    dst.write(data); h.update(data)
                for chunk in iter(lambda: src.read(1024 * 1024), b''):
                    prior.update(chunk)
                    if data is None:
                        dst.write(chunk); h.update(chunk)
            hashes[name] = h.hexdigest()
            if h.hexdigest() != prior.hexdigest():
                changed[name] = {'old_sha256': prior.hexdigest(), 'new_sha256': h.hexdigest()}
        assert set(changed) == set(replacements)
    print('Checking all output member CRCs and hashes', flush=True)
    with zipfile.ZipFile(partial) as archive:
        assert len(archive.infolist()) == 37
        for entry in archive.infolist():
            with archive.open(entry) as stream:
                assert hashlib.file_digest(stream, 'sha256').hexdigest() == hashes[entry.filename]
    partial.rename(final)
    print('Signing and independently verifying complete ZIP', flush=True)
    signing = sign_generated_zip(final,
        ROOT / 'builder/work/installer-ri3-recovery/images-ziptrust/development-zip.x509.pem',
        ROOT / 'builder/work/installer-ri3-recovery/.private/development-zip-rsa2048.pem',
        generated_root=out, work_dir=WORK)
    receipt = {'archive': str(final), 'bytes': final.stat().st_size, 'sha256': digest(final),
        'source_archive_sha256': old_receipt['sha256'], 'changes': changed,
        'all_32_partition_payloads_byte_identical': True, 'all_member_crc_sha_checks_passed': True,
        'expanded_super': old_receipt['expanded_super_unchanged_verified_by_encoded_identity'],
        'native_sha256': native_receipt['binary_sha256'], 'dm_abi_tests': tests,
        'signing': signing, 'phone_actions_performed': False, 'device_tested': False}
    save(out / 'VALIDATION.json', receipt)
    (out / (NAME + '.sha256')).write_text(receipt['sha256'] + '  ' + NAME + '\n')
    print(json.dumps({k: receipt[k] for k in ['archive', 'bytes', 'sha256']}, indent=2), flush=True)

if __name__ == '__main__':
    {'prepare': prepare, 'package': package}[sys.argv[1]]()
