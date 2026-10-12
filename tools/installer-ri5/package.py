"""Package unchanged RI4 raw images as a separately signed compressed RI5 ZIP."""
from pathlib import Path
import hashlib, json, shutil, sys, time, zipfile

ROOT = Path(__file__).resolve().parents[2]
WORK = ROOT / 'builder/work/installer-ri5-stream-20261004'
NAME = 'F6-Global-HyperOS4-DEV2-RI5-COMPRESSED-DECRYPT-20261004.zip'
sys.path.insert(0, str(ROOT / 'tools/installer-ri3/zip-signing'))
from sign_zip import sign_generated_zip

def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def info(name, size):
    i = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
    i.compress_type = zipfile.ZIP_DEFLATED
    i._compresslevel = 6
    i.create_system = 3
    i.external_attr = (0o100755 if name.endswith('update-binary') else 0o100644) << 16
    i.file_size = size
    return i

def main():
    started = time.monotonic()
    tests = json.loads((WORK / 'stream-tests.json').read_text())
    assert tests['passed']
    for name, digest in tests['source_sha256'].items():
        assert sha(ROOT / name) == digest, 'Tested source changed'
    native = json.loads((WORK / 'native/android-build-receipt.json').read_text())
    for name, digest in native['source_sha256'].items():
        assert sha(ROOT / name) == digest, 'Compiled source changed'
    binary = (WORK / 'native/update-binary').read_bytes()
    assert hashlib.sha256(binary).hexdigest() == native['binary_sha256']
    plan = json.loads((WORK / 'images.json').read_text())
    images = {x['name']: x for x in plan['images']}
    baseline = json.loads((ROOT / 'builder/work/installer-ri4-dmfix-20261004/images.json').read_text())
    assert plan == baseline, 'Partition content/ownership plan changed'
    out = WORK / 'package'
    out.mkdir(exist_ok=True)
    reserve = 8 * 1024**3  # No uncompressed staging file is created.
    total_raw = sum(x['size'] for x in images.values())
    assert shutil.disk_usage(out).free > total_raw + reserve + 128 * 1024**2
    final, partial = out / NAME, out / (NAME + '.partial')
    assert not final.exists() and not partial.exists(), 'Refuse overwrite'
    script = '''ui_print("F6 Global HyperOS4 RI5 COMPRESSED DECRYPT: slot-A installation.");
ui_print("Streaming compressed images; slot A is selected after verified success.");
assert(ri5_install());
ui_print("Install verified. Reboot Recovery, then Format Data for the encrypted-to-decrypted transition.");
ui_print("Format Data erases internal storage. No automatic data wipe was performed.");
'''
    manifest = {'build_id': 'F6-Global-HyperOS4-DEV2-RI5-COMPRESSED-DECRYPT',
        'images': [{'name': name, 'bytes': images[name]['size'], 'sha256': images[name]['sha256']} for name in native['image_order']],
        'compression': 'ZIP_DEFLATED level 6, raw images including super',
        'installer': 'held signed ZIP; metadata-only image preflight; one decompression/write/hash pass per image; fsync and full readback',
        'all_32_expanded_image_hashes_unchanged_from_RI4_DMFIX': True,
        'writes': 'shared super and 31 slot-A image prefixes; active A selected last',
        'B_physical_images_written': False, 'B_logical_images_preserved': False,
        'userdata_or_metadata_erased': False, 'encryption_configuration': 'retained RI4 DECRYPT images',
        'device_tested': False, 'production_release': False}
    small = [('META-INF/com/android/otacert', (ROOT / 'builder/work/installer-ri3-recovery/images-ziptrust/development-zip.x509.pem').read_bytes()),
        ('META-INF/com/google/android/update-binary', binary), ('META-INF/com/google/android/updater-script', script.encode()),
        ('RI5-SOURCE-MANIFEST.json', (ROOT / '.cache/global-single-recovery-ri2/source-images/MANIFEST.json').read_bytes()),
        ('RI5-BUILD-MANIFEST.json', (json.dumps(manifest, indent=2) + '\n').encode())]
    hashes = {}
    with zipfile.ZipFile(partial, 'x', allowZip64=True) as archive:
        for name, data in small:
            with archive.open(info(name, len(data)), 'w', force_zip64=True) as dst:
                dst.write(data)
            hashes[name] = hashlib.sha256(data).hexdigest()
        for name in native['image_order']:
            row = images[name]; source = Path(row['path']); before = source.stat()
            assert before.st_size == row['size'], 'Image length changed'
            print('Compressing', name, row['size'], 'bytes', flush=True)
            member = 'partitions/' + name + '.bin'; h = hashlib.sha256(); count = 0
            with source.open('rb') as src, archive.open(info(member, row['size']), 'w', force_zip64=True) as dst:
                for chunk in iter(lambda: src.read(1024 * 1024), b''):
                    dst.write(chunk); h.update(chunk); count += len(chunk)
            after = source.stat()
            assert (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            assert count == row['size'] and h.hexdigest() == row['sha256'], 'Input image hash mismatch'
            hashes[member] = h.hexdigest()
    print('Independent decompression, CRC, size and SHA256 readback of every ZIP member', flush=True)
    sizes = {}
    with zipfile.ZipFile(partial) as archive:
        assert len(archive.infolist()) == len(set(archive.namelist())) == 37
        for entry in archive.infolist():
            assert entry.compress_type == zipfile.ZIP_DEFLATED
            with archive.open(entry) as stream:
                assert hashlib.file_digest(stream, 'sha256').hexdigest() == hashes[entry.filename]
            sizes[entry.filename] = {'raw_bytes': entry.file_size, 'compressed_bytes': entry.compress_size}
    partial.rename(final)
    print('Signing and verifying the compressed ZIP', flush=True)
    signing = sign_generated_zip(final,
        ROOT / 'builder/work/installer-ri3-recovery/images-ziptrust/development-zip.x509.pem',
        ROOT / 'builder/work/installer-ri3-recovery/.private/development-zip-rsa2048.pem',
        generated_root=out, work_dir=WORK, reserve_bytes=reserve)
    receipt = {'archive': str(final), 'bytes': final.stat().st_size, 'sha256': sha(final),
        'native_sha256': native['binary_sha256'], 'all_32_expanded_image_hashes_unchanged_from_RI4_DMFIX': True,
        'all_member_decompression_crc_sha_checks_passed': True, 'member_sizes': sizes, 'signing': signing,
        'stream_tests': tests, 'build_seconds': round(time.monotonic() - started, 2),
        'phone_actions_performed': False, 'device_tested': False}
    (out / 'VALIDATION.json').write_text(json.dumps(receipt, indent=2) + '\n')
    (out / (NAME + '.sha256')).write_text(receipt['sha256'] + '  ' + NAME + '\n')
    print(json.dumps({k: receipt[k] for k in ['archive', 'bytes', 'sha256', 'build_seconds']}, indent=2), flush=True)

if __name__ == '__main__':
    main()
