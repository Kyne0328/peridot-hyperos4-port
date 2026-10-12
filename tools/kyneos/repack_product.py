"""Rebuild only the RI6 product filesystem, with complete file and metadata readback."""
from pathlib import Path
import base64, hashlib, io, json, os, stat, struct, subprocess, sys, tarfile, uuid

ROOT = Path(__file__).resolve().parents[2]
WORK = ROOT / 'builder/work/kyneos-ri7-20261005'
TOOLS = ROOT / 'builder/tools/bin/windows'
sys.path.insert(0, str(ROOT / 'tools/postboot'))
from image import Image
from repack_windows import Reader, output_hash, sha, small

def main():
    inputs = json.loads((WORK / 'INPUTS.json').read_text())
    source = WORK / 'product-source.img'; assert sha(source) == inputs['files'][source.name]['sha256']
    original = Image(source); rows = original.inventory(); by = {x['path']: x for x in rows}
    replacements = {}; changes = []
    props = {'debug.hwui.renderer': 'skiavk', 'persist.sys.support.sar.device': 'peridot',
             'ro.kyneos.build.id': 'KYNEOS-RI7.1-20261005', 'ro.kyneos.version': 'RI7.1', 'ro.kyneos.maintainer': 'Kyne'}
    before = small(source, by['/etc/build.prop']['nid'])
    lines = before.decode().splitlines()
    for key, value in props.items():
        assert sum(line.startswith(key + '=') for line in lines) <= 1
        lines = [line for line in lines if not line.startswith(key + '=')]
    after = ('\n'.join(lines) + '\n\n# KyneOS: device-tested rendering and Bluetooth compatibility.\n' +
             ''.join(key + '=' + value + '\n' for key, value in props.items())).encode()
    assert b'ro.miui.product.home=com.miui.home' in after
    replacements['/etc/build.prop'] = after
    changes.append({'path': '/etc/build.prop', 'before_sha256': hashlib.sha256(before).hexdigest(), 'after_sha256': hashlib.sha256(after).hexdigest(), 'properties': props})
    folder = '/app/KyneOSInfo'; path = folder + '/KyneOSInfo.apk'
    assert folder not in by and path not in by
    directory = dict(by['/app'], path=folder, nid=-1); rows.append(directory)
    template = next(row for row in rows if row['path'].startswith('/app/') and row['path'].endswith('.apk'))
    apk = WORK / 'app/KyneOSInfo.apk'; apk_pin = json.loads((WORK / 'app/VALIDATION.json').read_text())
    assert sha(apk) == apk_pin['sha256']
    data = apk.read_bytes(); replacements[path] = data
    rows.append(dict(template, path=path, nid=-2, size=len(data)))
    changes.append({'path': path, 'before_sha256': None, 'after_sha256': apk_pin['sha256'], 'settings_route': 'com.android.updater/com.android.updater.UpdateActivity'})
    tar = WORK / 'product.tar'; assert not tar.exists(); expected = []; seen = {}; hashes = {}
    print('Streaming complete RI6 product contents with scoped changes', flush=True)
    with tarfile.open(tar, 'x', format=tarfile.PAX_FORMAT) as archive:
        for index, row in enumerate(sorted(rows, key=lambda x: (x['path'].count('/'), x['path']))):
            path = row['path']; entry = tarfile.TarInfo(path.lstrip('/') or '.')
            entry.mode = row['mode'] & 0o7777; entry.uid = row['uid']; entry.gid = row['gid']; entry.mtime = 1230768000
            entry.pax_headers = {'LIBARCHIVE.xattr.' + k: base64.b64encode(bytes.fromhex(v)).decode() for k, v in row['xattrs'].items()}
            value = {k: row[k] for k in ['path', 'mode', 'uid', 'gid', 'xattrs']}
            if stat.S_ISDIR(row['mode']): entry.type = tarfile.DIRTYPE; archive.addfile(entry)
            elif stat.S_ISLNK(row['mode']):
                data = small(source, row['nid']); entry.type = tarfile.SYMTYPE; entry.linkname = data.decode(); archive.addfile(entry)
                value.update(size=len(data), sha256=hashlib.sha256(data).hexdigest())
            elif stat.S_ISREG(row['mode']):
                if path in replacements:
                    data = replacements[path]; entry.size = len(data); archive.addfile(entry, io.BytesIO(data)); digest = hashlib.sha256(data).hexdigest()
                elif row['nid'] in seen:
                    entry.type = tarfile.LNKTYPE; entry.linkname = seen[row['nid']]; archive.addfile(entry)
                    entry.size = row['size']; digest = hashes[row['nid']]
                else:
                    entry.size = row['size']
                    process = subprocess.Popen([str(TOOLS / 'dump.erofs.exe'), '--cat', '--nid=' + str(row['nid']), str(source)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    reader = Reader(process.stdout); archive.addfile(entry, reader)
                    assert reader.count == entry.size and not process.stdout.read(1)
                    error = process.stderr.read(); assert process.wait() == 0, error.decode(errors='replace'); digest = reader.h.hexdigest()
                if row['nid'] not in seen: seen[row['nid']] = entry.name; hashes[row['nid']] = digest
                value.update(size=entry.size, sha256=digest)
            else: raise ValueError('Unexpected special inode ' + path)
            expected.append(value)
            if index % 400 == 0: print('Prepared', index, '/', len(rows), flush=True)
    original.close()
    assert {x['path'] for x in expected} == set(by) | {folder, '/app/KyneOSInfo/KyneOSInfo.apk'}
    output = WORK / 'product-filesystem.img'; assert not output.exists()
    temp = WORK / 'tmp-native'; temp.mkdir(exist_ok=True)
    env = os.environ.copy(); env.update(TMPDIR=str(temp), TEMP=str(temp), TMP=str(temp))
    with source.open('rb') as f: f.seek(1072); ident = uuid.UUID(bytes=f.read(16))
    output.touch(); subprocess.run(['fsutil', 'sparse', 'setflag', str(output)], check=True)
    subprocess.run([str(TOOLS / 'mkfs.erofs.exe'), '-d0', '-T1230768000', '-U', str(ident), '-zlz4hc,level=12', '--tar=f', str(output), str(tar)], env=env, check=True)
    assert output.stat().st_size < source.stat().st_size - 8 * 1024**2
    headers = {}
    for path in [source, output]:
        with path.open('rb') as f: f.seek(1024); header = f.read(128)
        headers[path.name] = {'magic': hex(struct.unpack_from('<I', header)[0]),
                              'feature_compat': hex(struct.unpack_from('<I', header, 8)[0]),
                              'block_bits': header[12], 'superblock_extension_slots': header[13],
                              'feature_incompat': hex(struct.unpack_from('<I', header, 80)[0]),
                              'compression_configuration': header[84:88].hex()}
    assert headers[source.name] == headers[output.name], 'EROFS compatibility features changed'
    subprocess.run([str(TOOLS / 'fsck.erofs.exe'), '--extract', str(output)], env=env, check=True)
    image = Image(output); actual = {row['path']: row for row in image.inventory()}
    assert actual.keys() == {row['path'] for row in expected}
    for index, row in enumerate(expected):
        got = actual[row['path']]
        for key in ['mode', 'uid', 'gid', 'xattrs']: assert got[key] == row[key], (row['path'], key)
        if 'sha256' in row: assert output_hash(output, got['nid'], row['size']) == row['sha256'], row['path']
        if index % 400 == 0: print('Verified', index, '/', len(expected), flush=True)
    image.close()
    (WORK / 'FILESYSTEM-COMPATIBILITY.json').write_text(json.dumps({'passed': True, 'source_and_output': headers,
                                                                 'all_files_independently_decoded': True}, indent=2) + '\n', encoding='utf-8')
    receipt = {'partition': 'product', 'source_sha256': inputs['files'][source.name]['sha256'], 'filesystem_path': str(output),
               'filesystem_sha256': sha(output), 'filesystem_bytes': output.stat().st_size, 'allocation_bytes': source.stat().st_size,
               'all_file_hashes_modes_uid_gid_xattrs_verified': True, 'changes': changes, 'entries': expected,
               'prepared_tar_sha256': sha(tar), 'phone_partition_flash_performed': False}
    (WORK / 'product-repack.json').write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
    print('Product filesystem independently verified', flush=True)

if __name__ == '__main__': main()
