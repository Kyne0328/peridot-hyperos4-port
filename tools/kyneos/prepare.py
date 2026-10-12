"""Freeze RI6 inputs and copy bounded SSD authoring inputs for RI7."""
from pathlib import Path
import hashlib, json, shutil

ROOT = Path(__file__).resolve().parents[2]
WORK = ROOT / 'builder/work/kyneos-ri7-20261005'
OLD = Path('D:/hyperos4-peridot-postboot-20261004')

def sha(path):
    with Path(path).open('rb') as stream: return hashlib.file_digest(stream, 'sha256').hexdigest()

def main():
    WORK.mkdir(parents=True, exist_ok=True)
    previous = json.loads((OLD / 'outputs/VALIDATION.json').read_text())
    archive = Path(previous['archive'])
    print('Hashing immutable RI6 source archive', flush=True)
    assert archive.stat().st_size == previous['bytes'] and sha(archive) == previous['sha256']
    assembly = json.loads((OLD / 'ASSEMBLY.json').read_text())
    pins = {row['name']: row for row in assembly['pins']}
    assert sha(OLD / 'super.img') == pins['super']['sha256']
    assert shutil.disk_usage(WORK).free > 55 * 1024**3
    files = {'product-source.img': (OLD / 'product.img', assembly['images']['product']['sha256']),
             'super-source.img': (OLD / 'super.img', pins['super']['sha256'])}
    # All files needed by independent AVB verification, without re-extracting proprietary trees.
    for name in ['system', 'system_ext', 'odm', 'mi_ext', 'vendor', 'system_dlkm', 'vendor_dlkm',
                 'vbmeta', 'vbmeta_system', 'boot', 'recovery', 'dtbo', 'init_boot', 'vendor_boot', 'countrycode']:
        path = OLD / (name + '.img')
        digest = assembly['images'][name]['sha256'] if name in assembly['images'] else pins[name]['sha256'] if name in pins else sha(path)
        files[name + '.img'] = (path, digest)
    receipts = {}
    for name, (source, digest) in files.items():
        target = WORK / name
        if not target.exists():
            print('Copying verified input', name, flush=True)
            shutil.copyfile(source, target)
        assert sha(target) == digest, name
        receipts[name] = {'source': str(source), 'path': str(target), 'sha256': digest, 'bytes': target.stat().st_size}
    manifest = {'source_archive': str(archive), 'source_archive_sha256': previous['sha256'],
                'source_archive_bytes': previous['bytes'], 'files': receipts, 'old_assembly': assembly,
                'build_id': 'KYNEOS-RI7.1-20261005', 'source_archives_modified': False}
    (WORK / 'INPUTS.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    (ROOT / '00-manifest/kyneos-ri7-20261005.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    print('Frozen inputs verified', flush=True)

if __name__ == '__main__': main()
