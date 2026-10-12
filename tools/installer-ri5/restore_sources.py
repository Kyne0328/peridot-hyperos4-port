"""Restore deleted build inputs from exact SHA256-pinned upstream sources."""
from pathlib import Path
import base64, concurrent.futures, hashlib, json, tarfile, time, urllib.request

ROOT = Path(__file__).resolve().parents[2]
CORE = ROOT / 'tools/installer-ri3/native-updater'
WORK = ROOT / 'builder/work/installer-ri3-native'
RUN = ROOT / 'builder/work/installer-ri5-recoveryfix-20261004'
WORK.mkdir(parents=True, exist_ok=True)
RUN.mkdir(exist_ok=True)
lock = json.loads((CORE / 'sources.lock.json').read_text())
production = json.loads((CORE / 'production-sources.lock.json').read_text())

def sha(data):
    return hashlib.sha256(data).hexdigest()

def acquire(url, expected, path, encoded=False):
    path = path.resolve()
    assert path.is_relative_to(WORK.resolve()), 'Destination escapes build root'
    if path.exists():
        assert sha(path.read_bytes()) == expected, 'Existing source mismatch: ' + str(path)
        return {'path': str(path.relative_to(ROOT)), 'sha256': expected, 'reused': True}
    error = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers={'User-Agent': 'Pinned-ROM-build-source-restore'}), timeout=35) as response:
                data = response.read(20 * 1024**2)
            if encoded:
                data = base64.b64decode(data, validate=True)
            assert sha(data) == expected, 'Downloaded source SHA256 mismatch'
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open('xb') as out:
                out.write(data)
            return {'path': str(path.relative_to(ROOT)), 'sha256': expected, 'url': url, 'reused': False}
        except Exception as failure:
            error = failure
            time.sleep(min(attempt + 1, 3))
    raise RuntimeError(str(path) + ': ' + str(error))

jobs = []
for name, repo in lock['aosp'].items():
    for row in repo['files']:
        jobs.append((row['url'], row['sha256'], WORK / 'vendor' / name / row['path'], True))
for row in production['files']:
    jobs.append((row['url'], row['sha256'], WORK / 'production-vendor' / row['path'], True))
extra = json.loads((CORE / 'extract/extra-sources.lock.json').read_text())
jobs.append((extra['url'], extra['sha256'], ROOT / extra['path'], True))
with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
    results = list(pool.map(lambda args: acquire(*args), jobs))
print('Restored and hash-verified', len(results), 'pinned AOSP files', flush=True)
archives = [(name, row, WORK / 'vendor') for name, row in lock['archives'].items()]
m = production['mbedtls']
archives.append(('mbedtls-3.6.7', {'url': m['url'], 'sha256': m['archive_sha256']}, WORK / 'production-vendor'))
for name, row, destination in archives:
    path = WORK / 'downloads' / row['url'].rsplit('/', 1)[1]
    results.append(acquire(row['url'], row['sha256'], path))
    with tarfile.open(path) as archive:
        for member in archive.getmembers():
            target = (destination / member.name).resolve()
            assert target.is_relative_to(destination.resolve()), 'Unsafe source archive path'
        archive.extractall(destination, filter='data')
    print('Restored pinned source archive', name, flush=True)
for row in m['files']:
    assert sha((WORK / 'production-vendor' / row['path']).read_bytes()) == row['sha256']
(RUN / 'restored-sources.json').write_text(json.dumps({'passed': True, 'inputs': results, 'mbedtls_files_verified': len(m['files'])}, indent=2) + '\n', encoding='utf-8')
print('Pinned source restoration complete', flush=True)
