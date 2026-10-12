"""Restore the previously authenticated QEMU tool into this task, without installation."""
from pathlib import Path
import hashlib, json, subprocess, tarfile, urllib.request

ROOT = Path(__file__).resolve().parents[2]
WORK = ROOT / 'builder/work/kyneos-ri7-20261005/arm64-tools'

def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def linux(path): return '/mnt/' + path.drive[0].lower() + str(path)[2:].replace('\\', '/')

def main():
    WORK.mkdir(parents=True, exist_ok=True)
    provenance = json.loads((ROOT / '09-reports/installer-ri3/arm64-harness/tool-provenance.json').read_text())
    assert provenance['status'] == 'verified' and provenance['release']['returncode'] == 0
    package = next(p for p in provenance['packages'] if p['name'] == 'qemu-user-static')
    deb = WORK / 'qemu-user-static.deb'
    if not deb.exists():
        with urllib.request.urlopen(package['url'], timeout=45) as response:
            data = response.read(package['deb_bytes'] + 1)
        assert len(data) == package['deb_bytes'] and hashlib.sha256(data).hexdigest() == package['deb_sha256']
        deb.write_bytes(data)
    assert sha(deb) == package['deb_sha256']
    process = subprocess.Popen(['wsl', '-d', 'Ubuntu', '--exec', 'dpkg-deb', '--fsys-tarfile', linux(deb)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    with tarfile.open(fileobj=process.stdout, mode='r|') as tar:
        for member in tar:
            clean = member.name.removeprefix('./')
            if clean != 'usr/bin/qemu-aarch64-static': continue
            assert member.isfile() and not member.mode & 0o6000
            data = tar.extractfile(member).read(); pin = next(p for p in package['extracted'] if p['member'] == clean)
            assert hashlib.sha256(data).hexdigest() == pin['sha256']
            (WORK / 'qemu-aarch64-static').write_bytes(data)
    assert process.wait() == 0, process.stderr.read().decode(errors='replace')
    # Keep the established regular-file-only, no-network, no-device jail. Raise only
    # the CPU budget for a complete ROM instead of small crypto fixtures.
    source = ROOT / 'tools/installer-ri3/arm64-harness/jail.c'
    text = source.read_text(); assert 'cpu={20,20}' in text
    text = text.replace('cpu={20,20}', 'cpu={1800,1800}')
    text = text.replace(' || setenv("HOME","/",1)', '')
    (WORK / 'jail.c').write_text(text)
    subprocess.run(['wsl', '-d', 'Ubuntu', '--exec', '/usr/bin/cc', '-O2', '-static', linux(WORK / 'jail.c'), '-o', linux(WORK / 'ri7-file-jail')], check=True)
    result = {'qemu_package': package, 'qemu_sha256': sha(WORK / 'qemu-aarch64-static'),
              'launcher_source_sha256': sha(WORK / 'jail.c'), 'launcher_sha256': sha(WORK / 'ri7-file-jail'),
              'original_jail_source_sha256': sha(source), 'cpu_limit_seconds': 1800, 'package_installed': False, 'maintainer_scripts_run': False}
    (WORK / 'PROVENANCE.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print('Authenticated task-local QEMU and regular-file jail ready', flush=True)

if __name__ == '__main__': main()
