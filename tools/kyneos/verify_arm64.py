"""Run only the ARM64 updater's read-only ROM verifier in a regular-file jail."""
from pathlib import Path
import hashlib, json, shutil, subprocess, time

ROOT = Path(__file__).resolve().parents[2]
WORK = ROOT / 'builder/work/kyneos-ri7-20261005'
OUT = Path('D:/hyperos4-peridot-kyneos-ri7-20261005/outputs')

def sha(path):
    with Path(path).open('rb') as f: return hashlib.file_digest(f, 'sha256').hexdigest()
def linux(path): return '/mnt/' + path.drive[0].lower() + str(path)[2:].replace('\\', '/')

def main():
    validation = json.loads((OUT / 'VALIDATION.json').read_text())
    archive = Path(validation['archive']); assert sha(archive) == validation['sha256']
    native = ROOT / 'builder/work/installer-ri5-recoveryfix-20261004/native-android-new-kyneosri7/update-binary'
    assert sha(native) == validation['native_sha256']
    tools = WORK / 'arm64-tools'; provenance = json.loads((tools / 'PROVENANCE.json').read_text())
    for name, key in [('qemu-aarch64-static', 'qemu_sha256'), ('ri7-file-jail', 'launcher_sha256')]: assert sha(tools / name) == provenance[key]
    jail = OUT.parent / 'readonly-arm64'; jail.mkdir(exist_ok=False)
    # Hard-link only the generated finalized archive on its existing volume. The
    # jail enforces read-only access; inputs cannot be changed by the verifier.
    (jail / 'rom.zip').hardlink_to(archive)
    shutil.copyfile(tools / 'qemu-aarch64-static', jail / 'qemu-aarch64-static')
    shutil.copyfile(native, jail / 'update-binary')
    assert not (jail / 'dev').exists() and not (jail / 'proc').exists()
    subprocess.run(['wsl', '-d', 'Ubuntu', '--exec', 'chmod', '700', linux(jail / 'qemu-aarch64-static'), linux(jail / 'update-binary'), linux(tools / 'ri7-file-jail')], check=True)
    before = archive.stat()
    command = ['wsl', '-d', 'Ubuntu', '--exec', '/usr/bin/unshare', '--user', '--map-root-user', '--mount', '--net', '--pid', '--fork', '--kill-child', '--ipc',
               '--propagation', 'unchanged', linux(tools / 'ri7-file-jail'), linux(jail), '/qemu-aarch64-static', '/update-binary', '--verify-rom', '/rom.zip']
    start = time.monotonic(); print('ARM64 read-only signature, image payload and Edify verification', flush=True)
    result = subprocess.run(command, capture_output=True, text=True, timeout=1900)
    after = archive.stat()
    identity_unchanged = (before.st_size, before.st_mtime_ns, before.st_ino) == (after.st_size, after.st_mtime_ns, after.st_ino)
    passed = result.returncode == 0 and 'RI5_READONLY_PAYLOADS_AND_EDIFY_VERIFIED' in result.stdout and identity_unchanged
    receipt = {'passed': passed, 'argv': command, 'exit_code': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr,
               'elapsed_seconds': round(time.monotonic() - start, 2), 'archive_sha256': validation['sha256'], 'archive_identity_unchanged': identity_unchanged,
               'native_sha256': validation['native_sha256'], 'tools': provenance, 'execution': 'ARM64 QEMU in read-only Landlock/seccomp regular-file jail',
               'device_test': False, 'partition_writes_or_flash_performed': False}
    (OUT / 'ARM64-READONLY-VERIFICATION.json').write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
    print(result.stdout, flush=True); print(result.stderr, flush=True)
    assert passed, 'ARM64 read-only verifier failed; see receipt'

if __name__ == '__main__': main()
