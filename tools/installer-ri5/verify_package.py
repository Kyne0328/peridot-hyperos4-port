"""Run the exact compiled native read-only verifier on the completed signed ZIP."""
from pathlib import Path
import hashlib, json, os, subprocess, time

ROOT = Path(__file__).resolve().parents[2]
WORK = ROOT / 'builder/work/installer-ri5-stream-20261004'

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def linux(path):
    return '/mnt/' + path.drive[0].lower() + str(path)[2:].replace('\\', '/') if os.name == 'nt' else str(path)

receipt = json.loads((WORK / 'package/VALIDATION.json').read_text())
archive = Path(receipt['archive'])
binary = WORK / 'native/verify-host'
args = [linux(binary), '--verify-rom', linux(archive)]
if os.name == 'nt':
    args = ['wsl', '-d', 'Ubuntu', '--', *args]
print('Native read-only verification of signed compressed ZIP, every raw image hash, and Edify script', flush=True)
started = time.monotonic()
result = subprocess.run(args, capture_output=True, text=True)
verification = {'passed': result.returncode == 0 and 'RI5_READONLY_PAYLOADS_AND_EDIFY_VERIFIED' in result.stdout,
    'exit_code': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr, 'command': args,
    'archive_sha256': receipt['sha256'], 'verifier_sha256': sha(binary), 'seconds': round(time.monotonic() - started, 2),
    'device_operations_performed': False}
(WORK / 'host-verification.json').write_text(json.dumps(verification, indent=2) + '\n')
assert verification['passed'], result.stdout + result.stderr
receipt['host_native_readonly_verification'] = verification
(WORK / 'package/VALIDATION.json').write_text(json.dumps(receipt, indent=2) + '\n')
print(json.dumps(verification, indent=2), flush=True)
