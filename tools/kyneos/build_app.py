"""Build the permission-free KyneOS Settings destination with the pinned ROM certificate."""
from pathlib import Path
import hashlib, json, os, subprocess, zipfile
from cryptography.hazmat.primitives import serialization

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'builder/work/kyneos-ri7-20261005/app'
SOURCE = Path(__file__).parent / 'app'

def main():
    OUT.mkdir(parents=True, exist_ok=True)
    sdk = Path(os.environ['LOCALAPPDATA']) / 'Android/Sdk'
    tools = sdk / 'build-tools/37.0.0'; android = sdk / 'platforms/android-37.2/android.jar'
    java = Path('C:/Program Files/Android/Android Studio/jbr/bin/java.exe')
    javac = java.with_name('javac.exe')
    signing = json.loads((ROOT / 'builder/work/installer-ri5-recoveryfix-20261004/signing-public.json').read_text())
    key = serialization.load_pem_private_key((ROOT / signing['private_key_path']).read_bytes(), None)
    pk8 = ROOT / '.private/kyneos/app-pkcs8.der'; pk8.parent.mkdir(parents=True, exist_ok=True)
    # Reuse protected signing storage; no key material is included in the output.
    owner = subprocess.run(['whoami'], capture_output=True, text=True, check=True).stdout.strip()
    subprocess.run(['icacls', str(pk8.parent), '/inheritance:r', '/grant:r', owner + ':(OI)(CI)F'], capture_output=True, check=True)
    if not pk8.exists():
        pk8.write_bytes(key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    classes = OUT / 'classes'; classes.mkdir(exist_ok=True)
    dex = OUT / 'dex'; dex.mkdir(exist_ok=True)
    commands = []
    def run(command):
        command = list(map(str, command)); result = subprocess.run(command, capture_output=True, text=True)
        commands.append({'argv': command, 'exit_code': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr})
        assert result.returncode == 0, result.stderr + result.stdout
        return result.stdout
    run([javac, '-source', '11', '-target', '11', '-classpath', android, '-d', classes, SOURCE / 'UpdateActivity.java'])
    run([java, '-cp', tools / 'lib/d8.jar', 'com.android.tools.r8.D8', '--lib', android, '--min-api', '28', '--output', dex, *classes.rglob('*.class')])
    run([tools / 'aapt2.exe', 'link', '-I', android, '--manifest', SOURCE / 'AndroidManifest.xml', '-o', OUT / 'unsigned.apk'])
    with zipfile.ZipFile(OUT / 'unsigned.apk', 'a') as z:
        z.write(dex / 'classes.dex', 'classes.dex', compress_type=zipfile.ZIP_DEFLATED)
    run([tools / 'zipalign.exe', '-f', '4', OUT / 'unsigned.apk', OUT / 'aligned.apk'])
    apk = OUT / 'KyneOSInfo.apk'
    run([java, '-jar', tools / 'lib/apksigner.jar', 'sign', '--key', pk8, '--cert', ROOT / signing['certificate_path'], '--out', apk, OUT / 'aligned.apk'])
    run([java, '-jar', tools / 'lib/apksigner.jar', 'verify', '--verbose', apk])
    manifest = run([tools / 'aapt2.exe', 'dump', 'xmltree', apk, '--file', 'AndroidManifest.xml'])
    assert 'com.android.updater' in manifest and '.UpdateActivity' in manifest and 'uses-permission' not in manifest
    receipt = {'apk': str(apk), 'sha256': hashlib.sha256(apk.read_bytes()).hexdigest(), 'bytes': apk.stat().st_size,
               'package': 'com.android.updater', 'activity': 'com.android.updater.UpdateActivity', 'requests_permissions': False,
               'source_hashes': {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in SOURCE.iterdir()}, 'commands': commands}
    (OUT / 'VALIDATION.json').write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({k: receipt[k] for k in ['apk', 'sha256', 'bytes']}, indent=2))

if __name__ == '__main__': main()
