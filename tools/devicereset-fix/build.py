"""Build and sign the narrowly scoped DeviceReset/Vector compatibility add-on."""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[2]
SOURCE = Path(__file__).parent
OUT = ROOT / 'builder/work/devicereset-repair-20261013/build'
API_SHA256 = 'f48c635f1c7469fdec0e00ad2ea0b7a6b2f5b55065784a35b7ca3a84615e8e25'


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    scratch = Path(tempfile.mkdtemp(prefix='compile-', dir=OUT))
    sdk = Path(os.environ.get('ANDROID_SDK_ROOT', str(Path(os.environ['LOCALAPPDATA']) / 'Android/Sdk')))
    bt = sdk / 'build-tools/37.0.0'
    android = sdk / 'platforms/android-37.2/android.jar'
    jdk = Path(os.environ.get('JAVA_HOME', 'C:/Program Files/Android/Android Studio/jbr')) / 'bin'
    api = Path(os.environ.get('XPOSED_API_JAR', str(ROOT / 'builder/work/battery-health-20261011/deps/api-82.jar')))
    assert hashlib.sha256(api.read_bytes()).hexdigest() == API_SHA256, 'Xposed API hash mismatch'
    commands = []

    def run(argv):
        result = subprocess.run(list(map(str, argv)), capture_output=True, text=True)
        commands.append({'argv': list(map(str, argv)), 'exit_code': result.returncode,
                         'stdout': result.stdout, 'stderr': result.stderr})
        (OUT / 'commands.json').write_text(json.dumps(commands, indent=2), encoding='utf-8')
        if result.returncode: raise RuntimeError(result.stdout + result.stderr)
        return result.stdout

    tests = scratch / 'tests'; tests.mkdir()
    run([jdk / 'javac.exe', '--release', '11', '-d', tests,
         SOURCE / 'app/ScopePlan.java', SOURCE / 'test/ScopePlanTest.java'])
    print(run([jdk / 'java.exe', '-cp', tests, 'io.kyne.deviceresetfix.ScopePlanTest']).strip())
    classes = scratch / 'classes'; classes.mkdir()
    sources = sorted((SOURCE / 'app').glob('*.java'))
    run([jdk / 'javac.exe', '-source', '11', '-target', '11', '-cp',
         str(android) + os.pathsep + str(api), '-d', classes, *sources])
    dex = scratch / 'dex'; dex.mkdir()
    run([jdk / 'java.exe', '-cp', bt / 'lib/d8.jar', 'com.android.tools.r8.D8',
         '--lib', android, '--classpath', api, '--min-api', '28', '--output', dex,
         *sorted(classes.rglob('*.class'))])
    resources = OUT / 'resources.zip'
    run([bt / 'aapt2.exe', 'compile', '--dir', SOURCE / 'app/res', '-o', resources])
    unsigned = OUT / 'unsigned.apk'
    run([bt / 'aapt2.exe', 'link', '-I', android, '--manifest', SOURCE / 'app/AndroidManifest.xml',
         '-o', unsigned, resources])
    with zipfile.ZipFile(unsigned, 'a') as archive:
        archive.write(dex / 'classes.dex', 'classes.dex', compress_type=zipfile.ZIP_DEFLATED)
        archive.write(SOURCE / 'app/assets/xposed_init', 'assets/xposed_init', compress_type=zipfile.ZIP_DEFLATED)
    aligned = OUT / 'aligned.apk'
    run([bt / 'zipalign.exe', '-f', '4', unsigned, aligned])
    keys = ROOT / '.private/kyneos/devicereset-fix'; keys.mkdir(parents=True, exist_ok=True)
    who = run(['whoami']).strip()
    run(['icacls', keys, '/inheritance:r', '/grant:r', who + ':(OI)(CI)F'])
    keystore = keys / 'module.p12'
    if not keystore.exists():
        run([jdk / 'keytool.exe', '-genkeypair', '-keystore', keystore, '-storepass', 'android',
             '-keypass', 'android', '-alias', 'devicereset-fix', '-keyalg', 'RSA', '-keysize', '3072',
             '-validity', '10000', '-dname', 'CN=DeviceReset Vector Compatibility'])
    apk = OUT / 'DeviceReset-Vector-Compatibility-v3.apk'
    run([jdk / 'java.exe', '-jar', bt / 'lib/apksigner.jar', 'sign', '--ks', keystore,
         '--ks-pass', 'pass:android', '--ks-key-alias', 'devicereset-fix', '--out', apk, aligned])
    verification = run([jdk / 'java.exe', '-jar', bt / 'lib/apksigner.jar',
                        'verify', '--verbose', '--print-certs', apk])
    with zipfile.ZipFile(apk) as archive:
        assert archive.testzip() is None
        assert archive.read('assets/xposed_init') == (SOURCE / 'app/assets/xposed_init').read_bytes()
    receipt = {'apk': str(apk), 'sha256': hashlib.sha256(apk.read_bytes()).hexdigest(),
               'signature_verification': verification, 'api_sha256': API_SHA256,
               'source_hashes': {str(f.relative_to(ROOT)): hashlib.sha256(f.read_bytes()).hexdigest()
                                 for f in sorted(SOURCE.rglob('*')) if f.is_file() and '__pycache__' not in f.parts},
               'device_validation': 'pending'}
    (OUT / 'validation.json').write_text(json.dumps(receipt, indent=2), encoding='utf-8')
    print(apk)
    print(receipt['sha256'])


if __name__ == '__main__': main()
