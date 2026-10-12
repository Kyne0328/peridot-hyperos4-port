"""Install the verified APK and enable only its SecurityCenter/user-0 Vector scope."""
from pathlib import Path
import argparse, hashlib, json, subprocess

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'builder/work/battery-health-20261011'
TARGET_SHA256 = 'da9c99b77d29f8052bd71ec98fa8736ba7b04ed13881ffb09575db1d592af793'

def main():
    p = argparse.ArgumentParser(); p.add_argument('--serial', required=True); a = p.parse_args()
    commands = []
    def adb(*args):
        r = subprocess.run(['adb', '-s', a.serial, *args], capture_output=True, text=True)
        commands.append({'args': args, 'exit_code': r.returncode, 'stdout': r.stdout, 'stderr': r.stderr})
        if r.returncode: raise RuntimeError(r.stdout + r.stderr)
        return r.stdout.strip()
    assert adb('shell', 'getprop', 'ro.product.device') == 'peridot', 'Wrong device'
    assert adb('shell', 'getprop', 'ro.build.version.sdk') == '37', 'Unsupported Android version'
    target = adb('shell', 'pm', 'path', 'com.miui.securitycenter').removeprefix('package:')
    assert target.startswith('/') and ' ' not in target and '\n' not in target
    assert adb('shell', 'sha256sum', target).split()[0] == TARGET_SHA256, 'SecurityCenter changed; review hooks before installation'
    validation = json.loads((OUT / 'build/validation.json').read_text())
    apk = Path(validation['apk'])
    assert hashlib.file_digest(apk.open('rb'), 'sha256').hexdigest() == validation['sha256'], 'APK changed'
    modules = adb('shell', "su -c '/data/adb/lspd/cli modules ls --json'")
    (OUT / 'vector-modules-before-install.json').write_text(modules)
    if 'io.kyne.batteryhealth' in modules:
        scope = adb('shell', "su -c '/data/adb/lspd/cli scope ls io.kyne.batteryhealth --json'")
        (OUT / 'vector-scope-before-install.json').write_text(scope)
    assert 'Success' in adb('install', '-r', str(apk))
    for cmd in ['modules enable io.kyne.batteryhealth --json', 'scope set io.kyne.batteryhealth com.miui.securitycenter/0 --json']:
        result = json.loads(adb('shell', "su -c '/data/adb/lspd/cli " + cmd + "'"))
        assert result['success'], result
    adb('shell', 'am', 'force-stop', 'com.miui.securitycenter')
    adb('shell', 'am', 'start', '-a', 'android.intent.action.POWER_USAGE_SUMMARY')
    (OUT / 'install-commands.json').write_text(json.dumps(commands, indent=2))
    print('Installed. Run verify_live.py for functional validation.')

if __name__ == '__main__': main()
