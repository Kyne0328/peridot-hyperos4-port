"""Back up state, install compatibility add-on and restore the existing identity."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'builder/work/devicereset-repair-20261013'
MODULE = 'io.github.gjr787878.devicereset'
ADDON = 'io.kyne.deviceresetfix'
TARGET = 'com.mcdonalds.mobileapp'
ORIGINAL_SHA = '72c096c345453e867cc6a38ac52cf604839f472d1fedb73fcb443ab815f14877'


def quote(value):
    return "'" + value.replace("'", "'\\''") + "'"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--serial', required=True)
    args = parser.parse_args()
    backup = OUT / ('backup-' + datetime.datetime.now().strftime('%Y%m%d-%H%M%S'))
    backup.mkdir(parents=True, exist_ok=False)
    commands = []

    def adb(*argv, input_text=None):
        r = subprocess.run(['adb', '-s', args.serial, *map(str, argv)], input=input_text,
                           capture_output=True, text=True, encoding='utf-8', timeout=45)
        commands.append({'args': list(map(str, argv)), 'exit_code': r.returncode,
                         'stdout': r.stdout, 'stderr': r.stderr})
        (backup / 'commands.json').write_text(json.dumps(commands, indent=2), encoding='utf-8')
        if r.returncode: raise RuntimeError(r.stdout + r.stderr)
        return r.stdout.strip()

    def cli(command):
        result = json.loads(adb('shell', '/data/adb/lspd/cli --json ' + command))
        if not result.get('success'): raise RuntimeError(str(result))
        return result

    assert adb('shell', 'getprop ro.product.device') == 'peridot'
    assert adb('shell', 'getprop ro.build.version.sdk') == '37'
    original = adb('shell', 'pm path ' + MODULE).removeprefix('package:')
    assert '\n' not in original and original.startswith('/data/app/')
    assert adb('shell', 'sha256sum ' + quote(original)).split()[0] == ORIGINAL_SHA
    before = {'status': cli('status'), 'modules': cli('modules ls'), 'scope': cli('scope ls ' + MODULE)}
    assert {'APP_PACKAGE': TARGET, 'USER_ID': 0} in before['scope']['data'], 'Target not scoped'
    (backup / 'framework-before.json').write_text(json.dumps(before, indent=2), encoding='utf-8')
    adb('pull', '/data/adb/lspd/config', backup / 'framework-config')
    adb('pull', '/data/user/0/' + MODULE, backup / 'module-data')
    adb('pull', original, backup / 'original-module.apk')
    internal = '/data/user/0/' + TARGET + '/files/.identity_sentinel'
    external = '/data/media/0/Android/data/' + TARGET + '/files/.identity_sentinel'
    metadata = adb('shell', 'ls -ldZ /data/user/0/' + TARGET + '/files /data/media/0/Android/data/' + TARGET +
                   ' /data/media/0/Android/data/' + TARGET + '/files; ls -lZ ' + quote(internal) + ' ' + quote(external) + ' 2>/dev/null; true')
    (backup / 'identity-metadata-before.txt').write_text(metadata, encoding='utf-8')
    for name, remote in [('internal', internal), ('external', external)]:
        if adb('shell', '[ -f ' + quote(remote) + ' ] && echo yes || echo no') == 'yes':
            adb('pull', remote, backup / (name + '-identity.json'))
    prefs = ET.parse(backup / 'module-data/shared_prefs/devicereset_config.xml').getroot()
    saved = next(e.text for e in prefs if e.get('name') == 'identity_' + TARGET)
    identity = json.loads(saved)
    assert identity.get('androidId') and identity.get('model'), 'Invalid existing identity'
    existing = backup / 'external-identity.json'
    if existing.exists(): assert json.loads(existing.read_text(encoding='utf-8')) == identity, 'Conflicting saved identities'
    uid = int(adb('shell', "stat -c '%u' /data/user/0/" + TARGET))
    assert 10000 <= uid < 100000, 'Unexpected target user/UID'
    receipt = json.loads((OUT / 'build/validation.json').read_text(encoding='utf-8'))
    apk = Path(receipt['apk'])
    assert hashlib.sha256(apk.read_bytes()).hexdigest() == receipt['sha256']
    assert 'Success' in adb('install', '-r', apk)
    cli('modules enable ' + ADDON)
    cli('scope set ' + ADDON + ' ' + MODULE + '/0 ' + TARGET + '/0')
    adb('shell', 'am force-stop ' + MODULE)
    adb('shell', 'am force-stop ' + TARGET)
    directory = '/data/user/0/' + TARGET + '/files'
    parent = '/data/media/0/Android/data/' + TARGET
    ext_dir = parent + '/files'
    # Identity contents are passed on stdin, never logged as command arguments.
    script = '\n'.join([
        'set -e', 'mkdir -p ' + quote(directory) + ' ' + quote(ext_dir),
        "printf '%s' " + quote(saved) + ' > ' + quote(internal),
        'chown ' + str(uid) + ':' + str(uid) + ' ' + quote(directory) + ' ' + quote(internal),
        'chmod 771 ' + quote(directory), 'chmod 600 ' + quote(internal),
        'restorecon -F ' + quote(directory) + ' ' + quote(internal),
        "printf '%s' " + quote(saved) + ' > ' + quote(external),
        'chown ' + str(uid) + ':ext_data_rw ' + quote(parent) + ' ' + quote(ext_dir) + ' ' + quote(external),
        'chmod 2770 ' + quote(parent) + ' ' + quote(ext_dir), 'chmod 600 ' + quote(external),
        'restorecon -F ' + quote(parent) + ' ' + quote(ext_dir) + ' ' + quote(external),
        'echo IDENTITY_RESTORED', '',
    ])
    assert 'IDENTITY_RESTORED' in adb('shell', 'sh -s', input_text=script)
    adb('pull', internal, backup / 'restored-identity.json')
    assert json.loads((backup / 'restored-identity.json').read_text(encoding='utf-8')) == identity
    assert cli('scope ls ' + MODULE)['data'] == before['scope']['data'], 'Original scope changed'
    adb('shell', 'am start -n ' + MODULE + '/.ui.MainActivity')
    (OUT / 'latest-backup.txt').write_text(str(backup), encoding='utf-8')
    receipt = {'backup': str(backup), 'original_apk_sha256': ORIGINAL_SHA, 'addon_apk_sha256': receipt['sha256'],
               'existing_identity_preserved': True, 'original_scope_preserved': True,
               'identity_sha256': hashlib.sha256(saved.encode('utf-8')).hexdigest(), 'functional_validation': 'pending'}
    (OUT / 'install-receipt.json').write_text(json.dumps(receipt, indent=2), encoding='utf-8')
    print('Installed compatibility add-on; existing identity restored. Backup:', backup)


if __name__ == '__main__': main()
