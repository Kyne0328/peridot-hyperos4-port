"""Verify current-identity Save, reversible scope edits and actual target reads."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import time
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
MODULE = 'io.github.gjr787878.devicereset'
TARGET = 'com.mcdonalds.mobileapp'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--serial', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    commands = []

    def adb(command):
        r = subprocess.run(['adb', '-s', args.serial, 'shell', command], capture_output=True,
                           text=True, encoding='utf-8', timeout=35)
        # Record operation/error metadata only; UI and identity captures stay local.
        commands.append({'command': command, 'exit_code': r.returncode, 'stderr': r.stderr})
        if r.returncode: raise RuntimeError(r.stderr)
        return r.stdout.strip()

    def cli(command):
        result = json.loads(adb('/data/adb/lspd/cli --json ' + command))
        assert result['success'], result
        return result['data']

    counter = 0

    def ui():
        nonlocal counter
        remote = '/data/local/tmp/kyne-devicereset-verify.xml'
        adb('uiautomator dump --compressed ' + remote + ' >/dev/null')
        raw = adb('cat ' + remote)
        counter += 1
        (args.output / f'ui-{counter:02d}.xml').write_text(raw, encoding='utf-8')
        return ET.fromstring(raw)

    def tap(text):
        root = ui()
        parents = {child: parent for parent in root.iter() for child in parent}
        node = next(n for n in root.iter('node') if n.get('text') == text)
        while node.get('clickable') != 'true' and node in parents:
            node = parents[node]
        assert node.get('clickable') == 'true', 'No clickable node for ' + text
        x1, y1, x2, y2 = map(int, re.findall(r'\d+', node.get('bounds')))
        adb(f'input tap {(x1+x2)//2} {(y1+y2)//2}')

    def has_text(text):
        return any(n.get('text') == text for n in ui().iter('node'))

    def wait_scope(expected):
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if cli('scope ls ' + MODULE) == expected: return
            time.sleep(0.25)
        raise AssertionError('Scope change did not reach expected state')

    internal = '/data/user/0/' + TARGET + '/files/.identity_sentinel'
    external = '/data/media/0/Android/data/' + TARGET + '/files/.identity_sentinel'
    before_identity = json.loads(adb('cat ' + internal))
    before_scope = cli('scope ls ' + MODULE)
    before_modules = cli('modules ls')
    daemon = adb('pidof vectord')
    assert before_scope == [{'APP_PACKAGE': TARGET, 'USER_ID': 0}], 'Unexpected scope; review before toggling'
    result = {'scope_before': before_scope, 'daemon_pid_before': daemon}
    adb('am start -n ' + MODULE + '/.ui.MainActivity')
    assert has_text('Injected✓'), 'Initial UI status incorrect'
    before_stat = adb("stat -c '%i %y' " + internal)
    tap("McDonald's")
    tap('Customize')
    tap('Save')
    assert has_text('Clear data now?'), 'Missing expected non-destructive save prompt'
    tap('Cancel')
    after_stat = adb("stat -c '%i %y' " + internal)
    assert after_stat != before_stat, 'Save did not update the canonical private file'
    for name, path in [('internal', internal), ('external', external)]:
        data = adb('cat ' + path)
        (args.output / (name + '-after-save.json')).write_text(data, encoding='utf-8')
        assert json.loads(data) == before_identity, name + ' identity changed'
    result.update({'save_private_file_updated': True, 'identity_preserved': True,
                   'save_stat_before': before_stat, 'save_stat_after': after_stat})
    # Picker removal only edits scope/config; it is distinct from Delete Target.
    try:
        tap('＋ Select App')
        root = ui()
        search = next(n for n in root.iter('node') if n.get('class') == 'android.widget.EditText')
        x1, y1, x2, y2 = map(int, re.findall(r'\d+', search.get('bounds')))
        adb(f'input tap {(x1+x2)//2} {(y1+y2)//2}')
        adb('input text com.mcdonalds.mobileapp')
        adb('input keyevent KEYCODE_BACK')
        tap("McDonald's")
        wait_scope([])
        tap("McDonald's")
        wait_scope(before_scope)
        adb('input keyevent KEYCODE_BACK')
    finally:
        current = cli('scope ls ' + MODULE)
        if current != before_scope:
            pairs = ' '.join(row['APP_PACKAGE'] + '/' + str(row['USER_ID']) for row in before_scope)
            cli('scope set ' + MODULE + ' ' + pairs)
            raise AssertionError('UI scope test failed; original Vector scope restored')
    assert cli('modules ls') == before_modules, 'Other module states changed'
    assert adb('pidof vectord') == daemon, 'Vector daemon restarted'
    assert json.loads(adb('cat ' + internal)) == before_identity
    result.update({'ui_scope_remove_add_verified': True, 'daemon_unchanged': True,
                   'module_states_unchanged': True, 'scope_preserved': True})
    # Fresh processes provide new observations, not cached log lines.
    adb('am force-stop ' + TARGET)
    old_log = adb('cat /data/adb/lspd/log/modules*')
    adb('am start -n ' + TARGET + '/.SplashActivity')
    deadline = time.monotonic() + 35
    fresh = ''
    expected = [TARGET, TARGET + ':com.akamai.webview.process']
    while time.monotonic() < deadline:
        log = adb('cat /data/adb/lspd/log/modules*')
        fresh = log[len(old_log):] if log.startswith(old_log) else log
        if all('observed process=' + process + ' androidIdMatches=true modelMatches=true' in fresh for process in expected):
            break
        time.sleep(0.5)  # Bounded observation polling, not a fixed acceptance delay.
    else: raise AssertionError('Missing fresh target identity observations')
    (args.output / 'fresh-process.log').write_text(fresh, encoding='utf-8')
    result['fresh_main_and_child_identity_matches'] = True
    result['identity_metadata'] = adb('ls -lZ ' + internal + ' ' + external)
    result['post_reboot_test'] = 'not performed'
    (args.output / 'validation.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    (args.output / 'commands.json').write_text(json.dumps(commands, indent=2), encoding='utf-8')
    print(json.dumps(result, indent=2))


if __name__ == '__main__': main()
