"""Verify the installed add-on through the actual Battery Settings navigation.

Opens battery screens and reads telemetry/UI. Does not change charging settings,
clear app data, restart the device, or alter framework scopes.
"""
from pathlib import Path
import argparse, datetime, hashlib, json, re, subprocess, xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'builder/work/battery-health-20261011'

def main():
    p = argparse.ArgumentParser(); p.add_argument('--serial', required=True); a = p.parse_args()
    def adb(*args):
        r = subprocess.run(['adb', '-s', a.serial, *args], capture_output=True, text=True, encoding='utf-8', errors='replace')
        if r.returncode: raise RuntimeError(r.stdout + r.stderr)
        return r.stdout.strip()
    assert adb('shell', 'getprop', 'ro.product.device') == 'peridot', 'Wrong target'
    assert adb('shell', 'getprop', 'ro.build.version.sdk') == '37', 'Different Android version'
    def node(path): return adb('shell', "su -c 'cat " + path + "'")
    soh = int(node('/sys/class/qcom-battery/fg1_soh'))
    full = int(node('/sys/class/power_supply/battery/charge_full')) // 1000
    design = int(node('/sys/class/power_supply/battery/charge_full_design')) // 1000
    cycles = int(node('/sys/class/power_supply/battery/cycle_count'))
    expected = [str(soh) + '%', f'{full:,} mAh', f'{design:,} mAh', f'{cycles:,}']
    states = {}
    def dump(label):
        # A notification shade can cover a correctly resumed Battery activity.
        # Collapse the shade without dismissing notifications or changing settings.
        adb('shell', 'cmd', 'statusbar', 'collapse')
        remote = '/data/local/tmp/kyneos-battery-' + label + '.xml'
        adb('shell', 'uiautomator', 'dump', remote)
        adb('pull', remote, str(OUT / (label + '-ui.xml')))
        tree = ET.parse(OUT / (label + '-ui.xml'))
        texts = [n.get('text', '') for n in tree.iter('node') if n.get('text') and n.get('package') == 'com.miui.securitycenter']
        states[label] = texts
        text = '\n'.join(texts)
        assert 'About these readings' not in texts
        assert 'Reported by the battery fuel gauge. Values are estimates.' not in text
        if label.startswith('protection'):
            for value in expected: assert value in text, label + ' missing ' + value
            assert texts.count('Battery health') == 1, label + ' duplicated health section'
        else:
            assert 'Battery health' not in texts and 'Maximum capacity' not in texts, label + ' has unwanted health UI'
        return tree
    def tap(tree, resource):
        rows = [n for n in tree.iter('node') if n.get('resource-id') == 'com.miui.securitycenter:id/' + resource]
        assert len(rows) == 1, 'Missing/ambiguous navigation row ' + resource
        bounds = list(map(int, re.findall(r'\d+', rows[0].get('bounds'))))
        x, y = (bounds[0] + bounds[2]) // 2, (bounds[1] + bounds[3]) // 2
        adb('shell', 'input', 'tap', str(x), str(y))
    adb('shell', 'am', 'start', '-a', 'android.intent.action.POWER_USAGE_SUMMARY')
    tree = dump('main')
    assert 'Current mode' in states['main'] and 'Charging options' in states['main'], 'Native controls missing'
    tap(tree, 'fl_battery_health')
    dump('protection')
    assert 'Charging protection' in states['protection'], 'Native protection options missing'
    adb('shell', 'input', 'keyevent', '4')
    tree = dump('main-return')
    tap(tree, 'fl_more_feature')
    dump('settings')
    adb('shell', 'input', 'keyevent', '4')
    tree = dump('main-return-2')
    tap(tree, 'fl_battery_health')
    dump('protection-reopened')
    scope = json.loads(adb('shell', "su -c '/data/adb/lspd/cli scope ls io.kyne.batteryhealth --json'"))
    assert scope['success'] and scope['data'] == [{'APP_PACKAGE': 'com.miui.securitycenter', 'USER_ID': 0}], 'Unexpected scope'
    modules = json.loads(adb('shell', "su -c '/data/adb/lspd/cli modules ls --json'"))
    before = json.loads((OUT / 'vector-modules-before.json').read_text(encoding='utf-8-sig'))
    after = {row['PACKAGE']: row['STATUS'] for row in modules['data']}
    for row in before['data']: assert after[row['PACKAGE']] == row['STATUS'], 'Unrelated module changed'
    assert after['io.kyne.batteryhealth'] == 'enabled'
    apppath = adb('shell', 'pm', 'path', 'io.kyne.batteryhealth').removeprefix('package:')
    adb('pull', apppath, str(OUT / 'installed.apk'))
    deployed = hashlib.file_digest((OUT / 'installed.apk').open('rb'), 'sha256').hexdigest()
    build = json.loads((OUT / 'build/validation.json').read_text())
    assert deployed == build['sha256'], 'Installed APK differs from validated build'
    logs = adb('shell', "su -c 'grep KyneOSBatteryHealth /data/adb/lspd/log/modules_*.log'")
    (OUT / 'module-validation-log.txt').write_text('\n'.join(logs.splitlines()[-30:]), encoding='utf-8')
    receipt = {'verified_at': datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=8))).isoformat(), 'passed': True, 'checks': ['only Battery protection shows health, matching the current gauge', 'native main Battery screen has no added card', 'Additional features has no added health section', 'About these readings and explanatory footer removed', 'protection reopening does not duplicate UI', 'only SecurityCenter user 0 scoped', 'other modules retain enabled/disabled state', 'installed APK matches signed validated build'], 'gauge': {'soh_percent': soh, 'full_mah': full, 'design_mah': design, 'cycles': cycles}, 'apk_sha256': deployed, 'scope': scope['data'], 'screen_text': states, 'limits': ['No device reboot performed', 'No ROM ZIP integration', 'Light theme and future SecurityCenter updates untested']}
    (OUT / 'live-validation.json').write_text(json.dumps(receipt, indent=2), encoding='utf-8')
    print(json.dumps({k: receipt[k] for k in ['passed', 'checks', 'gauge', 'apk_sha256', 'limits']}, indent=2))

if __name__ == '__main__': main()
