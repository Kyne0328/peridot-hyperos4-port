"""Run the installed Play Integrity checker and save a fresh timestamped result."""
import argparse
import json
import pathlib
import re
import shlex
import subprocess
import time
import xml.etree.ElementTree as ET

p = argparse.ArgumentParser()
p.add_argument('--serial', required=True)
p.add_argument('--out', required=True)
p.add_argument('--adb', default='adb')
a = p.parse_args()
out = pathlib.Path(a.out)
out.mkdir(parents=True, exist_ok=False)

def adb(*args, timeout=25):
    return subprocess.check_output([a.adb, '-s', a.serial, *args], timeout=timeout)

def root(command):
    return adb('exec-out', 'su -c ' + shlex.quote(command))

def snapshot(label):
    adb('shell', 'uiautomator dump /data/local/tmp/root-integrity-test-ui.xml')
    raw = adb('exec-out', 'cat /data/local/tmp/root-integrity-test-ui.xml')
    (out / (label + '.xml')).write_bytes(raw)
    return list(ET.fromstring(raw).iter('node'))

def tap(node):
    x1, y1, x2, y2 = map(int, re.findall(r'\d+', node.attrib['bounds']))
    root(f'input tap {(x1+x2)//2} {(y1+y2)//2}')

# Do not clear data or force-stop the checker. Its existing result provides a
# timestamp guard so reopening an old response cannot be mistaken for a new test.
root('am start -n gr.nikolasspyr.integritycheck/.MainActivity')
nodes = snapshot('initial')
old_timestamp = None
for n in nodes:
    if n.get('text', '').startswith('{'):
        old_timestamp = json.loads(n.get('text'))['requestDetails']['timestampMillis']
if any(n.get('text') == 'OK' for n in nodes):
    tap(next(n for n in nodes if n.get('text') == 'OK'))
    nodes = snapshot('closed-dialog')

button = next((n for n in nodes if n.get('resource-id', '').endswith(':id/check_btn')), None)
if button is None:
    raise RuntimeError('Checker CHECK button not visible; no input sent')
if button.get('enabled') == 'true':
    tap(button)

deadline = time.monotonic() + 50
for index in range(12):
    nodes = snapshot(f'poll-{index}')
    icons = {n.get('resource-id', '').rsplit('/', 1)[-1]: n.get('content-desc') for n in nodes}
    button = next((n for n in nodes if n.get('resource-id', '').endswith(':id/check_btn')), None)
    if button is not None and button.get('enabled') == 'true' and icons.get('basic_integrity_icon') in ('Pass', 'Fail'):
        break
    if time.monotonic() >= deadline:
        raise RuntimeError('Checker did not finish in bounded polling window')
else:
    raise RuntimeError('Checker did not finish')

json_button = next(n for n in nodes if n.get('content-desc') == 'Show JSON response')
tap(json_button)
nodes = snapshot('response')
text = next((n.get('text') for n in nodes if n.get('text', '').startswith('{')), None)
if text is None:
    raise RuntimeError('No JSON verdict visible; inspect saved UI')
verdict = json.loads(text)
if verdict['requestDetails']['timestampMillis'] == old_timestamp:
    raise RuntimeError('Checker returned its previous response timestamp')
(out / 'verdict.json').write_text(json.dumps(verdict, indent=2), encoding='utf-8')
(out / 'screen.png').write_bytes(adb('exec-out', 'screencap -p'))
(out / 'logcat.txt').write_bytes(root('logcat -b all -d -v threadtime -t 12000'))
print(json.dumps(verdict, indent=2))
root('input keyevent 4')
