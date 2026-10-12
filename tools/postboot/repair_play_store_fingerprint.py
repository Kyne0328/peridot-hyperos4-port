"""Backed-up, scoped PIF v18 Play Store fingerprint correction for peridot."""
import argparse
import hashlib
import json
import pathlib
import re
import shlex
import subprocess

p = argparse.ArgumentParser()
p.add_argument('--serial', required=True)
p.add_argument('--out', required=True)
p.add_argument('--adb', default='adb')
p.add_argument('--apply', action='store_true')
a = p.parse_args()
out = pathlib.Path(a.out)
out.mkdir(parents=True, exist_ok=False)
remote = '/data/adb/modules/playintegrityfix/custom.pif.prop'

def adb(*args):
    return subprocess.check_output([a.adb, '-s', a.serial, *args], timeout=30)

def root(command):
    return adb('exec-out', 'su -c ' + shlex.quote(command))

assert adb('shell', 'getprop ro.product.device').decode().strip() == 'peridot'
assert re.search(rb'^versionCode=180000$', root('cat /data/adb/modules/playintegrityfix/module.prop'), re.M)
before = root('cat ' + remote)
assert len(re.findall(rb'^spoofVendingFinger=.*$', before, re.M)) == 1
assert b'spoofVendingSdk=0' in before, 'Preserve Android 13+ verdicts; inspect unusual SDK config manually'
after = re.sub(rb'^spoofVendingFinger=.*$', b'spoofVendingFinger=1', before, flags=re.M)
(out / 'before.prop').write_bytes(before)
(out / 'after.prop').write_bytes(after)
changed = before != after
receipt = {'device': a.serial, 'path': remote, 'changed': changed, 'applied': a.apply,
           'before_sha256': hashlib.sha256(before).hexdigest(),
           'after_sha256': hashlib.sha256(after).hexdigest()}
if a.apply and changed:
    stage = '/data/local/tmp/peridot-play-store-fingerprint.prop'
    adb('push', str(out / 'after.prop'), stage)
    # Existing inode retains its DAC owner/mode and SELinux label.
    root('cat ' + shlex.quote(stage) + ' > ' + remote)
    assert root('cat ' + remote) == after
    receipt['restart'] = root('sh /data/adb/modules/playintegrityfix/killpi.sh').decode(errors='replace')
if a.apply:
    assert root('cat ' + remote) == after
(out / 'receipt.json').write_text(json.dumps(receipt, indent=2), encoding='utf-8')
print(json.dumps(receipt, indent=2))
