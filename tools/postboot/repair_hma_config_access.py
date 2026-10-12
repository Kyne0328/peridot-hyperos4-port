"""Back up and repair only HMA config ownership; preserve content and mode 0600."""
import argparse
import hashlib
import json
import pathlib
import shlex
import subprocess

p = argparse.ArgumentParser()
p.add_argument('--adb', required=True)
p.add_argument('--serial', required=True)
p.add_argument('--out', required=True)
p.add_argument('--apply', action='store_true')
a = p.parse_args()
out = pathlib.Path(a.out)
out.mkdir(parents=True, exist_ok=True)

def root(cmd):
    return subprocess.check_output([a.adb, '-s', a.serial, 'exec-out', 'su -c ' + shlex.quote(cmd)], timeout=30)

device = subprocess.check_output([a.adb, '-s', a.serial, 'shell', 'getprop', 'ro.product.device'], text=True).strip()
assert device == 'peridot', device
directory = '/data/misc/hide_my_applist_jbmdiexvvujcnvjx'
appdir = '/data/user/0/org.frknkrc44.hma_oss/files'
app_owner = root('stat -c %u:%g ' + shlex.quote(appdir)).decode().strip()
assert app_owner == '10399:10399', app_owner
receipt = {'applied': a.apply, 'files': []}
for label, path, owner in [('service', directory + '/config.json', '1000:1000'),
                           ('manager', appdir + '/config.json', app_owner)]:
    q = shlex.quote(path)
    content = root('cat ' + q)
    json.loads(content)
    backup = out / (label + '-config-before.json')
    if backup.exists():
        assert backup.read_bytes() == content, 'Existing backup differs; choose new output directory'
    else:
        backup.write_bytes(content)
    before = root('ls -lnZ ' + q).decode().strip()
    if a.apply:
        root('chown ' + owner + ' ' + q + ' && chmod 0600 ' + q)
        root('restorecon -F ' + q)
    after = root('ls -lnZ ' + q).decode().strip()
    assert root('cat ' + q) == content, 'Config content changed'
    receipt['files'].append({'path': path, 'before': before, 'after': after,
                             'sha256': hashlib.sha256(content).hexdigest()})
(out / 'hma-access-repair.json').write_text(json.dumps(receipt, indent=2), encoding='utf8')
print(json.dumps(receipt, indent=2))
