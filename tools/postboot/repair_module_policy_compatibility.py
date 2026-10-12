"""Apply narrowly scoped, backed-up module policy corrections for this peridot ROM."""
import argparse, pathlib, subprocess, shlex, json
p=argparse.ArgumentParser()
p.add_argument('--adb', required=True); p.add_argument('--serial', required=True)
p.add_argument('--out', required=True); p.add_argument('--apply', action='store_true')
a=p.parse_args(); out=pathlib.Path(a.out); out.mkdir(parents=True, exist_ok=True)
def root(c):
    return subprocess.check_output([a.adb,'-s',a.serial,'exec-out','su -c '+shlex.quote(c)],timeout=30)
assert subprocess.check_output([a.adb,'-s',a.serial,'shell','getprop','ro.product.device'],text=True).strip()=='peridot'
receipt=[]
for module in ['zygisksu','zygisk_vector']:
    path='/data/adb/modules/'+module+'/sepolicy.rule'
    raw=root('cat '+shlex.quote(path)); text=raw.decode()
    backup=out/(module+'-policy-before.rule')
    assert not backup.exists(), 'Use a fresh backup directory'
    backup.write_bytes(raw)
    if module=='zygisksu':
        assert 'allow zygote unlabeled file { open read getattr }' in text
        assert 'allow zygote nsfs file { open read }' in text
        text=text.replace('allow zygote nsfs file { open read }',
            '# Peridot Android17: nsfs type absent. Namespace files are unlabeled.\n'
            '# Existing zygote -> unlabeled open/read/getattr rule covers them.')
    else:
        text+='\n# Peridot: LSPlant dual-map execution of system_server memfd.\n'
        text+='allow system_server system_server_tmpfs file execute\n'
    patched=out/(module+'-policy-after.rule'); patched.write_bytes(text.encode('utf8'))
    remote='/data/local/tmp/peridot-'+module+'-policy-20261006.rule'
    if a.apply:
        subprocess.run([a.adb,'-s',a.serial,'push',str(patched),remote],check=True)
        root('/data/adb/ksud sepolicy check '+shlex.quote(remote))
        root('cp '+shlex.quote(remote)+' '+shlex.quote(path)+' && chown 0:0 '+shlex.quote(path)+' && chmod 0644 '+shlex.quote(path))
        if module=='zygisk_vector':
            result=root('/data/adb/ksud sepolicy patch '+shlex.quote('allow system_server system_server_tmpfs file execute')).decode()
        else: result='Absent target rule removed; existing active permissions retained.'
        assert root('cat '+shlex.quote(path))==patched.read_bytes()
    else: result='Dry run'
    receipt.append({'module':module,'applied':a.apply,'result':result})
(out/'receipt.json').write_text(json.dumps(receipt,indent=2),encoding='utf8')
print(json.dumps(receipt,indent=2))
