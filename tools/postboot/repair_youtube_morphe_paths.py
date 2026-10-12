"""Refresh installed Morphe targets after a signed stock reinstall; retain patched APK."""
import argparse, pathlib, subprocess, shlex, json
p=argparse.ArgumentParser(); p.add_argument('--adb',required=True);p.add_argument('--serial',required=True);p.add_argument('--out',required=True)
a=p.parse_args(); out=pathlib.Path(a.out);out.mkdir(parents=True,exist_ok=True)
def root(c):return subprocess.check_output([a.adb,'-s',a.serial,'exec-out','su -c '+shlex.quote(c)],timeout=30)
base='/data/adb/modules/com.google.android.youtube-morphe'
paths=subprocess.check_output([a.adb,'-s',a.serial,'shell','pm','path','com.google.android.youtube'],text=True).splitlines()
assert len(paths)==1,paths
target=paths[0].removeprefix('package:').strip()
assert target.startswith('/data/app/') and target.endswith('/base.apk') and '==deleted==' not in target,target
root('test -f '+shlex.quote(target))
root('test -f '+shlex.quote(target.rsplit('/',1)[0]+'/lib/arm64/libelements.so'))
receipt={'new_target':target}
for name in ['service.sh','post-fs-data.sh','stock-paths.txt']:
    raw=root('cat '+shlex.quote(base+'/'+name)); backup=out/(name+'.before')
    assert not backup.exists(),'Use fresh output directory'
    backup.write_bytes(raw)
    if name=='stock-paths.txt':text=target+'\n';mode='0644'
    else:
        text=raw.decode();mode='0755'
        text=text.replace('nsenter -t "$zpid" -m mount','nsenter -t "$zpid" -m -- mount')
        text=text.replace('nsenter -t "$zpid" -m umount','nsenter -t "$zpid" -m -- umount')
    local=out/(name+'.after');local.write_bytes(text.encode('utf8'))
    tmp='/data/local/tmp/peridot-morphe-'+name+'-20261006'
    subprocess.run([a.adb,'-s',a.serial,'push',str(local),tmp],check=True)
    if name.endswith('.sh'):root('sh -n '+shlex.quote(tmp))
    root('cp '+shlex.quote(tmp)+' '+shlex.quote(base+'/'+name)+' && chmod '+mode+' '+shlex.quote(base+'/'+name))
    assert root('cat '+shlex.quote(base+'/'+name))==local.read_bytes()
root('sh '+shlex.quote(base+'/service.sh'))
receipt['mount_log']=root('cat '+shlex.quote(base+'/log.txt')).decode()
(out/'receipt.json').write_text(json.dumps(receipt,indent=2),encoding='utf8');print(json.dumps(receipt,indent=2))
