"""Keep the task's Linux mount namespace alive through extraction and verification."""
from pathlib import Path
import json,os,shutil,subprocess,sys

ROOT=Path(__file__).resolve().parents[2]
DISK=Path('/mnt/d/hyperos4-peridot-postboot-20261004');NATIVE=Path('/mnt/peridot-postboot-native')
scratch=DISK/'native-build-scratch.ext4'
assert scratch.is_file() and scratch.stat().st_size==48*1024**3
assert NATIVE.is_dir() and not any(NATIVE.iterdir())
subprocess.run(['mount','-o','loop',str(scratch),str(NATIVE)],check=True)
assert subprocess.run(['mountpoint','-q',str(NATIVE)]).returncode==0
tools=ROOT/'.cache/global-single-recovery-ri2/host-tools/extracted/usr/bin'
env=os.environ.copy();env['POSTBOOT_WORK']=str(NATIVE)
try:
 for name in ['product','odm']:
  source=NATIVE/(name+'-source.img');tree=NATIVE/(name+'-tree')
  shutil.copyfile(DISK/(name+'-source.img'),source);tree.mkdir()
  print('Decoding',name,'on native task filesystem',flush=True)
  subprocess.run([str(tools/'fsck.erofs'),'--extract='+str(tree),'--no-preserve',str(source)],check=True)
  subprocess.run([sys.executable,str(ROOT/'tools/postboot/repack.py'),name],env=env,check=True)
  receipt=json.loads((NATIVE/(name+'-repack.json')).read_text());target=DISK/(name+'-filesystem.img')
  assert not target.exists();shutil.copyfile(NATIVE/(name+'-filesystem.img'),target)
  receipt['filesystem_path']='/mnt/d/hyperos4-peridot-postboot-20261004/'+target.name
  (DISK/(name+'-repack.json')).write_text(json.dumps(receipt,indent=2)+'\n')
 print('Both rebuilt filesystems verified and exported',flush=True)
finally:
 subprocess.run(['sync'],check=True)
 subprocess.run(['umount',str(NATIVE)],check=True)
