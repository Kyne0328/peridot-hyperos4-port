"""Create a task-only ext4 build filesystem in a fresh regular scratch file."""
from pathlib import Path
import argparse,os,subprocess

root=Path('/mnt/d/hyperos4-peridot-postboot-20261004').resolve()
image=root/'native-build-scratch.ext4';mount=Path('/mnt/peridot-postboot-native')
ap=argparse.ArgumentParser();ap.add_argument('--finish-existing',action='store_true');a=ap.parse_args()
assert root.is_dir() and image.parent==root and not image.is_symlink()
if a.finish_existing:
 assert image.is_file() and image.stat().st_size==24*1024**3
 assert subprocess.run(['mountpoint','-q',str(mount)]).returncode!=0
 with image.open('r+b') as f:f.truncate(48*1024**3)
else:
 assert not image.exists()
 with image.open('xb') as f:f.truncate(48*1024**3)
assert image.is_file() and image.stat().st_size==48*1024**3
mount.mkdir(exist_ok=True);assert not any(mount.iterdir())
subprocess.run(['mkfs.ext4','-F','-m','0','-N','65536','-E','lazy_itable_init=1,lazy_journal_init=1,nodiscard',str(image)],check=True)
subprocess.run(['mount','-o','loop',str(image),str(mount)],check=True)
os.chown(mount,1000,1000)
print('Created task-only native build filesystem',mount,flush=True)
