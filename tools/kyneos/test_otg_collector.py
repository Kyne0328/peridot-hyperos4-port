"""Sanitizer-backed physical inventory regression tests; regular files and mocked DM only."""
from pathlib import Path
import hashlib,json,subprocess
ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/'builder/work/kyneos-ri7-install-failure-20261005'
def linux(p):return '/mnt/'+p.drive[0].lower()+str(p)[2:].replace('\\','/')
here=ROOT/'tools/installer-ri3/native-updater/backend'
sources=[here/(n+'.cpp') for n in ['storage_backend','topology','verity_table','unmount','test_backend']]
binary=OUT/'test-backend'
command=['wsl','-d','Ubuntu','--exec','/usr/bin/clang++','-std=c++17','-O2','-Wall','-Wextra','-Werror','-D_FILE_OFFSET_BITS=64','-D_LARGEFILE64_SOURCE=1','-D_POSIX_C_SOURCE=200809L','-fsanitize=address,undefined','-fno-omit-frame-pointer',*[linux(p) for p in sources],'-Wl,--wrap=read','-Wl,--wrap=open','-Wl,--wrap=open64','-o',linux(binary)]
p=subprocess.run(command,capture_output=True,text=True);assert p.returncode==0,p.stderr
p=subprocess.run(['wsl','-d','Ubuntu','--exec',linux(binary),linux(OUT/'output.fixture')],capture_output=True,text=True)
receipt={'passed':p.returncode==0,'exit_code':p.returncode,'stdout':p.stdout,'stderr':p.stderr,'compile_argv':command,'sources':{str(x.relative_to(ROOT)):hashlib.sha256(x.read_bytes()).hexdigest() for x in sources},'device_writes':False}
(OUT/'BACKEND-TESTS.json').write_text(json.dumps(receipt,indent=2)+'\n',encoding='utf-8')
print(p.stdout);print(p.stderr);assert receipt['passed']
