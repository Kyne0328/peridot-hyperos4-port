"""Nonwriting RI3 draft tests; never run full installer or recovery executables."""
import ctypes,hashlib,json,pathlib,re,subprocess,zipfile,shlex
from prepare_repair import ROOT,OUT,ROM,render
with zipfile.ZipFile(ROM) as z: raw=z.read('META-INF/com/google/android/update-binary')
draft,rows=render(raw); source=draft.decode(); results=[]
def check(name,yes,detail=''):
    results.append(dict(name=name,passed=bool(yes),detail=detail))
def shell(text):
    p=subprocess.run(['wsl.exe','-d','Ubuntu','--','bash','-s'],input=text.encode(),capture_output=True,timeout=180)
    return p.returncode,p.stdout.decode(errors='replace'),p.stderr.decode(errors='replace')
check('draft_reproducible',draft==(OUT/'update-binary.DRAFT.sh').read_bytes())
check('draft_install_interlock','WRITES_STARTED=0\n# DRAFT ONLY: outer recovery contract unresolved.\nexit 1' in source)
rc,out,err=shell("bash -n <<'DRAFT'\n"+source+'\nDRAFT\n')
check('host_syntax',rc==0,err)
for sec,name,n,h in rows:
    check('i32_'+name,ctypes.c_int32(sec).value==sec and ctypes.c_int32(n).value==n and ctypes.c_int32(n//512).value==n//512)
check('ri2_overflow_reproduced',ctypes.c_int32(4295041536).value//512!=4295041536//512)
reader=source[source.index('read_payload() {'):source.index('firmware() {')]
cases=[('1','512',0),('19348972','4096',0),('20000000','268435456',0),
       ('0','512',1),('-1','512',1),('01','512',1),('2147483648','512',1),
       ('4295041536','512',1),('20000001','512',1),('1','0',1),('1','-512',1),
       ('1','0512',1),('1','513',1),('1','268435968',1),('1','999999999999999999999',1),
       ('x','512',1),('1','1+511',1),('1','$(id)',1),('','512',1)]
text='set -u\nBB=_bb\nZIPFILE=unused\n_bb() { printf "DD %s\\n" "$*"; }\n'+reader
for idx,(sec,n,expected) in enumerate(cases):
    text+='printf "CASE '+str(idx)+'\\n"\nread_payload '+shlex.quote(sec)+' '+shlex.quote(n)+'\nprintf "RC %s\\n" "$?"\n'
text+='printf "CASE arity\\n"\nread_payload 1\nprintf "RC %s\\n" "$?"\n'
rc,out,err=shell(text); parts=re.split(r'CASE ([^\n]+)\n',out); found=dict(zip(parts[1::2],parts[2::2]))
for idx,(_,_,expected) in enumerate(cases):
    part=found.get(str(idx),'')
    check('range_argument_'+str(idx),'RC '+str(expected) in part and ('DD ' in part)==(expected==0),part)
check('range_arity','RC 1' in found.get('arity','') and 'DD ' not in found.get('arity',''))
node=source[source.index('node() {'):source.index('prefix_hash() {')]
node_mock=r"""
set -eu
BB=_bb
abort() { printf 'ABORT: %s\n' "$*"; exit 1; }
[() {
 case "$1" in
 -b) return 0;;
 '!') if builtin [ "$2" = -e ]; then builtin [ "$SCENARIO" != holder ]; return; fi;;
 esac
 builtin [ "$@"
}
_bb() {
 case "$1" in
 readlink) printf '/dev/block/mock_super\n';;
 basename) printf 'mock_super\n';;
 cat) if builtin [ "$SCENARIO" = devnum_error ]; then return 2; fi
      if builtin [ "$SCENARIO" = bad_devnum ]; then printf '8:1oops\n'; else printf '8:1\n'; fi;;
 awk)
   shift
   case "$SCENARIO" in
   mountinfo_error) return 2;;
   output_then_error) printf 'clear\n'; return 2;;
   bad_output) printf 'nonsense\n'; return 0;;
   mounted) fixture='24 1 8:1 / /mnt rw - ext4 /dev/block/mock_super rw';;
   empty) fixture='';;
   malformed) fixture='garbage';;
   bad_separator) fixture='24 1 8:2 / /mnt rw wrong ext4 /dev/test rw';;
   bad_dev_field) fixture='24 1 8:2oops / /mnt rw - ext4 /dev/test rw';;
   *) fixture='24 1 8:2 / /mnt rw shared:1 - ext4 /dev/test rw';;
   esac
   printf '%s\n' "$fixture" | /usr/bin/awk "$1" "$2" "$3";;
 *) return 99;;
 esac
}
"""
cases_node=['unmounted','mounted','holder','devnum_error','bad_devnum','mountinfo_error','output_then_error','bad_output','empty','malformed','bad_separator','bad_dev_field']
text=''
for case in cases_node:
    text+='printf "CASE '+case+'\\n"\n(\nSCENARIO='+case+'\n'+node_mock+node+'\nnode super\n)\nprintf "RC %s\\n" "$?"\n'
rc,out,err=shell(text);parts=re.split(r'CASE ([^\n]+)\n',out);found=dict(zip(parts[1::2],parts[2::2]))
for case in cases_node:
    expected=0 if case=='unmounted' else 1
    check('node_'+case,'RC '+str(expected) in found.get(case,''),found.get(case,'')+err)
host='/mnt/'+ROM.drive[0].lower()+'/'+ROM.as_posix()[3:]
selected=[r for r in rows if r[1] in ['super/super.008','super/super.016','images/vbmeta_system.img']]
text='set -eu\nset -o pipefail\nBB=/usr/bin/env\nZIPFILE='+shlex.quote(host)+'\n'+reader
for sec,name,n,h in selected:
    text+='printf "CASE '+name+'\\n"\nread_payload '+str(sec)+' '+str(n)+' | sha256sum\n'
rc,out,err=shell(text)
for sec,name,n,h in selected:
    check('host_read_'+name,rc==0 and h in out,dict(sector=sec,bytes=n,expected=h,host_only=True,stderr=err))
report={'scope':'Nonwriting exact draft fragments; 32-bit model and host Bash/GNU dd/awk only. No exact ARM64 execution, no full installation, no ZIP built.',
        'draft_sha256':hashlib.sha256(draft).hexdigest(),'results':results,'passed':sum(x['passed'] for x in results),'failed':sum(not x['passed'] for x in results)}
(OUT/'tests.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({k:v for k,v in report.items() if k!='results'},indent=2))
for r in results:
    if not r['passed']: print(json.dumps(r))
raise SystemExit(bool(report['failed']))
