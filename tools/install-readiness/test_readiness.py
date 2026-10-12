"""Nonwriting host tests of exact RI2 shell fragments. No recovery binary or phone is executed/accessed.
Mocks establish control-flow behavior only. No modified installer is packaged.
"""
import hashlib,json,pathlib,re,subprocess,zipfile,datetime
ROOT=pathlib.Path(__file__).resolve().parents[2]
OUT=ROOT/'09-reports/install-readiness'
ROM=ROOT/'F6-Global-HyperOS4-DEV2-RI2.zip'
OUT.mkdir(exist_ok=True)
with zipfile.ZipFile(ROM) as z:
    raw=z.read('META-INF/com/google/android/update-binary')
    source=raw.decode()
    manifest=json.loads(z.read('SOURCE-MANIFEST.json'))
    entries={i.filename:i for i in z.infolist()}
results=[]
def check(name,condition,detail):
    results.append(dict(name=name,passed=bool(condition),detail=detail))
def shell(text,args=()):
    p=subprocess.run(['wsl.exe','-d','Ubuntu','--','bash','-s','--',*args],input=text.encode(),capture_output=True,timeout=45)
    p.stdout=p.stdout.decode('utf-8','replace'); p.stderr=p.stderr.decode('utf-8','replace'); return p
syntax=subprocess.run(['wsl.exe','-d','Ubuntu','--','bash','-n'],input=raw,capture_output=True,timeout=45)
syntax.stderr=syntax.stderr.decode('utf-8','replace')
check('host_bash_syntax',syntax.returncode==0,syntax.stderr)
rows=re.search(r"cat <<'SPEC'\n(.*?)\nSPEC",source,re.S).group(1).splitlines()
spec=[line.split() for line in rows]
check('65_unique_payloads',len(spec)==65 and len({r[1] for r in spec})==65,len(spec))
check('sector_aligned_in_bounds',all(int(o)%512==0 and int(n)%512==0 and int(o)+int(n)<=ROM.stat().st_size for o,_,n,_ in spec),'Every pinned range is sector aligned and within archive')
check('super_coverage',sum(int(n) for _,p,n,_ in spec if p.startswith('super/'))==9126805504,'34 chunks total 8704 MiB')
# Do not derive local header extra size from central-directory extra: ZIP64 metadata differs.
with ROM.open('rb') as f:
    all_offsets=True
    import struct
    for o,p,n,h in spec:
        i=entries[p]; f.seek(i.header_offset); header=f.read(30); vals=struct.unpack('<IHHHHHIIIHH',header)
        all_offsets &= vals[0]==0x04034b50 and i.header_offset+30+vals[-2]+vals[-1]==int(o)
check('all_local_header_offsets',all_offsets,'Raw local headers checked for all 65 ranges including ZIP64 positions')
prefix=source[:source.index('# Bind tools')]
# Remove only environment assignment in copied test fragment; original archive is read-only.
prefix=prefix.replace('PATH=/sbin:/system/bin:/system/xbin:/vendor/bin','PATH=/usr/bin:/bin')
mock=r"""
[() {
 case "$1" in
 -x) if builtin [ "$SCENARIO" = missing_tool ]; then return 1; fi; return 0;;
 -r|-f) if builtin [ "$SCENARIO" = missing_zip ]; then return 1; fi; return 0;;
 esac
 builtin [ "$@"
}
getprop() {
 case "$1" in
 ro.product.device) v=peridot; s=device;;
 ro.build.fox_id) v=e5499108-49b2-43cf-80c1-18a53db7a0fa; s=recovery;;
 ro.boot.flash.locked) v=0; s=locked;;
 ro.boot.vbmeta.device_state) v=unlocked; s=vbmeta_state;;
 ro.boot.slot_suffix) v=_a; s=slot;;
 *) return 9;;
 esac
 if builtin [ "$SCENARIO" = "$s" ]; then v=wrong; fi
 printf '%s\n' "$v"
}
_bc() {
 case "$1" in
 get-current-slot) v=0; s=current;;
 get-active-boot-slot) v=0; s=selected;;
 get-number-slots) v=2; s=count;;
 get-snapshot-merge-status) v=none; s=snapshot;;
 *) return 9;;
 esac
 if builtin [ "$SCENARIO" = "$s" ]; then v=wrong; fi
 printf '%s\n' "$v"
}
_bb() { return 99; }
"""
prefix=prefix.replace('BC=/system/bin/bootctl','BC=_bc\n'+mock)
for scenario in ['success','missing_tool','device','recovery','locked','vbmeta_state','slot','current','selected','count','snapshot','missing_zip']:
    p=shell('SCENARIO='+scenario+'\n'+prefix+'\nprintf GUARDS_PASSED\n',['3','1','/usb_otg/rom.zip'])
    expected=0 if scenario=='success' else 1
    check('early_preflight_'+scenario,p.returncode==expected and ('GUARDS_PASSED' in p.stdout)==(scenario=='success'),dict(exit=p.returncode,stdout=p.stdout,stderr=p.stderr))
for args in [[],['3'],['3','1'],['3','1','/usb_otg/rom.zip','extra']]:
    p=shell(prefix,args)
    check('arity_'+str(len(args)),p.returncode==1,dict(exit=p.returncode,stderr=p.stderr))
# Execute only the isolated target-checking function with synthetic tool results.
node=source[source.index('node() {'):source.index('prefix_hash() {')]
node_mock=r"""
set -eu
BB=_bb
abort() { printf 'ABORT: %s\n' "$*"; exit 1; }
[() {
 case "$1" in
 -b) return 0;;
 '!') if builtin [ "$2" = -e ]; then if builtin [ "$SCENARIO" = holder ]; then return 1; fi; return 0; fi;;
 -e) if builtin [ "$SCENARIO" = holder ]; then return 0; fi; return 1;;
 esac
 builtin [ "$@"
}
_bb() {
 case "$1" in
 readlink) printf '/dev/block/mock_super\n';;
 basename) printf 'mock_super\n';;
 cat) if builtin [ "$SCENARIO" = devnum_error ]; then return 2; fi; printf '8:1\n';;
 awk)
   case "$SCENARIO" in mounted) return 0;; mountinfo_error) return 2;; *) return 1;; esac;;
 *) return 99;;
 esac
}
"""
for scenario,expected in [('unmounted',0),('mounted',1),('holder',1),('devnum_error',1),('mountinfo_error',1)]:
    p=shell('SCENARIO='+scenario+'\n'+node_mock+node+'\nnode super\n')
    check('target_guard_'+scenario,p.returncode==expected,dict(expected_exit=expected,actual_exit=p.returncode,stdout=p.stdout,stderr=p.stderr))
# Actual read-only host dd at a pinned >9 GiB offset, using exact read_payload function.
reader=source[source.index('read_payload() {'):source.index('firmware() {')]
o,p,n,h=next(r for r in spec if r[1]=='images/vbmeta_system.img')
host_path='/mnt/'+ROM.drive[0].lower()+'/'+ROM.as_posix()[3:]
readtest=shell('set -eu\nset -o pipefail\nBB=/usr/bin/env\nZIPFILE="'+host_path+'"\n'+reader+'\nread_payload '+o+' '+n+' | sha256sum\n')
check('host_dd_over_9GiB',readtest.returncode==0 and readtest.stdout.split()[0]==h,dict(exit=readtest.returncode,offset=o,bytes=n,stdout=readtest.stdout,stderr=readtest.stderr,scope='GNU host dd only; not supplied ARM64 BusyBox'))
report=dict(utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),installer_sha256=hashlib.sha256(raw).hexdigest(),scope='Read-only exact archive metadata and host shell control-flow tests with synthetic recovery state. No device access. No packaged installer changes. Actual OrangeFox launcher and ARM64 BusyBox execution remain untested.',results=results,passed=sum(x['passed'] for x in results),failed=sum(not x['passed'] for x in results))
(OUT/'nonwriting-tests.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
raise SystemExit(1 if report['failed'] else 0)
