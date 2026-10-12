"""Supplemental nonwriting tests for exact RI3 draft lookups and mount queries."""
import json,re,subprocess,hashlib,shlex,zipfile
from prepare_repair import ROOT,OUT,ROM
raw=(OUT/'update-binary.DRAFT.sh').read_bytes(); s=raw.decode(); results=[]
def check(name,yes,detail=''):results.append(dict(name=name,passed=bool(yes),detail=detail))
def between(a,b):return s[s.index(a):s.index(b,s.index(a))]
reader=between('read_payload() {','firmware() {')
frags={
'dm':between('dm_mounted=$(', 'case "$ZIPFILE" in /data/'),
'logical':between('logical_mounted=$(', 'ZIPFILE=$('),
'storage':next(l for l in s.splitlines() if l.startswith('storage=$("$BB" awk')),
'metadata':next(l for l in s.splitlines() if l.startswith('metadata=$("$BB" awk'))}
common=r"""
set -eu
BB=_bb
ZIPFILE=/usb_otg/rom.zip
abort() { printf 'ABORT %s\n' "$*"; exit 1; }
_bb() {
 shift
 case "$SCENARIO" in
 error) return 2;;
 output_error) printf 'no\n'; return 2;;
 empty) fixture='';;
 malformed) fixture='oops';;
 matched_dm) fixture='/dev/block/dm-0 /vendor ext4 ro 0 0';;
 matched_logical) fixture='/dev/block/sda1 /data ext4 rw 0 0';;
 *) fixture='/dev/block/sda1 /usb_otg ext4 rw 0 0';;
 esac
 case "$FRAG" in
 storage) printf '%s\n' "$fixture" | /usr/bin/awk "$1" "$2" "$3";;
 *) printf '%s\n' "$fixture" | /usr/bin/awk "$1";;
 esac
}
"""
cases=[]
for frag in ('dm','logical'):
    for scenario in ('clear','error','output_error','empty','malformed','matched_'+frag):
        cases.append((frag,scenario,0 if scenario=='clear' else 1))
for frag in ('storage','metadata'):
    for scenario in ('clear','error','output_error'):
        cases.append((frag,scenario,0 if scenario=='clear' else 1))
text=''
for frag,scenario,expected in cases:
    name=frag+'_'+scenario
    text+='printf "CASE '+name+'\\n"\n(\nFRAG='+frag+'\nSCENARIO='+scenario+'\n'+common+frags[frag]+'\nprintf "PASSED\\n"\n)\nprintf "RC %s\\n" "$?"\n'
text+='printf "CASE reader_exact\\n"\n(\nset -eu\nBB=_dd\nZIPFILE=/read-only/fixture.zip\n_dd() { printf "%s\\n" "$@"; }\n'+reader+'\nread_payload 8388753 268435456\n)\nprintf "RC %s\\n" "$?"\n'
p=subprocess.run(['wsl.exe','-d','Ubuntu','--','bash','-s'],input=text.encode(),capture_output=True,timeout=90)
stdout=p.stdout.decode(errors='replace');stderr=p.stderr.decode(errors='replace')
parts=re.split(r'CASE ([^\n]+)\n',stdout);found=dict(zip(parts[1::2],parts[2::2]))
for frag,scenario,expected in cases:
    name=frag+'_'+scenario;output=found.get(name,'')
    check(name,'RC '+str(expected) in output and ('PASSED' in output)==(expected==0),output+stderr)
check('reader_exact_argv',found.get('reader_exact','')=='dd\nif=/read-only/fixture.zip\nbs=512\nskip=8388753\ncount=524288\nRC 0\n',found.get('reader_exact','')+stderr)
with zipfile.ZipFile(ROM) as z: original=z.read('META-INF/com/google/android/update-binary').decode()
def table(txt,marker):return re.search("cat <<'"+marker+r"'\n(.*?)\n"+marker,txt,re.S).group(1)
old=[r.split() for r in table(original,'SPEC').splitlines()];new=[r.split() for r in table(s,'SPEC').splitlines()]
check('all_65_exact_sector_mappings',len(old)==len(new)==65 and all(int(a[0])%512==0 and int(a[0])//512==int(b[0]) and a[1:]==b[1:] for a,b in zip(old,new)))
for marker in ['FW','WRITE']:check(marker+'_table_preserved',table(original,marker)==table(s,marker))
report={'scope':'Exact draft host fragment tests only; no recovery execution or device I/O. Storage/metadata empty-output rejection remains at downstream caller checks, not tested here.',
'draft_sha256':hashlib.sha256(raw).hexdigest(),'results':results,'passed':sum(r['passed'] for r in results),'failed':sum(not r['passed'] for r in results)}
(OUT/'supplemental-tests.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({k:v for k,v in report.items() if k!='results'},indent=2))
for r in results:
    if not r['passed']:print(json.dumps(r))
raise SystemExit(bool(report['failed']))
