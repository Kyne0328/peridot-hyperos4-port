#!/usr/bin/env python3
"""Prepare an UNRELEASED RI3 installer draft from immutable RI2; no ZIP build or device I/O.
A supported outer recovery contract must be approved and independently verified before packaging.
"""
import hashlib,json,pathlib,re,zipfile
ROOT=pathlib.Path(__file__).resolve().parents[2]
OUT=ROOT/'09-reports/installer-ri3'
ROM=ROOT/'F6-Global-HyperOS4-DEV2-RI2.zip'
ENTRY='META-INF/com/google/android/update-binary'
PIN='2f7e76ae406fadd962267d78b18b0533f3dec72592c91a2963a2005810c0ef65'
def replace(s,old,new):
    assert s.count(old)==1, ('Unexpected source match',old)
    return s.replace(old,new,1)
def render(raw):
    assert hashlib.sha256(raw).hexdigest()==PIN,'RI2 installer changed'
    s=raw.decode().rstrip()
    # Remove original reservation padding, preserving actual source.
    s=s[:s.rfind('\n#')+1] if s.endswith('#') else s
    s=s.replace('DEV2-RI2','DEV2-RI3-DRAFT').replace('dev2-ri2','dev2-ri3')
    rows=re.search(r"cat <<'SPEC'\n(.*?)\nSPEC",s,re.S).group(1)
    planned=[]
    for row in rows.splitlines():
        off,name,size,sha=row.split(); off=int(off); size=int(size)
        assert off%512==size%512==0 and 0<off//512<=20000000
        assert 0<size<=268435456
        planned.append([off//512,name,size,sha])
    s=replace(s,rows,'\n'.join(' '.join(map(str,row)) for row in planned))
    begin=s.index('read_payload() {');end=s.index('firmware() {',begin)
    s=s[:begin]+"""# The SPEC first column is a precomputed 512-byte sector index, NEVER byte offset.
# All shell arithmetic operands are canonical decimal values below 2^31.
read_payload() {
    [ "$#" = 2 ] || return 1
    sector=$1
    bytes=$2
    case "$sector" in ''|0|0*|*[!0-9]*) return 1;; esac
    case "$bytes" in ''|0|0*|*[!0-9]*) return 1;; esac
    [ "${#sector}" -le 8 ] && [ "${#bytes}" -le 9 ] || return 1
    [ "$sector" -le 20000000 ] && [ "$bytes" -le 268435456 ] || return 1
    [ "$((bytes % 512))" = 0 ] || return 1
    "$BB" dd if="$ZIPFILE" bs=512 skip="$sector" count="$((bytes / 512))" 2>/dev/null
}
"""+s[end:]
    s=replace(s,"""    if "$BB" awk -v d="$devnum" '$3 == d {found=1} END {exit !found}' /proc/self/mountinfo; then
        abort "Target is mounted: $1"
    fi""","""    # A failed inspection is not evidence of an unmounted target.
    mount_state=$("$BB" awk -v d="$devnum" '
        BEGIN {if (d !~ /^[0-9]+:[0-9]+$/) bad=1}
        {
            records++
            if (NF<10 || $1 !~ /^[0-9]+$/ || $2 !~ /^[0-9]+$/ ||
                $3 !~ /^[0-9]+:[0-9]+$/ || $4 !~ /^\\// || $5 !~ /^\\//) bad=1
            sep=0
            for (i=7;i<=NF;i++) if ($i=="-") {sep=i;break}
            if (sep<7 || NF!=sep+3) bad=1
            if ($3==d) found=1
        }
        END {
            if (bad || records==0) exit 2
            print found ? "mounted" : "clear"
        }' /proc/self/mountinfo) || abort "Cannot inspect target mount state: $1"
    case "$mount_state" in
        clear) ;;
        mounted) abort "Target is mounted: $1";;
        *) abort "Invalid target mount evidence: $1";;
    esac""")
    # Apply the same fail-closed contract to both other rejecting mount queries.
    s=replace(s,"""if "$BB" grep -Eq '^/dev/block/(mapper/|dm-)' /proc/mounts; then
    abort "Unmount userdata and all logical partitions; use external ZIP storage"
fi""","""dm_mounted=$("$BB" awk '
    {n++; if (NF!=6 || $5 !~ /^[0-9]+$/ || $6 !~ /^[0-9]+$/) bad=1
     if ($1 ~ /^\\/dev\\/block\\/(mapper\\/|dm-)/) found=1}
    END {if (bad || n==0) exit 2; print found ? "yes" : "no"}
    ' /proc/mounts) || abort "Cannot inspect mounted device-mapper state"
case "$dm_mounted" in
    no) ;;
    yes) abort "Unmount userdata and all logical partitions; use external ZIP storage";;
    *) abort "Invalid mounted device-mapper evidence";;
esac""")
    s=replace(s,"""if "$BB" awk '$2 == "/data" || $2 == "/sdcard" || $2 == "/system" || $2 == "/vendor" || $2 == "/product" || $2 == "/odm" || $2 == "/system_ext" || $2 == "/mi_ext" {found=1} END {exit !found}' /proc/mounts; then
    abort "Userdata or logical mountpoint remains mounted"
fi""","""logical_mounted=$("$BB" awk '
    {n++; if (NF!=6 || $5 !~ /^[0-9]+$/ || $6 !~ /^[0-9]+$/) bad=1}
    $2 == "/data" || $2 == "/sdcard" || $2 == "/system" ||
    $2 == "/vendor" || $2 == "/product" || $2 == "/odm" ||
    $2 == "/system_ext" || $2 == "/mi_ext" {found=1}
    END {if (bad || n==0) exit 2; print found ? "yes" : "no"}
    ' /proc/mounts) || abort "Cannot inspect logical mountpoints"
case "$logical_mounted" in
    no) ;;
    yes) abort "Userdata or logical mountpoint remains mounted";;
    *) abort "Invalid logical mountpoint evidence";;
esac""")
    # All successful lookups must also propagate inspection process errors.
    s=replace(s,"""storage=$("$BB" awk -v z="$ZIPFILE" 'index(z,$2 "/")==1 && length($2)>best {best=length($2);source=$1} END {print source}' /proc/mounts)""","""storage=$("$BB" awk -v z="$ZIPFILE" 'index(z,$2 "/")==1 && length($2)>best {best=length($2);source=$1} END {print source}' /proc/mounts) || abort "Cannot inspect ZIP backing mount"\n""")
    s=replace(s,"""metadata=$("$BB" awk '$2 == "/metadata" {print $1}' /proc/mounts)""","""metadata=$("$BB" awk '$2 == "/metadata" {print $1}' /proc/mounts) || abort "Cannot inspect metadata mount"\n""")
    # Explicit draft interlock: this is not an installable release.
    s=replace(s,'WRITES_STARTED=0','WRITES_STARTED=0\n# DRAFT ONLY: outer recovery contract unresolved.\nexit 1')
    return s.encode(),planned
def main():
    OUT.mkdir(exist_ok=True)
    with zipfile.ZipFile(ROM) as z: raw=z.read(ENTRY)
    result,rows=render(raw)
    (OUT/'update-binary.DRAFT.sh').write_bytes(result)
    (OUT/'sector-plan.json').write_text(json.dumps(rows,indent=2)+'\n')
    receipt={'state':'UNRELEASED_DRAFT','source_installer_sha256':PIN,
        'draft_sha256':hashlib.sha256(result).hexdigest(),'draft_bytes':len(result),
        'payload_ranges':len(rows),'max_sector':max(r[0] for r in rows),
        'outer_contract':'BLOCKED: exact OrangeFox standard ZIP hooks exceed permitted writes',
        'zip_created':False,'device_actions':False}
    (OUT/'repair-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps(receipt,indent=2))
if __name__=='__main__': main()
