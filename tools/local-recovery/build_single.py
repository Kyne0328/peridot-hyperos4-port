#!/usr/bin/env python3
"""Reproducible single recovery ZIP with source-identical DEV2 payloads.
No recovery/ROM executable is run and no device is accessed by this builder.
"""
import argparse,hashlib,io,json,struct,zipfile,zlib
from pathlib import Path
from build_local import *
RESERVE=65536
ENTRY='META-INF/com/google/android/update-binary'
def put(path,obj):
    Path(path).write_text(json.dumps(obj,indent=2)+'\n',encoding='utf-8',newline='\n')
def info(name,size,offset,align=False):
    z=zipfile.ZipInfo(name,(2026,10,2,0,0,0));z.compress_type=zipfile.ZIP_STORED
    z.create_system=3;z.external_attr=((0o100755 if name==ENTRY else 0o100644)<<16);z.file_size=size
    if align:
        padding=(-(offset+30+len(name.encode())+4))%512
        z.extra=struct.pack('<HH',0xCAFE,padding)+bytes(padding)
    return z
def validate(work):
    src=work/'source-images';m=json.loads((src/'MANIFEST.json').read_text());images=checked_manifest(m)
    require(digest(REPO/'F6-Global-HyperOS4-DEV2.tar.zst')==ARCHIVE_SHA,'Source archive mismatch')
    require(digest(REPO/'OrangeFox-R12.0_202610011528_crypto-Unofficial-peridot.zip')==FOX_SHA,'Recovery archive mismatch')
    for i in images:
        p=src/i['path'];require(p.stat().st_size==i['size'] and digest(p)==i['sha256'],'Source image differs '+i['path'])
    layout=inspect_all(src/'images/super.img');parts={p['name']:p for p in layout['partitions']}
    hashes=[]
    with (src/'images/super.img').open('rb') as f:
        for p in m['logical_inputs']:
            a=parts[p['partition']+'_a'];require(a['size_bytes']==p['size_bytes'],'LP size')
            ex=[[e['offset_bytes'],e['size_bytes']] for e in a['extents']]
            require(ex==p['physical_extents'] and parts[p['partition']+'_b']['size_bytes']==0,'LP extents or B size')
            h=hashlib.sha256()
            for off,n in ex:
                f.seek(off)
                while n:
                    b=f.read(min(n,8*1024**2));require(b,'Short LP span');h.update(b);n-=len(b)
            require(h.hexdigest()==p['sha256'],'LP span hash');hashes.append({'partition':p['partition'],'sha256':h.hexdigest()})
    # Independently extracted by installed fsck.erofs; never silently skip compressed data.
    fstab=(work/'vendor-extracted/etc/fstab.qcom').read_text()
    vb=(src/'images/vendor_boot.img').read_bytes();size=struct.unpack_from('<I',vb,24)[0]
    synthetic=bytearray(4096);synthetic[:8]=b'ANDROID!';struct.pack_into('<II',synthetic,8,0,size);struct.pack_into('<I',synthetic,40,4)
    _,files=ramdisk(bytes(synthetic)+vb[4096:4096+size]);normal=files['first_stage_ramdisk/fstab.qcom'].decode()
    flags=['fileencryption=aes-256-xts:aes-256-cts:v2+inlinecrypt_optimized+wrappedkey_v0','keydirectory=/metadata/vold/metadata_encryption','metadata_encryption=aes-256-xts:wrappedkey_v0']
    for t in [fstab,normal]:
        lines=[l for l in t.splitlines() if not l.startswith('#') and ' /data ' in l]
        require(len(lines)==2 and all(all(flag in l for flag in flags) for l in lines),'FBE flags differ')
    stock=avb((src/'images/recovery.img').read_bytes());top=avb((src/'images/vbmeta.img').read_bytes())
    chain=[d for d in top['descriptors'] if d.get('partition')=='recovery']
    require(len(chain)==1 and chain[0]['public_key_sha256']==stock['public_key_sha256'] and stock['algorithm']!=0 and top['flags']==stock['flags']==0,'Recovery AVB relationship')
    put(work/'reports/single-preparation.json',{'all_32_images_verified':True,'logical_hashes':hashes,'layout':layout,'vendor_fstab':fstab,'vendor_boot_fstab':normal,'fbe_verified':True,'stock_recovery_chain_retained':True,'device_tested':False})
    print('Single preparation passed',flush=True)

def render(spec,images):
    require(digest(HERE/'update-binary.template.sh')=='193be87caadd15ced21416a6000f24ca81899daa3dd77d16741e60d0ae785dad','Base template changed; review substitutions before build')
    s=(HERE/'update-binary.template.sh').read_text()
    s=s.replace('DEV2-RI1','DEV2-RI2').replace('dev2-ri1','dev2-ri2')
    # Early arity check before positional expansion.
    s=s.replace('OUTFD=$2','[ "$#" = 3 ] || exit 1\nOUTFD=$2',1)
    s=s.replace("packs() {\ncat <<'PACKS'\n@PACKS@\nPACKS\n}",'')
    begin=s.index('payload_path() {');end=s.index('firmware() {',begin)
    s=s[:begin]+'''read_payload() {
    offset=$1
    bytes=$2
    "$BB" dd if="$ZIPFILE" bs=512 skip="$((offset / 512))" count="$((bytes / 512))" 2>/dev/null
}
'''+s[end:]
    s=s.replace('packs > "$TMP_DIR/packs"','')
    begin=s.index('while read -r pack size digest; do');end=s.index('# Stage sizing',begin)
    s=s[:begin]+'''while read -r offset member size digest; do
    got=$(read_payload "$offset" "$size" | "$BB" sha256sum | "$BB" cut -d' ' -f1) || abort "Cannot read $member"
    [ "$got" = "$digest" ] || abort "Payload hash mismatch: $member"
done < "$TMP_DIR/spec"
'''+s[end:]
    s=s.replace('while read -r pack member size digest; do\n    file=$(payload_path "$pack") || abort "Invalid payload path"','while read -r offset member size digest; do')
    s=s.replace('"$BB" unzip -p "$file" "$member"','read_payload "$offset" "$size"')
    s=s.replace('    file=$("$BB" awk -v m="images/$name.img" \'$2 == m {print $1}\' "$TMP_DIR/spec")\n    file=$(payload_path "$file") || abort "Missing image pack mapping"\n    "$BB" unzip -p "$file" "images/$name.img"','    offset=$("$BB" awk -v m="images/$name.img" \'$2 == m {print $1}\' "$TMP_DIR/spec")\n    [ -n "$offset" ] || abort "Missing image offset"\n    read_payload "$offset" "$size"')
    guard='''# Reject all live DM mappings, mounted or not. Do not tear them down.
for dm in /sys/class/block/dm-*; do
    [ ! -e "$dm" ] || abort "Live device-mapper mapping exists; stop and resolve through recovery"
done
[ -r /proc/swaps ] || abort "Cannot inspect swap"
[ "$("$BB" wc -l < /proc/swaps)" -eq 1 ] || abort "Active swap is unsupported"
if "$BB" awk '$2 == "/data" || $2 == "/sdcard" || $2 == "/system" || $2 == "/vendor" || $2 == "/product" || $2 == "/odm" || $2 == "/system_ext" || $2 == "/mi_ext" {found=1} END {exit !found}' /proc/mounts; then
    abort "Userdata or logical mountpoint remains mounted"
fi
ZIPFILE=$("$BB" readlink -f "$ZIPFILE") || abort "Cannot resolve ZIP path"
case "$ZIPFILE" in /usb_otg/*|/external_sd/*|/mnt/media_rw/*) ;; *) abort "Use a regular file on external USB storage; sideload unsupported";; esac
# The longest mountpoint prefix must resolve to a removable block-backed filesystem.
storage=$("$BB" awk -v z="$ZIPFILE" 'index(z,$2 "/")==1 && length($2)>best {best=length($2);source=$1} END {print source}' /proc/mounts)
storage=$("$BB" readlink -f "$storage") || abort "Cannot resolve external storage"
[ -b "$storage" ] || abort "ZIP storage must be block backed"
disk=$("$BB" basename "$storage")
sys=$("$BB" readlink -f "/sys/class/block/$disk") || abort "Unknown ZIP backing device"
if [ -f "$sys/partition" ]; then sys=$("$BB" dirname "$sys"); fi
[ "$("$BB" cat "$sys/removable")" = 1 ] || abort "ZIP storage is not removable"
metadata=$("$BB" awk '$2 == "/metadata" {print $1}' /proc/mounts)
[ "$("$BB" readlink -f "$metadata")" = "$("$BB" readlink -f /dev/block/by-name/metadata)" ] || abort "Wrong metadata mount source"
[ -r /metadata ] && [ -x /metadata ] || abort "Metadata is not inspectable"
'''
    guard += '''if [ -e /metadata/ota ]; then
    [ -d /metadata/ota ] && [ -r /metadata/ota ] && [ -x /metadata/ota ] || abort "OTA state is not inspectable"
    ota_entries=$("$BB" ls -A /metadata/ota) || abort "OTA state listing failed"
    [ -z "$ota_entries" ] || abort "Metadata OTA state exists"
fi
'''
    s=s.replace('PAYLOAD_ROOT=$("$BB" dirname "$ZIPFILE")',guard)
    s=s.replace('    [ -b "$resolved" ] || abort "Target $1 is not a block device"', '''    [ -b "$resolved" ] || abort "Target $1 is not a block device"
    sysnode="/sys/class/block/$("$BB" basename "$resolved")"
    devnum=$("$BB" cat "$sysnode/dev") || abort "Cannot determine target device number"
    if "$BB" awk -v d="$devnum" '$3 == d {found=1} END {exit !found}' /proc/self/mountinfo; then
        abort "Target is mounted: $1"
    fi
    for holder in "$sysnode"/holders/*; do
        [ ! -e "$holder" ] || abort "Target has a live holder: $1"
    done''')
    # Check target identity by kernel device number, not just alias spelling.
    s=s.replace("printf '%s\\n' \"$SUPER\" >> \"$TMP_DIR/targets\"",'"$BB" stat -c "%t:%T" "$SUPER" >> "$TMP_DIR/targets"')
    s=s.replace("printf '%s\\n' \"$target\" >> \"$TMP_DIR/targets\"",'"$BB" stat -c "%t:%T" "$target" >> "$TMP_DIR/targets"')
    s=s.replace('@SPEC@','\n'.join(' '.join(map(str,r)) for r in spec))
    s=s.replace('@FIRMWARE@',rows(images,sorted(PHYSICAL-set(WRITE_ORDER)))).replace('@WRITES@',rows(images,WRITE_ORDER))
    require('@' not in s,'Unrendered placeholder');require('unzip' not in s and 'payload_path' not in s,'Old extraction remains')
    require(len(s.encode())<RESERVE,'Installer exceeds reservation')
    return s.encode()+b'\n#'+b' '*(RESERVE-len(s.encode())-3)+b'\n'
def build(work):
    require(json.loads((work/'reports/single-preparation.json').read_text())['fbe_verified'],'Preparation missing')
    src=work/'source-images';m=json.loads((src/'MANIFEST.json').read_text());images=checked_manifest(m)
    require(digest(src/'MANIFEST.json')=='bc5f9e4f415e2910667aae20935e3130a1bfa99acb46c1131c170b31a325c38b','Unreviewed source manifest')
    for i in images:
        require(digest(src/i['path'])==i['sha256'],'Prepared image changed: '+i['path'])
    out=work/'F6-Global-HyperOS4-DEV2-RI2.zip';require(not out.exists(),'Refuse overwrite')
    # Installer occupies a fixed-size initial member. Payload positions are known before writing.
    records=[];pos=30+len(ENTRY)+RESERVE
    for i in images:
        path=src/i['path'];step=CHUNK if path.name=='super.img' else i['size']
        with path.open('rb') as f:
            off=0
            while off<i['size']:
                n=min(step,i['size']-off);name=(f"super/super.{off//CHUNK:03}" if path.name=='super.img' else i['path'])
                zi=info(name,n,pos,True);start=pos+30+len(name)+len(zi.extra)
                b=f.read(n);require(len(b)==n,'Short source');h=hashlib.sha256(b).hexdigest()
                records.append({'name':name,'offset':start,'size':n,'sha256':h,'source':str(path),'source_offset':off,'header_offset':pos})
                pos=start+n;off+=n
    spec=[[r['offset'],r['name'],r['size'],r['sha256']] for r in records];script=render(spec,images)
    with zipfile.ZipFile(out,'x',compression=zipfile.ZIP_STORED,allowZip64=True) as z:
        z.writestr(info(ENTRY,RESERVE,0),script)
        for r in records:
            zi=info(r['name'],r['size'],z.fp.tell(),True)
            require(z.fp.tell()==r['header_offset'],'Offset planning mismatch')
            with open(r['source'],'rb') as f,z.open(zi,'w') as dst:
                f.seek(r['source_offset']);require(copy_hash(f,dst,r['size'])==r['sha256'],'Input changed during packaging')
            print('Stored',r['name'],flush=True)
        z.writestr(info('META-INF/com/google/android/updater-script',8,z.fp.tell()),b'#MAGISK\n')
        z.writestr(info('SOURCE-MANIFEST.json',0,z.fp.tell()),(src/'MANIFEST.json').read_bytes())
        z.writestr(info('INSTALL-PREREQUISITES.txt',0,z.fp.tell()),(HERE/'SINGLE-INSTALL-PREREQUISITES.txt').read_bytes())
    put(work/'reports/single-package-manifest.json',{'build_id':'DEV2-RI2','path':str(out),'size':out.stat().st_size,'sha256':digest(out),'payload':records,'images':images,'zip64':True,'all_images_unchanged':True,'device_tested':False})
    (work/'reports/single-update-binary.sh').write_bytes(script)
    print('BUILT',out,out.stat().st_size,digest(out),flush=True)
def verify(work):
    m=json.loads((work/'reports/single-package-manifest.json').read_text());out=Path(m['path'])
    require(out.stat().st_size==m['size'] and digest(out)==m['sha256'],'Whole ZIP mismatch')
    whole=hashlib.sha256();size=0;phys={}
    with zipfile.ZipFile(out) as z,out.open('rb') as raw:
        require(len(z.namelist())==len(set(z.namelist())),'Duplicate names')
        require(z.testzip() is None,'CRC failure')
        for r in m['payload']:
            zi=z.getinfo(r['name']);raw.seek(zi.header_offset);head=raw.read(30)
            magic,vers,flags,method,tm,dt,crc,csize,usize,nlen,elen=struct.unpack('<IHHHHHIIIHH',head)
            require(magic==0x04034b50 and flags==0 and method==0,'Not plain stored entry')
            require(zi.header_offset+30+nlen+elen==r['offset'] and r['offset']%512==0 and r['size']%512==0,'Raw offset alignment')
            require(zi.file_size==r['size'] and zi.compress_size==r['size'],'Member size')
            h=hashlib.sha256()
            with z.open(zi) as f:
                while b:=f.read(8*1024**2):
                    h.update(b)
                    if r['name'].startswith('super/'):whole.update(b);size+=len(b)
            require(h.hexdigest()==r['sha256'],'Member hash')
            raw.seek(r['offset']);require(copy_hash(raw,io.BytesIO(),r['size'])==r['sha256'],'Raw range differs')
            if r['name'].startswith('images/'):phys[r['name']]=(r['size'],r['sha256'])
    pin=next(i for i in m['images'] if i['path']=='images/super.img')
    require(size==pin['size'] and whole.hexdigest()==pin['sha256'],'Reassembled super differs')
    for p in m['images']:
        if p['path']!='images/super.img':require(phys[p['path']]==(p['size'],p['sha256']),'Physical payload differs')
    put(work/'reports/single-verification.json',{'archive_sha256':m['sha256'],'archive_size':m['size'],'zip_crc_all_pass':True,'all_stored_offsets_verified':True,'all_32_images_identical':True,'super_sha256':whole.hexdigest(),'zip64':True,'boot_tested':False,'recovery_launch_tested':False})
    print('VERIFY PASS',m['sha256'],flush=True)
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('phase',choices=['validate','build','verify']);p.add_argument('--work',type=Path,required=True);a=p.parse_args();globals()[a.phase](a.work)
