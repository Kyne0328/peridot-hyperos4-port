#!/usr/bin/env python3
"""Build an immutable-image, split recovery package. No device commands are executed."""
import argparse, hashlib, json, os, shutil, struct, sys, tarfile, zipfile
from pathlib import Path
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
REPO=HERE.parents[1]
sys.path[:0]=[str(REPO/'builder'),str(REPO/'tools/global-build/linux-assembly')]
from inspect_recovery import inspect_fox, avb, ramdisk, require
from super_stream import inspect_all
from inspect_erofs_payload import Erofs

ARCHIVE_SHA='af21e312267035d7de1d1aff6511000f6ccffdc948b80506198a43e5eea82435'
FOX_SHA='b04ec7c0add35457fe7f53e308acf23cdf0a62d8d4ed05f1392ac23e6cbb5cf4'
SUPER_SIZE=9126805504
CHUNK=256*1024*1024
PACK_LIMIT=1792*1024*1024
WRITE_ORDER=['boot','dtbo','init_boot','vendor_boot','recovery','vbmeta_system','vbmeta']
PARTITIONS={'mi_ext','odm','product','system','system_dlkm','system_ext','vendor','vendor_dlkm'}
PHYSICAL={'abl','aop','aop_config','bluetooth','boot','countrycode','cpucp','cpucp_dtb',
'devcfg','dsp','dtbo','featenabler','hyp','imagefv','init_boot','keymaster','modem',
'modemfirmware','multiimgqti','qupfw','recovery','shrm','tz','uefi','uefisecapp',
'vbmeta','vbmeta_system','vendor_boot','xbl','xbl_config','xbl_ramdump'}

def digest(path):
    with Path(path).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def save(path,data):
    with Path(path).open('x',encoding='utf-8',newline='\n') as f:
        json.dump(data,f,indent=2);f.write('\n')
def checked_manifest(manifest):
    images=manifest['images']; names=[i['path'] for i in images]
    require(len(names)==32 and set(names)=={'images/super.img'}|{'images/'+n+'.img' for n in PHYSICAL},'Unexpected image set')
    require(len(set(names))==len(names),'Duplicate image paths')
    for i in images:
        require(type(i['size']) is int and i['size']>0 and i['size']%512==0,'Invalid sector-aligned image size')
        require(len(i['sha256'])==64 and all(c in '0123456789abcdef' for c in i['sha256']),'Invalid image digest')
    require(sum(i['size'] for i in images)==9909477376,'Unexpected total image bytes')
    require(manifest['super']['size_bytes']==SUPER_SIZE if 'size_bytes' in manifest['super'] else next(i for i in images if i['path']=='images/super.img')['size']==SUPER_SIZE,'Unexpected super size')
    return images
def safe_member(name,expected):
    require(name in expected and not name.startswith('/') and '..' not in Path(name).parts,'Unexpected archive member')
def copy_hash(src,dst,size):
    h=hashlib.sha256();remaining=size
    while remaining:
        b=src.read(min(8*1024*1024,remaining));require(b,'Short input');dst.write(b);h.update(b);remaining-=len(b)
    return h.hexdigest()

class MappedErofs(Erofs):
    def __init__(self,f,extents,size):
        self.f=f;self.extents=extents;self.size=size
        s=self.read(1024,128)
        require(struct.unpack_from('<I',s)[0]==0xe0f5e1e2,'Not EROFS')
        self.bs=1<<s[12];self.root=struct.unpack_from('<H',s,14)[0]
        self.meta=struct.unpack_from('<I',s,40)[0]*self.bs
        self.xattr_base=struct.unpack_from('<I',s,44)[0]*self.bs
        require(self.bs==4096,'Unsupported block size')
    def read(self,off,n):
        # Inline-only EROFS inodes may carry an unused UINT32_MAX block address.
        # A zero-byte read must not dereference that unused address.
        if n == 0: return b''
        require(off>=0 and n>0 and off+n<=self.size,'Out of partition bounds')
        result=bytearray();logical=0
        for physical,length in self.extents:
            if off<logical+length and n:
                take=min(n,logical+length-off)
                self.f.seek(physical+off-logical);b=self.f.read(take)
                require(len(b)==take,'Short super read');result+=b;off+=take;n-=take
            logical+=length
        require(n==0,'Unmapped bytes');return bytes(result)
    def file(self,path):
        nid=self.root
        for component in path.strip('/').split('/'):
            matches=[x for x in self.entries(nid) if x[0]==component]
            require(len(matches)==1,'Missing EROFS path '+path);nid=matches[0][1]
        return self.data(self.inode(nid))

def prepare(work):
    src=REPO/'F6-Global-HyperOS4-DEV2.tar.zst';fox=REPO/'OrangeFox-R12.0_202610011528_crypto-Unofficial-peridot.zip'
    require(src.stat().st_size==7459585211 and digest(src)==ARCHIVE_SHA,'DEV2 archive differs')
    require(fox.stat().st_size==74771231 and digest(fox)==FOX_SHA,'OrangeFox differs')
    print('Input hashes verified',flush=True)
    manifest=json.loads((REPO/'09-reports/global-4.0.0.9-on-f6-3.0.303/dev2/image-set-manifest.json').read_text())
    images=checked_manifest(manifest)
    require(not work.exists(),'Work directory already exists; refuse overwrite')
    require(shutil.disk_usage(work.parent).free>32*1024**3,'Need at least 32 GiB available')
    work.mkdir();(work/'reports').mkdir();extract=work/'source-images';extract.mkdir()
    expected={'F6-Global-HyperOS4-DEV2/'+i['path']:i for i in images}
    expected.update({'F6-Global-HyperOS4-DEV2/'+n:None for n in ['README.txt','MANIFEST.json','SHA256SUMS','development.avbpubkey']})
    seen=set()
    with tarfile.open(src,mode='r|zst') as tar:
        for member in tar:
            safe_member(member.name,expected);require(member.isfile() and member.name not in seen,'Unsafe/duplicate tar entry')
            seen.add(member.name);relative=member.name.split('/',1)[1];dest=extract/relative;dest.parent.mkdir(exist_ok=True)
            pin=expected[member.name]
            if pin:require(member.size==pin['size'],'Tar image size mismatch')
            with tar.extractfile(member) as fin,dest.open('xb') as fout:got=copy_hash(fin,fout,member.size)
            if pin:require(got==pin['sha256'],'Extracted image digest mismatch')
            print('Verified extraction',relative,member.size,flush=True)
    require(seen==set(expected),'Incomplete archive')
    require((extract/'MANIFEST.json').read_bytes()==(REPO/'09-reports/global-4.0.0.9-on-f6-3.0.303/dev2/image-set-manifest.json').read_bytes(),'Archive manifest differs from reviewed report')
    fox_report=inspect_fox(fox);save(work/'reports/orangefox-inspection.json',fox_report)
    print('OrangeFox static inspection complete',flush=True)
    stock=avb((extract/'images/recovery.img').read_bytes());top=avb((extract/'images/vbmeta.img').read_bytes())
    chain=[i for i in top['descriptors'] if i.get('partition')=='recovery']
    require(len(chain)==1 and chain[0]['public_key_sha256']==stock['public_key_sha256'] and stock['algorithm']!=0,'DEV2 recovery child-chain mismatch')
    require(top['flags']==stock['flags']==0,'Verification disable flags present')
    save(work/'reports/recovery-avb-decision.json',{
      'stock_recovery':stock,'dev2_top_vbmeta':top,'supplied_orangefox':fox_report['avb'],
      'decision':'Keep exact signed stock recovery. Supplied OrangeFox is unsigned (algorithm NONE, no key) and cannot satisfy retained OEM recovery child-chain.',
      'orangefox_integrated':False,'new_signing_performed':False,
      'remaining_gate':'Temporary/existing OrangeFox recovery access and bootloader acceptance need separate device validation; no setup performed.'})
    layout=inspect_all(extract/'images/super.img')
    require({i['name'] for i in layout['partitions']}=={n+'_'+s for n in PARTITIONS for s in ['a','b']},'Unexpected LP partitions')
    lookup={i['name']:i for i in layout['partitions']}
    observed=[]
    with (extract/'images/super.img').open('rb') as f:
        for pin in manifest['logical_inputs']:
            actual=lookup[pin['partition']+'_a']
            ex=[[e['offset_bytes'],e['size_bytes']] for e in actual['extents']]
            require(actual['size_bytes']==pin['size_bytes'] and ex==pin['physical_extents'],'LP map mismatch')
            require(lookup[pin['partition']+'_b']['size_bytes']==0,'Inactive logical slot not empty')
            h=hashlib.sha256()
            for offset,size in ex:
                f.seek(offset);remaining=size
                while remaining:
                    b=f.read(min(8*1024**2,remaining));require(b,'Short span');h.update(b);remaining-=len(b)
            require(h.hexdigest()==pin['sha256'],'Logical image digest mismatch')
            observed.append({'partition':pin['partition'],'sha256':h.hexdigest(),'size':pin['size_bytes']})
        pin=next(i for i in manifest['logical_inputs'] if i['partition']=='vendor')
        e=MappedErofs(f,pin['physical_extents'],pin['size_bytes'])
        fstab=e.file('/etc/fstab.qcom').decode()
    save(work/'reports/lp-and-image-validation.json',{'layout':layout,'logical_hashes':observed,'all_32_images_source_identical':True})
    vb=(extract/'images/vendor_boot.img').read_bytes()
    require(vb[:8]==b'VNDRBOOT','Wrong vendor_boot header')
    size=struct.unpack_from('<I',vb,24)[0]
    # Adapt the actual vendor ramdisk to the same bounded legacy-LZ4/CPIO reader.
    synthetic=bytearray(4096);synthetic[:8]=b'ANDROID!';struct.pack_into('<II',synthetic,8,0,size);struct.pack_into('<I',synthetic,40,4)
    _,files=ramdisk(bytes(synthetic)+vb[4096:4096+size])
    normal=files['first_stage_ramdisk/fstab.qcom'].decode()
    required=['fileencryption=aes-256-xts:aes-256-cts:v2+inlinecrypt_optimized+wrappedkey_v0',
              'keydirectory=/metadata/vold/metadata_encryption','metadata_encryption=aes-256-xts:wrappedkey_v0']
    for text in (fstab,normal):
        lines=[l for l in text.splitlines() if not l.startswith('#') and ' /data ' in l]
        require(len(lines)==2 and all(all(flag in l for flag in required) for l in lines),'FBE configuration differs')
    save(work/'reports/fbe-contract.json',{'vendor_fstab':fstab,'vendor_boot_fstab':normal,
        'stock_recovery_retained':True,'source_images_unchanged':True,'runtime_key_provisioning_verified':False,
        'encrypted_data_migration_supported':False,'recovery_decryption_verified':False})
    save(work/'reports/preparation.json',{'source_archive_sha256':ARCHIVE_SHA,'orangefox_archive_sha256':FOX_SHA,
        'all_source_images_verified':True,'all_lp_copies_verified':True,'all_logical_spans_verified':True,
        'fbe_flags_verified':True,'input_archives_immutable':True,'phone_actions':False})
    print('Preparation complete:',work,flush=True)

def rows(images,order):
    by={Path(i['path']).stem:i for i in images}
    return '\n'.join(f"{n} {by[n]['size']} {by[n]['sha256']}" for n in order)

def build(work):
    extract=work/'source-images';manifest=json.loads((extract/'MANIFEST.json').read_text());images=checked_manifest(manifest)
    require(json.loads((work/'reports/preparation.json').read_text())['fbe_flags_verified'],'Preparation not complete')
    out=work/'F6-Global-HyperOS4-DEV2-RI1';require(not out.exists(),'Refuse output overwrite');out.mkdir()
    payloads=[];spec=[];archive=None;payload_index=-1;used=0
    def new_pack():
        nonlocal archive,payload_index,used
        if archive:archive.close()
        payload_index+=1;used=0
        archive=zipfile.ZipFile(out/f'payload.{payload_index:03}.zip','x',compression=zipfile.ZIP_STORED,allowZip64=False)
    def append(member,fin,size,expected=None):
        nonlocal used
        if archive is None or used+size+4096>PACK_LIMIT:new_pack()
        info=zipfile.ZipInfo(member,date_time=(2026,10,2,0,0,0));info.compress_type=zipfile.ZIP_STORED
        info.external_attr=(0o100644<<16)
        with archive.open(info,'w') as fout:got=copy_hash(fin,fout,size)
        if expected:require(got==expected,'Source changed during packaging')
        spec.append([f'payload.{payload_index:03}.zip',member,size,got]);used+=size+256
    try:
        with (extract/'images/super.img').open('rb') as f:
            offset=0;index=0;whole=hashlib.sha256()
            while offset<SUPER_SIZE:
                size=min(CHUNK,SUPER_SIZE-offset)
                # One chunk fits memory and is hashed independently; no sparse holes.
                data=f.read(size);require(len(data)==size,'Short super');whole.update(data)
                import io
                append(f'super/super.{index:03}',io.BytesIO(data),size)
                offset+=size;index+=1
                print('Packaged super chunk',index,flush=True)
            require(whole.hexdigest()==next(i['sha256'] for i in images if i['path']=='images/super.img'),'Super changed')
        for i in images:
            if i['path']=='images/super.img':continue
            with (extract/i['path']).open('rb') as f:append(i['path'],f,i['size'],i['sha256'])
    finally:
        if archive:archive.close()
    for f in sorted(out.glob('payload.*.zip')):
        require(f.stat().st_size<2**31,'Companion exceeds ZIP32 compatibility bound')
        payloads.append({'name':f.name,'size':f.stat().st_size,'sha256':digest(f)})
    firmware=sorted(PHYSICAL-set(WRITE_ORDER))
    template=(HERE/'update-binary.template.sh').read_text()
    rendered=template.replace('@SPEC@','\n'.join(' '.join(map(str,r)) for r in spec))
    rendered=rendered.replace('@PACKS@','\n'.join(f"{i['name']} {i['size']} {i['sha256']}" for i in payloads))
    rendered=rendered.replace('@FIRMWARE@',rows(images,firmware)).replace('@WRITES@',rows(images,WRITE_ORDER))
    require('@SPEC@' not in rendered and '@PACKS@' not in rendered,'Unrendered installer')
    (work/'reports/rendered-update-binary.sh').write_text(rendered,encoding='utf-8',newline='\n')
    notes=(HERE/'INSTALL-PREREQUISITES.txt').read_text()
    with zipfile.ZipFile(out/'INSTALL-DEV2-RI1.zip','x',compression=zipfile.ZIP_STORED,allowZip64=False) as z:
        for name,text in [('META-INF/com/google/android/update-binary',rendered),
                          ('META-INF/com/google/android/updater-script','#MAGISK\n'),
                          ('INSTALL-PREREQUISITES.txt',notes)]:
            info=zipfile.ZipInfo(name,date_time=(2026,10,2,0,0,0));info.external_attr=((0o100755 if name.endswith('update-binary') else 0o100644)<<16)
            z.writestr(info,text.encode())
    (out/'INSTALL-PREREQUISITES.txt').write_text(notes,encoding='utf-8',newline='\n')
    files=payloads+[{'name':'INSTALL-DEV2-RI1.zip','size':(out/'INSTALL-DEV2-RI1.zip').stat().st_size,'sha256':digest(out/'INSTALL-DEV2-RI1.zip')}]
    package={'build_id':'F6-Global-HyperOS4-DEV2-RI1','image_build':'unchanged DEV2',
      'status':'offline_packaging_candidate_runtime_installation_unverified','source_archive_sha256':ARCHIVE_SHA,
      'source_image_manifest_sha256':digest(extract/'MANIFEST.json'),'files':files,'payload_members':spec,
      'writes':WRITE_ORDER+['shared super'],'firmware':'Exact source-prefix verification only; no firmware writes',
      'target_slot':'A only, already current and active','slot_B_boot_firmware_untouched':True,
      'slot_B_old_ROM_rollback_available':False,'userdata_metadata_wiped':False,'orangefox_permanently_integrated':False,
      'security_settings_changed':False,'new_signing_performed':False,'device_actions_performed':False,
      'runtime_gates':['Bootloader development-key acceptance','Clean-data initialization','First boot',
                      'FBE wrapped-key provisioning and credential unlock','Stock recovery decryption',
                      'Recovery execution and ZIP parser/tool support','Interruption/recovery behavior'],
      'existing_known_strict_selinux_assertions':77}
    save(out/'PACKAGE-MANIFEST.json',package)
    (out/'SHA256SUMS').write_text(''.join(i['sha256']+'  '+i['name']+'\n' for i in files)+digest(out/'PACKAGE-MANIFEST.json')+'  PACKAGE-MANIFEST.json\n',newline='\n')
    print('Built split package',out,flush=True)

def verify(work):
    out=work/'F6-Global-HyperOS4-DEV2-RI1';m=json.loads((out/'PACKAGE-MANIFEST.json').read_text())
    seen={};whole=hashlib.sha256();super_size=0
    for pin in m['files']:
        f=out/pin['name'];require(f.stat().st_size==pin['size'] and digest(f)==pin['sha256'],'Package file changed')
        require(f.stat().st_size<2**31,'ZIP32 bound exceeded')
        with zipfile.ZipFile(f) as z:
            require(len(z.namelist())==len(set(z.namelist())),'Duplicate ZIP members')
            require(z.testzip() is None,'CRC error')
            if not pin['name'].startswith('payload.'):continue
            for info in z.infolist():
                require(info.filename not in seen,'Duplicate payload member');h=hashlib.sha256()
                with z.open(info) as fin:
                    while b:=fin.read(8*1024**2):
                        h.update(b)
                        if info.filename.startswith('super/'):whole.update(b);super_size+=len(b)
                seen[info.filename]=(info.file_size,h.hexdigest())
    require(seen=={r[1]:(r[2],r[3]) for r in m['payload_members']},'Package payload differs from pinned spec')
    src=json.loads((work/'source-images/MANIFEST.json').read_text())
    super_pin=next(i for i in src['images'] if i['path']=='images/super.img')
    require(super_size==SUPER_SIZE and whole.hexdigest()==super_pin['sha256'],'Reassembled super differs')
    for i in src['images']:
        if i['path']!='images/super.img':require(seen[i['path']]==(i['size'],i['sha256']),'Packaged physical image differs')
    require(m['writes'][-1]=='shared super' and m['target_slot'].startswith('A only'),'Unexpected install contract')
    save(work/'reports/package-verification.json',{'package_manifest_sha256':digest(out/'PACKAGE-MANIFEST.json'),
      'all_companion_hashes_verified':True,'all_zip_crc_verified':True,'all_payload_member_hashes_verified':True,
      'reassembled_super_sha256':whole.hexdigest(),'all_32_images_source_identical':True,
      'zip64_required':False,'runtime_install_tested':False,'boot_tested':False})
    print('Independent full package readback passed; package manifest SHA256',digest(out/'PACKAGE-MANIFEST.json'),flush=True)

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('phase',choices=['prepare','build','verify']);parser.add_argument('--work',type=Path,required=True);args=parser.parse_args()
    {'prepare':prepare,'build':build,'verify':verify}[args.phase](args.work)
