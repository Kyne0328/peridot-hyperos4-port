#!/usr/bin/env python3
"""Generate a fixed host-only miniature trusted contract; never used by ARM builds."""
from pathlib import Path
import hashlib, json, struct, zipfile, zlib
ROOT=Path(__file__).resolve().parents[5]
WORK=ROOT/'builder/work/installer-ri3-native/runtime-fixture'
HERE=Path(__file__).resolve().parent
FIRMWARE='abl aop aop_config bluetooth countrycode cpucp cpucp_dtb devcfg dsp featenabler hyp imagefv keymaster modem modemfirmware multiimgqti qupfw shrm tz uefi uefisecapp xbl xbl_config xbl_ramdump'.split()
WRITES=['super','boot_a','dtbo_a','init_boot_a','vendor_boot_a','vbmeta_system_a','vbmeta_a']
RUNTIME=['/system/bin/recovery','/system/bin/pre_rom_flash.sh','/system/bin/post_rom_flash_completion.sh','/system/etc/twrp.flags','/system/bin/twrp','/system/etc/security/otacerts.zip']
def content(label,size):
    unit=hashlib.sha256(('RI3 compiled regular-file fixture v1:'+label).encode()).digest()
    return (unit*((size+len(unit)-1)//len(unit)))[:size]
def digest(data): return hashlib.sha256(data).hexdigest()
def write(path,data):
    path.parent.mkdir(parents=True,exist_ok=True); path.write_bytes(data)
def zip_write(z,name,data):
    i=zipfile.ZipInfo(name,(2020,1,1,0,0,0));i.compress_type=zipfile.ZIP_STORED;i.external_attr=0o100644<<16
    z.writestr(i,data)
def main():
    data=WORK/'data';data.mkdir(parents=True,exist_ok=True)
    raw=content('super-first',4096)+bytes(4096)+content('super-last',4096)
    crc=zlib.crc32(raw)&0xffffffff
    sparse=struct.pack('<IHHHHIIII',0xed26ff3a,1,0,28,12,4096,3,4,crc)
    sparse+=struct.pack('<HHII',0xcac1,0,1,4108)+raw[:4096]
    sparse+=struct.pack('<HHII',0xcac2,0,1,16)+bytes(4)
    sparse+=struct.pack('<HHII',0xcac1,0,1,4108)+raw[-4096:]
    sparse+=struct.pack('<HHII',0xcac4,0,0,16)+struct.pack('<I',crc)
    images={n:(raw if n=='super' else content(n,12288 if n=='vbmeta_a' else 4096)) for n in WRITES}
    pins={n:{'bytes':len(v),'sha256':digest(v)} for n,v in images.items()}
    for n,v in images.items():
        write(data/'expected'/n,v);write(data/'targets'/n,bytes([0xa5])*len(v))
    protected={}
    for n in sorted(set([x[:-2]+'_b' for x in WRITES if x!='super']+[x+'_b' for x in FIRMWARE]+['recovery_a','recovery_b'])):
        v=content(n,4096);write(data/'targets'/n,v);protected[n]={'bytes':len(v),'sha256':digest(v)}
    firmware={}
    for f in FIRMWARE:
        n=f+'_a';v=content(n,512)+content(n+'-unhashed-tail',3584)
        write(data/'targets'/n,v);firmware[n]={'bytes':512,'sha256':digest(v[:512])}
    runtime={}
    for n in RUNTIME:
        v=content(n,128);write(data/'runtime'/n.lstrip('/'),v);runtime[n]={'bytes':len(v),'sha256':digest(v)}
    write(data/'boot-id',b'RI3-COMPILED-REGULAR-FILE-FIXTURE\n')
    cert=(ROOT/'builder/work/installer-ri3-recovery/images-ziptrust/development-zip.x509.pem').read_bytes()
    with zipfile.ZipFile(WORK/'fixture-unsigned.zip','w') as z:
        for n,v in images.items():
            base='super' if n=='super' else n[:-2]
            zip_write(z,'images/'+base+'.img',sparse if n=='super' else v)
        zip_write(z,'META-INF/com/android/otacert',cert)
    def gd(p):return '{'+str(p['bytes'])+',"'+p['sha256']+'"}'
    h=['#pragma once','#ifndef RI3_FILE_FIXTURE_RUNTIME','#error "Fixture trusted data must never enter release compilation"','#endif','#ifdef __ANDROID__','#error "Regular-file fixture is host-only"','#endif','#include "../../guard/guard_policy.h"','namespace ri3::fixture {',
       'inline const char* SuperSha256(){return "'+digest(raw)+'";}',
       'inline guard::PairContract Pair(){return {guard::Status::Known,"RI3_HOST_REGULAR_FILE_FIXTURE_V1","'+digest(b'RI3_HOST_REGULAR_FILE_FIXTURE_V1')+'",'+gd(protected['recovery_a'])+','+gd(pins['vbmeta_a'])+','+gd(runtime[RUNTIME[-1]])+'};}',
       'inline guard::Manifest ManifestFor(const std::string& id,const guard::PairContract& pair){return {id,{']
    h += ['{"'+n+'",'+str(pins[n]['bytes'])+',"'+pins[n]['sha256']+'"},' for n in WRITES]
    h += ['},pair};}','inline const std::map<std::string,guard::Digest>& FirmwarePins(){static const std::map<std::string,guard::Digest> pins={']
    h += ['{"'+n+'",'+gd(p)+'},' for n,p in firmware.items()]
    h += ['};return pins;}','inline std::map<std::string,guard::Digest> RecoveryPins(const guard::PairContract& pair){return {{"recovery_a",pair.recovery_a},']
    h += ['{"'+n+'",'+gd(p)+'},' for n,p in runtime.items()]
    h += ['};}','} // namespace ri3::fixture','']
    (HERE/'fixture_profile.h').write_text('\n'.join(h),encoding='utf-8',newline='\n')
    receipt={'contract':'compile-time host-only regular-file fixture; not physical device evidence','images':pins,'protected':protected,'firmware_prefixes':firmware,'runtime':runtime,'unsigned_zip_sha256':digest((WORK/'fixture-unsigned.zip').read_bytes()),'sparse_bytes':len(sparse),'expanded_super_bytes':len(raw)}
    (WORK/'fixture-contract.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps({'unsigned_zip':str(WORK/'fixture-unsigned.zip'),'sha256':receipt['unsigned_zip_sha256'],'profile':str(HERE/'fixture_profile.h')}))
if __name__=='__main__':main()
