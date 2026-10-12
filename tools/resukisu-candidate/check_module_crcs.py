#!/usr/bin/env python3
"""Compare preserved module imports against official stock exports; no module loading."""
import hashlib,json,struct
from pathlib import Path
from inspect_baseline import ROOT,require,ramdisk

def imports(b):
    require(b[:6]==b'\x7fELF\x02\x01','Expected ELF64 little-endian module')
    off=struct.unpack_from('<Q',b,40)[0];ent,n,si=struct.unpack_from('<HHH',b,58)
    require(ent==64 and off+n*ent<=len(b) and si<n,'ELF section table bounds')
    sections=[struct.unpack_from('<IIQQQQIIQQ',b,off+i*ent) for i in range(n)]
    sh=sections[si];names=b[sh[4]:sh[4]+sh[5]]
    found=[]
    for s in sections:
        name=names[s[0]:].split(b'\0')[0]
        if name==b'__versions':
            raw=b[s[4]:s[4]+s[5]];require(len(raw)==s[5] and len(raw)%64==0,'Module version bounds')
            for p in range(0,len(raw),64):
                crc=struct.unpack_from('<Q',raw,p)[0];symbol=raw[p+8:p+64].split(b'\0')[0].decode()
                found.append((symbol,crc))
    require(found,'Missing __versions');return found

def main():
    p=ROOT/'00-manifest/resukisu-candidate/kernel_aarch64_Module.symvers';raw=p.read_bytes()
    require(hashlib.sha256(raw).hexdigest()=='56f0b4c1974c39ab33ae4af6d1938b72e30b6a61d3404e0f4f0976f65a803657','Official symbol file mismatch')
    exports={}
    for line in raw.decode().splitlines():
        cells=line.split();require(cells[1] not in exports,'Duplicate export');exports[cells[1]]=int(cells[0],16)
    src=ROOT/'.cache/global-single-recovery-ri2/source-images/images';vb=(src/'vendor_boot.img').read_bytes();size=struct.unpack_from('<I',vb,24)[0]
    synthetic=bytearray(4096);synthetic[:8]=b'ANDROID!';struct.pack_into('<II',synthetic,8,0,size);struct.pack_into('<I',synthetic,40,4)
    _,files=ramdisk(bytes(synthetic)+vb[4096:4096+size])
    rows=[]
    def check(data,name,origin):
        versions=imports(data);known=[(s,c) for s,c in versions if s in exports]
        rows.append({'origin':origin,'path':name,'imports':len(versions),'known_official_exports':len(known),'matching_crcs':sum(exports[s]==c for s,c in known),'mismatches':[{'symbol':s,'module_crc':hex(c),'stock_crc':hex(exports[s])} for s,c in known if exports[s]!=c],'not_in_aosp_exports':[s for s,c in versions if s not in exports]})
    for name,data in files.items():
        if name.endswith('.ko'):check(data,name,'vendor_boot')
    for origin in ['system_dlkm','vendor_dlkm']:
        root=ROOT/'.cache/resukisu-candidate'/(origin+'-extracted')
        for p in sorted(root.rglob('*.ko')):check(p.read_bytes(),p.relative_to(root).as_posix(),origin)
    summary={}
    for origin in ['vendor_boot','system_dlkm','vendor_dlkm']:
        r=[x for x in rows if x['origin']==origin];summary[origin]={'module_instances':len(r),'matched_import_instances':sum(x['matching_crcs'] for x in r),'mismatched_import_instances':sum(len(x['mismatches']) for x in r),'unresolved_vendor_or_other_import_instances':sum(len(x['not_in_aosp_exports']) for x in r)}
    report={'scope':'Preserved baseline only; no rebuilt kernel exists','official_export_count':len(exports),'official_exports_sha256':hashlib.sha256(raw).hexdigest(),'summary':summary,'modules':rows,'all_module_signatures_verified':False,'runtime_compatibility_verified':False,'unresolved_imports_are_not_automatically_defects':True}
    out=ROOT/'09-reports/resukisu-candidate/preflight-v1/module-crc-baseline.json';out.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(summary,indent=2))
if __name__=='__main__':main()
