#!/usr/bin/env python3
"""Static RI2 / OrangeFox contract audit; never executes supplied binaries."""
from pathlib import Path
import hashlib, importlib.util, json, re, struct, zipfile
import capstone
ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/'09-reports/install-readiness-guards'
OUT.mkdir(parents=True,exist_ok=True)
spec=importlib.util.spec_from_file_location('recovery_parser',ROOT/'tools/local-recovery/inspect_recovery.py')
rp=importlib.util.module_from_spec(spec); spec.loader.exec_module(rp)
fox=ROOT/'OrangeFox-R12.0_202610011528_crypto-Unofficial-peridot.zip'
with fox.open('rb') as f: fox_hash=hashlib.file_digest(f,'sha256').hexdigest()
with zipfile.ZipFile(fox) as z: recovery=z.read('recovery.img')
head,files=rp.ramdisk(recovery)
with zipfile.ZipFile(ROOT/'F6-Global-HyperOS4-DEV2-RI2.zip') as z:
    installer=z.read('META-INF/com/google/android/update-binary')
def strings(b):
    return [{'offset':m.start(),'text':m.group().decode('ascii')} for m in re.finditer(rb'[\x20-\x7e]{4,}',b)]
def elf(b):
    if not b.startswith(b'\x7fELF'): return None
    assert b[4:6]==b'\x02\x01'
    shoff=struct.unpack_from('<Q',b,40)[0]
    ents,n,sti=struct.unpack_from('<HHH',b,58)
    secs=[struct.unpack_from('<IIQQQQIIQQ',b,shoff+i*ents) for i in range(n)]
    sb=secs[sti]; names=b[sb[4]:sb[4]+sb[5]]
    secnames=[names[s[0]:].split(b'\0',1)[0].decode() for s in secs]
    symbols=[]
    for i,s in enumerate(secs):
        if s[1] not in (2,11): continue
        st=secs[s[6]]; stdata=b[st[4]:st[4]+st[5]]
        for off in range(s[4],s[4]+s[5],s[9]):
            nm,info,oth,idx,val,size=struct.unpack_from('<IBBHQQ',b,off)
            name=stdata[nm:].split(b'\0',1)[0].decode('utf8','replace')
            if name: symbols.append({'name':name,'info':info,'index':idx,'address':val,'size':size})
    needed=[]
    if '.dynamic' in secnames:
        ds=secs[secnames.index('.dynamic')]; st=secs[ds[6]]; stdata=b[st[4]:st[4]+st[5]]
        for off in range(ds[4],ds[4]+ds[5],16):
            tag,val=struct.unpack_from('<qQ',b,off)
            if tag==1: needed.append(stdata[val:].split(b'\0',1)[0].decode())
    return {'machine':struct.unpack_from('<H',b,18)[0],'sections':[(nm,s[3],s[4],s[5]) for nm,s in zip(secnames,secs)],'needed':needed,'symbols':symbols}
wanted=['sbin/busybox','system/bin/toybox','system/bin/bootctl','system/bin/sh','sbin/sh','sbin/bash','system/bin/getprop','system/lib64/libboot_control_client.so','vendor/bin/hw/android.hardware.boot-service.qti.recovery','vendor/lib64/libboot_control_qti.so']
report={'method':'Static archive/CPIO/ELF inspection; supplied binaries were not executed','recovery_archive_sha256':fox_hash,'recovery_image_sha256':rp.sha(recovery),'recovery_header':head,'installer_sha256':rp.sha(installer),'tools':{},'configs':{},'init_matches':{},'recovery_setting_strings':[]}
for p in wanted:
    b=files.get(p)
    if b is None: report['tools'][p]={'present':False}; continue
    e=elf(b)
    entry={'present':True,'size':len(b),'sha256':rp.sha(b),'elf_machine':e['machine'] if e else None,'needed':e['needed'] if e else [],'alias_payload':b.decode('utf8','replace') if len(b)<100 else None}
    allstrings=strings(b)
    needles=('get-active-boot-slot','get-snapshot-merge-status','none','snapshotted','merging','cancelled','unknown','pipefail','MIRBSD','KSH','BusyBox v','busybox 1.','%t','%T','stat_main','df_main','getActiveBootSlot','getSnapshotMergeStatus','GetActiveBootSlot','GetSnapshotMergeStatus','WaitForService','ash','Filesystem')
    entry['selected_strings']=[s for s in allstrings if any(k in s['text'] for k in needles)]
    if e:
        entry['relevant_symbols']=[s for s in e['symbols'] if any(k in s['name'] for k in ('MergeStatus','ActiveBootSlot','GetVersion','main','WaitForService'))]
    report['tools'][p]=entry
for p,b in files.items():
    if 'fstab' in p or p in ('system/etc/fox.cfg','system/etc/twrp.flags','vendor/etc/vintf/manifest/boot-service.qti.xml') or ('boot' in p and p.endswith('.rc')):
        report['configs'][p]={'sha256':rp.sha(b),'text':b.decode('utf8','replace')}
    if p.endswith(('.rc','.sh')) and len(b)<200000:
        ls=b.decode('utf8','replace').splitlines()
        hits=set()
        for i,line in enumerate(ls):
            if re.search(r'boot-hal|early_hal|/metadata|mount_all|foxstart|vendor_dlkm|system_dlkm|skip.*patch|patch.*(boot|vbmeta)|dm-|/tmp|tmpfs',line,re.I):
                hits.update(range(max(0,i-1),min(len(ls),i+2)))
        if hits: report['init_matches'][p]=[{'line':i+1,'text':ls[i]} for i in sorted(hits)]
rb=files['system/bin/recovery']
report['recovery_setting_strings']=[s for s in strings(rb) if re.search(r'(skip.*(patch|process)|disable.*(verity|encrypt)|reflash|mount.*(system|vendor)|unmount.*(system|vendor)|boot-hal)',s['text'],re.I)]
dis=[]
md=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN)
for p in ('system/bin/bootctl','system/lib64/libboot_control_client.so'):
    b=files[p]; e=elf(b)
    for sym in e['symbols']:
        if not sym['size'] or not sym['index']: continue
        if not (sym['name']=='main' or 'MergeStatus' in sym['name'] or 'GetActiveBootSlot' in sym['name']): continue
        sec=next((s for s in e['sections'] if s[1]<=sym['address']<s[1]+s[3]),None)
        if sec is None: continue
        off=sec[2]+sym['address']-sec[1]; size=min(sym['size'],12000)
        dis.append('\n'+p+' '+sym['name']+' address='+hex(sym['address'])+' size='+str(sym['size']))
        dis.extend(f'{i.address:08x}: {i.mnemonic} {i.op_str}' for i in md.disasm(b[off:off+size],sym['address']))
    dis.append('\n'+p+' relevant literal file offsets')
    dis.extend(hex(s['offset'])+' '+s['text'] for s in strings(b) if s['text'] in ('none','NONE','snapshotted','merging','cancelled','unknown'))
(OUT/'static-recovery-contract.json').write_text(json.dumps(report,indent=2),encoding='utf8')
(OUT/'bootctl-disassembly.txt').write_text('\n'.join(dis),encoding='utf8')
(OUT/'packaged-update-binary.txt').write_text(installer.decode(),encoding='utf8')
print(json.dumps({'report':str(OUT/'static-recovery-contract.json'),'disassembly':str(OUT/'bootctl-disassembly.txt'),'recovery_sha256':fox_hash,'installer_sha256':rp.sha(installer),'tool_hashes':{p:it.get('sha256') for p,it in report['tools'].items()},'disassembly_lines':len(dis)}))
