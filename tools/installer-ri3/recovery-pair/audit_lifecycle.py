#!/usr/bin/env python3
"""Offline exact-artifact lifecycle audit. No supplied executables are run."""
import ast, hashlib, json, pathlib, re, runpy, zipfile, lzma
ROOT=pathlib.Path.cwd()
OUT=ROOT/'09-reports/installer-ri3/recovery-pair'
OUT.mkdir(parents=True,exist_ok=True)
source=ROOT/'tools/install-readiness-launcher/audit_launcher.py'
tree=ast.parse(source.read_text(encoding='utf-8-sig'))
# Reuse read-only ELF helpers without executing their report-producing main body.
nodes=[n for n in tree.body if isinstance(n,(ast.Import,ast.ImportFrom,ast.FunctionDef))]
env={}
exec(compile(ast.Module(body=nodes,type_ignores=[]),str(source),'exec'),env)
env['rx']=re.compile('Fox_Post_Zip_Install|IsRecoveryOverwritten|Deactivation_Process|RunFoxScript|Flash_Current_Twrp|Fox_Skip_OTA|Get_Partition_Checksums|CommandLine|Parse_Command|Run_CLI|GetVar|GetVariable|MIUI_ROM_SetProperty')
env['sha_rx']=re.compile('FindEntry|execve|mmap|fstat|lseek|open|write|read|ioctl')
archive=ROOT/'OrangeFox-R12.0_202610011528_crypto-Unofficial-peridot.zip'
ah=hashlib.file_digest(archive.open('rb'),'sha256').hexdigest()
assert ah=='b04ec7c0add35457fe7f53e308acf23cdf0a62d8d4ed05f1392ac23e6cbb5cf4'
with zipfile.ZipFile(archive) as z: image=z.read('recovery.img')
module=runpy.run_path(str(ROOT/'tools/local-recovery/inspect_recovery.py'))
header,files=module['ramdisk'](image)
b=files['system/bin/recovery']
report=env['analyze'](b)
e,secs,names=env['sections'](b)
report['resolved_literals']={}
for f in report['functions'].values():
 regs={}
 for line in f['disassembly']:
  m=re.search(r'adrp (x\d+), #(0x[0-9a-f]+)',line)
  if m: regs[m[1]]=int(m[2],16)
  m=re.search(r'add (x\d+), (x\d+), #(0x[0-9a-f]+|[0-9]+)$',line)
  if m and m[2] in regs:
   a=regs[m[2]]+int(m[3],0)
   for s in secs:
    if s[1]!=8 and s[3]<=a<s[3]+s[5]:
     p=s[4]+a-s[3];text=env['cstr'](b,p)
     if text and len(text)<500 and all(31<ord(c)<127 or c in '\n\t' for c in text):report['resolved_literals'][hex(a)]=text
report['source_archive_sha256']=ah
report['image_sha256']=hashlib.sha256(image).hexdigest()
report['image_size']=len(image)
report['scripts']={n:{'sha256':hashlib.sha256(p).hexdigest(),'text':p.decode('utf-8','replace')} for n,p in files.items() if n.endswith('.sh') and (b'rom_flash' in n.encode() or b'getvar' in p.lower() or b'get ' in p and 'twrp' in n.lower())}
report['available_cli_paths']=[n for n in files if n.endswith('/twrp') or 'orangefox' in n.lower()]
report['extra_paths']={n:{'sha256':hashlib.sha256(files[n]).hexdigest(),'size':len(files[n]),'text':files[n].decode('utf-8','replace') if len(files[n])<5000 else None} for n in ['system/bin/sha256sum','sbin/afterromflash.sh','system/etc/twrp.flags','vendor/etc/twrp.flags'] if n in files}
# Exact direct-call cross references, annotated with containing debug function.
allsyms,_=env['symbols'](b)
s=names['.gnu_debugdata'];dbg,_=env['symbols'](lzma.decompress(b[s[4]:s[4]+s[5]]));allsyms+=dbg
funcs=[s for s in allsyms if s['defined'] and s['size']]
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
import struct
report['checksum_call_sites']=[]
for sec in secs:
 if not sec[2]&4:continue
 for p in range(sec[4],sec[4]+sec[5]-3,4):
  w=struct.unpack_from('<I',b,p)[0]
  if w>>26 != 0b100101:continue
  imm=w&0x3ffffff;imm=imm-(1<<26) if imm&(1<<25) else imm
  addr=sec[3]+p-sec[4]
  if addr+imm*4!=0x1d0af0:continue
  owner=next((s['name'] for s in funcs if s['value']<=addr<s['value']+s['size']),None)
  lines=[f'{i.address:#x}: {i.mnemonic} {i.op_str}' for i in Cs(CS_ARCH_ARM64,CS_MODE_ARM).disasm(b[p-48:p+12],addr-48)]
  report['checksum_call_sites'].append({'address':hex(addr),'owner':owner,'context':lines})
report['tool_hashes']={n:hashlib.sha256(files[n]).hexdigest() for n in report['available_cli_paths']}
report['untrusted_code_executed']=False
(OUT/'lifecycle-evidence.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({k:report[k] for k in ['sha256','image_size','image_sha256','available_cli_paths','tool_hashes','resolved_literals']},indent=2))
print('FUNCTIONS',[(k,v['address'],v['size']) for k,v in report['functions'].items()])
