#!/usr/bin/env python3
"""Read-only binary/ZIP launch audit; never executes supplied images or installer."""
import pathlib,zipfile,runpy,struct,re,json,hashlib,lzma
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
ROOT=pathlib.Path.cwd()
OUT=ROOT/'09-reports/install-readiness-launcher'
OUT.mkdir(parents=True,exist_ok=True)
def sha(b):return hashlib.sha256(b).hexdigest()
def cstr(b,o):
 end=b.find(b'\0',o)
 return b[o:end if end>=0 else len(b)].decode('utf-8','replace')
def sections(b):
 e=struct.unpack_from('<16sHHIQQQIHHHHHH',b)
 assert e[0][:6]==b'\x7fELF\x02\x01'
 ss=[struct.unpack_from('<IIQQQQIIQQ',b,e[6]+i*e[11]) for i in range(e[12])]
 st=ss[e[13]];ns=b[st[4]:st[4]+st[5]]
 return e,ss,{cstr(ns,s[0]):s for s in ss}
def symbols(b):
 e,ss,names=sections(b);syms=[];needs=[]
 for s in ss:
  if s[1] in (2,11):
   st=ss[s[6]];strings=b[st[4]:st[4]+st[5]]
   for p in range(s[4],s[4]+s[5],s[9]):
    n,info,other,shndx,value,size=struct.unpack_from('<IBBHQQ',b,p)
    syms.append(dict(name=cstr(strings,n),defined=shndx!=0,value=value,size=size))
  if s[1]==6:
   st=ss[s[6]];strings=b[st[4]:st[4]+st[5]]
   for p in range(s[4],s[4]+s[5],s[9]):
    tag,val=struct.unpack_from('<qQ',b,p)
    if tag==1:needs.append(cstr(strings,val))
 return syms,needs
rx=re.compile('TWinstall_zip|Prepare_Update_Binary|Run_Update_Binary|update_binary_command|Installing_ROM_Query|find_in_zip_installer|GetZipArchiveHandle|CreateMemoryPackage|MapFile|MapCentralDirectory|FindCentralDirectoryInfo|ParseZip64|OpenArchiveInternal|Check_OrangeFox_Overwrite_FromROM|IsRecoveryOverwritten|Fox_Skip_OTA|RunFoxScript|Fox_Post_Zip_Install|Deactivation_Process|Patch_AVB20|Disable_AVB2|Flash_Current_Twrp')
sha_rx=re.compile('FindEntry|ExtractEntryToFile|OpenArchive|execve|mmap|fstat|lseek')
def analyze(b):
 e,ss,ns=sections(b);dyn,needs=symbols(b);allsyms=dyn[:]
 if '.gnu_debugdata' in ns:
  s=ns['.gnu_debugdata'];db=lzma.decompress(b[s[4]:s[4]+s[5]])
  dbg,_=symbols(db);allsyms+=dbg
 funcs={s['value']:s for s in allsyms if s['defined'] and s['value']}
 byaddr={}
 for x in allsyms:
  if x['defined'] and x['value']:
   v=x['value'];n=x['name']
   if v not in byaddr:byaddr[v]=n
   elif n not in byaddr[v].split(' | '):byaddr[v]+=' | '+n
 # Resolve PLT through GOT relocation addresses, not assumed stub widths.
 reloc={}
 if '.rela.plt' in ns and '.dynsym' in ns:
  sec=ns['.dynsym'];st=ss[sec[6]];strings=b[st[4]:st[4]+st[5]];dy=[]
  for p in range(sec[4],sec[4]+sec[5],sec[9]):
   vals=struct.unpack_from('<IBBHQQ',b,p);dy.append(cstr(strings,vals[0]))
  sec=ns['.rela.plt']
  for p in range(sec[4],sec[4]+sec[5],sec[9]):
   off,info,add=struct.unpack_from('<QQq',b,p);reloc[off]=dy[info>>32]
 if '.plt' in ns:
  sec=ns['.plt'];last=None;regs={};start=sec[3]
  for ins in Cs(CS_ARCH_ARM64,CS_MODE_ARM).disasm(b[sec[4]:sec[4]+sec[5]],sec[3]):
   if ins.mnemonic=='bti':start=ins.address
   if ins.mnemonic=='adrp':
    reg,imm=ins.op_str.split(', ');regs[reg]=int(imm[1:],16)
    if not last or last.mnemonic!='bti':start=ins.address
   if ins.mnemonic=='ldr':
    mt=re.match(r'(x\d+), \[(x\d+)(?:, #(0x[0-9a-f]+|[0-9]+))?\]',ins.op_str)
    if mt and mt[2] in regs:
     got=regs[mt[2]]+int(mt[3] or '0',0)
     if got in reloc:byaddr[start]=reloc[got]+'@plt'
   last=ins
 def at(addr,size):
  for s in ss:
   if s[1]!=8 and s[3]<=addr<s[3]+s[5]:return b[s[4]+addr-s[3]:s[4]+addr-s[3]+size]
  return b''
 cs=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
 traces={};selected=[]
 for v,s in funcs.items():
  if rx.search(s['name']) and s['size']:
   selected.append(s);lines=[];calls=[]
   for i in cs.disasm(at(v,s['size']),v):
    line=f'{i.address:#x}: {i.mnemonic} {i.op_str}'
    if i.mnemonic in ('bl','b') and i.op_str.startswith('#'):
     dest=int(i.op_str[1:],16);target=byaddr.get(dest)
     if target:line+=' ; '+target;calls.append(dict(address=i.address,target=target))
    lines.append(line)
   traces[s['name']]={'address':v,'size':s['size'],'calls':calls,'disassembly':lines}
 literals=[]
 for mt in re.finditer(rb'[ -~]{5,}',b):
  txt=mt[0].decode('utf-8','replace')
  if re.search('post_rom|pre_rom|after_rom|fox_backup|found_non_standard|fox_zip|zip_installer|auto_reflash|Non-standard|update-binary',txt):
   for sec in ss:
    if sec[1]!=8 and sec[4]<=mt.start()<sec[4]+sec[5]:
     literals.append(dict(address=sec[3]+mt.start()-sec[4],text=txt));break
 strings=[s.decode('utf-8','replace') for s in re.findall(rb'[ -~]{5,}',b)]
 return dict(literal_strings=literals,sha256=sha(b),size=len(b),elf_class=64,machine=e[2],needed=needs,
  relevant_dynamic_symbols=[s for s in dyn if sha_rx.search(s['name'])],
  selected_debug_symbols=selected,strings=[s for s in strings if re.search('zip64|KSH_VERSION|pipefail|R12.0|Non-standard vAB|found_non_standard',s)],
  functions=traces)
p=ROOT/'OrangeFox-R12.0_202610011528_crypto-Unofficial-peridot.zip'
with p.open('rb') as f: ah=hashlib.file_digest(f,'sha256').hexdigest()
assert ah=='b04ec7c0add35457fe7f53e308acf23cdf0a62d8d4ed05f1392ac23e6cbb5cf4'
m=runpy.run_path(str(ROOT/'tools/local-recovery/inspect_recovery.py'))
with zipfile.ZipFile(p) as z:image=z.read('recovery.img')
h,files=m['ramdisk'](image)
report={'recovery_archive_sha256':ah,'recovery_image_sha256':sha(image),'ramdisk':h,'untrusted_code_executed':False,
 'properties':[x for x in files['prop.default'].decode().splitlines() if re.search('ro.build.(fox|version.sdk)|fox_16',x)],'binaries':{}}
for name in ['system/bin/recovery','system/lib64/libziparchive.so','system/lib64/libaosprecovery.so','system/bin/sh']:
 report['binaries'][name]=analyze(files[name])
 print(name,[(s['name'],s['value'],s['size']) for s in report['binaries'][name]['selected_debug_symbols']])
with zipfile.ZipFile(ROOT/'F6-Global-HyperOS4-DEV2-RI2.zip') as z:
 entries=z.infolist();update=z.read('META-INF/com/google/android/update-binary');dummy=z.read('META-INF/com/google/android/updater-script')
 report['rom']={'size':(ROOT/'F6-Global-HyperOS4-DEV2-RI2.zip').stat().st_size,'entries':[dict(name=e.filename,size=e.file_size,header_offset=e.header_offset,compression=e.compress_type,flags=e.flag_bits,extra_hex=e.extra.hex()) for e in entries],
  'update_binary':dict(size=len(update),sha256=sha(update),shebang=update.splitlines()[0].decode(),crlf=b'\r\n' in update),
  'updater_script':dummy.decode()}
(OUT/'launcher-binary-evidence.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
print('SAVED',OUT/'launcher-binary-evidence.json')
