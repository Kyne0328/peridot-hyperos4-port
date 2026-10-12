"""Static paired recovery logical/AVB mapping call inventory. No recovered code execution."""
import io,json,pathlib,sys,hashlib
sys.path.insert(0,'tools/installer-ri3/recovery-pair')
import pair_format
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
p=pathlib.Path('builder/work/installer-ri3-recovery/images-ziptrust/recovery.img')
blob=p.read_bytes()
assert hashlib.sha256(blob).hexdigest()=='8ba7e1e077f31e1a345397fca9842ed1bdf39e69d1003b7bbbcde0830b65e52a'
header,blocks=pair_format.unpack_boot(blob)
raw=b''.join(decoded for compressed,decoded in blocks)
entries=pair_format.cpio_entries(raw)
e=next(x for x in entries if x['name']=='system/bin/recovery')
binary=raw[e['offset']:e['offset']+e['size']]
assert hashlib.sha256(binary).hexdigest()=='b9416f70f6403ffe6cadc51626515f49f66a9961bbb7ef14898fdd9173c44a49'
elf=ELFFile(io.BytesIO(binary))
symbols={}
functions=[]
for section in elf.iter_sections():
    if section.header['sh_type'] not in ('SHT_SYMTAB','SHT_DYNSYM'): continue
    for sym in section.iter_symbols():
        a=int(sym['st_value']); n=int(sym['st_size'])
        if a and sym.name: symbols.setdefault(a,sym.name)
        if a and n and sym['st_info']['type']=='STT_FUNC': functions.append((a,n,sym.name))
plt=elf.get_section_by_name('.plt'); reloc=elf.get_section_by_name('.rela.plt')
if plt and reloc:
    dyn=elf.get_section(reloc['sh_link'])
    for i,rel in enumerate(reloc.iter_relocations()):
        symbols[int(plt['sh_addr'])+32+16*i]=dyn.get_symbol(rel['r_info_sym']).name+'@plt'
def data_at(a,n):
    for seg in elf.iter_segments():
        if seg['p_type']=='PT_LOAD' and int(seg['p_vaddr'])<=a and a+n<=int(seg['p_vaddr'])+int(seg['p_filesz']):
            off=int(seg['p_offset'])+a-int(seg['p_vaddr']);return binary[off:off+n]
    raise ValueError('function outside file segments')
selected=[]
for a,n,name in sorted(set(functions)):
    low=name.lower()
    if any(x in low for x in ('verity','avb','logical')) or ('TWPartition' in name and any(x in name for x in ('Mount','mount','Map','Setup'))):
        selected.append((a,n,name))
md=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
reports=[]
for a,n,name in selected:
    if n>100000: continue
    calls=[]; lines=[]
    for ins in md.disasm(data_at(a,n),a):
        if ins.mnemonic=='bl':
            try: dest=int(ins.op_str.lstrip('#'),0)
            except ValueError: dest=None
            calls.append({'address':hex(ins.address),'target':symbols.get(dest,hex(dest) if dest else ins.op_str)})
        if ins.mnemonic in ('bl','blr','br','ret'):
            lines.append(hex(ins.address)+': '+ins.mnemonic+' '+ins.op_str)
    reports.append({'address':hex(a),'bytes':n,'name':name,'calls':calls,'control_calls':lines})
out=pathlib.Path('09-reports/installer-ri3/map-audit');out.mkdir(parents=True,exist_ok=True)
receipt={'recovery_image_sha256':hashlib.sha256(blob).hexdigest(),'recovery_elf_sha256':hashlib.sha256(binary).hexdigest(),'method':'static ELF symbol and AArch64 direct-call inventory; indirect/runtime paths not proven','selected_count':len(selected),'functions':reports}
(out/'paired-recovery-map-calls.json').write_text(json.dumps(receipt,indent=2))
print('SELECTED',len(selected))
for a,n,name in selected:
    if 'TWPartition' in name or any(x in name for x in ('CreateLogicalPartitions','SetUpAvbHashtree','SetupVerity','FirstStageMount')):
        print(hex(a),n,name)
        r=next((r for r in reports if r['address']==hex(a) and r['name']==name),None)
        if r:
            for c in r['calls']: print(' ',c['address'],c['target'])
