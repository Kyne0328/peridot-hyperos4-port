import sys,pathlib,json,re,hashlib,argparse
sys.path.insert(0,str(pathlib.Path(__file__).parent/'python-tools'))
from elftools.elf.elffile import ELFFile
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_INS_ADRP,ARM64_INS_ADR,ARM64_INS_ADD,ARM64_OP_IMM,ARM64_OP_REG
parser=argparse.ArgumentParser(description="Read-only AArch64 init string/load-path evidence for the locked Global donor")
parser.add_argument("--init", default="/workspace/shared/peridot-global-builder/review-properties/consumer-files/system/system/bin/init")
parser.add_argument("--out-dir", default="/workspace/shared/peridot-global-builder/review-properties")
args=parser.parse_args()
root=pathlib.Path(args.out_dir).resolve();root.mkdir(parents=True,exist_ok=True)
p=pathlib.Path(args.init).resolve()
if p.stat().st_size!=2888936 or hashlib.sha256(p.read_bytes()).hexdigest()!="9bb24ead728c13c50a5c734e6b3f951c83c7a81d86e2f973b1a1bd4fa9cab020":
 raise ValueError("Init input differs from the reviewed Global donor")
with p.open('rb') as f:
 elf=ELFFile(f);text=elf.get_section_by_name('.text');ro=elf.get_section_by_name('.rodata');syms=elf.get_section_by_name('.dynsym');plt=elf.get_section_by_name('.plt');rel=elf.get_section_by_name('.rela.plt')
 symbols={s['st_value']:s.name for s in syms.iter_symbols() if s['st_value']}
 if plt and rel:
  got={r['r_offset']:syms.get_symbol(r['r_info_sym']).name for r in rel.iter_relocations()}
  decoder=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);decoder.detail=True
  pcode=plt.data();paddr=plt['sh_addr']
  for off in range(0,len(pcode),4):
   state={}
   for op in decoder.disasm(pcode[off:off+32],paddr+off):
    if op.mnemonic=='adrp':state[op.operands[0].reg]=op.operands[1].imm
    if op.mnemonic=='ldr' and len(op.operands)==2 and op.operands[1].type==3:
     mem=op.operands[1].mem
     addr=state.get(mem.base,0)+mem.disp
     if addr in got:symbols[paddr+off]=got[addr]+'@plt';break
    if op.mnemonic in ['br','ret']:break
 strings={}
 data=ro.data();base=ro['sh_addr']
 for m in re.finditer(rb'[\x20-\x7e]{5,}',data):
  value=m.group().decode()
  if any(x in value for x in ['mi_product','/mnt/vendor/mi_ext','/vendor/build.prop','/system/build.prop','/product','/odm','failed to mount','Failed to mount']):strings[base+m.start()]=value
 md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);md.detail=True;ins=list(md.disasm(text.data(),text['sh_addr']));regs={};xrefs=[]
 for i,x in enumerate(ins):
  o=x.operands
  if x.id==ARM64_INS_ADRP:regs[o[0].reg]=(o[1].imm,i)
  elif x.id==ARM64_INS_ADR:
   regs[o[0].reg]=(o[1].imm,i)
   if o[1].imm in strings:xrefs.append((i,o[1].imm))
  elif x.id==ARM64_INS_ADD and len(o)==3 and o[1].type==ARM64_OP_REG and o[2].type==ARM64_OP_IMM and o[1].reg in regs:
   addr,j=regs[o[1].reg]
   if i-j<16:
    result=addr+o[2].imm
    regs[o[0].reg]=(result,i)
    if result in strings:xrefs.append((i,result))
 lines=[]
 for i,target in xrefs:
  if 'mi_product' not in strings[target] and 'build.prop' not in strings[target]:continue
  lines.append('\nREFERENCE '+hex(ins[i].address)+' -> '+hex(target)+' '+strings[target])
  for x in ins[max(0,i-30):min(len(ins),i+36)]:
   extra=''
   if x.mnemonic in ['bl','b'] and x.operands[0].type==ARM64_OP_IMM:extra=symbols.get(x.operands[0].imm,'')
   lines.append(f'{x.address:08x}: {x.mnemonic:8} {x.op_str:40} {extra}')
 (root/'init-xrefs.txt').write_text('\n'.join(lines)+'\n');(root/'init-string-refs.json').write_text(json.dumps([{'address':hex(ins[i].address),'target':hex(t),'string':strings[t]} for i,t in xrefs],indent=2));print('instructions',len(ins),'refs',len(xrefs));print('\n'.join(l for l in lines if l.startswith('\nREFERENCE')))
