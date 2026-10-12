#!/usr/bin/env python3
"""Focused static shell arithmetic-width audit. Never executes recovery code."""
from pathlib import Path
import importlib.util,json,re
ROOT=Path(__file__).resolve().parents[2]
sp=importlib.util.spec_from_file_location('audit',ROOT/'tools/install-readiness-guards/audit_recovery_contract.py')
m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m)
b=m.files['system/bin/sh']; e=m.elf(b)
ss=m.strings(b)
interesting=[s for s in ss if re.search(r'zero divisor|arithmetic|division|overflow|MIRBSD|KSH_VERSION|LKSH',s['text'],re.I)]
for s in interesting:
    sec=next((sec for sec in e['sections'] if sec[2]<=s['offset']<sec[2]+sec[3]),None)
    s['vaddr']=s['offset']-sec[2]+sec[1] if sec else None
sec=next(s for s in e['sections'] if s[0]=='.text')
ins=list(m.md.disasm(b[sec[2]:sec[2]+sec[3]],sec[1]))
hitidx=[i for i,x in enumerate(ins) if x.mnemonic in ('sdiv','udiv')]
refs=[]
targets={s['vaddr'] for s in interesting if 'zero divisor' in s['text'].lower()}
for i,x in enumerate(ins):
    if x.mnemonic=='adr' and any(x.op_str.endswith('#'+hex(t)) for t in targets): refs.append(i)
select=set()
for i in hitidx+refs:
    select.update(range(max(0,i-40),min(len(ins),i+45)))
lines=['shell_sha256='+m.rp.sha(b),'ELF_MACHINE_AARCH64=183','Interesting strings:',json.dumps(interesting,indent=2),'Division instructions:']
lines += [f'{ins[i].address:08x}: {ins[i].mnemonic} {ins[i].op_str}' for i in hitidx]
lines += ['Focused contexts:']
for i in sorted(select): lines.append(f'{ins[i].address:08x}: {ins[i].mnemonic} {ins[i].op_str}')
out=ROOT/'09-reports/install-readiness-guards/mksh-arithmetic-disassembly.txt'
out.write_text('\n'.join(lines),encoding='utf8')
print(json.dumps({'report':str(out),'interesting_strings':interesting,'divisions':[f'{ins[i].address:x} {ins[i].mnemonic} {ins[i].op_str}' for i in hitidx],'zero_divisor_refs':[hex(ins[i].address) for i in refs],'lines':len(lines)}))
