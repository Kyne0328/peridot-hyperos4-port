#!/usr/bin/env python3
"""Static inspection of the approved paired recovery; no recovered code execution."""
from pathlib import Path
import importlib.util,hashlib,json,struct
import capstone
ROOT=Path(__file__).resolve().parents[4]
out=ROOT/"builder/work/installer-ri3-native/snapshot";out.mkdir(exist_ok=True)
spec=importlib.util.spec_from_file_location("pf",ROOT/"tools/installer-ri3/recovery-pair/pair_format.py")
pf=importlib.util.module_from_spec(spec);spec.loader.exec_module(pf)
image=(ROOT/"builder/work/installer-ri3-recovery/images-ziptrust/recovery.img").read_bytes()
assert hashlib.sha256(image).hexdigest()=="8ba7e1e077f31e1a345397fca9842ed1bdf39e69d1003b7bbbcde0830b65e52a"
_,blocks=pf.unpack_boot(image);raw=b"".join(x[1] for x in blocks)
e=next(x for x in pf.cpio_entries(raw) if x["name"]=="system/bin/bootctl")
b=raw[e["offset"]:e["offset"]+e["size"]]
assert hashlib.sha256(b).hexdigest()=="be618f8c9434c66c3a73fd309395bd1456d114afb048d1dd8e1a8c86b7b6a863"
shoff=struct.unpack_from("<Q",b,40)[0];sz,n,sti=struct.unpack_from("<HHH",b,58)
secs=[struct.unpack_from("<IIQQQQIIQQ",b,shoff+i*sz) for i in range(n)]
st=secs[sti];names=b[st[4]:st[4]+st[5]]
named={names[s[0]:].split(b"\0",1)[0].decode():s for s in secs}
syms=[]
for name,s in named.items():
 if s[1] not in (2,11):continue
 st=secs[s[6]];strings=b[st[4]:st[4]+st[5]]
 for off in range(s[4],s[4]+s[5],s[9]):
  nm,info,oth,idx,val,size=struct.unpack_from("<IBBHQQ",b,off)
  syms.append((strings[nm:].split(b"\0",1)[0].decode(),val,size))
md=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN)
s=named[".text"];lines=[f"{i.address:08x}: {i.mnemonic} {i.op_str}" for i in md.disasm(b[s[4]:s[4]+s[5]],s[3])]
(out/"bootctl-full-disassembly.txt").write_text("\n".join(lines))
report={"bootctl_sha256":hashlib.sha256(b).hexdigest(),"symbols":syms,"sections":named,"command_literal_file_offset":b.index(b"get-snapshot-merge-status")}
(out/"bootctl-symbols.json").write_text(json.dumps(report,indent=2))
print(json.dumps({"symbols":[(n,hex(v),s) for n,v,s in syms if any(k in n.lower() for k in ["snapshot","main","exit","endl","flush","put","getversion","status"])],"sections":[(n,hex(s[3]),s[5]) for n,s in named.items() if n in [".text",".plt",".rodata"]],"command_offset":hex(report["command_literal_file_offset"])}))
print("\n".join(lines[:65]))

print("COMMAND_LITERALS",[(hex(i),b[i:i+100].split(b"\0")[0].decode()) for i in [0x1000,0x10aa,0x1044,0x143b,0x1268,0x11b2,0x12a5,0x176d,0x1787,0x1111,0x1421,0x112b,0x1282]])
q=named[".plt"];plines=[f"{i.address:08x}: {i.mnemonic} {i.op_str}" for i in md.disasm(b[q[4]:q[4]+q[5]],q[3])];(out/"bootctl-plt.txt").write_text("\n".join(plines));print("SYMBOL_ORDER",[(i,n) for i,(n,v,z) in enumerate(syms)])
