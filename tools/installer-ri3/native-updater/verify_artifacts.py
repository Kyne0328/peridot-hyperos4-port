#!/usr/bin/env python3
"""Inspect newly built ELF files without running them and compare independent build outputs."""
import hashlib,json,os,pathlib,struct,subprocess
ROOT=pathlib.Path(__file__).resolve().parents[3]
WORK=ROOT/"builder/work/installer-ri3-native"
a=WORK/"build-android/prep-update-binary"
b=WORK/"build-android-repro/prep-update-binary"
data=a.read_bytes()
digest=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert data[:6]==b"\x7fELF\x02\x01","Expected little-endian ELF64"
header=struct.unpack_from("<HHIQQQIHHHHHH",data,16)
etype,machine=header[0],header[1]
phoff,phsize,phcount=header[4],header[8],header[9]
assert machine==183,"Not AArch64"
assert etype in (2,3),"Not an executable ELF"
assert phsize==56
segments=[struct.unpack_from("<IIQQQQQQ",data,phoff+i*phsize) for i in range(phcount)]
assert all(s[0]!=3 for s in segments),"Interpreter dependency"
assert all(not(s[0]==1 and s[1]&1 and s[1]&2) for s in segments),"Writable executable load segment"
stack=[s for s in segments if s[0]==0x6474e551]
assert len(stack)==1 and stack[0][1]&1==0,"Executable or missing stack policy"
ndk=pathlib.Path(os.environ["LOCALAPPDATA"])/"Android/Sdk/ndk/28.2.13676358"
readelf=ndk/"toolchains/llvm/prebuilt/windows-x86_64/bin/llvm-readelf.exe"
env=os.environ.copy();env.update({x:str(WORK/"tmp") for x in ["TMPDIR","TEMP","TMP"]})
def run(*args):
    p=subprocess.run([str(readelf),*args,str(a)],check=True,capture_output=True,text=True,env=env)
    return p.stdout
details=run("-h","-l","-d")
assert "(NEEDED)" not in details,"Dynamic shared-library requirement"
symbols=run("--symbols")
assert "ParseString" in symbols and "unzOpen2_64" in symbols and " inflate" in symbols,"Missing compiled core symbols"
assert b"--test-recovery" not in data and b"--read-entry" not in data,"Host-only entrypoints leaked"
assert b"--verify-package" in data and b"--verify-entry" in data,"Read-only core entrypoints missing"
assert digest(a)==digest(b),"Independent AArch64 builds differ"
receipt={"status":"passed","installation_enabled":False,"architecture":"AArch64","elf_bits":64,
         "elf_type":etype,"has_interpreter":False,"needed_libraries":[],"non_executable_stack":True,
         "writable_executable_segments":False,"edify_zip_zlib_symbols_present":True,
         "host_entrypoints_present":False,"independent_build_hashes_match":True,
         "binary_bytes":len(data),"binary_sha256":digest(a),
         "builds":[str(a),str(b)],"aarch64_binary_executed":False}
(WORK/"elf-inspection.txt").write_text(details)
(WORK/"verification-receipt.json").write_text(json.dumps(receipt,indent=2)+"\n")
print(json.dumps(receipt))
