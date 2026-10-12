#!/usr/bin/env python3
"""Pinned-source offline RI3 signature build. No package install, device access, or key read."""
import argparse, concurrent.futures, datetime, hashlib, json, os, pathlib, subprocess, sys, time
ROOT=pathlib.Path(__file__).resolve().parents[4]
HERE=ROOT/"tools/installer-ri3/native-updater/crypto"
WORK=ROOT/"builder/work/installer-ri3-native/crypto"
VENDOR=ROOT/"builder/work/installer-ri3-native/production-vendor/mbedtls-3.6.7"
SIGNER=ROOT/"tools/installer-ri3/zip-signing/native"
C_NAMES=["bignum.c","bignum_core.c","bignum_mod.c","bignum_mod_raw.c",
         "constant_time.c","md.c","oid.c","platform_util.c",
         "rsa.c","rsa_alt_helpers.c","sha256.c"]
def c_sources(): return [VENDOR/"library"/n for n in C_NAMES]
def includes(): return [HERE,VENDOR/"include",VENDOR/"library",SIGNER]
def definitions(): return ['-DMBEDTLS_CONFIG_FILE="ri3_mbedtls_config.h"','-D_FILE_OFFSET_BITS=64','-D_LARGEFILE64_SOURCE=1','-D_POSIX_C_SOURCE=200809L']
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def run(args,env,timeout=28):
    t=time.monotonic()
    p=subprocess.run([str(a) for a in args],cwd=ROOT,env=env,capture_output=True,text=True,timeout=timeout)
    result={"argv":[str(a) for a in args],"exit_code":p.returncode,"seconds":round(time.monotonic()-t,3),"stdout":p.stdout,"stderr":p.stderr}
    if p.returncode: print(json.dumps(result),flush=True); raise RuntimeError("Compiler/test rejected command")
    return result
def validate_inputs():
    lock=json.loads((ROOT/"tools/installer-ri3/native-updater/production-sources.lock.json").read_text())
    m=lock.get("mbedtls")
    if not m or m["archive_sha256"]!="a7e8bcbec0e6f761b4af24f25677626b35f762f68eef79c08677a363212d11f6" or "crypto" not in lock.get("completed_parts",[]): raise RuntimeError("Mbed TLS source acquisition incomplete")
    for f in m["files"]:
        p=VENDOR.parent/f["path"]
        if not p.is_file() or sha(p)!=f["sha256"]: raise RuntimeError("Pinned Mbed TLS source drift: "+str(p))
    contract=ROOT/"09-reports/installer-ri3/recovery-pair/FROZEN-CONTRACT.json"
    if sha(contract)!="76b6b839b320fd4796808fe9fa7ab4c03cc4e81bbd275a7617f26a80930515c0": raise RuntimeError("Frozen recovery contract changed")
    pk=SIGNER/"public-key.json"
    if sha(pk)!="4717df469d5a3c741d0517f9391f21589936ea94ac4d7d1366304e0955a2635e": raise RuntimeError("Pinned public key record changed")
    return {"mbedtls_archive_sha256":m["archive_sha256"],"mbedtls_files_verified":len(m["files"]),
            "frozen_contract_sha256":sha(contract),"public_key_json_sha256":sha(pk)}
def main():
    ap=argparse.ArgumentParser();ap.add_argument("--target",choices=["host","android"],required=True);ap.add_argument("--label",required=True);ap.add_argument("--sanitize",action="store_true");ap.add_argument("--group",type=int,choices=[0,1,2,3]);a=ap.parse_args()
    if any(x not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for x in a.label): raise RuntimeError("Invalid label")
    out=WORK/(a.label+"-"+a.target);out.mkdir(parents=True,exist_ok=(a.group is not None and a.group>0))
    env=os.environ.copy()
    for n in ["tmp","home","cache"]: (out/n).mkdir(exist_ok=True)
    env.update({"HOME":str(out/"home"),"TMPDIR":str(out/"tmp"),"TMP":str(out/"tmp"),"TEMP":str(out/"tmp"),"XDG_CACHE_HOME":str(out/"cache")})
    provenance=validate_inputs()
    if a.target=="host":
        cc="/usr/bin/clang";cxx="/usr/bin/clang++";target=[]
        if os.name=="nt": raise RuntimeError("Host target runs in WSL")
    else:
        bindir=pathlib.Path(os.environ["ANDROID_NDK_HOME"]) / "toolchains/llvm/prebuilt/windows-x86_64/bin"
        cc=bindir/"clang.exe";cxx=bindir/"clang++.exe";target=["--target=aarch64-linux-android30"]
    flags=target+["-O2","-fvisibility=hidden","-ffunction-sections","-fdata-sections"]+definitions()+["-I"+str(p) for p in includes()]
    if a.sanitize:
        if a.target!="host": raise RuntimeError("Sanitizer applies to host tests")
        flags+=["-fsanitize=address,undefined","-fno-omit-frame-pointer","-g"]
    sources=c_sources()+[HERE/"native_zip_crypto.cpp",SIGNER/"zip_verify_adapter.cpp",SIGNER/"asn1_decoder.cpp",HERE/"test_crypto.cpp"]
    def compile_one(p):
        obj=out/(p.stem+".o"); compiler=cc if p.suffix==".c" else cxx
        r=run([compiler,*flags,"-std=c11" if p.suffix==".c" else "-std=c++17","-c",p,"-o",obj],env)
        print(json.dumps({"compiled":p.name,"seconds":r["seconds"]}),flush=True)
        return obj,r
    started=datetime.datetime.now(datetime.timezone.utc).isoformat()
    bound_sources=sources+[HERE/"native_zip_crypto.h",HERE/"ri3_mbedtls_config.h",SIGNER/"zip_verify_adapter.h",SIGNER/"strict_cms_profile.h",SIGNER/"trusted_cert_der.h"]
    binding={str(p.relative_to(ROOT)):sha(p) for p in bound_sources}
    if a.group is not None:
        plan=out/"build-plan.json"
        if a.group==0: plan.write_text(json.dumps({"source_sha256":binding,"target":a.target,"sanitized":a.sanitize},indent=2)+chr(10))
        else:
            prior=json.loads(plan.read_text())
            if prior!={"source_sha256":binding,"target":a.target,"sanitized":a.sanitize}:raise RuntimeError("Build source/config drift between groups")
        groups=[sources[:6],sources[6:11],sources[11:]]
        selected=groups[a.group] if a.group<3 else []
    else: selected=sources
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool: results=list(pool.map(compile_one,selected))
    objects=[out/(p.stem+".o") for p in sources]; cmds=[r[1] for r in results]
    if a.group is not None and a.group<3:
        (out/("group-"+str(a.group)+".json")).write_text(json.dumps({"source_sha256":binding,"commands":cmds,"objects":{str(p.name):sha(p) for p,_ in results}},indent=2)+chr(10))
        print(json.dumps({"group":a.group,"target":a.target,"objects":len(results),"output":str(out)}),flush=True)
        return
    if a.group==3:
        cmds=[]
        for g in range(3):
            rec=json.loads((out/("group-"+str(g)+".json")).read_text())
            if rec["source_sha256"]!=binding:raise RuntimeError("Group source binding mismatch")
            for name,digest in rec["objects"].items():
                if sha(out/name)!=digest:raise RuntimeError("Compiled object drift")
            cmds.extend(rec["commands"])
    binary=out/"test-crypto"
    ld=target+["-Wl,--gc-sections","-Wl,--wrap=pread","-Wl,--wrap=pread64"]
    if a.target=="android": ld+=["-static"]
    if a.sanitize: ld+=["-fsanitize=address,undefined"]
    cmds.append(run([cxx,*ld,*objects,"-o",binary],env))
    receipt={"schema":1,"started":started,"completed":datetime.datetime.now(datetime.timezone.utc).isoformat(),"target":a.target,"sanitized":a.sanitize,"provenance":provenance,"source_sha256":binding,"commands":cmds,"binary":str(binary.relative_to(ROOT)),"binary_sha256":sha(binary),"device_execution":False,"tests_run":False}
    (out/"build-receipt.json").write_text(json.dumps(receipt,indent=2)+chr(10))
    print(json.dumps({"build_receipt":str((out/"build-receipt.json").relative_to(ROOT)),"binary":str(binary),"sha256":sha(binary),"target":a.target}),flush=True)
if __name__=="__main__": main()
