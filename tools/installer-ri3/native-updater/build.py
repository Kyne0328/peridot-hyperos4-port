#!/usr/bin/env python3
"""Compile pinned source with installed compilers; writes only under the RI3 native work root."""
import argparse, hashlib, json, os, pathlib, subprocess, sys, tarfile
ROOT=pathlib.Path(__file__).resolve().parents[3]
HERE=ROOT/"tools/installer-ri3/native-updater"
WORK=ROOT/"builder/work/installer-ri3-native"
def digest(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--target",choices=["host","android"],required=True)
    ap.add_argument("--out",default=None)
    ap.add_argument("--sanitize",action="store_true")
    args=ap.parse_args()
    out=WORK/(args.out or ("build-"+args.target))
    if not out.resolve().is_relative_to(WORK.resolve()): raise RuntimeError("output outside work root")
    out.mkdir(parents=True,exist_ok=True)
    for name in ["tmp","home","cache"]: (WORK/name).mkdir(exist_ok=True)
    env=os.environ.copy()
    env.update({x:str(WORK/"tmp") for x in ["TMPDIR","TMP","TEMP"]})
    env.update({"HOME":str(WORK/"home"),"XDG_CACHE_HOME":str(WORK/"cache"),"LC_ALL":"C","TZ":"UTC","SOURCE_DATE_EPOCH":"1661990400"})
    lock=json.loads((HERE/"sources.lock.json").read_text())
    for name,repo in lock["aosp"].items():
        for f in repo["files"]:
            if digest(WORK/"vendor"/name/f["path"])!=f["sha256"]: raise RuntimeError("AOSP source mismatch")
    for name,record in lock["archives"].items():
        if digest(WORK/"downloads"/record["url"].rsplit("/",1)[1])!=record["sha256"]:
            raise RuntimeError("source archive mismatch")
        if name!="zlib-1.3.2": continue  # Generator inputs are independently pinned; only zlib headers enter this compilation.
        archive=WORK/"downloads"/record["url"].rsplit("/",1)[1]
        with tarfile.open(archive) as tf:
            for member in tf:
                if member.isfile():
                    actual=WORK/"vendor"/member.name
                    expected=hashlib.sha256(tf.extractfile(member).read()).hexdigest()
                    if digest(actual)!=expected: raise RuntimeError("extracted source mismatch: "+member.name)
    # Verify generated parser/lexer/header together, including the header consumed by both C++ files.
    generated_manifest=WORK/"generated/generated.sha256"
    seen_generated=set()
    for line in generated_manifest.read_text().splitlines():
        expected,name=line.split(None,1); name=name.lstrip("*")
        if pathlib.Path(name).name!=name: raise RuntimeError("unsafe generated manifest path")
        if name in seen_generated: raise RuntimeError("duplicate generated manifest entry")
        seen_generated.add(name)
        if digest(WORK/"generated"/name)!=expected: raise RuntimeError("generated source mismatch")
    if seen_generated!={"parser.h","parser.cpp","lexer.cpp"}: raise RuntimeError("incomplete generated manifest")
    # Verify pristine extracted headers as well as implementation sources.
    flags=["-O2","-fno-ident","-ffunction-sections","-fdata-sections","-D_FILE_OFFSET_BITS=64","-D_LARGEFILE64_SOURCE=1","-D_POSIX_C_SOURCE=200809L","-DHAVE_UNISTD_H","-DNOUNCRYPT","-DNOCRYPT",f"-ffile-prefix-map={ROOT}=."]
    links=["-Wl,--gc-sections","-Wl,--build-id=sha1","-Wl,-z,noexecstack","-Wl,-z,relro","-Wl,-z,now"]
    if args.target=="android":
        ndk=pathlib.Path(os.environ["LOCALAPPDATA"])/"Android/Sdk/ndk/28.2.13676358"
        props=(ndk/"source.properties").read_text()
        if "Pkg.Revision = 28.2.13676358" not in props: raise RuntimeError("Unexpected NDK")
        prefix=ndk/"toolchains/llvm/prebuilt/windows-x86_64/bin"
        cc=str(prefix/"clang.exe"); cxx=str(prefix/"clang++.exe")
        flags+=["--target=aarch64-linux-android30"]
        links+=["--target=aarch64-linux-android30","-static"]
    else:
        cc="/usr/bin/clang"; cxx="/usr/bin/clang++"
        flags+=["-DRI3_HOST_TEST=1"]
    if args.sanitize:
        if args.target!="host": raise RuntimeError("Sanitizer target must be host")
        flags+=["-fsanitize=address,undefined","-fno-omit-frame-pointer"]
        links+=["-fsanitize=address,undefined"]
    vendor=WORK/"vendor"; recovery=vendor/"recovery"; base=vendor/"libbase"; zlib=vendor/"zlib-1.3.2"
    inc=[HERE,recovery/"edify/include",recovery/"edify",recovery/"otautil/include",base/"include",zlib,zlib/"contrib/minizip",WORK/"generated"]
    flags += [f"-I{x}" for x in inc]
    c_sources=[zlib/(x+".c") for x in ["adler32","crc32","deflate","infback","inffast","inflate","inftrees","trees","zutil","compress","uncompr","gzclose","gzlib","gzread","gzwrite"]]
    c_sources += [zlib/"contrib/minizip"/(x+".c") for x in ["ioapi","unzip"]]
    cpp_sources=[recovery/"edify/expr.cpp",base/"strings.cpp",base/"stringprintf.cpp",base/"posix_strerror_r.cpp",WORK/"generated/parser.cpp",WORK/"generated/lexer.cpp",HERE/"main.cpp"]
    commands=[]
    def run(command):
        command=[str(x) for x in command]; commands.append(command)
        p=subprocess.run(command,env=env,capture_output=True,text=True)
        with (out/"compile.log").open("a",encoding="utf-8") as f:
            f.write(json.dumps(command)+"\n"+p.stdout+p.stderr)
        if p.returncode: print(p.stderr); raise RuntimeError("compile command failed")
        return p.stdout
    (out/"compile.log").write_text("",encoding="utf-8")
    version=run([cxx,"--version"])
    objects=[]
    for i,source in enumerate(c_sources+cpp_sources):
        obj=out/(str(i)+"-"+source.stem+".o")
        language=["-std=c++17"] if source in cpp_sources else ["-std=c11"]
        run([cxx if source in cpp_sources else cc,*flags,*language,"-c",source,"-o",obj])
        objects.append(obj)
    binary=out/"prep-update-binary"
    run([cxx,*objects,*links,"-o",binary])
    sources={str(p.relative_to(ROOT)):digest(p) for p in c_sources+cpp_sources}
    for generated in ["parser.h","generated.sha256"]:
        p=WORK/"generated"/generated; sources[str(p.relative_to(ROOT))]=digest(p)
    sources[str(HERE.relative_to(ROOT)/"sources.lock.json")]=digest(HERE/"sources.lock.json")
    receipt={"target":args.target,"installation_enabled":False,"compiler_version":version,"compiler_sha256":digest(pathlib.Path(cxx).resolve()),"binary":str(binary),"binary_bytes":binary.stat().st_size,"binary_sha256":digest(binary),"sources":sources,"commands":commands,"sanitizers":args.sanitize}
    (out/"build-receipt.json").write_text(json.dumps(receipt,indent=2)+"\n",encoding="utf-8")
    print(json.dumps({k:receipt[k] for k in ["target","installation_enabled","binary","binary_bytes","binary_sha256"]}))
if __name__=="__main__": main()
