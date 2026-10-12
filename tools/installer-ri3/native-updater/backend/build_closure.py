#!/usr/bin/env python3
"""RI3 backend archive and static ARM64 link-closure proof; never executed."""
import argparse,difflib,hashlib,json,os,pathlib,re,subprocess
ROOT=pathlib.Path(__file__).resolve().parents[4]
HERE=ROOT/"tools/installer-ri3/native-updater/backend"
WORK=ROOT/"builder/work/installer-ri3-native/backend"
VENDOR=ROOT/"builder/work/installer-ri3-native/production-vendor"
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def reject_body(text,pattern,body):
 hits=list(re.finditer(pattern,text,re.S))
 if len(hits)!=1:raise RuntimeError("Expected one exact upstream method")
 begin=text.index("{",hits[0].end())
 mask=re.sub(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|//[^\n]*|/\*.*?\*/',lambda m:" "*len(m[0]),text,flags=re.S)
 depth=0
 for end in range(begin,len(text)):
  if mask[end]=="{":depth+=1
  elif mask[end]=="}":
   depth-=1
   if depth==0:return text[:begin]+"{\n"+body+"\n}"+text[end+1:]
 raise RuntimeError("Unbalanced upstream method")
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--label",required=True);a=ap.parse_args()
 if re.fullmatch(r"[A-Za-z0-9_-]+",a.label) is None:raise RuntimeError("label")
 out=WORK/a.label
 if out.exists():raise RuntimeError("refuse duplicate closure run")
 out.mkdir(parents=True);(out/"tmp").mkdir()
 lock=json.loads((HERE.parent/"production-sources.lock.json").read_text())
 pinned=[x for x in lock["files"] if x["path"].startswith(("base/","core/fs_mgr/libdm/"))]
 for x in pinned:
  if sha(VENDOR/x["path"])!=x["sha256"]:raise RuntimeError("pinned upstream changed")
 uuid=json.loads((HERE/"vendor/uuid/source.json").read_text())
 if sha(HERE/"vendor/uuid/uuid.h")!=uuid["sha256"]:raise RuntimeError("uuid header")
 original=(VENDOR/"core/fs_mgr/libdm/dm.cpp").read_text()
 adapted=reject_body(original,r"bool DeviceMapper::CreateDevice\(const std::string& name,\s*const DmTable& table,\s*std::string\* path,\s*const std::chrono::milliseconds& timeout_ms\)",
  "    // RI3 removal-only capability boundary: map creation is unsupported.\n    (void)name; (void)table; (void)path; (void)timeout_ms;\n    return false;")
 adapted=reject_body(adapted,r"bool DeviceMapper::LoadTableAndActivate\(const std::string& name,\s*const DmTable& table\)",
  "    // RI3 removal-only capability boundary: table mutation is unsupported.\n    (void)name; (void)table;\n    return false;")
 dm=out/"dm-remove-only.cpp";dm.write_text(adapted,encoding="utf-8",newline="\n")
 (out/"upstream-remove-only.diff").write_text("".join(difflib.unified_diff(original.splitlines(True),adapted.splitlines(True),fromfile="pristine/dm.cpp",tofile="ri3/dm-remove-only.cpp")))
 ndk=pathlib.Path(os.environ["LOCALAPPDATA"])/"Android/Sdk/ndk/28.2.13676358"
 if "Pkg.Revision = 28.2.13676358" not in (ndk/"source.properties").read_text():raise RuntimeError("NDK")
 tools=ndk/"toolchains/llvm/prebuilt/windows-x86_64/bin"
 cxx=tools/"clang++.exe";ar=tools/"llvm-ar.exe";nm=tools/"llvm-nm.exe";readelf=tools/"llvm-readelf.exe"
 flags=["--target=aarch64-linux-android30","-std=c++17","-O2","-Wall","-Wextra","-Werror","-Wno-error=inconsistent-missing-override","-fno-ident","-ffunction-sections","-fdata-sections","-D_FILE_OFFSET_BITS=64","-D_LARGEFILE64_SOURCE=1","-D_GNU_SOURCE",f"-ffile-prefix-map={ROOT}=."]
 for p in [HERE,HERE/"vendor/base-internal",HERE/"vendor",VENDOR/"core/fs_mgr/libdm/include",VENDOR/"core/fs_mgr/libdm",VENDOR/"base/include",VENDOR/"base"]:flags+=["-I"+str(p)]
 env=os.environ.copy();env.update({k:str(out/"tmp") for k in ["TMPDIR","TMP","TEMP","HOME","XDG_CACHE_HOME"]});env.update({"LC_ALL":"C","TZ":"UTC","SOURCE_DATE_EPOCH":"1661990400"})
 logs=[]
 def run(cmd):
  cmd=list(map(str,cmd));record={"command":cmd}
  try:
   p=subprocess.run(cmd,env=env,capture_output=True,text=True,timeout=35)
   record.update(returncode=p.returncode,stdout=p.stdout,stderr=p.stderr)
  except Exception as error:record.update(returncode=1,error=repr(error),stdout="",stderr="")
  finally:
   logs.append(record);(out/"commands.json").write_text(json.dumps(logs,indent=2)+"\n")
  if record["returncode"]:raise RuntimeError(record.get("error") or record["stderr"] or record["stdout"])
  return record["stdout"]
 version=run([cxx,"--version"])
 sources=[HERE/n for n in ["storage_backend.cpp","topology.cpp","verity_table.cpp","unmount.cpp","libdm_adapter.cpp","stderr_log.cpp"]]
 sources += [dm]+[VENDOR/"core/fs_mgr/libdm"/n for n in ["dm_table.cpp","dm_target.cpp","loop_control.cpp","utility.cpp"]]
 sources += [(VENDOR/"base"/n if (VENDOR/"base"/n).is_file() else HERE/"vendor/base-internal"/n) for n in ["file.cpp","logging.cpp","threads.cpp","strings.cpp","stringprintf.cpp","posix_strerror_r.cpp","properties.cpp"]]
 objects=[]
 for i,source in enumerate(sources):
  obj=out/(str(i)+"-"+source.stem+".o");compat=["-Wno-error=vla-cxx-extension","-Wno-error=c99-designator"] if source==VENDOR/"base/logging.cpp" else [];run([cxx,*flags,*compat,"-c",source,"-o",obj]);objects.append(obj)
 archive=out/"libbackend-ri3.a";run([ar,"rcD",archive,*objects])
 undefined=run([nm,"-u","-C",archive]);(out/"archive-undefined.txt").write_text(undefined)
 probe=out/"link_probe.cpp"
 probe.write_text('#include "storage_backend.h"\nint main(){auto dm=ri3::backend::NewLibDmAdapter();auto um=ri3::backend::NewNormalUnmountOps();return dm&&um?0:1;}\n')
 binary=out/"backend-link-proof-aarch64"
 run([cxx,*flags,probe,archive,"-static","-Wl,--gc-sections","-Wl,--build-id=sha1","-Wl,-z,noexecstack","-Wl,-z,relro","-Wl,-z,now","-o",binary])
 elf=run([readelf,"-h","-l","-d",binary]);(out/"elf.txt").write_text(elf)
 if "INTERP" in elf or "(NEEDED)" in elf:raise RuntimeError("not fully static")
 unresolved=run([nm,"-u",binary]).strip()
 optional_weak={"_ZN5scudo20computeHardwareCRC32Ejm","__loader_remove_thread_local_dtor","__scudo_default_options"}
 for line in unresolved.splitlines():
  fields=line.split()
  if len(fields)!=2 or fields[0]!="w" or fields[1] not in optional_weak:raise RuntimeError("unexpected undefined symbol: "+line)
 baseline=run([nm,"-u",ROOT/"builder/work/installer-ri3-native/build-android/prep-update-binary"])
 if not set(unresolved.splitlines()).issubset(set(baseline.strip().splitlines())):raise RuntimeError("optional weak ABI differs from verified NDK baseline")
 source_paths=set(sources+[HERE/"build_closure.py",HERE/"storage_backend.h",HERE/"verity_table.h",HERE/"vendor/uuid/uuid.h",HERE/"vendor/uuid/source.json",HERE/"vendor/base-internal/logging_splitters.h",HERE/"vendor/base-internal/source.json"])
 source_paths.update(VENDOR/x["path"] for x in pinned)
 receipt={"label":a.label,"target":"aarch64-linux-android30","device_operations_executed":False,"probe_executed":False,
  "archive":str(archive),"archive_sha256":sha(archive),"static_link_probe":str(binary),"probe_sha256":sha(binary),
  "fully_static":True,"final_undefined_symbols":unresolved,"required_undefined_symbols":[],"optional_weak_undefined_symbols":unresolved.splitlines(),"compiler_sha256":sha(cxx),"compiler_version":version,
  "sources":{str(p.relative_to(ROOT)):sha(p) for p in source_paths},
  "adaptation":"Exactly two unused virtual methods CreateDevice(table,path,timeout) and LoadTableAndActivate return false; upstream files unchanged. Read/delete APIs remain authentic. Section garbage collection required. No UUID shim. Standalone logging ABI emits stderr, preserves fatal abort; logd/property filtering not used.",
  "diff":str(out/"upstream-remove-only.diff"),"commands":logs}
 (out/"receipt.json").write_text(json.dumps(receipt,indent=2)+"\n")
 print(json.dumps({k:receipt[k] for k in ["archive","archive_sha256","static_link_probe","probe_sha256","fully_static","device_operations_executed"]}))
if __name__=="__main__":main()
