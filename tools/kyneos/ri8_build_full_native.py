"""Build KyneOS RI8 full-ROM native recovery updater from existing RI7.1 OTG-fix source.

Unlike RI7.3, compile exact SHA-256 pins for changed RI8 super, root
vbmeta and RI7.3 vbmeta_system. All 29 other images are unchanged, including
the ROM's standard boot/init_boot/vendor_boot partitions. ReSukiSU addons are
NOT modified or included; the user can install the custom kernel separately
after the ROM.

The existing RI5/RI7 firmware installer architecture is preserved; only
its 32-image immutable payload pins are refreshed.
"""
from pathlib import Path
import hashlib
import json
import shutil
import subprocess
import zipfile

ROOT=Path(__file__).resolve().parents[2]
PARENT=ROOT/"builder/work/installer-ri5-recoveryfix-20261004"
SOURCE_RECEIPT=PARENT/"native-android-new-kyneosri7otgfix/build-receipt.json"
SOURCE_NATIVE=PARENT/"native-android-new-kyneosri7otgfix"
OUT=ROOT/"builder/work/kyneos-ri8-full-20261014/native"
RI7_ZIP=Path("D:/hyperos4-peridot-kyneos-ri7.3-messenger-callaudio-20261007/outputs/KyneOS-Global-HyperOS4-POCO-F6-RI7.3-20261007.zip")
RI8_ASSEMBLY=Path("D:/hyperos4-peridot-kyneos-ri8-20261014/work/ri8-assembly.json")

def sha(path):
    with Path(path).open("rb") as inp:
        return hashlib.file_digest(inp,"sha256").hexdigest()

def main():
    receipt=json.loads(SOURCE_RECEIPT.read_text(encoding="utf-8"))
    refs=json.loads((RI7_ZIP.parent/"VALIDATION.json").read_text(encoding="utf-8"))
    assembly=json.loads(RI8_ASSEMBLY.read_text(encoding="utf-8"))
    assert sha(RI7_ZIP)==refs["sha256"],"RI7.3 signed source changed"
    assert all(assembly[x] is True for x in (
        "only_vendor_span_changed","all_other_super_bytes_verified_identical",
        "root_vbmeta_only_vendor_descriptor_changed",
        "root_vbmeta_boot_chain_descriptors_preserved","avb_key_rollback_flags_preserved",
        "system_ri7_3_preserved")), "RI8 staged AVB proof incomplete"
    OUT.mkdir(parents=True,exist_ok=True)
    if any((OUT/x).exists() for x in ("image_pins.h","main.cpp","install_runtime.cpp","update-binary","BUILD-RECEIPT.json")):
        raise FileExistsError("RI8 full native build outputs already exist")
    for path,digest in receipt["objects"].items():
        p=ROOT/path
        if sha(p)!=digest:
            raise ValueError("Pinned native recovery dependency changed "+str(p))
    with zipfile.ZipFile(RI7_ZIP) as z:
        old=json.loads(z.read("RI5-BUILD-MANIFEST.json"))
    pin_list=[dict(x) for x in old["images"]]
    assert len(pin_list)==32 and len({p["name"] for p in pin_list})==32
    old_names={p["name"] for p in pin_list}
    assert {"super","vbmeta","vbmeta_system","boot","init_boot","vendor_boot","recovery"}<=old_names
    verified_paths={
        "super":("output_super","output_super_sha256"),
        "vbmeta":("output_vbmeta","output_vbmeta_sha256")
    }
    for row in pin_list:
        if row["name"] in verified_paths:
            path_key,sha_key=verified_paths[row["name"]]
            path=Path(assembly[path_key])
            if sha(path)!=assembly[sha_key]:
                raise ValueError("RI8 source image drift: "+row["name"])
            if row["bytes"]!=path.stat().st_size:
                raise ValueError("Partition capacity drift: "+row["name"])
            row["sha256"]=assembly[sha_key]
    target_system=json.loads((ROOT/"builder/work/screen-recorder-call-audio-20261007/screenrecorder-call-audio-assembly.json").read_text())
    old_sys=next(x for x in pin_list if x["name"]=="vbmeta_system")
    assert old_sys["sha256"]==target_system["output_vbmeta_system_sha256"],"RI7.3 system signing descriptor drift"
    assert next(x for x in pin_list if x["name"]=="super")["sha256"]==assembly["output_super_sha256"]
    assert next(x for x in pin_list if x["name"]=="vbmeta")["sha256"]==assembly["output_vbmeta_sha256"]
    # Ensure we did NOT generate or incorporate a ReSukiSU-custom boot image.
    assert all(next(x for x in pin_list if x["name"]==n)["sha256"]==
        next(x for x in old["images"] if x["name"]==n)["sha256"]
        for n in ("boot","init_boot","vendor_boot","dtbo","recovery")), "Boot/recovery payload modified"
    # Compiled image order exactly follows the signed parent manifest,
    # which is matched to the RI5 validated 32-image package contract.
    header=['#pragma once','#include <cstdint>',
      'namespace ri4 { struct Pin { const char*name; uint64_t bytes; const char*sha; };',
      'constexpr unsigned kImageCount=32;',
      'inline const Pin kPins[]={']
    for row in pin_list:
        assert isinstance(row["bytes"],int) and row["bytes"]>0
        assert len(row["sha256"])==64
        header.append('{"%s",%dULL,"%s"},' % (row["name"],row["bytes"],row["sha256"]))
    header+=['}; }']
    (OUT/"image_pins.h").write_text("\n".join(header)+"\n",encoding="utf-8")
    # Use exact reviewed source of existing RI7 recovery updater with the
    # bounded OTG/storage collection improvements linked from its original objects.
    main_source=PARENT/"generated-kyneosri7otgfix/main.cpp"
    rt_source=ROOT/"tools/installer-ri5/install_runtime.cpp"
    for src,dst in [(main_source,OUT/"main.cpp"),(rt_source,OUT/"install_runtime.cpp")]:
        shutil.copyfile(src,dst)
    commands=receipt["commands"]
    compile_results=[]
    for index,source_file in ((36,OUT/"install_runtime.cpp"),(37,OUT/"main.cpp")):
        previous=commands[index]["argv"]
        cmd=list(previous)
        input_cpp=next(x for x in cmd if x.endswith(".cpp"))
        cmd[cmd.index(input_cpp)]=str(source_file)
        cmd.insert(1,"-I"+str(OUT))
        obj=OUT/("%d-ri8.o"%index)
        cmd[cmd.index("-o")+1]=str(obj)
        run=subprocess.run(cmd,capture_output=True,text=True)
        compile_results.append({"phase":"compile","index":index,"exit_code":run.returncode,"stderr":run.stderr[-4000:]})
        if run.returncode:
            (OUT/"FAILED-BUILD.json").write_text(json.dumps(compile_results,indent=2))
            raise RuntimeError("RI8 native compile failure: "+run.stderr[-2700:])
    link=list(commands[-1]["argv"])
    for index,stem in ((36,"install_runtime"),(37,"main")):
        previous=str(SOURCE_NATIVE/("%d-%s.o"%(index,stem)))
        assert previous in link,"Expected previous object missing"
        link[link.index(previous)]=str(OUT/("%d-ri8.o"%index))
    dest=OUT/"update-binary"
    link[link.index("-o")+1]=str(dest)
    run=subprocess.run(link,capture_output=True,text=True)
    compile_results.append({"phase":"link","exit_code":run.returncode,"stderr":run.stderr[-5000:]})
    if run.returncode:
        (OUT/"FAILED-BUILD.json").write_text(json.dumps(compile_results,indent=2))
        raise RuntimeError("RI8 native link failure: "+run.stderr[-2700:])
    binary=dest.read_bytes()
    assert binary[:4]==b"\x7fELF" and binary[4]==2 and int.from_bytes(binary[18:20],"little")==183
    for name in ("super","vbmeta","vbmeta_system"):
        target=next(x for x in pin_list if x["name"]==name)["sha256"].encode()
        assert target in binary,"Compiled updater missing updated "+name+" pin"
    stale={x["name"]:x["sha256"] for x in old["images"]}
    for name in ("super","vbmeta"):
        assert stale[name].encode() not in binary,"Stale RI7.3 pin remained in updater for "+name
    result={"build_id":"KYNEOS-RI8-20261014",
        "updater_binary":str(dest),"updater_sha256":sha(dest),"updater_bytes":len(binary),
        "image_pins":pin_list,"image_count":32,"native_source":str(rt_source),
        "source_native_baseline":receipt["binary_sha256"],
        "native_dependency_objects_sha_verified":len(receipt["objects"])-2,
        "compile_results":compile_results,
        "original_boot_images_preserved_in_source_plan":True,
        "separately_installed_ReSukiSU_integrated":False,
        "ROM_flash_after_ReSukiSU_will_replace_boot_images":True,
        "install_architecture":"RI5 streaming 32 images to slot A (existing developer-owned ROM workflow)",
        "full_zip_built":False,"device_tested":False,"flashed":False}
    (OUT/"BUILD-RECEIPT.json").write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8")
    print(json.dumps({k:result[k] for k in ("build_id","updater_binary","updater_sha256","updater_bytes","image_count","separately_installed_ReSukiSU_integrated")},indent=2))

if __name__=="__main__":
    main()
