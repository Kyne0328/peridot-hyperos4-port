"""RI8 stage 2: preserve RI7.3 system, replace ONLY vendor_a in shared super, sign vbmeta_a.

No vendor_boot, boot, init_boot, DTBO, recovery, kernel, or root addon is modified.
Does not install or reboot. Output is an image set pending safe selective updater.
"""
from __future__ import annotations
from pathlib import Path
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[2]
WORK=Path("D:/hyperos4-peridot-kyneos-ri8-20261014/work")
SOURCE_WORK=ROOT/"builder/work/screen-recorder-call-audio-20261007"
BASE=ROOT/"builder/work/kyneos-ri7-20261005"
sys.path.insert(0,str(ROOT/"tools/postboot"))
from assemble import descriptor_name,footer_metadata,resign
sys.path.insert(0,str(ROOT/"tools/kyneos"))
from assemble_system_call_audio import sha,digest_range,property_descriptor
sys.path.insert(0,str(ROOT/"tools/installer-ri3/recovery-pair"))
from pair_format import verify_avb,public_blob
sys.path.insert(0,str(ROOT/"builder"))
from peridot_builder.lp import parse_super_metadata_prefix
from cryptography.hazmat.primitives import serialization

def run():
    receipt=json.loads((WORK/"vendor-ri8-repack.json").read_text(encoding="utf-8"))
    if not receipt["all_file_contents_and_metadata_verified"]:
        raise ValueError("Unvalidated vendor filesystem")
    fs=Path(receipt["filesystem_path"])
    if sha(fs)!=receipt["filesystem_sha256"] or fs.stat().st_size!=receipt["filesystem_bytes"]:
        raise ValueError("Vendor filesystem drift")
    original_vendor=BASE/"vendor.img"
    if sha(original_vendor)!=receipt["source_vendor_sha256"]:
        raise ValueError("Original vendor image drift")
    source_assembly=json.loads((SOURCE_WORK/"screenrecorder-call-audio-assembly.json").read_text())
    old_super=Path(source_assembly["output_super"])
    if sha(old_super)!=source_assembly["output_super_sha256"]:
        raise ValueError("RI7.3 parent super image drift")
    old_vbmeta=BASE/"vbmeta.img"
    old_meta=verify_avb(old_vbmeta.read_bytes())
    source_footer=footer_metadata(original_vendor)
    source_descriptor=next(d for d in source_footer["descriptors"] if descriptor_name(d)=="vendor")
    root_descriptor=next(d for d in old_meta["descriptors"] if descriptor_name(d)=="vendor")
    if source_descriptor!=root_descriptor:
        raise ValueError("Vendor descriptor differs from pinned root AVB")
    if struct.unpack_from(">Q",source_descriptor,20)[0]!=fs.stat().st_size:
        raise ValueError("Original vendor filesystem body size changed")
    if struct.unpack_from(">I",source_descriptor,52)[0]!=0:
        raise ValueError("Unexpected original vendor FEC policy")
    n,s=struct.unpack_from(">II",source_descriptor,104)
    salt=source_descriptor[180+n:180+n+s].hex()
    if len(salt)!=s*2:
        raise ValueError("Invalid descriptor salt")
    properties=[p for d in source_footer["descriptors"] if (p:=property_descriptor(d)) is not None]

    target_vendor=WORK/"vendor.ri8.img"
    target_super=WORK/"super.ri8.img"
    target_vbmeta=WORK/"vbmeta.ri8.img"
    if any(p.exists() for p in (target_vendor,target_super,target_vbmeta)):
        raise FileExistsError("Refusing to overwrite authored RI8 image")
    shutil.copyfile(fs,target_vendor)
    avbtool=ROOT/"builder/tools/bin/avbtool.py"
    args=[sys.executable,str(avbtool),"add_hashtree_footer","--image",str(target_vendor),
          "--partition_name","vendor","--partition_size",str(original_vendor.stat().st_size),
          "--hash_algorithm","sha256","--block_size","4096","--salt",salt,
          "--algorithm","NONE","--flags","0","--do_not_generate_fec"]
    for name,value in properties:
        args.extend(["--prop",f"{name}:{value}"])
    subprocess.run(args,check=True)
    if target_vendor.stat().st_size!=original_vendor.stat().st_size:
        raise ValueError("Target vendor partition allocation drift")
    dest_footer=footer_metadata(target_vendor)
    new_desc=next(d for d in dest_footer["descriptors"] if descriptor_name(d)=="vendor")
    if struct.unpack_from(">Q",new_desc,20)[0]!=fs.stat().st_size:
        raise ValueError("Descriptor does not describe authored filesystem")
    if struct.unpack_from(">I",new_desc,52)[0]!=0:
        raise ValueError("Accidentally added vendor FEC")
    for d in source_footer["descriptors"]:
        if descriptor_name(d)!="vendor" and d not in dest_footer["descriptors"]:
            raise ValueError("Unrelated vendor AVB footer descriptor changed")
    key=serialization.load_pem_private_key((ROOT/".private/avb/postbootfix1/root-rsa4096.pem").read_bytes(),None)
    if old_meta["pk"]!=public_blob(key):
        raise ValueError("Root AVB private key does not match original")
    vbmeta=resign(old_vbmeta.read_bytes(),[new_desc if descriptor_name(d)=="vendor" else d for d in old_meta["descriptors"]],key)
    target_vbmeta.write_bytes(vbmeta)
    checked=verify_avb(vbmeta)
    if checked["pk"]!=old_meta["pk"] or checked["header"][16:19]!=old_meta["header"][16:19]:
        raise ValueError("Root AVB signing key, flags or rollback changed")
    for d in old_meta["descriptors"]:
        if descriptor_name(d)!="vendor" and d not in checked["descriptors"]:
            raise ValueError("Unrelated root AVB descriptor changed")
    if next(d for d in checked["descriptors"] if descriptor_name(d)=="vendor")!=new_desc:
        raise ValueError("Root AVB does not bind authored vendor")

    with old_super.open("rb") as stream:
        layout=parse_super_metadata_prefix(stream.read(1024*1024))
    vendor_part=next(p for p in layout["partitions"] if p["name"]=="vendor_a")
    if len(vendor_part["extents"])!=1:
        raise ValueError("Unexpected fragmented vendor allocation")
    span=vendor_part["extents"][0]
    offset=span["offset_bytes"]
    size=span["size_bytes"]
    if size!=target_vendor.stat().st_size:
        raise ValueError("Vendor super extent size mismatch")
    if digest_range(old_super,offset,size)!=sha(original_vendor):
        raise ValueError("RI7.3 vendor span is not the pinned untouched RI7.1 vendor image")
    shutil.copyfile(old_super,target_super)
    with target_super.open("r+b") as dest,target_vendor.open("rb") as source:
        dest.seek(offset)
        for block in iter(lambda:source.read(4*1024*1024),b""):
            dest.write(block)
        dest.flush()
        os.fsync(dest.fileno())
    if digest_range(target_super,offset,size)!=sha(target_vendor):
        raise ValueError("Target super vendor readback failed")
    if digest_range(old_super,0,offset)!=digest_range(target_super,0,offset):
        raise ValueError("An unexpected super prefix change would affect other partitions")
    after=offset+size
    suffix=old_super.stat().st_size-after
    if suffix<0 or digest_range(old_super,after,suffix)!=digest_range(target_super,after,suffix):
        raise ValueError("An unexpected super suffix change would affect other partitions")
    assembly={
        "base":"KYNEOS-RI7.3-20261007",
        "output_vendor":str(target_vendor),"output_vendor_sha256":sha(target_vendor),
        "output_super":str(target_super),"output_super_sha256":sha(target_super),
        "output_vbmeta":str(target_vbmeta),"output_vbmeta_sha256":sha(target_vbmeta),
        "source_super_sha256":source_assembly["output_super_sha256"],
        "source_root_vbmeta_sha256":sha(old_vbmeta),
        "vendor_a_offset_bytes":offset,"vendor_a_size_bytes":size,
        "only_vendor_span_changed":True,
        "all_other_super_bytes_verified_identical":True,
        "root_vbmeta_only_vendor_descriptor_changed":True,
        "root_vbmeta_boot_chain_descriptors_preserved":True,
        "avb_key_rollback_flags_preserved":True,
        "system_ri7_3_preserved":True,
        "boot_init_boot_vendor_boot_recovery_kernel_modified":False,
        "boot_init_boot_vendor_boot_recovery_kernel_flash_allowed":False,
        "flashing_tested":False,
        "safe_selective_recovery_installer_implemented":False
    }
    (WORK/"ri8-assembly.json").write_text(json.dumps(assembly,indent=2)+"\n",encoding="utf-8")
    print(json.dumps(assembly,indent=2),flush=True)
if __name__=="__main__":
    run()
