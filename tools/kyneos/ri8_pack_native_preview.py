"""Sign RI8 recovery *read-only preview* ZIP. Its native InstallHeldPackage is disabled.

This is not a flashable ROM. It contains only the vendor_a and vbmeta_a payloads,
and a recovery update-binary compiled for validation. Attempted ri8_install
always returns error without opening partition devices for write.
"""
from pathlib import Path
import hashlib,json,shutil,sys,zipfile
ROOT=Path(__file__).resolve().parents[2]
WORK=ROOT/"builder/work/kyneos-ri8-20261014"
STAGE=Path("D:/hyperos4-peridot-kyneos-ri8-20261014/work")
OUT=Path("D:/hyperos4-peridot-kyneos-ri8-20261014/outputs")
NAME="KyneOS-RI8-READONLY-RECOVERY-PREVIEW-NOFLASH-20261014.zip"
sys.path.insert(0,str(ROOT/"tools/installer-ri3/zip-signing"))
from sign_zip import sign_generated_zip
def sha(p):
    with Path(p).open("rb") as stream:
        return hashlib.file_digest(stream,"sha256").hexdigest()
def main():
    native=json.loads((WORK/"native/native-build.json").read_text(encoding="utf-8"))
    if native["device_write_entrypoint_enabled"] is not False:
        raise ValueError("RI8 native device writes are enabled")
    binary=Path(native["binary"])
    if sha(binary)!=native["sha256"]:
        raise ValueError("Updater binary drift")
    stage=json.loads((OUT/"RI8-VENDOR-ONLY-VALIDATION.json").read_text(encoding="utf-8"))
    with zipfile.ZipFile(stage["archive"]) as original:
        source=json.loads(original.read("RI8-VENDOR-ONLY-MANIFEST.json"))
    if source["required_write_allowlist"]!=["vendor_a","vbmeta_a"] or source["recovery_installer_present"]:
        raise ValueError("Source staging write scope changed")
    images=[("partitions/vendor.bin",STAGE/"vendor.ri8.img",source["target_images"]["images/vendor_a.img"]["sha256"]),
            ("partitions/vbmeta.bin",STAGE/"vbmeta.ri8.img",source["target_images"]["images/vbmeta_a.img"]["sha256"])]
    for name,path,h in images:
        if sha(path)!=h:
            raise ValueError("Authored ROM image drift: "+name)
    keys=json.loads((ROOT/"builder/work/installer-ri5-recoveryfix-20261004/signing-public.json").read_text())
    small={
        "META-INF/com/android/otacert":(ROOT/keys["certificate_path"]).read_bytes(),
        "META-INF/com/google/android/update-binary":binary.read_bytes(),
        "META-INF/com/google/android/updater-script":(
           b'ui_print("RI8 READONLY PREVIEW - NO PARTITION WRITES AUTHORIZED.");\n'
           b'assert(ri8_install());\n'),
        "RI8-SOURCE-MANIFEST.json":(json.dumps(source,indent=2)+"\n").encode(),
        "RI8-BUILD-MANIFEST.json":(json.dumps({
            "build_id":"KYNEOS-RI8-READONLY-PREVIEW",
            "status":"DO_NOT_FLASH; native InstallHeldPackage denies writes",
            "native_sha256":native["sha256"],
            "partition_images":[{"name":name,"sha256":h,"bytes":p.stat().st_size} for name,p,h in images],
            "write_allowed":False,
            "boot_init_boot_vendor_boot_recovery_root_module_changes":False,
            "requires_compatible_current_vbmeta_hash":source["source_vbmeta_a_sha256"],
            "functional_regressions_passed":False},indent=2)+"\n").encode(),
    }
    if shutil.disk_usage(OUT).free<5*1024**3:
        raise ValueError("Insufficient staging disk reserve")
    final=OUT/NAME
    partial=OUT/(NAME+".partial")
    if final.exists() or partial.exists():
        raise FileExistsError("Refusing overwrite")
    with zipfile.ZipFile(partial,"x",allowZip64=True) as z:
        for name,data in small.items():
            z.writestr(name,data,compress_type=zipfile.ZIP_STORED)
        for name,path,digest in images:
            info=zipfile.ZipInfo(name)
            info.compress_type=zipfile.ZIP_STORED
            info.file_size=path.stat().st_size
            h=hashlib.sha256()
            with z.open(info,"w",force_zip64=True) as out,path.open("rb") as inp:
                for buf in iter(lambda:inp.read(4*1024*1024),b""):
                    out.write(buf);h.update(buf)
            if h.hexdigest()!=digest:
                raise ValueError("Input drift during ZIP pack")
    with zipfile.ZipFile(partial) as z:
        if len(z.namelist())!=7 or len(set(z.namelist()))!=7:
            raise ValueError("Invalid member contract")
        for name,path,digest in images:
            with z.open(name) as stream:
                if hashlib.file_digest(stream,"sha256").hexdigest()!=digest:
                    raise ValueError("ZIP CRC/SHA mismatch")
    partial.rename(final)
    WORK.mkdir(parents=True,exist_ok=True)
    sig=sign_generated_zip(final,ROOT/keys["certificate_path"],ROOT/keys["private_key_path"],
             generated_root=OUT,generated_parent=OUT.parent,work_dir=WORK,
             expected_cert_sha256=keys["certificate_der_sha256"],reserve_bytes=2*1024**3)
    if not sig["verified"]:
        raise ValueError("Signed ZIP verification failed")
    receipt={"archive":str(final),"bytes":final.stat().st_size,"sha256":sha(final),
        "signature_verified":True,"partition_images":{name:h for name,p,h in images},
        "updater_binary_sha256":native["sha256"],"native_install_enabled":False,
        "ready_to_flash":False,"device_installed":False,"test_in_recovery":False,
        "boot_kernel_root_addons_included":False}
    (OUT/"RI8-READONLY-RECOVERY-VALIDATION.json").write_text(json.dumps(receipt,indent=2)+"\n")
    print(json.dumps(receipt,indent=2))
if __name__=="__main__":main()
