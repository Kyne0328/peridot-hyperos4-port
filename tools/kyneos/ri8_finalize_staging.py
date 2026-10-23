"""Finish a fully checked RI8 non-installable image-set ZIP after an interrupted packaging/signing step.

No image is rewritten; adds only public OTA certificate and signed ZIP footer.
The result remains NOT FLASHABLE and includes no update-binary.
"""
from __future__ import annotations
from pathlib import Path
import hashlib,json,sys,zipfile
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"tools/installer-ri3/zip-signing"))
from sign_zip import sign_generated_zip
OUT=Path("D:/hyperos4-peridot-kyneos-ri8-20261014/outputs")
ZIP=OUT/"KyneOS-RI8-STAGING-NOT-FLASHABLE-20261014.zip"
WORK=ROOT/"builder/work/kyneos-ri8-20261014"
def sha(p):
    with Path(p).open("rb") as f:
        return hashlib.file_digest(f,"sha256").hexdigest()
def main():
    src=json.loads((Path("D:/hyperos4-peridot-kyneos-ri8-20261014/work")/"ri8-assembly.json").read_text())
    prev=json.loads((ROOT/"builder/work/screen-recorder-call-audio-20261007/screenrecorder-call-audio-assembly.json").read_text())
    pins={"images/super.img":src["output_super_sha256"],
          "images/vbmeta.img":src["output_vbmeta_sha256"],
          "images/vbmeta_system.img":prev["output_vbmeta_system_sha256"]}
    signing=json.loads((ROOT/"builder/work/installer-ri5-recoveryfix-20261004/signing-public.json").read_text())
    with zipfile.ZipFile(ZIP) as z:
        names=z.namelist()
        if len(names)!=len(set(names)) or set(pins)-set(names) or len(names)>6:
            raise ValueError("Unexpected staging ZIP content")
        for disallowed in ["META-INF/com/google/android/update-binary","META-INF/com/google/android/updater-script"]:
            if disallowed in names:
                raise ValueError("Unsafe recovery updater found in staging")
        if json.loads(z.read("RI8-STAGING-MANIFEST.json"))["release_status"]!="NOT_FLASHABLE_INCOMPLETE_4_GROUPS":
            raise ValueError("Incorrect release status")
    cert=(ROOT/signing["certificate_path"]).read_bytes()
    if "META-INF/com/android/otacert" not in names:
        with zipfile.ZipFile(ZIP,"a",allowZip64=True) as z:
            z.writestr("META-INF/com/android/otacert",cert)
    else:
        with zipfile.ZipFile(ZIP) as z:
            if z.read("META-INF/com/android/otacert")!=cert:
                raise ValueError("OTA certificate differs")
    WORK.mkdir(parents=True,exist_ok=True)
    sig=sign_generated_zip(ZIP,ROOT/signing["certificate_path"],ROOT/signing["private_key_path"],
                           generated_root=OUT,generated_parent=OUT.parent,work_dir=WORK,
                           expected_cert_sha256=signing["certificate_der_sha256"],
                           reserve_bytes=2*1024**3)
    if not sig["verified"]:
        raise ValueError("ZIP signature not independently verified")
    print("Signed ZIP; verifying staged image CRC and SHA256",flush=True)
    with zipfile.ZipFile(ZIP) as z:
        if len(z.namelist())!=6:
            raise ValueError("Unexpected final member count")
        for name,h in pins.items():
            with z.open(name) as stream:
                got=hashlib.file_digest(stream,"sha256").hexdigest()
            if got!=h:
                raise ValueError("Bad decoded image "+name)
            print("PASS",name,flush=True)
        if "META-INF/com/google/android/update-binary" in z.namelist() or "META-INF/com/google/android/updater-script" in z.namelist():
            raise ValueError("Unexpected updater presence")
    result={"archive":str(ZIP),"size_bytes":ZIP.stat().st_size,"sha256":sha(ZIP),
            "verified_signature":True,"image_sha256":pins,
            "exact_member_count":6,"all_three_images_verified":True,
            "flash_safe":False,"ROM_installer_present":False,"ROM_boot_tested":False,
            "kernel_images_or_root_addons_included":False}
    (OUT/"STAGING-VALIDATION.json").write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8")
    (OUT/(ZIP.name+".sha256")).write_text(result["sha256"]+"  "+ZIP.name+"\n",encoding="utf-8")
    (OUT/"README-DO-NOT-FLASH.txt").write_text(
        "DEVELOPMENT IMAGE SET ONLY. DO NOT FLASH. Not a four-fix release.\n"
        "Contains super, vbmeta and vbmeta_system ONLY; no boot/kernel/root addons.\n"
        "Requires an independently tested selective updater before device use.\n",encoding="utf-8")
    print(json.dumps({k:result[k] for k in ("archive","size_bytes","sha256","flash_safe")},indent=2),flush=True)
if __name__=="__main__":
    main()
