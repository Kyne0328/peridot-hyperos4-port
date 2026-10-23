#!/usr/bin/env python3
"""Build POCO F6 camera text-logging-off A/B module update.

Module ID matches the existing EIS A/B to ensure *one* camera ODM overlay.
No camera pipeline, thermal safeguards, clock caps or SELinux edits.
"""
from __future__ import annotations
from pathlib import Path
import hashlib, json, zipfile

ROOT=Path(__file__).resolve().parents[3]
STOCK=ROOT/".cache/three-way/odm/stock/etc/camera/camxoverridesettings.txt"
OUT=ROOT/"builder/work/kyneos-camera-log-ab-20261015"
ZIP=OUT/"POCO-F6-Camera-EIS-Off-TextLogging-Off-AB2-20261015.zip"
MOD="kyneos_camera_3rdeis_ab"
EXPECTED_ORIGINAL="9ca1ddd03029e30c8f1e261f149985a626c14dbd79c7476d8c58897883892da4"
EXPECTED_EIS="7526d8325a7b6d820ea643cce0a58d93833f10381a8b9124d25c23639f738a53"
PATH="system/odm/etc/camera/camxoverridesettings.txt"
def sha(b:bytes)->str:return hashlib.sha256(b).hexdigest()

def main():
    orig=STOCK.read_bytes()
    assert sha(orig)==EXPECTED_ORIGINAL,"Owner's pin for stock Xiaomi peridot camera config changed"
    assert orig.count(b"is3rdEISV2Enabled=TRUE")==1 and orig.count(b"enableTxtLogging=1")==1
    eis=orig.replace(b"is3rdEISV2Enabled=TRUE",b"is3rdEISV2Enabled=FALSE")
    assert sha(eis)==EXPECTED_EIS
    trial=eis.replace(b"enableTxtLogging=1",b"enableTxtLogging=0")
    assert trial.replace(b"enableTxtLogging=0",b"enableTxtLogging=1")==eis
    assert trial.replace(b"is3rdEISV2Enabled=FALSE",b"is3rdEISV2Enabled=TRUE").replace(b"enableTxtLogging=0",b"enableTxtLogging=1")==orig
    assert b"enable3rdAppPowerSave=TRUE" in trial
    assert b"chiLogWarningMask=0x1" in trial
    metadata=(
      f"id={MOD}\n"
      "name=KyneOS Camera Third-Party EIS and Text-Logging A/B\n"
      "version=0.2-ab\nversionCode=2\n"
      "author=KyneOS\n"
      "description=Experimental reversible EISv2 OFF + CamX text logging OFF. No thermal or SELinux change; performance not yet proven.\n"
    ).encode()
    install=(
      "#!/system/bin/sh\n"
      "ui_print '- KyneOS peridot camera metadata-only logging A/B'\n"
      "dev=\"$(getprop ro.product.device)\"\n"
      "[ \"$dev\" = peridot ] || abort 'Wrong device'\n"
      "visible=\"$(sha256sum /odm/etc/camera/camxoverridesettings.txt | cut -d ' ' -f 1)\"\n"
      f"if [ \"$visible\" != '{EXPECTED_ORIGINAL}' ] && [ \"$visible\" != '{EXPECTED_EIS}' ]; then\n"
      " abort 'Unexpected live camera config; refuse overlay'; fi\n"
      f"set_perm \"$MODPATH/{PATH}\" 0 0 0644\n"
      "ui_print '- Staged for NEXT reboot; does not restart camera or change heat safeguards'\n"
    ).encode()
    readme=(
      "A/B 0.2: NOT A PROVEN OPTIMIZATION. EIS already OFF in 0.1.\n"
      "Single ADDITIONAL trial change: enableTxtLogging=1 -> enableTxtLogging=0.\n"
      "All remaining vendor camera settings, chiLogInfoMask and warnings unchanged.\n"
      "Rationale: during native 3s simpleperf call profile camera provider spent\n"
      "~6.27% sampled CPU cycles in libc __vfprintf text formatting; not proof\n"
      "all this work comes from CamX text logging. Test hypothesis safely.\n"
      "After reboot verify mounted /odm/etc/camera/camxoverridesettings.txt hash.\n"
      "For A/B rollback, reinstall original v0.1 EIS-off ZIP, reboot. To return\n"
      "fully stock, disable module via ksud module disable kyneos_camera_3rdeis_ab;\n"
      "then reboot. SELinux and thermal safeguards stay unchanged.\n"
    ).encode()
    files={"module.prop":metadata,"customize.sh":install,PATH:trial,"A-B-TEST-README.txt":readme}
    OUT.mkdir(parents=True,exist_ok=True)
    with zipfile.ZipFile(ZIP,"x",compression=zipfile.ZIP_DEFLATED) as z:
      for name,data in files.items():
        zi=zipfile.ZipInfo(name,date_time=(2026,10,15,0,0,0))
        zi.compress_type=zipfile.ZIP_DEFLATED;zi.create_system=3
        zi.external_attr=(0o755 if name.endswith(".sh") else 0o644)<<16
        z.writestr(zi,data)
    with zipfile.ZipFile(ZIP) as z:
      assert z.testzip() is None
      assert list(z.namelist())==list(files)
      assert all(z.read(k)==v for k,v in files.items())
    receipt={
      "module_id":MOD,
      "trial":"EXPERIMENTAL_STAGED_ONLY",
      "original_sha256":EXPECTED_ORIGINAL,
      "current_eis_off_sha256":EXPECTED_EIS,
      "updated_file_sha256":sha(trial),
      "archive_sha256":sha(ZIP.read_bytes()),
      "zip":str(ZIP),
      "deltas_from_existing_eis_off":[{"before":"enableTxtLogging=1","after":"enableTxtLogging=0"}],
      "keeps_thermal_profiles":True,
      "keeps_selinux":True,
      "keeps_kernel":True,
      "sets_any_cpu_limits":False,
      "performance_benefit_verified":False
    }
    (OUT/"A-B2-RECEIPT.json").write_text(json.dumps(receipt,indent=2)+"\n",encoding="utf-8")
    print(json.dumps(receipt,indent=2))
if __name__=="__main__":main()
