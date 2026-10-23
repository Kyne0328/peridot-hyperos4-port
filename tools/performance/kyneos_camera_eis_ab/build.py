#!/usr/bin/env python3
"""Create one-change POCO F6 camera/EIS A/B trial as a KernelSU module.

The module is not a proven cure. Tests whether disabling the device's
*third-party EISv2 support* flag reduces call processing and heat.
It NEVER modifies thermal controls, stock files, kernel or userdata.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parents[3]
ORIGINAL = ROOT / ".cache/three-way/odm/stock/etc/camera/camxoverridesettings.txt"
OUTPUT = ROOT / "builder/work/kyneos-camera-eis-ab-20261015"
ID = "kyneos_camera_3rdeis_ab"
EXPECTED_SHA = "9ca1ddd03029e30c8f1e261f149985a626c14dbd79c7476d8c58897883892da4"
FIND = b"is3rdEISV2Enabled=TRUE"
REPLACE = b"is3rdEISV2Enabled=FALSE"
TARGET = "system/odm/etc/camera/camxoverridesettings.txt"
ZIPNAME = "POCO-F6-KyneOS-Camera-ThirdPartyEIS-OFF-AB-20261015.zip"


def sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def manifest() -> dict:
    original = ORIGINAL.read_bytes()
    if sha256(original) != EXPECTED_SHA:
        raise ValueError("Original stock peridot camera config SHA-256 changed; refuse to package")
    if original.count(FIND) != 1 or REPLACE in original:
        raise ValueError("Original third-party EIS flag not exactly as expected")
    trial = original.replace(FIND, REPLACE)
    assert trial.replace(REPLACE, FIND) == original
    assert trial.count(REPLACE) == 1
    assert original.count(b"enable3rdAppPowerSave=TRUE") == trial.count(b"enable3rdAppPowerSave=TRUE") == 1

    zipfile_path = OUTPUT / ZIPNAME
    if zipfile_path.exists():
        raise FileExistsError("Refusing to overwrite an earlier A/B trial archive")
    OUTPUT.mkdir(parents=True, exist_ok=True)

    prop = (
        f"id={ID}\n"
        "name=KyneOS POCO F6 Camera Third-party EIS A/B (OFF)\n"
        "version=0.1-ab\n"
        "versionCode=1\n"
        "author=KyneOS\n"
        "description=Experimental reversible 3rd party EISv2 flag OFF. May reduce video stabilization. Does NOT relax thermal or security protections. Not a verified performance fix.\n"
    ).encode()

    customize = (
        "#!/system/bin/sh\n"
        "ui_print '- KyneOS third-party camera EIS A/B test'\n"
        "device=\"$(getprop ro.product.device)\"\n"
        "[ \"$device\" = 'peridot' ] || abort 'POCO F6 peridot only'\n"
        "present=\"$(sha256sum /odm/etc/camera/camxoverridesettings.txt | cut -d ' ' -f 1)\"\n"
        f"[ \"$present\" = '{EXPECTED_SHA}' ] || abort 'Unexpected stock camera file; refusing to install'\n"
        f"set_perm \"$MODPATH/{TARGET}\" 0 0 0644\n"
        "ui_print '- Original camera defaults preserved except third-party EISv2=FALSE'\n"
        "ui_print '- Reboot is required to activate; disable this module and reboot to undo'\n"
    ).encode()
    readme = (
        "EXPERIMENTAL POCO F6 THIRD-PARTY EIS A/B TRIAL - NOT A PROVEN FIX\n"
        f"Stock SHA-256: {EXPECTED_SHA}\n"
        f"Replacement SHA-256: {sha256(trial)}\n"
        "The only stock file edit is one literal is3rdEISV2Enabled=TRUE -> FALSE.\n"
        "This may reduce electronic stabilization in third-party camera apps; the flag\n"
        "might not be consumed in Messenger's camera graph and have zero effect.\n"
        "The KernelSU system/odm magic-mount must work for your configuration.\n"
        "Check after reboot: sha256sum /odm/etc/camera/camxoverridesettings.txt,\n"
        "then compare the same Messenger video-call duration, brightness, temperature,\n"
        "charging status, CPU PSI, provider CPU and thermal scenario.\n"
        f"Rollback: ksud module disable {ID}; REBOOT. Or uninstall via KernelSU.\n"
        "Do NOT change thermal throttling, CPU/GPU clocks or SELinux globally.\n"
    ).encode()

    members = {
        "module.prop": prop,
        "customize.sh": customize,
        TARGET: trial,
        "A-B-TEST-README.txt": readme,
    }
    with zipfile.ZipFile(zipfile_path, "x", compression=zipfile.ZIP_DEFLATED) as z:
        for name, payload in members.items():
            info = zipfile.ZipInfo(name, date_time=(2026, 10, 15, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = (0o755 if name.endswith(".sh") else 0o644) << 16
            z.writestr(info, payload)
    with zipfile.ZipFile(zipfile_path) as z:
        assert z.testzip() is None
        assert z.namelist() == list(members)
        assert all(z.read(k) == v for k, v in members.items())
        assert z.read(TARGET).replace(REPLACE, FIND) == original
    summary = {
        "status": "PACKAGED_EXPERIMENTAL_NOT_DEVICE_TESTED",
        "device": "peridot",
        "module_id": ID,
        "archive": str(zipfile_path),
        "archive_sha256": sha256(zipfile_path.read_bytes()),
        "archive_size": zipfile_path.stat().st_size,
        "input": str(ORIGINAL),
        "input_sha256": EXPECTED_SHA,
        "test_image_sha256": sha256(trial),
        "exact_edits": [{"path": "/odm/etc/camera/camxoverridesettings.txt", "from": FIND.decode(), "to": REPLACE.decode()}],
        "changes_thermal_policy": False,
        "changes_selinux_policy": False,
        "changes_kernel": False,
        "changes_root_configuration": False,
        "changes_third_party_camera_stabilization": True,
        "expected_activation": "after next reboot and verified KernelSU magic mount",
        "evidence": "Stock peridot file flag is enabled; EIS actual use in Messenger has not been established",
        "rollback": f"ksud module disable {ID} then reboot",
        "proven_to_improve_calls": False,
    }
    (OUTPUT / "A-B-TEST-RECEIPT.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    return summary


if __name__ == "__main__":
    manifest()
