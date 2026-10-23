#!/usr/bin/env python3
"""Build an UNINSTALLED controlled CamX GPU rotation A/B variant.

Does not change the connected device. User must confirm camera orientation,
framerate, EIS and audio quality before production adoption.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
from zipfile import ZipFile, ZipInfo, ZIP_DEFLATED

PROJECT = Path(__file__).resolve().parents[3]
STOCK = PROJECT / ".cache/three-way/odm/stock/etc/camera/camxoverridesettings.txt"
DEST = PROJECT / "builder/work/kyneos-camera-rotation-ab-20261017"
OUT = DEST / "POCO-F6-Camera-GPURotation-OFF-AB3-UNVERIFIED.zip"
STOCK_SHA = "9ca1ddd03029e30c8f1e261f149985a626c14dbd79c7476d8c58897883892da4"
LIVE_AB2_SHA = "098516ece81777b6e153b9db8eb3d43d302b81184876373345d21eb32155aefe"
CAM_PATH = "system/odm/etc/camera/camxoverridesettings.txt"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def derive() -> dict[str, bytes]:
    orig = STOCK.read_bytes()
    if sha(orig) != STOCK_SHA:
        raise ValueError("Official F6 ODM source changed; pin mismatch")
    baseline = orig
    for before, after in ((b"is3rdEISV2Enabled=TRUE", b"is3rdEISV2Enabled=FALSE"),
                          (b"enableTxtLogging=1", b"enableTxtLogging=0")):
        if baseline.count(before) != 1:
            raise ValueError(f"Missing original single flag: {before!r}")
        baseline = baseline.replace(before, after)
    if sha(baseline) != LIVE_AB2_SHA:
        raise ValueError("Source does not reproduce live AB2 camera config")
    if baseline.count(b"enableGPURotation=TRUE") != 1:
        raise ValueError("Missing unique GPU rotation setting")
    trial = baseline.replace(b"enableGPURotation=TRUE", b"enableGPURotation=FALSE")
    if trial.replace(b"enableGPURotation=FALSE", b"enableGPURotation=TRUE") != baseline:
        raise ValueError("Unexpected changes in camera trial")
    for critical in (b"enableHealthMonitor=FALSE", b"enable3rdAppPowerSave=TRUE"):
        if critical not in trial:
            raise ValueError("Camera safety/config invariant changed")
    prop = (b"id=kyneos_camera_3rdeis_ab\n"
            b"name=KyneOS Camera GPU Rotation A/B (EXPERIMENTAL)\n"
            b"version=0.3-ab\nversionCode=3\n"
            b"author=KyneOS\n"
            b"description=UNVERIFIED trial: EIS/logging already off; GPU rotation flag off, no other camera/thermal/policy changes.\n")
    installer = (b"#!/system/bin/sh\n"
                 b"dev=\"$(getprop ro.product.device)\"\n"
                 b"[ \"$dev\" = peridot ] || abort 'Wrong device'\n"
                 b"actual=\"$(sha256sum /odm/etc/camera/camxoverridesettings.txt | cut -d ' ' -f 1)\"\n"
                 + f"[ \"$actual\" = '{LIVE_AB2_SHA}' ] || abort 'Unexpected camera config; refuse trial'\n".encode()
                 + f"set_perm \"$MODPATH/{CAM_PATH}\" 0 0 0644\n".encode())
    readme = (b"EXPERIMENT ONLY: NOT INSTALLED. GPU rotation FALSE may break camera orientation or image handling.\n"
              b"The only change versus already-mounted AB2 is enableGPURotation=TRUE -> FALSE.\n"
              b"Requires controlled reboot and owner-verified outgoing Messenger video quality and orientation.\n"
              b"Roll back by reinstalling the prior AB2 ZIP, then reboot.\n"
              b"Thermal, SELinux, camera hardware library, service binaries, video codec unchanged.\n")
    return {"module.prop": prop, "customize.sh": installer, CAM_PATH: trial,
            "A-B-TEST-README.txt": readme}


def main() -> None:
    contents = derive()
    DEST.mkdir(parents=True, exist_ok=True)
    with ZipFile(OUT, "w") as archive:
        for name, data in contents.items():
            info = ZipInfo(name, (2026, 10, 17, 0, 0, 0))
            info.compress_type = ZIP_DEFLATED
            info.external_attr = ((0o100755 if name.endswith(".sh")
                                   else 0o100644) << 16)
            archive.writestr(info, data)
    with ZipFile(OUT) as archive:
        if archive.testzip() is not None or archive.namelist() != list(contents):
            raise ValueError("ZIP verification failed")
        if any(archive.read(k) != v for k, v in contents.items()):
            raise ValueError("Contents mismatch")
    receipt = {"status": "OFFLINE_AB_CANDIDATE_NOT_INSTALLED",
               "original_stock_sha256": STOCK_SHA, "live_ab2_sha256": LIVE_AB2_SHA,
               "trial_cam_config_sha256": sha(contents[CAM_PATH]),
               "zip_sha256": sha(OUT.read_bytes()), "zip": str(OUT),
               "only_delta_from_ab2": "enableGPURotation=TRUE -> FALSE",
               "requires_reboot": True, "validated_on_device": False}
    (DEST / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()
