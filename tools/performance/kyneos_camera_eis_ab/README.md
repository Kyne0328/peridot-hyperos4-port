# KyneOS POCO F6: Third-party EIS A/B camera-processing experiment

Status: **INSTALLED IN KERNELSU PENDING REBOOT**, 2026-10-15. No phone restart or app interruption during the live video call. **NOT YET PROVEN TO FIX LAG**.

## Why this test exists
- The user reports video-call lag on both stock HyperOS and custom HyperOS4.
- On a live Messenger call the Qualcomm camera provider used roughly 143-146% of one CPU core while Messenger itself used 78-95%.
- The Xiaomi phone thermal profile 5 restricted CPU3 and CPU7 maxima to 787.2 MHz while virtual thermal sensor reached ~45-46.5 C.
- The phone was charging via USB, battery ~43.4-43.8 C. CPU PSI was high; 8s snapshot memory PSI full stayed below 0.5% with ~1.8GiB MemAvailable.
- The original peridot ODM camxoverridesettings.txt from retained **stock firmware** and active ROM match SHA256 9ca1ddd03029e30c8f1e261f149985a626c14dbd79c7476d8c58897883892da4 and include is3rdEISV2Enabled=TRUE and enable3rdAppPowerSave=TRUE.
- The hypothesis is that eliminating third-party electronic video stabilization may reduce vendor camera processing workload, and the phone may respond better during prolonged calls. **There is no direct proof that Messenger uses the EISv2 path**. It could have zero effect or reduce video stability in other third-party apps.

## Exactly what is changed
An optional KernelSU magic-mount module replaces only one line in the ORIGINAL ODM camera config (the remaining 7045 original bytes are equivalent after reversing that substitution):

  is3rdEISV2Enabled=TRUE -> is3rdEISV2Enabled=FALSE

The prepared target file is 7046 bytes, SHA256 7526d8325a7b6d820ea643cce0a58d93833f10381a8b9124d25c23639f738a53. No other original config lines changed, no thermal scene files touched, and KernelSU installer had an explicit stock SHA-256 and POCO F6 device gate.

The KernelSU module is kyneos_camera_3rdeis_ab, zipped artifact:
builder/work/kyneos-camera-eis-ab-20261015/POCO-F6-KyneOS-Camera-ThirdPartyEIS-OFF-AB-20261015.zip
archive SHA256 5172875ffa826eddd44a1be73e67c7e7d68907ac8724851d9686f70ed1bac0fc.

Module builder:
tools/performance/kyneos_camera_eis_ab/build.py
Receipt:
builder/work/kyneos-camera-eis-ab-20261015/A-B-TEST-RECEIPT.json

## Device installation and current state
Ran adb push, then ksud module install with success:
  Installing to /data/adb/modules_update/kyneos_camera_3rdeis_ab
  Handle partition /odm
  Module installed successfully!

Post-install:
- Live /odm/etc/camera/camxoverridesettings.txt SHA256 still original 9ca1ddd0..., proving no immediate mount.
- Pending KernelSU file SHA256 7526d832..., exactly the single-line trial file.
- Messenger camera1 client PID14374 remained active; no call interruption.
- SELinux remains Enforcing, thermal scenario remains 5; neither changed.
- The KernelSU magic mount should activate on **NEXT REBOOT**, not during the current call.

## October 15 post-reboot finding: systemless mount was NOT activated

The phone rebooted, and KernelSU reports this trial as enabled/mountable,
but the visible ODM camera file still has stock SHA256 `9ca1ddd0...`.
The trial bytes are correctly present inside the module with SHA256
`7526d832...`. No installed KernelSU module declares `metamodule=1` or
`metamodule=true`, and the camera provider shares the init mount namespace
where `/odm` is still the original EROFS mount. KernelSU v4.2 uses
**metamodules** for file overlays; without a compatible one, a normal module's
`system/` files are not mounted. Consult https://kernelsu.org/guide/metamodule.html.

Therefore the October 15 post-reboot call is NOT a valid EIS-off trial.
**Do not claim this module improved or worsened camera performance.** Adding a
metamodule can activate other installed modules and change system-wide boot
behavior. This was not done while the user remained on a call. The verifier
now checks and reports this missing prerequisite.

## After compatible mount support and another controlled reboot: validate and A/B test
1. Check the actual ODM config file hash:
   adb shell sha256sum /odm/etc/camera/camxoverridesettings.txt
   A successful overlay should read 7526d8325a7b6d820ea643cce0a58d93833f10381a8b9124d25c23639f738a53. If it remains 9ca1ddd..., the module is not active; do NOT claim a fix.
2. Compare Messenger call video-on with similarly long prior calls under comparable ambient light, charger status, brightness, battery and workload.
3. Capture the existing read-only video profile:
   python tools/performance/capture_call_pipeline.py --label video --seconds 8
   Compare CamX FPS, camera-provider CPU%, CPU PSI, temp, CPU limits, HWC mode; prioritize sustained user experience rather than a single top sample.
4. Re-enable stabilization (rollback):
   adb shell ksud module disable kyneos_camera_3rdeis_ab
   REBOOT to undo the systemless file overlay. Uninstall through KernelSU instead if no longer needed.

If video image stabilization visibly degrades, camera breaks, or thermals get worse, disable it and reboot. Retain all stock thermal safeguards. The experiment could not be tested end to end without interrupting the user's ongoing video call, which was intentionally avoided.

## Further high-value investigation if no improvement
- Determine if the front camera's ~10fps/100ms exposure is lighting related versus sensor/ISP mode restrictions.
- Identify the outgoing encoder actually selected by Messenger WebRTC (not just hardware DECODERS).
- Trace camera provider CPU-heavy threads/active EIS nodes and camera/perf hints; avoid full logcat under heavy call.
- Verify the system-selected thermal phone scenario is appropriate and safely compare official scene settings. Do not force frequencies/disable throttling.
- OEM hardware limitations or defective thermal hardware are possible, but not established from these logs; the reproduced stock-ROM symptoms make port-only root cause unlikely.
