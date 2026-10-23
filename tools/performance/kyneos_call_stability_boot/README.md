# KyneOS call stability boot integration

This KernelSU service module re-applies two **previously validated** user-scoped
settings without modifying ROM images. It is not a camera performance/thermal
tweak. It runs only once after boot, is device/SDK gated, and does not keep a
resident process. It does not access audio or video content.

* Adds Android Doze user whitelist entry for installed Messenger.
* Preserves existing ANGLE package driver selections. If Chrome has no entry,
  appends `com.android.chrome=angle` without changing other package values.
* Does not override a manually configured Chrome entry, including a different
  backend. Does not write inconsistent/malformed driver selection lists.
* No memory threshold, camera stream, thermal cap, SELinux, CPU scheduler,
  encoder, or system service changes.

Source: `tools/performance/kyneos_call_stability_boot`.
Reproducible artifact: `builder/work/call-stability-boot-20261017/KyneOS-CallStability-Boot-20261017.zip`.
Build: `python tools/performance/kyneos_call_stability_boot/build.py`.
Install using KernelSU; it takes effect only after the next reboot.
The user's current active Messenger call must not be interrupted to apply it.
It may increase battery use by exempting Messenger from Doze; this does not
block Xiaomi's user-invoked OneKeyClean Clear all. To roll back: use
`ksud module disable kyneos_call_stability_boot` and reboot; the Doze user
whitelist entry can separately be removed with
`adb shell cmd deviceidle whitelist -com.facebook.orca`. Existing ANGLE settings
should not be removed without independently restoring the user's prior list.

Post-boot validation:
`adb shell cmd deviceidle whitelist`,
`adb shell settings get global angle_gl_driver_selection_pkgs`,
`adb shell settings get global angle_gl_driver_selection_values`,
`adb shell getenforce`, Chrome repeated launches, Messenger long call, PiP,
camera orientation, audio stability, thermal PSI and frame timing.

This module is intentionally a small ROM integration layer, not proof that
camera-call CPU/UMMS performance bottlenecks have been resolved.
