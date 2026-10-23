# Post-RI8 performance and root addon source

Code under tools/performance represents measured investigations and targeted
experiments, not confirmed ROM-wide fixes.

- kyneos_call_stability_boot: systemless Messenger Doze/ANGLE settings helper.
  Post-boot call-quality acceptance testing remains incomplete.
- kyneos_gpu_telemetry: narrow SELinux GPU-clock read telemetry policy;
  it changes neither GPU clocks nor global thermal safeguards.
- kyneos_camera_eis_ab: camera experiments; the GPU rotation candidate was
  created but not successfully verified on a sustained real-device call.
- vendor_seccomp_fix.py: earlier systemless repair for the vendor seccomp
  policies; the two underlying rules are built into RI8.
- mglru_postcall_ab.py: reversible memory experiment; confounded by Xiaomi
  UMMS kill/reclaim activity, defaults restored, no proven performance gain.

ReSukiSU/SUSFS and Play Integrity/keybox configuration are not integrated into
RI8. Preserve private keys, device logs, proprietary ROM images, and local
device credentials outside this public repository.
