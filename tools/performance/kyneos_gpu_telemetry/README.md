# KyneOS GPU clock telemetry policy (POCO F6)

## Exact repair

The running OS4.0.0.9.XPCMIXM build records `ThermalCollector` in the `system_app` domain receiving `avc: denied { read }` for the GPU `gpuclk` sysfs node labeled `vendor_sysfs_kgsl_gpuclk`. The underlying sysfs node is world-readable at the DAC layer, so SELinux is the blocking policy. This module supplies **one scoped read-only SELinux allow**, with no write/execute permission, no change to service contexts, and no change to thermal or GPU clocks.

```
allow system_app vendor_sysfs_kgsl_gpuclk file { open read getattr }
```

This is a telemetry access repair, **not a fix for Chrome EGL, QESD, Messenger memory management, camera frame rate, or global thermal throttling**. The single system_app SELinux domain includes other privileged apps; a separate package-specific domain would require source-level policy/app-label rework. There is no blanket `sysfs`, `default_android_service`, or permissive rule.

## Building and deploying

Run `python tools/performance/kyneos_gpu_telemetry/build.py` from the workspace root. The deterministic ZIP is emitted into `builder/work/gpu-telemetry-policy-20261017`, is systemless, and is installed with KernelSU's `ksud module install`. No change is active until KernelSU's next boot policy application. Do not interrupt an active Messenger camera call to restart.

After an authorized reboot, verify: `getenforce` remains `Enforcing`; `ls -Z /sys/devices/platform/soc/3d00000.qcom,kgsl-3d0/kgsl/kgsl-3d0/gpuclk` shows `vendor_sysfs_kgsl_gpuclk`; and fresh ThermalCollector sampling no longer causes that specific AVC. Confirm camera/video-call quality and no new denials.

To roll back: `su -c '/data/adb/ksu/bin/ksud module disable kyneos_gpuclk_telemetry'` followed by reboot. Module installation alone must not be reported as a runtime validation.

## Security verification

The build script requires an exact rule whitelist and rejects `permissive`, policy globals, write/execute permissions, and symlink traversal. It records SHA-256 and ZIP membership. `sepolicy.rule` is the sole policy payload, preserving prior camera-thermal and seccomp addons.
