# KyneOS camera thermal policy

A minimal KernelSU module for the POCO F6 / peridot Android 17 HyperOS 4 port.

## Evidence

The live kernel audit on 2026-10-14, with SELinux enforcing, repeatedly denied `hal_camera_default` the `read` permission and, after live `read` was permitted, the `open` permission on a `sysfs_poweraware` `file` named `temp_aware`. The Qualcomm camera provider concurrently logged `get TempAware failed` and thermal warnings during Messenger video calling. The live KernelSU rule parser accepted and applied the two individual read/open rules successfully.

## Scope

Only `allow hal_camera_default sysfs_poweraware file { open read }`. No wildcard domains or broad permissions, no permissive SELinux state, no changes to thermal thresholds, kernel, or system partitions. The host Android SELinux policy build is not modified. Requires KernelSU module sepolicy rule support. The live policy patch for the current boot was applied separately.

## Validation

Check `getenforce` remains `Enforcing`; while the camera runs, inspect *new* kernel AVC logs for `temp_aware` and vendor camera logs for `get TempAware failed`. Compare CPU and memory pressure under matched workloads. Do not infer that policy success fixes all overheating, call load, or unrelated application exceptions.

## Uninstall

Disable/uninstall the `kyneos_camera_thermal` module in KernelSU and reboot. Removing the module only removes the supplemental boot-time rule; it cannot undo an already-applied live rule until reboot.
