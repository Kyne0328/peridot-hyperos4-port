# KyneOS RI8 release status

Target: POCO F6 (peridot), Global HyperOS 4 / Android 17.
Build date: October 14, 2026.

**State:** full 32-image package passed offline SHA-256, archive, native installer
pin and OTA signature validation; **physical-device flash and boot are untested**.
Do not treat this as a verified safe-to-flash release.

RI8 adds the lseek: 1 seccomp rule to vendor/etc/seccomp_policy/atfwd@2.0.policy
and vendor/etc/seccomp_policy/qesdksec.policy, then refreshes the vendor AVB
metadata and native recovery-installer checksum pins. RI7.3 screen recorder
framework changes carry forward but Messenger call-audio capture is unverified.

The ROM deliberately does **not** bundle ReSukiSU, SUSFS, WildKernels or other
root addons. Normal full-ROM boot, init_boot and vendor_boot images can replace
an installed custom kernel. Compatible root/kernel addons must be managed
separately after installing the ROM.

Final RI8 ZIP: KyneOS-Global-HyperOS4-POCO-F6-RI8-20261014.zip
Size: 8,868,523,381 bytes.
SHA-256: 3f3bc4b80069e2cbe79a26c1b48bd6e81eca0ad12b29e8eaa90e7b9845a7b94c

Source entry points: tools/kyneos/ri8_repack_vendor.py,
ri8_assemble_vendor.py, ri8_build_full_native.py, ri8_package_full.py,
and ri8_verify_full.py.

These historical scripts have workspace-specific input paths. A rebuild needs
the original verified base ROMs, matching image assets, Android toolchain and
authorized signing environment. Some disposable local intermediates have been
cleaned; publishing source does not prove a fresh rebuild is turnkey.

Open: charging HAL integration; missing Qualcomm/Xiaomi service registrations;
SystemUI ANRs; video-call CPU/memory pressure and thermals; Chrome EGL crashes;
and long-term Play Integrity behavior. These are not solved by RI8.
