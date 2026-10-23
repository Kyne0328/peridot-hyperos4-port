#!/usr/bin/env bash
set -euo pipefail

BASE=$HOME/peridot-resukisu-uapi5-v1
COMMON="$BASE/common"
OUT="$BASE/out"
LOG="$BASE/build.log"
EXPECTED_RELEASE=6.1.138-android14-11-g0c3d559bcd85-ab14529422
export LOCALVERSION=-android14-11-g0c3d559bcd85-ab14529422
COMMON_SHA=0c3d559bcd85c64dae9c9c9687abbe5347fff3ad
RESUKISU_SHA=8770c7e324a22895703c4916b8a16520e0b81c79
SUSFS_SHA=24743360ea08d98f6ad72b856851abed8de5854f

[[ -d "$COMMON/.git" && -f "$OUT/.config" ]]
[[ "$(git -C "$COMMON" rev-parse HEAD)" == "$COMMON_SHA" ]]
[[ "$(git -C "$BASE/ReSukiSU" rev-parse HEAD)" == "$RESUKISU_SHA" ]]
[[ "$(git -C "$BASE/susfs4ksu" rev-parse HEAD)" == "$SUSFS_SHA" ]]
grep -q 'KERNEL_SU_UAPI_VERSION = 5' "$BASE/ReSukiSU/uapi/supercall.h"

cd "$COMMON"

make O="$OUT" ARCH=arm64 LLVM=1 olddefconfig

release="$(make -s O="$OUT" ARCH=arm64 LLVM=1 kernelrelease)"
echo "KERNEL_RELEASE=$release"
[[ "$release" == "$EXPECTED_RELEASE" ]]

required_yes=(
  CONFIG_KSU
  CONFIG_KSU_TOOLKIT_SUPPORT
  CONFIG_KSU_SUSFS
  CONFIG_KSU_SUSFS_SUS_PATH
  CONFIG_KSU_SUSFS_SUS_MOUNT
  CONFIG_KSU_SUSFS_SUS_KSTAT
  CONFIG_KSU_SUSFS_SPOOF_UNAME
  CONFIG_KSU_SUSFS_ENABLE_LOG
  CONFIG_KSU_SUSFS_HIDE_KSU_SUSFS_SYMBOLS
  CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
  CONFIG_KSU_SUSFS_SUS_MAP
  CONFIG_KSU_SUSFS_OPEN_REDIRECT
  CONFIG_MODVERSIONS
)
for option in "${required_yes[@]}"; do
  grep -q "^${option}=y$" "$OUT/.config" || {
    echo "Required config missing: ${option}=y" >&2
    exit 3
  }
done
grep -q '^# CONFIG_KSU_MULTI_MANAGER_SUPPORT is not set$' "$OUT/.config"

# Reproduce Kleaf's combined GKI KMI whitelist: base list plus all OEM additions.
# This preserves CONFIG_TRIM_UNUSED_KSYMS rather than widening the exported ABI.
cat "$COMMON/android/abi_gki_aarch64" "$COMMON"/android/abi_gki_aarch64_* |
  python3 /mnt/c/Dev/peridot-hyperos4-port/.cache/resukisu-build/build/kernel/abi/flatten_symbol_list.py |
  sort -u > "$COMMON/abi_symbollist.raw"
[[ -s "$COMMON/abi_symbollist.raw" ]]
echo "ABI_SYMBOLLIST_SHA256=$(sha256sum "$COMMON/abi_symbollist.raw" | awk '{print $1}')"
echo "ABI_SYMBOLLIST_COUNT=$(wc -l < "$COMMON/abi_symbollist.raw")"

jobs="$(nproc)"
if (( jobs > 8 )); then jobs=8; fi
echo "BUILD_JOBS=$jobs"
echo "BUILD_LOG=$LOG"

export KBUILD_BUILD_TIMESTAMP="Thu Jun 5 04:20:00 UTC 2025"
export KBUILD_BUILD_USER="android-build"
export KBUILD_BUILD_HOST="peridot-uapi5"

if ! make -j"$jobs" O="$OUT" ARCH=arm64 LLVM=1 Image >"$LOG" 2>&1; then
  echo "BUILD_FAILED"
  tail -n 160 "$LOG"
  exit 4
fi

IMAGE="$OUT/arch/arm64/boot/Image"
[[ -s "$IMAGE" ]]
image_sha="$(sha256sum "$IMAGE" | awk '{print $1}')"
image_size="$(stat -c %s "$IMAGE")"
banner="$(strings "$IMAGE" | grep -m1 '^Linux version 6\.1\.138-android14-11-g0c3d559bcd85-ab14529422' || true)"
[[ -n "$banner" ]]

echo "BUILD_OK"
echo "IMAGE=$IMAGE"
echo "IMAGE_BYTES=$image_size"
echo "IMAGE_SHA256=$image_sha"
echo "BANNER=$banner"
echo "RESUKISU_UAPI=5"
echo "RESUKISU_HEAD=$RESUKISU_SHA"
echo "SUSFS_HEAD=$SUSFS_SHA"
