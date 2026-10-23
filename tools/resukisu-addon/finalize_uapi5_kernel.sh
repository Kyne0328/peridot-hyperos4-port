#!/usr/bin/env bash
set -euo pipefail
BASE=$HOME/peridot-resukisu-uapi5
COMMON="$BASE/common"
OUT="$BASE/out-uapi5"
PUBLIC=/mnt/c/Dev/peridot-hyperos4-port/.cache/resukisu-uapi5-finalize/stock-module-public.pem
[[ "$(git -C "$COMMON" rev-parse HEAD)" == 0c3d559bcd85c64dae9c9c9687abbe5347fff3ad ]]
[[ "$(git -C "$BASE/ReSukiSU" rev-parse HEAD)" == 8770c7e324a22895703c4916b8a16520e0b81c79 ]]
grep -q 'KERNEL_SU_UAPI_VERSION = 5' "$BASE/ReSukiSU/uapi/supercall.h"
test -s "$PUBLIC"
test -s "$OUT/arch/arm64/boot/Image"
# Preserve the prior candidate before the small public-trust configuration change.
mkdir -p "$BASE/trust-finalize-evidence"
test ! -e "$BASE/trust-finalize-evidence/Image-before"
cp "$OUT/arch/arm64/boot/Image" "$BASE/trust-finalize-evidence/Image-before"
cp "$OUT/.config" "$BASE/trust-finalize-evidence/config-before"
cp "$PUBLIC" "$COMMON/certs/peridot-stock-public.pem"
"$COMMON/scripts/config" --file "$OUT/.config" --set-str SYSTEM_TRUSTED_KEYS certs/peridot-stock-public.pem
make -C "$COMMON" O="$OUT" ARCH=arm64 LLVM=1 LLVM_IAS=1 LOCALVERSION= olddefconfig
grep -q '^CONFIG_MODULE_SIG_PROTECT=y$' "$OUT/.config"
grep -q '^CONFIG_CFI_CLANG=y$' "$OUT/.config"
grep -q '^CONFIG_MODVERSIONS=y$' "$OUT/.config"
[[ "$(cat "$OUT/include/config/kernel.release")" == 6.1.138-android14-11-g0c3d559bcd85-ab14529422 ]]
make -C "$COMMON" O="$OUT" ARCH=arm64 LLVM=1 LLVM_IAS=1 LOCALVERSION= -j8 Image
sha256sum "$OUT/arch/arm64/boot/Image"
