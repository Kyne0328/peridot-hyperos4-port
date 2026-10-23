#!/usr/bin/env bash
set -euo pipefail

BASE=$HOME/peridot-resukisu-uapi5-v1
COMMON_SHA=0c3d559bcd85c64dae9c9c9687abbe5347fff3ad
RESUKISU_SHA=8770c7e324a22895703c4916b8a16520e0b81c79
SUSFS_SHA=24743360ea08d98f6ad72b856851abed8de5854f
SOURCE_COMMON=/mnt/c/Dev/peridot-hyperos4-port/.cache/resukisu-build/common
STOCK_CONFIG=/mnt/c/Dev/peridot-hyperos4-port/09-reports/resukisu-candidate/preflight-v1/stock.config
EXPECTED_RELEASE=6.1.138-android14-11-g0c3d559bcd85-ab14529422

if [[ -e "$BASE" ]]; then
  echo "Refusing to overwrite existing staging tree: $BASE" >&2
  exit 2
fi

mkdir -p "$BASE/common"
git -C "$BASE/common" init
git -C "$BASE/common" remote add origin "file://$SOURCE_COMMON"
git -C "$BASE/common" fetch --depth=1 origin "$COMMON_SHA"
git -C "$BASE/common" checkout --detach FETCH_HEAD
[[ "$(git -C "$BASE/common" rev-parse HEAD)" == "$COMMON_SHA" ]]

git -C "$BASE" init ReSukiSU
git -C "$BASE/ReSukiSU" remote add origin https://github.com/ReSukiSU/ReSukiSU.git
git -C "$BASE/ReSukiSU" fetch --depth=1 origin "$RESUKISU_SHA"
git -C "$BASE/ReSukiSU" checkout --detach FETCH_HEAD
[[ "$(git -C "$BASE/ReSukiSU" rev-parse HEAD)" == "$RESUKISU_SHA" ]]
grep -q 'KERNEL_SU_UAPI_VERSION = 5' "$BASE/ReSukiSU/uapi/supercall.h"

git -C "$BASE" init susfs4ksu
git -C "$BASE/susfs4ksu" remote add origin https://gitlab.com/simonpunk/susfs4ksu.git
git -C "$BASE/susfs4ksu" fetch --depth=1 origin "$SUSFS_SHA"
git -C "$BASE/susfs4ksu" checkout --detach FETCH_HEAD
[[ "$(git -C "$BASE/susfs4ksu" rev-parse HEAD)" == "$SUSFS_SHA" ]]

cd "$BASE/common"
ln -s ../../ReSukiSU/kernel drivers/kernelsu
grep -q 'obj-$(CONFIG_KSU) += kernelsu/' drivers/Makefile ||
  printf '\nobj-$(CONFIG_KSU) += kernelsu/\n' >> drivers/Makefile
grep -q 'source "drivers/kernelsu/Kconfig"' drivers/Kconfig ||
  sed -i '/endmenu/i source "drivers/kernelsu/Kconfig"' drivers/Kconfig

if grep -q 'You should use $(REPO_NAME) as a git submodule instead of copying code directly' "$BASE/ReSukiSU/kernel/Kbuild"; then
  sed -i 's/$(error You should use $(REPO_NAME) as a git submodule instead of copying code directly)/$(warning You should use $(REPO_NAME) as a git submodule instead of copying code directly)/' "$BASE/ReSukiSU/kernel/Kbuild"
fi

# The upstream Kbuild tries to fetch the complete ReSukiSU history from inside
# make when the checkout is shallow. This build is SHA-pinned and network-free
# after source acquisition. v4.2.0-rc3 is versionCode 35203; the selected commit
# is exactly 32 commits ahead, so its source-accurate code is 35235.
python3 - "$BASE/ReSukiSU/kernel/Kbuild" <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1])
s = p.read_text()
old = '''$(shell cd $(KSU_SRC); [ -f ../.git/shallow ] && $(GIT_BIN) fetch --unshallow)\nKSU_LOCAL_VERSION := $(shell cd $(KSU_SRC); $(GIT_BIN) rev-list --count HEAD)\nKSU_VERSION := $(shell expr 30000 + $(KSU_LOCAL_VERSION) + 700)'''
new = '''KSU_LOCAL_VERSION := 4535\nKSU_VERSION := 35235'''
if old not in s:
    raise SystemExit('ReSukiSU Kbuild version block changed')
p.write_text(s.replace(old, new, 1))
PY

grep -q '^KSU_VERSION := 35235$' "$BASE/ReSukiSU/kernel/Kbuild"

cp "$BASE/susfs4ksu/kernel_patches/fs/"* fs/
cp "$BASE/susfs4ksu/kernel_patches/include/linux/"* include/linux/
cp "$BASE/susfs4ksu/kernel_patches/50_add_susfs_in_gki-android14-6.1.patch" ./

# WildKernels' compatibility adjustment for Android 14 / 6.1 sublevels <= 141.
sed -i '/^#include <linux\/cpufreq_times.h>$/a #include <linux/dma-buf.h>' fs/proc/base.c
patch -p1 < 50_add_susfs_in_gki-android14-6.1.patch

mkdir -p "$BASE/out"
cp "$STOCK_CONFIG" "$BASE/out/.config"

scripts/config --file "$BASE/out/.config"   -e KSU   -d KSU_MULTI_MANAGER_SUPPORT   -e KSU_TOOLKIT_SUPPORT   -e KSU_SUSFS   -e KSU_SUSFS_SUS_PATH   -e KSU_SUSFS_SUS_MOUNT   -e KSU_SUSFS_SUS_KSTAT   -e KSU_SUSFS_SPOOF_UNAME   -e KSU_SUSFS_ENABLE_LOG   -e KSU_SUSFS_HIDE_KSU_SUSFS_SYMBOLS   -e KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG   -e KSU_SUSFS_SUS_MAP   -e KSU_SUSFS_OPEN_REDIRECT   -d LOCALVERSION_AUTO   --set-str LOCALVERSION ""

# Keep the stock module/kernel release contract despite the intentionally modified tree.
printf '%s\n' '-android14-11-g0c3d559bcd85-ab14529422' > .scmversion

make O="$BASE/out" ARCH=arm64 LLVM=1 olddefconfig

release="$(make -s O="$BASE/out" ARCH=arm64 LLVM=1 kernelrelease)"
echo "KERNEL_RELEASE=$release"
[[ "$release" == "$EXPECTED_RELEASE" ]]

grep -E '^(CONFIG_KSU=|CONFIG_KSU_TOOLKIT_SUPPORT=|CONFIG_KSU_MULTI_MANAGER_SUPPORT=|CONFIG_KSU_SUSFS=|CONFIG_KSU_SUSFS_SUS_PATH=|CONFIG_KSU_SUSFS_SUS_MOUNT=|CONFIG_KSU_SUSFS_SUS_KSTAT=|CONFIG_KSU_SUSFS_SPOOF_UNAME=|CONFIG_KSU_SUSFS_HIDE_KSU_SUSFS_SYMBOLS=|CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG=|CONFIG_KSU_SUSFS_SUS_MAP=|CONFIG_KSU_SUSFS_OPEN_REDIRECT=|CONFIG_MODVERSIONS=)' "$BASE/out/.config"

echo "COMMON_HEAD=$(git -C "$BASE/common" rev-parse HEAD)"
echo "RESUKISU_HEAD=$(git -C "$BASE/ReSukiSU" rev-parse HEAD)"
echo "SUSFS_HEAD=$(git -C "$BASE/susfs4ksu" rev-parse HEAD)"
echo "PREPARED=$BASE"
