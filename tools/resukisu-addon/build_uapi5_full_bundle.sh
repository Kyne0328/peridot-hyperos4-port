#!/usr/bin/env bash
set -euo pipefail

# Rebuild the existing working ReSukiSU UAPI-5 + SUSFS POCO F6 kernel with the
# complete WildKernels toggleable feature bundle. The known-good UAPI5 tree is
# treated as immutable input; all additional work happens in a new staging tree.

SRC=/home/kyne/peridot-resukisu-uapi5
BASE=/home/kyne/peridot-resukisu-uapi5-fullbundle-20261004
COMMON="$BASE/common"
OUT="$BASE/out-fullbundle"
PUBLIC_OUT=/mnt/c/Dev/peridot-hyperos4-port/builder/work/resukisu-uapi5-fullbundle-20261004
STOCK_PUBLIC=/mnt/c/Dev/peridot-hyperos4-port/.cache/resukisu-uapi5-finalize/stock-module-public.pem
EXPECTED_RELEASE=6.1.138-android14-11-g0c3d559bcd85-ab14529422
STOCK_LOCALVERSION=-android14-11-g0c3d559bcd85-ab14529422

COMMON_SHA=0c3d559bcd85c64dae9c9c9687abbe5347fff3ad
RESUKISU_SHA=8770c7e324a22895703c4916b8a16520e0b81c79
SUSFS_SHA=24743360ea08d98f6ad72b856851abed8de5854f
WILDKERNELS_SHA=e0ecd61219baaa0c3eae821246e31136302fd0dc
KERNEL_PATCHES_SHA=41ae18b35d20e0c6ac04116785a4a1089528ae94
BBG_SHA=a54e0dc6cf0aff4dd87fec49644a02d2eb612905
DROIDSPACES_SHA=ac38c11fef1402c0db8172ea8187db0401a0bc30
NOMOUNT_SHA=5fac312b143e632e483c3c8b9ab325b6d4527314

FEATURE_SET='SUSFS+NoMount+BBG+NET+DS+NTSync+Ptrace+Unicode+BPF+Perf'

die() { echo "ERROR: $*" >&2; exit 1; }
stage() { printf '\n==== %s ====\n' "$*"; }
clone_pin() {
  local url="$1" dst="$2" sha="$3"
  git clone --no-checkout "$url" "$dst"
  git -C "$dst" fetch --depth=1 origin "$sha"
  git -C "$dst" checkout --detach "$sha"
  [[ "$(git -C "$dst" rev-parse HEAD)" == "$sha" ]] || die "pin mismatch: $dst"
}
apply_patch_file() {
  local file="$1" label="$2"
  echo "[patch] $label <- $file"
  patch -p1 --forward < "$file"
}

[[ -d "$SRC/common" ]] || die "Known-good UAPI5 source tree missing: $SRC"
[[ -s "$SRC/out-uapi5/arch/arm64/boot/Image" ]] || die "Known-good UAPI5 Image missing"
[[ -s "$SRC/out-uapi5/.config" ]] || die "Known-good UAPI5 config missing"
[[ -s "$STOCK_PUBLIC" ]] || die "Stock module public certificate missing"
[[ ! -e "$BASE" ]] || die "Refusing to overwrite staging tree: $BASE"
[[ ! -e "$PUBLIC_OUT" ]] || die "Refusing to overwrite output directory: $PUBLIC_OUT"

stage "Clone preserved UAPI5 source state"
mkdir -p "$BASE"
for tree in common ReSukiSU susfs4ksu; do
  [[ -d "$SRC/$tree" ]] || die "Required preserved source tree missing: $SRC/$tree"
  if command -v rsync >/dev/null 2>&1; then
    rsync -a "$SRC/$tree/" "$BASE/$tree/"
  else
    cp -a "$SRC/$tree" "$BASE/$tree"
  fi
done

[[ "$(git -C "$COMMON" rev-parse HEAD)" == "$COMMON_SHA" ]] || die "common source pin mismatch"
[[ "$(git -C "$BASE/ReSukiSU" rev-parse HEAD)" == "$RESUKISU_SHA" ]] || die "ReSukiSU pin mismatch"
[[ "$(git -C "$BASE/susfs4ksu" rev-parse HEAD)" == "$SUSFS_SHA" ]] || die "SUSFS pin mismatch"
grep -q 'KERNEL_SU_UAPI_VERSION = 5' "$BASE/ReSukiSU/uapi/supercall.h" || die "ReSukiSU is not UAPI 5"

mkdir -p "$OUT" "$PUBLIC_OUT"
cp "$SRC/out-uapi5/.config" "$OUT/.config"

stage "Acquire exact WildKernels bundle sources"
mkdir -p "$BASE/deps"
clone_pin https://github.com/WildKernels/GKI_KernelSU_SUSFS.git "$BASE/deps/WildKernels" "$WILDKERNELS_SHA"
clone_pin https://github.com/WildKernels/kernel_patches.git "$BASE/deps/kernel_patches" "$KERNEL_PATCHES_SHA"
clone_pin https://github.com/vc-teahouse/Baseband-guard.git "$BASE/deps/Baseband-guard" "$BBG_SHA"
clone_pin https://github.com/ravindu644/Droidspaces-OSS.git "$BASE/deps/Droidspaces-OSS" "$DROIDSPACES_SHA"
clone_pin https://github.com/maxsteeel/nomount.git "$BASE/deps/nomount" "$NOMOUNT_SHA"

cd "$COMMON"

stage "Baseband Guard"
clone_pin https://github.com/vc-teahouse/Baseband-guard.git "$COMMON/Baseband-guard" "$BBG_SHA"
sh "$BASE/deps/Baseband-guard/setup.sh" "$BBG_SHA"
sed -i '/^config LSM$/,/^help$/{ /^[[:space:]]*default/ { /baseband_guard/! s/selinux/selinux,baseband_guard/ } }' security/Kconfig

stage "Networking + BBRv3"
apply_patch_file "$BASE/deps/kernel_patches/common/bbrv3/0001-net-tcp-backport-BBRv3-to-android14-6.1.patch" "BBRv3 android14-6.1"

stage "DroidSpaces"
apply_patch_file "$BASE/deps/Droidspaces-OSS/Documentation/resources/kernel-patches/GKI/below-kernel-6.12/001.GKI-below-6.12-fix_sysvipc_kabi_6_7_8.patch" "DroidSpaces SYSVIPC kABI"

stage "NTSync"
apply_patch_file "$BASE/deps/kernel_patches/common/ntsync/ntsync_compat_android14-6.1.patch" "NTSync compatibility"
apply_patch_file "$BASE/deps/kernel_patches/common/ntsync/ntsync_base.patch" "NTSync base"

stage "Ptrace"
# WildKernels only applies the ptrace compatibility patch to kernels <= 5.16.
# 6.1 is intentionally a no-op for this feature toggle.
echo "Ptrace toggle enabled; WildKernels rule skips patch on kernel 6.1."

stage "Unicode"
apply_patch_file "$BASE/deps/kernel_patches/common/unicode_bypass_fix_6.1+.patch" "Unicode fix 6.1+"

stage "Performance"
PERF_PATCHES=(
  optimized_mem_operations.patch
  file_struct_8bytes_align.patch
  reduce_cache_pressure.patch
  mem_opt_prefetch.patch
  optimise_memcmp.patch
  minimise_wakeup_time.patch
  int_sqrt.patch
  reduce_gc_thread_sleep_time.patch
  add_timeout_wakelocks_globally.patch
  f2fs_reduce_congestion.patch
  reduce_freeze_timeout.patch
)
for p in "${PERF_PATCHES[@]}"; do
  apply_patch_file "$BASE/deps/kernel_patches/common/$p" "Perf/$p"
done

FILE=drivers/base/power/wakeup.c
if grep -q '^void pm_system_wakeup(void)' "$FILE" &&    sed -n '/^void pm_system_wakeup(void)/,/^}/p' "$FILE" | grep -q 'suspend_abort_fs_sync();'; then
  sed -i '/^void pm_system_wakeup(void)/,/^}/{/suspend_abort_fs_sync();/d}' "$FILE"
fi
patch -p1 -F3 --forward < "$BASE/deps/kernel_patches/common/avoid_extra_s2idle_wake_attempts.patch"
patch -p1 -F3 --forward < "$BASE/deps/kernel_patches/common/disable_cache_hot_buddy.patch"
patch -p1 -F3 --forward < "$BASE/deps/kernel_patches/common/f2fs_enlarge_min_fsync_blocks.patch"
patch -p1 -F3 --forward < "$BASE/deps/kernel_patches/common/increase_ext4_default_commit_age.patch"
patch -p1 -F3 --forward < "$BASE/deps/kernel_patches/common/increase_sk_mem_packets.patch"
patch -p1 -F3 --forward < "$BASE/deps/kernel_patches/common/reduce_pci_pme_wakeups.patch"
patch -p1 -F3 --forward < "$BASE/deps/kernel_patches/common/silence_irq_cpu_logspam.patch"
patch -p1 -F3 --forward < "$BASE/deps/kernel_patches/common/silence_system_logspam.patch"
# 6.1 is > 5.16, matching WildKernels' __pi_clear_page branch.
sed -e 's/SYM_FUNC_START_PI(clear_page)/SYM_FUNC_START_PI(__pi_clear_page)/'   "$BASE/deps/kernel_patches/common/clear_page_16bytes_align.patch" | patch -p1 -F3 --forward

stage "NoMount"
clone_pin https://github.com/maxsteeel/nomount.git "$COMMON/NoMount" "$NOMOUNT_SHA"
sh "$BASE/deps/nomount/kernel/setup.sh" "$NOMOUNT_SHA"
[[ -L fs/nomount ]] || die "NoMount symlink missing"

stage "Kernel configuration"
CFG="$COMMON/scripts/config"
"$CFG" --file "$OUT/.config"   -e BBG   -e IP_SET --set-val IP_SET_MAX 65534   -e IP_SET_BITMAP_IP -e IP_SET_BITMAP_IPMAC -e IP_SET_BITMAP_PORT   -e IP_SET_HASH_IP -e IP_SET_HASH_IPMARK -e IP_SET_HASH_IPPORT   -e IP_SET_HASH_IPPORTIP -e IP_SET_HASH_IPPORTNET -e IP_SET_HASH_IPMAC   -e IP_SET_HASH_MAC -e IP_SET_HASH_NETPORTNET -e IP_SET_HASH_NET   -e IP_SET_HASH_NETNET -e IP_SET_HASH_NETPORT -e IP_SET_HASH_NETIFACE   -e IP_SET_LIST_SET -e NETFILTER_XT_MATCH_ADDRTYPE -e NETFILTER_XT_SET   -e NETFILTER_XT_TARGET_LOG -e NETFILTER_XT_MATCH_RECENT   -e IP6_NF_NAT -e IP6_NF_TARGET_MASQUERADE   -e TCP_CONG_ADVANCED -e TCP_CONG_BBR -e TCP_CONG_CUBIC -e TCP_CONG_BIC   -e TCP_CONG_WESTWOOD -e TCP_CONG_HTCP -e DEFAULT_BBR --set-str DEFAULT_TCP_CONG bbr   -e TCP_CONG_BBR3   -e NET_SCH_FQ -e NET_SCH_FQ_CODEL -e NET_SCH_CAKE   -e NET_ACT_CONNMARK -e IP_NF_TARGET_TTL -e IP6_NF_TARGET_HL -e IP6_NF_MATCH_HL   -e WIREGUARD   -e CIFS -e NETWORK_FILESYSTEMS -e NETFS_SUPPORT -e KEYS -e CIFS_XATTR -e CIFS_POSIX   -e PID_NS -e SYSVIPC -e POSIX_MQUEUE -e IPC_NS -e DEVTMPFS   -e BINFMT_MISC -e BINFMT_SCRIPT -e BINFMT_ELF -e USER_NS   -e NTSYNC   -e DEBUG_INFO_BTF -e BPF_EVENTS -e KPROBE_EVENTS -e UPROBES -e UPROBE_EVENTS   -e FUSE_FS -e BPF_SYSCALL -e FUSE_BPF   -e NOMOUNT   -d LOCALVERSION_AUTO --set-str LOCALVERSION ""

# Preserve the stock module trust contract used by the working UAPI5 candidate.
cp "$STOCK_PUBLIC" certs/peridot-stock-public.pem
"$CFG" --file "$OUT/.config" --set-str SYSTEM_TRUSTED_KEYS certs/peridot-stock-public.pem

# Ensure BBG is actually in the selected LSM string, not merely in Kconfig's default.
CURRENT_LSM="$(sed -n 's/^CONFIG_LSM="\(.*\)"/\1/p' "$OUT/.config")"
if [[ -n "$CURRENT_LSM" && ",$CURRENT_LSM," != *",baseband_guard,"* ]]; then
  "$CFG" --file "$OUT/.config" --set-str LSM "$CURRENT_LSM,baseband_guard"
fi

# Keep the exact stock kernel release contract.
printf '%s\n' '-android14-11-g0c3d559bcd85-ab14529422' > .scmversion

make O="$OUT" ARCH=arm64 LLVM=1 LLVM_IAS=1 LOCALVERSION="$STOCK_LOCALVERSION" olddefconfig

stage "Validate final feature configuration"
required_y=(
  KSU KSU_SUSFS BBG
  IP_SET TCP_CONG_BBR TCP_CONG_BBR3 NET_SCH_FQ NET_SCH_FQ_CODEL NET_SCH_CAKE
  WIREGUARD CIFS
  PID_NS SYSVIPC POSIX_MQUEUE IPC_NS USER_NS
  NTSYNC DEBUG_INFO_BTF BPF_EVENTS KPROBE_EVENTS UPROBES UPROBE_EVENTS
  FUSE_FS BPF_SYSCALL FUSE_BPF NOMOUNT
  MODVERSIONS MODULE_SIG_PROTECT CFI_CLANG
)
for key in "${required_y[@]}"; do
  grep -q "^CONFIG_${key}=y$" "$OUT/.config" || die "required config disabled after olddefconfig: CONFIG_${key}"
done
grep -q '^CONFIG_DEFAULT_TCP_CONG="bbr"$' "$OUT/.config" || die "default TCP congestion is not bbr"
grep -q '^CONFIG_SYSTEM_TRUSTED_KEYS="certs/peridot-stock-public.pem"$' "$OUT/.config" || die "stock trusted key path changed"
grep -q '^CONFIG_LSM=.*baseband_guard' "$OUT/.config" || die "baseband_guard missing from CONFIG_LSM"
grep -q 'KERNEL_SU_UAPI_VERSION = 5' "$BASE/ReSukiSU/uapi/supercall.h" || die "UAPI version changed"

release="$(make -s O="$OUT" ARCH=arm64 LLVM=1 LLVM_IAS=1 LOCALVERSION="$STOCK_LOCALVERSION" kernelrelease)"
[[ "$release" == "$EXPECTED_RELEASE" ]] || die "kernel release mismatch: $release"

stage "Build full-bundle Image"
make O="$OUT" ARCH=arm64 LLVM=1 LLVM_IAS=1 LOCALVERSION="$STOCK_LOCALVERSION" -j8 Image

[[ -s "$OUT/arch/arm64/boot/Image" ]] || die "Image not produced"
[[ -s "$OUT/vmlinux.symvers" ]] || die "vmlinux.symvers not produced"

stage "Publish immutable build evidence"
cp "$OUT/arch/arm64/boot/Image" "$PUBLIC_OUT/Image"
cp "$OUT/.config" "$PUBLIC_OUT/kernel.config"
cp "$OUT/vmlinux.symvers" "$PUBLIC_OUT/vmlinux.symvers"
git -C "$COMMON" status --short > "$PUBLIC_OUT/common-status.txt"
sha256sum "$PUBLIC_OUT/Image" "$PUBLIC_OUT/kernel.config" "$PUBLIC_OUT/vmlinux.symvers" > "$PUBLIC_OUT/SHA256SUMS.txt"

python3 - "$PUBLIC_OUT" "$BASE" "$release" "$FEATURE_SET" <<'PY'
import hashlib, json, pathlib, subprocess, sys
out = pathlib.Path(sys.argv[1])
base = pathlib.Path(sys.argv[2])
release = sys.argv[3]
features = sys.argv[4]

def sha(p):
    return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()

def head(path):
    return subprocess.check_output(["git","-C",str(path),"rev-parse","HEAD"], text=True).strip()

receipt = {
    "schema_version": 1,
    "status": "kernel-build-complete",
    "device": "peridot",
    "kernel_release": release,
    "feature_set": features,
    "features": features.split("+"),
    "resukisu_uapi_version": 5,
    "source_pins": {
        "common": head(base/"common"),
        "resukisu": head(base/"ReSukiSU"),
        "susfs": head(base/"susfs4ksu"),
        "wildkernels": head(base/"deps/WildKernels"),
        "kernel_patches": head(base/"deps/kernel_patches"),
        "baseband_guard": head(base/"deps/Baseband-guard"),
        "droidspaces": head(base/"deps/Droidspaces-OSS"),
        "nomount": head(base/"deps/nomount"),
    },
    "image": {"path": str(out/"Image"), "sha256": sha(out/"Image"), "bytes": (out/"Image").stat().st_size},
    "kernel_config": {"path": str(out/"kernel.config"), "sha256": sha(out/"kernel.config")},
    "vmlinux_symvers": {"path": str(out/"vmlinux.symvers"), "sha256": sha(out/"vmlinux.symvers")},
    "ptrace": {"toggle_enabled": True, "patch_applied": False, "reason": "WildKernels skips ptrace compatibility patch for kernel 6.1 (> 5.16)"},
    "base_uapi5_tree_preserved": True,
    "device_flash_performed": False,
}
(out/"build-receipt.json").write_text(json.dumps(receipt, indent=2, sort_keys=True)+"\n")
print(json.dumps(receipt, indent=2))
PY

echo "FULL_BUNDLE_BUILD_COMPLETE=$PUBLIC_OUT"
