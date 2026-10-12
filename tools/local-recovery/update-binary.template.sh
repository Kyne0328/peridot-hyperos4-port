#!/system/bin/sh
# Recovery-only installer. No host execution, formatting, firmware updates or AVB patches.
set -eu
set -o pipefail
PATH=/sbin:/system/bin:/system/xbin:/vendor/bin
export PATH
BB=/sbin/busybox
TB=/system/bin/toybox
BC=/system/bin/bootctl
OUTFD=$2
ZIPFILE=$3
PAYLOAD_ROOT=
TMP_DIR=
WRITES_STARTED=0
ui() { printf 'ui_print %s\nui_print\n' "$*" >&"$OUTFD"; }
abort() {
    ui "ERROR: $*"
    if [ "$WRITES_STARTED" = 1 ]; then
        ui "Writes began: installation is incomplete. Do not boot system or assume slot B is a rollback."
    else
        ui "Preflight failed before any partition writes."
    fi
    exit 1
}
cleanup() {
    case "$TMP_DIR" in /tmp/f6-dev2-ri1.*) "$BB" rm -rf "$TMP_DIR";; esac
}
trap cleanup EXIT
trap 'abort "Interrupted"' HUP INT TERM
[ "$#" = 3 ] || exit 1
case "$OUTFD" in ''|*[!0-9]*) exit 1;; esac
[ -x "$BB" ] && [ -x "$TB" ] && [ -x "$BC" ] || abort "Required crypto-recovery tools absent"
[ "$(getprop ro.product.device)" = peridot ] || abort "Device must be peridot"
[ "$(getprop ro.build.fox_id)" = e5499108-49b2-43cf-80c1-18a53db7a0fa ] || abort "Use the inspected OrangeFox R12.0 crypto build"
[ "$(getprop ro.boot.flash.locked)" = 0 ] || abort "Unlocked-state prerequisite not established"
[ "$(getprop ro.boot.vbmeta.device_state)" = unlocked ] || abort "Unlocked vbmeta state not established"
[ "$(getprop ro.boot.slot_suffix)" = _a ] || abort "This fixed-layout candidate requires current slot A"
[ "$("$BC" get-current-slot)" = 0 ] || abort "Boot HAL current slot must be A"
[ "$("$BC" get-active-boot-slot)" = 0 ] || abort "Boot HAL selected slot must already be A"
[ "$("$BC" get-number-slots)" = 2 ] || abort "Expected two boot slots"
[ "$("$BC" get-snapshot-merge-status)" = none ] || abort "Snapshot status must be known NONE; no merge/cancel performed"
[ -r "$ZIPFILE" ] && [ -f "$ZIPFILE" ] || abort "ZIP must remain accessible throughout installation"
# Bind tools to the supplied recovery; never use package-provided executables.
hash_file() { "$BB" sha256sum "$1" | "$BB" cut -d' ' -f1; }
[ "$(hash_file "$BB")" = 4d60ab3f5a59ebb2ca863f2f514e6924401b581e9b64f602665c008177626651 ] || abort "BusyBox bytes differ"
[ "$(hash_file "$TB")" = ba0b4037d260ab256464cb98ebfe9785c3c28c3dff9beb4920d4a3f5371a02bd ] || abort "Toybox bytes differ"
[ "$(hash_file "$BC")" = be618f8c9434c66c3a73fd309395bd1456d114afb048d1dd8e1a8c86b7b6a863 ] || abort "bootctl bytes differ"
"$BB" grep -q ' /metadata ' /proc/mounts || abort "Metadata must be readable to inspect snapshot files"
if [ -d /metadata/ota ] && [ -n "$("$BB" ls -A /metadata/ota)" ]; then
    abort "Metadata OTA state exists; clear it only through its supported lifecycle, not this installer"
fi
# Mounted userdata/Dynamic partitions can hold dm references to old super.
if "$BB" grep -Eq '^/dev/block/(mapper/|dm-)' /proc/mounts; then
    abort "Unmount userdata and all logical partitions; use external ZIP storage"
fi
case "$ZIPFILE" in /data/*|/sdcard/*|/storage/emulated/*)
    abort "Use external USB storage, not userdata";;
esac
PAYLOAD_ROOT=$("$BB" dirname "$ZIPFILE")
TMP_DIR=$("$BB" mktemp -d /tmp/f6-dev2-ri1.XXXXXX) || abort "Cannot create private recovery staging directory"
FREE_KB=$("$BB" df -Pk "$TMP_DIR" | "$BB" awk 'NR==2 {print $4}')
case "$FREE_KB" in ''|*[!0-9]*) abort "Unknown RAM staging capacity";; esac
[ "$FREE_KB" -ge 393216 ] || abort "Need at least 384 MiB free RAM staging space"
spec() {
cat <<'SPEC'
@SPEC@
SPEC
}
packs() {
cat <<'PACKS'
@PACKS@
PACKS
}
payload_path() {
    case "$1" in payload.[0-9][0-9][0-9].zip) ;; *) abort "Invalid payload archive name";; esac
    printf '%s/%s\n' "$PAYLOAD_ROOT" "$1"
}
firmware() {
cat <<'FW'
@FIRMWARE@
FW
}
writes() {
cat <<'WRITE'
@WRITES@
WRITE
}
node() {
    resolved=$("$BB" readlink -f "/dev/block/by-name/$1") || abort "Missing target $1"
    case "$resolved" in /dev/block/*) ;; *) abort "Unexpected target path";; esac
    [ -b "$resolved" ] || abort "Target $1 is not a block device"
    printf '%s\n' "$resolved"
}
prefix_hash() {
    # All physical images are sector aligned. BusyBox pipefail catches read errors.
    "$BB" dd if="$1" bs=512 count="$2" 2>/dev/null | "$BB" sha256sum | "$BB" cut -d' ' -f1
}
ui "F6 Global DEV2-RI1: recovery-only, no data migration, no automatic wipes."
ui "Checking every package member and target before writes; this may take several minutes."
spec > "$TMP_DIR/spec"
packs > "$TMP_DIR/packs"
firmware > "$TMP_DIR/firmware"
writes > "$TMP_DIR/writes"
# Hash every payload completely before the first write. ZIP CRC/read errors fail closed.
while read -r pack size digest; do
    file=$(payload_path "$pack") || abort "Invalid payload path"
    [ -f "$file" ] && [ -r "$file" ] || abort "Missing companion $pack"
    [ "$("$BB" stat -c %s "$file")" = "$size" ] || abort "Companion size mismatch"
    [ "$(hash_file "$file")" = "$digest" ] || abort "Companion checksum mismatch"
done < "$TMP_DIR/packs"
while read -r pack member size digest; do
    file=$(payload_path "$pack") || abort "Invalid payload path"
    got=$("$BB" unzip -p "$file" "$member" | "$BB" sha256sum | "$BB" cut -d' ' -f1) || abort "Cannot read $member"
    [ "$got" = "$digest" ] || abort "Payload hash mismatch: $member"
done < "$TMP_DIR/spec"
# Stage sizing and unique target identity checks.
: > "$TMP_DIR/targets"
SUPER=$(node super) || abort "Invalid shared super"
[ "$("$TB" blockdev --getsize64 "$SUPER")" = 9126805504 ] || abort "Super capacity mismatch"
printf '%s\n' "$SUPER" >> "$TMP_DIR/targets"
while read -r name size digest; do
    target=$(node "$name"_a) || abort "Missing slot-A firmware"
    capacity=$("$TB" blockdev --getsize64 "$target") || abort "Unknown firmware capacity"
    [ "$capacity" -ge "$size" ] || abort "Firmware capacity too small: $name"
    [ "$(prefix_hash "$target" "$((size / 512))")" = "$digest" ] || abort "Firmware must match exact Global OS3.0.303: $name"
    printf '%s\n' "$target" >> "$TMP_DIR/targets"
done < "$TMP_DIR/firmware"
while read -r name size digest; do
    target=$(node "$name"_a) || abort "Missing slot-A boot/metadata target"
    capacity=$("$TB" blockdev --getsize64 "$target") || abort "Unknown target capacity"
    [ "$capacity" -ge "$size" ] || abort "Image exceeds target: $name"
    printf '%s\n' "$target" >> "$TMP_DIR/targets"
done < "$TMP_DIR/writes"
[ -z "$("$BB" sort "$TMP_DIR/targets" | "$BB" uniq -d)" ] || abort "Partition aliases overlap"
# No changing slots, rollback values, mount verification, firmware, userdata or metadata.
ui "Preflight passed. Shared super will be replaced; no untouched-ROM slot rollback exists."
WRITES_STARTED=1
seek_mb=0
while read -r pack member size digest; do
    file=$(payload_path "$pack") || abort "Invalid payload path"
    case "$member" in super/*)
        "$BB" unzip -p "$file" "$member" > "$TMP_DIR/chunk" || abort "Chunk extraction failed"
        [ "$(hash_file "$TMP_DIR/chunk")" = "$digest" ] || abort "Chunk changed after preflight"
        "$BB" dd if="$TMP_DIR/chunk" of="$SUPER" bs=1048576 seek="$seek_mb" conv=notrunc || abort "Super write failed"
        "$TB" sync || abort "Sync failed"
        got=$("$BB" dd if="$SUPER" bs=1048576 skip="$seek_mb" count="$((size / 1048576))" 2>/dev/null | "$BB" sha256sum | "$BB" cut -d' ' -f1) || abort "Super readback failed"
        [ "$got" = "$digest" ] || abort "Super readback mismatch"
        seek_mb=$((seek_mb + size / 1048576))
        "$BB" rm -f "$TMP_DIR/chunk"
        ui "Super checked through MiB $seek_mb / 8704"
    ;; esac
done < "$TMP_DIR/spec"
[ "$seek_mb" = 8704 ] || abort "Super coverage incomplete"
# Signed vbmeta_system and top-level vbmeta are deliberately last.
while read -r name size digest; do
    target=$(node "$name"_a) || abort "Target disappeared"
    file=$("$BB" awk -v m="images/$name.img" '$2 == m {print $1}' "$TMP_DIR/spec")
    file=$(payload_path "$file") || abort "Missing image pack mapping"
    "$BB" unzip -p "$file" "images/$name.img" > "$TMP_DIR/image" || abort "Image extraction failed"
    [ "$(hash_file "$TMP_DIR/image")" = "$digest" ] || abort "Image changed after preflight"
    "$BB" dd if="$TMP_DIR/image" of="$target" bs=1048576 conv=notrunc || abort "Image write failed: $name"
    "$TB" sync || abort "Sync failed"
    [ "$(prefix_hash "$target" "$((size / 512))")" = "$digest" ] || abort "Image readback mismatch: $name"
    "$BB" rm -f "$TMP_DIR/image"
    ui "Verified $name on slot A"
done < "$TMP_DIR/writes"
ui "All writes/readbacks completed. Slot remains A; userdata/metadata were not formatted."
ui "Stock DEV2 recovery restored on A; supplied OrangeFox is NOT permanently integrated."
ui "Read INSTALL-PREREQUISITES.txt before any reboot. Boot/FBE are untested."
exit 0
