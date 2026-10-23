#!/bin/sh
# No ADB or host system settings touched; test boot integration with mocks.
set -eu
base="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

run_case() (
    pkgs="$1"
    vals="$2"
    product="$3"
    log="$4"
    : > "$log"
    getprop() {
        case "$1" in
          ro.product.device) printf '%s\n' "$product";;
          ro.build.version.sdk) printf '37\n';;
          sys.boot_completed) printf '1\n';;
          *) printf '\n';;
        esac
    }
    pm() { [ "$1" = path ] && return 0; return 1; }
    cmd() { printf 'CMD %s\n' "$*" >> "$log"; }
    settings() {
        if [ "$1" = get ]; then
            case "$3" in
              angle_gl_driver_selection_pkgs) printf '%s\n' "$pkgs";;
              angle_gl_driver_selection_values) printf '%s\n' "$vals";;
            esac
        elif [ "$1" = put ]; then
            printf 'PUT %s=%s\n' "$3" "$4" >> "$log"
        fi
    }
    . "$base/service.sh"
)

run_case 'com.android.angle,com.android.chrome' 'angle,angle' peridot "$tmp/exists"
grep -q '^CMD deviceidle whitelist +com.facebook.orca$' "$tmp/exists"
if grep -q '^PUT ' "$tmp/exists"; then echo 'FAIL: changed existing Chrome choice'; exit 1; fi

run_case 'com.android.angle' 'angle' peridot "$tmp/append"
grep -q '^PUT angle_gl_driver_selection_pkgs=com.android.angle,com.android.chrome$' "$tmp/append"
grep -q '^PUT angle_gl_driver_selection_values=angle,angle$' "$tmp/append"

run_case 'com.android.angle,another.app' 'angle' peridot "$tmp/malformed"
if grep -q '^PUT ' "$tmp/malformed"; then echo 'FAIL: changed malformed user list'; exit 1; fi

run_case 'com.android.angle' 'angle' madrid "$tmp/wrong"
if [ -s "$tmp/wrong" ]; then echo 'FAIL: changed wrong device'; exit 1; fi

run_case 'com.android.chrome' 'native' peridot "$tmp/user_choice"
if grep -q '^PUT ' "$tmp/user_choice"; then echo 'FAIL: changed explicit user backend'; exit 1; fi

printf '%s\n' 'PASS: 5 mocked boot integration cases'
