#!/system/bin/sh
# Run-once conservative post-boot configuration. No daemons or background loops.
[ "$(getprop ro.product.device)" = peridot ] || exit 0
[ "$(getprop ro.build.version.sdk)" = 37 ] || exit 0
i=0
while [ "$(getprop sys.boot_completed)" != 1 ] && [ "$i" -lt 60 ]; do
  sleep 2
  i=$((i + 1))
done
[ "$(getprop sys.boot_completed)" = 1 ] || exit 0

# Only apply a user whitelist entry for a locally installed Messenger package.
if pm path com.facebook.orca >/dev/null 2>&1; then
  cmd deviceidle whitelist +com.facebook.orca >/dev/null 2>&1 || :
fi

# Keep the existing user's ANGLE driver overrides; append only if Chrome
# exists and is not already explicitly configured.
pm path com.android.chrome >/dev/null 2>&1 || exit 0
pkgs="$(settings get global angle_gl_driver_selection_pkgs 2>/dev/null)"
values="$(settings get global angle_gl_driver_selection_values 2>/dev/null)"
[ "$pkgs" = null ] && pkgs=
[ "$values" = null ] && values=
# Existing list shape must be consistent; never overwrite a broken/user list.
if [ -n "$pkgs" ] && [ -z "$values" ]; then exit 0; fi
if [ -z "$pkgs" ] && [ -n "$values" ]; then exit 0; fi
case ",$pkgs," in
  *,com.android.chrome,*) exit 0 ;;
esac
if [ -n "$pkgs" ]; then
  pkg_count="$(printf '%s' "$pkgs" | tr -cd ',' | wc -c)"
  val_count="$(printf '%s' "$values" | tr -cd ',' | wc -c)"
  [ "$pkg_count" = "$val_count" ] || exit 0
  pkgs="$pkgs,com.android.chrome"
  values="$values,angle"
else
  pkgs="com.android.chrome"
  values="angle"
fi
settings put global angle_gl_driver_selection_pkgs "$pkgs" 2>/dev/null || exit 0
settings put global angle_gl_driver_selection_values "$values" 2>/dev/null || exit 0
