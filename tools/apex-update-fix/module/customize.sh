#!/system/bin/sh
# Installation guard: this fix is scoped to the POCO F6 Android 17 port.
DEVICE="$(getprop ro.product.device)"
SDK="$(getprop ro.build.version.sdk)"
if [ "$DEVICE" != "peridot" ]; then
    abort "UPDATE-001: wrong device ($DEVICE); POCO F6/peridot only."
fi
if [ "$SDK" != "37" ]; then
    abort "UPDATE-001: Android 17 (SDK 37) required; found $SDK."
fi
ui_print "- UPDATE-001: applying apexd.config.use_fiemap=false"
ui_print "- No filesystem images, AVB, SELinux or userdata are modified by this module."
ui_print "- Reboot required; then verify APEX services and retry the Play system update."
