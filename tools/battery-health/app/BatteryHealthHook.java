package io.kyne.batteryhealth;

import android.content.Context;
import android.os.Bundle;
import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;
import java.io.BufferedReader;
import java.io.FileReader;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Only adds read-only UI. No health gates, charge policy or stored values are overridden. */
public final class BatteryHealthHook implements IXposedHookLoadPackage {
    private static final String TARGET = "com.miui.securitycenter";
    private static final String TAG = "kyneos_battery_health";
    private static final ExecutorService IO = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "KyneOS-BatteryHealth"); t.setDaemon(true); return t;
    });

    @Override public void handleLoadPackage(XC_LoadPackage.LoadPackageParam p) {
        if (!TARGET.equals(p.packageName) || !"peridot".equals(android.os.Build.DEVICE)) return;
        try {
            Class<?> protection = XposedHelpers.findClass("com.miui.powercenter.nightcharge.ChargeProtectFragment", p.classLoader);
            XposedHelpers.findAndHookMethod(protection, "onCreatePreferences", Bundle.class, String.class, new XC_MethodHook() {
                @Override protected void afterHookedMethod(MethodHookParam param) { addPreferences(param.thisObject, p.classLoader); }
            });
            XposedBridge.log("KyneOSBatteryHealth: protection-only hook installed for " + p.processName);
        } catch (Throwable e) { error(e); }
    }
    private static void error(Throwable e) { XposedBridge.log("KyneOSBatteryHealth: " + e); }
    private static String file(String node) {
        try (BufferedReader r = new BufferedReader(new FileReader("/sys/class/power_supply/battery/" + node))) {
            return r.readLine();
        } catch (Exception e) { return null; }
    }
    private static String gauge(ClassLoader loader, String node) {
        try {
            Class<?> c = XposedHelpers.findClass("miui.util.IMiCharge", loader);
            Object charge = XposedHelpers.callStaticMethod(c, "getInstance");
            Object s = XposedHelpers.callMethod(charge, "getMiChargePath", node);
            return s instanceof String ? (String) s : null;
        } catch (Throwable e) { return null; }
    }
    private static Reading read(ClassLoader loader) {
        String full = file("charge_full"), cycles = file("cycle_count");
        if (full == null) full = gauge(loader, "fg1_fcc");
        if (cycles == null) cycles = gauge(loader, "fg1_cycle");
        return new Reading(gauge(loader, "fg1_soh"), full, file("charge_full_design"), cycles);
    }
    private static void addPreferences(Object fragment, ClassLoader loader) {
        try {
            Object screen = XposedHelpers.callMethod(fragment, "getPreferenceScreen");
            Context c = (Context) XposedHelpers.callMethod(fragment, "getContext");
            if (screen == null || c == null) return;
            Object group = XposedHelpers.callMethod(screen, "findPreference", TAG);
            if (group == null) {
                Class<?> categoryClass = XposedHelpers.findClass("androidx.preference.PreferenceCategory", loader);
                group = XposedHelpers.newInstance(categoryClass, c);
                XposedHelpers.callMethod(group, "setKey", TAG);
                XposedHelpers.callMethod(group, "setTitle", (CharSequence) "Battery health");
                XposedHelpers.callMethod(group, "setOrder", -100);
                XposedHelpers.callMethod(screen, "addPreference", group);
                String[] titles = {"Maximum capacity", "Full-charge capacity", "Design capacity", "Charge cycles"};
                Class<?> prefClass = XposedHelpers.findClass("androidx.preference.Preference", loader);
                for (int i = 0; i < titles.length; i++) {
                    Object pref = XposedHelpers.newInstance(prefClass, c);
                    XposedHelpers.callMethod(pref, "setKey", TAG + "_" + i);
                    XposedHelpers.callMethod(pref, "setTitle", (CharSequence) titles[i]);
                    XposedHelpers.callMethod(pref, "setPersistent", false);
                    XposedHelpers.callMethod(pref, "setSelectable", false);
                    XposedHelpers.callMethod(pref, "setSummary", (CharSequence) "Reading battery…");
                    XposedHelpers.callMethod(group, "addPreference", pref);
                }
            }
            Object destination = group;
            IO.execute(() -> {
                Reading r = read(loader);
                new android.os.Handler(android.os.Looper.getMainLooper()).post(() -> {
                    try {
                        if (XposedHelpers.callMethod(fragment, "getContext") == null) return;
                        String[] values = {r.health(), r.capacity(r.full), r.capacity(r.design), r.cycles()};
                        for (int i = 0; i < values.length; i++) {
                            Object pref = XposedHelpers.callMethod(destination, "findPreference", TAG + "_" + i);
                            if (pref != null) XposedHelpers.callMethod(pref, "setSummary", (CharSequence) values[i]);
                        }
                        XposedBridge.log("KyneOSBatteryHealth: settings " + r.health() + " cycles=" + r.cycles);
                    } catch (Throwable e) { error(e); }
                });
            });
        } catch (Throwable e) { error(e); }
    }
}
