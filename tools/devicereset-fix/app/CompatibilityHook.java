package io.kyne.deviceresetfix;

import android.app.Application;
import android.app.Instrumentation;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.os.Build;
import android.provider.Settings;
import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XC_MethodReplacement;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import org.json.JSONArray;
import org.json.JSONObject;

/** Compatibility repairs run in the original module's root-authorized process. */
public final class CompatibilityHook implements IXposedHookLoadPackage {
    private static final String MODULE = "io.github.gjr787878.devicereset";
    private static final String TARGET = "com.mcdonalds.mobileapp";
    private static final String PREFIX = "io.github.gjr787878.devicereset.";
    private static final String CLI = "/data/adb/lspd/cli --json ";
    private static final String TAG = "DeviceResetFix";
    private static final Object SCOPE_LOCK = new Object();

    private static void log(String value) { XposedBridge.log(TAG + ": " + value); }

    @Override public void handleLoadPackage(XC_LoadPackage.LoadPackageParam p) {
        if (TARGET.equals(p.packageName)) { installProbe(p); return; }
        if (!MODULE.equals(p.packageName)) return;
        try {
            Class<?> root = XposedHelpers.findClass(PREFIX + "RootScopeManager", p.classLoader);
            Class<?> config = XposedHelpers.findClass(PREFIX + "Config", p.classLoader);
            Class<?> activity = XposedHelpers.findClass(PREFIX + "ui.MainActivity", p.classLoader);
            XposedHelpers.findAndHookMethod(root, "readScope", new XC_MethodReplacement() {
                @Override protected Object replaceHookedMethod(MethodHookParam param) {
                    try { return scope(root); }
                    catch (Throwable e) { log("scope read failed: " + e); return null; }
                }
            });
            XposedHelpers.findAndHookMethod(root, "syncScope", Set.class, new XC_MethodReplacement() {
                @Override protected Object replaceHookedMethod(MethodHookParam param) {
                    return sync(root, (Set<String>) param.args[0]);
                }
            });
            XposedHelpers.findAndHookMethod(config, "syncScopeToLSPosed", Context.class, Set.class,
                    new XC_MethodReplacement() {
                @Override protected Object replaceHookedMethod(MethodHookParam param) {
                    Context ctx = (Context) param.args[0];
                    boolean ok = sync(root, (Set<String>) param.args[1]);
                    XposedHelpers.callStaticMethod(config, "setScopeSyncPending", ctx, !ok);
                    return null;
                }
            });
            // Fallback uses the same supported API instead of assuming a SQLite schema.
            XposedHelpers.findAndHookMethod(config, "readLSPosedDbState", Context.class,
                    new XC_MethodReplacement() {
                @Override protected Object replaceHookedMethod(MethodHookParam param) {
                    try {
                        Object state = XposedHelpers.newInstance(XposedHelpers.findClass(PREFIX + "Config$ScopeDbState", p.classLoader));
                        Set<String> current = scope(root);
                        JSONArray modules = cli(root, "modules ls").getJSONArray("data");
                        boolean enabled = false;
                        for (int i = 0; i < modules.length(); i++) {
                            JSONObject row = modules.getJSONObject(i);
                            if (MODULE.equals(row.getString("PACKAGE"))) enabled = "enabled".equals(row.getString("STATUS"));
                        }
                        XposedHelpers.setBooleanField(state, "dbOk", true);
                        XposedHelpers.setBooleanField(state, "enabled", enabled);
                        XposedHelpers.setBooleanField(state, "hasSystem", current.contains("android"));
                        XposedHelpers.setBooleanField(state, "hasSelf", current.contains(MODULE));
                        current.remove("android"); current.remove(MODULE);
                        XposedHelpers.setObjectField(state, "targets", current);
                        return state;
                    } catch (Throwable e) { log("fallback read failed: " + e); return null; }
                }
            });
            XposedHelpers.findAndHookMethod(activity, "writeIdentityFile", String.class, String.class,
                    new XC_MethodReplacement() {
                @Override protected Object replaceHookedMethod(MethodHookParam param) throws Throwable {
                    writeIdentity(root, (Context) param.thisObject, (String) param.args[0], (String) param.args[1], false);
                    return null;
                }
            });
            XposedHelpers.findAndHookMethod(activity, "writeExternalIdentityFile", String.class, String.class,
                    new XC_MethodReplacement() {
                @Override protected Object replaceHookedMethod(MethodHookParam param) throws Throwable {
                    writeIdentity(root, (Context) param.thisObject, (String) param.args[0], (String) param.args[1], true);
                    return null;
                }
            });
            XposedHelpers.findAndHookMethod(activity, "readIdentityFile", String.class,
                    new XC_MethodReplacement() {
                @Override protected Object replaceHookedMethod(MethodHookParam param) {
                    try {
                        String pkg = ScopePlan.packageName((String) param.args[0]);
                        userZeroTarget((Context) param.thisObject, pkg);
                        String internal = "/data/user/0/" + pkg + "/files/.identity_sentinel";
                        String external = "/data/media/0/Android/data/" + pkg + "/files/.identity_sentinel";
                        String value = runIdentity("if [ -f " + ScopePlan.quote(internal) + " ]; then cat " +
                                ScopePlan.quote(internal) + "; elif [ -f " + ScopePlan.quote(external) +
                                " ]; then cat " + ScopePlan.quote(external) + "; fi");
                        return value.startsWith("{") ? value : null;
                    } catch (Throwable e) { log("identity read failed: " + e); return null; }
                }
            });
            XposedHelpers.findAndHookMethod(activity, "deleteIdentityFiles", String.class,
                    new XC_MethodReplacement() {
                @Override protected Object replaceHookedMethod(MethodHookParam param) throws Throwable {
                    String pkg = ScopePlan.packageName((String) param.args[0]);
                    userZeroTarget((Context) param.thisObject, pkg);
                    StringBuilder command = new StringBuilder("rm -f");
                    for (String directory : new String[]{"/data/user/0/" + pkg + "/files",
                            "/data/media/0/Android/data/" + pkg + "/files"}) {
                        command.append(" ").append(ScopePlan.quote(directory + "/.identity_sentinel"));
                        command.append(" ").append(ScopePlan.quote(directory + "/.identity_runtime"));
                    }
                    runIdentity(command.toString());
                    log("selected target identity removed from canonical paths, pkg=" + pkg);
                    return null;
                }
            });
            log("management repairs installed in " + p.processName);
        } catch (Throwable e) { log("installation failed: " + e); }
    }

    private static String run(Class<?> root, String command) {
        Object result = XposedHelpers.callStaticMethod(root, "runRoot", command);
        int code = XposedHelpers.getIntField(result, "exitCode");
        String output = (String) XposedHelpers.getObjectField(result, "output");
        if (code != 0) throw new IllegalStateException("Root command failed, exit=" + code);
        return output;
    }

    private static JSONObject cli(Class<?> root, String command) throws Exception {
        JSONObject result = new JSONObject(run(root, CLI + command));
        if (!result.getBoolean("success")) throw new IllegalStateException("Vector rejected command");
        return result;
    }

    /** App mount views can retain masked paths or pre-reset package directories. */
    private static String runIdentity(String command) throws Exception {
        Process process = new ProcessBuilder("su", "-M").redirectErrorStream(true).start();
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        Thread reader = new Thread(() -> {
            try (InputStream input = process.getInputStream()) {
                byte[] buffer = new byte[4096];
                int count;
                while ((count = input.read(buffer)) >= 0) output.write(buffer, 0, count);
            } catch (Exception ignored) { }
        }, "DeviceReset-IdentityRoot");
        reader.setDaemon(true);
        reader.start();
        try {
            try (OutputStream input = process.getOutputStream()) {
                input.write((command + "\nexit\n").getBytes(StandardCharsets.UTF_8));
            }
            if (!process.waitFor(30, TimeUnit.SECONDS))
                throw new IllegalStateException("Identity root operation timed out");
            reader.join(3000);
            if (reader.isAlive()) throw new IllegalStateException("Identity root output incomplete");
            if (process.exitValue() != 0)
                throw new IllegalStateException("Identity root operation failed, exit=" + process.exitValue());
            return new String(output.toByteArray(), StandardCharsets.UTF_8).trim();
        } finally {
            process.destroy();
            if (process.isAlive()) process.destroyForcibly();
        }
    }

    private static Set<String> scope(Class<?> root) throws Exception {
        JSONArray rows = cli(root, "scope ls " + MODULE).getJSONArray("data");
        Set<String> result = new LinkedHashSet<>();
        for (int i = 0; i < rows.length(); i++) {
            JSONObject row = rows.getJSONObject(i);
            if (row.getInt("USER_ID") == 0) result.add(ScopePlan.packageName(row.getString("APP_PACKAGE")));
        }
        log("scope read via Vector CLI, user0 count=" + result.size());
        return result;
    }

    private static boolean sync(Class<?> root, Set<String> desired) {
        synchronized (SCOPE_LOCK) {
            try {
                ScopePlan plan = ScopePlan.between(scope(root), desired);
                cli(root, "modules enable " + MODULE);
                // Edit only explicit package/user pairs. Do not overwrite other users' scopes.
                for (String pkg : plan.add) cli(root, "scope add " + MODULE + " " + pkg + "/0");
                for (String pkg : plan.remove) cli(root, "scope rm " + MODULE + " " + pkg + "/0");
                boolean ok = scope(root).equals(desired);
                log("scope sync via Vector CLI, verified=" + ok);
                return ok;
            } catch (Throwable e) { log("scope sync failed: " + e); return false; }
        }
    }

    private static void writeIdentity(Class<?> root, Context context, String pkg, String json, boolean external) throws Exception {
        ScopePlan.packageName(pkg);
        JSONObject identity = new JSONObject(json);
        if (identity.optString("androidId").isEmpty()) throw new IllegalArgumentException("Missing saved identity");
        ApplicationInfo info = userZeroTarget(context, pkg);
        String dir, parent, owner, modes;
        if (external) {
            parent = "/data/media/0/Android/data/" + pkg;
            dir = parent + "/files";
            owner = info.uid + ":ext_data_rw";
            modes = "chmod 2770 " + ScopePlan.quote(parent) + " " + ScopePlan.quote(dir) + "\n";
        } else {
            // Android app-data isolation masks /data/data with a per-process tmpfs.
            // The explicit user directory is the target's actual backing directory.
            parent = "/data/user/0/" + pkg;
            dir = parent + "/files";
            owner = info.uid + ":" + info.uid;
            modes = "chmod 771 " + ScopePlan.quote(dir) + "\n";
        }
        String file = dir + "/.identity_sentinel";
        String owned = (external ? ScopePlan.quote(parent) + " " : "") + ScopePlan.quote(dir) + " " + ScopePlan.quote(file);
        String command = "set -e\nmkdir -p " + ScopePlan.quote(dir) + "\nprintf '%s' " + ScopePlan.quote(json) +
                " > " + ScopePlan.quote(file) + "\nchown " + owner + " " + owned + "\n" + modes +
                "chmod 600 " + ScopePlan.quote(file) + "\nrestorecon -F " + owned + "\n";
        runIdentity(command);
        log("identity saved with target ownership and label, external=" + external + " pkg=" + pkg);
    }

    private static ApplicationInfo userZeroTarget(Context context, String pkg) throws Exception {
        ApplicationInfo info = context.getPackageManager().getApplicationInfo(pkg, 0);
        if (info.uid / 100000 != 0 || android.os.Process.myUid() / 100000 != 0)
            throw new IllegalStateException("This compatibility build supports user0 only");
        if (!info.dataDir.equals("/data/user/0/" + pkg) && !info.dataDir.equals("/data/data/" + pkg))
            throw new IllegalStateException("Unexpected app data directory");
        return info;
    }

    /** Read-only functional probe, scoped to the owner's requested target. */
    private static void installProbe(XC_LoadPackage.LoadPackageParam p) {
        if (!TARGET.equals(p.processName) && !p.processName.startsWith(TARGET + ":")) return;
        XposedHelpers.findAndHookMethod(Instrumentation.class, "callApplicationOnCreate", Application.class,
                new XC_MethodHook() {
            @Override protected void afterHookedMethod(MethodHookParam param) {
                try {
                    Application app = (Application) param.args[0];
                    String json = new String(Files.readAllBytes(new java.io.File(app.getFilesDir(), ".identity_sentinel").toPath()), StandardCharsets.UTF_8);
                    JSONObject expected = new JSONObject(json);
                    String actual = Settings.Secure.getString(app.getContentResolver(), Settings.Secure.ANDROID_ID);
                    boolean idMatch = expected.getString("androidId").equals(actual);
                    boolean modelMatch = expected.getString("model").equals(Build.MODEL);
                    byte[] digest = MessageDigest.getInstance("SHA-256").digest(actual.getBytes(StandardCharsets.UTF_8));
                    StringBuilder hash = new StringBuilder();
                    for (byte b : digest) hash.append(String.format("%02x", b & 255));
                    log("observed process=" + p.processName + " androidIdMatches=" + idMatch +
                            " modelMatches=" + modelMatch + " androidIdSha256=" + hash);
                } catch (Throwable e) { log("observation unavailable in " + p.processName + ": " + e); }
            }
        });
    }
}
