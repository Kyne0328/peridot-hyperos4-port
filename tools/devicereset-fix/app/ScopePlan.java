package io.kyne.deviceresetfix;

import java.util.Collection;
import java.util.Set;
import java.util.TreeSet;

/** Incremental user-zero scope edits preserve other users and unrelated modules. */
public final class ScopePlan {
    public final Set<String> add = new TreeSet<>();
    public final Set<String> remove = new TreeSet<>();

    public static String packageName(String value) {
        if (value == null || !(value.equals("android") ||
                value.matches("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z0-9_]+)+"))) {
            throw new IllegalArgumentException("Invalid package name");
        }
        return value;
    }

    public static ScopePlan between(Collection<String> current, Collection<String> desired) {
        if (current == null || desired == null) throw new IllegalArgumentException("Missing scope");
        ScopePlan plan = new ScopePlan();
        Set<String> oldSet = new TreeSet<>(), newSet = new TreeSet<>();
        for (String value : current) oldSet.add(packageName(value));
        for (String value : desired) newSet.add(packageName(value));
        plan.add.addAll(newSet); plan.add.removeAll(oldSet);
        plan.remove.addAll(oldSet); plan.remove.removeAll(newSet);
        return plan;
    }

    public static String quote(String value) {
        return "'" + value.replace("'", "'\\''") + "'";
    }
}
