package io.kyne.deviceresetfix;

import java.util.Arrays;
import java.util.Collections;

public final class ScopePlanTest {
    private static void check(boolean ok) { if (!ok) throw new AssertionError(); }
    public static void main(String[] args) {
        ScopePlan p = ScopePlan.between(Arrays.asList("android", "com.mcdonalds.mobileapp"),
                Arrays.asList("com.mcdonalds.mobileapp", "com.example.probe", "com.example.probe"));
        check(p.add.equals(Collections.singleton("com.example.probe")));
        check(p.remove.equals(Collections.singleton("android")));
        p = ScopePlan.between(Collections.singleton("com.example.probe"), Collections.emptySet());
        check(p.add.isEmpty() && p.remove.equals(Collections.singleton("com.example.probe")));
        p = ScopePlan.between(Collections.singleton("com.example.probe"), Collections.singleton("com.example.probe"));
        check(p.add.isEmpty() && p.remove.isEmpty());
        for (String bad : Arrays.asList("x;reboot", "com.example/999", "../com.example", "", null)) {
            try { ScopePlan.packageName(bad); throw new AssertionError("Accepted invalid target"); }
            catch (IllegalArgumentException expected) { }
        }
        check(ScopePlan.quote("a'b").equals("'a'\\''b'"));
        System.out.println("Scope delta and input safety contracts passed");
    }
}
