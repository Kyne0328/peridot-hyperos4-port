package io.kyne.batteryhealth;

import java.util.Locale;

public final class ReadingTest {
    private static void check(boolean b, String message) { if (!b) throw new AssertionError(message); }
    public static void main(String[] args) {
        Locale.setDefault(Locale.US);
        Reading actual = new Reading("83", "4194000", "5000000", "1360");
        check(actual.health().equals("83%"), "Prefer gauge SOH over the capacity ratio");
        check(actual.capacity(actual.full).equals("4,194 mAh"), "Convert microamp-hours to mAh");
        check(actual.cycles().equals("1,360"), "Use the reported cycles without rescaling");
        Reading absent = new Reading(null, "error", "0", "-1");
        check(absent.health().equals("Unavailable"), "Do not invent 100% for missing data");
        check(absent.capacity(absent.full).equals("Unavailable"), "Invalid capacity");
        check(absent.cycles().equals("Unavailable"), "Invalid cycle count");
        Reading fallback = new Reading("0", "4194000", "5000000", "0");
        check(fallback.health().equals("83.9% (capacity estimate)"), "Clearly label a ratio fallback");
        check(fallback.cycles().equals("0"), "Zero cycles is a valid reading");
        check(new Reading("101", "6000000", "5000000", "100001").health().equals("Unavailable"), "Reject out-of-range data");
        check(new Reading(" 83\n", "4194000\n", "5000000\n", "1360\n").health().equals("83%"), "Accept sysfs line endings");
        System.out.println("Reading contracts passed");
    }
}
