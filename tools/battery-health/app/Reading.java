package io.kyne.batteryhealth;

import java.util.Locale;

/** Values are gauge telemetry; missing/invalid readings must never become 100%. */
public final class Reading {
    public final long soh, full, design, cycles;
    public Reading(String soh, String full, String design, String cycles) {
        this.soh = bounded(soh, 1, 100);
        this.full = bounded(full, 100000, 100000000);
        this.design = bounded(design, 100000, 100000000);
        this.cycles = bounded(cycles, 0, 100000);
    }
    private static long bounded(String s, long min, long max) {
        try {
            long n = Long.parseLong(s == null ? "" : s.trim());
            return n >= min && n <= max ? n : -1;
        } catch (NumberFormatException e) { return -1; }
    }
    public String health() {
        if (soh > 0) return soh + "%";
        if (full > 0 && design > 0 && full <= design)
            return String.format(Locale.getDefault(), "%.1f%% (capacity estimate)", 100.0 * full / design);
        return "Unavailable";
    }
    public String capacity(long value) {
        return value < 0 ? "Unavailable" : String.format(Locale.getDefault(), "%,d mAh", value / 1000);
    }
    public String cycles() {
        return cycles < 0 ? "Unavailable" : String.format(Locale.getDefault(), "%,d", cycles);
    }
}
