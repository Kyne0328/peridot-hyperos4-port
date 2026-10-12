package com.android.updater;

import android.app.Activity;
import android.content.res.Configuration;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Build;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.view.WindowInsets;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

/** Information destination for Settings' existing HyperOS version card. */
public final class UpdateActivity extends Activity {
    private int foreground, secondary, surface, accent;
    private int dp(float value) { return Math.round(value * getResources().getDisplayMetrics().density); }
    private TextView text(String value, float size, int color, boolean bold) {
        TextView view = new TextView(this);
        view.setText(value); view.setTextSize(size); view.setTextColor(color);
        if (bold) view.setTypeface(Typeface.create("sans-serif", Typeface.BOLD));
        view.setTextIsSelectable(true);
        view.setLayoutParams(new LinearLayout.LayoutParams(-1, -2));
        return view;
    }
    private GradientDrawable shape(int color, int radius) {
        GradientDrawable drawable = new GradientDrawable();
        drawable.setColor(color); drawable.setCornerRadius(dp(radius)); return drawable;
    }
    private LinearLayout card(LinearLayout parent, String title) {
        LinearLayout card = new LinearLayout(this); card.setOrientation(LinearLayout.VERTICAL);
        card.setPadding(dp(20), dp(20), dp(20), dp(20)); card.setBackground(shape(surface, 24));
        LinearLayout.LayoutParams layout = new LinearLayout.LayoutParams(-1, -2);
        layout.setMargins(0, dp(16), 0, 0); parent.addView(card, layout);
        TextView heading = text(title, 19, foreground, true); heading.setPadding(0, 0, 0, dp(8));
        card.addView(heading); return card;
    }
    private void detail(LinearLayout parent, String label, String value) {
        TextView key = text(label, 13, secondary, false); key.setPadding(0, dp(12), 0, dp(4));
        parent.addView(key); parent.addView(text(value, 16, foreground, false));
    }
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        boolean dark = (getResources().getConfiguration().uiMode & Configuration.UI_MODE_NIGHT_MASK) == Configuration.UI_MODE_NIGHT_YES;
        foreground = Color.parseColor(dark ? "#F1F4FA" : "#172033");
        secondary = Color.parseColor(dark ? "#A7B0C4" : "#657087");
        surface = Color.parseColor(dark ? "#1B2434" : "#FFFFFF");
        accent = Color.parseColor(dark ? "#9CB8FF" : "#325ECC");
        LinearLayout root = new LinearLayout(this); root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(Color.parseColor(dark ? "#101723" : "#F3F5FA"));
        root.setOnApplyWindowInsetsListener((view, insets) -> {
            android.graphics.Insets bars = insets.getInsets(WindowInsets.Type.systemBars() | WindowInsets.Type.displayCutout());
            view.setPadding(bars.left, bars.top, bars.right, bars.bottom); return insets;
        });
        getWindow().getDecorView().setSystemUiVisibility(dark ? 0 : View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR | View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR);
        LinearLayout toolbar = new LinearLayout(this); toolbar.setGravity(Gravity.CENTER_VERTICAL);
        toolbar.setPadding(dp(12), dp(8), dp(20), dp(8));
        TextView back = text("‹", 32, foreground, false); back.setTextIsSelectable(false);
        back.setGravity(Gravity.CENTER); back.setContentDescription("Back");
        back.setOnClickListener(view -> finish()); toolbar.addView(back, new LinearLayout.LayoutParams(dp(48), dp(48)));
        toolbar.addView(text("KyneOS", 19, foreground, true), new LinearLayout.LayoutParams(-1, -2));
        root.addView(toolbar);
        ScrollView scroll = new ScrollView(this); scroll.setFillViewport(true);
        LinearLayout content = new LinearLayout(this); content.setOrientation(LinearLayout.VERTICAL);
        content.setPadding(dp(24), dp(22), dp(24), dp(32));
        TextView brand = text("KyneOS", 38, foreground, true); content.addView(brand);
        TextView description = text("Global HyperOS 4 for POCO F6", 18, foreground, false);
        description.setPadding(0, dp(8), 0, 0); content.addView(description);
        TextView maintainer = text("Port maintained by Kyne", 15, secondary, false);
        maintainer.setPadding(0, dp(8), 0, dp(18)); content.addView(maintainer);
        TextView badge = text("POCO F6 · peridot", 13, accent, true);
        badge.setPadding(dp(14), dp(8), dp(14), dp(8)); badge.setBackground(shape(dark ? Color.parseColor("#243656") : Color.parseColor("#E7EDFE"), 14));
        content.addView(badge, new LinearLayout.LayoutParams(-2, -2));
        LinearLayout build = card(content, "Build details");
        detail(build, "KyneOS release", "RI7 · KyneOS 1");
        detail(build, "Port build", "KYNEOS-RI7.1-20261005");
        detail(build, "HyperOS donor", "Global OS4.0.0.9.XPCMIXM · pudding");
        detail(build, "POCO F6 hardware base", "Global OS3.0.303.0.WNPMIXM · peridot");
        detail(build, "Android version", Build.VERSION.RELEASE);
        detail(build, "Android security update", Build.VERSION.SECURITY_PATCH);
        detail(build, "Device software build", Build.DISPLAY);
        LinearLayout credits = card(content, "Credits");
        detail(credits, "Kyne", "Port integration, maintenance and device testing");
        detail(credits, "Xiaomi & POCO", "HyperOS and official donor / POCO F6 firmware");
        detail(credits, "Android Open Source Project", "Android platform");
        detail(credits, "OrangeFox Recovery Project", "Recovery");
        scroll.addView(content); root.addView(scroll, new LinearLayout.LayoutParams(-1, 0, 1));
        setContentView(root); root.requestApplyInsets();
    }
}
