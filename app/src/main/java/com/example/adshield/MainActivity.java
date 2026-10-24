package com.example.adshield;

import android.animation.ArgbEvaluator;
import android.animation.ValueAnimator;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.content.res.ColorStateList;
import android.content.res.Configuration;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.RectF;
import android.graphics.Typeface;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.RippleDrawable;
import android.net.VpnService;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.text.DateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

public class MainActivity extends Activity {

    private static final int REQ_VPN = 1;

    // قائمة جاهزة وكبيرة. لو عايزها أخف جرّب: https://adaway.org/hosts.txt
    private static final String LIST_URL = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts";

    private final Handler handler = new Handler(Looper.getMainLooper());
    private boolean visible;
    private boolean updating;

    // الألوان (فاتح / داكن حسب إعدادات الموبايل)
    private int cBg, cCard, cText, cSub, cAccent, cOff, cWarn, cLine;
    private float density;

    private PowerButton power;
    private TextView statusTitle, statusSub;
    private TextView statBlocked, statTotal, statList;
    private TextView updateSub;
    private View dnsWarn;

    private final Runnable ticker = new Runnable() {
        @Override
        public void run() {
            refresh();
            if (visible) handler.postDelayed(this, 1000); // التحديث بس والشاشة ظاهرة
        }
    };

    // ---------------------------------------------------------------- بناء الشاشة

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        density = getResources().getDisplayMetrics().density;
        initColors();

        getWindow().setStatusBarColor(cBg);
        if (!isNight()) {
            getWindow().getDecorView().setSystemUiVisibility(View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR);
        }

        ScrollView scroll = new ScrollView(this);
        scroll.setBackgroundColor(cBg);
        scroll.setFillViewport(true);
        scroll.setLayoutDirection(View.LAYOUT_DIRECTION_RTL); // الواجهة عربي من اليمين لليسار

        LinearLayout col = new LinearLayout(this);
        col.setOrientation(LinearLayout.VERTICAL);
        col.setPadding(dp(20), dp(24), dp(20), dp(32));
        scroll.addView(col, new ScrollView.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        // العنوان
        TextView title = text("AdShield", 26, cText, true);
        TextView subtitle = text("حاجب إعلانات خفيف بيشتغل على جهازك", 14, cSub, false);
        col.addView(title);
        col.addView(subtitle);

        // زرار التشغيل
        power = new PowerButton(this, cAccent, cOff);
        power.setContentDescription("تشغيل أو إيقاف الحجب");
        power.setOnClickListener(v -> onToggle());
        LinearLayout.LayoutParams pl = new LinearLayout.LayoutParams(dp(176), dp(176));
        pl.gravity = Gravity.CENTER_HORIZONTAL;
        pl.topMargin = dp(28);
        col.addView(power, pl);

        statusTitle = text("", 22, cText, true);
        statusTitle.setGravity(Gravity.CENTER);
        LinearLayout.LayoutParams tl = matchWrap();
        tl.topMargin = dp(20);
        col.addView(statusTitle, tl);

        statusSub = text("", 14, cSub, false);
        statusSub.setGravity(Gravity.CENTER);
        LinearLayout.LayoutParams sl = matchWrap();
        sl.topMargin = dp(4);
        col.addView(statusSub, sl);

        // تحذير Private DNS (بيظهر لما يكون مفعّل بالاسم)
        LinearLayout warn = new LinearLayout(this);
        warn.setOrientation(LinearLayout.VERTICAL);
        warn.setPadding(dp(16), dp(14), dp(16), dp(14));
        warn.setBackground(ripple(shape(withAlpha(cWarn, 36), cWarn, 14)));
        TextView warnTitle = text("Private DNS شغال", 15, cWarn, true);
        TextView warnBody = text("النظام هيتخطى الحجب. اقفله من إعدادات الشبكة "
                + "(Private DNS ← Off أو Automatic). اضغط هنا لفتح الإعدادات.", 13, cText, false);
        warn.addView(warnTitle);
        warn.addView(warnBody);
        warn.setOnClickListener(v -> openNetworkSettings());
        warn.setVisibility(View.GONE);
        LinearLayout.LayoutParams wl = matchWrap();
        wl.topMargin = dp(20);
        col.addView(warn, wl);
        dnsWarn = warn;

        // الإحصائيات
        statBlocked = text("0", 22, cAccent, true);
        statTotal = text("0", 22, cText, true);
        statList = text("—", 22, cText, true);
        LinearLayout stats = new LinearLayout(this);
        stats.setOrientation(LinearLayout.HORIZONTAL);
        stats.addView(statCard(statBlocked, "إعلان محجوب"), weight(0));
        stats.addView(statCard(statTotal, "طلب اتفحص"), weight(dp(10)));
        stats.addView(statCard(statList, "نطاق في القائمة"), weight(dp(10)));
        LinearLayout.LayoutParams stl = matchWrap();
        stl.topMargin = dp(24);
        col.addView(stats, stl);

        // الأدوات
        TextView tools = text("الأدوات", 13, cSub, true);
        LinearLayout.LayoutParams tol = matchWrap();
        tol.topMargin = dp(28);
        col.addView(tools, tol);

        updateSub = addRow(col, "تحديث قائمة الحجب", "", this::updateList);
        addRow(col, "النطاقات المحجوبة مؤخراً",
                "لو تطبيق باظ، اعرف مين اتحجب واسمح بيه", this::showBlocked);
        addRow(col, "تطبيقات مستثناة من الحجب",
                "التطبيق ده يشتغل خارج الـ VPN تماماً", this::showApps);

        TextView foot = text("الفلترة بتحصل على جهازك. الأسئلة المسموحة بتتبعت لـ DNS "
                + "(1.1.1.1 وبعده 8.8.8.8 كاحتياطي) والردود بتتخزن مؤقتاً لتقليل استهلاك الشبكة.",
                12, cSub, false);
        LinearLayout.LayoutParams fl = matchWrap();
        fl.topMargin = dp(24);
        col.addView(foot, fl);

        setContentView(scroll);
        updateSubtitle();
    }

    @Override
    protected void onResume() {
        super.onResume();
        visible = true;
        updateDnsWarning();
        updateSubtitle();
        handler.post(ticker);
    }

    @Override
    protected void onPause() {
        visible = false; // مفيش تحديثات في الخلفية
        handler.removeCallbacks(ticker);
        super.onPause();
    }

    // ---------------------------------------------------------------- حالة الشاشة

    private void refresh() {
        boolean on = AdBlockVpnService.running;
        power.setOn(on);
        statusTitle.setText(on ? "الحماية شغالة" : "الحماية متوقفة");
        statusSub.setText(on ? "بنحجب الإعلانات في كل التطبيقات" : "اضغط الزرار عشان تبدأ الحجب");

        statBlocked.setText(fmt(AdBlockVpnService.blocked.get()));
        statTotal.setText(fmt(AdBlockVpnService.total.get()));
        int size = AdBlockVpnService.blockList.size();
        statList.setText(size > 0 ? fmt(size) : "—");
    }

    private void updateDnsWarning() {
        String mode = null;
        try {
            mode = android.provider.Settings.Global.getString(getContentResolver(), "private_dns_mode");
        } catch (Exception ignored) {
        }
        dnsWarn.setVisibility("hostname".equals(mode) ? View.VISIBLE : View.GONE);
    }

    private void updateSubtitle() {
        if (updating) return;
        long t = Settings.getLong(this, Settings.K_LIST_TIME);
        if (t == 0) {
            updateSub.setText("بتستخدم القائمة المدمجة الصغيرة. حدّثها لتحميل القائمة الكاملة");
        } else {
            updateSub.setText("آخر تحديث: " + DateFormat.getDateInstance(DateFormat.MEDIUM).format(new Date(t)));
        }
    }

    private void openNetworkSettings() {
        try {
            startActivity(new Intent(android.provider.Settings.ACTION_WIRELESS_SETTINGS));
        } catch (Exception e) {
            Toast.makeText(this, "افتح الإعدادات ← الشبكة ← Private DNS", Toast.LENGTH_LONG).show();
        }
    }

    // ---------------------------------------------------------------- تشغيل وإيقاف

    private void onToggle() {
        if (AdBlockVpnService.running) {
            Intent i = new Intent(this, AdBlockVpnService.class);
            i.setAction(AdBlockVpnService.ACTION_STOP);
            startService(i);
        } else {
            Intent p = VpnService.prepare(this); // نافذة موافقة النظام (أول مرة بس)
            if (p != null) {
                startActivityForResult(p, REQ_VPN);
            } else {
                startVpn();
            }
        }
        handler.postDelayed(this::refresh, 300);
    }

    private void startVpn() {
        startService(new Intent(this, AdBlockVpnService.class));
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REQ_VPN && resultCode == RESULT_OK) startVpn();
        handler.postDelayed(this::refresh, 300);
    }

    // ---------------------------------------------------------------- الأدوات

    /** آخر نطاقات اتحجبت: علّم اللي عايز تسمح بيه. بيتطبّق فوراً. */
    private void showBlocked() {
        final List<String> items = AdBlockVpnService.recentBlocked();
        if (items.isEmpty()) {
            Toast.makeText(this, "مفيش نطاقات محجوبة لسه. شغّل الحجب، افتح التطبيق اللي فيه المشكلة، وارجع هنا.",
                    Toast.LENGTH_LONG).show();
            return;
        }
        final boolean[] checked = new boolean[items.size()];
        new AlertDialog.Builder(this)
                .setTitle("اختار النطاقات اللي عايز تسمح بيها")
                .setMultiChoiceItems(items.toArray(new String[0]), checked, (d, i, c) -> checked[i] = c)
                .setPositiveButton("سماح", (d, w) -> {
                    Set<String> a = Settings.get(this, Settings.K_ALLOWED);
                    for (int i = 0; i < checked.length; i++) {
                        if (checked[i]) a.add(items.get(i));
                    }
                    Settings.put(this, Settings.K_ALLOWED, a);
                    AdBlockVpnService.allowed = a;
                    Toast.makeText(this, "اتسمح. اقفل التطبيق وافتحه تاني.", Toast.LENGTH_LONG).show();
                })
                .setNeutralButton("مسح كل الاستثناءات", (d, w) -> {
                    Settings.put(this, Settings.K_ALLOWED, new HashSet<String>());
                    AdBlockVpnService.allowed = new HashSet<String>();
                })
                .setNegativeButton("إلغاء", null)
                .show();
    }

    /** تطبيقات تتشال من الـ VPN بالكامل (لا حجب ولا VPN ظاهر ليها). محتاج إيقاف وتشغيل الحجب. */
    private void showApps() {
        PackageManager pm = getPackageManager();
        Intent main = new Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER);
        final ArrayList<String[]> apps = new ArrayList<>();
        HashSet<String> seen = new HashSet<>();
        for (ResolveInfo ri : pm.queryIntentActivities(main, 0)) {
            String pkg = ri.activityInfo.packageName;
            if (pkg.equals(getPackageName()) || !seen.add(pkg)) continue;
            apps.add(new String[]{ri.loadLabel(pm).toString(), pkg});
        }
        Collections.sort(apps, (x, y) -> x[0].compareToIgnoreCase(y[0]));

        Set<String> cur = Settings.get(this, Settings.K_EXCLUDED);
        String[] names = new String[apps.size()];
        final boolean[] checked = new boolean[apps.size()];
        for (int i = 0; i < apps.size(); i++) {
            names[i] = apps.get(i)[0];
            checked[i] = cur.contains(apps.get(i)[1]);
        }
        new AlertDialog.Builder(this)
                .setTitle("تطبيقات مستثناة من الحجب")
                .setMultiChoiceItems(names, checked, (d, i, c) -> checked[i] = c)
                .setPositiveButton("حفظ", (d, w) -> {
                    Set<String> s = new HashSet<>();
                    for (int i = 0; i < checked.length; i++) {
                        if (checked[i]) s.add(apps.get(i)[1]);
                    }
                    Settings.put(this, Settings.K_EXCLUDED, s);
                    Toast.makeText(this, "اتحفظ. أوقف الحجب وشغّله تاني عشان يتطبّق.", Toast.LENGTH_LONG).show();
                })
                .setNegativeButton("إلغاء", null)
                .show();
    }

    private void updateList() {
        if (updating) return;
        updating = true;
        updateSub.setText("جاري التحميل...");
        final File dst = BlockList.downloadedFile(this);
        final File tmp = new File(getFilesDir(), "blocklist.tmp");
        new Thread(() -> {
            String msg;
            boolean ok = false;
            try {
                HttpURLConnection c = (HttpURLConnection) new URL(LIST_URL).openConnection();
                c.setConnectTimeout(15000);
                c.setReadTimeout(30000);
                try (InputStream in = c.getInputStream(); OutputStream out = new FileOutputStream(tmp)) {
                    byte[] b = new byte[16384];
                    int n;
                    while ((n = in.read(b)) > 0) out.write(b, 0, n);
                }
                BlockList parsed;
                try (InputStream in = new FileInputStream(tmp)) {
                    parsed = BlockList.parse(in);
                }
                if (parsed.size() < 1000) throw new Exception("القائمة المحمّلة غير صالحة");
                if (dst.exists()) dst.delete();
                if (!tmp.renameTo(dst)) throw new Exception("تعذّر حفظ القائمة");
                AdBlockVpnService.blockList = parsed; // يتطبّق فوراً لو الحجب شغال
                Settings.putLong(this, Settings.K_LIST_TIME, System.currentTimeMillis());
                msg = "تم التحديث: " + fmt(parsed.size()) + " نطاق";
                ok = true;
            } catch (Exception e) {
                tmp.delete();
                msg = "فشل التحديث. اتأكد من النت وجرّب تاني";
            }
            final String m = msg;
            final boolean success = ok;
            runOnUiThread(() -> {
                updating = false;
                Toast.makeText(this, m, Toast.LENGTH_LONG).show();
                if (success) {
                    updateSubtitle();
                    refresh();
                } else {
                    updateSub.setText(m);
                }
            });
        }, "adshield-update").start();
    }

    // ---------------------------------------------------------------- عناصر الواجهة

    private TextView addRow(LinearLayout parent, String title, String sub, final Runnable action) {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);
        row.setPadding(dp(18), dp(16), dp(18), dp(16));
        row.setBackground(ripple(shape(cCard, cLine, 16)));
        row.setClickable(true);
        row.setFocusable(true);

        LinearLayout texts = new LinearLayout(this);
        texts.setOrientation(LinearLayout.VERTICAL);
        TextView t = text(title, 16, cText, true);
        TextView s = text(sub, 13, cSub, false);
        texts.addView(t);
        texts.addView(s);
        row.addView(texts, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        TextView chevron = text("‹", 26, cSub, false);
        row.addView(chevron);

        row.setOnClickListener(v -> action.run());
        LinearLayout.LayoutParams lp = matchWrap();
        lp.topMargin = dp(10);
        parent.addView(row, lp);
        return s;
    }

    private View statCard(TextView value, String label) {
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setGravity(Gravity.CENTER_HORIZONTAL);
        card.setPadding(dp(8), dp(14), dp(8), dp(14));
        card.setBackground(shape(cCard, cLine, 16));
        value.setGravity(Gravity.CENTER);
        TextView l = text(label, 12, cSub, false);
        l.setGravity(Gravity.CENTER);
        card.addView(value);
        card.addView(l);
        return card;
    }

    private TextView text(String s, int sp, int color, boolean bold) {
        TextView tv = new TextView(this);
        tv.setText(s);
        tv.setTextSize(sp);
        tv.setTextColor(color);
        tv.setLineSpacing(0f, 1.2f);
        if (bold) tv.setTypeface(Typeface.DEFAULT_BOLD);
        return tv;
    }

    private LinearLayout.LayoutParams matchWrap() {
        return new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
    }

    private LinearLayout.LayoutParams weight(int startMargin) {
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        lp.setMarginStart(startMargin);
        return lp;
    }

    private GradientDrawable shape(int fill, int stroke, float radiusDp) {
        GradientDrawable g = new GradientDrawable();
        g.setColor(fill);
        g.setCornerRadius(dp(radiusDp));
        if (stroke != 0) g.setStroke(Math.max(1, dp(1)), stroke);
        return g;
    }

    private Drawable ripple(Drawable content) {
        return new RippleDrawable(ColorStateList.valueOf(withAlpha(cAccent, 50)), content, null);
    }

    private int dp(float v) {
        return Math.round(v * density);
    }

    private static int withAlpha(int color, int alpha) {
        return Color.argb(alpha, Color.red(color), Color.green(color), Color.blue(color));
    }

    private static String fmt(int n) {
        return String.format(Locale.US, "%,d", n);
    }

    private boolean isNight() {
        return (getResources().getConfiguration().uiMode & Configuration.UI_MODE_NIGHT_MASK)
                == Configuration.UI_MODE_NIGHT_YES;
    }

    private void initColors() {
        if (isNight()) {
            cBg = 0xFF0E1615;
            cCard = 0xFF152120;
            cText = 0xFFE4EEEC;
            cSub = 0xFF9DB0AD;
            cAccent = 0xFF4FC4B4;
            cOff = 0xFF6B7D7A;
            cWarn = 0xFFFF8C84;
            cLine = 0xFF2A3B39;
        } else {
            cBg = 0xFFF3F6F5;
            cCard = 0xFFFFFFFF;
            cText = 0xFF13201F;
            cSub = 0xFF5B6B6A;
            cAccent = 0xFF0E7468;
            cOff = 0xFF8A9896;
            cWarn = 0xFFB3261E;
            cLine = 0xFFDCE5E3;
        }
    }

    /** زرار تشغيل دائري: حلقة + رمز Power، بيتغير لونه بحركة خفيفة (مرة واحدة عند التبديل). */
    private static final class PowerButton extends View {
        private final Paint fill = new Paint(Paint.ANTI_ALIAS_FLAG);
        private final Paint ring = new Paint(Paint.ANTI_ALIAS_FLAG);
        private final Paint icon = new Paint(Paint.ANTI_ALIAS_FLAG);
        private final RectF oval = new RectF();
        private final int onColor, offColor;
        private final ArgbEvaluator eval = new ArgbEvaluator();
        private boolean on;
        private float progress; // 0 = متوقف، 1 = شغال

        PowerButton(Context c, int onColor, int offColor) {
            super(c);
            this.onColor = onColor;
            this.offColor = offColor;
            float d = c.getResources().getDisplayMetrics().density;
            ring.setStyle(Paint.Style.STROKE);
            ring.setStrokeWidth(4f * d);
            icon.setStyle(Paint.Style.STROKE);
            icon.setStrokeWidth(7f * d);
            icon.setStrokeCap(Paint.Cap.ROUND);
            fill.setStyle(Paint.Style.FILL);
            setClickable(true);
            setFocusable(true);
        }

        void setOn(boolean v) {
            if (v == on) return;
            on = v;
            ValueAnimator a = ValueAnimator.ofFloat(progress, v ? 1f : 0f);
            a.setDuration(250);
            a.addUpdateListener(an -> {
                progress = (Float) an.getAnimatedValue();
                invalidate();
            });
            a.start();
        }

        @Override
        protected void onDraw(Canvas canvas) {
            float cx = getWidth() / 2f;
            float cy = getHeight() / 2f;
            float r = Math.min(cx, cy) - ring.getStrokeWidth();
            int color = (Integer) eval.evaluate(progress, offColor, onColor);

            fill.setColor(Color.argb((int) (22 + 38 * progress), Color.red(color), Color.green(color), Color.blue(color)));
            canvas.drawCircle(cx, cy, r, fill);
            ring.setColor(color);
            canvas.drawCircle(cx, cy, r, ring);

            icon.setColor(color);
            float ir = r * 0.36f;
            oval.set(cx - ir, cy - ir, cx + ir, cy + ir);
            canvas.drawArc(oval, -50f, 280f, false, icon); // الفتحة في الأعلى
            canvas.drawLine(cx, cy - ir * 1.25f, cx, cy - ir * 0.15f, icon);
        }

        @Override
        public boolean performClick() {
            return super.performClick();
        }
    }
}
