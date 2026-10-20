package com.example.adshield;

import android.app.Activity;
import android.content.Intent;
import android.net.VpnService;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.Gravity;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;

public class MainActivity extends Activity {

    private static final int REQ_VPN = 1;

    // قائمة جاهزة وكبيرة. لو عايزها أخف جرّب: https://adaway.org/hosts.txt
    private static final String LIST_URL = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts";

    private final Handler handler = new Handler(Looper.getMainLooper());
    private TextView status;
    private Button toggle;
    private Button update;
    private boolean visible;

    private final Runnable ticker = new Runnable() {
        @Override
        public void run() {
            refresh();
            if (visible) handler.postDelayed(this, 1000);
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setGravity(Gravity.CENTER);
        int pad = (int) (24 * getResources().getDisplayMetrics().density);
        root.setPadding(pad, pad, pad, pad);

        status = new TextView(this);
        status.setTextSize(18);
        status.setGravity(Gravity.CENTER);

        toggle = new Button(this);
        toggle.setOnClickListener(v -> onToggle());

        update = new Button(this);
        update.setText("تحديث قائمة الحجب");
        update.setOnClickListener(v -> updateList());

        root.addView(status);
        root.addView(toggle);
        root.addView(update);
        setContentView(root);
    }

    @Override
    protected void onResume() {
        super.onResume();
        visible = true;
        handler.post(ticker);
    }

    @Override
    protected void onPause() {
        visible = false; // مفيش تحديثات في الخلفية
        super.onPause();
    }

    private void refresh() {
        if (AdBlockVpnService.running) {
            status.setText("الحجب شغال\nتم حجب " + AdBlockVpnService.blocked.get()
                    + " من " + AdBlockVpnService.total.get() + " طلب"
                    + "\nحجم القائمة: " + AdBlockVpnService.blockList.size());
            toggle.setText("إيقاف");
        } else {
            status.setText("الحجب متوقف");
            toggle.setText("تشغيل");
        }
    }

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

    private void updateList() {
        update.setEnabled(false);
        final File dst = BlockList.downloadedFile(this);
        final File tmp = new File(getFilesDir(), "blocklist.tmp");
        new Thread(() -> {
            String msg;
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
                msg = "تم التحديث: " + parsed.size() + " نطاق";
            } catch (Exception e) {
                msg = "فشل التحديث: " + e.getMessage();
            }
            final String m = msg;
            runOnUiThread(() -> {
                Toast.makeText(this, m, Toast.LENGTH_LONG).show();
                update.setEnabled(true);
            });
        }, "adshield-update").start();
    }
}
