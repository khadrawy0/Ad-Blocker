package com.example.adshield;

import android.content.Context;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;

/** قائمة نطاقات محجوبة. بحث فوري: بيجرّب النطاق ثم النطاقات الأب (ads.x.com ← x.com). */
final class BlockList {

    private final HashSet<String> set;

    BlockList(HashSet<String> set) {
        this.set = set;
    }

    int size() {
        return set.size();
    }

    boolean isBlocked(String name) {
        String d = name;
        while (true) {
            if (set.contains(d)) return true;
            int i = d.indexOf('.');
            if (i < 0) return false;
            d = d.substring(i + 1);
        }
    }

    /** بيقبل صيغة hosts ("0.0.0.0 domain")، أو نطاق في كل سطر، أو ||domain^ بتاعة AdGuard. */
    static BlockList parse(InputStream in) throws IOException {
        HashSet<String> set = new HashSet<>(1 << 14);
        BufferedReader r = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8), 1 << 16);
        String line;
        while ((line = r.readLine()) != null) {
            line = line.trim();
            if (line.isEmpty()) continue;
            char c0 = line.charAt(0);
            if (c0 == '#' || c0 == '!' || c0 == '[') continue;
            if (line.startsWith("@@")) continue;

            String d;
            if (line.startsWith("||")) {
                if (!line.endsWith("^")) continue;
                d = line.substring(2, line.length() - 1);
            } else {
                int h = line.indexOf('#');
                if (h >= 0) line = line.substring(0, h).trim();
                if (line.isEmpty()) continue;
                String[] t = line.split("\\s+");
                if (t.length >= 2) {
                    if (!t[0].equals("0.0.0.0") && !t[0].equals("127.0.0.1")) continue;
                    d = t[1];
                } else {
                    d = t[0];
                }
            }
            d = d.toLowerCase();
            if (!validDomain(d)) continue;
            set.add(d);
        }
        return new BlockList(set);
    }

    private static boolean validDomain(String d) {
        int n = d.length();
        if (n < 3 || n > 253 || d.indexOf('.') < 0) return false;
        if (d.equals("localhost") || d.equals("broadcasthost") || d.equals("local")) return false;
        for (int i = 0; i < n; i++) {
            char c = d.charAt(i);
            boolean ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_';
            if (!ok) return false;
        }
        return true;
    }

    static File downloadedFile(Context ctx) {
        return new File(ctx.getFilesDir(), "blocklist.txt");
    }

    /** بيحمّل القائمة اللي نزّلتها بنفسك لو موجودة، وإلا القائمة المدمجة في التطبيق. */
    static BlockList load(Context ctx) {
        try {
            File f = downloadedFile(ctx);
            if (f.exists() && f.length() > 0) {
                try (InputStream in = new FileInputStream(f)) {
                    return parse(in);
                }
            }
        } catch (IOException ignored) {
            // نكمّل بالقائمة المدمجة
        }
        try (InputStream in = ctx.getAssets().open("blocklist.txt")) {
            return parse(in);
        } catch (IOException e) {
            return new BlockList(new HashSet<String>());
        }
    }
}
