package com.example.adshield;

import android.content.Context;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * قائمة نطاقات محجوبة، محفوظة كـ hashes (64 بت لكل نطاق) في مصفوفة long مرتبة.
 * القائمة الكاملة (مئات الآلاف من النطاقات) بتاخد حوالي ميجا واحد بدل عشرات الميجا لو اتخزنت كنصوص،
 * والبحث بالـ binary search من غير ما نعمل أي كائنات جديدة وقت الاستعلام.
 * بيجرّب النطاق ثم النطاقات الأب (ads.x.com ← x.com).
 */
final class BlockList {

    private final long[] hashes; // مرتبة ومن غير تكرار

    BlockList(long[] sortedUniqueHashes) {
        this.hashes = sortedUniqueHashes;
    }

    int size() {
        return hashes.length;
    }

    boolean isBlocked(String name) {
        final long[] h = hashes;
        if (h.length == 0) return false;
        final int n = name.length();
        int from = 0;
        while (true) {
            if (Arrays.binarySearch(h, hash(name, from, n)) >= 0) return true;
            int i = name.indexOf('.', from);
            if (i < 0) return false;
            from = i + 1;
        }
    }

    /** FNV-1a 64 بت + خلط أخير. احتمال التصادم مع قائمة 500 ألف نطاق أقل من واحد في المليار. */
    static long hash(CharSequence s, int from, int to) {
        long h = 0xcbf29ce484222325L;
        for (int i = from; i < to; i++) {
            h ^= s.charAt(i);
            h *= 0x100000001b3L;
        }
        h ^= h >>> 33;
        h *= 0xff51afd7ed558ccdL;
        h ^= h >>> 33;
        return h;
    }

    /** بيقبل صيغة hosts ("0.0.0.0 domain")، أو نطاق في كل سطر، أو ||domain^ بتاعة AdGuard. */
    static BlockList parse(InputStream in) throws IOException {
        long[] buf = new long[1 << 14];
        int count = 0;
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

            if (count == buf.length) buf = Arrays.copyOf(buf, count * 2);
            buf[count++] = hash(d, 0, d.length());
        }

        long[] all = Arrays.copyOf(buf, count);
        Arrays.sort(all);
        int u = 0;
        for (int i = 0; i < all.length; i++) {
            if (i == 0 || all[i] != all[i - 1]) all[u++] = all[i];
        }
        return new BlockList(u == all.length ? all : Arrays.copyOf(all, u));
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
            return new BlockList(new long[0]);
        }
    }
}
