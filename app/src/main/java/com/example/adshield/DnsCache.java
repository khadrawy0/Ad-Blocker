package com.example.adshield;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * كاش صغير لردود DNS المسموحة (حد أقصى 512 رد، الأقدم استخداماً يتشال أولاً).
 * الهدف: نقلل الاتصالات بسيرفر الـ DNS ونرد فوراً على الأسئلة المتكررة، فتقل الحركة على الشبكة والبطارية.
 * بيتخزن بس الرد السليم (NOERROR) الغير مقطوع وفيه إجابات، والصلاحية = أقل TTL في الإجابات (بين 20 و600 ثانية).
 */
final class DnsCache {

    private static final int MAX_ENTRIES = 512;
    private static final int MIN_TTL = 20;
    private static final int MAX_TTL = 600;

    private static final class CacheEntry {
        final byte[] resp;
        final long expiresAt;

        CacheEntry(byte[] resp, long expiresAt) {
            this.resp = resp;
            this.expiresAt = expiresAt;
        }
    }

    private final LinkedHashMap<String, CacheEntry> map =
            new LinkedHashMap<String, CacheEntry>(64, 0.75f, true) {
                @Override
                protected boolean removeEldestEntry(Map.Entry<String, CacheEntry> eldest) {
                    return size() > MAX_ENTRIES;
                }
            };

    static String key(String name, int qtype) {
        return name + '/' + qtype;
    }

    /** يرجّع نسخة من الرد الأصلي بعد ما يبدّل رقم الاستعلام (ID) برقم الطلب الحالي، أو null. */
    synchronized byte[] get(String key, int id, long nowMs) {
        CacheEntry e = map.get(key);
        if (e == null) return null;
        if (nowMs >= e.expiresAt) {
            map.remove(key);
            return null;
        }
        byte[] r = e.resp.clone();
        r[0] = (byte) (id >> 8);
        r[1] = (byte) id;
        return r;
    }

    synchronized void put(String key, byte[] resp, int len, long nowMs) {
        if (len < 12) return;
        if ((resp[2] & 0x02) != 0) return;          // TC: الرد مقطوع
        if ((resp[3] & 0x0F) != 0) return;          // أي RCODE غير NOERROR
        int ttl = minTtl(resp, len);
        if (ttl < 0) return;
        if (ttl < MIN_TTL) ttl = MIN_TTL;
        if (ttl > MAX_TTL) ttl = MAX_TTL;
        byte[] copy = new byte[len];
        System.arraycopy(resp, 0, copy, 0, len);
        map.put(key, new CacheEntry(copy, nowMs + ttl * 1000L));
    }

    synchronized void clear() {
        map.clear();
    }

    synchronized int size() {
        return map.size();
    }

    /** أقل TTL في قسم الإجابات. -1 لو مفيش إجابات أو الرد تالف. */
    static int minTtl(byte[] b, int len) {
        if (len < 12) return -1;
        int qd = ((b[4] & 0xFF) << 8) | (b[5] & 0xFF);
        int an = ((b[6] & 0xFF) << 8) | (b[7] & 0xFF);
        if (an == 0) return -1;

        int p = 12;
        for (int i = 0; i < qd; i++) {
            p = skipName(b, p, len);
            if (p < 0 || p + 4 > len) return -1;
            p += 4;
        }
        long min = Long.MAX_VALUE;
        for (int i = 0; i < an; i++) {
            p = skipName(b, p, len);
            if (p < 0 || p + 10 > len) return -1;
            long ttl = ((long) (b[p + 4] & 0xFF) << 24) | ((b[p + 5] & 0xFF) << 16)
                    | ((b[p + 6] & 0xFF) << 8) | (b[p + 7] & 0xFF);
            int rdlen = ((b[p + 8] & 0xFF) << 8) | (b[p + 9] & 0xFF);
            p += 10;
            if (p + rdlen > len) return -1;
            p += rdlen;
            if (ttl < min) min = ttl;
        }
        return min > Integer.MAX_VALUE ? Integer.MAX_VALUE : (int) min;
    }

    private static int skipName(byte[] b, int p, int len) {
        while (true) {
            if (p >= len) return -1;
            int l = b[p] & 0xFF;
            if (l == 0) return p + 1;
            if ((l & 0xC0) == 0xC0) return p + 2 <= len ? p + 2 : -1; // مؤشر ضغط
            if ((l & 0xC0) != 0) return -1;
            p += 1 + l;
        }
    }
}
