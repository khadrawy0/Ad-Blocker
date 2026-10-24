package com.example.adshield;

/**
 * أدوات خفيفة لقراءة/بناء حزم DNS وIPv4/UDP. مفيش اعتماد على Android عشان نقدر نختبرها على أي JVM.
 */
final class DnsUtil {

    private DnsUtil() {}

    static final class Query {
        int id;
        String name;   // lowercase, من غير النقطة الأخيرة
        int qtype;     // 1 = A, 28 = AAAA
        int qEnd;      // نهاية قسم السؤال، نسبةً لبداية رسالة الـ DNS
    }

    static final class UdpPacket {
        final byte[] src = new byte[4];
        final byte[] dst = new byte[4];
        int sport;
        int dport;
        int payloadOff;
        int payloadLen;
    }

    /** يقرأ حزمة IPv4/UDP جاية من الـ TUN. يرجّع null لو مش UDP سليمة أو لو متجزّأة. */
    static UdpPacket parseUdpIpv4(byte[] b, int n) {
        if (n < 28) return null;
        if ((b[0] >> 4) != 4) return null;
        int ihl = (b[0] & 0x0F) * 4;
        if (ihl < 20 || n < ihl + 8) return null;
        if ((b[9] & 0xFF) != 17) return null;
        int fragField = ((b[6] & 0x3F) << 8) | (b[7] & 0xFF); // MF + fragment offset
        if (fragField != 0) return null;

        UdpPacket u = new UdpPacket();
        System.arraycopy(b, 12, u.src, 0, 4);
        System.arraycopy(b, 16, u.dst, 0, 4);
        u.sport = ((b[ihl] & 0xFF) << 8) | (b[ihl + 1] & 0xFF);
        u.dport = ((b[ihl + 2] & 0xFF) << 8) | (b[ihl + 3] & 0xFF);
        int udpLen = ((b[ihl + 4] & 0xFF) << 8) | (b[ihl + 5] & 0xFF);
        int plen = Math.min(udpLen - 8, n - ihl - 8);
        if (plen <= 0) return null;
        u.payloadOff = ihl + 8;
        u.payloadLen = plen;
        return u;
    }

    /** يقرأ أول سؤال في رسالة DNS (طلب فقط). يرجّع null لو الرسالة مش طلب سليم. */
    static Query parseQuestion(byte[] b, int off, int len) {
        if (len < 17) return null;
        int flags = ((b[off + 2] & 0xFF) << 8) | (b[off + 3] & 0xFF);
        if ((flags & 0x8000) != 0) return null;       // ده رد مش طلب
        if (((flags >> 11) & 0xF) != 0) return null;  // opcode لازم يكون QUERY
        int qd = ((b[off + 4] & 0xFF) << 8) | (b[off + 5] & 0xFF);
        if (qd < 1) return null;

        int p = off + 12;
        int end = off + len;
        StringBuilder sb = new StringBuilder();
        while (true) {
            if (p >= end) return null;
            int l = b[p++] & 0xFF;
            if (l == 0) break;
            if ((l & 0xC0) != 0) return null;          // ضغط الأسماء مش مسموح في السؤال
            if (p + l > end) return null;
            if (sb.length() > 0) sb.append('.');
            for (int i = 0; i < l; i++) {
                char c = (char) (b[p + i] & 0xFF);
                if (c >= 'A' && c <= 'Z') c += 32;
                sb.append(c);
            }
            p += l;
            if (sb.length() > 253) return null;
        }
        if (p + 4 > end) return null;

        Query q = new Query();
        q.id = ((b[off] & 0xFF) << 8) | (b[off + 1] & 0xFF);
        q.name = sb.toString();
        q.qtype = ((b[p] & 0xFF) << 8) | (b[p + 1] & 0xFF);
        q.qEnd = p + 4 - off;
        return q;
    }

    /**
     * رد محلي للنطاقات المحجوبة: A → 0.0.0.0، AAAA → ::، وأي نوع تاني → NOERROR من غير إجابات.
     */
    static byte[] blockedResponse(byte[] b, int off, Query q) {
        boolean a = q.qtype == 1;
        boolean aaaa = q.qtype == 28;
        int rdlen = a ? 4 : (aaaa ? 16 : 0);
        int answerLen = (a || aaaa) ? 12 + rdlen : 0;

        byte[] r = new byte[q.qEnd + answerLen];
        System.arraycopy(b, off, r, 0, q.qEnd);
        int rd = b[off + 2] & 0x01;
        r[2] = (byte) (0x80 | rd);            // QR=1 + نسخ RD
        r[3] = (byte) 0x80;                   // RA=1، RCODE=0
        r[4] = 0; r[5] = 1;                   // QDCOUNT = 1
        r[6] = 0; r[7] = (byte) ((a || aaaa) ? 1 : 0); // ANCOUNT
        r[8] = 0; r[9] = 0; r[10] = 0; r[11] = 0;      // NS/AR = 0

        if (a || aaaa) {
            int p = q.qEnd;
            r[p++] = (byte) 0xC0; r[p++] = 0x0C;       // اسم = مؤشر لأول السؤال
            r[p++] = 0; r[p++] = (byte) q.qtype;       // TYPE
            r[p++] = 0; r[p++] = 1;                    // CLASS IN
            r[p++] = 0; r[p++] = 0; r[p++] = 0; r[p++] = 60; // TTL = 60 ثانية
            r[p++] = 0; r[p++] = (byte) rdlen;         // RDLENGTH
            // RDATA أصفار (0.0.0.0 أو ::)
        }
        return r;
    }

    /** يبني حزمة IPv4/UDP كاملة جاهزة تتكتب في الـ TUN. */
    static byte[] buildUdpIpv4(byte[] src, int sport, byte[] dst, int dport, byte[] payload, int plen) {
        int total = 20 + 8 + plen;
        byte[] p = new byte[total];
        p[0] = 0x45;
        p[2] = (byte) (total >> 8);
        p[3] = (byte) total;
        p[6] = 0x40;            // DF
        p[8] = 64;              // TTL
        p[9] = 17;              // UDP
        System.arraycopy(src, 0, p, 12, 4);
        System.arraycopy(dst, 0, p, 16, 4);
        int ck = checksum(p, 0, 20);
        p[10] = (byte) (ck >> 8);
        p[11] = (byte) ck;

        p[20] = (byte) (sport >> 8);
        p[21] = (byte) sport;
        p[22] = (byte) (dport >> 8);
        p[23] = (byte) dport;
        int ul = 8 + plen;
        p[24] = (byte) (ul >> 8);
        p[25] = (byte) ul;
        // UDP checksum = 0 مسموح في IPv4
        System.arraycopy(payload, 0, p, 28, plen);
        return p;
    }

    static int checksum(byte[] b, int off, int len) {
        long sum = 0;
        for (int i = 0; i < len; i += 2) {
            int hi = b[off + i] & 0xFF;
            int lo = (i + 1 < len) ? (b[off + i + 1] & 0xFF) : 0;
            sum += (hi << 8) | lo;
        }
        while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
        return (int) (~sum & 0xFFFF);
    }
}
