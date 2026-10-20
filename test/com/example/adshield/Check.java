package com.example.adshield;
import java.io.*;
import java.nio.charset.StandardCharsets;
public class Check {
    static int fail = 0;
    static void ok(boolean c, String m){ System.out.println((c?"PASS ":"FAIL ")+m); if(!c) fail++; }
    static byte[] dnsQuery(String name, int qtype){
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        o.write(0x12);o.write(0x34);o.write(0x01);o.write(0x00);
        o.write(0);o.write(1);o.write(0);o.write(0);o.write(0);o.write(0);o.write(0);o.write(0);
        for(String l: name.split("\\.")){ o.write(l.length()); byte[] b=l.getBytes(); o.write(b,0,b.length);}
        o.write(0); o.write(0); o.write(qtype); o.write(0); o.write(1);
        return o.toByteArray();
    }
    public static void main(String[] a) throws Exception {
        // IP checksum: مثال معروف من RFC 1071 / ويكيبيديا
        byte[] hdr = {0x45,0,0,0x73,0,0,0x40,0,0x40,0x11,0,0,(byte)0xc0,(byte)0xa8,0,1,(byte)0xc0,(byte)0xa8,0,(byte)0xc7};
        ok(DnsUtil.checksum(hdr,0,20)==0xb861, "ip checksum matches known vector 0xb861");

        byte[] q = dnsQuery("Ads.Example.COM", 1);
        DnsUtil.Query p = DnsUtil.parseQuestion(q,0,q.length);
        ok(p!=null && p.name.equals("ads.example.com") && p.qtype==1 && p.id==0x1234 && p.qEnd==q.length, "parse question A");

        byte[] r = DnsUtil.blockedResponse(q,0,p);
        ok((r[2]&0x80)!=0 && (r[2]&1)==1 && (r[3]&0x0F)==0, "response QR=1, RD copied, RCODE=0");
        ok(r[7]==1 && r.length==q.length+16 && r[r.length-1]==0 && r[r.length-5]==4, "A answer 0.0.0.0 len 4");

        byte[] q6 = dnsQuery("ads.example.com", 28);
        DnsUtil.Query p6 = DnsUtil.parseQuestion(q6,0,q6.length);
        byte[] r6 = DnsUtil.blockedResponse(q6,0,p6);
        ok(r6.length==q6.length+28 && r6[r6.length-17]==16, "AAAA answer :: len 16");

        byte[] qm = dnsQuery("ads.example.com", 15);
        byte[] rm = DnsUtil.blockedResponse(qm,0,DnsUtil.parseQuestion(qm,0,qm.length));
        ok(rm[7]==0 && rm.length==qm.length, "MX -> NOERROR no answers");

        byte[] resp = r.clone(); 
        ok(DnsUtil.parseQuestion(resp,0,resp.length)==null, "responses are not parsed as queries");

        // حزمة كاملة ذهاب وعودة
        byte[] src={10,111,(byte)222,2}, dst={10,111,(byte)222,1};
        byte[] pkt = DnsUtil.buildUdpIpv4(src,40000,dst,53,q,q.length);
        ok(DnsUtil.checksum(pkt,0,20)==0, "built IP header checksum validates to 0");
        DnsUtil.UdpPacket u = DnsUtil.parseUdpIpv4(pkt,pkt.length);
        ok(u!=null && u.sport==40000 && u.dport==53 && u.payloadLen==q.length && u.dst[3]==1 && u.src[3]==2, "udp build/parse roundtrip");
        DnsUtil.Query p2 = DnsUtil.parseQuestion(pkt,u.payloadOff,u.payloadLen);
        ok(p2!=null && p2.name.equals("ads.example.com"), "query inside packet parsed with offset");

        // مدخلات تالفة ما تكسرش حاجة
        byte[] junk = new byte[40]; new java.util.Random(1).nextBytes(junk);
        boolean noCrash=true;
        for(int i=0;i<20000;i++){ new java.util.Random(i).nextBytes(junk);
            try{ DnsUtil.UdpPacket x=DnsUtil.parseUdpIpv4(junk,junk.length); DnsUtil.parseQuestion(junk,0,junk.length);}catch(Exception e){noCrash=false;System.out.println(e);break;} }
        ok(noCrash, "20000 random packets: no exceptions");

        // قائمة الحجب
        String list = "# c\n127.0.0.1 localhost\n0.0.0.0 Ads.Tracker.NET # x\n||adguard-style.com^\n@@||allowed.com^\nplain.org\n! bad\n0.0.0.0 bad_domain!.com\n1.2.3.4 ignored.com\n";
        BlockList bl = BlockList.parse(new ByteArrayInputStream(list.getBytes(StandardCharsets.UTF_8)));
        ok(bl.size()==3, "parsed 3 domains (got "+bl.size()+")");
        ok(bl.isBlocked("ads.tracker.net") && bl.isBlocked("sub.adguard-style.com") && bl.isBlocked("a.b.plain.org"), "exact + subdomain blocked");
        ok(!bl.isBlocked("allowed.com") && !bl.isBlocked("org") && !bl.isBlocked("example.com") && !bl.isBlocked("ignored.com"), "others not blocked");

        // القائمة المدمجة في التطبيق
        BlockList bundled = BlockList.parse(new FileInputStream("app/src/main/assets/blocklist.txt"));
        ok(bundled.size()>=40 && bundled.isBlocked("config.unityads.unity3d.com") && !bundled.isBlocked("google.com") && !bundled.isBlocked("youtube.com"), "bundled list ok, doesn't block google.com/youtube.com");

        System.out.println(fail==0?"ALL OK":"FAILURES: "+fail);
        System.exit(fail==0?0:1);
    }
}
