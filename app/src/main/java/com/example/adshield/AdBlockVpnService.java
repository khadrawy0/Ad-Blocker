package com.example.adshield;

import android.content.Intent;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import android.os.SystemClock;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * فلتر DNS محلي.
 *
 * الـ VPN بيوجّه للجهاز عنوان واحد بس (عنوان DNS وهمي) عن طريق route /32،
 * يعني استعلامات DNS بس هي اللي بتعدّي على التطبيق، وباقي الإنترنت بيروح مباشرة.
 * الاستعلام لو نطاقه في القائمة بنرد عليه 0.0.0.0 فيفشل الإعلان قبل ما يتحمّل،
 * ولو لأ بنرد من الكاش لو موجود، أو بنبعته لـ DNS حقيقي (1.1.1.1 ثم 8.8.8.8 كاحتياطي) ونرجّع الرد.
 *
 * توفير الموارد: قراءة blocking من غير polling (التطبيق نايم لما مفيش أسئلة)، قائمة حجب كـ hashes في
 * مصفوفة long، كاش للردود، وthreads محدودة بتتقفل لوحدها وقت الخمول.
 */
public class AdBlockVpnService extends VpnService {

    static final String ACTION_STOP = "com.example.adshield.STOP";

    private static final String VPN_ADDR = "10.111.222.2";
    private static final String VPN_DNS = "10.111.222.1";
    private static final int UPSTREAM_TIMEOUT_MS = 2500;
    private static final InetAddress[] UPSTREAMS = upstreams();

    static volatile boolean running = false;
    static volatile BlockList blockList = new BlockList(new long[0]);
    static final AtomicInteger total = new AtomicInteger();
    static final AtomicInteger blocked = new AtomicInteger();

    /** نطاقات المستخدم سمح بيها (بتتطبّق فوراً من غير إعادة تشغيل). */
    static volatile Set<String> allowed = new HashSet<String>();

    /** آخر النطاقات المحجوبة، عشان لو تطبيق باظ تعرف مين اتحجب. */
    private static final LinkedHashSet<String> recent = new LinkedHashSet<String>();

    /**
     * نطاقات تسجيل الدخول بفيسبوك وقائمة الأصدقاء. مسموحة دايماً بالاسم بالظبط (من غير النطاقات الفرعية)،
     * عشان إعلانات فيسبوك على نطاقات زي an.facebook.com تفضل محجوبة.
     */
    private static final Set<String> DEFAULT_ALLOWED = new HashSet<String>(Arrays.asList(
            "graph.facebook.com", "api.facebook.com", "www.facebook.com",
            "m.facebook.com", "web.facebook.com", "facebook.com"));

    private final DnsCache cache = new DnsCache();

    private ParcelFileDescriptor tun;
    private Thread worker;
    private ExecutorService pool;

    private static InetAddress[] upstreams() {
        try {
            return new InetAddress[]{
                    InetAddress.getByAddress(new byte[]{1, 1, 1, 1}),
                    InetAddress.getByAddress(new byte[]{8, 8, 8, 8})
            };
        } catch (UnknownHostException e) {
            throw new IllegalStateException(e);
        }
    }

    static boolean isAllowed(String name) {
        if (DEFAULT_ALLOWED.contains(name)) return true;
        Set<String> a = allowed;
        if (a.isEmpty()) return false;
        String d = name;
        while (true) {
            if (a.contains(d)) return true;
            int i = d.indexOf('.');
            if (i < 0) return false;
            d = d.substring(i + 1);
        }
    }

    private static void noteBlocked(String name) {
        synchronized (recent) {
            recent.remove(name);
            recent.add(name);
            if (recent.size() > 80) {
                Iterator<String> it = recent.iterator();
                it.next();
                it.remove();
            }
        }
    }

    static List<String> recentBlocked() {
        synchronized (recent) {
            ArrayList<String> l = new ArrayList<String>(recent);
            Collections.reverse(l); // الأحدث الأول
            return l;
        }
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && ACTION_STOP.equals(intent.getAction())) {
            stopVpn();
            stopSelf();
            return START_NOT_STICKY;
        }
        startVpn();
        return START_STICKY;
    }

    private synchronized void startVpn() {
        if (running) return;

        allowed = Settings.allowed(this); // القائمة نفسها بتتحمّل في الـ worker عشان الواجهة ما تهنجش
        cache.clear();
        total.set(0);
        blocked.set(0);

        Builder b = new Builder()
                .setSession("AdShield")
                .setMtu(1500)
                .setBlocking(true)
                .addAddress(VPN_ADDR, 32)
                .addDnsServer(VPN_DNS)
                .addRoute(VPN_DNS, 32); // استعلامات DNS بس هي اللي بتدخل على التطبيق
        try {
            // التطبيق نفسه خارج الـ VPN: تحديث القوائم بيشتغل عادي ومفيش حلقات
            b.addDisallowedApplication(getPackageName());
        } catch (Exception ignored) {
        }

        // تطبيقات المستخدم استثناها: ترافيكها (ومنها DNS) بيعدّي خارج الـ VPN تماماً،
        // وبالتالي مش بتشوف VPN شغال ولا بتتفلتر.
        for (String pkg : Settings.get(this, Settings.K_EXCLUDED)) {
            try {
                b.addDisallowedApplication(pkg);
            } catch (Exception ignored) {
                // التطبيق اتشال
            }
        }

        final ParcelFileDescriptor fd = b.establish();
        if (fd == null) { // الصلاحية اتسحبت
            stopSelf();
            return;
        }
        tun = fd;

        ThreadPoolExecutor ex = new ThreadPoolExecutor(
                1, 4, 20, TimeUnit.SECONDS,
                new ArrayBlockingQueue<Runnable>(64),
                new ThreadPoolExecutor.DiscardPolicy());
        ex.allowCoreThreadTimeOut(true); // مفيش threads شغالة وقت الخمول
        pool = ex;

        running = true;
        worker = new Thread(new Runnable() {
            @Override
            public void run() {
                loop(fd);
            }
        }, "adshield-loop");
        worker.start();
    }

    private void loop(ParcelFileDescriptor fd) {
        final FileInputStream in = new FileInputStream(fd.getFileDescriptor());
        final FileOutputStream out = new FileOutputStream(fd.getFileDescriptor());
        byte[] buf = new byte[32767];
        blockList = BlockList.load(this); // الأسئلة اللي توصل في الأثناء بتستنى في الطابور ثواني قليلة
        try {
            while (running) {
                int n = in.read(buf); // blocking: مفيش polling ولا استهلاك CPU وقت الخمول
                if (n < 0) break;
                if (n == 0) continue;
                handle(buf, n, out);
            }
        } catch (IOException ignored) {
            // الـ fd اتقفل
        } finally {
            if (running) {
                stopVpn();
                stopSelf();
            }
        }
    }

    private void handle(byte[] buf, int n, final FileOutputStream out) {
        final DnsUtil.UdpPacket u = DnsUtil.parseUdpIpv4(buf, n);
        if (u == null || u.dport != 53) return;

        final DnsUtil.Query q = DnsUtil.parseQuestion(buf, u.payloadOff, u.payloadLen);
        total.incrementAndGet();

        if (q != null) {
            if (blockList.isBlocked(q.name) && !isAllowed(q.name)) {
                blocked.incrementAndGet();
                noteBlocked(q.name);
                byte[] r = DnsUtil.blockedResponse(buf, u.payloadOff, q);
                write(out, DnsUtil.buildUdpIpv4(u.dst, 53, u.src, u.sport, r, r.length));
                return;
            }
            byte[] hit = cache.get(DnsCache.key(q.name, q.qtype), q.id, SystemClock.elapsedRealtime());
            if (hit != null) { // رد فوري من غير أي اتصال بالشبكة
                write(out, DnsUtil.buildUdpIpv4(u.dst, 53, u.src, u.sport, hit, hit.length));
                return;
            }
        }

        final byte[] payload = Arrays.copyOfRange(buf, u.payloadOff, u.payloadOff + u.payloadLen);
        ExecutorService p = pool;
        if (p == null) return;
        p.execute(new Runnable() {
            @Override
            public void run() {
                forward(u, payload, out, q);
            }
        });
    }

    private void forward(DnsUtil.UdpPacket u, byte[] payload, FileOutputStream out, DnsUtil.Query q) {
        DatagramSocket s = null;
        try {
            s = new DatagramSocket();
            protect(s);
            byte[] resp = new byte[4096];
            DatagramPacket rp = new DatagramPacket(resp, resp.length);
            for (InetAddress up : UPSTREAMS) {
                try {
                    s.setSoTimeout(UPSTREAM_TIMEOUT_MS);
                    s.send(new DatagramPacket(payload, payload.length, up, 53));
                    s.receive(rp);
                } catch (SocketTimeoutException e) {
                    continue; // نجرّب السيرفر الاحتياطي
                }
                int len = rp.getLength();
                write(out, DnsUtil.buildUdpIpv4(u.dst, 53, u.src, u.sport, resp, len));
                if (q != null) {
                    cache.put(DnsCache.key(q.name, q.qtype), resp, len, SystemClock.elapsedRealtime());
                }
                return;
            }
        } catch (IOException ignored) {
            // شبكة مقطوعة: التطبيق هيعيد المحاولة بنفسه
        } finally {
            if (s != null) s.close();
        }
    }

    private static void write(FileOutputStream out, byte[] packet) {
        try {
            synchronized (out) {
                out.write(packet);
            }
        } catch (IOException ignored) {
        }
    }

    private synchronized void stopVpn() {
        running = false;
        if (pool != null) {
            pool.shutdownNow();
            pool = null;
        }
        if (tun != null) {
            try {
                tun.close();
            } catch (IOException ignored) {
            }
            tun = null;
        }
        cache.clear();
    }

    @Override
    public void onRevoke() {
        stopVpn();
        super.onRevoke();
    }

    @Override
    public void onDestroy() {
        stopVpn();
        super.onDestroy();
    }
}
