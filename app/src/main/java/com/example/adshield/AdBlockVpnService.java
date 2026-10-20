package com.example.adshield;

import android.content.Intent;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.Arrays;
import java.util.HashSet;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * فلتر DNS محلي.
 *
 * الفكرة: الـ VPN بيوجّه للجهاز عنوان واحد بس (عنوان DNS وهمي) عن طريق route /32،
 * يعني استعلامات DNS بس هي اللي بتعدّي على التطبيق، وباقي الإنترنت (يوتيوب، ألعاب، تصفح...)
 * بيروح مباشرة من غير ما يتأثر بأي شكل. الاستعلام لو نطاقه في القائمة بنرد عليه 0.0.0.0 فيفشل الإعلان
 * قبل ما يتحمّل، ولو لأ بنبعته لـ DNS حقيقي ونرجّع الرد زي ما هو.
 */
public class AdBlockVpnService extends VpnService {

    static final String ACTION_STOP = "com.example.adshield.STOP";

    private static final String VPN_ADDR = "10.111.222.2";
    private static final String VPN_DNS = "10.111.222.1";
    private static final String UPSTREAM_DNS = "1.1.1.1";

    static volatile boolean running = false;
    static volatile BlockList blockList = new BlockList(new HashSet<String>());
    static final AtomicInteger total = new AtomicInteger();
    static final AtomicInteger blocked = new AtomicInteger();

    private ParcelFileDescriptor tun;
    private Thread worker;
    private ExecutorService pool;

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

        blockList = BlockList.load(this);
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

        final ParcelFileDescriptor fd = b.establish();
        if (fd == null) { // الصلاحية اتسحبت
            stopSelf();
            return;
        }
        tun = fd;

        ThreadPoolExecutor ex = new ThreadPoolExecutor(
                1, 6, 30, TimeUnit.SECONDS,
                new ArrayBlockingQueue<Runnable>(128),
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

        DnsUtil.Query q = DnsUtil.parseQuestion(buf, u.payloadOff, u.payloadLen);
        total.incrementAndGet();

        if (q != null && blockList.isBlocked(q.name)) {
            blocked.incrementAndGet();
            byte[] r = DnsUtil.blockedResponse(buf, u.payloadOff, q);
            write(out, DnsUtil.buildUdpIpv4(u.dst, 53, u.src, u.sport, r, r.length));
            return;
        }

        final byte[] payload = Arrays.copyOfRange(buf, u.payloadOff, u.payloadOff + u.payloadLen);
        ExecutorService p = pool;
        if (p == null) return;
        p.execute(new Runnable() {
            @Override
            public void run() {
                forward(u, payload, out);
            }
        });
    }

    private void forward(DnsUtil.UdpPacket u, byte[] payload, FileOutputStream out) {
        DatagramSocket s = null;
        try {
            s = new DatagramSocket();
            protect(s);
            s.setSoTimeout(4000);
            s.send(new DatagramPacket(payload, payload.length, InetAddress.getByName(UPSTREAM_DNS), 53));
            byte[] resp = new byte[4096];
            DatagramPacket rp = new DatagramPacket(resp, resp.length);
            s.receive(rp);
            write(out, DnsUtil.buildUdpIpv4(u.dst, 53, u.src, u.sport, resp, rp.getLength()));
        } catch (IOException ignored) {
            // timeout أو شبكة مقطوعة: التطبيق هيعيد المحاولة بنفسه
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
