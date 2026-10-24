package com.example.adshield;

import android.content.Context;
import android.content.SharedPreferences;

import java.util.HashSet;
import java.util.Set;

/** إعدادات المستخدم: نطاقات مسموحة، وتطبيقات مستثناة من الـ VPN بالكامل، وآخر تحديث للقائمة. */
final class Settings {

    static final String K_ALLOWED = "allowed";
    static final String K_EXCLUDED = "excluded";
    static final String K_LIST_TIME = "list_updated";

    private Settings() {}

    private static SharedPreferences prefs(Context c) {
        return c.getSharedPreferences("adshield", Context.MODE_PRIVATE);
    }

    static Set<String> get(Context c, String key) {
        Set<String> s = prefs(c).getStringSet(key, null);
        return s == null ? new HashSet<String>() : new HashSet<String>(s);
    }

    static void put(Context c, String key, Set<String> value) {
        prefs(c).edit().putStringSet(key, new HashSet<String>(value)).apply();
    }

    static Set<String> allowed(Context c) {
        return get(c, K_ALLOWED);
    }

    static long getLong(Context c, String key) {
        return prefs(c).getLong(key, 0L);
    }

    static void putLong(Context c, String key, long value) {
        prefs(c).edit().putLong(key, value).apply();
    }
}
