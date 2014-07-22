package cm.android.sdk.preference.util;

import android.annotation.TargetApi;
import android.content.SharedPreferences;
import android.content.SharedPreferences.Editor;
import android.util.Base64;
import cm.android.sdk.preference.SecuredEditor;

import java.util.Map;
import java.util.Set;

/**
 * Util classes for {@link cm.android.sdk.preference.SecureFactory}.
 */
public final class SecureUtil {
    private static final String VERSION_KEY = "SecurePreferences_version";

    /**
     * Hidden util constructor.
     */
    private SecureUtil() {
    }

    /**
     * Copies data from one {@link android.content.SharedPreferences} to another.
     *
     * @param from    The source.
     * @param to      The target.
     * @param version The version code to write into the preferences for future check.
     */
    @SuppressWarnings("unchecked")
    @TargetApi(11)
    public static void migrateData(SharedPreferences from, SharedPreferences to, int version) {
        Map<String, ?> all = from.getAll();
        Set<String> keySet = all.keySet();
        Editor edit = to.edit();
        for (String key : keySet) {
            Object object = all.get(key);
            if (object == null) {
                // should not reach here
                edit.remove(key);
            } else if (object instanceof String) {
                edit.putString(key, (String) object);
            } else if (object instanceof Integer) {
                edit.putInt(key, (Integer) object);
            } else if (object instanceof Long) {
                edit.putLong(key, (Long) object);
            } else if (object instanceof Float) {
                edit.putFloat(key, (Float) object);
            } else if (object instanceof Boolean) {
                edit.putBoolean(key, (Boolean) object);
            } else if (object instanceof Set<?>) {
                edit.putStringSet(key, (Set<String>) object);
            }
        }
        edit.putInt(VERSION_KEY, version);
        SecuredEditor.compatilitySave(edit);
    }

    /**
     * Gets the version of {@link android.content.SharedPreferences} if any.
     *
     * @param preferences
     * @return The version or -1.
     */
    public static int getVersion(SharedPreferences preferences) {
        int currentVersion = preferences.getInt(VERSION_KEY, -1);
        return currentVersion;
    }

    @TargetApi(8)
    public static String encode(byte[] input) {
        return Base64.encodeToString(input, Base64.NO_PADDING | Base64.NO_WRAP);
    }

    @TargetApi(8)
    public static byte[] decode(String input) {
        return Base64.decode(input, Base64.NO_PADDING | Base64.NO_WRAP);
    }

}
