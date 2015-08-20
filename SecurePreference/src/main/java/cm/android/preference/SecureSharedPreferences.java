package cm.android.preference;

import android.annotation.TargetApi;
import android.content.SharedPreferences;
import android.os.Build;

import java.util.Map;
import java.util.Set;

import cm.android.preference.crypto.CryptoHelper;
import cm.android.preference.crypto.ICipher;

public class SecureSharedPreferences implements SharedPreferences {

    private static final String VERSION_KEY = "SecureSharedPreferences_version";

    private SharedPreferences prefs;

    private CryptoHelper helper;

    public SecureSharedPreferences(SharedPreferences original, ICipher keyCipher,
            ICipher valueCipher) {
        this.prefs = original;
        helper = new CryptoHelper(keyCipher, valueCipher);
    }

    public void setVersion(int version) {
        this.prefs.edit().putInt(VERSION_KEY, version).apply();
    }

    public int getVersion() {
        return this.prefs.getInt(VERSION_KEY, -1);
    }

    @Override
    public boolean contains(String key) {
        return helper.contains(prefs, key);
    }

    @Override
    public SecureEditor edit() {
        return new SecureEditor(helper, prefs.edit());
    }

    @Override
    public Map<String, ?> getAll() {
        return helper.getAll(prefs);
    }

    @Override
    public boolean getBoolean(String key, boolean defValue) {
        return helper.getValue(prefs, key, defValue);
    }

    @Override
    public float getFloat(String key, float defValue) {
        return helper.getValue(prefs, key, defValue);
    }

    @Override
    public int getInt(String key, int defValue) {
        return helper.getValue(prefs, key, defValue);
    }

    @Override
    public long getLong(String key, long defValue) {
        return helper.getValue(prefs, key, defValue);
    }

    @Override
    public String getString(String key, String defValue) {
        return helper.getValue(prefs, key, defValue);
    }

    @TargetApi(value = Build.VERSION_CODES.HONEYCOMB)
    @Override
    public Set<String> getStringSet(String key, Set<String> defValues) {
        return helper.getValue(prefs, key, defValues);
    }

    @Override
    public void registerOnSharedPreferenceChangeListener(
            OnSharedPreferenceChangeListener listener) {
        prefs.registerOnSharedPreferenceChangeListener(listener);
    }

    @Override
    public void unregisterOnSharedPreferenceChangeListener(
            OnSharedPreferenceChangeListener listener) {
        prefs.unregisterOnSharedPreferenceChangeListener(listener);
    }

    protected SharedPreferences getPrefs() {
        return prefs;
    }

    public static class SecureEditor implements Editor {

        private Editor editor;

        private CryptoHelper helper;

        private SecureEditor(CryptoHelper helper, Editor edit) {
            this.helper = helper;
            this.editor = edit;
        }

        @Override
        public SecureEditor putString(String key, String value) {
            helper.putValue(editor, key, value);
            return this;
        }

        @Override
        public SecureEditor putStringSet(String key, Set<String> values) {
            helper.putValue(editor, key, values);
            return this;
        }

        @Override
        public SecureEditor putInt(String key, int value) {
            helper.putValue(editor, key, value);
            return this;
        }

        @Override
        public SecureEditor putLong(String key, long value) {
            helper.putValue(editor, key, value);
            return this;
        }

        @Override
        public SecureEditor putFloat(String key, float value) {
            helper.putValue(editor, key, value);
            return this;
        }

        @Override
        public SecureEditor putBoolean(String key, boolean value) {
            helper.putValue(editor, key, value);
            return this;
        }

        @Override
        public SecureEditor remove(String key) {
            helper.remove(editor, key);
            return this;
        }

        @Override
        public SecureEditor clear() {
            editor.clear();
            return this;
        }

        @Override
        public boolean commit() {
            return editor.commit();
        }

        @Override
        @TargetApi(9)
        public void apply() {
            editor.apply();
        }

        public void save() {
            compatilitySave(this);
        }

        @TargetApi(9)
        public static void compatilitySave(Editor editor) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.HONEYCOMB) {
                editor.apply();
            } else {
                synchronized (SecureEditor.class) {
                    editor.commit();
                }
            }
        }

    }
}
