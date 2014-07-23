package cm.android.preference;

import android.annotation.TargetApi;
import android.content.SharedPreferences;
import android.os.Build;
import cm.android.preference.encryption.EncryptionHelper;
import cm.android.preference.encryption.IEncrypt;

import java.util.Map;
import java.util.Set;

/**
 */
public class SecureSharedPreferences implements SharedPreferences {
    private SharedPreferences prefs;
    private IEncrypt encryption;
    private EncryptionHelper helper;

    public SecureSharedPreferences(SharedPreferences preferences, IEncrypt encryption) {
        this.prefs = preferences;
        this.encryption = encryption;
        helper = new EncryptionHelper(encryption);
    }

    @Override
    public boolean contains(String key) {
        return helper.contains(prefs, key);
    }

    @Override
    public SecuredEditor edit() {
        return new SecuredEditor(helper, prefs.edit());
    }

    @Override
    public Map<String, ?> getAll() {
        return prefs.getAll();
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
    public void registerOnSharedPreferenceChangeListener(OnSharedPreferenceChangeListener listener) {
        prefs.registerOnSharedPreferenceChangeListener(listener);
    }

    @Override
    public void unregisterOnSharedPreferenceChangeListener(OnSharedPreferenceChangeListener listener) {
        prefs.unregisterOnSharedPreferenceChangeListener(listener);
    }

    protected SharedPreferences getPrefs() {
        return prefs;
    }

    /**
     * An {@link android.content.SharedPreferences.Editor} decorator.
     */
    public static class SecuredEditor implements Editor {
        private Editor editor;
        private EncryptionHelper helper;

        /**
         * Initializes with the {@link EncryptionHelper} an the original
         * {@link android.content.SharedPreferences.Editor}.
         *
         * @param helper The helper to use.
         * @param edit   The editor to use.
         */
        public SecuredEditor(EncryptionHelper helper, Editor edit) {
            this.helper = helper;
            this.editor = edit;
        }

        @Override
        public SecuredEditor putString(String key, String value) {
            helper.putValue(editor, key, value);
            return this;
        }

        @Override
        public SecuredEditor putStringSet(String key, Set<String> values) {
            helper.putValue(editor, key, values);
            return this;
        }

        @Override
        public SecuredEditor putInt(String key, int value) {
            helper.putValue(editor, key, value);
            return this;
        }

        @Override
        public SecuredEditor putLong(String key, long value) {
            helper.putValue(editor, key, value);
            return this;
        }

        @Override
        public SecuredEditor putFloat(String key, float value) {
            helper.putValue(editor, key, value);
            return this;
        }

        @Override
        public SecuredEditor putBoolean(String key, boolean value) {
            helper.putValue(editor, key, value);
            return this;
        }

        @Override
        public SecuredEditor remove(String key) {
            editor.remove(key);
            return this;
        }

        @Override
        public SecuredEditor clear() {
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

        /**
         * Compatibility version of original {@link android.content.SharedPreferences.Editor#apply()}
         * method that simply call {@link android.content.SharedPreferences.Editor#commit()} for pre Android Honeycomb (API 11).
         * This method is thread safe also on pre API 11.
         * Note that when two editors are modifying preferences at the same time, the last one to call apply wins. (Android Doc)
         */
        public void save() {
            compatilitySave(this);
        }

        /**
         * Saves the {@link android.content.SharedPreferences}. See save method.
         *
         * @param editor The editor to save/commit.
         */
        @TargetApi(9)
        public static void compatilitySave(Editor editor) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.HONEYCOMB) {
                editor.apply();
            } else {
                synchronized (SecuredEditor.class) {
                    editor.commit();
                }
            }
        }

    }
}