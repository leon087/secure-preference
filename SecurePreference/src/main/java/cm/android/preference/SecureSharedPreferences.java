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
}
