package cm.android.preference;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import android.content.Context;
import android.content.SharedPreferences;

import cm.android.preference.crypto.Cipher;
import cm.android.preference.crypto.ICipher;
import cm.android.preference.util.Util;

public final class PreferenceFactory {

    private static final String INITIALIZATION_ERROR = "Can not initialize SecureSharedPreferences";

    public static final int VERSION_1 = 1;

    public static final int LATEST_VERSION = VERSION_1;

    private static final Logger LOGGER = LoggerFactory.getLogger("SecurePreference");

    private PreferenceFactory() {
    }

    public static SecureSharedPreferences getPreferences(SharedPreferences original,
            ICipher keyCipher, ICipher valueCipher) {
        SecureSharedPreferences sharedPreferences;
        if (original instanceof SecureSharedPreferences) {
            sharedPreferences = (SecureSharedPreferences) original;
        } else {
            sharedPreferences = new SecureSharedPreferences(original, keyCipher, valueCipher);
        }
        if (Util.getVersion(sharedPreferences) < VERSION_1) {
            LOGGER.info("Initial migration to Secure storage.");
            //Util.migrateData(original, sharedPreferences, VERSION_1);
        }
        return sharedPreferences;
    }

    public static SecureSharedPreferences getPreferences(Context context, String preferencesName,
            ICipher keyCipher, ICipher valueCipher) {
        SharedPreferences preference = context
                .getSharedPreferences(preferencesName, Context.MODE_PRIVATE);
        return getPreferences(preference, keyCipher, valueCipher);
    }

    public static SecureSharedPreferences getPreferences(Context context, String preferencesName) {
        SharedPreferences preference = context
                .getSharedPreferences(preferencesName, Context.MODE_PRIVATE);
        ICipher cipher = new Cipher();
        byte[] key = Cipher.KeyHelper.initKey(context, preferencesName, preference);
        byte[] iv = Cipher.KeyHelper.initIv(context, preferencesName, preference);
        cipher.initKey(key, iv, preferencesName);

        return getPreferences(preference, cipher, cipher);
    }

}
