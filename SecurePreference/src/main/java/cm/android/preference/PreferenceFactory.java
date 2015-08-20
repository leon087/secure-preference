package cm.android.preference;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import android.content.Context;
import android.content.SharedPreferences;

import cm.android.preference.crypto.Cipher;
import cm.android.preference.crypto.ICipher;
import cm.android.preference.util.Util;

public final class PreferenceFactory {

    public static final int VERSION = 2;

    private static final Logger LOGGER = LoggerFactory.getLogger("SecurePreference");

    private PreferenceFactory() {
    }

//    public static SecureSharedPreferences getPreferences(SharedPreferences original, int version,
//            ICipher keyCipher, ICipher valueCipher) {
//        SecureSharedPreferences sharedPreferences;
//        if (original instanceof SecureSharedPreferences) {
//            sharedPreferences = (SecureSharedPreferences) original;
//        } else {
//            sharedPreferences = new SecureSharedPreferences(original, keyCipher, valueCipher);
//        }
//
//        int oldVersion = Util.getVersion(sharedPreferences);
//        if (oldVersion < version) {
//            LOGGER.info("oldVersion = {},version = {}", version, version);
////            Util.upgrade(sharedPreferences, version);
//        }
//        return sharedPreferences;
//    }

    public static SecureSharedPreferences getPreferences(Context context, String preferencesName,
            String password) {
        String tag = preferencesName + password;
        ICipher valueCipher = Cipher.KeyHelper.initCipher(context, tag);

        SharedPreferences original = context.getSharedPreferences(preferencesName,
                Context.MODE_PRIVATE);
        return getPreferences(context, tag, VERSION, valueCipher, original);
    }

    public static SecureSharedPreferences getPreferences(Context context, String tag, int version,
            ICipher valueCipher, SharedPreferences original) {
        Util.checkVersion(original, version);

        ICipher keyCipher = Cipher.KeyHelper.initKeyCipher(context, tag, valueCipher, original);
        SecureSharedPreferences securePreferences = new SecureSharedPreferences(original, keyCipher,
                valueCipher);

        return securePreferences;
    }
}
