package cm.android.preference;

import android.content.Context;
import android.content.SharedPreferences;
import cm.android.preference.encryption.Encrypter;
import cm.android.preference.encryption.IEncrypt;
import cm.android.preference.util.SecureUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A factory class to ease the creation of the SecureSharedPreferences instance.
 */
public final class SecureFactory {
    private static final String INITIALIZATION_ERROR = "Can not initialize SecureSharedPreferences";
    public static final int VERSION_1 = 1;
    public static final int LATEST_VERSION = VERSION_1;
    private static final Logger LOGGER = LoggerFactory.getLogger(SecureFactory.class);

    /**
     * Hidden util constructor.
     */
    private SecureFactory() {
    }

    /**
     * Creates the {@link SecureSharedPreferences} instance with a given original and an {@link cm.android.preference.encryption.IEncrypt}.
     * This function does a version check and the required migrations when the local structure is outdated or not encrypted yet.
     *
     * @param original   The original {@link android.content.SharedPreferences}, which can be also a {@link SecureSharedPreferences} instance.
     * @param encryption The {@link cm.android.preference.encryption.IEncrypt} to use.
     * @return A {@link SecureSharedPreferences} instance.
     */
    public static SecureSharedPreferences getPreferences(SharedPreferences original, IEncrypt encryption) {
        SecureSharedPreferences sharedPreferences;
        if (original instanceof SecureSharedPreferences) {
            sharedPreferences = (SecureSharedPreferences) original;
        } else {
            sharedPreferences = new SecureSharedPreferences(original, encryption);
        }
        if (SecureUtil.getVersion(sharedPreferences) < VERSION_1) {
            LOGGER.info("Initial migration to Secure storage.");
            //SecureUtil.migrateData(original, sharedPreferences, VERSION_1);
        }
        return sharedPreferences;
    }

    /**
     * Creates a {@link SecureSharedPreferences} instance.
     *
     * @param context         The current context.
     * @param preferencesName The name of the {@link android.content.SharedPreferences}.
     * @param encryption      The {@link cm.android.preference.encryption.IEncrypt} to use.
     * @return The initialized {@link SecureSharedPreferences}.
     */
    public static SecureSharedPreferences getPreferences(Context context, String preferencesName, IEncrypt encryption) {
        return getPreferences(context.getSharedPreferences(preferencesName, Context.MODE_PRIVATE), encryption);
    }

    public static SecureSharedPreferences getPreferences(Context context, String preferencesName) {
        SharedPreferences preference = context.getSharedPreferences(preferencesName, Context.MODE_PRIVATE);
        IEncrypt encryption = new Encrypter();
        encryption.initKey(Encrypter.KeyHelper.initKey(context, preferencesName, preference));
        return getPreferences(preference, encryption);
    }
}
