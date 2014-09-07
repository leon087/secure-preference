package cm.android.preference.encryption;

import android.annotation.TargetApi;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.provider.Settings;
import android.text.TextUtils;
import cm.android.preference.util.AESCoder;
import cm.android.preference.util.HashUtil;
import cm.android.preference.util.SecureUtil;
import cm.android.preference.util.Util;

import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;

/**
 */
public class Encrypter implements IEncrypt {

    private byte[] key;
    private byte[] iv;

    public Encrypter() {
    }

    @Override
    public void initKey(byte[] key, byte[] iv, String tag) {
        this.key = key;
        this.iv = iv;
    }

    @Override
    public byte[] encrypt(byte[] bytes) throws EncryptionException {
        if (bytes == null || bytes.length == 0) {
            return bytes;
        }
        try {
            return AESCoder.encrypt(key, iv, bytes);
        } catch (Exception e) {
            return null;
        }
    }

    @Override
    public byte[] decrypt(byte[] bytes) throws EncryptionException {
        if (bytes == null || bytes.length == 0) {
            return bytes;
        }
        try {
            return AESCoder.decrypt(key, iv, bytes);
        } catch (Exception e) {
            return null;
        }
    }

    public static class KeyHelper {

        public static byte[] initIv(Context context, String tag, SharedPreferences preference) {
            char[] password = getPassword(context, tag).toCharArray();
            final byte[] salt = getDeviceSerialNumber(context).getBytes();//

            try {
                final String key = generateKeyName(password, salt);
                String value = preference.getString(key, null);
                if (value == null) {
                    byte[] iv = SecureUtil.generateIv();
                    byte[] encryptKey = AESCoder.encryptBySeed(key.getBytes(), null, iv);
                    value = Util.encode(encryptKey);
                    preference.edit().putString(key, value).commit();
                    return iv;
                } else {
                    byte[] encryptData = Util.decode(value);
                    byte[] data = AESCoder.decryptBySeed(key.getBytes(), null, encryptData);
                    return data;
                }
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }

        private static String getPassword(Context context, String tag) {
            String sigStr = "";
            android.content.pm.Signature[] signatures = Util.getSignature(context.getPackageManager(), context.getPackageName());
            if (signatures != null && signatures.length > 0) {
                sigStr = signatures[0].toCharsString();
            }
            return context.getPackageName() + tag + sigStr;
        }

        public static byte[] initKey(Context context, String tag, SharedPreferences preference) {
            final byte[] seed = getPassword(context, tag).getBytes();

            try {
                Key key = AESCoder.generateKey(seed);
                return key.getEncoded();
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }

        private static String generateKeyName(char[] password, byte[] salt)
                throws InvalidKeySpecException, NoSuchAlgorithmException,
                NoSuchProviderException {
            Key key = HashUtil.generateHash(password, salt, 256);
            return Util.encode(key.getEncoded());
        }

        /**
         * Gets the hardware serial number of this device.
         *
         * @return serial number or Settings.Secure.ANDROID_ID if not available.
         */
        @TargetApi(3)
        private static String getDeviceSerialNumber(Context context) {
            // We're using the Reflection API because Build.SERIAL is only available
            // since API Level 9 (Gingerbread, Android 2.3).
            try {
                String deviceSerial = (String) Build.class.getField("SERIAL").get(
                        null);
                if (TextUtils.isEmpty(deviceSerial)) {
                    deviceSerial = Settings.Secure.getString(
                            context.getContentResolver(),
                            Settings.Secure.ANDROID_ID);
                }
                return deviceSerial;
            } catch (Exception ignored) {
                // default to Android_ID
                return Settings.Secure.getString(context.getContentResolver(),
                        Settings.Secure.ANDROID_ID);
            }
        }
    }
}
