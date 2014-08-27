package cm.android.preference.encryption;

import android.annotation.TargetApi;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.provider.Settings;
import android.text.TextUtils;
import cm.android.preference.util.AESCoder;
import cm.android.preference.util.PBEAESCoder;
import cm.android.preference.util.SecureUtil;
import cm.android.preference.util.Util;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
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
    public void initKey(byte[] key, byte[] iv) {
        this.key = key;
        this.iv = iv;
    }

    @Override
    public byte[] encrypt(byte[] bytes) throws EncryptionException {
        if (bytes == null || bytes.length == 0) {
            return bytes;
        }
        try {
            SecretKey secretKey = new SecretKeySpec(key, PBEAESCoder.CIPHER_ALGORITHM);
            return AESCoder.encrypt(key, iv, bytes);
//            return PBEAESCoder.encrypt(secretKey, iv, bytes);
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
            SecretKey secretKey = new SecretKeySpec(key, PBEAESCoder.CIPHER_ALGORITHM);
            return AESCoder.decrypt(key, iv, bytes);
//            return PBEAESCoder.decrypt(secretKey, iv, bytes);
        } catch (Exception e) {
            return null;
        }
    }

    public static class KeyHelper {

        private static final int KEY_SIZE = 256;

        public static byte[] initIv(Context context, String tag, SharedPreferences preference) {
            final char[] password = (context.getPackageName() + tag).toCharArray();
            final byte[] salt = getDeviceSerialNumber(context).getBytes();

            try {
                final String key = generateKeyName(password, salt);
                String value = preference.getString(key, null);
                if (value == null) {
                    byte[] iv = SecureUtil.generateIv();
                    byte[] encryptKey = PBEAESCoder.encrypt(password, salt, null, iv);
                    value = Util.encode(encryptKey);
                    preference.edit().putString(key, value).commit();
                    return iv;
                } else {
                    byte[] encryptData = Util.decode(value);
                    byte[] data = PBEAESCoder.decrypt(password, salt, null, encryptData);
                    return data;
                }
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }

        public static byte[] initKey(Context context, String tag, SharedPreferences preference) {
            // Initialize encryption/decryption key
            final char[] password = (context.getPackageName() + tag).toCharArray();
            final byte[] salt = getDeviceSerialNumber(context).getBytes();

            try {
//                Key key = PBEAESCoder.toKey(password, salt);
                Key key = AESCoder.generateKey((context.getPackageName() + tag).getBytes());
                return key.getEncoded();
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }
//        public static byte[] initKey(Context context, String tag, SharedPreferences preference) {
//            // Initialize encryption/decryption key
//            final char[] password = (context.getPackageName() + tag).toCharArray();
//            final byte[] salt = getDeviceSerialNumber(context).getBytes();
//
//            try {
//                final String key = generateAesKeyName(password, salt);
//                String value = preference.getString(key, null);
//                if (value == null) {
//                    //生成SecretKey
//                    SecretKey secretKey = AESCoder.generateKey();
//
//                    //加密保存
//                    byte[] encryptKey = PBECoder.encrypt(secretKey.getEncoded(), password, salt);
//                    value = Util.encode(encryptKey);
//                    preference.edit().putString(key, value).commit();
//                }
//                byte[] encryptKey = Util.decode(value);
//                byte[] secretKeyEncoded = PBECoder.decrypt(encryptKey, password, salt);
//                return secretKeyEncoded;
//            } catch (Exception e) {
//                throw new IllegalStateException(e);
//            }
//        }

        private static String generateKeyName(char[] password, byte[] salt)
                throws InvalidKeySpecException, NoSuchAlgorithmException,
                NoSuchProviderException {
//            Key key = PBECoder.genHashKey(password, salt);
            Key key = PBEAESCoder.toKey(password, salt);
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
