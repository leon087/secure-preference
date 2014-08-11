package cm.android.preference.encryption;

import android.annotation.TargetApi;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.provider.Settings;
import android.text.TextUtils;
import cm.android.preference.util.PBECoder;
import cm.android.preference.util.SecureUtil;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

/**
 */
public class Encrypter implements IEncrypt {
    // private static final String AES_KEY_ALG = "AES/GCM/NoPadding";
    // private static final String AES_KEY_ALG = "AES/CBC/PKCS5Padding";
    private static final String AES_KEY_ALG = "AES";

    // change to SC if using Spongycastle crypto libraries
    public static final String PROVIDER = "BC";

    private byte[] key;

    public Encrypter() {
    }

    @Override
    public void initKey(byte[] key) {
        this.key = key;
    }

    @Override
    public byte[] encrypt(byte[] bytes) throws EncryptionException {
        if (bytes == null || bytes.length == 0) {
            return bytes;
        }
        try {
            final Cipher cipher = Cipher.getInstance(AES_KEY_ALG, PROVIDER);
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(
                    key, AES_KEY_ALG));
            return cipher.doFinal(bytes);
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
            final Cipher cipher = Cipher.getInstance(AES_KEY_ALG, PROVIDER);
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(
                    key, AES_KEY_ALG));
            return cipher.doFinal(bytes);
        } catch (Exception e) {
            return null;
        }
    }

    public static class KeyHelper {

        private static final int KEY_SIZE = 256;

        public static byte[] initKey(Context context, String tag, SharedPreferences preference) {
            // Initialize encryption/decryption key
            final char[] password = (context.getPackageName() + tag).toCharArray();
            final byte[] salt = getDeviceSerialNumber(context).getBytes();

            try {
                final String key = generateAesKeyName(context, tag);
                String value = preference.getString(key, null);
                if (value == null) {
                    //生成SecretKey
                    SecretKey secretKey = generateAesKeyValue();
                    //加密保存
                    byte[] encryptKey = PBECoder.encrypt(secretKey.getEncoded(), password, salt);
                    value = SecureUtil.encode(encryptKey);
                    preference.edit().putString(key, value).commit();
                }
                byte[] encryptKey = SecureUtil.decode(value);
                byte[] secretKeyEncoded = PBECoder.decrypt(encryptKey, password, salt);
                return secretKeyEncoded;
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }

        private static String generateAesKeyName(Context context, String tag)
                throws InvalidKeySpecException, NoSuchAlgorithmException,
                NoSuchProviderException {
            final char[] password = (context.getPackageName() + tag).toCharArray();

            final byte[] salt = getDeviceSerialNumber(context).getBytes();

            Key key = PBECoder.genHashKey(password, salt);
            return SecureUtil.encode(key.getEncoded());
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

        private static SecretKey generateAesKeyValue() throws NoSuchAlgorithmException {
            // Do *not* seed secureRandom! Automatically seeded from system entropy
            final SecureRandom random = new SecureRandom();

            // Use the largest AES key length which is supported by the OS
            final KeyGenerator generator = KeyGenerator.getInstance("AES");
            try {
                generator.init(KEY_SIZE, random);
            } catch (Exception e) {
                try {
                    generator.init(192, random);
                } catch (Exception e1) {
                    generator.init(128, random);
                }
            }

            return generator.generateKey();
            //return SecureUtil.encode(generator.generateKey().getEncoded());
        }
    }
}
