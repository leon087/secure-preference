package cm.android.preference.crypto;

import android.annotation.TargetApi;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.provider.Settings;
import android.text.TextUtils;

import java.security.Key;

import javax.crypto.SecretKey;

import cm.android.preference.util.AESCoder;
import cm.android.preference.util.SecureUtil;
import cm.android.preference.util.Util;

public class Cipher implements ICipher {

    private byte[] key;

    private byte[] iv;

    public Cipher() {
    }

    @Override
    public void initKey(byte[] key, byte[] iv, String tag) {
        this.key = key;
        this.iv = iv;
    }

    @Override
    public byte[] encrypt(byte[] bytes) throws CryptoException {
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
    public byte[] decrypt(byte[] bytes) throws CryptoException {
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
            String password = getPassword(context, tag);
            final byte[] salt = SecureUtil.SALT_DEF;//

            try {
                SecretKey aesSecretKey = AESCoder.generateKey(password.getBytes());
//                SecretKey aesSecretKey = AESCoder.generateKey(password, salt);
                String keyName = Util.encodeBase64(aesSecretKey.getEncoded());

                String value = preference.getString(keyName, null);
                if (value == null) {
                    byte[] iv = SecureUtil.generateIv();
                    byte[] encryptKey = AESCoder.encrypt(aesSecretKey, null, iv);
                    value = Util.encodeBase64(encryptKey);
                    preference.edit().putString(keyName, value).commit();
                    return iv;
                } else {
                    byte[] encryptData = Util.decodeBase64(value);
                    byte[] data = AESCoder.decrypt(aesSecretKey, null, encryptData);
                    return data;
                }
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }

        private static String getPassword(Context context, String tag) {
            String deviceId = getDeviceSerialNumber(context);
            byte[] fingerprint = Util.getFingerprint(context, tag + deviceId);
            return Util.encodeBase64(fingerprint);
        }

        public static byte[] initKey(Context context, String tag, SharedPreferences preference) {
            final String password = getPassword(context, tag);

            try {
                Key key = AESCoder.generateKey(password.getBytes());
                return key.getEncoded();
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }

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
