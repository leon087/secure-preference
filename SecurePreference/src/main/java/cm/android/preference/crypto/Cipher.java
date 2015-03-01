package cm.android.preference.crypto;

import android.annotation.TargetApi;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.provider.Settings;
import android.text.TextUtils;

import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKey;

import cm.android.preference.util.AESCoder;
import cm.android.preference.util.HashUtil;
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
            char[] password = getPassword(context, tag).toCharArray();
            final byte[] salt = getDeviceSerialNumber(context).getBytes();//

            try {
                final String key = generateKeyName(password, salt);
                String value = preference.getString(key, null);
                if (value == null) {
                    byte[] iv = SecureUtil.generateIv();
                    SecretKey secretKey = AESCoder.generateKey(key.toCharArray(), null);
                    byte[] encryptKey = AESCoder.encrypt(secretKey, null, iv);
                    value = Util.encode(encryptKey);
                    preference.edit().putString(key, value).commit();
                    return iv;
                } else {
                    byte[] encryptData = Util.decode(value);
                    SecretKey secretKey = AESCoder.generateKey(key.toCharArray(), null);
                    byte[] data = AESCoder.decrypt(secretKey, null, encryptData);
                    return data;
                }
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }

        private static String getPassword(Context context, String tag) {
            String sigStr = "";
            android.content.pm.Signature[] signatures = Util
                    .getSignature(context.getPackageManager(), context.getPackageName());
            if (signatures != null && signatures.length > 0) {
                sigStr = signatures[0].toCharsString();
            }
            return context.getPackageName() + tag + sigStr;
        }

        public static byte[] initKey(Context context, String tag, SharedPreferences preference) {
            final char[] password = getPassword(context, tag).toCharArray();

            try {
                Key key = AESCoder.generateKey(password, null);
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
