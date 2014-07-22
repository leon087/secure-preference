package cm.android.sdk.preference.encryption;

import android.annotation.TargetApi;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.provider.Settings;
import android.text.TextUtils;
import cm.android.sdk.preference.util.SecureUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

/**
 * Encrypting / decrypting support algorithms and type conversions.
 */
public class EncryptionHelper {
    private static final Logger LOGGER = LoggerFactory.getLogger(EncryptionHelper.class);
    private IEncrypt encryption;

    /**
     * Initializes with ecryption.
     *
     * @param encryption The {@link IEncrypt} to use.
     */
    public EncryptionHelper(IEncrypt encryption) {
        super();
        this.encryption = encryption;
    }

    /**
     * Reads a value from a {@link android.content.SharedPreferences}.
     *
     * @param <T>      The type of the result and the default value.
     * @param prefs    The preferences to use.
     * @param key      The key to read.
     * @param defValue The default value, when the key does not exist.
     * @return Return the T type of result.
     */
    @SuppressWarnings("unchecked")
    public <T> T getValue(SharedPreferences prefs, String key, T defValue) {
        String keyEncrypt = encrypt(key.getBytes());

        T result = defValue;
        ObjectInputStream ois = readDecoded(prefs, keyEncrypt);
        if (ois != null) {
            try {
                result = (T) ois.readObject();
            } catch (IOException e) {
                LOGGER.error("Error reading value by key: {}", key, e);
            } catch (ClassNotFoundException e) {
                LOGGER.error("Error reading value by key: {}", key, e);
            }
        }
        return result;
    }

    public <T> void putValue(SharedPreferences.Editor editor, String key, T value) {
        String keyEncrypt = encrypt(key.getBytes());
        String valueEncrypt = encode(value);
        editor.putString(keyEncrypt, valueEncrypt);
    }

    /**
     * Encodes a single value to string.
     * May result null on an internal problem.
     *
     * @param <T>   The type of the value.
     * @param value The T type of value to encrypt.
     * @return The encrypted value as string.
     */
    private <T> String encode(T value) {
        String result = null;
        if (value != null) {
            try {
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                ObjectOutputStream oos = new ObjectOutputStream(baos);
                oos.writeObject(value);
                byte[] byteArray = baos.toByteArray();
                result = encrypt(byteArray);
            } catch (IOException e) {
                LOGGER.error("Error encoding value", e);
            }
        }
        return result;
    }

    private <T> String encrypt(byte[] byteArray) {
        try {
            byte[] encrypt = encryption.encrypt(byteArray);
            String result = SecureUtil.encode(encrypt);
            return result;
        } catch (EncryptionException e) {
            LOGGER.error("Error encoding value", e);
            return new String(byteArray);
        }
    }

    private byte[] decrypt(String stringValue) throws EncryptionException {
        byte[] decodedBytes = SecureUtil.decode(stringValue);
        byte[] decoded = encryption.decrypt(decodedBytes);
        return decoded;
    }

    private ObjectInputStream readDecoded(SharedPreferences prefs, String key) {
        String stringValue = prefs.getString(key, null);
        ObjectInputStream result;
        if (stringValue != null) {
            try {
                result = createDecodedObjectStream(stringValue);
            } catch (EncryptionException e) {
                LOGGER.error("Error reading from properties. Key: {}", key, e);
                result = null;
            }
        } else {
            result = null;
        }
        return result;
    }

    private ObjectInputStream createDecodedObjectStream(String stringValue) throws EncryptionException {
        byte[] decoded = decrypt(stringValue);
        try {
            return new ObjectInputStream(new ByteArrayInputStream(decoded));
        } catch (IOException e) {
            throw new EncryptionException(e);
        }
    }

    public boolean contains(SharedPreferences preference, String key) {
        String keyEncrypt = encrypt(key.getBytes());
        return preference.contains(keyEncrypt);
    }

    public static class KeyHelper {

        private static final int KEY_SIZE = 256;

        private static final String PRIMARY_PBE_KEY_ALG = "PBKDF2WithHmacSHA1";
        private static final String BACKUP_PBE_KEY_ALG = "PBEWithMD5AndDES";
        private static final int ITERATIONS = 2000;

        public static byte[] initKey(Context context, SharedPreferences preference) {
            // Initialize encryption/decryption key
            try {
                final String key = generateAesKeyName(context);
                String value = preference.getString(key, null);
                if (value == null) {
                    value = generateAesKeyValue();
                    preference.edit().putString(key, value).commit();
                }
                return SecureUtil.decode(value);
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }

        private static String generateAesKeyName(Context context)
                throws InvalidKeySpecException, NoSuchAlgorithmException,
                NoSuchProviderException {
            final char[] password = context.getPackageName().toCharArray();

            final byte[] salt = getDeviceSerialNumber(context).getBytes();

            SecretKey key;
            try {
                // TODO: what if there's an OS upgrade and now supports the primary
                // PBE
                key = generatePBEKey(password, salt,
                        PRIMARY_PBE_KEY_ALG, ITERATIONS, KEY_SIZE);
            } catch (NoSuchAlgorithmException e) {
                // older devices may not support the have the implementation try
                // with a weaker
                // algorthm
                key = generatePBEKey(password, salt,
                        BACKUP_PBE_KEY_ALG, ITERATIONS, KEY_SIZE);
            }
            return SecureUtil.encode(key.getEncoded());
        }

        /**
         * Derive a secure key based on the passphraseOrPin
         *
         * @param passphraseOrPin
         * @param salt
         * @param algorthm        - which PBE algorthm to use. some <4.0 devices don;t support
         *                        the prefered PBKDF2WithHmacSHA1
         * @param iterations      - Number of PBKDF2 hardening rounds to use. Larger values
         *                        increase computation time (a good thing), defaults to 1000 if
         *                        not set.
         * @param keyLength
         * @return Derived Secretkey
         * @throws java.security.NoSuchAlgorithmException
         * @throws java.security.spec.InvalidKeySpecException
         * @throws java.security.NoSuchProviderException
         */
        private static SecretKey generatePBEKey(char[] passphraseOrPin,
                                                byte[] salt, String algorthm, int iterations, int keyLength)
                throws NoSuchAlgorithmException, InvalidKeySpecException,
                NoSuchProviderException {

            if (iterations == 0) {
                iterations = 1000;
            }

            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(
                    algorthm, Encrypter.PROVIDER);
            KeySpec keySpec = new PBEKeySpec(passphraseOrPin, salt, iterations,
                    keyLength);
            SecretKey secretKey = secretKeyFactory.generateSecret(keySpec);
            return secretKey;
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

        private static String generateAesKeyValue() throws NoSuchAlgorithmException {
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
            return SecureUtil.encode(generator.generateKey().getEncoded());
        }
    }

}
