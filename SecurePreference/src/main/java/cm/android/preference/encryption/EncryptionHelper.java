package cm.android.preference.encryption;

import android.content.SharedPreferences;
import cm.android.preference.util.IoUtil;
import cm.android.preference.util.SecureUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

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
        String stringValue = prefs.getString(keyEncrypt, null);
        if (stringValue == null) {
            return defValue;
        }

        try {
            T result = readDecoded(stringValue);
            return result;
        } catch (EncryptionException e) {
            LOGGER.error("Error reading value by key: {}", key, e);
            return defValue;
        }
    }

    public <T> void putValue(SharedPreferences.Editor editor, String key, T value) {
        String keyEncrypt = encrypt(key.getBytes());
        String valueEncrypt = encode(value);
        editor.putString(keyEncrypt, valueEncrypt);
    }

    public void remove(SharedPreferences.Editor editor, String key) {
        String keyEncrypt = encrypt(key.getBytes());
        editor.remove(keyEncrypt);
    }

    public Map<String, ?> getAll(SharedPreferences prefs) {
        Map<String, ?> tmp = prefs.getAll();
        Map<String, Object> decryptedMap = new HashMap<String, Object>(tmp.size());

        Iterator iterator = tmp.entrySet().iterator();
        while (iterator.hasNext()) {
            Map.Entry<String, ?> entry = (Map.Entry<String, ?>) iterator.next();
            try {
                byte[] keyBytes = decrypt(entry.getKey());
                if (keyBytes == null) {
                    continue;
                }

                String key = new String(keyBytes);
                Object value = readDecoded((String) entry.getValue());
                decryptedMap.put(key, value);
            } catch (EncryptionException e) {
                continue;
            }
        }

        return decryptedMap;
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

    private <T> T readDecoded(String stringValue) throws EncryptionException {
        ObjectInputStream ois = null;
        try {
            byte[] decoded = decrypt(stringValue);
            ois = new ObjectInputStream(new ByteArrayInputStream(decoded));
            return (T) ois.readObject();
        } catch (Exception e) {
            throw new EncryptionException(e);
        } finally {
            IoUtil.closeQuietly(ois);
        }
    }


    public boolean contains(SharedPreferences preference, String key) {
        String keyEncrypt = encrypt(key.getBytes());
        return preference.contains(keyEncrypt);
    }
}
