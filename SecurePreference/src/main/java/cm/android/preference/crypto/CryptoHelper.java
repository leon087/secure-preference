package cm.android.preference.crypto;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import android.content.SharedPreferences;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import cm.android.preference.util.IoUtil;
import cm.android.preference.util.Util;

public class CryptoHelper {

    private static final Logger LOGGER = LoggerFactory.getLogger("SecurePreference");

    private ICipher valueCipher;

    private ICipher keyCipher;

    public CryptoHelper(ICipher keyCipher, ICipher valueCipher) {
        this.valueCipher = valueCipher;
        this.keyCipher = keyCipher;
    }

    @SuppressWarnings("unchecked")
    public <T> T getValue(SharedPreferences prefs, String key, T defValue) {
        String keyEncrypt = encryptKey(key.getBytes());
        String stringValue = prefs.getString(keyEncrypt, null);
        if (stringValue == null) {
            return defValue;
        }

        try {
            T result = readDecoded(stringValue);
            return result;
        } catch (CryptoException e) {
            LOGGER.error("Error reading value by key: {}", key, e);
            return defValue;
        }
    }

    public <T> void putValue(SharedPreferences.Editor editor, String key, T value) {
        String keyEncrypt = encryptKey(key.getBytes());
        String valueEncrypt = encode(value);
        editor.putString(keyEncrypt, valueEncrypt);
    }

    public void remove(SharedPreferences.Editor editor, String key) {
        String keyEncrypt = encryptKey(key.getBytes());
        editor.remove(keyEncrypt);
    }

    public Map<String, ?> getAll(SharedPreferences prefs) {
        Map<String, ?> tmp = prefs.getAll();
        Map<String, Object> decryptedMap = new HashMap<String, Object>(tmp.size());

        Iterator iterator = tmp.entrySet().iterator();
        while (iterator.hasNext()) {
            Map.Entry<String, ?> entry = (Map.Entry<String, ?>) iterator.next();
            try {
                byte[] keyBytes = decryptKey(entry.getKey());
                if (keyBytes == null) {
                    continue;
                }

                String key = new String(keyBytes);
                Object value = readDecoded((String) entry.getValue());
                decryptedMap.put(key, value);
            } catch (CryptoException e) {
                continue;
            }
        }

        return decryptedMap;
    }

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
            byte[] encrypt = valueCipher.encrypt(byteArray);
            String result = Util.encodeBase64(encrypt);
            return result;
        } catch (CryptoException e) {
            LOGGER.error("Error encoding value", e);
            return new String(byteArray);
        }
    }

    private byte[] decrypt(String stringValue) throws CryptoException {
        byte[] decodedBytes = Util.decodeBase64(stringValue);
        byte[] decoded = valueCipher.decrypt(decodedBytes);
        return decoded;
    }

    private <T> T readDecoded(String stringValue) throws CryptoException {
        ObjectInputStream ois = null;
        try {
            byte[] decoded = decrypt(stringValue);
            ois = new ObjectInputStream(new ByteArrayInputStream(decoded));
            return (T) ois.readObject();
        } catch (Exception e) {
            throw new CryptoException(e);
        } finally {
            IoUtil.closeQuietly(ois);
        }
    }


    public boolean contains(SharedPreferences preference, String key) {
        String keyEncrypt = encryptKey(key.getBytes());
        return preference.contains(keyEncrypt);
    }

    public String encryptKey(byte[] keyByteArray) {
        try {
            //确保返回的值固定
            byte[] encrypt = keyCipher.encrypt(keyByteArray);
            String result = Util.encodeBase64(encrypt);
            return result;
        } catch (CryptoException e) {
            LOGGER.error("Error encoding value", e);
            return new String(keyByteArray);
        } catch (Exception e) {
            LOGGER.error("Error encoding value", e);
            return new String(keyByteArray);
        }
    }

    public byte[] decryptKey(String stringValue) {
        byte[] decodedBytes = Util.decodeBase64(stringValue);
        try {
            byte[] decoded = keyCipher.decrypt(decodedBytes);
            return decoded;
        } catch (Exception e) {
            LOGGER.error(e.getMessage(), e);
            return null;
        }
    }
}
