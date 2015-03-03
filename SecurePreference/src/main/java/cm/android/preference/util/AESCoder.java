package cm.android.preference.util;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class AESCoder {

    private static final int KEY_SIZE = 128;

    public static final String KEY_ALGORITHM = "AES";

    public static final String C_AES_CBC_PKCS5PADDING = "AES/CBC/PKCS5Padding";

    private AESCoder() {
    }

    public static SecretKey generateKey() throws NoSuchAlgorithmException {
        return generateKey(KEY_SIZE);
    }

    public static SecretKey generateKey(int keySize) throws NoSuchAlgorithmException {
        // Do *not* seed secureRandom! Automatically seeded from system entropy
        final SecureRandom random = new SecureRandom();

        final KeyGenerator generator = KeyGenerator.getInstance(KEY_ALGORITHM);
        generator.init(keySize, random);

        return generator.generateKey();
    }

    public static SecretKey generateKey(char[] password, byte[] salt, int keySize)
            throws InvalidKeySpecException {
        SecretKey tmp = HashUtil.generateHash(password, salt, keySize);
        SecretKey secret = getSecretKey(tmp.getEncoded());
        return secret;
    }

    private static SecretKey getSecretKey(byte[] key) {
        SecretKey secret = new SecretKeySpec(key, KEY_ALGORITHM);
        return secret;
    }

    public static byte[] encrypt(byte[] key, byte[] iv, byte[] src) throws Exception {
        SecretKey secret = getSecretKey(key);
        return encrypt(secret, iv, src);
    }

    public static byte[] decrypt(byte[] key, byte[] iv, byte[] encrypted) throws Exception {
        SecretKey secret = getSecretKey(key);
        return decrypt(secret, iv, encrypted);
    }

    public static byte[] encrypt(SecretKey secretKey, byte[] iv, byte[] src) throws Exception {
        IvParameterSpec ivSpec = SecureUtil.getIv(iv);

        Cipher cipher = Cipher.getInstance(C_AES_CBC_PKCS5PADDING);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        byte[] encrypted = cipher.doFinal(src);
        return encrypted;
    }

    public static byte[] decrypt(SecretKey secretKey, byte[] iv, byte[] encrypted)
            throws Exception {
        IvParameterSpec ivSpec = SecureUtil.getIv(iv);

        Cipher cipher = Cipher.getInstance(C_AES_CBC_PKCS5PADDING);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
        byte[] decrypted = cipher.doFinal(encrypted);
        return decrypted;
    }

}
