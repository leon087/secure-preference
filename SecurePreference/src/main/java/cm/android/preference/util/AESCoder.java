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

    private static final int KEY_SIZE = 256;

    public static final String KEY_ALGORITHM = "AES";

    public static final String C_AES_CBC_PKCS5PADDING = "AES/CBC/PKCS5Padding";

    private AESCoder() {
    }

    public static SecretKey generateKey() throws NoSuchAlgorithmException {
        // Do *not* seed secureRandom! Automatically seeded from system entropy
        final SecureRandom random = new SecureRandom();

        // Use the largest AES key length which is supported by the OS
        final KeyGenerator generator = KeyGenerator.getInstance(KEY_ALGORITHM);
        try {
            generator.init(KEY_SIZE, random);
        } catch (Exception e) {
            generator.init(128, random);
        }

        return generator.generateKey();
        //return SecureUtil.encode(generator.generateKey().getEncoded());
    }

    public static SecretKey generateKey(char[] password, byte[] salt)
            throws InvalidKeySpecException {
        SecretKey tmp = HashUtil.generateHash(password, salt);
        SecretKey secret = getSecretKey(tmp.getEncoded());
        return secret;
    }

    public static SecretKey generateKey(byte[] key) {
        byte[] tmp = HashUtil.getSha(key);
        SecretKey secret = getSecretKey(tmp);
        return secret;
    }

    private static SecretKey getSecretKey(byte[] key) {
        SecretKey secret = new SecretKeySpec(key, C_AES_CBC_PKCS5PADDING);
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
