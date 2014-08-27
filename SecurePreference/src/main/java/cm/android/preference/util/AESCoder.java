package cm.android.preference.util;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class AESCoder {
    private static final int KEY_SIZE = 256;

    public static final String KEY_ALGORITHM = "AES";

    public static final String RANDOM_ALGORITHM = "SHA1PRNG";

    /**
     * 加密/解密算法/工作模式/填充方式
     * <p/>
     * JAVA6 支持PKCS5PADDING填充方式 Bouncy castle支持PKCS7Padding填充方式
     */
    public static final String CIPHER_ALGORITHM = "AES/ECB/PKCS5Padding";

    public static byte[] encrypt(String key, byte[] iv, byte[] data) throws Exception {
        byte[] rawKey = generateKey(key.getBytes()).getEncoded();
        byte[] result = encrypt(rawKey, iv, data);
        return result;
    }

    public static byte[] decrypt(String key, byte[] iv, byte[] encrypted) throws Exception {
        byte[] rawKey = generateKey(key.getBytes()).getEncoded();
        byte[] result = decrypt(rawKey, iv, encrypted);
        return result;
    }

    public static SecretKey generateKey(byte[] seed) throws Exception {
        KeyGenerator kgen = KeyGenerator.getInstance(KEY_ALGORITHM);
        // SHA1PRNG 强随机种子算法, 要区别4.2以上版本的调用方法
        SecureRandom sr = null;
        try {
            sr = SecureRandom.getInstance(RANDOM_ALGORITHM, "Crypto");
        } catch (Exception e) {
            sr = SecureRandom.getInstance(RANDOM_ALGORITHM);
        }
        sr.setSeed(seed);
        kgen.init(256, sr); //256 bits or 128 bits,192bits
        SecretKey secretKey = kgen.generateKey();
        return secretKey;
    }

    public static byte[] encrypt(byte[] key, byte[] iv, byte[] src) throws Exception {
        SecretKeySpec skeySpec = new SecretKeySpec(key, KEY_ALGORITHM);
        IvParameterSpec ivSpec = SecureUtil.getIv(iv);

        Cipher cipher = Cipher.getInstance(KEY_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, ivSpec);
        byte[] encrypted = cipher.doFinal(src);
        return encrypted;
    }

    public static byte[] decrypt(byte[] key, byte[] iv, byte[] encrypted) throws Exception {
        SecretKeySpec skeySpec = new SecretKeySpec(key, KEY_ALGORITHM);
        IvParameterSpec ivSpec = SecureUtil.getIv(iv);

        Cipher cipher = Cipher.getInstance(KEY_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, ivSpec);
        byte[] decrypted = cipher.doFinal(encrypted);
        return decrypted;
    }

    public static SecretKey generateKey() throws NoSuchAlgorithmException {
        // Do *not* seed secureRandom! Automatically seeded from system entropy
        final SecureRandom random = new SecureRandom();

        // Use the largest AES key length which is supported by the OS
        final KeyGenerator generator = KeyGenerator.getInstance(KEY_ALGORITHM);
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
