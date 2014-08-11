package cm.android.preference.util;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

public class PBECoder {
    private static final int KEY_SIZE = 256;
    // change to SC if using Spongycastle crypto libraries
    public static final String PROVIDER = "BC";

    private static final String PRIMARY_PBE_KEY_ALG = "PBKDF2WithHmacSHA1";
    private static final String BACKUP_PBE_KEY_ALG = "PBEWithMD5AndDES";
    private static final int ITERATIONS = 2000;

    public static byte[] initSalt() {
        // 实例化安全随机数
        SecureRandom random = new SecureRandom();
        // 产出盐
        return random.generateSeed(8);
    }

    public static SecretKey genHashKey(char[] password, byte[] salt) throws InvalidKeySpecException, NoSuchAlgorithmException,
            NoSuchProviderException {
        SecretKey key;
        try {
            // TODO: what if there's an OS upgrade and now supports the primary PBE
            key = generatePBEKey(password, salt,
                    PRIMARY_PBE_KEY_ALG, ITERATIONS, KEY_SIZE);
        } catch (NoSuchAlgorithmException e) {
            // older devices may not support the have the implementation try with a weaker algorthm
            key = generatePBEKey(password, salt,
                    BACKUP_PBE_KEY_ALG, ITERATIONS, KEY_SIZE);
        }
        return key;
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
                algorthm, PROVIDER);
        KeySpec keySpec = new PBEKeySpec(passphraseOrPin, salt, iterations,
                keyLength);
        SecretKey secretKey = secretKeyFactory.generateSecret(keySpec);
        return secretKey;
    }

    public static Key toKey(char[] password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        // 密钥彩礼转换
        PBEKeySpec keySpec = new PBEKeySpec(password, salt, ITERATIONS);
        SecretKeyFactory keyFactory = null;
        // 实例化
        keyFactory = SecretKeyFactory.getInstance(BACKUP_PBE_KEY_ALG);
        // 生成密钥
        SecretKey secretKey = keyFactory.generateSecret(keySpec);

        return secretKey;
    }

    /**
     * 加密
     *
     * @param data     待加密数据
     * @param password 密码
     * @param salt     盐
     * @return byte[] 加密数据
     */
    public static byte[] encrypt(byte[] data, char[] password, byte[] salt)
            throws Exception {
        // 转换密钥
        Key key = toKey(password, salt);
        // 实例化PBE参数材料
        PBEParameterSpec paramSpec = new PBEParameterSpec(salt, ITERATIONS);
        // 实例化
        Cipher cipher = null;
        cipher = Cipher.getInstance(BACKUP_PBE_KEY_ALG, PROVIDER);

        // 初始化
        cipher.init(Cipher.ENCRYPT_MODE, key, paramSpec);
        // 执行操作
        return cipher.doFinal(data);
    }

    /**
     * 解密
     *
     * @param data     待解密数据
     * @param password 密码
     * @param salt     盐
     * @return byte[] 解密数据
     */
    public static byte[] decrypt(byte[] data, char[] password, byte[] salt)
            throws Exception {
        // 转换密钥
        Key key = toKey(password, salt);
        // 实例化PBE参数材料
        PBEParameterSpec paramSpec = new PBEParameterSpec(salt, ITERATIONS);
        // 实例化
        Cipher cipher = null;
        cipher = Cipher.getInstance(BACKUP_PBE_KEY_ALG, PROVIDER);
        // 初始化
        cipher.init(Cipher.DECRYPT_MODE, key, paramSpec);
        // 执行操作
        return cipher.doFinal(data);
    }
}
