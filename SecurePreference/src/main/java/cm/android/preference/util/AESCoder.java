package cm.android.preference.util;

import android.annotation.TargetApi;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class AESCoder {

    private static final int KEY_LENGTH = 16;

    public static final String ALG_AES = "AES";

    public static final String C_AES_CBC_PKCS5PADDING = "AES/CBC/PKCS5Padding";

    public static final String C_AES_GCM = "AES/GCM/NoPadding";

    /**
     * BouncyCastleProvider
     */
    public static final String PROVIDER_BC = "BC";

    private AESCoder() {
    }

    public static SecretKey generateKey() throws NoSuchAlgorithmException {
        return generateKey(KEY_LENGTH);
    }

    public static SecretKey generateKey(int keyLength) throws NoSuchAlgorithmException {
        final SecureRandom random = new SecureRandom();

        final KeyGenerator generator = KeyGenerator.getInstance(ALG_AES);

        int keySizeBit = SecureUtil.convertSize(keyLength);
        generator.init(keySizeBit, random);

        return generator.generateKey();
    }

    public static SecretKey generateKey(char[] password, byte[] salt, int keyLength)
            throws InvalidKeySpecException {
        SecretKey tmp = HashUtil.generateHash(password, salt, keyLength);
        SecretKey secret = getSecretKey(tmp.getEncoded());
        return secret;
    }

    public static SecretKey getSecretKey(byte[] key) {
        SecretKey secret = new SecretKeySpec(key, ALG_AES);
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

    public static byte[] decrypt(SecretKey secretKey, byte[] iv, byte[] src)
            throws Exception {
        IvParameterSpec ivSpec = SecureUtil.getIv(iv);

        Cipher cipher = Cipher.getInstance(C_AES_CBC_PKCS5PADDING);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
        byte[] decrypted = cipher.doFinal(src);
        return decrypted;
    }

    /**
     * 需要BC支持<br>
     * BouncyCastleProvider provider = new BouncyCastleProvider(); <br>
     * Security.addProvider(provider);
     */
    @TargetApi(19)
    public static byte[] encrypt(SecretKey secretKey, byte[] iv, byte[] aad, byte[] src)
            throws Exception {
        IvParameterSpec ivSpec = SecureUtil.getIv(iv);

        Cipher cipher = Cipher.getInstance(C_AES_GCM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        cipher.updateAAD(aad);
        byte[] encrypted = cipher.doFinal(src);
        return encrypted;
    }

    /**
     * 需要BC支持<br>
     * BouncyCastleProvider provider = new BouncyCastleProvider(); <br>
     * Security.addProvider(provider);
     */
    @TargetApi(19)
    public static byte[] decrypt(SecretKey secretKey, byte[] iv, byte[] aad, byte[] src)
            throws Exception {
        IvParameterSpec ivSpec = SecureUtil.getIv(iv);

        Cipher cipher = Cipher.getInstance(C_AES_GCM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
        cipher.updateAAD(aad);
        byte[] decrypted = cipher.doFinal(src);
        return decrypted;
    }

}
