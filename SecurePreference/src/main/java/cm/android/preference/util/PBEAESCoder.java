package cm.android.preference.util;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

public class PBEAESCoder {
    public static final int PBE_ITERATION_COUNT = 1024;

    public static final String RANDOM_ALGORITHM = "SHA1PRNG";
    public static final String PBE_ALGORITHM = "PBEWithSHA256And256BitAES-CBC-BC";
    public static final String PBK_ALGORITHM = "PBKDF2WithHmacSHA1";
    public static final String CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";

    public static byte[] encrypt(char[] password, byte[] salt, byte[] iv, byte[] data)
            throws Exception {
        SecretKey secret = toKey(password, salt);
        return encrypt(secret, iv, data);
    }

    public static byte[] decrypt(char[] password, byte[] salt, byte[] iv, byte[] data) throws Exception {
        SecretKey secret = toKey(password, salt);
        return decrypt(secret, iv, data);
    }

    public static byte[] encrypt(SecretKey key, byte[] iv, byte[] data) throws Exception {
        IvParameterSpec ivSpec = SecureUtil.getIv(iv);

        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        return cipher.doFinal(data);
    }

    public static byte[] decrypt(SecretKey key, byte[] iv, byte[] data) throws Exception {
        IvParameterSpec ivSpec = SecureUtil.getIv(iv);

        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        return cipher.doFinal(data);
    }

    public static SecretKey toKey(char[] password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(PBE_ALGORITHM);
        KeySpec spec = new PBEKeySpec(password, salt, PBE_ITERATION_COUNT, 256);
        SecretKey tmp = factory.generateSecret(spec);
        SecretKey secret = new SecretKeySpec(tmp.getEncoded(), CIPHER_ALGORITHM);

        return secret;
    }
}
