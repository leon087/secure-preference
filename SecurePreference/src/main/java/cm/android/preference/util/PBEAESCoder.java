package cm.android.preference.util;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class PBEAESCoder {
    public static final String CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";

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

    public static SecretKey generateKey(char[] password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKey tmp = HashUtil.generateHash(password, salt);
        SecretKey secret = new SecretKeySpec(tmp.getEncoded(), CIPHER_ALGORITHM);
        return secret;
    }
}
